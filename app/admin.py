#!/usr/bin/env python3
"""
admin.py

Session-based admin login/logout, backed by SQLite. Designed to be
imported into main.py as a Blueprint:

    from admin import admin_bp, admin_required, init_admin_db

    app.secret_key = "change-this-to-something-random"  # required for sessions
    app.register_blueprint(admin_bp)
    init_admin_db()

    @app.route("/login/username", methods=["POST"])
    @admin_required
    def login_username():
        ...

Routes:
  GET  /admin/login   -> serves templates/admin_login.html
  POST /admin/login    -> { "username": "...", "password": "..." } authenticates,
                           sets session cookie
  POST /admin/logout    -> clears session
  GET  /admin/me        -> { "ok": true, "username": "..." } if logged in, 401 otherwise

No admin account exists until you create one. Run this file directly to
create the first admin from the command line:

    python3 admin.py create-admin

which prompts for username/password and writes into admin.db (SQLite,
alongside this file). Only one admin is assumed for a personal tool like
this, but the schema supports more than one if you ever want that.
"""

import sqlite3
import getpass
import sys
from functools import wraps
from pathlib import Path

from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = Path(__file__).parent / "admin.db"

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ---------------------------------------------------------------------------
# DB — small, single-purpose helpers (mirrors get_service/get_webdriver split
# in roadtx's SeleniumAuthentication: one function, one job)
# ---------------------------------------------------------------------------

def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_admin_db():
    """Call once at app startup. Safe to call every time — CREATE TABLE IF NOT EXISTS."""
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


def _find_admin(username: str):
    with _get_db() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM admins WHERE username = ?",
            (username,),
        ).fetchone()
    return row


def create_admin(username: str, password: str) -> bool:
    """Returns False if the username already exists, True on success."""
    if _find_admin(username):
        return False
    with _get_db() as conn:
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
    return True


def _verify_admin(username: str, password: str):
    row = _find_admin(username)
    if row and check_password_hash(row["password_hash"], password):
        return row
    return None


# ---------------------------------------------------------------------------
# Auth guard — one decorator, used everywhere, same idea as roadtx's
# @selenium_wrap: write the guard logic once, apply it by decoration.
# ---------------------------------------------------------------------------

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return jsonify({"ok": False, "output": "Authentication required."}), 401
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@admin_bp.route("/", methods=["GET"])
def admin_index_redirect():
    return redirect(url_for("admin.admin_login_page"))


@admin_bp.route("/login", methods=["GET"])
def admin_login_page():
    return render_template("admin.html")


@admin_bp.route("/login", methods=["POST"])
def admin_login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "output": "username and password are both required."}), 400

    row = _verify_admin(username, password)
    if not row:
        return jsonify({"ok": False, "output": "Invalid username or password."}), 401

    session.clear()
    session["admin_id"] = row["id"]
    session["admin_username"] = row["username"]
    return jsonify({"ok": True, "username": row["username"]})


@admin_bp.route("/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"ok": True})


@admin_bp.route("/me", methods=["GET"])
def admin_me():
    if not session.get("admin_id"):
        return jsonify({"ok": False, "output": "Not logged in."}), 401
    return jsonify({"ok": True, "username": session.get("admin_username")})


# ---------------------------------------------------------------------------
# CLI: create the first admin account
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "create-admin":
        print("Usage: python3 admin.py create-admin")
        sys.exit(1)

    init_admin_db()
    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords didn't match.")
        sys.exit(1)

    if create_admin(username, password):
        print(f"Admin '{username}' created.")
    else:
        print(f"An admin with username '{username}' already exists.")
        sys.exit(1)