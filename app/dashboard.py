#!/usr/bin/env python3
"""
dashboard.py

Post-login landing page: summary stats + admin user CRUD. Import into
main.py the same way as admin.py:

    from dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

Routes:
  GET  /dashboard              -> renders templates/dashboard.html (admin_required)
  GET  /api/stats               -> counts for the dashboard cards (admin_required)
  GET  /api/admin-users         -> list admin accounts (admin_required)
  POST /api/admin-users         -> { "username": "...", "password": "..." } create one
  DELETE /api/admin-users/<id>  -> delete one (can't delete yourself)

STATS CAVEAT: "Access Tokens / Refresh Tokens / Device Codes / Device Certs /
PRTs" counts are read from roadtx's local auth-state file if one is found
(checked at ROADTOOLS_AUTH_FILE below). The exact JSON structure of that
file is NOT verified against your installed roadtx version — this reads it
defensively and returns 0 for anything it can't confidently find, rather
than guessing at keys. Paste the real file's structure (with actual token
values redacted) and I'll wire this to the real schema.

"Databases" count and DB introspection ARE verified — they just read
whatever tables/rows actually exist in roadrecon.db via sqlite_master,
so nothing there depends on guessed table names.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional

from flask import Blueprint, jsonify, request, render_template, session
from werkzeug.security import generate_password_hash

from admin import admin_required, _get_db as _get_admin_db

dashboard_bp = Blueprint("dashboard", __name__)

APP_DIR = Path(__file__).parent
ROADRECON_DB_PATH = APP_DIR / "roadrecon.db"
ROADTOOLS_AUTH_FILE = APP_DIR / ".roadtools_auth"


# ---------------------------------------------------------------------------
# roadrecon.db introspection — reads whatever tables actually exist,
# no hardcoded/guessed table names
# ---------------------------------------------------------------------------

def _roadrecon_table_counts() -> dict:
    if not ROADRECON_DB_PATH.exists():
        return {}
    counts = {}
    try:
        conn = sqlite3.connect(ROADRECON_DB_PATH)
        tables = [
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        ]
        for table in tables:
            try:
                count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                counts[table] = count
            except sqlite3.Error:
                pass  # skip tables that error out (e.g. views without simple COUNT support)
        conn.close()
    except sqlite3.Error:
        pass
    return counts


# ---------------------------------------------------------------------------
# Local roadtx auth-state file — verified structure:
# tokenType, expiresOn, tenantId, _clientId, accessToken, refreshToken,
# idToken, expiresIn. Device codes / certs / PRTs are not part of this file
# (roadtx stores those elsewhere per-flow), so those counts stay at 0 until
# we wire up reading whatever roadtx actually writes for them.
# ---------------------------------------------------------------------------

def _load_auth_file() -> Optional[dict]:
    if not ROADTOOLS_AUTH_FILE.exists():
        return None
    try:
        data = json.loads(ROADTOOLS_AUTH_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _read_auth_state() -> dict:
    defaults = {
        "access_tokens": 0,
        "refresh_tokens": 0,
        "device_codes": 0,
        "device_certs": 0,
        "prts": 0,
    }
    data = _load_auth_file()
    if data:
        if data.get("accessToken"):
            defaults["access_tokens"] = 1
        if data.get("refreshToken"):
            defaults["refresh_tokens"] = 1
    return defaults


def _auth_state_details() -> Optional[dict]:
    """Non-secret metadata from the auth cache file, for display in the UI."""
    data = _load_auth_file()
    if not data:
        return None
    return {
        "path": str(ROADTOOLS_AUTH_FILE),
        "token_type": data.get("tokenType"),
        "tenant_id": data.get("tenantId"),
        "client_id": data.get("_clientId"),
        "expires_on": data.get("expiresOn"),
        "expires_in": data.get("expiresIn"),
        "has_access_token": bool(data.get("accessToken")),
        "has_refresh_token": bool(data.get("refreshToken")),
        "has_id_token": bool(data.get("idToken")),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@dashboard_bp.route("/dashboard")
@admin_required
def dashboard_page():
    return render_template("dashboard.html")


@dashboard_bp.route("/api/stats")
@admin_required
def api_stats():
    auth_state = _read_auth_state()
    table_counts = _roadrecon_table_counts()

    return jsonify({
        "ok": True,
        "access_tokens": auth_state["access_tokens"],
        "refresh_tokens": auth_state["refresh_tokens"],
        "device_codes": auth_state["device_codes"],
        "device_certs": auth_state["device_certs"],
        "prts": auth_state["prts"],
        "databases": 1 if ROADRECON_DB_PATH.exists() else 0,
        "tables": table_counts,  # { "Users": 142, "Devices": 30, ... } — real, live counts
        "auth_details": _auth_state_details(),
    })


@dashboard_bp.route("/api/auth-state/reveal", methods=["POST"])
@admin_required
def reveal_auth_state():
    data = _load_auth_file()
    if not data:
        return jsonify({"ok": False, "output": "No .roadtools_auth file found."}), 404
    return jsonify({
        "ok": True,
        "access_token": data.get("accessToken"),
        "refresh_token": data.get("refreshToken"),
        "id_token": data.get("idToken"),
    })


@dashboard_bp.route("/api/admin-users", methods=["GET"])
@admin_required
def list_admin_users():
    with _get_admin_db() as conn:
        rows = conn.execute("SELECT id, username, created_at FROM admins ORDER BY id").fetchall()
    return jsonify({
        "ok": True,
        "users": [dict(row) for row in rows],
    })


@dashboard_bp.route("/api/admin-users", methods=["POST"])
@admin_required
def create_admin_user():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "output": "username and password are both required."}), 400

    with _get_admin_db() as conn:
        existing = conn.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
        if existing:
            return jsonify({"ok": False, "output": "That username already exists."}), 409
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
    return jsonify({"ok": True})


@dashboard_bp.route("/api/admin-users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_admin_user(user_id: int):
    if session.get("admin_id") == user_id:
        return jsonify({"ok": False, "output": "You can't delete your own account while logged in as it."}), 400

    with _get_admin_db() as conn:
        conn.execute("DELETE FROM admins WHERE id = ?", (user_id,))
    return jsonify({"ok": True})