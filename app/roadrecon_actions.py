#!/usr/bin/env python3
"""
roadrecon_actions.py

Blueprint version of what used to be main.py's standalone app: every route
still just shells out to the real `roadrecon` / `roadtx` CLI in a subprocess,
but now lives behind the same admin session as the rest of the dashboard
instead of running as its own unauthenticated Flask app.

Routes (all admin_required):
  GET  /api/status
  POST /api/auth/password
  POST /api/auth/devicecode
  POST /api/auth/interactive
  POST /api/auth/keepass
  POST /api/auth/prt
  POST /api/gather
  POST /api/gui
  POST /api/custom
"""

import os
import shutil
import subprocess

from flask import Blueprint, request, jsonify

from admin import admin_required

actions_bp = Blueprint("actions", __name__)


def roadrecon_available():
    return shutil.which("roadrecon") is not None


def roadtx_available():
    return shutil.which("roadtx") is not None


def run_cmd(cmd, timeout=None):
    """Run a command and capture combined output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "output": output.strip(),
            "cmd": " ".join(cmd),
        }
    except FileNotFoundError:
        return {"ok": False, "returncode": -1, "output": "roadrecon command not found. Is your venv activated?", "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": -1, "output": "Command timed out.", "cmd": " ".join(cmd)}


@actions_bp.route("/api/status")
@admin_required
def api_status():
    cwd = os.getcwd()
    return jsonify({
        "cwd": cwd,
        "roadrecon_installed": roadrecon_available(),
        "roadtx_installed": roadtx_available(),
        "db_exists": os.path.isfile("roadrecon.db"),
        "auth_exists": os.path.isfile(".roadtools_auth"),
    })


@actions_bp.route("/api/auth/password", methods=["POST"])
@admin_required
def api_auth_password():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    tenant = data.get("tenant", "").strip()

    if not username or not password:
        return jsonify({"ok": False, "output": "Username and password are required."})

    cmd = ["roadrecon", "auth", "-u", username, "-p", password]
    if tenant:
        cmd += ["--tenant", tenant]

    result = run_cmd(cmd, timeout=120)
    result["cmd"] = result["cmd"].replace(password, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/devicecode", methods=["POST"])
@admin_required
def api_auth_devicecode():
    result = run_cmd(["roadrecon", "auth", "--device-code"], timeout=300)
    return jsonify(result)


@actions_bp.route("/api/auth/interactive", methods=["POST"])
@admin_required
def api_auth_interactive():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client = data.get("client", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    cmd = ["roadtx", "interactiveauth"]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if client:
        cmd += ["-c", client]

    result = run_cmd(cmd, timeout=300)
    if password:
        result["cmd"] = result["cmd"].replace(password, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/keepass", methods=["POST"])
@admin_required
def api_auth_keepass():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    client = data.get("client", "").strip()
    kdbx_path = data.get("kdbx_path", "").strip()
    kdbx_password = data.get("kdbx_password", "")

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if not username or not kdbx_path or not kdbx_password:
        return jsonify({"ok": False, "output": "Username, KeePass file path, and KeePass password are all required."})

    cmd = ["roadtx", "keepassauth", "-u", username, "-kp", kdbx_path, "-kpp", kdbx_password]
    if client:
        cmd += ["-c", client]

    result = run_cmd(cmd, timeout=180)
    result["cmd"] = result["cmd"].replace(kdbx_password, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/prt", methods=["POST"])
@admin_required
def api_auth_prt():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    key_pem = data.get("key_pem", "").strip()
    cert_pem = data.get("cert_pem", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if not username or not password or not key_pem or not cert_pem:
        return jsonify({"ok": False, "output": "Username, password, key .pem path, and cert .pem path are all required."})

    cmd = ["roadtx", "prt", "-u", username, "-p", password, "--key-pem", key_pem, "--cert-pem", cert_pem]
    result = run_cmd(cmd, timeout=120)
    result["cmd"] = result["cmd"].replace(password, "********")
    return jsonify(result)


@actions_bp.route("/api/gather", methods=["POST"])
@admin_required
def api_gather():
    data = request.get_json(force=True) or {}
    mfa = data.get("mfa", False)
    cmd = ["roadrecon", "gather"]
    if mfa:
        cmd.append("--mfa")
    result = run_cmd(cmd, timeout=1800)
    return jsonify(result)


@actions_bp.route("/api/gui", methods=["POST"])
@admin_required
def api_gui():
    if not os.path.isfile("roadrecon.db"):
        return jsonify({"ok": False, "output": "roadrecon.db not found. Run 'gather' first."})
    try:
        subprocess.Popen(["roadrecon", "gui"])
        return jsonify({"ok": True, "output": "roadrecon gui launched. It should be available at http://127.0.0.1:5000 (default roadrecon port)."})
    except FileNotFoundError:
        return jsonify({"ok": False, "output": "roadrecon command not found."})


@actions_bp.route("/api/custom", methods=["POST"])
@admin_required
def api_custom():
    data = request.get_json(force=True)
    args = data.get("args", "").strip()
    if not args:
        return jsonify({"ok": False, "output": "No arguments provided."})
    cmd = ["roadrecon"] + args.split()
    result = run_cmd(cmd, timeout=300)
    return jsonify(result)
