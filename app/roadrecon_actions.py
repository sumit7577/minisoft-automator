#!/usr/bin/env python3
"""
roadrecon_actions.py

Blueprint version of what used to be main.py's standalone app: every route
still just shells out to the real `roadrecon` / `roadtx` CLI in a subprocess,
but now lives behind the same admin session as the rest of the dashboard
instead of running as its own unauthenticated Flask app.

Routes (all admin_required):
  GET  /api/status
  GET  /api/cookies/session
  POST /api/cookies/prtcookie
  POST /api/auth/password
  POST /api/auth/devicecode
  POST /api/auth/interactive
  POST /api/auth/keepass
  POST /api/auth/prt
  POST /api/auth/device
  POST /api/auth/prtauth
  POST /api/gather
  POST /api/gui
  POST /api/custom
"""

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, request, jsonify

from admin import admin_required

actions_bp = Blueprint("actions", __name__)

# Written by pain.py's interactive flow (_persist_session_cookies) into this
# same app/ directory; read here regardless of the process's cwd.
SESSION_COOKIES_FILE = Path(__file__).parent / ".roadtools_sessioncookies.json"


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


@actions_bp.route("/api/cookies/session")
@admin_required
def api_cookies_session():
    """
    Return the browser session cookies captured during the last successful
    Interactive login (written by pain.py to .roadtools_sessioncookies.json),
    together with when they were captured (the file's modification time, since
    the file itself is just the raw cookie list). Returns ok=false when no
    successful Interactive login has happened yet (file absent).
    """
    if not SESSION_COOKIES_FILE.exists():
        return jsonify({"ok": False, "output": "No session cookies captured yet. Complete an Interactive login first."})

    try:
        cookies = json.loads(SESSION_COOKIES_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return jsonify({"ok": False, "output": f"Could not read session cookie file: {exc}"})

    captured_at = datetime.fromtimestamp(SESSION_COOKIES_FILE.stat().st_mtime, tz=timezone.utc)
    return jsonify({
        "ok": True,
        "cookies": cookies,
        "count": len(cookies) if isinstance(cookies, list) else None,
        "captured_at": captured_at.isoformat(),
        "path": str(SESSION_COOKIES_FILE),
    })


@actions_bp.route("/api/cookies/prtcookie", methods=["POST"])
@admin_required
def api_cookies_prtcookie():
    """
    roadtx prtcookie — generate a fresh PRT-based auth cookie (x-ms-RefreshToken
    Cookie) from a Primary Refresh Token. By default reads the PRT from the
    roadtx.prt file produced by the PRT tab; --prt/--prt-sessionkey override it.

    The cookie roadtx prints is short-lived (roadtx notes ~5 minutes) and meant
    to be regenerated right before use, so nothing is persisted server-side —
    stdout (cookie string + roadtx's validity note) is returned as-is.
    """
    data = request.get_json(force=True) or {}
    prt_file = data.get("prt_file", "").strip() or "roadtx.prt"
    prt = data.get("prt", "").strip()
    prt_sessionkey = data.get("prt_sessionkey", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if prt and not prt_sessionkey:
        return jsonify({"ok": False, "output": "When passing an explicit PRT you must also supply its session key (--prt-sessionkey)."})

    cmd = ["roadtx", "prtcookie"]
    if prt:
        cmd += ["--prt", prt, "--prt-sessionkey", prt_sessionkey]
    else:
        cmd += ["-f", prt_file]

    result = run_cmd(cmd, timeout=60)
    if prt:
        result["cmd"] = result["cmd"].replace(prt, "********")
    if prt_sessionkey:
        result["cmd"] = result["cmd"].replace(prt_sessionkey, "********")
    return jsonify(result)


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
    """
    roadtx prt — requests a Primary Refresh Token using a device key/cert
    plus either username+password OR a refresh token (roadtx's own
    '--refresh-token file' sentinel means "use the one already cached in
    .roadtools_auth" instead of a fresh sign-in).
    """
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    key_pem = data.get("key_pem", "").strip()
    cert_pem = data.get("cert_pem", "").strip()
    refresh_token = data.get("refresh_token", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if not key_pem or not cert_pem:
        return jsonify({"ok": False, "output": "Device key .pem path and cert .pem path are always required."})
    if not refresh_token and not (username and password):
        return jsonify({"ok": False, "output": "Provide either a refresh token (or 'file' to use the cached one), or a username and password."})

    cmd = ["roadtx", "prt", "--key-pem", key_pem, "--cert-pem", cert_pem]
    if refresh_token:
        cmd += ["--refresh-token", refresh_token]
    else:
        cmd += ["-u", username, "-p", password]

    result = run_cmd(cmd, timeout=120)
    if password:
        result["cmd"] = result["cmd"].replace(password, "********")
    if refresh_token and refresh_token.lower() != "file":
        result["cmd"] = result["cmd"].replace(refresh_token, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/refreshtokento", methods=["POST"])
@admin_required
def api_auth_refreshtokento():
    """
    roadtx refreshtokento — mints a new access token for a different
    resource using the refresh token already cached in .roadtools_auth (or
    a custom one), without a fresh sign-in. This is how you get a token
    with the right audience for things like WinHello
    (urn:ms-drs:enterpriseregistration.windows.net) when the cached token
    was obtained for a different resource.
    """
    data = request.get_json(force=True) or {}
    resource = data.get("resource", "").strip()
    client = data.get("client", "").strip()
    refresh_token = data.get("refresh_token", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if refresh_token and not client:
        return jsonify({"ok": False, "output": "Client (application) ID is required when supplying a custom refresh token."})

    cmd = ["roadtx", "refreshtokento"]
    if resource:
        cmd += ["-r", resource]
    if client:
        cmd += ["-c", client]
    if refresh_token:
        cmd += ["--refresh-token", refresh_token]

    result = run_cmd(cmd, timeout=60)
    if refresh_token:
        result["cmd"] = result["cmd"].replace(refresh_token, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/winhello", methods=["POST"])
@admin_required
def api_auth_winhello():
    """
    roadtx winhello — registers a Windows Hello / passkey key against the
    device registration service. Needs an access token scoped to
    urn:ms-drs:enterpriseregistration.windows.net; if none is pasted in,
    roadtx falls back to whatever's cached in .roadtools_auth (which will
    fail with a "wrong token audience" message if that token was requested
    for a different resource).
    """
    data = request.get_json(force=True) or {}
    key_pem = data.get("key_pem", "").strip()
    access_token = data.get("access_token", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    cmd = ["roadtx", "winhello"]
    if key_pem:
        cmd += ["-k", key_pem]
    if access_token:
        cmd += ["--access-token", access_token]

    result = run_cmd(cmd, timeout=60)
    if access_token:
        result["cmd"] = result["cmd"].replace(access_token, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/device", methods=["POST"])
@admin_required
def api_auth_device():
    """
    roadtx device — join / register / delete a device object in the tenant.

    'join' and 'register' create a REAL device object in the target tenant
    (join = Azure AD joined, register = Azure AD registered) and write a
    device cert (-c) + private key (-k) locally that later flows (prt, prtauth
    v4) consume. Needs an access token scoped to the device registration
    service; if --access-token isn't supplied roadtx falls back to whatever's
    cached in .roadtools_auth (mint one via "Refresh -> Resource" first, same
    prerequisite as WinHello). 'delete' removes a device using its cert/key.
    """
    data = request.get_json(force=True) or {}
    action = data.get("action", "join").strip() or "join"
    cert_pem = data.get("cert_pem", "").strip()
    key_pem = data.get("key_pem", "").strip()
    name = data.get("name", "").strip()
    domain = data.get("domain", "").strip()
    access_token = data.get("access_token", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if action not in ("join", "register", "delete"):
        return jsonify({"ok": False, "output": "Action must be one of: join, register, delete."})

    cmd = ["roadtx", "device", "-a", action]
    if cert_pem:
        cmd += ["-c", cert_pem]
    if key_pem:
        cmd += ["-k", key_pem]
    if name:
        cmd += ["-n", name]
    if domain:
        cmd += ["-d", domain]
    if access_token:
        cmd += ["--access-token", access_token]

    result = run_cmd(cmd, timeout=120)
    if access_token:
        result["cmd"] = result["cmd"].replace(access_token, "********")
    return jsonify(result)


@actions_bp.route("/api/auth/prtauth", methods=["POST"])
@admin_required
def api_auth_prtauth():
    """
    roadtx prtauth — authenticate to a resource using a Primary Refresh Token
    (produced by the PRT tab, stored in roadtx.prt by default) and store the
    resulting tokens in .roadtools_auth like the other auth methods.

    Defaults match the real CLI: client 04b07795-8ddb-461a-bbee-02f9e1bf7b46
    (Azure CLI) and resource https://graph.windows.net. Override the resource
    to urn:ms-drs:enterpriseregistration.windows.net to mint a token WinHello
    can use. The PRT can come from a file (-f, default roadtx.prt) or be passed
    explicitly via --prt / --prt-sessionkey.
    """
    data = request.get_json(force=True) or {}
    resource = data.get("resource", "").strip()
    client = data.get("client", "").strip()
    prt_file = data.get("prt_file", "").strip()
    prt = data.get("prt", "").strip()
    prt_sessionkey = data.get("prt_sessionkey", "").strip()

    if not roadtx_available():
        return jsonify({"ok": False, "output": "roadtx command not found. Install it with 'pip install roadtx' or activate the right venv."})

    if prt and not prt_sessionkey:
        return jsonify({"ok": False, "output": "When passing an explicit PRT you must also supply its session key (--prt-sessionkey)."})

    cmd = ["roadtx", "prtauth"]
    if client:
        cmd += ["-c", client]
    if resource:
        cmd += ["-r", resource]
    if prt:
        cmd += ["--prt", prt, "--prt-sessionkey", prt_sessionkey]
    elif prt_file:
        cmd += ["-f", prt_file]

    result = run_cmd(cmd, timeout=120)
    if prt:
        result["cmd"] = result["cmd"].replace(prt, "********")
    if prt_sessionkey:
        result["cmd"] = result["cmd"].replace(prt_sessionkey, "********")
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
