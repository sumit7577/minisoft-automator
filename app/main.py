#!/usr/bin/env python3
"""
roadrecon_web_ui / app.py

A minimal local web UI that wraps the `roadrecon` CLI you already have
installed. It does NOT reimplement any ROADtools logic — every action
just shells out to the real `roadrecon` command in a subprocess.

Run this from inside your activated virtualenv (the one where
`pip install -e roadlib/ roadrecon/` was done), from the directory
where you want roadrecon.db / .roadtools_auth to live:

    python3 app.py

Then open http://127.0.0.1:5050 in your browser.

NOTE: This binds to 127.0.0.1 (localhost only) on purpose. Do not expose
this to a network — it runs commands with credentials on your behalf.
"""

import os
import shutil
import subprocess
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    cwd = os.getcwd()
    return jsonify({
        "cwd": cwd,
        "roadrecon_installed": roadrecon_available(),
        "roadtx_installed": roadtx_available(),
        "db_exists": os.path.isfile("roadrecon.db"),
        "auth_exists": os.path.isfile(".roadtools_auth"),
    })


@app.route("/api/auth/password", methods=["POST"])
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
    # never echo the password back
    result["cmd"] = result["cmd"].replace(password, "********")
    return jsonify(result)


@app.route("/api/auth/devicecode", methods=["POST"])
def api_auth_devicecode():
    # Device code flow prints a URL + code and then blocks waiting for
    # the user to complete sign-in in a browser. We give it a generous
    # timeout so the user has time to go complete it.
    result = run_cmd(["roadrecon", "auth", "--device-code"], timeout=300)
    return jsonify(result)


@app.route("/api/auth/interactive", methods=["POST"])
def api_auth_interactive():
    """
    roadtx interactiveauth — opens a real browser window for sign-in.
    Username/password are pre-filled if given; the person completes MFA
    themselves in that window. Requires roadtx (not roadrecon).
    """
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

    # Opens a browser window and waits for the user to finish (incl. MFA),
    # so give it a generous timeout.
    result = run_cmd(cmd, timeout=300)
    if password:
        result["cmd"] = result["cmd"].replace(password, "********")
    return jsonify(result)


@app.route("/api/auth/keepass", methods=["POST"])
def api_auth_keepass():
    """
    roadtx keepassauth — automates MFA using a TOTP seed stored in a
    KeePass database the person already owns/enrolled. Does not bypass
    MFA; it supplies the same code you'd otherwise type by hand.
    """
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


@app.route("/api/auth/prt", methods=["POST"])
def api_auth_prt():
    """
    roadtx prt — requests a Primary Refresh Token using username/password
    plus a device key/cert pair. Note: a PRT obtained this way typically
    still will NOT satisfy Conditional Access MFA requirements on its own;
    getting an MFA-satisfying PRT usually requires 'roadtx prtenrich'
    after an interactive/device-code sign-in. Included here for
    completeness of the auth flows roadtx exposes.
    """
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


@app.route("/api/gather", methods=["POST"])
def api_gather():
    data = request.get_json(force=True) or {}
    mfa = data.get("mfa", False)
    cmd = ["roadrecon", "gather"]
    if mfa:
        cmd.append("--mfa")
    result = run_cmd(cmd, timeout=1800)
    return jsonify(result)


@app.route("/api/gui", methods=["POST"])
def api_gui():
    if not os.path.isfile("roadrecon.db"):
        return jsonify({"ok": False, "output": "roadrecon.db not found. Run 'gather' first."})
    # Launch detached so it doesn't block this web server
    try:
        subprocess.Popen(["roadrecon", "gui"])
        return jsonify({"ok": True, "output": "roadrecon gui launched. It should be available at http://127.0.0.1:5000 (default roadrecon port)."})
    except FileNotFoundError:
        return jsonify({"ok": False, "output": "roadrecon command not found."})


@app.route("/api/custom", methods=["POST"])
def api_custom():
    data = request.get_json(force=True)
    args = data.get("args", "").strip()
    if not args:
        return jsonify({"ok": False, "output": "No arguments provided."})
    cmd = ["roadrecon"] + args.split()
    result = run_cmd(cmd, timeout=300)
    return jsonify(result)


if __name__ == "__main__":
    if not roadrecon_available():
        print("⚠️  'roadrecon' not found on PATH. Activate your venv first, e.g.:")
        print("     source env/bin/activate")
    app.run(host="127.0.0.1", port=5050, debug=False)