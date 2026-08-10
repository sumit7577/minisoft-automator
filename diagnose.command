#!/usr/bin/env python3
"""Double-click this to diagnose + deploy to the server."""
import sys, time

try:
    import paramiko
except ImportError:
    import subprocess
    r = subprocess.run([sys.executable, "-m", "pip", "install", "paramiko", "-q",
                        "--break-system-packages"], capture_output=True)
    if r.returncode != 0:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko", "-q"])
    import paramiko

HOST = "45.143.166.108"
PORT = 56777
USER = "root"
PASS = "3ph37xW9M1BaiUMWk7"
LOCAL_MAIN = "/Users/sumitkumar/code/personal/offspring/app/main.py"
REMOTE_MAIN = "/opt/app/app/main.py"

DIAG = (
    'echo "=== CONTAINER STATE ==="; '
    'docker inspect roadtools-dashboard --format '
    '"RestartCount={{.RestartCount}} Status={{.State.Status}} Started={{.State.StartedAt}}" 2>/dev/null || echo "Container not found"; '
    'echo; echo "=== LAST 40 LOG LINES ==="; '
    'docker logs --tail 40 roadtools-dashboard 2>&1; '
    'echo; echo "=== HTTP CHECK ==="; '
    'curl -s -o /dev/null -w "localhost:5000 -> HTTP %{http_code}\\n" http://localhost:5000/ 2>/dev/null || echo "curl failed"; '
    'echo; echo "=== RUNNING CONTAINERS ==="; '
    'docker ps --format "{{.Names}}  {{.Status}}  {{.Ports}}"; '
    'echo; echo "=== GIT STATUS ==="; '
    'git -C /opt/app log --oneline -3 2>/dev/null; '
    'git -C /opt/app status --short 2>/dev/null'
)

def stream(client, cmd, label=""):
    if label:
        print(f"\n{'─'*55}")
        print(f"  {label}")
        print('─'*55)
    _, stdout, _ = client.exec_command(cmd, get_pty=True)
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            print(stdout.channel.recv(4096).decode("utf-8", errors="replace"), end="", flush=True)
        time.sleep(0.1)
    out = stdout.channel.recv(65535)
    if out:
        print(out.decode("utf-8", errors="replace"), end="", flush=True)
    return stdout.channel.recv_exit_status()

def main():
    print(f"Connecting to {HOST}:{PORT}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=20)
        print("Connected!")
    except Exception as e:
        print(f"Connection failed: {e}")
        input("\nPress Enter to close...")
        sys.exit(1)

    # ── 1. Diagnostics ──────────────────────────────────────────────────────
    stream(client, DIAG, "DIAGNOSTICS")

    # ── 2. Upload updated main.py ───────────────────────────────────────────
    print(f"\n{'─'*55}")
    print(f"  UPLOADING {LOCAL_MAIN}")
    print('─'*55)
    try:
        sftp = client.open_sftp()
        sftp.put(LOCAL_MAIN, REMOTE_MAIN)
        sftp.close()
        print("Upload done.")
    except Exception as e:
        print(f"Upload failed: {e}")
        input("\nPress Enter to close...")
        sys.exit(1)

    # ── 3. Restart container ────────────────────────────────────────────────
    stream(client, "docker restart roadtools-dashboard", "RESTARTING CONTAINER")
    time.sleep(4)
    stream(client, "docker logs roadtools-dashboard --tail 20 2>&1", "POST-RESTART LOGS")
    stream(client, 'curl -s -o /dev/null -w "HTTP %{http_code}\\n" http://localhost:5000/', "HTTP CHECK")

    client.close()
    print("\n\nDone! Dashboard: http://45.143.166.108:5000")
    input("\nPress Enter to close...")

if __name__ == "__main__":
    main()
