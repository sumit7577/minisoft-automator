#!/usr/bin/env python3
"""
deploy.py — deploys minisoft-automator to 45.143.166.108
Run: pip3 install paramiko && python3 deploy.py
"""
import sys
import time

try:
    import paramiko
except ImportError:
    print("Installing paramiko...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])
    import paramiko

HOST = "45.143.166.108"
SSH_PORT = 56777
USER = "root"
PASS = "3ph37xW9M1BaiUMWk7"
REPO = "https://github.com/sumit7577/minisoft-automator.git"
APP_DIR = "/opt/app"

DEPLOY_SCRIPT = f"""
set -e

echo "==> System info"
uname -a
cat /etc/os-release | grep PRETTY_NAME

# ── Docker ────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "==> Installing Docker..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release git
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo $ID)/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo $ID) $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  echo "Docker installed: $(docker --version)"
else
  echo "==> Docker already present: $(docker --version)"
fi

# ── Git ───────────────────────────────────────────────────────────────────
if ! command -v git &>/dev/null; then
  apt-get install -y -qq git
fi

# ── Clone / update ────────────────────────────────────────────────────────
if [ -d "{APP_DIR}/.git" ]; then
  echo "==> Pulling latest code..."
  cd {APP_DIR} && git pull
else
  echo "==> Cloning repo..."
  git clone {REPO} {APP_DIR}
fi

cd {APP_DIR}

# ── Pre-create bind-mount files (avoid Docker creating them as dirs) ──────
touch {APP_DIR}/app/admin.db
touch {APP_DIR}/app/roadrecon.db
touch {APP_DIR}/app/.roadtools_auth

# ── Build & launch ────────────────────────────────────────────────────────
echo "==> Building Docker image (this takes a few minutes)..."
docker compose -f offspring-compose.yaml down --remove-orphans 2>/dev/null || true
docker compose -f offspring-compose.yaml up -d --build

echo ""
echo "============================================"
echo " Deployment complete!"
echo " App: http://{HOST}:5000"
echo " Create admin: docker compose -f {APP_DIR}/offspring-compose.yaml exec dashboard python admin.py create-admin"
echo "============================================"
"""


def run(client, cmd, desc=""):
    if desc:
        print(f"\n{'='*50}")
        print(f"  {desc}")
        print('='*50)

    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)

    # Stream output live
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            data = stdout.channel.recv(4096).decode("utf-8", errors="replace")
            print(data, end="", flush=True)
        time.sleep(0.1)

    # Flush remaining
    remaining = stdout.channel.recv(65535)
    if remaining:
        print(remaining.decode("utf-8", errors="replace"), end="", flush=True)

    return stdout.channel.recv_exit_status()


def main():
    print(f"Connecting to {HOST}...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(HOST, port=SSH_PORT, username=USER, password=PASS, timeout=15)
        print(f"Connected to {HOST} as {USER}")
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    exit_code = run(client, DEPLOY_SCRIPT, "Running deployment")

    client.close()

    if exit_code == 0:
        print(f"\n✓ Deployment successful!")
        print(f"  Dashboard: http://{HOST}:5000")
    else:
        print(f"\n✗ Deployment failed (exit code {exit_code})")
        sys.exit(1)


if __name__ == "__main__":
    main()
