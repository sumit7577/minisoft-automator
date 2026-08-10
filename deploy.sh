#!/usr/bin/env bash
# deploy.sh — one-shot deploy of minisoft-automator to 45.143.166.108
# Run from your local terminal: bash deploy.sh
set -e

SERVER="root@45.143.166.108"
SSH_PORT="56777"
PASS="3ph37xW9M1BaiUMWk7"
REPO="https://github.com/sumit7577/minisoft-automator.git"
APP_DIR="/opt/app"

echo "==> Deploying to $SERVER ..."

sshpass -p "$PASS" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no "$SERVER" bash -s <<REMOTE
set -e

echo "--- System info ---"
uname -a

# ── Docker ──────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "--- Installing Docker ---"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian \$(. /etc/os-release && echo \$VERSION_CODENAME) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  echo "--- Docker installed: \$(docker --version) ---"
else
  echo "--- Docker already installed: \$(docker --version) ---"
fi

# ── Clone / update repo ──────────────────────────────────────────────────────
if [ -d "$APP_DIR/.git" ]; then
  echo "--- Updating existing repo ---"
  cd $APP_DIR
  git pull
else
  echo "--- Cloning repo ---"
  git clone $REPO $APP_DIR
  cd $APP_DIR
fi

# ── Pre-create mounted files so Docker doesn't make them directories ─────────
touch $APP_DIR/app/admin.db
touch $APP_DIR/app/roadrecon.db
touch $APP_DIR/app/.roadtools_auth

# ── Build & start ────────────────────────────────────────────────────────────
echo "--- Building and starting containers ---"
cd $APP_DIR
docker compose -f offspring-compose.yaml down --remove-orphans 2>/dev/null || true
docker compose -f offspring-compose.yaml up -d --build

echo ""
echo "=== Done! ==="
echo "App is running. Create your first admin account with:"
echo "  docker compose -f $APP_DIR/offspring-compose.yaml exec dashboard python admin.py create-admin"
echo ""
echo "Access the dashboard at: http://45.143.166.108:5000"
REMOTE
