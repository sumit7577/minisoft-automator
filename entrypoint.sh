#!/bin/sh
set -e

# Clear any stale lock left by a previous container so Xvfb can claim :99 on restart
rm -f /tmp/.X99-lock && Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp &

export DISPLAY=:99

exec gunicorn \
  --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
  --workers 1 \
  --bind 0.0.0.0:5000 \
  --timeout 120 \
  --keep-alive 5 \
  "main:socketio.wsgi_app"
