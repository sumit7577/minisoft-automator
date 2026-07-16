#!/bin/sh
set -e

Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp &

export DISPLAY=:99

exec python main.py
