#!/bin/bash
# ======================================================================
# DEPRECATED — do not use to run Lab Manager.
#
# OLD foreground launcher that starts the Hub + a Vite dev server + the CS
# spoke by backgrounding PIDs and `wait`ing. Superseded by the systemd unit
# written by install_all.sh (`systemctl start lm`), which:
#   * runs the hub as the non-root svc_lm user (this script runs as whoever
#     invoked it, typically root — the old `User=root` anti-pattern),
#   * uses a precise `ExecStop=pkill -f "core/src/main.py"` instead of the
#     broad `pkill -f python` this script's `kill $HUB_PID $UI_PID $CS_PID`
#     approximates, and
#   * delegates spoke start/stop to per-spoke lm-* units instead of one
#     foreground process group.
#
# Kept for reference only. Behavior changes belong in install_all.sh + the
# systemd unit, NOT here.
# ======================================================================

# Lab Manager Starter
# Launches both Hub and WebUI

echo "🚀 Launching Lab Manager..."

# Path to the root directory
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 1. Start Hub in background
echo "Starting Hub..."
cd "$ROOT_DIR/hub"
# We use the venv created by install.sh
./venv/bin/python3 src/main.py &
HUB_PID=$!

# 2. Start WebUI in background
echo "Starting WebUI (Vite dev server)..."
cd "$ROOT_DIR/ui"
npm run dev &
UI_PID=$!

# 3. Start Client Simulator (CS) Module as a Spoke
echo "Starting Client Simulator module..."
cd "$ROOT_DIR/cs"
./venv/bin/python3 src/control_plane.py --id cs-spoke-1 --secret la-manager-secret --hub ws://localhost:8765 &
CS_PID=$!

echo ""
echo "✅ Lab Manager is running!"
echo "Hub PID: $HUB_PID"
echo "WebUI PID: $UI_PID"
echo "CS Module PID: $CS_PID"
echo "Press Ctrl+C to stop all services."

# Wait for processes and kill them on exit
trap "kill $HUB_PID $UI_PID $CS_PID; echo 'Stopping Lab Manager...'; exit" INT TERM

wait
