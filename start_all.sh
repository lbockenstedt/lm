#!/bin/bash
# Lab Manager Native Orchestrator (API-Only)
# Launches only Python components. Node.js is no longer required.

set -e

# Get the absolute path of the current directory (the lm repo)
BASE_DIR=$(pwd)
PARENT_DIR=$(dirname "$BASE_DIR")

echo "🚀 Launching Lab Manager Stack (Native API-Only Mode)..."

# Kill existing processes to avoid port conflicts
echo "🧹 Cleaning up existing processes..."
# Specifically target the Hub port to avoid OSError 48
PORT_PID=$(lsof -t -i :8765)
if [ -n "$PORT_PID" ]; then
    echo "Found process $PORT_PID on port 8765. Killing it..."
    kill -9 $PORT_PID
fi
pkill -f python || true
pkill -f node || true
sleep 2

# --- 1. Launch Hub ---
echo "Starting Hub..."
cd "$BASE_DIR"
nohup ./venv/bin/python hub/src/main.py > hub.log 2>&1 &
echo "Hub started (logs: hub.log)"
sleep 5 # Give hub time to initialize

# --- 2. Launch Spokes ---
# Note: These use a default secret. In production, update these to match Hub config.
SECRET="la-manager-secret"

# Client Simulator
echo "Starting Client Simulator..."
cd "$PARENT_DIR/cs"
# Run as module to fix relative import errors
nohup ./venv/bin/python -m src.control_plane --id cs-spoke-1 --secret "$SECRET" --hub ws://localhost:8765 > "$BASE_DIR/cs.log" 2>&1 &
echo "CS started (logs: $BASE_DIR/cs.log)"

# Proxmox
echo "Starting Proxmox Manager..."
cd "$PARENT_DIR/pxmx"
# Run as module to fix relative import errors
nohup ./venv/bin/python -m src.control_plane --id pxmx-spoke-1 --secret "$SECRET" --hub ws://localhost:8765 > "$BASE_DIR/pxmx.log" 2>&1 &
echo "PXMX started (logs: $BASE_DIR/pxmx.log)"

# OPNsense
echo "Starting OPNsense Manager..."
cd "$PARENT_DIR/opnsense"
# Run as module to fix relative import errors
nohup ./venv/bin/python -m src.control_plane --id opn-spoke-1 --secret "$SECRET" --hub ws://localhost:8765 > "$BASE_DIR/opnsense.log" 2>&1 &
echo "OPNsense started (logs: $BASE_DIR/opnsense.log)"

echo ""
echo "🎉 All systems launched in the background!"
echo "------------------------------------------------------------------"
echo "Hub API:   http://localhost:8000"
echo "------------------------------------------------------------------"
echo "To stop all services, run: pkill -f python"
echo "To view logs, use: tail -f <module>.log"
