#!/bin/bash

# Lab Manager Native Orchestrator
# This script launches all components in the background using virtual environments.
# It assumes the installation was done via install_all.sh.

set -e

# Get the absolute path of the current directory (the lm repo)
BASE_DIR=$(pwd)
PARENT_DIR=$(dirname "$BASE_DIR")

echo "🚀 Launching Lab Manager Stack (Native Mode)..."

# --- 1. Launch Hub ---
echo "Starting Hub..."
cd "$BASE_DIR"
nohup ./venv/bin/python hub/src/main.py > hub.log 2>&1 &
echo "Hub started (logs: hub.log)"
sleep 5 # Give hub time to initialize

# --- 2. Launch WebUI ---
echo "Starting WebUI..."
cd "$BASE_DIR/ui"
nohup npm run dev -- --host > ui.log 2>&1 &
echo "WebUI started (logs: ui.log)"

# --- 3. Launch Spokes ---
# Note: These use a default secret. In production, update these to match Hub config.
SECRET="la-manager-secret"

# Client Simulator
echo "Starting Client Simulator..."
cd "$PARENT_DIR/cs"
nohup ./venv/bin/python src/control_plane.py --id cs-spoke-1 --secret "$SECRET" --hub ws://localhost:8765 > cs.log 2>&1 &
echo "CS started (logs: cs.log)"

# Proxmox
echo "Starting Proxmox Manager..."
cd "$PARENT_DIR/pxmx"
nohup ./venv/bin/python src/control_plane.py --id pxmx-spoke-1 --secret "$SECRET" --hub ws://localhost:8765 > pxmx.log 2>&1 &
echo "PXMX started (logs: pxmx.log)"

# OPNsense
echo "Starting OPNsense Manager..."
cd "$PARENT_DIR/opnsense"
nohup ./venv/bin/python src/control_plane.py --id opn-spoke-1 --secret "$SECRET" --hub ws://localhost:8765 > opnsense.log 2>&1 &
echo "OPNsense started (logs: opnsense.log)"

echo ""
echo "🎉 All systems launched in the background!"
echo "------------------------------------------------------------------"
echo "Dashboard: http://localhost:5173"
echo "Hub API:   http://localhost:8000"
echo "------------------------------------------------------------------"
echo "To stop all services, run: pkill -f python && pkill -f node"
echo "To view logs, use: tail -f <module>.log"
