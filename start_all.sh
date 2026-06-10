#!/bin/bash
# Lab Manager Native Orchestrator (API-Only)
# Launches only Python components. Node.js is no longer required.

# ------------------------------------------------------------------
# DEBUGGING: Log every step of the start process to a separate file
# ------------------------------------------------------------------
# Determine root directory for logs and config
if [ -d "/opt/lm" ]; then
    ROOT_DIR="/opt/lm"
else
    ROOT_DIR="$(pwd)"
fi

LOG_DIR="/var/log/lm"
# Fallback to ROOT_DIR if /var/log/lm is not writable
if [ ! -w "$LOG_DIR" ]; then
    LOG_DIR="$ROOT_DIR/logs"
    mkdir -p "$LOG_DIR"
fi
LOG_FILE="$LOG_DIR/start_all.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ------------------------------------------------------------------
# CONFIGURATION: Hub Server URL
# ------------------------------------------------------------------
HUB_URL_FILE="$ROOT_DIR/hub_url.conf"
DEFAULT_HUB_URL="ws://localhost:8765"

# Parse arguments for --server
HUB_SERVER_OVERRIDE=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --server) HUB_SERVER_OVERRIDE="$2"; shift ;;
    esac
    shift
done

# Determine which URL to use
if [ -n "$HUB_SERVER_OVERRIDE" ]; then
    echo "🎯 Server override detected: $HUB_SERVER_OVERRIDE"
    echo "$HUB_SERVER_OVERRIDE" > "$HUB_URL_FILE"
    HUB_URL="$HUB_SERVER_OVERRIDE"
elif [ -f "$HUB_URL_FILE" ]; then
    HUB_URL=$(cat "$HUB_URL_FILE")
    echo "📖 Using saved Hub URL: $HUB_URL"
else
    HUB_URL="$DEFAULT_HUB_URL"
    echo "🌐 Using default Hub URL: $HUB_URL"
fi

echo "🕒 Start time: $(date)"
echo "🚀 Launching Lab Manager Stack (Native API-Only Mode)..."

# --- 0. Environment Setup ---
# We assume we are running from the project root where 'lm' folder and spokes exist
BASE_DIR="$(pwd)"

echo "🧹 Cleaning up existing processes..."
for port in 8000 8765; do
    PORT_PID=$(lsof -t -i :$port || true)
    if [ -n "$PORT_PID" ]; then
        echo "Found process $PORT_PID on port $port. Killing it..."
        kill -9 $PORT_PID || true
    fi
done
pkill -f python || true
pkill -f node || true
sleep 2

# --- 1. Launch Hub ---
echo "Starting Hub..."
HUB_DIR="$ROOT_DIR/core"
if [ ! -d "$HUB_DIR/src" ]; then
    echo "❌ Hub core not found at $HUB_DIR/src. Please run this script from the project root."
    exit 1
fi

export PYTHONPATH="$HUB_DIR/src:$PYTHONPATH"

# Launch Hub in background
nohup "$HUB_DIR/venv/bin/python3" "$HUB_DIR/src/main.py" > "$LOG_DIR/hub.log" 2>&1 &
echo "Hub started (logs: $LOG_DIR/hub.log)"
sleep 5 # Give hub time to initialize

# --- 2. Launch Spokes ---
SECRET="lm-secret"

# Define spokes and their folders
SPOKES=("cs" "pxmx" "opnsense" "cppm")

for spoke in "${SPOKES[@]}"; do
    SPOKE_DIR="$ROOT_DIR/$spoke"
    if [ -d "$SPOKE_DIR" ]; then
        echo "Starting $spoke..."
        cd "$SPOKE_DIR" || continue
        export PYTHONPATH="$SPOKE_DIR/src:$PYTHONPATH"

        # Determine the correct spoke ID
        case $spoke in
            "cs") SPOKE_ID="cs-spoke-1" ;;
            "pxmx") SPOKE_ID="pxmx-spoke-1" ;;
            "opnsense") SPOKE_ID="opn-spoke-1" ;;
            "cppm") SPOKE_ID="cppm-spoke-1" ;;
        esac

        nohup "$SPOKE_DIR/venv/bin/python3" "$SPOKE_DIR/src/control_plane.py" --id "$SPOKE_ID" --secret "$SECRET" --hub "$HUB_URL" > "$LOG_DIR/$spoke.log" 2>&1 &
        echo "$spoke started (logs: $LOG_DIR/$spoke.log)"
    else
        echo "⚠️  Warning: Spoke directory $SPOKE_DIR not found. Skipping..."
    fi
done

echo ""
echo "🎉 All systems launched in the background!"
echo "------------------------------------------------------------------"
echo "Hub API:   ${HUB_URL//ws\:\/\/http\:\/\/}"
echo "------------------------------------------------------------------"
echo "🕒 End time: $(date)"
