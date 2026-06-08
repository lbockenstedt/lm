#!/bin/bash
# Lab Manager Native Orchestrator (API-Only)
# Launches only Python components. Node.js is no longer required.

# ------------------------------------------------------------------
# DEBUGGING: Log every step of the start process to a separate file
# ------------------------------------------------------------------
LOG_FILE="/root/lab-manager/lm/start_all.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "🕒 Start time: $(date)"
echo "🚀 Launching Lab Manager Stack (Native API-Only Mode)..."

# Get the absolute paths
BASE_DIR="/root/lab-manager/lm"
PARENT_DIR="/root/lab-manager"

# Ensure we are in the correct directory
cd "$BASE_DIR" || { echo "❌ Failed to cd to $BASE_DIR"; exit 1; }

echo "🧹 Cleaning up existing processes..."
# Use absolute paths for binaries to ensure systemd can find them
for port in 8000 8765; do
    PORT_PID=$(/usr/bin/lsof -t -i :$port || true)
    if [ -n "$PORT_PID" ]; then
        echo "Found process $PORT_PID on port $port. Killing it..."
        /usr/bin/kill -9 $PORT_PID || true
    fi
done
/usr/bin/pkill -f python || true
/usr/bin/pkill -f node || true
sleep 2

# --- 1. Launch Hub ---
echo "Starting Hub..."
# Set PYTHONPATH to include the hub source directory so imports work
export PYTHONPATH="$BASE_DIR/hub/src:$PYTHONPATH"

# Launch Hub in background
/usr/bin/nohup "$BASE_DIR/venv/bin/python3" "$BASE_DIR/hub/src/main.py" > "$BASE_DIR/hub.log" 2>&1 &
echo "Hub started (logs: $BASE_DIR/hub.log)"
sleep 5 # Give hub time to initialize

# --- 2. Launch Spokes ---
SECRET="lab-manager-secret"

# Define spokes and their folders
SPOKES=("cs" "pxmx" "opnsense" "cppm")

for spoke in "${SPOKES[@]}"; do
    SPOKE_DIR="$PARENT_DIR/$spoke"
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

        /usr/bin/nohup "$SPOKE_DIR/venv/bin/python3" -m src.control_plane --id "$SPOKE_ID" --secret "$SECRET" --hub ws://localhost:8765 > "$BASE_DIR/$spoke.log" 2>&1 &
        echo "$spoke started (logs: $BASE_DIR/$spoke.log)"
    else
        echo "⚠️  Warning: Spoke directory $SPOKE_DIR not found. Skipping..."
    fi
done

echo ""
echo "🎉 All systems launched in the background!"
echo "------------------------------------------------------------------"
echo "Hub API:   http://localhost:8000"
echo "------------------------------------------------------------------"
echo "🕒 End time: $(date)"
