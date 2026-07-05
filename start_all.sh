#!/bin/bash
# Lab Manager Native Orchestrator (API-Only)
# Launches only Python components. Node.js is no longer required.
set -euo pipefail

# ------------------------------------------------------------------
# DEBUGGING: Log every step of the start process to a separate file
# ------------------------------------------------------------------
# Determine root directory for logs and config
if [ -d "/opt/lm" ]; then
    ROOT_DIR="/opt/lm"
    SPOKE_ROOT="/opt/lm"
else
    ROOT_DIR="$(pwd)"
    SPOKE_ROOT="$(dirname "$ROOT_DIR")"
fi

LOG_DIR="/var/log/lm"
# Fallback to ROOT_DIR if /var/log/lm is not writable
if [ ! -w "$LOG_DIR" ]; then
    LOG_DIR="$ROOT_DIR/logs"
    mkdir -p "$LOG_DIR"
fi
LOG_FILE="$LOG_DIR/start_all.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Logging helpers — copied from install_all.sh so this launcher surfaces
# failures the same way the installer does. ``log`` appends a timestamped line
# directly to LOG_FILE; ``log_c`` prints to the console (and, via the exec tee
# above, to LOG_FILE) for high-level progress; ``log_e`` prints to stderr and
# logs ERROR. None of them exit — callers decide that.
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_c() {
    echo "$1"
    log "$1"
}

log_e() {
    echo "❌ $1" >&2
    log "ERROR: $1"
}

log_w() {
    # Warning: console + file, but NOT logged as ERROR — keeps expected
    # conditions (e.g. a spoke that runs on another host) out of the hub's
    # Error Log / BugFixer, which key off the "error" token.
    echo "⚠️  $1" >&2
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE" 2>/dev/null || true
}

# ------------------------------------------------------------------
# CONFIGURATION: Hub Server URL
# ------------------------------------------------------------------
HUB_URL_FILE="$ROOT_DIR/hub_url.conf"
DEFAULT_HUB_URL="wss://localhost:443/ws/spoke"

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
    log_c "🎯 Server override detected: $HUB_SERVER_OVERRIDE"
    echo "$HUB_SERVER_OVERRIDE" > "$HUB_URL_FILE" || log_e "Failed to save Hub URL to $HUB_URL_FILE"
    HUB_URL="$HUB_SERVER_OVERRIDE"
elif [ -f "$HUB_URL_FILE" ]; then
    HUB_URL=$(cat "$HUB_URL_FILE")
    log_c "📖 Using saved Hub URL: $HUB_URL"
else
    HUB_URL="$DEFAULT_HUB_URL"
    log_c "🌐 Using default Hub URL: $HUB_URL"
fi

log_c "🕒 Start time: $(date)"
log_c "🚀 Launching Lab Manager Stack (Native API-Only Mode)..."

# --- 0. Environment Setup ---
# We assume we are running from the project root where 'lm' folder and spokes exist
BASE_DIR="$(pwd)"

log_c "🧹 Cleaning up existing processes..."
# Clear the unified 443 port (real hub), 8000 (boot probe / legacy hub), and
# 8765 (legacy spoke-WS) so nothing stale can hold the hub's bind.
for port in 443 8000 8765; do
    PORT_PID=$(lsof -t -i :$port || true)
    if [ -n "$PORT_PID" ]; then
        log_c "Found process $PORT_PID on port $port. Killing it..."
        kill -9 $PORT_PID || true
    fi
done
# Kill only the spokes this script manages — do NOT kill separately-managed
# systemd services (lm-ldap, lm-netbox, lm-dns, lm-dhcp), and do NOT touch
# spokes that have their own dedicated, enabled lm-<spoke> systemd unit. Those
# units own the spoke (with Restart=always); killing the unit's process here
# just makes systemd respawn it, and if this script then also launches the
# spoke we get a split-brain — two processes on the same spoke_id where only
# one holds the agent socket, so the agent vanishes from the UI
# (GET_AGENTS returns []).
for spoke in cs pxmx opnsense cppm; do
    if systemctl is-enabled --quiet "lm-$spoke" 2>/dev/null; then
        continue
    fi
    case $spoke in
        cs) id="cs-spoke-1" ;; pxmx) id="pxmx-spoke-1" ;;
        opnsense) id="opn-spoke-1" ;; cppm) id="cppm-spoke-1" ;;
    esac
    pkill -f "$id" 2>/dev/null || true
done
sleep 2

# --- 1. Launch Hub ---
log_c "Starting Hub..."
HUB_DIR="$ROOT_DIR/core"
if [ ! -d "$HUB_DIR/src" ]; then
    log_e "Hub core not found at $HUB_DIR/src. Please run this script from the project root."
    exit 1
fi

export PYTHONPATH="$HUB_DIR/src:${PYTHONPATH:-}"

# Load Hub environment variables (.env contains LM_FERNET_KEY and other secrets)
if [ -f "$ROOT_DIR/.env" ]; then
    set -a
    source "$ROOT_DIR/.env" || log_e "Failed to source $ROOT_DIR/.env"
    set +a
fi

# Launch Hub in background
nohup "$HUB_DIR/venv/bin/python3" "$HUB_DIR/src/main.py" > "$LOG_DIR/hub.log" 2>&1 &
log_c "Hub started (logs: $LOG_DIR/hub.log)"
sleep 5 # Give hub time to initialize

# --- 2. Launch Spokes ---
# Define spokes and their folders
SPOKES=("cs" "pxmx" "opnsense" "cppm")

for spoke in "${SPOKES[@]}"; do
    SPOKE_DIR="$SPOKE_ROOT/$spoke"
    if [ -d "$SPOKE_DIR" ]; then
        # If this spoke has its own dedicated, enabled systemd unit (lm-<spoke>),
        # let that unit own it — do NOT launch a second instance here. Launching
        # here races the unit (Restart=always) and creates a split-brain: two
        # processes share the same spoke_id but only one holds the agent socket,
        # so the agent disappears from the UI (GET_AGENTS returns []).
        if systemctl is-enabled --quiet "lm-$spoke" 2>/dev/null; then
            log_c "$spoke has a dedicated systemd unit (lm-$spoke) — leaving it to the unit, not launching a duplicate."
            continue
        fi
        log_c "Starting $spoke..."
        cd "$SPOKE_DIR" || continue
        export PYTHONPATH="$SPOKE_DIR/src:$ROOT_DIR:${PYTHONPATH:-}"

        # Determine the correct spoke ID
        case $spoke in
            "cs") SPOKE_ID="cs-$(hostname -s)" ;;
            "pxmx") SPOKE_ID="pxmx-$(hostname -s)" ;;
            "opnsense") SPOKE_ID="opn-$(hostname -s)" ;;
            "cppm") SPOKE_ID="cppm-$(hostname -s)" ;;
        esac

        # Read SPOKE_SECRET and HUB_SECRET from the spoke's own .env. The grep
        # pipelines are guarded with `|| true` because a missing key line is the
        # normal case (zero-touch spokes have no secret) — under set -e + pipefail
        # an unguarded no-match grep would abort the launch.
        SECRET="lm-secret"
        HUB_SECRET_ARG=""
        if [ -f ".env" ]; then
            SPOKE_SECRET_FILE=$(grep "^SPOKE_SECRET=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" || true)
            [ -n "$SPOKE_SECRET_FILE" ] && SECRET="$SPOKE_SECRET_FILE"
            SPOKE_HUB_SECRET=$(grep "^HUB_SECRET=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" || true)
            [ -n "$SPOKE_HUB_SECRET" ] && HUB_SECRET_ARG="--hub-secret $SPOKE_HUB_SECRET"
        fi

        nohup "$SPOKE_DIR/venv/bin/python3" "$SPOKE_DIR/src/control_plane.py" --id "$SPOKE_ID" --secret "$SECRET" --hub "$HUB_URL" $HUB_SECRET_ARG > "$LOG_DIR/$spoke.log" 2>&1 &
        log_c "$spoke started (logs: $LOG_DIR/$spoke.log) with secret ${SECRET:0:4}...${SECRET: -4}"
    else
        log_w "Spoke directory $SPOKE_DIR not found (runs on another host?). Skipping..."
    fi
done

log_c ""
log_c "🎉 All systems launched in the background!"
log_c "------------------------------------------------------------------"
# HUB_URL is the spoke-WS URL (wss://…:443/ws/spoke). Derive the WebUI/API URL
# from it for the printed dashboard line (wss→https, strip the /ws/spoke path).
_HUB_WEBUI="${HUB_URL%%/ws/spoke}"
_HUB_WEBUI="${_HUB_WEBUI/wss:\/\//https:\/\/}"
_HUB_WEBUI="${_HUB_WEBUI/ws:\/\//http:\/\/}"
log_c "Hub WebUI: $_HUB_WEBUI"
log_c "Spoke WS:  $HUB_URL"
log_c "------------------------------------------------------------------"
log_c "🕒 End time: $(date)"