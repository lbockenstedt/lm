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
# Unified agent-spoke model: this box runs ONE agent (which hosts every
# module as a role). Kill only a manually-launched agent this script started —
# do NOT touch an enabled lm-agent systemd unit (killing it just makes systemd
# respawn it, and a second launch here would split-brain the agent socket, so
# the agent vanishes from the UI / GET_AGENTS returns []).
if ! systemctl is-enabled --quiet lm-agent 2>/dev/null; then
    pkill -f "agent/src/control_plane.py" 2>/dev/null || true
fi
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

# --- 2. Launch the unified agent (hosts every module as a role) ---
# One agent replaces the former per-module dedicated spokes. If a
# dedicated lm-agent systemd unit is enabled, that unit owns it — don't launch a
# duplicate (it races Restart=always and split-brains the agent socket).
AGENT_DIR="$ROOT_DIR/agent"
if systemctl is-enabled --quiet lm-agent 2>/dev/null; then
    log_c "lm-agent has a dedicated systemd unit — leaving it to the unit, not launching a duplicate."
elif [ -d "$AGENT_DIR/src" ]; then
    log_c "Starting unified agent..."
    cd "$AGENT_DIR" || true
    export PYTHONPATH="$AGENT_DIR/src:$ROOT_DIR:$ROOT_DIR/core/src:${PYTHONPATH:-}"
    # Roles persist in the agent .env (LOADED_ROLES); pass them so the agent
    # re-hosts each role sub-spoke on this manual launch too.
    AGENT_ROLES_ARG=""
    if [ -f "$AGENT_DIR/.env" ]; then
        _LR=$(grep "^LOADED_ROLES=" "$AGENT_DIR/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
        [ -n "$_LR" ] && AGENT_ROLES_ARG="--roles $_LR"
    fi
    nohup "$AGENT_DIR/venv/bin/python3" "$AGENT_DIR/src/control_plane.py" --hub "$HUB_URL" $AGENT_ROLES_ARG > "$LOG_DIR/agent.log" 2>&1 &
    log_c "unified agent started (logs: $LOG_DIR/agent.log)${_LR:+ with roles: $_LR}"
else
    log_w "Agent directory $AGENT_DIR not found (runs on another host?). Skipping agent launch."
fi

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