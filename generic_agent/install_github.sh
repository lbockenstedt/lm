#!/bin/bash
# ------------------------------------------------------------------
# Lab Manager GitHub Bootstrap
# This script allows for direct installation of the Generic Agent from GitHub.
# ------------------------------------------------------------------

set -e

HUB_WS=""
SPOKE_ID=""
SPOKE_SECRET=""
HUB_SECRET=""
CLONE_ONLY=false

# --- Logging Setup ---
LOG_DIR="/var/log/lm"
INSTALL_LOG="$LOG_DIR/generic-agent-install.log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR" 2>/dev/null || true
chmod 755 "$LOG_DIR" 2>/dev/null || true

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$INSTALL_LOG" 2>/dev/null || true
}

log_c() {
    echo "$1"
    log "$1"
}

log_e() {
    echo "❌ $1" >&2
    log "ERROR: $1"
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_WS="$2"; shift ;;
        --id) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --clone) CLONE_ONLY=true; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# If not in clone mode, we still need the HUB_WS to configure the service
if [ "$CLONE_ONLY" = false ] && [ -z "$HUB_WS" ]; then
    echo "❌ Missing required argument: --hub is required for full installation."
    echo "Usage: curl -sSL <url> | sudo bash -s -- --hub <hub_ws>"
    exit 1
fi

log_c "🚀 Starting Lab Manager GitHub Bootstrap..."

# 1. Install System Dependencies
log_c "📦 Installing system dependencies..."
apt-get update >> "$INSTALL_LOG" 2>&1
apt-get install -y python3-pip python3-venv git >> "$INSTALL_LOG" 2>&1

# 2. Create service user
if ! id "svc_lm" &>/dev/null; then
    log_c "👤 Creating service user svc_lm..."
    useradd -r -s /bin/false svc_lm >> "$INSTALL_LOG" 2>&1
fi

# 3. Setup Directory Structure
ROOT_DIR="/opt/lm"
log_c "📁 Setting up directories in $ROOT_DIR..."
mkdir -p "$ROOT_DIR/core" >> "$INSTALL_LOG" 2>&1
mkdir -p "$ROOT_DIR/generic-agent" >> "$INSTALL_LOG" 2>&1

log_c "📦 Cloning Core and Generic Agent from GitHub..."
REPO_URL="https://github.com/lbockenstedt/lm"

# Clone to temporary location
git clone --depth 1 "$REPO_URL" "$ROOT_DIR/tmp_repo" >> "$INSTALL_LOG" 2>&1
cp -r "$ROOT_DIR/tmp_repo/core" "$ROOT_DIR/" >> "$INSTALL_LOG" 2>&1
cp -r "$ROOT_DIR/tmp_repo/generic_agent" "$ROOT_DIR/generic-agent" >> "$INSTALL_LOG" 2>&1
rm -rf "$ROOT_DIR/tmp_repo"

# 4. Python Environment Setup
log_c "🐍 Setting up Python environment..."
cd "$ROOT_DIR/generic-agent"
python3 -m venv venv >> "$INSTALL_LOG" 2>&1
./venv/bin/python3 -m pip install --upgrade pip -q >> "$INSTALL_LOG" 2>&1
./venv/bin/python3 -m pip install websockets python-dotenv -q >> "$INSTALL_LOG" 2>&1

# 5. Systemd Service Setup
log_c "⚙️ Configuring systemd service..."
cat <<EOF > /etc/systemd/system/lm-bootstrap.service
[Unit]
Description=Lab Manager Bootstrap Agent
After=network.target

[Service]
User=svc_lm
WorkingDirectory=$ROOT_DIR/generic-agent
Environment="PYTHONPATH=$ROOT_DIR"
ExecStart=$ROOT_DIR/generic-agent/venv/bin/python3 $ROOT_DIR/generic-agent/src/agent.py --id $SPOKE_ID --secret $SPOKE_SECRET --hub-secret $HUB_SECRET --hub $HUB_WS
StandardOutput=append:/var/log/lm/generic-agent.log
StandardError=append:/var/log/lm/generic-agent.log
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Enable the service so it starts on next reboot
systemctl enable lm-bootstrap

if [ "$CLONE_ONLY" = true ]; then
    log_c "❄️  Clone-only mode active. Files and service enabled, but service is NOT started."
    echo "The agent will start automatically on the next reboot."
    echo "Note: To change the spoke ID manually, edit /etc/systemd/system/lm-bootstrap.service"
else
    log_c "🔄 Starting agent service..."
    systemctl restart lm-bootstrap
    log_c "🎉 Bootstrap installation complete! The agent is now calling home to $HUB_WS"
    echo "--------------------------------------------------------------------------------"
    echo "Logs are available at: $INSTALL_LOG and $LOG_DIR/generic-agent.log"
    echo "You can now approve this spoke in the Hub WebUI to negotiate its session secret."
    echo "--------------------------------------------------------------------------------"
fi
