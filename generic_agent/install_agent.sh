#!/bin/bash
set -e

# ------------------------------------------------------------------
# Lab Manager Bootstrap Installer
# This script installs the Generic Agent and the necessary Core libraries
# so the agent can call home to the Hub and receive provisioning commands.
# ------------------------------------------------------------------

HUB_WS=""
SPOKE_ID=""
SPOKE_SECRET=""
HUB_SECRET=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_WS="$2"; shift ;;
        --id) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$HUB_WS" ] || [ -z "$SPOKE_ID" ] || [ -z "$SPOKE_SECRET" ]; then
    echo "❌ Missing required arguments: --hub, --id, and --secret are required."
    exit 1
fi

echo "🚀 Starting Lab Manager Bootstrap..."

# 1. Install System Dependencies
apt-get update
apt-get install -y python3-pip python3-venv git

# 2. Create service user
if ! id "svc_lm" &>/dev/null; then
    echo "👤 Creating service user svc_lm..."
    useradd -r -s /bin/false svc_lm
fi

# 3. Setup Directory Structure
ROOT_DIR="/opt/lm"
mkdir -p "$ROOT_DIR/core"
mkdir -p "$ROOT_DIR/generic-agent"

echo "📦 Deploying Core and Generic Agent files..."

# Assuming the script is run from the repo root or we have the files locally
# In a real-world scenario, these might be cloned from Git or downloaded as a tarball.
# For this installer, we copy from the current working directory.
if [ -d "core" ]; then
    cp -r core "$ROOT_DIR/"
else
    echo "⚠️  Core directory not found locally. Please run this from the repo root."
    exit 1
fi

if [ -d "generic_agent" ]; then
    cp -r generic_agent "$ROOT_DIR/generic-agent"
else
    echo "⚠️  generic_agent directory not found locally. Please run this from the repo root."
    exit 1
fi

# 4. Python Environment Setup
cd "$ROOT_DIR/generic-agent"
python3 -m venv venv
./venv/bin/python3 -m pip install --upgrade pip -q
# Install from requirements.txt (websockets, python-dotenv, psutil). agent.py
# imports psutil at module top — a bare `pip install websockets python-dotenv`
# here previously left the venv without psutil → ModuleNotFoundError crash-loop
# at boot. requirements.txt is the single source so this can't drift again.
if [ -f requirements.txt ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q
else
    ./venv/bin/python3 -m pip install websockets python-dotenv psutil -q
fi

# Log directory shared with the hub + spokes; the systemd service runs as
# svc_lm and agent.py writes /var/log/lm/agent.log directly (no root
# shell to pre-open the redirect), so svc_lm must own the dir.
mkdir -p /var/log/lm
chown -R svc_lm:svc_lm /var/log/lm 2>/dev/null || true

# 5. Systemd Service Setup
# Note: We add PYTHONPATH=/opt/lm so that 'import core...' works.
cat <<EOF > /etc/systemd/system/lm-bootstrap.service
[Unit]
Description=Lab Manager Bootstrap Agent
After=network.target

[Service]
User=svc_lm
WorkingDirectory=$ROOT_DIR/generic-agent
Environment="PYTHONPATH=$ROOT_DIR"
ExecStart=$ROOT_DIR/generic-agent/venv/bin/python3 $ROOT_DIR/generic-agent/src/agent.py --id $SPOKE_ID --secret $SPOKE_SECRET --hub-secret $HUB_SECRET --hub $HUB_WS
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-bootstrap
systemctl restart lm-bootstrap

echo "🎉 Bootstrap installation complete! The agent is now calling home to $HUB_WS"
