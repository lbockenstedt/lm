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

echo "🚀 Starting Lab Manager GitHub Bootstrap..."

# 1. Install System Dependencies
apt-get update && apt-get install -y python3-pip python3-venv git

# 2. Create service user
if ! id "svc_lm" &>/dev/null; then
    echo "👤 Creating service user svc_lm..."
    useradd -r -s /bin/false svc_lm
fi

# 3. Setup Directory Structure
ROOT_DIR="/opt/lm"
mkdir -p "$ROOT_DIR/core"
mkdir -p "$ROOT_DIR/generic-agent"

echo "📦 Cloning Core and Generic Agent from GitHub..."
REPO_URL="https://github.com/lbockenstedt/lm"

git clone --depth 1 "$REPO_URL" "$ROOT_DIR/tmp_repo"
cp -r "$ROOT_DIR/tmp_repo/core" "$ROOT_DIR/"
cp -r "$ROOT_DIR/tmp_repo/generic_agent" "$ROOT_DIR/generic-agent"
rm -rf "$ROOT_DIR/tmp_repo"

# 4. Python Environment Setup
cd "$ROOT_DIR/generic-agent"
python3 -m venv venv
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install websockets python-dotenv -q

# 5. Systemd Service Setup
# We use a template-like approach or just write the file.
cat <<EOF > /etc/systemd/system/lm-bootstrap.service
[Unit]
Description=Lab Manager Bootstrap Agent
After=network.target

[Service]
User=svc_lm
WorkingDirectory=$ROOT_DIR/generic-agent
Environment="PYTHONPATH=$ROOT_DIR"
ExecStart=$ROOT_DIR/generic-agent/venv/bin/python3 $ROOT_DIR/generic-agent/src/agent.py --id $SPOKE_ID --secret $SPOKE_SECRET --hub-secret $HUB_SECRET --hub $HUB_WS
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Enable the service so it starts on next reboot
systemctl enable lm-bootstrap

if [ "$CLONE_ONLY" = true ]; then
    echo "❄️  Clone-only mode active. Files and service enabled, but service is NOT started."
    echo "The agent will start automatically on the next reboot."
    echo "Note: To change the spoke ID manually, edit /etc/systemd/system/lm-bootstrap.service"
else
    systemctl restart lm-bootstrap
    echo "🎉 Bootstrap installation complete! The agent is now calling home to $HUB_WS"
    echo "You can now approve this spoke in the Hub WebUI to negotiate its session secret."
fi
