#!/bin/bash
set -e

# Default Configuration
HUB_URL="wss://localhost:443/ws/spoke"
SPOKE_ID="${SPOKE_ID:-pxmx-$(hostname -s)}"
SPOKE_SECRET="lm-secret"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --all-prereqs) ;;  # no-op (system prereqs are always installed); accepted so the Hub's install-module call doesn't abort
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    SPOKE_SECRET=""
    echo "ℹ️  No pre-shared secret — spoke will connect unauthenticated and await admin approval in the LM WebUI."
fi

echo "🚀 Installing Proxmox Manager Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl

INSTALL_DIR="/opt/lm"
OLD_INSTALL_DIR="/opt/lm-manager"

# Cleanup legacy installation
if [ -d "$OLD_INSTALL_DIR" ]; then
    echo "🗑️  Removing legacy installation at $OLD_INSTALL_DIR..."
    rm -rf "$OLD_INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d "pxmx/.git" ]; then
    echo "📂 PXMX repository already exists. Updating..."
    cd pxmx && git pull --rebase --autostash && cd ..
else
    echo "🌐 Cloning Proxmox Manager repository..."
    git clone https://github.com/lbockenstedt/pxmx.git
fi

echo "🛠️ Setting up Proxmox Manager..."
cd pxmx

# Always remove existing venv to ensure clean local environment (prevents cross-platform path issues)
echo "♻️ Resetting virtual environment..."
rm -rf venv

python3 -m venv venv
if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed."
    exit 1
fi

echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q
fi

# --- Persistence Configuration ---
echo "⚙️ Configuring Spoke Identity..."
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
# Unified-443 merge: this co-located pxmx spoke's agent listener runs in
# LOOPBACK mode — bind 127.0.0.1:8443 plaintext. TLS terminates at the hub's
# single :443 surface; the hub's /ws/agent route byte-proxies to this loopback
# listener. The 8443 loopback port is NOT advertised (mDNS agent_port TXT
# advertises the external 443).
LM_PXMX_AGENT_PORT=8443
LM_PXMX_AGENT_LOOPBACK=1
EOF

# --- Agent Secret (shared with local Proxmox agent on this machine) ---
# Preserve an existing agent_secret so a re-install doesn't break a running agent.
AGENT_CONFIG="/etc/lm-agent/config.json"
EXISTING_AGENT_SECRET=""
if [ -f "$AGENT_CONFIG" ]; then
    EXISTING_AGENT_SECRET=$(python3 -c "import json,sys; d=json.load(open('$AGENT_CONFIG')); print(d.get('agent_secret',''))" 2>/dev/null || true)
fi

if [ -z "$EXISTING_AGENT_SECRET" ]; then
    AGENT_SECRET=$(openssl rand -base64 32 | tr -d '/+=\n')
    echo "🔑 Generated new agent_secret."
else
    AGENT_SECRET="$EXISTING_AGENT_SECRET"
    echo "🔑 Preserved existing agent_secret."
fi

mkdir -p /etc/lm-agent
python3 -c "
import json, sys
path = '$AGENT_CONFIG'
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    data = {}
data['agent_secret'] = '$AGENT_SECRET'
with open(path, 'w') as f:
    json.dump(data, f, indent=2)
"
chmod 600 "$AGENT_CONFIG"
chown svc_lm:svc_lm "$AGENT_CONFIG" 2>/dev/null || true
echo "✅ Agent secret written to $AGENT_CONFIG"

# --- Systemd Service (For Remote/Independent Deployment) ---
echo "⚙️ Creating systemd service for auto-start..."

# Only pass --secret when a value is present; zero-touch provisioning handles the empty case
SECRET_ARG=""
[ -n "$SPOKE_SECRET" ] && SECRET_ARG="--secret=$SPOKE_SECRET"
HUB_SECRET_ARG=""
[ -n "${HUB_SECRET:-}" ] && HUB_SECRET_ARG="--hub-secret=$HUB_SECRET"

cat <<EOF > /etc/systemd/system/lm-pxmx.service
[Unit]
Description=Lab Manager Spoke - Proxmox Manager
After=network.target

[Service]
Type=simple
User=svc_lm
WorkingDirectory=$INSTALL_DIR/pxmx
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/pxmx/src"
EnvironmentFile=$INSTALL_DIR/pxmx/.env
ExecStart=$INSTALL_DIR/pxmx/venv/bin/python3 -m src.control_plane --id \$SPOKE_ID --hub \$HUB_URL $SECRET_ARG $HUB_SECRET_ARG
StandardOutput=append:/var/log/lm/lm-pxmx.log
StandardError=append:/var/log/lm/lm-pxmx.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-pxmx

# Apply new code now and prevent split-brain: stop the current instance, reap
# any orphaned/stale pxmx control_plane process left by a previous install
# (different unit or invocation), then start fresh. A stale instance holding
# the loopback :8443 while a new one reaches the hub with no agent is exactly
# the split-brain that makes the node agent invisible in the UI.
systemctl stop lm-pxmx 2>/dev/null || true
pkill -f 'control_plane.*--id pxmx-spoke-1' 2>/dev/null || true
sleep 1
systemctl start lm-pxmx

echo "🎉 Proxmox Manager installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"

# Print the agent install command so the admin knows what to run on each Proxmox node.
# Default to mDNS/DNS auto-discovery: the agent reads this hub's _lm-hub._tcp TXT
# agent_port record (443 — the unified external surface) and dials
# wss://<hub>:443/ws/agent automatically — no --spoke-url / port needed. Pinning
# is shown only as an optional fallback.
LM_HOST=$(echo "$HUB_URL" | sed 's|^wss://||;s|^ws://||' | cut -d: -f1)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Run this on each Proxmox node to install the pxmx agent:"
echo ""
echo "  curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \\"
echo "    | sudo bash"
echo "  (auto-discovers this hub via DNS lm-hub.* / mDNS _lm-hub._tcp — no port needed;"
echo "   the agent reads the hub's agent_port TXT record, 443, and dials wss://<hub>:443/ws/agent.)"
if [ -n "$LM_HOST" ]; then
    echo "  To pin instead:  --spoke-url wss://${LM_HOST}:443/ws/agent"
fi
echo "  (omitting --id derives <hostname>-agent; clone+rename auto-correlates via install UUID)"
echo ""
echo "  The agent will appear as 'Pending' in the LM WebUI (Setup → Spokes & Agents → Agents tile)."
echo "  Approve it there and the authentication secret will be provisioned automatically."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
