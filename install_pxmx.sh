#!/bin/bash
set -e

# Default Configuration
HUB_URL="wss://localhost:443/ws/spoke"
SPOKE_ID="${SPOKE_ID:-pxmx-$(hostname -s)}"
SPOKE_SECRET="lm-secret"
# Agent-listener mode. DEFAULT standalone (agent → spoke → hub): this pxmx spoke
# is on its OWN box, serves wss on :443 so a remote Proxmox agent dials
# wss://<this-spoke>:443/ws/agent directly, and this spoke talks to the hub
# outbound. --loopback flips to all-in-one/co-located mode (hub on the SAME
# box): bind 127.0.0.1:8443 plaintext, hub /ws/agent byte-proxies to it. --loopback
# is intended to be passed ONLY by install_all.sh (the rare co-located all-in-one
# path); a standalone install never sets it. See docs/pxmx.md "Agent listener
# modes".
PXMX_LOOPBACK=0

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --loopback) PXMX_LOOPBACK=1 ;;
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
# Standalone (default): this pxmx spoke serves wss on :443 directly (remote
# Proxmox agents dial wss://<this-spoke>:443/ws/agent — agent → spoke → hub) and
# talks to the hub outbound. A self-signed cert is generated for the listener
# (skipped gracefully if openssl is absent → falls back to plaintext :8766).
# Loopback (--loopback, install_all only): no cert — bind 127.0.0.1:8443
# plaintext; the hub /ws/agent route byte-proxies to it (TLS terminates at the
# hub's :443, which the hub owns).
PXMX_CERT_DIR="$INSTALL_DIR/pxmx/certs"
PXMX_CERT="$PXMX_CERT_DIR/hub.crt"
PXMX_KEY="$PXMX_CERT_DIR/hub.key"
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
EOF
if [ "$PXMX_LOOPBACK" = "1" ]; then
    {
        echo "# Loopback (all-in-one, --loopback): bind 127.0.0.1:8443 plaintext;"
        echo "# the hub /ws/agent route byte-proxies here. TLS terminates at the hub :443."
        echo "LM_PXMX_AGENT_PORT=8443"
        echo "LM_PXMX_AGENT_LOOPBACK=1"
    } >> .env
else
    mkdir -p "$PXMX_CERT_DIR"
    if ! command -v openssl >/dev/null 2>&1; then
        echo "⚠️  openssl not found — skipping pxmx TLS cert (agent listener stays plaintext :8766)."
    elif [ -f "$PXMX_CERT" ] && [ -f "$PXMX_KEY" ]; then
        echo "🔒 pxmx TLS cert already present at $PXMX_CERT — preserving."
    else
        echo "🔒 Generating self-signed pxmx TLS cert at $PXMX_CERT…"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$PXMX_KEY" -out "$PXMX_CERT" -days 3650 \
            -subj "/CN=lm-pxmx" -addext "subjectAltName=IP:127.0.0.1,DNS:lm-hub,DNS:lm-hub.local" \
            >/dev/null 2>&1 || echo "⚠️  openssl cert generation failed — agent listener stays plaintext."
    fi
    if [ -f "$PXMX_KEY" ]; then
        chmod 600 "$PXMX_KEY"
        chown svc_lm:svc_lm "$PXMX_KEY" "$PXMX_CERT" 2>/dev/null || true
    fi
    {
        echo "LM_TLS_CERT=$PXMX_CERT"
        echo "LM_TLS_KEY=$PXMX_KEY"
        echo "LM_PXMX_AGENT_PORT=443"
    } >> .env
fi

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

# Agent-listener port per mode: 443 wss standalone (default), 8443 loopback
# (--loopback / install_all co-located). AmbientCapabilities lets svc_lm bind
# 443 non-root (harmless in loopback, which binds 8443 >1024).
if [ "$PXMX_LOOPBACK" = "1" ]; then
    PXMX_AGENT_PORT_UNIT=8443
else
    PXMX_AGENT_PORT_UNIT=443
fi

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
# Agent listener: standalone serves wss on :443 (remote Proxmox agents dial
# wss://<this-spoke>:443/ws/agent directly — agent → spoke → hub); loopback
# (--loopback, install_all co-located only) binds 127.0.0.1:8443 plaintext and
# the hub /ws/agent route byte-proxies to it (agent → hub → spoke).
Environment=LM_PXMX_AGENT_PORT=$PXMX_AGENT_PORT_UNIT
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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
# Standalone (default): the agent dials THIS spoke directly (agent → spoke → hub).
#   A standalone spoke does NOT broadcast _lm-hub mDNS (only the hub does), so the
#   agent cannot auto-discover it — --spoke-url (pinned to this box) is REQUIRED.
# Loopback (--loopback, install_all co-located): the agent auto-discovers the HUB
#   via _lm-hub mDNS / lm-hub DNS and dials wss://<hub>:443/ws/agent; the hub's
#   /ws/agent route byte-proxies to this spoke's loopback :8443.
LM_HOST=$(echo "$HUB_URL" | sed 's|^wss://||;s|^ws://||' | cut -d: -f1)
SPOKE_HOST="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -1)"
[ -z "$SPOKE_HOST" ] && SPOKE_HOST="$(hostname -s)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Run this on each Proxmox node to install the pxmx agent:"
echo ""
echo "  curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \\"
if [ "$PXMX_LOOPBACK" = "1" ]; then
    echo "    | sudo bash"
    echo "  (loopback/all-in-one: the agent auto-discovers the HUB via DNS lm-hub.* / mDNS"
    echo "   _lm-hub._tcp and dials wss://<hub>:443/ws/agent; the hub /ws/agent route"
    echo "   byte-proxies to this spoke's loopback :8443 — agent → hub → spoke.)"
    if [ -n "$LM_HOST" ]; then
        echo "  To pin instead:  --spoke-url wss://${LM_HOST}:443/ws/agent"
    fi
else
    echo "    | sudo bash -s -- --spoke-url wss://${SPOKE_HOST}:443/ws/agent"
    echo "  (standalone spoke: the agent dials THIS spoke directly — agent → spoke → hub."
    echo "   A standalone spoke does not broadcast _lm-hub mDNS, so --spoke-url is REQUIRED.)"
fi
echo "  (omitting --id derives <hostname>-agent; clone+rename auto-correlates via install UUID)"
echo ""
echo "  The agent will appear as 'Pending' in the LM WebUI (Setup → Spokes & Agents → Agents tile)."
echo "  Approve it there and the authentication secret will be provisioned automatically."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
