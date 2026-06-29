#!/usr/bin/env bash
# Lab Manager — Generic Agent Installer
#
# Deploys the morphable LM agent on a remote server.
# Once installed, assign a role from the hub:
#   POST /api/agent/<spoke_id>/command  {"command":"LOAD_ROLE","data":{"role":"dns"}}
#
# The lm repo is cloned to /opt/lm on this server so all role code is local.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
#     | sudo bash -s -- --hub ws://HUB_IP:8765 [--role dns] [--id my-agent-1]
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-agent"
ENV_FILE="$INSTALL_DIR/agent/.env"
LM_BRANCH="${LM_BRANCH:-main}"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""; STARTUP_ROLE=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)    HUB_URL="$2";      shift ;;
        --id)     SPOKE_ID="$2";     shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --role)   STARTUP_ROLE="$2"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

[[ -z "$HUB_URL" ]] && { echo "Usage: $0 --hub <ws://HUB:8765> [--id my-agent-1] [--role dns]"; exit 1; }
SPOKE_ID="${SPOKE_ID:-agent-$(hostname -s)}"
mkdir -p /var/log/lm

# System deps
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl

# Clone or update the LM repo (contains agent + all roles)
if [[ -d "$INSTALL_DIR/core" ]]; then
    echo "Updating existing LM installation…"
    git -C "$INSTALL_DIR" pull --rebase --autostash -q 2>/dev/null || true
else
    echo "Cloning LM repo…"
    git clone -q --branch "$LM_BRANCH" https://github.com/lbockenstedt/lm.git "$INSTALL_DIR"
fi

# Python venv for agent
cd "$INSTALL_DIR/agent"
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q
[[ -f requirements.txt ]] && ./venv/bin/pip install -r requirements.txt -q

# Also install role-specific requirements if role is set
if [[ -n "$STARTUP_ROLE" ]] && [[ -f "$INSTALL_DIR/$STARTUP_ROLE/requirements.txt" ]]; then
    ./venv/bin/pip install -r "$INSTALL_DIR/$STARTUP_ROLE/requirements.txt" -q
fi

# Preserve an existing secret so re-installs don't break a running agent.
if [[ -f "$ENV_FILE" ]] && grep -q "^SPOKE_SECRET=" "$ENV_FILE"; then
    EXISTING=$(grep "^SPOKE_SECRET=" "$ENV_FILE" | cut -d= -f2-)
    [[ -n "$EXISTING" ]] && SPOKE_SECRET="$EXISTING" && echo "Preserving existing spoke secret."
fi

if [[ -z "$SPOKE_SECRET" ]]; then
    echo "ℹ️  No pre-shared secret. Agent will connect unauthenticated and await admin approval."
    echo "   Approve it in the LM WebUI (Setup → Spoke Approvals) to complete provisioning."
fi

cat > "$ENV_FILE" <<EOF
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_URL=$HUB_URL
STARTUP_ROLE=${STARTUP_ROLE:-}
EOF
chmod 600 "$ENV_FILE"

ROLE_ARG=""
[[ -n "$STARTUP_ROLE" ]] && ROLE_ARG="--role $STARTUP_ROLE"

# Only pass --secret if we have one; otherwise agent connects in zero-touch mode.
SECRET_ARG=""
[[ -n "$SPOKE_SECRET" ]] && SECRET_ARG="--secret \$SPOKE_SECRET"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager Generic Agent ($SPOKE_ID)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/agent/src"
WorkingDirectory=$INSTALL_DIR/agent/src
ExecStart=$INSTALL_DIR/agent/venv/bin/python3 control_plane.py --id \$SPOKE_ID $SECRET_ARG --hub \$HUB_URL $ROLE_ARG
StandardOutput=append:/var/log/lm/lm-agent.log
StandardError=append:/var/log/lm/lm-agent.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "Generic agent installed (ID: $SPOKE_ID, role: ${STARTUP_ROLE:-none})"
