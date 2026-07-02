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
#     | sudo bash -s -- --hub ws://HUB_IP:8765 [--role <role>] [--id my-agent-1]
#   Roles: dns | dhcp | network | netbox | opnsense | ldap | simulation | cppm
#   (omit --role for a bare agent that morphs later via LOAD_ROLE from the hub)
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

[[ -z "$HUB_URL" ]] && { echo "Usage: $0 --hub <ws://HUB:8765> [--id my-agent-1] [--role dns|dhcp|network|netbox|opnsense|ldap|simulation|cppm]"; exit 1; }
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

# Stage the startup role's code + Python deps.
#   - in-repo roles (dns, dhcp) ship inside the lm clone already.
#   - sibling roles (network, netbox, opnsense, ldap, simulation, cppm) live in
#     separate GitHub repos; clone them shallowly into /opt/lm/<dir> so the
#     boot-time --role load (which does NOT run the agent's _install_role) can
#     find the spoke code immediately. requirements.txt path mirrors the
#     agent's role_file.parent.parent derivation (simulation's is under cs/lm-spoke).
if [[ -n "$STARTUP_ROLE" ]]; then
    ROLE_REPO=""; ROLE_CLONE_DIR=""; ROLE_REQ=""
    case "$STARTUP_ROLE" in
        dns)        ROLE_REQ="$INSTALL_DIR/dns/requirements.txt" ;;
        dhcp)       ROLE_REQ="$INSTALL_DIR/dhcp/requirements.txt" ;;
        network)    ROLE_REPO="https://github.com/lbockenstedt/nw.git";        ROLE_CLONE_DIR="nw";       ROLE_REQ="$INSTALL_DIR/nw/requirements.txt" ;;
        netbox)     ROLE_REPO="https://github.com/lbockenstedt/netbox.git";    ROLE_CLONE_DIR="netbox";   ROLE_REQ="$INSTALL_DIR/netbox/requirements.txt" ;;
        opnsense)   ROLE_REPO="https://github.com/lbockenstedt/opnsense.git";  ROLE_CLONE_DIR="opnsense"; ROLE_REQ="$INSTALL_DIR/opnsense/requirements.txt" ;;
        ldap)       ROLE_REPO="https://github.com/lbockenstedt/ldap.git";      ROLE_CLONE_DIR="ldap";     ROLE_REQ="$INSTALL_DIR/ldap/requirements.txt" ;;
        simulation) ROLE_REPO="https://github.com/lbockenstedt/cs.git";        ROLE_CLONE_DIR="cs";       ROLE_REQ="$INSTALL_DIR/cs/lm-spoke/requirements.txt" ;;
        cppm)       ROLE_REPO="https://github.com/lbockenstedt/cppm.git";      ROLE_CLONE_DIR="cppm";     ROLE_REQ="$INSTALL_DIR/cppm/requirements.txt" ;;
        *) echo "❌ Unknown role '$STARTUP_ROLE'"; echo "Valid: dns dhcp network netbox opnsense ldap simulation cppm"; exit 1 ;;
    esac

    if [[ -n "$ROLE_REPO" ]]; then
        if [[ -d "$INSTALL_DIR/$ROLE_CLONE_DIR" ]]; then
            echo "Updating role repo '$ROLE_CLONE_DIR'…"
            git -C "$INSTALL_DIR/$ROLE_CLONE_DIR" pull --rebase --autostash -q 2>/dev/null || true
        else
            echo "Cloning role repo '$ROLE_CLONE_DIR'…"
            git clone -q --depth 1 "$ROLE_REPO" "$INSTALL_DIR/$ROLE_CLONE_DIR"
        fi
    fi

    if [[ -f "$ROLE_REQ" ]]; then
        echo "Installing Python deps for role '$STARTUP_ROLE'…"
        ./venv/bin/pip install -r "$ROLE_REQ" -q
    else
        echo "⚠️  No requirements.txt found at $ROLE_REQ for role '$STARTUP_ROLE'"
    fi
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
