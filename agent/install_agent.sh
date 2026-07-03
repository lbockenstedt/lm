#!/usr/bin/env bash
# Lab Manager — Generic Agent Installer
#
# Deploys the morphable LM agent on a remote server. A generic agent can HOST
# multiple roles at once: each loaded role opens its own sub-spoke
# ({spoke_id}-{role}) that auto-approves via this agent. Assign roles from the
# hub WebUI (Load Role) or pre-load them at boot with --roles.
#
# The lm repo is cloned to /opt/lm on this server so all role code is local.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
#     | sudo bash -s -- --hub wss://HUB_IP:443/ws/spoke [--id my-agent-1] [--roles dns,dhcp]
#   Roles: dns | dhcp | network | netbox | opnsense | ldap | simulation | cppm | proxmox | le
#   (--roles is a comma-list; --role <one> is accepted as a backward-compat alias.
#    Omit both for a bare agent that loads roles later via the hub WebUI.)
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-agent"
ENV_FILE="$INSTALL_DIR/agent/.env"
LM_BRANCH="${LM_BRANCH:-main}"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""; STARTUP_ROLE=""; STARTUP_ROLES=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)    HUB_URL="$2";      shift ;;
        --id)     SPOKE_ID="$2";     shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --role)   STARTUP_ROLE="$2"; shift ;;
        --roles)  STARTUP_ROLES="$2"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

[[ -z "$HUB_URL" ]] && { echo "Usage: $0 --hub <wss://HUB:443/ws/spoke> [--id my-agent-1] [--roles dns,dhcp,...]"; exit 1; }
SPOKE_ID="${SPOKE_ID:-agent-$(hostname -s)}"
mkdir -p /var/log/lm

# Normalize the startup-role set: --roles (comma-list) + --role (single alias),
# de-duplicated, order-preserved. Passed to the unit as --roles so the agent
# spawns one RoleConnection sub-spoke per role at boot.
mapfile -t _ROLE_LIST < <(printf '%s\n' "${STARTUP_ROLES//,/ }" $STARTUP_ROLE | awk 'NF && !seen[$0]++')
STARTUP_ROLES_CSV="$(IFS=,; printf '%s' "${_ROLE_LIST[*]}")"

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

# Stage each startup role's code + Python deps + system packages.
#   - in-repo roles (dns, dhcp) ship inside the lm clone already.
#   - sibling roles (network, netbox, opnsense, ldap, simulation, cppm, proxmox,
#     le) live in separate GitHub repos; clone them shallowly into /opt/lm/<dir>
#     so the boot-time --roles load (which does NOT run the agent's _install_role)
#     can find the spoke code immediately. requirements.txt path mirrors the
#     agent's role_file.parent.parent derivation (simulation's is under cs/lm-spoke).
# Re-evaluated per role so a multi-role boot (e.g. --roles dns,network) stages
# every role's repo + deps, not just the last one.
stage_role() {
    local role="$1"
    local ROLE_REPO="" ROLE_CLONE_DIR="" ROLE_REQ="" ROLE_APT=""
    case "$role" in
        dns)        ROLE_REQ="$INSTALL_DIR/dns/requirements.txt" ;;
        dhcp)       ROLE_REQ="$INSTALL_DIR/dhcp/requirements.txt" ;;
        network)    ROLE_REPO="https://github.com/lbockenstedt/nw.git";        ROLE_CLONE_DIR="nw";       ROLE_REQ="$INSTALL_DIR/nw/requirements.txt" ;;
        netbox)     ROLE_REPO="https://github.com/lbockenstedt/netbox.git";    ROLE_CLONE_DIR="netbox";   ROLE_REQ="$INSTALL_DIR/netbox/requirements.txt" ;;
        opnsense)   ROLE_REPO="https://github.com/lbockenstedt/opnsense.git";  ROLE_CLONE_DIR="opnsense"; ROLE_REQ="$INSTALL_DIR/opnsense/requirements.txt" ;;
        ldap)       ROLE_REPO="https://github.com/lbockenstedt/ldap.git";      ROLE_CLONE_DIR="ldap";     ROLE_REQ="$INSTALL_DIR/ldap/requirements.txt" ;;
        simulation) ROLE_REPO="https://github.com/lbockenstedt/cs.git";        ROLE_CLONE_DIR="cs";       ROLE_REQ="$INSTALL_DIR/cs/lm-spoke/requirements.txt" ;;
        cppm)       ROLE_REPO="https://github.com/lbockenstedt/cppm.git";      ROLE_CLONE_DIR="cppm";     ROLE_REQ="$INSTALL_DIR/cppm/requirements.txt" ;;
        proxmox)    ROLE_REPO="https://github.com/lbockenstedt/pxmx.git";      ROLE_CLONE_DIR="pxmx";     ROLE_REQ="$INSTALL_DIR/pxmx/requirements.txt" ;;
        le)         ROLE_REPO="https://github.com/lbockenstedt/le.git";        ROLE_CLONE_DIR="le";       ROLE_REQ="$INSTALL_DIR/le/requirements.txt"
                    ROLE_APT="certbot python3-certbot-dns-cloudflare python3-certbot-dns-route53 openssl" ;;
        *) echo "❌ Unknown role '$role'"; echo "Valid: dns dhcp network netbox opnsense ldap simulation cppm proxmox le"; exit 1 ;;
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
        echo "Installing Python deps for role '$role'…"
        ./venv/bin/pip install -r "$ROLE_REQ" -q
    else
        echo "⚠️  No requirements.txt found at $ROLE_REQ for role '$role'"
    fi

    # System packages a boot-time --roles load needs but can't install itself
    # (the agent's _install_role only runs on a later LOAD_ROLE from the hub).
    # Today only le needs one: certbot (+ the common DNS-01 plugins). The le
    # spoke creates /etc/lm-le and its ledger dir on demand and runs as root
    # (the generic-agent unit is User=root), so no extra dirs/permissions here.
    if [[ -n "$ROLE_APT" ]]; then
        echo "Installing system packages for role '$role': $ROLE_APT…"
        apt-get install -y -qq $ROLE_APT
    fi
}

for _role in "${_ROLE_LIST[@]}"; do
    [[ -n "$_role" ]] && stage_role "$_role"
done

# Preserve an existing secret + LOADED_ROLES so re-installs don't break a
# running multi-role agent (LOADED_ROLES is the durable set the agent re-spawns
# on every boot; preserving it keeps runtime-loaded roles across a reinstall).
if [[ -f "$ENV_FILE" ]]; then
    if grep -q "^SPOKE_SECRET=" "$ENV_FILE"; then
        EXISTING=$(grep "^SPOKE_SECRET=" "$ENV_FILE" | cut -d= -f2-)
        [[ -n "$EXISTING" ]] && SPOKE_SECRET="$EXISTING" && echo "Preserving existing spoke secret."
    fi
    if [[ -z "$STARTUP_ROLES_CSV" ]] && grep -q "^LOADED_ROLES=" "$ENV_FILE"; then
        STARTUP_ROLES_CSV=$(grep "^LOADED_ROLES=" "$ENV_FILE" | cut -d= -f2-)
        [[ -n "$STARTUP_ROLES_CSV" ]] && echo "Preserving existing LOADED_ROLES: $STARTUP_ROLES_CSV"
    fi
fi

if [[ -z "$SPOKE_SECRET" ]]; then
    echo "ℹ️  No pre-shared secret. Agent will connect unauthenticated and await admin approval."
    echo "   Approve it in the LM WebUI (Setup → Spoke Approvals) to complete provisioning."
fi

cat > "$ENV_FILE" <<EOF
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_URL=$HUB_URL
STARTUP_ROLES=$STARTUP_ROLES_CSV
LOADED_ROLES=$STARTUP_ROLES_CSV
EOF
chmod 600 "$ENV_FILE"

# Pass --roles (comma-list) to the unit. The agent's AgentControlPlane reads
# LOADED_ROLES from this .env on boot (durable across self-update restarts); the
# CLI --roles seeds it on first install. --role (single) is accepted by
# control_plane.py as a backward-compat alias.
ROLES_ARG=""
[[ -n "$STARTUP_ROLES_CSV" ]] && ROLES_ARG="--roles $STARTUP_ROLES_CSV"

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
ExecStart=$INSTALL_DIR/agent/venv/bin/python3 control_plane.py --id \$SPOKE_ID $SECRET_ARG --hub \$HUB_URL $ROLES_ARG
StandardOutput=append:/var/log/lm/lm-agent.log
StandardError=append:/var/log/lm/lm-agent.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "Generic agent installed (ID: $SPOKE_ID, roles: ${STARTUP_ROLES_CSV:-none})"