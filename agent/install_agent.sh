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
#
#   --hub is optional: omit it (or pass "auto") to let the agent auto-discover the
#   hub via mDNS/DNS (BaseControlPlane._resolve_hub_url).
#
#   --clone        Clone-only: stage files + enable the unit but STOP the service
#                  so this box can be cloned. --id is NOT pinned, so each cloned
#                  disk derives its spoke id from its OWN hostname at runtime and
#                  inherits this template's PSK (carryover).
#   --tls-verify   Verify the hub TLS cert (default: encrypt without auth).
#                  Requires --tls-ca-cert <path> (or a co-located /opt/lm/certs/hub.crt).
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-agent"
ENV_FILE="$INSTALL_DIR/agent/.env"
LM_BRANCH="${LM_BRANCH:-main}"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""; HUB_SECRET=""; STARTUP_ROLE=""; STARTUP_ROLES=""
CLONE_ONLY=false
TLS_VERIFY=false
TLS_CA_CERT=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)        HUB_URL="$2";      shift ;;
        --id)         SPOKE_ID="$2";     shift ;;
        --secret)     SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2";   shift ;;
        --role)       STARTUP_ROLE="$2"; shift ;;
        --roles)      STARTUP_ROLES="$2"; shift ;;
        --clone)      CLONE_ONLY=true; shift ;;
        --tls-verify) TLS_VERIFY=true; shift ;;
        --tls-ca-cert) TLS_CA_CERT="$2"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

# --hub is optional: omit it (or pass "auto") and the agent auto-discovers the
# hub (same-box wss://127.0.0.1:443/ws/spoke, remote wss://<hub>:443 via
# mDNS/DNS) — BaseControlPlane._resolve_hub_url handles the "auto" sentinel.
# A concrete wss:// URL pins it.
[[ -z "$HUB_URL" ]] && HUB_URL="auto"

# Clone-only: do NOT pin a spoke id here. The unit omits --id, so each cloned
# disk derives its spoke id from its OWN hostname at runtime
# (socket.gethostname() in control_plane.py) — parity with the leaf agent's
# clone-name fix. The PSK (--secret) is retained (carryover) so the clone
# authenticates + can be approved under its own hostname. Full install: default
# the id to agent-<hostname> when the operator didn't pass --id.
if [ "$CLONE_ONLY" = true ]; then
    SPOKE_ID="${SPOKE_ID:-}"
else
    SPOKE_ID="${SPOKE_ID:-agent-$(hostname -s)}"
fi
mkdir -p /var/log/lm

# Resolve the TLS-verify flag into unit env values (mirrors install_github.sh).
# Verify OFF by default (self-signed hub cert → encrypt without auth). With
# --tls-verify, LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT verifies against a CA.
# No --tls-ca-cert → /opt/lm/certs/hub.crt if present (co-located with the hub);
# a remote agent with no local hub cert must supply --tls-ca-cert <path>.
if $TLS_VERIFY; then
    if [ -z "$TLS_CA_CERT" ]; then
        if [ -f /opt/lm/certs/hub.crt ]; then
            TLS_CA_CERT=/opt/lm/certs/hub.crt
        else
            echo "❌ --tls-verify requires --tls-ca-cert <path> (no /opt/lm/certs/hub.crt on this box — copy the hub CA cert here first)."
            exit 1
        fi
    fi
    HUB_TLS_VERIFY_ENV=1
    HUB_TLS_CA_ENV="$TLS_CA_CERT"
else
    HUB_TLS_VERIFY_ENV=0
    HUB_TLS_CA_ENV=""
fi

# Normalize the startup-role set: --roles (comma-list) + --role (single alias),
# de-duplicated, order-preserved. Passed to the unit as --roles so the agent
# spawns one RoleConnection sub-spoke per role at boot.
mapfile -t _ROLE_LIST < <(printf '%s\n' "${STARTUP_ROLES//,/ }" $STARTUP_ROLE | awk 'NF && !seen[$0]++')
STARTUP_ROLES_CSV="$(IFS=,; printf '%s' "${_ROLE_LIST[*]}")"

# System deps
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl

# Clone or update the LM repo (contains agent + all roles).
# A real prior install is a git checkout at $INSTALL_DIR (has .git + agent/).
# NOTE: a bare /opt/lm/core with NO .git is the cs-spoke base_spoke extraction
# (install_cs.sh copies only core/ so base_spoke.py resolves) — that is NOT a
# full LM clone, so detecting on core/ alone would wrongly skip the clone and
# then fail at `cd $INSTALL_DIR/agent` (the original "No such file or directory"
# symptom on a box that already ran the cs spoke installer). Detect on .git.
if [[ -d "$INSTALL_DIR/.git" ]]; then
    # HARD-SYNC an existing clone to origin/$LM_BRANCH instead of a soft
    # `pull --rebase --autostash`. A soft pull silently no-ops (|| true) on a
    # detached HEAD, a diverged/conflicting local history, or a stale branch —
    # leaving the OLD checkout in place. If that old checkout predates the
    # control_plane.py entrypoint, the unit written below crash-loops with
    # "can't open .../agent/src/control_plane.py: No such file or directory".
    # fetch + `reset --hard FETCH_HEAD` forces the TRACKED tree to match remote
    # exactly regardless of local state; untracked venv/ and .env are left
    # intact (so the preserved SPOKE_SECRET read further down survives). git
    # clean is deliberately NOT run — it would delete venv/ and .env.
    echo "Syncing existing LM installation to origin/$LM_BRANCH…"
    if git -C "$INSTALL_DIR" fetch -q origin "$LM_BRANCH" 2>/dev/null; then
        git -C "$INSTALL_DIR" reset --hard FETCH_HEAD -q 2>/dev/null || true
    else
        echo "⚠️  fetch failed — keeping current checkout; the entrypoint check below will re-clone if needed."
    fi
elif [[ -d "$INSTALL_DIR" && ! -d "$INSTALL_DIR/.git" ]]; then
    # /opt/lm already exists but is NOT a git clone (e.g. cs-spoke left core/
    # behind). `git clone` refuses to write into a non-empty dir, so clone to
    # a temp dir and merge the checkout in — core/ is overwritten with the real
    # lm core (same source the cs spoke uses), and agent/ + role dirs land too.
    echo "Cloning LM repo into existing $INSTALL_DIR …"
    _LM_TMP="$(mktemp -d)"
    if git clone -q --branch "$LM_BRANCH" https://github.com/lbockenstedt/lm.git "$_LM_TMP/lm"; then
        cp -a "$_LM_TMP/lm/." "$INSTALL_DIR"/
        rm -rf "$_LM_TMP"
    else
        rm -rf "$_LM_TMP"
        echo "ERROR: git clone of LM repo failed (network / DNS to github.com?). Re-run $0." >&2
        exit 1
    fi
else
    echo "Cloning LM repo…"
    git clone -q --branch "$LM_BRANCH" https://github.com/lbockenstedt/lm.git "$INSTALL_DIR"
fi

# Belt-and-suspenders: the unit below execs $INSTALL_DIR/agent/src/control_plane.py.
# If a fetch failed above and the existing checkout is stale (or the tree is
# otherwise incomplete), that entrypoint can still be absent — which would
# crash-loop the service. Force one clean re-clone via temp+cp (leaves venv/
# and .env intact), then abort loudly BEFORE writing the unit if it is STILL
# missing, so the failure surfaces at install time instead of as a restart loop.
AGENT_ENTRY="$INSTALL_DIR/agent/src/control_plane.py"
if [[ ! -f "$AGENT_ENTRY" ]]; then
    echo "⚠️  $AGENT_ENTRY missing after sync — forcing a clean re-clone…"
    _LM_TMP="$(mktemp -d)"
    if git clone -q --branch "$LM_BRANCH" https://github.com/lbockenstedt/lm.git "$_LM_TMP/lm"; then
        cp -a "$_LM_TMP/lm/." "$INSTALL_DIR"/
    fi
    rm -rf "$_LM_TMP"
fi
if [[ ! -f "$AGENT_ENTRY" ]]; then
    echo "ERROR: $AGENT_ENTRY still missing after re-clone. Aborting install." >&2
    echo "       Check network access to github.com/lbockenstedt/lm ($LM_BRANCH branch)." >&2
    exit 1
fi

# Python venv for agent
if [[ ! -d "$INSTALL_DIR/agent" ]]; then
    echo "ERROR: $INSTALL_DIR/agent is missing — LM clone failed. Re-run $0." >&2
    exit 1
fi
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
        console)    ROLE_REQ="$INSTALL_DIR/console/requirements.txt" ;;   # in-repo (pyserial); agent runs as root so /dev/tty* needs no dialout
        network)    ROLE_REPO="https://github.com/lbockenstedt/nw.git";        ROLE_CLONE_DIR="nw";       ROLE_REQ="$INSTALL_DIR/nw/requirements.txt" ;;
        netbox)     ROLE_REPO="https://github.com/lbockenstedt/netbox.git";    ROLE_CLONE_DIR="netbox";   ROLE_REQ="$INSTALL_DIR/netbox/requirements.txt" ;;
        opnsense)   ROLE_REPO="https://github.com/lbockenstedt/opnsense.git";  ROLE_CLONE_DIR="opnsense"; ROLE_REQ="$INSTALL_DIR/opnsense/requirements.txt" ;;
        ldap)       ROLE_REPO="https://github.com/lbockenstedt/ldap.git";      ROLE_CLONE_DIR="ldap";     ROLE_REQ="$INSTALL_DIR/ldap/requirements.txt" ;;
        simulation) ROLE_REPO="https://github.com/lbockenstedt/cs.git";        ROLE_CLONE_DIR="cs";       ROLE_REQ="$INSTALL_DIR/cs/lm-spoke/requirements.txt" ;;
        cppm)       ROLE_REPO="https://github.com/lbockenstedt/cppm.git";      ROLE_CLONE_DIR="cppm";     ROLE_REQ="$INSTALL_DIR/cppm/requirements.txt" ;;
        proxmox)    ROLE_REPO="https://github.com/lbockenstedt/pxmx.git";      ROLE_CLONE_DIR="pxmx";     ROLE_REQ="$INSTALL_DIR/pxmx/requirements.txt" ;;
        le)         ROLE_REPO="https://github.com/lbockenstedt/le.git";        ROLE_CLONE_DIR="le";       ROLE_REQ="$INSTALL_DIR/le/requirements.txt"
                    ROLE_APT="certbot python3-certbot-dns-cloudflare python3-certbot-dns-route53 openssl" ;;
        *) echo "❌ Unknown role '$role'"; echo "Valid: dns dhcp network netbox opnsense ldap simulation cppm proxmox le console"; exit 1 ;;
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
    if grep -q "^HUB_SECRET=" "$ENV_FILE"; then
        EXISTING=$(grep "^HUB_SECRET=" "$ENV_FILE" | cut -d= -f2-)
        [[ -n "$EXISTING" ]] && HUB_SECRET="$EXISTING" && echo "Preserving existing hub secret."
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
HUB_SECRET=$HUB_SECRET
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

# Only pass --id when pinned. Omitting it (clone-only) lets each cloned disk
# derive its spoke id from its own hostname at runtime (control_plane.py).
ID_ARG=""
[[ -n "$SPOKE_ID" ]] && ID_ARG="--id \$SPOKE_ID"

# TLS-verify Environment fragment (empty when verification is off, the default).
_TLS_ENV="LM_HUB_TLS_VERIFY=$HUB_TLS_VERIFY_ENV"
[ -n "$HUB_TLS_CA_ENV" ] && _TLS_ENV="$_TLS_ENV LM_HUB_CA_CERT=$HUB_TLS_CA_ENV"

# Display id for the unit Description + summary (clone-only has no pinned id).
if [ -n "$SPOKE_ID" ]; then
    ID_DISP="$SPOKE_ID"
else
    ID_DISP="(derived from each clone's hostname at runtime)"
fi

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager Generic Agent ($ID_DISP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/agent/src"
Environment=$_TLS_ENV
WorkingDirectory=$INSTALL_DIR/agent/src
ExecStart=$INSTALL_DIR/agent/venv/bin/python3 control_plane.py $ID_ARG $SECRET_ARG --hub \$HUB_URL $ROLES_ARG
StandardOutput=append:/var/log/lm/lm-agent.log
StandardError=append:/var/log/lm/lm-agent.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Retire the LEGACY Generic Leaf Agent (lm-generic-agent.service) if it's
# installed on this box. The legacy leaf (formerly generic_agent/, removed from
# the lm repo — no longer installable) is protocol-INCOMPATIBLE with the hub:
# it dispatches on top-level `type` and has no SPOKE_UPDATE_SESSION_KEY /
# LOAD_ROLE / GET_AVAILABLE_ROLES handlers, so it can never adopt a session
# key. If BOTH this role-capable lm-agent AND the legacy lm-generic-agent run
# on the same box, both dial the hub as the SAME spoke_id (derived from
# hostname) and race for the hub's single active_connections slot. Whichever
# connects first wins; when an admin then approves, approve_and_bind_spoke
# pushes the session key to THAT ws — if it's the legacy one, it ignores the
# push, the role-capable agent never adopts its key, and LOAD_ROLE 503s with
# "connected but not authenticated". Stop + mask (not just disable) so it
# can't be started again even by hand, and remove the unit + install dir
# entirely — this is a full purge, not a temporary disable, since the legacy
# leaf is no longer shipped or supported. Non-fatal if it isn't present.
LEGACY_SERVICE="lm-generic-agent"
if systemctl list-unit-files 2>/dev/null | grep -qE "\\${LEGACY_SERVICE}\\.service"; then
    systemctl stop "$LEGACY_SERVICE" 2>/dev/null || true
    systemctl disable "$LEGACY_SERVICE" 2>/dev/null || true
    systemctl mask "$LEGACY_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${LEGACY_SERVICE}.service"
    rm -rf "/opt/lm/generic-agent"
    systemctl daemon-reload
    echo "🧹  Purged legacy ${LEGACY_SERVICE}.service (stopped, masked, unit + install dir removed)."
    echo "    The role-capable ${SERVICE_NAME} now owns this box's spoke connection."
fi

# Enable so a CLONED disk auto-starts on first boot and onboards under its own
# hostname (carryover: retains the template's PSK so it can be approved without
# admin re-approval). Clone-only STOPs the service here so the template box does
# not register while it is being prepared for cloning; the unit stays enabled.
systemctl enable "$SERVICE_NAME" 2>/dev/null || true
if [ "$CLONE_ONLY" = true ]; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    echo "❄️  Clone-only mode active. Files staged + unit enabled, but service STOPPED."
    echo "The service will start automatically when this disk is cloned and booted."
    echo "Each clone derives its spoke id from its own hostname and inherits this"
    echo "template's PSK (carryover). To pin a spoke ID instead, edit"
    echo "/etc/systemd/system/${SERVICE_NAME}.service and add --id <id>."
else
    systemctl restart "$SERVICE_NAME"
fi
echo "Generic agent installed (ID: $ID_DISP, roles: ${STARTUP_ROLES_CSV:-none})"