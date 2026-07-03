#!/bin/bash
# ------------------------------------------------------------------
# Lab Manager GitHub Bootstrap
# This script allows for direct installation of the Generic Agent from GitHub.
# ------------------------------------------------------------------

set -e

SPOKE_URL=""
SPOKE_ID=""
SPOKE_SECRET=""
HUB_SECRET=""
CLONE_ONLY=false

# --- Logging Setup ---
LOG_DIR="/var/log/lm"
INSTALL_LOG="$LOG_DIR/lm-agent-install.log"

# Create the log directory (shared with the hub + spokes; the agent runtime
# log /var/log/lm/agent.log lives here too). The installer runs as root, so it
# can create the dir; the chown to svc_lm below (step 4) lets the User=svc_lm
# service write its own runtime log here.
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

# TLS cert verification is OFF by default (self-signed hub cert → encrypt
# without auth). Pass --tls-verify to make the agent verify the hub cert. With
# no --tls-ca-cert, /opt/lm/certs/hub.crt is used if present (co-located with
# the hub); otherwise --tls-ca-cert <path> is required (a remote agent has no
# local hub cert to default to).
TLS_VERIFY=false
TLS_CA_CERT=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --spoke-url) SPOKE_URL="$2"; shift 2 ;;
        --id) SPOKE_ID="$2"; shift 2 ;;
        --secret) SPOKE_SECRET="$2"; shift 2 ;;
        --hub-secret) HUB_SECRET="$2"; shift 2 ;;
        --tls-verify)  TLS_VERIFY=true; shift ;;
        --tls-ca-cert) TLS_CA_CERT="$2"; shift 2 ;;
        --clone) CLONE_ONLY=true; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
done

# Resolve the verify flag into unit env values.
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

# --spoke-url is optional: omit it (or pass "auto") and the agent auto-discovers
# the hub (same-box ws://127.0.0.1:8765, remote wss://<hub>:443 via mDNS/DNS).
# A concrete URL pins it. Backward compat: an explicit --spoke-url still works.
if [ "$CLONE_ONLY" = false ] && [ -z "$SPOKE_URL" ]; then
    SPOKE_URL="auto"
    log_c "ℹ️ No --spoke-url given — agent will auto-discover the hub."
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
# Clean both name variants: the runtime path is generic-agent (hyphen) below,
# but a prior broken run may have left generic_agent (underscore, the repo dir
# name) behind — clear both so we always start fresh.
rm -rf "$ROOT_DIR/core" "$ROOT_DIR/generic-agent" "$ROOT_DIR/generic_agent" >> "$INSTALL_LOG" 2>&1

log_c "📦 Cloning Core and Generic Agent from GitHub..."
REPO_URL="https://github.com/lbockenstedt/lm"

# Clone to temporary location
git clone --depth 1 "$REPO_URL" "$ROOT_DIR/tmp_repo" >> "$INSTALL_LOG" 2>&1
cp -r "$ROOT_DIR/tmp_repo/core" "$ROOT_DIR/" >> "$INSTALL_LOG" 2>&1
# Copy the repo's generic_agent (underscore) dir INTO the runtime path
# generic-agent (hyphen) that the service/WorkingDirectory/ExecStart expect.
cp -r "$ROOT_DIR/tmp_repo/generic_agent" "$ROOT_DIR/generic-agent" >> "$INSTALL_LOG" 2>&1
rm -rf "$ROOT_DIR/tmp_repo"

# 4. Python Environment Setup
log_c "🐍 Setting up Python environment..."
cd "$ROOT_DIR/generic-agent"
python3 -m venv venv >> "$INSTALL_LOG" 2>&1
./venv/bin/python3 -m pip install --upgrade pip -q >> "$INSTALL_LOG" 2>&1
# Install from requirements.txt (websockets, python-dotenv, psutil, zeroconf).
# agent.py imports psutil at module top — a bare `pip install websockets
# python-dotenv` here previously left the venv without psutil →
# ModuleNotFoundError crash-loop at boot. zeroconf is required for mDNS hub
# auto-discovery (_lm-hub._tcp.local.) — without it a same-L2 agent with no
# lm-hub DNS record silently never finds the hub. requirements.txt is the
# single source so this can't drift again.
if [ -f requirements.txt ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q >> "$INSTALL_LOG" 2>&1
else
    ./venv/bin/python3 -m pip install websockets python-dotenv psutil zeroconf -q >> "$INSTALL_LOG" 2>&1
fi

# Log directory shared with the hub + spokes; the systemd service runs as
# svc_lm and agent.py writes /var/log/lm/agent.log directly (no root
# shell to pre-open the redirect), so svc_lm must own the dir.
mkdir -p /var/log/lm >> "$INSTALL_LOG" 2>&1
chown -R svc_lm:svc_lm /var/log/lm 2>/dev/null || true

# 5. Systemd Service Setup
log_c "⚙️ Configuring systemd service..."

# Migrate from the older installer's unit name. install_agent.sh (the legacy
# generic installer) wrote lm-bootstrap.service for this agent; this installer
# uses lm-generic-agent.service. A re-install over an old box would otherwise
# leave BOTH units enabled — the stale lm-bootstrap would crash-loop on boot
# because its ExecStart uses the retired --hub/--hub-secret args the current
# agent.py no longer accepts. Disable + remove it so only the new unit remains.
if [ -f /etc/systemd/system/lm-bootstrap.service ] || \
   systemctl list-unit-files 2>/dev/null | grep -q '^lm-bootstrap\.service'; then
    log_c "🧹 Removing stale lm-bootstrap.service (older installer's unit)…"
    systemctl disable --now lm-bootstrap 2>/dev/null || true
    rm -f /etc/systemd/system/lm-bootstrap.service
    systemctl daemon-reload 2>/dev/null || true
fi

# Clone-only: strip the agent's persisted identity so the disk image is
# clone-ready. The base spoke (agent-spoke) writes its install UUID — the guid
# the hub uses for clone/rename correlation — plus HUB_SECRET and the negotiated
# session key to a .env at its repo root (_repo_root/.env). A cloned disk
# inheriting that .env would replay THIS template's identity: same UUID → the
# hub treats every clone as a clone-and-rename of the template (carrying its
# approval) instead of a fresh spoke awaiting admin approval.
#
# Line 77's rm -rf already wipes /opt/lm/generic-agent (this installer's dir),
# but the identity .env can persist at paths that survive that wipe: the legacy
# install_agent.sh layout /opt/lm/agent/.env, a top-level /opt/lm/.env, and the
# leaf agent's /etc/lm-agent/config.json (which carries the secret). Strip all
# of them so the clone generates a fresh install UUID on first start. (Full
# installs are untouched — they WANT the prompted identity.)
if [ "$CLONE_ONLY" = true ]; then
    log_c "🧹 Clone-only: stripping persisted agent identity (.env / config) for clone-readiness…"
    rm -f "$ROOT_DIR/generic-agent/.env" "$ROOT_DIR/agent/.env" "$ROOT_DIR/.env" 2>/dev/null || true
    rm -f /etc/lm-agent/config.json 2>/dev/null || true
fi
# Build the ExecStart argument list conditionally so an empty --secret (or
# --id) is OMITTED entirely rather than passed as a blank token. A blank
# `--secret ` here would otherwise swallow the next flag (`--spoke-url`) and
# make argparse error out at service start. No secret is a valid first-install
# state: the agent connects unauthenticated and awaits admin approval in the
# hub WebUI (agent.py treats a None secret as "pending approval").
EXEC_ARGS=(--spoke-url "\"$SPOKE_URL\"")
[ -n "$SPOKE_ID" ]     && EXEC_ARGS+=(--id "\"$SPOKE_ID\"")
[ -n "$SPOKE_SECRET" ] && EXEC_ARGS+=(--secret "\"$SPOKE_SECRET\"")
EXEC_START="$(printf ' %s' "${EXEC_ARGS[@]}")"
EXEC_START="${EXEC_START:1}"
# Build the TLS-verify Environment fragment (empty when verification is off,
# the default). When --tls-verify was passed, set LM_HUB_TLS_VERIFY=1 +
# LM_HUB_CA_CERT so the agent authenticates the hub cert.
_TLS_ENV="LM_HUB_TLS_VERIFY=$HUB_TLS_VERIFY_ENV"
[ -n "$HUB_TLS_CA_ENV" ] && _TLS_ENV="$_TLS_ENV LM_HUB_CA_CERT=$HUB_TLS_CA_ENV"
cat <<EOF > /etc/systemd/system/lm-generic-agent.service
[Unit]
Description=Lab Manager Generic Leaf Agent
After=network.target

[Service]
User=svc_lm
WorkingDirectory=$ROOT_DIR/generic-agent
Environment="PYTHONPATH=$ROOT_DIR"
Environment=$_TLS_ENV
ExecStart=$ROOT_DIR/generic-agent/venv/bin/python3 $ROOT_DIR/generic-agent/src/agent.py ${EXEC_START}
StandardOutput=append:/var/log/lm/agent.log
StandardError=append:/var/log/lm/agent.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Enable the service so it starts on next reboot
systemctl enable lm-generic-agent

if [ "$CLONE_ONLY" = true ]; then
    log_c "❄️  Clone-only mode active. Files and service enabled, but service is NOT started."
    echo "The agent will start automatically on the next reboot."
    echo "Note: To change the spoke ID manually, edit /etc/systemd/system/lm-bootstrap.service"
else
    log_c "🔄 Starting agent service..."
    systemctl restart lm-generic-agent
    log_c "🎉 Bootstrap installation complete! The agent is now calling home to $SPOKE_URL"
    echo "--------------------------------------------------------------------------------"
    echo "Logs are available at: $INSTALL_LOG and /var/log/lm/agent.log"
    echo "You can now approve this spoke in the Hub WebUI to negotiate its session secret."
    echo "--------------------------------------------------------------------------------"
fi
