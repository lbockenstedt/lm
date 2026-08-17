#!/usr/bin/env bash
# Lab Manager — Hurricane Electric (HE.NET) public-DNS Spoke Installer
# Called by install_all.sh; source is already present at $INSTALL_DIR/henet.
#
# Unlike the Unbound "dns" role there is NO local server to install — HE.NET is a
# hosted public-DNS service, so this only lays down the spoke venv + systemd
# unit. The HE DDNS key is NOT configured here; it lives in the hub Credential
# Vault and the hub injects it into each write command at runtime.
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-henet"
ENV_FILE="$INSTALL_DIR/henet/.env"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)    HUB_URL="$2";      shift ;;
        --id)     SPOKE_ID="$2";     shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

# Accept a bare hub IP/host for --hub (mirrors install_dns.sh).
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

if [[ -z "$HUB_URL" ]]; then
    echo "Usage: $0 --hub <ws://HUB:8765> [--id henet-spoke-1]"; exit 1
fi
SPOKE_ID="${SPOKE_ID:-${SERVICE_NAME}-$(hostname -s)}"
mkdir -p /var/log/lm /etc/lm-henet

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk.
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log /var/log/client-sim-*.log {
    su root root
    size 50M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LOGROTATE

# Python venv
cd "$INSTALL_DIR/henet"
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q
[[ -f requirements.txt ]] && ./venv/bin/pip install -r requirements.txt -q

# Preserve existing secret across re-installs; otherwise start without one.
if [[ -f "$ENV_FILE" ]] && grep -q "^SPOKE_SECRET=.\+" "$ENV_FILE"; then
    SPOKE_SECRET=$(grep "^SPOKE_SECRET=" "$ENV_FILE" | cut -d= -f2-)
    echo "Preserving existing SPOKE_SECRET."
elif [[ -z "$SPOKE_SECRET" ]]; then
    echo "ℹ️  No pre-shared secret — spoke will connect unauthenticated and await admin approval."
fi

# Preserve the minted INSTALL_UUID so a re-install keeps the same hub-side
# fingerprint (install_uuid); see install_dns.sh for the rationale.
INSTALL_UUID_LINE=""
if [[ -f "$ENV_FILE" ]] && grep -q "^INSTALL_UUID=.\+" "$ENV_FILE"; then
    EXISTING_UUID=$(grep "^INSTALL_UUID=" "$ENV_FILE" | cut -d= -f2-)
    [[ -n "$EXISTING_UUID" ]] && INSTALL_UUID_LINE="INSTALL_UUID=$EXISTING_UUID" \
        && echo "Preserving existing install UUID (hub fingerprint)."
fi

cat > "$ENV_FILE" <<EOF
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_URL=$HUB_URL
${INSTALL_UUID_LINE}
EOF
chmod 600 "$ENV_FILE"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager HE.NET Public-DNS Spoke
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=svc_lm
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/henet/src"
WorkingDirectory=$INSTALL_DIR/henet/src
ExecStart=$INSTALL_DIR/henet/venv/bin/python3 control_plane.py --id \$SPOKE_ID --hub \$HUB_URL
StandardOutput=append:/var/log/lm/lm-henet.log
StandardError=append:/var/log/lm/lm-henet.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "HE.NET spoke installed (ID: $SPOKE_ID)"
