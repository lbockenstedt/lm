#!/usr/bin/env bash
# Lab Manager — Kea DHCP Spoke Installer
# Called by install_all.sh; source is already present at $INSTALL_DIR/dhcp
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-dhcp"
ENV_FILE="$INSTALL_DIR/dhcp/.env"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)    HUB_URL="$2";      shift ;;
        --id)     SPOKE_ID="$2";     shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31` == `--hub
# wss://172.16.1.31:443`). A ws://|wss:// scheme or the "auto" sentinel is left
# as-is; host:port gets a scheme; a bare host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

[[ -z "$HUB_URL" ]] && { echo "Usage: $0 --hub <ws://HUB:8765> [--id dhcp-spoke-1]"; exit 1; }
SPOKE_ID="${SPOKE_ID:-${SERVICE_NAME}-$(hostname -s)}"
mkdir -p /var/log/lm

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk (copytruncate
# keeps the inode → the running spoke's O_APPEND FileHandler + systemd stderr
# keep appending). Belt-and-suspenders alongside logging_setup's RotatingFileHandler.
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

# Kea DHCP4 + Control Agent — noninteractive prevents credential prompts
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq kea-dhcp4-server kea-ctrl-agent

# Write a clean kea-ctrl-agent config: loopback-only, port 8001, no auth.
# The default Debian package config may prompt for HTTP auth credentials;
# this replaces it unconditionally so the install is fully non-interactive.
KEA_CA_CONF="/etc/kea/kea-ctrl-agent.conf"
cat > "$KEA_CA_CONF" <<'KEACONF'
{
    "Control-agent": {
        "http-host": "127.0.0.1",
        "http-port": 8001,
        "control-sockets": {
            "dhcp4": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            }
        },
        "loggers": [{
            "name": "kea-ctrl-agent",
            "output_options": [{"output": "syslog"}],
            "severity": "WARN"
        }]
    }
}
KEACONF

systemctl enable --now kea-ctrl-agent kea-dhcp4-server

# Python venv
cd "$INSTALL_DIR/dhcp"
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q
[[ -f requirements.txt ]] && ./venv/bin/pip install -r requirements.txt -q

# Preserve existing secret across re-installs; otherwise start without one (zero-touch).
if [[ -f "$ENV_FILE" ]] && grep -q "^SPOKE_SECRET=.\+" "$ENV_FILE"; then
    SPOKE_SECRET=$(grep "^SPOKE_SECRET=" "$ENV_FILE" | cut -d= -f2-)
    echo "Preserving existing SPOKE_SECRET."
elif [[ -z "$SPOKE_SECRET" ]]; then
    echo "ℹ️  No pre-shared secret — spoke will connect unauthenticated and await admin approval."
fi

cat > "$ENV_FILE" <<EOF
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_URL=$HUB_URL
KEA_CA_URL=http://localhost:8001
EOF
chmod 600 "$ENV_FILE"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager DHCP Spoke (Kea)
After=network-online.target kea-dhcp4-server.service kea-ctrl-agent.service
Wants=network-online.target

[Service]
Type=simple
User=svc_lm
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/dhcp/src"
WorkingDirectory=$INSTALL_DIR/dhcp/src
ExecStart=$INSTALL_DIR/dhcp/venv/bin/python3 control_plane.py --id \$SPOKE_ID --hub \$HUB_URL
StandardOutput=append:/var/log/lm/lm-dhcp.log
StandardError=append:/var/log/lm/lm-dhcp.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "DHCP spoke installed (ID: $SPOKE_ID)"
