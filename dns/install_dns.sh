#!/usr/bin/env bash
# Lab Manager — Unbound DNS Spoke Installer
# Called by install_all.sh; source is already present at $INSTALL_DIR/dns
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-dns"
ENV_FILE="$INSTALL_DIR/dns/.env"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)    HUB_URL="$2";      shift ;;
        --id)     SPOKE_ID="$2";     shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

[[ -z "$HUB_URL" ]] && { echo "Usage: $0 --hub <ws://HUB:8765> [--id dns-spoke-1]"; exit 1; }
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

# Unbound
apt-get install -y -qq unbound
grep -q "control-enable: yes" /etc/unbound/unbound.conf 2>/dev/null || cat >> /etc/unbound/unbound.conf <<'UNBOUNDCFG'

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
UNBOUNDCFG

# Listen on all interfaces + allow LAN clients. Unbound defaults to 127.0.0.1
# ONLY and REFUSES non-local queries, so the DNS role would never answer a query
# sent to its LAN IP — it looks like "no response / firewall" even with the
# firewall off. Idempotent: guarded on the interface line.
grep -q "interface: 0.0.0.0" /etc/unbound/unbound.conf 2>/dev/null || cat >> /etc/unbound/unbound.conf <<'UNBOUNDSRV'

server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 169.254.0.0/16 allow
UNBOUNDSRV
mkdir -p /etc/unbound/conf.d
grep -q "conf\.d" /etc/unbound/unbound.conf 2>/dev/null \
    || echo 'include-toplevel: "/etc/unbound/conf.d/*.conf"' >> /etc/unbound/unbound.conf
unbound-control-setup 2>/dev/null || true
systemctl enable --now unbound

# Python venv
cd "$INSTALL_DIR/dns"
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
EOF
chmod 600 "$ENV_FILE"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager DNS Spoke (Unbound)
After=network-online.target unbound.service
Wants=network-online.target

[Service]
Type=simple
User=svc_lm
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/dns/src"
WorkingDirectory=$INSTALL_DIR/dns/src
ExecStart=$INSTALL_DIR/dns/venv/bin/python3 control_plane.py --id \$SPOKE_ID --hub \$HUB_URL
StandardOutput=append:/var/log/lm/lm-dns.log
StandardError=append:/var/log/lm/lm-dns.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "DNS spoke installed (ID: $SPOKE_ID)"
