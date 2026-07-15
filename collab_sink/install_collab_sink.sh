#!/usr/bin/env bash
# Lab Manager — Collab Sink installer (hub-side UDP listener for
# Teams/Zoom/WebEx traffic simulation). Called by install_all.sh once the
# lm repo is deployed to /opt/lm; source is at $INSTALL_DIR/collab_sink.
#
# The sink is hub-NATIVE (like lm.service / lm-watchdog), NOT an agent role:
# it binds the hub's LAN IP and receives UDP from simulation clients over the
# wired/USB path. Stdlib-only → no venv, runs on system python3. All ports are
# >1024 → svc_lm binds them with no ambient capabilities.
set -euo pipefail

INSTALL_DIR="${LM_INSTALL_DIR:-/opt/lm}"
SERVICE_NAME="lm-collab-sink"
SRC_DIR="$INSTALL_DIR/collab_sink"
SVC_USER="${LM_SVC_USER:-svc_lm}"
BIND="${LM_COLLAB_BIND:-0.0.0.0}"
PORTS="${LM_COLLAB_PORTS:-3478,3481,3479,8801,8802,8803,9000,5004,5006}"
LOG_INTERVAL="${LM_COLLAB_LOG_INTERVAL:-30}"

if [[ ! -f "$SRC_DIR/sink.py" ]]; then
    echo "lm-collab-sink: $SRC_DIR/sink.py not found — is the lm repo deployed?" >&2
    exit 1
fi

# Ensure the service user + log dir exist (idempotent — install_all.sh may
# have already created them).
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null || true
mkdir -p /var/log/lm
chown -R "$SVC_USER":"$SVC_USER" "$SRC_DIR" 2>/dev/null || true

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager Collab Sink (Teams/Zoom/WebEx UDP media listener)
After=network-online.target lm.service
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
WorkingDirectory=$SRC_DIR
Environment=LM_COLLAB_BIND=$BIND
Environment=LM_COLLAB_PORTS=$PORTS
Environment=LM_COLLAB_LOG_INTERVAL=$LOG_INTERVAL
ExecStart=/usr/bin/python3 $SRC_DIR/sink.py
StandardOutput=append:/var/log/lm/lm-collab-sink.log
StandardError=append:/var/log/lm/lm-collab-sink.log
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "Collab sink installed + started (bind=$BIND ports=$PORTS)"