#!/bin/bash

# LXC Setup script for the WebUI module
set -e

./setup-lxc-base.sh ui

git clone https://github.com/lbockenstedt/lm.git /opt/lm
cd /opt/lm/ui

npm install

# Create systemd unit for persistence
cat <<EOF > /etc/systemd/system/lm-ui.service
[Unit]
Description=Lab Manager WebUI
After=network.target

[Service]
ExecStart=/usr/bin/npm run dev -- --host
WorkingDirectory=/opt/lm/ui
Restart=always
User=root
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-ui
systemctl start lm-ui

echo "✅ WebUI module deployed as a systemd service in LXC."
