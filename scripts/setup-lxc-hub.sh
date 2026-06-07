#!/bin/bash

# LXC Setup script for the Hub module
set -e

./setup-lxc-base.sh hub

git clone https://github.com/lbockenstedt/lm.git /opt/lm
cd /opt/lm/hub

python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Create systemd unit for persistence
cat <<EOF > /etc/systemd/system/lm-hub.service
[Unit]
Description=Lab Manager Hub
After=network.target

[Service]
ExecStart=/opt/lm/hub/venv/bin/python3 src/main.py
WorkingDirectory=/opt/lm/hub
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-hub
systemctl start lm-hub

echo "✅ Hub module deployed as a systemd service in LXC."
