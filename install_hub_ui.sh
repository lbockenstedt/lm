#!/bin/bash
# ======================================================================
# DEPRECATED — do not use for new installs.
#
# OLD combined Hub + WebUI installer. Superseded by:
#   install_all.sh        — full hub + all-spokes native install (LXC-optimized)
#   install_production.sh — one-liner wrapper around install_all.sh
#
# Anti-patterns vs install_all.sh (visible in the lm.service unit this script
# writes below): installs into /root/lm with `User=root` and uses
# `ExecStop=/usr/bin/pkill -f python`, which kills EVERY Python on the host
# (gunicorn, netbox-rq, every lm-* spoke) on each `systemctl stop lm`. No
# service user, no update snapshot/rollback, no sudoers self-restart helper.
# Behavior changes belong in install_all.sh, NOT here.
# ======================================================================
set -e

echo "🚀 Installing Lab Manager Core (Hub API & WebUI)..."

# 1. Root Check
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# 2. System Dependencies
echo "📦 Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv git curl lsof net-tools

# 3. Setup Paths
BASE_DIR="/root/lm"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

# 4. Install Hub Core
echo "🛠️ Installing Hub Core..."
# Clone and restructure as a single step to avoid nested folders
git clone "https://github.com/lbockenstedt/lm.git" lm_tmp
mv lm_tmp/hub "$BASE_DIR/core"
mv lm_tmp/ui "$BASE_DIR/WebUI"
cp -r lm_tmp/* "$BASE_DIR/" 2>/dev/null || true
rm -rf lm_tmp

# Now run the installers from their new locations
cd "$BASE_DIR/core"
bash ./install_hub.sh
cd "$BASE_DIR"

cd "$BASE_DIR/WebUI"
bash ./install_ui.sh
cd "$BASE_DIR"

# 6. Configure Auto-start
echo "⚙️ Configuring systemd for auto-start on reboot..."
cat <<EOF > /etc/systemd/system/lm.service
[Unit]
Description=Lab Manager Orchestrator
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=/root/lm
ExecStart=/bin/bash /root/lm/start_all.sh
ExecStop=/usr/bin/pkill -f python
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm
systemctl restart lm

echo ""
echo "🎉 Lab Manager Core installation complete!"
echo "⚙️ Service 'lm' is enabled and running."
echo "🌐 Hub API & Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
echo "📦 Version: 0.08"
