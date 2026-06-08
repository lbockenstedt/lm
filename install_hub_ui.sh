#!/bin/bash
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
BASE_DIR="/root/lab-manager"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

# 4. Install Hub Backend
echo "🛠️ Installing Hub Backend..."
cd "$BASE_DIR/lm" 2>/dev/null || {
    echo "🌐 Cloning Hub repository..."
    cd "$BASE_DIR"
    git clone https://github.com/lbockenstedt/lm.git
    cd "$BASE_DIR/lm"
}
bash ./install_hub.sh
cd "$BASE_DIR"

# 5. Install WebUI Assets
echo "🛠️ Installing WebUI Assets..."
cd "$BASE_DIR/lm"
bash ./install_ui.sh
cd "$BASE_DIR"

# 6. Configure Auto-start
echo "⚙️ Configuring systemd for auto-start on reboot..."
cat <<EOF > /etc/systemd/system/lab-manager.service
[Unit]
Description=Lab Manager Orchestrator
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=/root/lab-manager/lm
ExecStart=/bin/bash /root/lab-manager/lm/start_all.sh
ExecStop=/usr/bin/pkill -f python
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lab-manager
systemctl restart lab-manager

echo ""
echo "🎉 Lab Manager Core installation complete!"
echo "⚙️ Service 'lab-manager' is enabled and running."
echo "🌐 Hub API & Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
echo "📦 Version: 0.07"
