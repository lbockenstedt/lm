#!/bin/bash
set -e

echo "🚀 Starting Native Lab Manager Installation (LXC-Optimized)..."

# 1. Root Check
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# 2. System Dependencies
echo "📦 Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv git curl lsof net-tools

# 3. Path Configuration
BASE_DIR="/root/lab-manager"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

REPOS=("lm" "cs" "pxmx" "opnsense")

# 4. Repository Sync
for repo in "${REPOS[@]}"; do
    if [ -d "$repo/.git" ]; then
        echo "📂 $repo already exists. Updating via git pull..."
        cd "$repo" && git pull && cd ..
    else
        echo "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# 5. Run Modular Installers
echo "🛠️ Running modular installations..."

# Hub
echo "Setting up Hub Backend..."
cd "$BASE_DIR/lm"
bash ./install_hub.sh
cd "$BASE_DIR"

# UI (Assets only)
echo "Setting up WebUI assets..."
cd "$BASE_DIR/lm"
bash ./install_ui.sh
cd "$BASE_DIR"

# CS
echo "Setting up Client Simulator..."
cd "$BASE_DIR/cs"
bash ./install_cs.sh
cd "$BASE_DIR"

# PXMX
echo "Setting up Proxmox Manager..."
cd "$BASE_DIR/pxmx"
bash ./install_pxmx.sh
cd "$BASE_DIR"

# OPNsense
echo "Setting up OPNsense Manager..."
cd "$BASE_DIR/opnsense"
bash ./install_opnsense.sh
cd "$BASE_DIR"

# 6. Persistence & Auto-start
echo "⚙️ Configuring systemd for auto-start on reboot..."

# Create the systemd service unit
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

# Enable and start the service
systemctl daemon-reload
systemctl enable lab-manager
systemctl restart lab-manager

echo ""
echo "🎉 Native installation complete!"
echo "📂 All modules are located in: $BASE_DIR"
echo "⚙️ Service 'lab-manager' is enabled and running."
echo "🚀 To manage the system: systemctl start|stop|restart lab-manager"
echo "🌐 Hub API & Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
echo "📦 Version: 0.05"
