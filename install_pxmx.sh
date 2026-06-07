#!/bin/bash
set -e

echo "🚀 Installing Proxmox Manager Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git

INSTALL_DIR="lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "🌐 Cloning required repositories..."
git clone https://github.com/lbockenstedt/lm.git
git clone https://github.com/lbockenstedt/pxmx.git

echo "🛠️ Setting up Proxmox Manager..."
cd pxmx
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

echo "🎉 Proxmox Manager native installation complete!"
