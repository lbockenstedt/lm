#!/bin/bash
set -e

echo "🚀 Installing Client Simulator Module (Native)..."

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
git clone https://github.com/lbockenstedt/cs.git

echo "🛠️ Setting up Client Simulator..."
cd cs
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

echo "🎉 Client Simulator native installation complete!"
