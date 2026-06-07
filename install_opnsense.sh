#!/bin/bash
set -e

echo "🚀 Installing OPNsense Manager Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git

INSTALL_DIR="/root/lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# OPNsense depends on the Hub for its BaseSpoke definitions.
if [ ! -d "lm/.git" ]; then
    echo "🌐 Cloning required Hub repository..."
    git clone https://github.com/lbockenstedt/lm.git
fi

if [ -d "opnsense/.git" ]; then
    echo "📂 OPNsense repository already exists. Updating..."
    cd opnsense && git pull && cd ..
else
    echo "🌐 Cloning OPNsense Manager repository..."
    git clone https://github.com/lbockenstedt/opnsense.git
fi

echo "🛠️ Setting up OPNsense Manager..."
cd opnsense
python3 -m venv venv
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

echo "🎉 OPNsense Manager native installation complete!"
