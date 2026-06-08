#!/bin/bash
set -e

echo "🚀 Installing Lab Manager Hub (Native API-Only)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl

INSTALL_DIR="/root/lm-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d "lm/.git" ]; then
    echo "📂 Hub repository already exists. Updating..."
    cd lm && git pull && cd ..
else
    echo "🌐 Cloning Hub repository..."
    git clone https://github.com/lbockenstedt/lm.git
fi

echo "🛠️ Setting up Hub Backend..."
cd lm

# Robust Venv Setup
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then
    rm -rf venv
fi

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed."
    exit 1
fi

echo "Installing backend requirements..."
./venv/bin/python3 -m pip install --upgrade pip
./venv/bin/python3 -m pip install -r hub/requirementslerini.txt 2>/dev/null || ./venv/bin/python3 -m pip install -r hub/requirements.txt

echo "🎉 Hub Backend installation complete!"
echo "🚀 Start with: cd $INSTALL_DIR/lm && ./start_all.sh"
echo "🌐 API Access: http://$(hostname -I | awk '{print $1}'):8000"
echo "📦 Version: 0.08"
