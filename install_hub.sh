#!/bin/bash
set -e

echo "🚀 Installing Lab Manager Hub (Native API-Only)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl

INSTALL_DIR="/root/lm"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Clone and restructure core repo
echo "🌐 Cloning Core repository..."
git clone "https://github.com/lbockenstedt/lm.git" lm_tmp
mv lm_tmp/hub "$INSTALL_DIR/core"
mv lm_tmp/ui "$INSTALL_DIR/WebUI"
cp -r lm_tmp/* "$INSTALL_DIR/" 2>/dev/null || true
rm -rf lm_tmp

echo "🛠️ Setting up Hub Backend..."
cd "$INSTALL_DIR/core"

# Robust Venv Setup
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then
    rm -rf venv
fi
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

echo "Installing backend requirements..."
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install -r requirements.txt -q

echo "🎉 Hub Backend installation complete!"
echo "🚀 Start with: cd $INSTALL_DIR && ./start_all.sh"
echo "🌐 API Access: http://$(hostname -I | awk '{print $1}'):8000"
echo "📦 Version: 0.08"
