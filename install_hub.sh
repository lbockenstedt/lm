#!/bin/bash
set -e

echo "🚀 Installing Lab Manager Hub (Native API-Only)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git

INSTALL_DIR="lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "🌐 Cloning Hub repository..."
git clone https://github.com/lbockenstedt/lm.git

echo "🛠️ Setting up Hub..."
cd lm
python3 -m venv venv
./venv/bin/pip install -r hub/requirements.txt

echo "🎉 Hub native installation complete!"
echo "🚀 Start with: cd $INSTALL_DIR/lm && ./start_all.sh"
