#!/bin/bash
set -e

echo "🚀 Installing Client Simulator Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git

INSTALL_DIR="/root/lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# CS depends on the Hub for its BaseSpoke definitions in some contexts,
# so we ensure the Hub repo is present first.
if [ ! -d "lm/.git" ]; then
    echo "🌐 Cloning required Hub repository..."
    git clone https://github.com/lbockenstedt/lm.git
fi

if [ -d "cs/.git" ]; then
    echo "📂 CS repository already exists. Updating..."
    cd cs && git pull && cd ..
else
    echo "🌐 Cloning Client Simulator repository..."
    git clone https://github.com/lbockenstedt/cs.git
fi

echo "🛠️ Setting up Client Simulator..."
cd cs
python3 -m venv venv
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

echo "🎉 Client Simulator native installation complete!"
