#!/bin/bash
set -e

echo "🚀 Installing Client Simulator Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl

INSTALL_DIR="/root/lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Ensure Hub is present for shared logic
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

# --- Robust Venv Setup ---
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then
    echo "⚠️  Broken venv detected. Recreating..."
    rm -rf venv
fi

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed. Binary not found at $(pwd)/venv/bin/python3"
    exit 1
fi

echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt
fi

echo "🎉 Client Simulator native installation complete!"
echo "📦 Version: 0.01"
