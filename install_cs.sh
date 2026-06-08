#!/bin/bash
set -e

# Default Hub URL
HUB_URL="ws://localhost:8765"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

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
    rm -rf venv
fi

if [ ! -d "venv" ]; then
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

# --- Hub Configuration ---
echo "⚙️ Configuring Hub connection..."
echo "HUB_URL=$HUB_URL" > .env
echo "Hub URL set to: $HUB_URL"

echo "🎉 Client Simulator native installation complete!"
echo "📦 Version: 0.07"
