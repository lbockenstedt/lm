#!/bin/bash
set -e

echo "🚀 Installing Lab Manager Hub (Native API-Only)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git

INSTALL_DIR="/root/lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d "lm/.git" ]; then
    echo "📂 Hub repository already exists. Updating..."
    cd lm && git pull && cd ..
else
    echo "🌐 Cloning Hub repository..."
    git clone https://github.com/lbockenstedt/lm.git
fi

echo "🛠️ Setting up Hub..."
cd lm

# 1. Robust venv creation
# Remove existing venv if it's broken or missing the binary
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then
    echo "⚠️  Detected broken virtual environment. Removing and recreating..."
    rm -rf venv
fi

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# 2. Verification
if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: Virtual environment binary not found at $(pwd)/venv/bin/python3"
    echo "Please ensure python3-venv is installed correctly."
    exit 1
fi

# 3. Installation using the explicit venv path
echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip
./venv/bin/python3 -m pip install -r hub/requirements.txt

echo "🎉 Hub native installation complete!"
echo "🚀 Start with: cd $INSTALL_DIR/lm && ./start_all.sh"
