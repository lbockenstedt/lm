#!/bin/bash
set -e

echo "🚀 Starting Native Lab Manager Installation (Non-Docker)..."

# 1. Install System Dependencies
echo "📦 Installing system dependencies (Python, Node.js, venv)..."
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run this script as root or with sudo."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv nodejs npm git curl

# 2. Setup Project Directory
INSTALL_DIR="lab-manager"
echo "📂 Creating project directory: $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 3. Clone Repositories
echo "🌐 Cloning repositories..."
git clone https://github.com/lbockenstedt/lm.git
git clone https://github.com/lbockenstedt/cs.git
git clone https://github.com/lbockenstedt/pxmx.git
git clone https://github.com/lbockenstedt/opnsense.git

# 4. Setup Virtual Environments & Dependencies
echo "🛠️ Setting up Python environments and Node.js..."

# Hub
echo "Setting up Hub..."
cd lm
python3 -m venv venv
./venv/bin/pip install -r hub/requirements.txt
# UI
echo "Setting up UI..."
cd ui
npm install
cd ..

# CS
echo "Setting up Client Simulator..."
cd ../cs
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cd ../lm

# PXMX
echo "Setting up Proxmox Manager..."
cd ../pxmx
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cd ../lm

# OPNsense
echo "Setting up OPNsense Manager..."
cd ../opnsense
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cd ..

echo ""
echo "🎉 Native installation complete!"
echo "📂 Project located in: $INSTALL_DIR"
echo "🚀 To start the system, run: cd $INSTALL_DIR/lm && ./start_all.sh"
