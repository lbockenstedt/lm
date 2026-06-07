#!/bin/bash
set -e

echo "🚀 Starting Native Lab Manager Installation (API-Only Mode)..."

# 1. Install System Dependencies
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

# Removed Node.js and npm from requirements
apt-get update
apt-get install -y python3-pip python3-venv git curl

# 2. Define Paths
BASE_DIR="/Users/lbockenstedt/vscode"
REPOS=("lm" "cs" "pxmx" "opnsense")

# 3. Clone or Detect Repositories
for repo in "${REPOS[@]}"; do
    if [ ! -d "$BASE_DIR/$repo" ]; then
        echo "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git" "$BASE_DIR/$repo"
    else
        echo "📂 $repo repository already exists. Using existing directory."
    fi
done

# 4. Setup Environments
echo "🛠️ Setting up Python environments..."

# Hub
echo "Setting up Hub..."
cd "$BASE_DIR/lm"
python3 -m venv venv
./venv/bin/pip install -r hub/requirements.txt

# CS
echo "Setting up Client Simulator..."
cd "$BASE_DIR/cs"
python3 -m venv venv
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

# PXMX
echo "Setting up Proxmox Manager..."
cd "$BASE_DIR/pxmx"
python3 -m venv venv
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

# OPNsense
echo "Setting up OPNsense Manager..."
cd "$BASE_DIR/opnsense"
python3 -m venv venv
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

echo ""
echo "🎉 Native API-Only installation complete!"
echo "🚀 To start the system, run: cd $BASE_DIR/lm && ./start_all.sh"
