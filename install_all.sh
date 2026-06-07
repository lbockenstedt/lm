#!/bin/bash
set -e

echo "🚀 Starting Native Lab Manager Installation (Reinstall-Safe)..."

# 1. Install System Dependencies
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This step requires root privileges. Please run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv nodejs npm git curl

# 2. Define Paths
BASE_DIR="/root/lab-manager"
if [ ! -d "$BASE_DIR" ] && [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$BASE_DIR"
fi
cd "$BASE_DIR"

REPOS=("lm" "cs" "pxmx" "opnsense")

# 3. Clone or Update Repositories
for repo in "${REPOS[@]}"; do
    if [ -d "$repo/.git" ]; then
        echo "📂 $repo already exists. Updating..."
        cd "$repo"
        git pull
        cd ..
    else
        echo "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# Get version from the Hub repository
VERSION=$(cat lm/VERSION 2>/dev/null || echo "unknown")
echo "📦 Installing Lab Manager version $VERSION..."

# 4. Setup Environments
echo "🛠️ Setting up Python environments..."

# Hub
echo "Setting up Hub..."
cd "$BASE_DIR/lm"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r hub/requirements.txt

# CS
echo "Setting up Client Simulator..."
cd "$BASE_DIR/cs"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

# PXMX
echo "Setting up Proxmox Manager..."
cd "$BASE_DIR/pxmx"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

# OPNsense
echo "Setting up OPNsense Manager..."
cd "$BASE_DIR/opnsense"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
fi

echo ""
echo "🎉 Native installation/update complete (v$VERSION)!"
echo "🚀 To start the system, run: cd $BASE_DIR/lm && ./start_all.sh"
