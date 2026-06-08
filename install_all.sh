#!/bin/bash
set -e

echo "🚀 Starting Native Lab Manager Installation (LXC-Optimized)..."

# 1. Root Check
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# 2. System Dependencies
echo "📦 Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv git curl

# 3. Path Configuration
BASE_DIR="/root/lab-manager"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

REPOS=("lm" "cs" "pxmx" "opnsense")

# 4. Repository Sync
for repo in "${REPOS[@]}"; do
    if [ -d "$repo/.git" ]; then
        echo "📂 $repo already exists. Updating via git pull..."
        cd "$repo" && git pull && cd ..
    else
        echo "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# 5. Run Modular Installers
echo "🛠️ Running modular installations..."

# Hub
echo "Setting up Hub Backend..."
cd "$BASE_DIR/lm"
bash ./install_hub.sh
cd "$BASE_DIR"

# UI (Assets only)
echo "Setting up WebUI assets..."
cd "$BASE_DIR/lm"
bash ./install_ui.sh
cd "$BASE_DIR"

# CS
echo "Setting up Client Simulator..."
cd "$BASE_DIR/cs"
bash ./install_cs.sh
cd "$BASE_DIR"

# PXMX
echo "Setting up Proxmox Manager..."
cd "$BASE_DIR/pxmx"
bash ./install_pxmx.sh
cd "$BASE_DIR"

# OPNsense
echo "Setting up OPNsense Manager..."
cd "$BASE_DIR/opnsense"
bash ./install_opnsense.sh
cd "$BASE_DIR"

echo ""
echo "🎉 Native installation complete!"
echo "📂 All modules are located in: $BASE_DIR"
echo "🚀 To launch the system, run: cd $BASE_DIR/lm && ./start_all.sh"
echo "🌐 Hub API & Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
