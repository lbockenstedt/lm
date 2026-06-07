#!/bin/bash
set -e

echo "🚀 Installing OPNsense Manager Module..."

if ! command -v docker &> /dev/null; then
    echo "🐳 Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed. Please restart your shell."
    exit 0
fi

INSTALL_DIR="lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "🌐 Cloning required repositories..."
git clone https://github.com/lbockenstedt/lm.git
git clone https://github.com/lbockenstedt/opnsense.git

echo "📦 Launching OPNsense Manager..."
cd lm
docker compose up --build -d opnsense

echo "🎉 OPNsense Manager deployed successfully!"
