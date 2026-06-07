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
docker compose up --build -d opnsense
echo "🎉 OPNsense Manager deployed successfully!"
