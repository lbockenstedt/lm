#!/bin/bash
set -e

echo "🚀 Installing Lab Manager Hub & UI..."

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

echo "🌐 Cloning Hub repository..."
git clone https://github.com/lbockenstedt/lm.git

echo "📦 Launching Hub and UI..."
cd lm
docker compose up --build -d hub ui

echo "🎉 Hub and UI deployed successfully!"
echo "UI: http://localhost:5173 | API: http://localhost:8000"
