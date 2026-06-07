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
docker compose up --build -d hub ui
echo "🎉 Hub and UI deployed successfully!"
echo "UI: http://localhost:5173 | API: http://localhost:8000"
