#!/bin/bash

# Lab Manager Unified Installer
# Installs Docker and launches the full stack

set -e

echo "🚀 Starting Unified Lab Manager Installation..."

# 1. Check for Docker
if ! command -v docker &> /dev/null; then
    echo "🐳 Docker not found. Attempting to install via convenience script..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed. Please log out and back in, or run 'newgrp docker' before continuing."
    exit 0
fi

# 2. Build and Launch the Stack
echo "📦 Building and launching containers..."
docker compose up --build -d

echo ""
echo "🎉 System deployed successfully!"
echo "Hub: ws://localhost:8765 | API: http://localhost:8000"
echo "UI: http://localhost:5173"
echo "Run 'docker compose logs -f' to see the system in action."
