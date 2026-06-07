#!/bin/bash
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

# 4. Build and Launch
echo "📦 Building and launching containers..."
cd lm
docker compose up --build -d

echo ""
echo "🎉 System deployed successfully!"
echo "Hub: ws://localhost:8765 | API: http://localhost:8000"
echo "UI: http://localhost:5173"
echo "Run 'docker compose logs -f' to see the system in action."
