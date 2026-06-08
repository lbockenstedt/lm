#!/bin/bash
set -e

echo "🚀 Deploying Lab Manager WebUI Assets (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

INSTALL_DIR="/root/lab-manager"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# The UI is part of the 'lm' repository
if [ -d "lm/.git" ]; then
    echo "📂 Hub/UI repository already exists. Updating..."
    cd lm && git pull && cd ..
else
    echo "🌐 Cloning Hub/UI repository..."
    git clone https://github.com/lbockenstedt/lm.git
fi

UI_DIST_DIR="$INSTALL_DIR/lm/ui/dist"

# Check if the build exists
if [ ! -d "$UI_DIST_DIR" ]; then
    echo "⚠️  Warning: UI build folder (dist) not found at $UI_DIST_DIR"
    echo "------------------------------------------------------------------------"
    echo "The WebUI is a static build. It must be compiled on a development machine"
    echo "using Node.js (npm run build) and the 'dist' folder must be uploaded to"
    echo "the server at $UI_DIST_DIR."
    echo "------------------------------------------------------------------------"
    echo "The Hub will still start, but the dashboard will be empty."
else
    echo "✅ UI build assets found at $UI_DIST_DIR"
fi

echo ""
echo "🎉 WebUI asset deployment complete!"
echo "🌐 The Hub serves the dashboard natively on port 8000."
echo "🚀 Ensure the Hub Backend is running: cd $INSTALL_DIR/lm && ./start_all.sh"
echo "📦 Version: 0.04"
