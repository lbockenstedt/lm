#!/bin/bash
set -e

echo "🚀 Deploying Lab Manager WebUI Assets (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

INSTALL_DIR="/root/lm-manager"
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

UI_DIST_DIR="$INSTALL_DIR/lm/ui"

# Verify UI assets are present
if [ -d "$UI_DIST_DIR" ]; then
    echo "✅ UI assets found at $UI_DIST_DIR"
else
    echo "⚠️  Warning: UI folder not found at $UI_DIST_DIR"
fi

echo ""
echo "🎉 WebUI asset deployment complete!"
echo "🌐 The Hub serves the dashboard natively on port 8000."
echo "🚀 Ensure the Hub Backend is running: cd $INSTALL_DIR/lm && ./start_all.sh"
echo "📦 Version: 0.08"
