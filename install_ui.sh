#!/bin/bash
# ======================================================================
# DEPRECATED — do not use for new installs.
#
# OLD WebUI-asset deployment script. Superseded by:
#   install_all.sh        — moves WebUI/ into place as part of the repo clone
#   install_production.sh — one-liner wrapper around install_all.sh
#
# Anti-pattern vs install_all.sh: targets the legacy `lm_tmp/ui` -> `WebUI`
# layout, runs as root, and is paired with the deprecated install.sh which
# writes an lm.service using `User=root` + `ExecStop=pkill -f python`. No
# update snapshot/rollback. Behavior changes belong in install_all.sh.
# ======================================================================
set -e

echo "🚀 Deploying Lab Manager WebUI Assets (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

INSTALL_DIR="/opt/lm"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# The UI is part of the 'lm' repository
if [ -d "lm_tmp/.git" ]; then
    echo "📂 Hub/UI repository already exists. Updating..."
    cd lm_tmp && git pull --rebase --autostash && cd ..
else
    echo "🌐 Cloning Hub/UI repository..."
    git clone https://github.com/lbockenstedt/lm.git lm_tmp
fi

# Restructure if not already done
mv lm_tmp/ui "$INSTALL_DIR/WebUI" 2>/dev/null || true
mv lm_tmp/hub "$INSTALL_DIR/core" 2>/dev/null || true
cp -r lm_tmp/* "$INSTALL_DIR/" 2>/dev/null || true
rm -rf lm_tmp

UI_DIST_DIR="$INSTALL_DIR/WebUI"

# Verify UI assets are present
if [ -d "$UI_DIST_DIR" ]; then
    echo "✅ UI assets found at $UI_DIST_DIR"
else
    echo "⚠️  Warning: UI folder not found at $UI_DIST_DIR"
fi

echo ""
echo "🎉 WebUI asset deployment complete!"
echo "🌐 The Hub serves the dashboard natively on port 8000."
echo "🚀 Ensure the Hub Backend is running: cd $INSTALL_DIR && ./start_all.sh"
echo "📦 Version: 0.08"
