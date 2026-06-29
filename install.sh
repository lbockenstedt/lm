#!/bin/bash
# ======================================================================
# DEPRECATED — do not use for new installs.
#
# This is the OLD monolithic installer. It is superseded by:
#   install_all.sh      — full hub + all-spokes native install (LXC-optimized)
#   install_production.sh — one-liner wrapper that fetches install_all.sh
#
# Known anti-patterns that make this unsafe relative to install_all.sh:
#   * Installs into /root/lm and runs the hub as `User=root` (lm.service below).
#   * Uses `ExecStop=/usr/bin/pkill -f python`, which kills EVERY Python on the
#     host (gunicorn, netbox-rq, every lm-* spoke) on each `systemctl stop lm`.
#   * No update-snapshot / rollback recovery, no sudoers self-restart helper.
#
# Kept only for archaeological reference. Behavior changes must be made in
# install_all.sh, NOT here. See CLAUDE.md / webui-update-recovery-gap notes.
# ======================================================================

# Lab Manager Installer
# Handles Hub and WebUI setup

set -e

echo "🚀 Starting Lab Manager installation..."

# 1. Check Prerequisites
echo "🔍 Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 is not installed."
    echo "Please install Python 3 from https://www.python.org/"
    exit 1
fi

echo "✅ Prerequisites found (Python3)."

# 2. Hub Setup
echo "📦 Setting up Hub..."
cd "$(dirname "$0")/hub"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Installing Python dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "✅ Hub setup complete."

# 3. WebUI Setup
echo "📦 Setting up WebUI plugin..."
cd "$(dirname "$0")/ui"

echo "✅ WebUI setup complete (Static assets are now served by the Hub)."

# 4. CS Module Setup
echo "📦 Setting up Client Simulator (CS) module..."
cd "$(dirname "$0")/cs"

if [ ! -d "venv" ]; then
    echo "Creating venv for CS module..."
    python3 -m venv venv
fi

echo "Installing CS dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "✅ CS module setup complete."

echo ""
echo "🎉 Installation successful!"
echo "You can now start the system using: ./start.sh"
