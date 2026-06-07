#!/bin/bash

# Common LXC Bootstrap script for Lab Manager modules
set -e

echo "🛠️ Bootstrapping environment for Lab Manager module..."

# Update and install base dependencies
apt-get update
apt-get install -y python3 python3-pip python3-venv git curl wget build-essential

# If Node.js is needed (for UI)
if [[ "$1" == "ui" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

echo "✅ Base environment ready."
