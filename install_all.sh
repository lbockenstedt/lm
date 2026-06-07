#!/bin/bash
set -e

echo "🚀 Starting Native Lab Manager Installation (LXC-Optimized)..."

# 1. Root Check
if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# 2. System Dependencies
echo "📦 Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv git curl nginx

# 3. Path Configuration
BASE_DIR="/root/lab-manager"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

REPOS=("lm" "cs" "pxmx" "opnsense")

# 4. Repository Sync
for repo in "${REPOS[@]}"; do
    if [ -d "$repo/.git" ]; then
        echo "📂 $repo already exists. Updating..."
        cd "$repo" && git pull && cd ..
    else
        echo "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# 5. Run Modular Installers
echo "🛠️ Running modular installations..."

# Hub (installed first as it is a dependency for others)
echo "Setting up Hub..."
cd "$BASE_DIR/lm"
bash ./install_hub.sh
cd "$BASE_DIR"

# CS
echo "Setting up Client Simulator..."
cd "$BASE_DIR/cs"
bash ./install_cs.sh
cd "$BASE_DIR"

# PXMX
echo "Setting up Proxmox Manager..."
cd "$BASE_DIR/pxmx"
bash ./install_pxmx.sh
cd "$BASE_DIR"

# OPNsense
echo "Setting up OPNsense Manager..."
cd "$BASE_DIR/opnsense"
bash ./install_opnsense.sh
cd "$BASE_DIR"

# 6. Optional: Configure UI (if dist folder exists)
if [ -d "$BASE_DIR/lm/ui/dist" ]; then
    echo "🎨 Found UI build assets. Configuring Nginx..."
    cat <<EOF > /etc/nginx/sites-available/labmanager
server {
    listen 80;
    root $BASE_DIR/lm/ui/dist;
    index index.html;
    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/labmanager /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    systemctl restart nginx
fi

echo ""
echo "🎉 Native installation complete!"
echo "📂 All modules are located in: $BASE_DIR"
echo "🚀 To start the Hub and Spokes, run: cd $BASE_DIR/lm && ./start_all.sh"
echo "🌐 Hub API: http://$(hostname -I | awk '{print \$1}'):8000"
echo "🌐 Dashboard: http://$(hostname -I | awk '{print \$1}')"
