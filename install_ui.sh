#!/bin/bash
set -e

echo "🚀 Installing Lab Manager WebUI (Native Static)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# Install Nginx to serve the static files
apt-get update
apt-get install -y nginx git curl

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

# Path to the compiled UI assets
# NOTE: These must be built on a dev machine and pushed to the repo
# or built via a CI pipeline.
UI_DIST_DIR="$INSTALL_DIR/lm/ui/dist"

if [ ! -d "$UI_DIST_DIR" ]; then
    echo "❌ Error: Static UI build (dist folder) not found at $UI_DIST_DIR"
    echo "The WebUI must be compiled (npm run build) before it can be served natively."
    exit 1
fi

echo "🛠️ Configuring Nginx to serve the UI..."
# Create a simple Nginx config to serve the static files on port 80
cat <<EOF > /etc/nginx/sites-available/labmanager
server {
    listen 80;
    root $UI_DIST_DIR;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/labmanager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

systemctl restart nginx

echo "🎉 WebUI native installation complete!"
echo "🌐 Access the dashboard at: http://$(hostname -I | awk '{print \$1}')"
echo "⚠️  Ensure the Hub is running on its own instance to enable API connectivity."
