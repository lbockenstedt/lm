#!/bin/bash
set -e

echo "🚀 Installing Lab Manager WebUI (Native Static)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# Install Nginx to serve the static frontend
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

UI_DIST_DIR="$INSTALL_DIR/lm/ui/dist"

# Check if the la-manager build exists
if [ ! -d "$UI_DIST_DIR" ]; then
    echo "⚠️  Warning: UI build folder (dist) not found at $UI_DIST_DIR"
    echo "The WebUI must be compiled (npm run build) and the 'dist' folder uploaded."
    echo "The server will still start, but the dashboard will be empty."
fi

echo "🛠️ Configuring Nginx to serve the Static UI..."
cat <<EOF > /etc/nginx/sites-available/labmanager
server {
    listen 80;
    server_name _;

    root $UI_DIST_DIR;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Proxy API requests to the Hub Backend on port 8000
    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

ln -sf /etc/nginx/sites-available/labmanager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

echo "🎉 WebUI installation complete!"
echo "🌐 Dashboard Access: http://$(hostname -I | awk '{print \$1}')"
echo "⚠️  Ensure the Hub Backend is running on port 8000 for the UI to function."
