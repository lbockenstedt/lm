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
apt-get install -y python3-pip python3-venv git curl lsof net-tools jq sudo

# Mark all directories under /opt/lm as safe for git to avoid dubious ownership errors
git config --global --add safe.directory /opt/lm
git config --global --add safe.directory '/opt/lm/*'

# 3. Path Configuration
BASE_DIR="/opt/lm"
OLD_BASE_DIR="/opt/lm-manager"
SvcUser="svc_lm"

# Create non-root user for the service
if ! id -u "$SvcUser" >/dev/null 2>&1; then
    echo "👤 Creating system user $SvcUser..."
    useradd -r -m -d /opt/lm -s /usr/sbin/nologin "$SvcUser" || true
fi

# Grant svc_lm permission to restart the LM service without a password
echo "⚙️ Configuring sudoers for $SvcUser..."
echo "$SvcUser ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lm" > /etc/sudoers.d/lm
chmod 440 /etc/sudoers.d/lm

# Cleanup legacy installations
if [ -d "$OLD_BASE_DIR" ]; then
    echo "🗑️  Removing legacy installation at $OLD_BASE_DIR..."
    rm -rf "$OLD_BASE_DIR"
fi

mkdir -p "$BASE_DIR"
chown -R $SvcUser:$SvcUser "$BASE_DIR"
cd "$BASE_DIR"

# Clone core components (Hub and WebUI)
echo "🌐 Cloning Core Repository..."
rm -rf lm_tmp
git clone "https://github.com/lbockenstedt/lm.git" lm_tmp
rm -rf "$BASE_DIR/core" "$BASE_DIR/WebUI"
mv lm_tmp/core "$BASE_DIR/core"
mv lm_tmp/WebUI "$BASE_DIR/WebUI"
# Move remaining files from root of repo (start_all.sh, install scripts, etc.)
cp -r lm_tmp/* "$BASE_DIR/" 2>/dev/null || true
rm -rf lm_tmp

# Now we are in /opt/lm, and we have /opt/lm/core and /opt/lm/WebUI
# Sync other spokes
REPOS=("cs" "pxmx" "opnsense" "cppm")
for repo in "${REPOS[@]}"; do
    if [ -d "$repo/.git" ]; then
        echo "📂 $repo already exists. Updating..."
        cd "$repo"
        rm -rf venv
        git checkout .
        git pull
        cd ..
    else
        echo "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# 5. Run Modular Installers
echo "🛠️ Running modular installations..."

# Hub
echo "Setting up Hub Backend..."
cd "$BASE_DIR/core"

# Hub venv setup
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then rm -rf venv; fi
if [ ! -d "venv" ]; then python3 -m venv venv; fi
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install -r requirements.txt -q

# Start Hub temporarily for modular installation
echo "🚀 Starting Hub temporarily for modular setup..."
export PYTHONPATH="$BASE_DIR/core/src"
	if command -v sudo >/dev/null 2>&1; then
		sudo -u $SvcUser nohup "$BASE_DIR/core/venv/bin/python3" "$BASE_DIR/core/src/main.py" > "$BASE_DIR/hub.log" 2>&1 &
	else
		nohup "$BASE_DIR/core/venv/bin/python3" "$BASE_DIR/core/src/main.py" > "$BASE_DIR/hub.log" 2>&1 &
	fi

cd "$BASE_DIR"

# UI (Assets only)
echo "Setting up WebUI assets..."
cd "$BASE_DIR/WebUI"
if [ -f "install_ui.sh" ]; then
    bash ./install_ui.sh
else
    echo "✅ UI assets already in place (install_ui.sh not found in WebUI directory, skipping)."
fi
cd "$BASE_DIR"

# Give the Hub API a moment to fully start and stabilize
echo "⏳ Waiting for Hub API to initialize..."
until curl -s http://localhost:8000/status > /dev/null; do
    sleep 2
done
sleep 5

HUB_API="http://localhost:8000"
HUB_WS="ws://localhost:8765"

# Define modules and their corresponding installers
declare -A MODULES=(
    ["cs"]="install_cs.sh"
    ["pxmx"]="install_pxmx.sh"
    ["opnsense"]="install_opnsense.sh"
    ["cppm"]="install.sh"
)

# Map module keys to their actual Spoke IDs (must match start_all.sh)
declare -A SPOKE_IDS=(
    ["cs"]="cs-spoke-1"
    ["pxmx"]="pxmx-spoke-1"
    ["opnsense"]="opn-spoke-1"
    ["cppm"]="cppm-spoke-1"
)

for mod in "${!MODULES[@]}"; do
    installer=${MODULES[$mod]}
    SPOKE_ID=${SPOKE_IDS[$mod]}
    echo "Setting up $mod..."

    # Fetch First Secret from Hub API with retries
    SPOKE_SECRET=""
    for i in {1..10}; do
        SPOKE_SECRET=$(curl -s -X POST "$HUB_API/setup/generate-secret" \
            -H "Content-Type: application/json" \
            -d "{\"spoke_id\": \"$SPOKE_ID\"}" | jq -r '.secret' 2>/dev/null)
        if [ "$SPOKE_SECRET" != "null" ] && [ -n "$SPOKE_SECRET" ]; then
            echo "✅ Generated first-secret for $SPOKE_ID"
            break
        fi
        echo "⏳ Secret generation failed, retrying in 2s... ($i/10)"
        sleep 2
    done

    if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "null" ]; then
        echo "❌ Failed to generate secret for $SPOKE_ID. Using default (will fail auth)."
        SPOKE_SECRET="lm-secret"
    fi

    # Fetch Hub Secret for mutual authentication
    HUB_SECRET_FILE="$BASE_DIR/hub_secret.json"
    echo "⏳ Waiting for Hub to generate master secret..."
    for i in {1..10}; do
        if [ -f "$HUB_SECRET_FILE" ]; then
            break
        fi
        sleep 1
    done

    if [ -f "$HUB_SECRET_FILE" ]; then
        HUB_SECRET=$(cat "$HUB_SECRET_FILE")
        echo "✅ Loaded Hub secret for mutual auth"
    else
        echo "⚠️  Hub secret file not found at $HUB_SECRET_FILE. Mutual auth will be disabled."
        HUB_SECRET=""
    fi

    # Run the modular installer with the Hub-provided secret
    bash "$BASE_DIR/$mod/$installer" --hub "$HUB_WS" --id "$SPOKE_ID" --secret "$SPOKE_SECRET" --hub-secret "$HUB_SECRET"

done


# 6. Persistence & Auto-start
echo "⚙️ Configuring systemd for auto-start on reboot..."

# Final permission fix: ensure service user owns everything including files created by root during install
chown -R $SvcUser:$SvcUser "$BASE_DIR"

# Create the systemd service unit
cat <<EOF > /etc/systemd/system/lm.service
[Unit]
Description=Lab Manager Orchestrator
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=$SvcUser
WorkingDirectory=$BASE_DIR
ExecStart=/bin/bash $BASE_DIR/start_all.sh
ExecStop=/usr/bin/pkill -f python
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
systemctl daemon-reload
systemctl enable lm
systemctl restart lm

echo ""
echo "🎉 Native installation complete!"
echo "📂 All modules are located in: $BASE_DIR"
echo "⚙️ Service 'lm' is enabled and running."
echo "🚀 To manage the system: systemctl start|stop|restart lm"
echo "🌐 Hub API & Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
echo "📦 Version: 0.08"
