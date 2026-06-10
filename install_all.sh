#!/bin/bash
set -e

# ------------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------------
REINSTALL=false
RESET_SECRETS=false
for arg in "$@"; do
    if [ "$arg" == "--reinstall" ]; then
        REINSTALL=true
    elif [ "$arg" == "--reset-secrets" ]; then
        RESET_SECRETS=true
    fi
done

# ------------------------------------------------------------------
# Path Configuration & Logging
# ------------------------------------------------------------------
BASE_DIR="/opt/lm"
OLD_BASE_DIR="/opt/lm-manager"
SvcUser="svc_lm"
LOG_DIR="/var/log/lm"
INSTALL_LOG="$LOG_DIR/install.log"

# Create log directory early so logging helpers can work
mkdir -p "$LOG_DIR"
chown -R root:root "$LOG_DIR" # Temporary root ownership for installer
chmod 755 "$LOG_DIR"

# Logging Helpers
log() {
    # Standard info log: only to file
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$INSTALL_LOG" 2>/dev/null || true
}

log_c() {
    # Console and file: for high-level progress
    echo "$1"
    log "$1"
}

log_e() {
    # Error log: console and file
    echo "❌ $1" >&2
    log "ERROR: $1"
}

echo "🚀 Starting Native Lab Manager Installation (LXC-Optimized)..."

# 1. Pre-flight Check (Permissions)
log_c "🔍 Performing pre-flight checks..."
if [ "$(id -u)" -ne 0 ]; then
    log_e "This script must be run as root or with sudo."
    if command -v sudo >/dev/null 2>&1; then
        echo "👉 Please run: sudo bash $0"
        exit 1
    else
        log_e "Sudo not found. Root privileges are required for this installation."
        exit 1
    fi
fi

# 2. System Dependencies
log_c "📦 Installing system dependencies..."
apt-get update >> "$INSTALL_LOG" 2>&1
apt-get install -y python3-pip python3-venv git curl lsof net-tools jq sudo psmisc hostname systemd-container >> "$INSTALL_LOG" 2>&1

# Ensure consistent hostname for logging and diagnostics
log_c "🏷️  Setting system hostname to lm-hub..."
hostnamectl set-hostname lm-hub || echo "Hostname change failed (expected in some LXC environments)"

# Mark all directories under /opt/lm as safe for git to avoid dubious ownership errors
git config --global --add safe.directory /opt/lm
git config --global --add safe.directory '/opt/lm/*'

# ------------------------------------------------------------------
# User & Permission Setup
# ------------------------------------------------------------------
# Create non-root user for the service
if ! id -u "$SvcUser" >/dev/null 2>&1; then
    log_c "👤 Creating system user $SvcUser..."
    useradd -r -m -d /opt/lm -s /usr/sbin/nologin "$SvcUser" || true
fi

# Ensure global log directory ownership is correct now that user exists
chown -R $SvcUser:$SvcUser "$LOG_DIR"

# Grant svc_lm permission to restart the LM service without a password
log_c "⚙️ Configuring sudoers for $SvcUser..."
echo "$SvcUser ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lm" > /etc/sudoers.d/lm
chmod 440 /etc/sudoers.d/lm

# ------------------------------------------------------------------
# Reinstall Logic
# ------------------------------------------------------------------
# Always kill existing Hub processes to prevent "Address already in use"
log_c "🧹 Cleaning up existing Hub processes..."
systemctl stop lm || true
pkill -9 python || true
for port in 8000 8765; do
    pid=$(lsof -t -i :$port || true)
    if [ -n "$pid" ]; then
        kill -9 $pid || true
    fi
done

if [ "$REINSTALL" = true ]; then
    log_c "⚠️  REINSTALL MODE: Wiping all configuration, state, and installations..."
    # Remove installation directory and secrets
    rm -rf "$BASE_DIR"
    rm -f /etc/systemd/system/lm.service
    log_c "🧹 Clean slate achieved. Proceeding with fresh installation..."
fi

if [ "$RESET_SECRETS" = true ]; then
    log_c "🔑 RESET-SECRETS MODE: Wiping Hub identity and spoke keys..."
    # The secrets are located in $BASE_DIR/core/data
    rm -f "$BASE_DIR/core/data/keys.json"
    rm -f "$BASE_DIR/core/data/hub_secret.json"
    log_c "🧹 Secrets wiped. Hub will regenerate a new identity on start."
fi

# Cleanup legacy installations
if [ -d "$OLD_BASE_DIR" ]; then
    log_c "🗑️  Removing legacy installation at $OLD_BASE_DIR..."
    rm -rf "$OLD_BASE_DIR"
fi

mkdir -p "$BASE_DIR"
chown -R $SvcUser:$SvcUser "$BASE_DIR"
cd "$BASE_DIR"

# Clone core components (Hub and WebUI)
log_c "🌐 Cloning Core Repository..."
rm -rf lm_tmp
git clone "https://github.com/lbockenstedt/lm.git" lm_tmp

# Preserve data directory during updates
DATA_BACKUP_DIR="$BASE_DIR/core_data_backup"
if [ "$REINSTALL" = false ] && [ -d "$BASE_DIR/core/data" ]; then
    log "Preserving existing data directory during update..."
    mv "$BASE_DIR/core/data" "$DATA_BACKUP_DIR"
fi

rm -rf "$BASE_DIR/core" "$BASE_DIR/WebUI"
mv lm_tmp/core "$BASE_DIR/core"
mv lm_tmp/WebUI "$BASE_DIR/WebUI"

# Restore data directory
if [ -d "$DATA_BACKUP_DIR" ]; then
    log "Restoring preserved data directory..."
    rm -rf "$BASE_DIR/core/data"
    mv "$DATA_BACKUP_DIR" "$BASE_DIR/core/data"
fi

cp -r lm_tmp/* "$BASE_DIR/" 2>/dev/null || true
rm -rf lm_tmp

# Sync other spokes
REPOS=("cs" "pxmx" "opnsense" "cppm")
for repo in "${REPOS[@]}"; do
    if [ -d "$repo/.git" ]; then
        log_c "📂 $repo already exists. Updating..."
        cd "$repo"
        rm -rf venv
        git checkout .
        git pull
        cd ..
    else
        log_c "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# 5. Run Modular Installers
log_c "🛠️ Running modular installations..."

# Hub
log_c "Setting up Hub Backend..."
cd "$BASE_DIR/core"

# Hub venv setup
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then rm -rf venv; fi
if [ ! -d "venv" ]; then python3 -m venv venv; fi
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install -r requirements.txt -q

# Ensure the data directory exists and is owned by the service user
mkdir -p "$BASE_DIR/core/data"
chown -R $SvcUser:$SvcUser "$BASE_DIR"

# Start Hub temporarily for modular installation
log_c "🚀 Starting Hub temporarily for modular setup..."
export PYTHONPATH="$BASE_DIR/core/src"
if command -v sudo >/dev/null 2>&1; then
    sudo -u $SvcUser nohup "$BASE_DIR/core/venv/bin/python3" "$BASE_DIR/core/src/main.py" > "$LOG_DIR/hub.log" 2>&1 &
else
    nohup "$BASE_DIR/core/venv/bin/python3" "$BASE_DIR/core/src/main.py" > "$LOG_DIR/hub.log" 2>&1 &
fi

cd "$BASE_DIR"

# UI (Assets only)
log_c "Setting up WebUI assets..."
cd "$BASE_DIR/WebUI"
if [ -f "install_ui.sh" ]; then
    bash ./install_ui.sh
else
    log_c "✅ UI assets already in place (install_ui.sh not found in WebUI directory, skipping)."
fi
cd "$BASE_DIR"

# Give the Hub API a moment to fully start and stabilize
log_c "⏳ Waiting for Hub API and WebSocket server to initialize..."
until curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/status | grep -q "200"; do
    sleep 2
done
sleep 2

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
    log_c "Setting up $mod..."

    # Fetch First Secret from Hub API with retries
    SPOKE_SECRET=""
    for i in {1..15}; do
        # Using -v internally to log the attempt to the install log
        RESPONSE=$(curl -s -X POST "$HUB_API/setup/generate-secret" \
            -H "Content-Type: application/json" \
            -d "{\"spoke_id\": \"$SPOKE_ID\"}")

        SPOKE_SECRET=$(echo "$RESPONSE" | jq -r '.secret' 2>/dev/null)

        if [ "$SPOKE_SECRET" != "null" ] && [ -n "$SPOKE_SECRET" ]; then
            log_c "✅ Generated first-secret for $SPOKE_ID"
            break
        fi
        log_c "⏳ Secret generation failed, retrying in 3s... ($i/15). Response: $RESPONSE"
        sleep 3
    done

    if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "null" ]; then
        log_e "Failed to generate secret for $SPOKE_ID. Using default (will fail auth)."
        SPOKE_SECRET="lm-secret"
    fi

    # Fetch Hub Secret for mutual authentication
    HUB_SECRET_FILE="$BASE_DIR/core/data/hub_secret.json"
    log_c "⏳ Waiting for Hub to generate master secret..."
    for i in {1..10}; do
        if [ -f "$HUB_SECRET_FILE" ]; then
            break
        fi
        sleep 1
    done

    if [ -f "$HUB_SECRET_FILE" ]; then
        HUB_SECRET=$(cat "$HUB_SECRET_FILE")
        log_c "✅ Loaded Hub secret for mutual auth"
    else
        log_c "⚠️  Hub secret file not found at $HUB_SECRET_FILE. Mutual auth will be disabled."
        HUB_SECRET=""
    fi

    # Run the modular installer with the Hub-provided secret
    bash "$BASE_DIR/$mod/$installer" --hub "$HUB_WS" --id "$SPOKE_ID" --secret "$SPOKE_SECRET" --hub-secret "$HUB_SECRET"

    # Restart the spoke service to ensure it picks up the new secret
    log_c "🔄 Restarting $mod service to apply new secret..."
    systemctl restart "lm-$mod" || true
done

# 6. Persistence & Auto-start
log_c "⚙️ Configuring systemd for auto-start on reboot..."

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
log_c "🎉 Native installation complete!"
log_c "📂 All modules are located in: $BASE_DIR"
log_c "⚙️ Service 'lm' is enabled and running."
log_c "🚀 To manage the system: systemctl start|stop|restart lm"
log_c "🌐 Hub API & Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
log_c "📦 Version: 0.08"
