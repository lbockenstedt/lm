#!/bin/bash
# Lab Manager Secret Synchronization Script
# This script fetches real secrets from the Hub API and pushes them to the spoke configurations.

set -e

BASE_DIR="/opt/lm"
SvcUser="svc_lm"
LOG_DIR="/var/log/lm"
INSTALL_LOG="$LOG_DIR/sync_secrets.log"

# Logging Helpers
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$INSTALL_LOG" 2>/dev/null || true
}

log_c() {
    echo "$1"
    log "$1"
}

log_e() {
    echo "❌ $1" >&2
    log "ERROR: $1"
}

if [ "$(id -u)" -ne 0 ]; then
    log_e "This script must be run as root."
    exit 1
fi

mkdir -p "$LOG_DIR"
chown -R root:root "$LOG_DIR"
chmod 755 "$LOG_DIR"

HUB_API="http://localhost:8000"

# Define modules and their corresponding Spoke IDs
declare -A SPOKE_IDS=(
    ["cs"]="cs-spoke-1"
    ["pxmx"]="pxmx-spoke-1"
    ["opnsense"]="opn-spoke-1"
    ["cppm"]="cppm-spoke-1"
)

log_c "🔑 Starting Secret Synchronization..."

for mod in "${!SPOKE_IDS[@]}"; do
    SPOKE_ID=${SPOKE_IDS[$mod]}
    log_c "Processing $SPOKE_ID..."

    # Fetch real secret from Hub API
    SPOKE_SECRET=$(curl -s -X POST "$HUB_API/setup/generate-secret" \
        -H "Content-Type: application/json" \
        -d "{\"spoke_id\": \"$SPOKE_ID\"}" | jq -r '.secret' 2>/dev/null)

    if [ "$SPOKE_SECRET" != "null" ] && [ -n "$SPOKE_SECRET" ]; then
        log_c "✅ Fetched secret for $SPOKE_ID: ${SPOKE_SECRET:0:4}...${SPOKE_SECRET: -4}"

        SPOKE_PATH="$BASE_DIR/$mod"
        if [ -d "$SPOKE_PATH" ]; then
            # Update .env file
            if [ -f "$SPOKE_PATH/.env" ]; then
                sed -i "s/^SPOKE_SECRET=.*/SPOKE_SECRET=$SPOKE_SECRET/" "$SPOKE_PATH/.env"
                log_c "Updated .env for $SPOKE_ID"
            fi

            # Update systemd unit
            SERVICE_FILE="/etc/systemd/system/lm-$mod.service"
            if [ -f "$SERVICE_FILE" ]; then
                sed -i "s/--secret [^ ]*/--secret $SPOKE_SECRET/" "$SERVICE_FILE"
                systemctl daemon-reload
                log_c "Updated systemd unit for $SPOKE_ID"
            fi

            # Restart to apply
            systemctl restart "lm-$mod" || true
            log_c "🔄 Restarted $SPOKE_ID to apply new secret."
        else
            log_e "Module directory $SPOKE_PATH not found. Skipping update."
        fi
    else
        log_e "Failed to generate secret for $SPOKE_ID. Is the Hub API running on $HUB_API?"
    fi
done

log_c "🎉 Secret synchronization complete!"
