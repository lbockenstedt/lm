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

# Hub API base URL. Allow override via environment variable for non-localhost deployments.
HUB_API="${HUB_API:-http://localhost:8000}"

# Unified agent-spoke model: this box runs ONE generic agent (which hosts every
# module as a role), so there is a single id to sync a secret for. Its role
# sub-spokes ({agent}-{role}) parent-auto-approve and need no separate secret.
declare -A SPOKE_IDS=(
    ["agent"]="agent-$(hostname -s)"
)

log_c "🔑 Starting Secret Synchronization..."

# Wait for the Hub API to be reachable AND ready.
# We use --fail so curl returns non-zero on 4xx/5xx responses (e.g., 503 while the
# WebSocket server is still starting). This prevents the script from proceeding
# against an API that is technically listening but not yet ready to serve requests.
MAX_RETRIES=30
COUNT=0
API_READY=false
while [ $COUNT -lt $MAX_RETRIES ]; do
    if curl -sf -o /dev/null --max-time 5 "$HUB_API/status" 2>/dev/null; then
        API_READY=true
        break
    fi
    log_c "Waiting for Hub API at $HUB_API to become ready... (attempt $((COUNT + 1))/$MAX_RETRIES)"
    sleep 2
    COUNT=$((COUNT + 1))
done

if [ "$API_READY" != "true" ]; then
    log_e "Hub API at $HUB_API is unreachable (or not ready) after $MAX_RETRIES attempts. Aborting."
    exit 1
fi

log_c "✅ Hub API is ready. Generating secrets for ${#SPOKE_IDS[@]} spokes."

FAILED_COUNT=0
SUCCESS_COUNT=0
TOTAL_COUNT=${#SPOKE_IDS[@]}

for mod in "${!SPOKE_IDS[@]}"; do
    SPOKE_ID=${SPOKE_IDS[$mod]}
    log_c "Processing $SPOKE_ID..."

    # Fetch real secret from Hub API.
    # Temporarily disable `set -e` around curl so a failed request (connection
    # error, timeout, non-2xx response) does not abort the entire script; we
    # track failures explicitly and decide exit status at the end.
    set +e
    RESPONSE=$(curl -s -X POST "$HUB_API/setup/generate-secret" \
        -H "Content-Type: application/json" \
        -d "{\"spoke_id\": \"$SPOKE_ID\"}" --max-time 10 2>/dev/null)
    CURL_EXIT=$?
    set -e

    SPOKE_SECRET=""
    if [ $CURL_EXIT -eq 0 ] && [ -n "$RESPONSE" ]; then
        SPOKE_SECRET=$(echo "$RESPONSE" | jq -r '.secret // empty' 2>/dev/null)
    fi

    if [ -n "$SPOKE_SECRET" ] && [ "$SPOKE_SECRET" != "null" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
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
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        log_e "Failed to generate secret for $SPOKE_ID. Is the Hub API running on $HUB_API?"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

# Decision logic:
#   - If ALL secret generations failed: exit non-zero and DO NOT print the
#     success message (avoids giving a false impression of success).
#   - If some succeeded but some failed: report partial status, exit non-zero
#     so callers can detect the issue.
#   - If all succeeded: print success message and exit 0.
if [ $SUCCESS_COUNT -eq 0 ]; then
    log_e "All $TOTAL_COUNT secret generations failed. Synchronization FAILED."
    exit 1
fi

if [ $FAILED_COUNT -gt 0 ]; then
    log_c "⚠️ Secret synchronization partially complete: $SUCCESS_COUNT/$TOTAL_COUNT succeeded, $FAILED_COUNT failed."
    exit 2
fi

log_c "🎉 Secret synchronization complete! ($SUCCESS_COUNT/$TOTAL_COUNT succeeded)"
exit 0