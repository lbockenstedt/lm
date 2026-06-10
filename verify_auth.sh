#!/bin/bash
# Lab Manager Auth Verification & Self-Healing Script
# Scans Hub logs for authentication failures and triggers secret synchronization if needed.

set -e

BASE_DIR="/opt/lm"
LOG_DIR="/var/log/lm"
HUB_LOG="$LOG_DIR/hub.log"
SNC_SCRIPT="$BASE_DIR/sync_secrets.sh"

# Logging Helpers
log_c() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ This script must be run as root."
    exit 1
fi

if [ ! -f "$HUB_LOG" ]; then
    echo "⚠️  Hub log not found at $HUB_LOG. Nothing to verify."
    exit 0
fi

log_c "🔍 Scanning Hub logs for authentication failures..."

# Look for "Authentication failed" warnings specifically involving the dev secret
# We use a case-insensitive grep for "Authentication failed" and check for "lm-secret"
FAILURES=$(grep "Authentication failed" "$HUB_LOG" | grep "lm-s...cret" || true)

if [ -z "$FAILURES" ]; then
    log_c "✅ No dev-secret authentication failures detected. Auth is healthy."
    exit 0
fi

log_c "❌ Detected spokes attempting to connect with fallback 'lm-secret'."
echo "$FAILURES" | tail -n 5

if [ -f "$SNC_SCRIPT" ]; then
    log_c "🚀 Triggering automatic secret synchronization..."
    bash "$SNC_SCRIPT"

    # Wait for spokes to reconnect and attempt auth again
    log_c "⏳ Waiting 10s for spokes to reconnect..."
    sleep 10

    # Final check
    RETRY_FAILURES=$(grep "Authentication failed" "$HUB_LOG" | tail -n 20 | grep "lm-s...cret" || true)
    if [ -z "$RETRY_FAILURES" ]; then
        log_c "✅ Self-healing successful: Fallback auth errors resolved."
    else
        log_e "⚠️  Secret sync was triggered, but authentication failures persist. Manual intervention may be required."
    fi
else
    log_e "Error: Secret sync script not found at $SNC_SCRIPT. Cannot self-heal."
    exit 1
fi
