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

log_c "🔍 Scanning Hub logs for authentication status..."

# Unified agent-spoke model: one agent hosts every module as a role, so
# we verify the agent's auth (its role sub-spokes auth+approve via the parent).
SPOKES=("agent-$(hostname -s)")
ANY_FAILURES=false

echo "--------------------------------------------------"
printf "%-20s | %-15s\n" "SPOKE ID" "STATUS"
echo "--------------------------------------------------"

for sid in "${SPOKES[@]}"; do
    # Check if this spoke has a recent "Authentication failed" with lm-secret
    if grep "Authentication failed for spoke $sid" "$HUB_LOG" | grep -q "lm-s...cret"; then
        printf "%-20s | \033[0;31mFAIL (Fallback)\033[0m\n" "$sid"
        ANY_FAILURES=true
    elif grep -q "SPOKE_ID $sid" "$HUB_LOG" || grep -q "authenticated successfully" "$HUB_LOG" && grep -q "$sid" "$HUB_LOG"; then
        # Check for a positive authentication signal in the logs for this specific spoke
        printf "%-20s | \033[0;32mOK\033[0m\n" "$sid"
    else
        printf "%-20s | \033[0;33mUNKNOWN\033[0m\n" "$sid"
    fi
done
echo "--------------------------------------------------"

if [ "$ANY_FAILURES" = false ]; then
    log_c "✅ All spokes appear to be authenticating with real secrets."
    exit 0
fi

log_c "❌ Detected spokes attempting to connect with fallback 'lm-secret'."

if [ -f "$SNC_SCRIPT" ]; then
    log_c "🚀 Triggering automatic secret synchronization..."
    bash "$SNC_SCRIPT"

    # Wait for spokes to reconnect and attempt auth again
    log_c "⏳ Waiting 15s for spokes to reconnect..."
    sleep 15

    log_c "🔄 Re-verifying authentication..."
    echo "--------------------------------------------------"
    printf "%-20s | %-15s\n" "SPOKE ID" "STATUS"
    echo "--------------------------------------------------"

    FINAL_FAILURES=false
    for sid in "${SPOKES[@]}"; do
        # Check the end of the log for this spoke
        if grep "Authentication failed for spoke $sid" "$HUB_LOG" | tail -n 20 | grep -q "lm-s...cret"; then
            printf "%-20s | \033[0;31mSTILL FAILING\033[0m\n" "$sid"
            FINAL_FAILURES=true
        else
            printf "%-20s | \033[0;32mFIXED/OK\033[0m\n" "$sid"
        fi
    done
    echo "--------------------------------------------------"

    if [ "$FINAL_FAILURES" = false ]; then
        log_c "✅ Self-healing successful: Fallback auth errors resolved."
    else
        log_c "⚠️  Secret sync was triggered, but some spokes still fail. Manual intervention may be required."
        exit 1
    fi
else
    log_c "❌ Error: Secret sync script not found at $SNC_SCRIPT. Cannot self-heal."
    exit 1
fi
