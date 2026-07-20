#!/bin/bash
# uninstall_lm.sh — universal LM uninstaller. Removes EVERY trace of LM agents,
# spokes, modules, and helpers on this host, and purges all identity/state so a
# clone can NEVER reconnect under an old id (no surviving INSTALL_UUID anywhere).
#
# What it removes:
#   • systemd units — lm.service AND every lm-*.service / lm-*.timer (hub, spokes,
#     pxmx agent, module leaves, watchdogs, net-watchdog, self/update-restart,
#     role sub-spokes …) plus their drop-in dirs.
#   • install trees — /opt/lm (+ legacy /opt/lm-manager). This holds every
#     module/agent .env → INSTALL_UUID, HUB_SECRET, ids, venvs, and shared core.
#   • runtime/recovery state — /var/lib/lm, /var/lib/pxmx.
#   • /etc traces — /etc/lm-* (lm-agent, lm-cs-agent, lm-hub-self-agent config.json,
#     lm-encryption-secret, …).
#   • helper binaries — /usr/local/bin/lm-*.
#   • logs — /var/log/lm (keep with --keep-logs).
#   • the LM-MANAGED block in root's crontab (keep with --keep-crontab).
# After running, a reinstall mints a brand-new identity. It then VERIFIES nothing
# LM-related survives and reports any residue.
#
# SAFETY: a FULL wipe of LM on this box, INCLUDING the hub + shared /opt/lm/core.
# Run on a node you are decommissioning / re-imaging. Use --dry-run to preview.
# (To reset identity for a gold image WITHOUT removing code, use prep_for_imaging.sh.)
#
# Usage:
#   bash uninstall_lm.sh [--yes] [--dry-run] [--keep-logs] [--keep-crontab]
#
# One-liner from GitHub (must pass --yes when piped, no TTY for the prompt):
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall_lm.sh | bash -s -- --yes
set -uo pipefail

YES=0; DRY=0; KEEP_LOGS=0; KEEP_CRON=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)          YES=1; shift ;;
        --dry-run)      DRY=1; shift ;;
        --keep-logs)    KEEP_LOGS=1; shift ;;
        --keep-crontab) KEEP_CRON=1; shift ;;
        -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "❌ Run as root."; exit 1; }

run() { if [[ "$DRY" == 1 ]]; then echo "   would: $*"; else eval "$@"; fi; }

# ── Discover every LM unit: the lm-* family PLUS the bare lm.service ─────────
declare -a UNITS=()
while IFS= read -r u; do [[ -n "$u" ]] && UNITS+=("$u"); done < <(
    systemctl list-unit-files --no-legend 'lm-*' 'lm.service' 2>/dev/null | awk '{print $1}'
)
# Also sweep unit files on disk (masked/leftover units list-unit-files may skip).
while IFS= read -r f; do
    [[ -e "$f" ]] && UNITS+=("$(basename "$f")")
done < <(ls /etc/systemd/system/lm.service /etc/systemd/system/lm-*.service \
            /etc/systemd/system/lm-*.timer 2>/dev/null)
mapfile -t UNITS < <(printf '%s\n' "${UNITS[@]:-}" | sort -u | sed '/^$/d')

echo "🔎 LM uninstall on $(hostname) — will remove:"
echo "   Units (${#UNITS[@]}): ${UNITS[*]:-<none>}"
echo "   Dirs : /opt/lm /opt/lm-manager /var/lib/lm /var/lib/pxmx /etc/lm-* /usr/local/bin/lm-*$([[ $KEEP_LOGS == 0 ]] && echo ' /var/log/lm')"
[[ $KEEP_CRON == 0 ]] && echo "   Cron : LM-MANAGED block in root crontab"
echo

# ── Confirm (prompt on the real terminal, so curl|bash still works safely) ──
if [[ "$YES" != 1 && "$DRY" != 1 ]]; then
    if [[ -r /dev/tty ]]; then
        read -r -p "Permanently remove ALL LM components (incl. hub/core)? [y/N] " ans </dev/tty
        [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
    else
        echo "❌ No terminal for confirmation. Re-run with --yes (e.g. curl … | bash -s -- --yes)."
        exit 1
    fi
fi

# ── 1. Stop + disable every discovered unit ─────────────────────────────────
for u in "${UNITS[@]:-}"; do
    [[ -n "$u" ]] || continue
    run "systemctl stop '$u' 2>/dev/null || true"
    run "systemctl disable '$u' 2>/dev/null || true"
done

# ── 2. Remove unit files + drop-in dirs, then reload ────────────────────────
run "rm -f  /etc/systemd/system/lm.service /etc/systemd/system/lm-*.service /etc/systemd/system/lm-*.timer"
run "rm -rf /etc/systemd/system/lm.service.d /etc/systemd/system/lm-*.service.d /etc/systemd/system/lm-*.timer.d"
run "rm -f  /run/systemd/system/lm.service /run/systemd/system/lm-*.service /run/systemd/system/lm-*.timer 2>/dev/null || true"
run "systemctl daemon-reload"
run "systemctl reset-failed 2>/dev/null || true"

# ── 3. Kill any lingering agent/spoke processes ─────────────────────────────
run "pkill -f '/opt/lm/.*(src\\.agent|src\\.control_plane|generic-agent)' 2>/dev/null || true"

# ── 4. Purge install trees, ALL state/identity, /etc + /usr/local traces ────
run "rm -rf /opt/lm /opt/lm-manager"
run "rm -rf /var/lib/lm /var/lib/pxmx"
run "rm -rf /etc/lm-*"                       # lm-agent, lm-cs-agent, lm-hub-self-agent, lm-encryption-secret, …
run "rm -f  /usr/local/bin/lm-*"             # self-restart / update-restart helpers
[[ $KEEP_LOGS == 0 ]] && run "rm -rf /var/log/lm"

# ── 5. Strip the agent-managed LM-MANAGED block from root's crontab ─────────
if [[ $KEEP_CRON == 0 ]] && crontab -l 2>/dev/null | grep -q 'LM-MANAGED'; then
    if [[ "$DRY" == 1 ]]; then echo "   would: strip LM-MANAGED block from root crontab"
    else crontab -l 2>/dev/null | sed '/LM-MANAGED/,/LM-MANAGED/d' | crontab - 2>/dev/null || true; fi
fi

echo
[[ "$DRY" == 1 ]] && { echo "✅ Dry-run complete — nothing removed."; exit 0; }

# ── 6. Verify zero residue (this is what guarantees a clone is clean) ────────
echo "🔬 Verifying no LM trace remains…"
residue=0
leftover_units=$(systemctl list-unit-files --no-legend 'lm-*' 'lm.service' 2>/dev/null | awk '{print $1}')
[[ -n "$leftover_units" ]] && { echo "   ⚠ units still present: $leftover_units"; residue=1; }
for p in /opt/lm /opt/lm-manager /var/lib/lm /var/lib/pxmx /etc/lm-agent /etc/lm-cs-agent \
         /etc/lm-hub-self-agent /etc/lm-encryption-secret; do
    [[ -e "$p" ]] && { echo "   ⚠ still exists: $p"; residue=1; }
done
# The real prize: no INSTALL_UUID anywhere a spoke/agent could read one.
uuid_hits=$(grep -rls 'INSTALL_UUID' /opt /etc /var/lib 2>/dev/null | head)
[[ -n "$uuid_hits" ]] && { echo "   ⚠ INSTALL_UUID still on disk in: $uuid_hits"; residue=1; }

if [[ "$residue" == 0 ]]; then
    echo "✅ LM fully removed from $(hostname). No units, install trees, state, or INSTALL_UUID remain."
else
    echo "❌ Residue found above — remove it manually and re-verify before cloning."
    exit 1
fi
