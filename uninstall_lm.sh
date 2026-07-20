#!/bin/bash
# uninstall_lm.sh — universal LM uninstaller. Removes EVERY LM agent, spoke,
# module, and helper unit on this host in one shot, and (by default) purges all
# identity/state so nothing can reconnect under an old id.
#
# Every LM component installs a systemd unit named lm-* (lm-hub, lm-cs, lm-pxmx,
# lm-pxmx-agent, lm-nw, lm-dns, lm-dhcp, lm-netbox, lm-ldap, lm-kvm, lm-cppm,
# lm-opnsense, lm-le, lm-collab-sink, lm-generic-agent, lm-watchdog[.timer],
# lm-*-net-watchdog, lm-self-restart-*, lm-update-restart-*, lm-spoke-recover,
# role sub-spokes, …) under /opt/lm, with state in /var/lib/lm + /var/lib/pxmx
# and logs in /var/log/lm. This sweeps all of them by the lm-* convention, so it
# stays complete as new modules are added — no per-module list to maintain.
#
# SAFETY: this is a FULL wipe of LM on the box, INCLUDING the hub and the shared
# /opt/lm/core, if present. Run it on a node you are decommissioning from LM. To
# preview without deleting, use --dry-run. To reset identity for imaging WITHOUT
# removing code, use prep_for_imaging.sh instead.
#
# Usage:
#   bash uninstall_lm.sh [--yes] [--dry-run] [--keep-logs] [--keep-crontab]
#
#   --yes           skip the confirmation prompt
#   --dry-run       list what would be stopped/removed, delete nothing
#   --keep-logs     keep /var/log/lm (default: removed)
#   --keep-crontab  don't touch the root crontab (default: strip LM-MANAGED block)
#
# One-liner from GitHub:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall_lm.sh | sudo bash -s -- --yes
set -uo pipefail

YES=0
DRY=0
KEEP_LOGS=0
KEEP_CRON=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)          YES=1; shift ;;
        --dry-run)      DRY=1; shift ;;
        --keep-logs)    KEEP_LOGS=1; shift ;;
        --keep-crontab) KEEP_CRON=1; shift ;;
        -h|--help)      sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "❌ Run as root (sudo)."; exit 1; }

run() { if [[ "$DRY" == 1 ]]; then echo "   would: $*"; else eval "$@"; fi; }

# ── Discover every lm-* unit (services AND timers), enabled or not ──────────
mapfile -t UNITS < <(systemctl list-unit-files --no-legend 'lm-*' 2>/dev/null | awk '{print $1}' | sort -u)
# Also catch any lm-* unit files on disk that list-unit-files may miss (masked /
# leftover) so nothing is stranded.
while IFS= read -r f; do
    [[ -e "$f" ]] || continue
    UNITS+=("$(basename "$f")")
done < <(ls /etc/systemd/system/lm-*.service /etc/systemd/system/lm-*.timer 2>/dev/null)
mapfile -t UNITS < <(printf '%s\n' "${UNITS[@]}" | sort -u | sed '/^$/d')

echo "🔎 LM uninstall on $(hostname) — the following will be removed:"
echo "   Units (${#UNITS[@]}): ${UNITS[*]:-<none>}"
echo "   Dirs : /opt/lm  /opt/lm-manager  /var/lib/lm  /var/lib/pxmx$([[ $KEEP_LOGS == 0 ]] && echo '  /var/log/lm')"
[[ $KEEP_CRON == 0 ]] && echo "   Cron : LM-MANAGED block in root crontab"
echo

if [[ "$DRY" == 1 ]]; then echo "(dry-run — nothing deleted)"; fi

if [[ "$YES" != 1 && "$DRY" != 1 ]]; then
    read -r -p "This permanently removes ALL LM components (incl. hub/core) on this host. Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ── 1. Stop + disable every lm-* unit ───────────────────────────────────────
for u in "${UNITS[@]}"; do
    run "systemctl stop '$u' 2>/dev/null || true"
    run "systemctl disable '$u' 2>/dev/null || true"
done

# ── 2. Remove unit files + drop-in dirs, then reload ────────────────────────
run "rm -f /etc/systemd/system/lm-*.service /etc/systemd/system/lm-*.timer"
run "rm -rf /etc/systemd/system/lm-*.service.d /etc/systemd/system/lm-*.timer.d"
run "rm -f /run/systemd/system/lm-*.service /run/systemd/system/lm-*.timer 2>/dev/null || true"
run "systemctl daemon-reload"
run "systemctl reset-failed 2>/dev/null || true"

# ── 3. Kill any lingering agent/spoke processes (belt + suspenders) ─────────
run "pkill -f '/opt/lm/.*(src\\.agent|src\\.control_plane)' 2>/dev/null || true"
run "pkill -f '/opt/lm/generic-agent' 2>/dev/null || true"

# ── 4. Purge install dirs (current + legacy) and ALL state/identity ─────────
#    Removing /opt/lm takes each module's .env (INSTALL_UUID + secrets + env),
#    its venv, and the shared /opt/lm/core. /var/lib/* holds recovery/runtime
#    state keyed by spoke id — gone so a reinstall is a clean new identity.
run "rm -rf /opt/lm /opt/lm-manager"
run "rm -rf /var/lib/lm /var/lib/pxmx"
[[ $KEEP_LOGS == 0 ]] && run "rm -rf /var/log/lm"

# ── 5. Strip the agent-managed LM-MANAGED block from the root crontab ───────
if [[ $KEEP_CRON == 0 ]]; then
    if crontab -l 2>/dev/null | grep -q 'LM-MANAGED'; then
        if [[ "$DRY" == 1 ]]; then
            echo "   would: strip LM-MANAGED block from root crontab"
        else
            crontab -l 2>/dev/null | sed '/LM-MANAGED/,/LM-MANAGED/d' | crontab - 2>/dev/null || true
        fi
    fi
fi

echo
[[ "$DRY" == 1 ]] && { echo "✅ Dry-run complete — nothing was removed."; exit 0; }
echo "✅ LM fully uninstalled from $(hostname). Reinstall with the module installer(s) for a clean identity."
