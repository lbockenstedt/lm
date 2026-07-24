#!/usr/bin/env bash
# ======================================================================
# Lab Manager — Uninstaller
#
# Tears down EVERYTHING LM-related on this box: the hub (lm) + watchdog,
# any agent/spoke units, sudoers, the svc_lm user, and all LM data/config/
# log directories. Optionally also removes BugFixer (and Ollama).
#
# Discovery-first + guarded: it prints exactly what it will remove and
# requires a typed confirmation before touching anything. Safe to run on a
# box that has only some components (hub-only, agent-only, all-in-one).
#
# ⚠  DESTRUCTIVE + IRREVERSIBLE — wipes /var/lib/lm (Fernet-encrypted state),
#    certs, keys, and logs. There is no undo.
#
# Run:
#   sudo bash uninstall.sh                 # interactive, LM only
#   sudo bash uninstall.sh --bugfixer      # also remove BugFixer
#   sudo bash uninstall.sh --bugfixer --ollama   # also remove Ollama
#   sudo bash uninstall.sh --yes           # non-interactive (no prompt)
#   sudo bash uninstall.sh --dry-run       # show what would happen, change nothing
#
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall.sh | sudo bash -s -- --yes
# ======================================================================
set -o pipefail    # NOT -e/-u: teardown must survive missing/partial components + empty discovery arrays

ASSUME_YES=0
DRY_RUN=0
DO_BUGFIXER=0
DO_OLLAMA=0

for arg in "$@"; do
    case "$arg" in
        --yes|-y)     ASSUME_YES=1 ;;
        --dry-run|-n) DRY_RUN=1 ;;
        --bugfixer)   DO_BUGFIXER=1 ;;
        --ollama)     DO_OLLAMA=1; DO_BUGFIXER=1 ;;   # ollama was installed by bugfixer
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "uninstall: unknown flag '$arg' (see --help)" >&2; exit 2 ;;
    esac
done

# ── Colors (degrade when not a TTY) ──
if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_RESET=""
fi

# ── Require root (re-exec via sudo, preserving flags) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "${C_YELLOW}uninstall: re-running as root (sudo)…${C_RESET}"
    exec sudo -E bash "$0" "$@"
fi

# ── Known artifacts ──────────────────────────────────────────────────
# Explicit LM units (hub + watchdog + agent + legacy names).
LM_KNOWN_UNITS=(
    lm.service lm-watchdog.service lm-watchdog.timer
    lm-agent.service lm-generic-agent.service
    lm-manager.service lm-manager-watchdog.service
)
LM_DIRS=(/opt/lm /opt/lm-manager /var/lib/lm /var/log/lm /etc/lm /etc/lm-le /etc/lm-agent)
LM_SUDOERS=(/etc/sudoers.d/lm /etc/sudoers.d/lm-agent)
LM_USER="svc_lm"

BF_UNITS=(bugfixer.service bugfixer-watchdog.service)
BF_DIRS=(/opt/bugfixer /etc/bugfixer)
OLLAMA_UNITS=(ollama.service)

UNIT_DIR=/etc/systemd/system

# ── Discovery ────────────────────────────────────────────────────────
# Collect units to remove: the explicit LM names that exist, PLUS any unit
# file in $UNIT_DIR whose contents reference /opt/lm or /opt/lm-manager
# (catches per-spoke / loopback / role units regardless of name).
# Portable (no associative arrays / mapfile): dedup via a space-delimited string.
discover_units() {
    local seen=" " u f b
    _emit() { case "$seen" in *" $1 "*) return ;; esac; seen="$seen$1 "; printf '%s\n' "$1"; }
    for u in "${LM_KNOWN_UNITS[@]}"; do
        if [ -e "$UNIT_DIR/$u" ] || systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; then _emit "$u"; fi
    done
    # Glob lm-*.service / lm-*.timer
    for f in "$UNIT_DIR"/lm-*.service "$UNIT_DIR"/lm-*.timer; do
        [ -e "$f" ] && _emit "$(basename "$f")"
    done
    # Content-based: any unit referencing the LM install roots (catches per-spoke/role units)
    for f in "$UNIT_DIR"/*.service "$UNIT_DIR"/*.timer; do
        [ -e "$f" ] || continue
        grep -qE '/opt/lm(-manager)?(/|[[:space:]]|$)' "$f" 2>/dev/null && _emit "$(basename "$f")"
    done
}

existing_paths() { local p; for p in "$@"; do [ -e "$p" ] && printf '%s\n' "$p"; done; }
collect() { local __l; while IFS= read -r __l; do [ -n "$__l" ] && eval "$1+=(\"\$__l\")"; done; }

FOUND_UNITS=(); collect FOUND_UNITS < <(discover_units)
FOUND_DIRS=();  collect FOUND_DIRS  < <(existing_paths "${LM_DIRS[@]}")
FOUND_SUDO=();  collect FOUND_SUDO  < <(existing_paths "${LM_SUDOERS[@]}")
USER_EXISTS=0; id "$LM_USER" >/dev/null 2>&1 && USER_EXISTS=1

FOUND_BF_UNITS=(); FOUND_BF_DIRS=(); FOUND_OLLAMA_UNITS=()
if [ "$DO_BUGFIXER" -eq 1 ]; then
    for u in "${BF_UNITS[@]}"; do
        { [ -e "$UNIT_DIR/$u" ] || systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; } && FOUND_BF_UNITS+=("$u")
    done
    collect FOUND_BF_DIRS < <(existing_paths "${BF_DIRS[@]}")
fi
if [ "$DO_OLLAMA" -eq 1 ]; then
    for u in "${OLLAMA_UNITS[@]}"; do
        { [ -e "$UNIT_DIR/$u" ] || systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; } && FOUND_OLLAMA_UNITS+=("$u")
    done
fi

# Env values that live OUTSIDE the removed dirs: /etc/default, profile.d,
# /etc/environment, and (for bugfixer) the ollama systemd Environment= override.
# Note: hub/agent .env (/opt/lm/.env, /opt/lm/agent/.env) and per-unit
# Environment= lines / <unit>.service.d drop-ins are cleared with the dirs/units
# above; this covers everything else.
FOUND_ENVFILES=()
for f in /etc/default/lm /etc/default/lm-agent /etc/profile.d/lm.sh /etc/profile.d/lm-agent.sh \
         /etc/default/lm-* /etc/profile.d/lm-*.sh; do
    [ -e "$f" ] && FOUND_ENVFILES+=("$f")
done
ENV_PREFIXES='LM_|LABMANAGER_'
[ "$DO_BUGFIXER" -eq 1 ] && ENV_PREFIXES="$ENV_PREFIXES|BF_|BUGFIXER_"
ENV_HAS_LM=0
grep -qE "^[[:space:]]*($ENV_PREFIXES)[A-Z0-9_]+=" /etc/environment 2>/dev/null && ENV_HAS_LM=1
# Bugfixer-authored ollama Environment= override (only when we KEEP the ollama unit)
OLLAMA_OVERRIDE=/etc/systemd/system/ollama.service.d
BF_OLLAMA_OVERRIDE=0
[ "$DO_BUGFIXER" -eq 1 ] && [ "$DO_OLLAMA" -eq 0 ] && [ -d "$OLLAMA_OVERRIDE" ] && BF_OLLAMA_OVERRIDE=1

# ── Report ───────────────────────────────────────────────────────────
echo
echo "${C_BOLD}${C_CYAN}=== Lab Manager Uninstaller ===${C_RESET}"
[ "$DRY_RUN" -eq 1 ] && echo "${C_YELLOW}(dry-run — nothing will be changed)${C_RESET}"
echo
echo "${C_BOLD}Services/timers to stop + remove:${C_RESET}"
if [ "${#FOUND_UNITS[@]}" -eq 0 ]; then echo "  ${C_DIM}(none found)${C_RESET}"; else printf '  %s\n' "${FOUND_UNITS[@]}"; fi
[ "${#FOUND_BF_UNITS[@]}" -gt 0 ]     && { echo "${C_BOLD}BugFixer units:${C_RESET}"; printf '  %s\n' "${FOUND_BF_UNITS[@]}"; }
[ "${#FOUND_OLLAMA_UNITS[@]}" -gt 0 ] && { echo "${C_BOLD}Ollama units:${C_RESET}";   printf '  %s\n' "${FOUND_OLLAMA_UNITS[@]}"; }
echo
echo "${C_BOLD}Directories to delete:${C_RESET}"
if [ "${#FOUND_DIRS[@]}" -eq 0 ] && [ "${#FOUND_BF_DIRS[@]}" -eq 0 ]; then echo "  ${C_DIM}(none found)${C_RESET}"; else
    [ "${#FOUND_DIRS[@]}" -gt 0 ]    && printf '  %s\n' "${FOUND_DIRS[@]}"
    [ "${#FOUND_BF_DIRS[@]}" -gt 0 ] && printf '  %s\n' "${FOUND_BF_DIRS[@]}"
fi
echo
[ "${#FOUND_SUDO[@]}" -gt 0 ] && { echo "${C_BOLD}Sudoers to remove:${C_RESET}"; printf '  %s\n' "${FOUND_SUDO[@]}"; echo; }
if [ "${#FOUND_ENVFILES[@]}" -gt 0 ] || [ "$ENV_HAS_LM" -eq 1 ] || [ "$BF_OLLAMA_OVERRIDE" -eq 1 ]; then
    echo "${C_BOLD}Env values to clear:${C_RESET}"
    [ "${#FOUND_ENVFILES[@]}" -gt 0 ] && printf '  %s\n' "${FOUND_ENVFILES[@]}"
    [ "$ENV_HAS_LM" -eq 1 ]        && echo "  ${ENV_PREFIXES//|/, }* lines in /etc/environment"
    [ "$BF_OLLAMA_OVERRIDE" -eq 1 ] && echo "  $OLLAMA_OVERRIDE (bugfixer ollama Environment= override)"
    echo
fi
[ "$USER_EXISTS" -eq 1 ]      && echo "${C_BOLD}User to remove:${C_RESET} $LM_USER"
echo
echo "${C_RED}${C_BOLD}⚠  This DESTROYS all LM state (encrypted state, certs, keys, logs). Irreversible.${C_RESET}"
if [ "$DO_BUGFIXER" -eq 0 ]; then
    echo "${C_DIM}   BugFixer is NOT included (pass --bugfixer to also remove it).${C_RESET}"
fi

# Nothing to do?
if [ "${#FOUND_UNITS[@]}" -eq 0 ] && [ "${#FOUND_DIRS[@]}" -eq 0 ] && [ "${#FOUND_SUDO[@]}" -eq 0 ] \
   && [ "$USER_EXISTS" -eq 0 ] && [ "${#FOUND_BF_UNITS[@]}" -eq 0 ] && [ "${#FOUND_BF_DIRS[@]}" -eq 0 ] \
   && [ "${#FOUND_OLLAMA_UNITS[@]}" -eq 0 ] && [ "${#FOUND_ENVFILES[@]}" -eq 0 ] \
   && [ "$ENV_HAS_LM" -eq 0 ] && [ "$BF_OLLAMA_OVERRIDE" -eq 0 ]; then
    echo; echo "${C_GREEN}Nothing LM-related found on this box. Done.${C_RESET}"; exit 0
fi

# ── Confirm ──────────────────────────────────────────────────────────
if [ "$DRY_RUN" -eq 1 ]; then echo; echo "${C_YELLOW}Dry-run complete — no changes made.${C_RESET}"; exit 0; fi
if [ "$ASSUME_YES" -eq 0 ]; then
    echo
    if [ ! -t 0 ]; then
        echo "${C_RED}Refusing to proceed without a TTY. Re-run with --yes to confirm non-interactively.${C_RESET}"; exit 1
    fi
    read -rp "${C_BOLD}Type ${C_RED}REMOVE${C_RESET}${C_BOLD} to wipe everything above: ${C_RESET}" ans || ans=""
    if [ "$ans" != "REMOVE" ]; then echo "Aborted — nothing changed."; exit 1; fi
fi

# ── Teardown ─────────────────────────────────────────────────────────
echo; echo "${C_BOLD}Removing…${C_RESET}"

stop_and_remove_unit() {
    local u="$1"
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    systemctl stop "$u"           >/dev/null 2>&1 || true   # timers/oneshots
    rm -f  "$UNIT_DIR/$u" "$UNIT_DIR"/*/"$u" 2>/dev/null || true
    rm -rf "$UNIT_DIR/$u.d" 2>/dev/null || true             # drop-in override (Environment= values)
    echo "  ${C_GREEN}✓${C_RESET} unit $u"
}

for u in "${FOUND_UNITS[@]}" "${FOUND_BF_UNITS[@]}" "${FOUND_OLLAMA_UNITS[@]}"; do
    stop_and_remove_unit "$u"
done
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed  2>/dev/null || true

# Kill any straggler processes still holding LM install roots (best-effort).
pkill -f '/opt/lm(-manager)?/' 2>/dev/null || true
[ "$DO_BUGFIXER" -eq 1 ] && pkill -f '/opt/bugfixer/' 2>/dev/null || true

for d in "${FOUND_DIRS[@]}" "${FOUND_BF_DIRS[@]}"; do
    rm -rf "$d" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} dir  $d" || echo "  ${C_YELLOW}!${C_RESET} could not remove $d"
done

for s in "${FOUND_SUDO[@]}"; do
    rm -f "$s" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} sudoers $s"
done

# Env values outside the removed dirs.
for f in "${FOUND_ENVFILES[@]}"; do
    rm -f "$f" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} env  $f"
done
if [ "$ENV_HAS_LM" -eq 1 ]; then
    cp -a /etc/environment /etc/environment.lm-uninstall.bak 2>/dev/null || true
    if sed -i -E "/^[[:space:]]*($ENV_PREFIXES)[A-Z0-9_]+=/d" /etc/environment 2>/dev/null; then
        echo "  ${C_GREEN}✓${C_RESET} stripped ${ENV_PREFIXES//|/, }* from /etc/environment ${C_DIM}(backup: /etc/environment.lm-uninstall.bak)${C_RESET}"
    fi
fi
if [ "$BF_OLLAMA_OVERRIDE" -eq 1 ]; then
    rm -rf "$OLLAMA_OVERRIDE" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} env  $OLLAMA_OVERRIDE (ollama override)"
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart ollama 2>/dev/null || true   # let a kept ollama fall back to its defaults
fi

if [ "$USER_EXISTS" -eq 1 ]; then
    userdel "$LM_USER" >/dev/null 2>&1 && echo "  ${C_GREEN}✓${C_RESET} user $LM_USER" \
        || echo "  ${C_YELLOW}!${C_RESET} could not remove user $LM_USER (in use? try again after a reboot)"
fi

echo
echo "${C_GREEN}${C_BOLD}Lab Manager removed.${C_RESET}"
echo "${C_DIM}If any directory reported '!', a process still held it — reboot and re-run.${C_RESET}"
