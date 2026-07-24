#!/usr/bin/env bash
# ======================================================================
# Lab Manager — MASTER Uninstaller
#
# Removes EVERY LM-owned component across the whole ecosystem on this box —
# hub, watchdog, generic agent, all spoke roles (dns/dhcp/nw/cppm/opnsense/
# truenas/le/ldap/netbox/pxmx/cs/console/...), the pxmx host agent, the
# client-sim agents/dashboard/proxmox-agent, collab sink, and BugFixer —
# plus their dirs, /usr/local/bin helpers, sudoers, systemd drop-ins,
# sysctl/modules/cron/logrotate entries, LM users, and LM env values.
#
# Discovery-first + guarded: prints exactly what it will remove and requires
# a typed confirmation. Run it on each box; it only touches what's present.
#
# SHARED infrastructure is NEVER removed by default — postgresql, redis,
# nginx, unbound, kea, slapd/openldap, certbot (/etc/letsencrypt), ollama,
# dnsmasq, rsyslog, firewalld, kdump-tools. It is only WARNED about (opt in
# with the flags below). Host networking (the cs `vmbr255` bridge and
# /etc/network/interfaces edits) is NEVER touched — revert those by hand.
#
# ⚠  DESTRUCTIVE + IRREVERSIBLE — wipes LM state (Fernet-encrypted), certs,
#    keys, logs, and (for netbox) the app checkout. No undo.
#
# Run:
#   sudo bash uninstall.sh                 # interactive (type REMOVE)
#   sudo bash uninstall.sh --yes           # non-interactive
#   sudo bash uninstall.sh --dry-run       # preview, change nothing
#
# Opt-in extras (shared infra — off by default):
#   --ollama          also remove ollama.service + its override (bugfixer)
#   --letsencrypt     also remove /etc/letsencrypt + /var/lib|log/letsencrypt
#   --netbox-db       also DROP the netbox Postgres database + role
#   --nginx-site      also remove the netbox nginx site (safe; LM-owned file)
#   --keep-bugfixer   do NOT remove BugFixer (it is removed by default here)
#
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall.sh | sudo bash -s -- --yes
# ======================================================================
set -o pipefail    # NOT -e/-u: teardown must survive partial installs + empty arrays

ASSUME_YES=0; DRY_RUN=0
DO_OLLAMA=0; DO_LE=0; DO_NBDB=0; DO_NGINX=0; KEEP_BUGFIXER=0

for arg in "$@"; do
    case "$arg" in
        --yes|-y)       ASSUME_YES=1 ;;
        --dry-run|-n)   DRY_RUN=1 ;;
        --ollama)       DO_OLLAMA=1 ;;
        --letsencrypt)  DO_LE=1 ;;
        --netbox-db)    DO_NBDB=1 ;;
        --nginx-site)   DO_NGINX=1 ;;
        --keep-bugfixer) KEEP_BUGFIXER=1 ;;
        -h|--help)      sed -n '2,42p' "$0"; exit 0 ;;
        *) echo "uninstall: unknown flag '$arg' (see --help)" >&2; exit 2 ;;
    esac
done

# ── Colors ──
if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_RESET=""
fi

# ── Root ──
if [ "$(id -u)" -ne 0 ]; then
    echo "${C_YELLOW}uninstall: re-running as root (sudo)…${C_RESET}"
    exec sudo -E bash "$0" "$@"
fi

UNIT_DIR=/etc/systemd/system

# ── Known artifacts ──────────────────────────────────────────────────
# Distinctive LM unit-name globs (safe to match by name).
LM_UNIT_GLOBS=(lm-* client-sim-* webui-watchdog* proxmox-watchdog* kea-*-sim t3-simulation)
# Exact units incl. generically-named app units (also confirmed by content match).
LM_UNITS_EXACT=(lm.service lm-watchdog.service lm-watchdog.timer lm-hub.service
                lm-manager.service lm-manager-watchdog.service lm-generic-agent.service
                netbox.service netbox-rq.service hub.service)
# A unit file is LM-owned if its contents reference an LM install root / user / log.
LM_CONTENT_RE='/opt/lm(-manager)?(/|[[:space:]]|$)|/opt/netbox-app|/opt/hub(/|[[:space:]]|$)|/opt/bugfixer|/opt/client-sim|/opt/proxmox-agent-installer|/var/log/lm|/var/log/bugfixer|/var/log/client-sim|User=svc_lm|User=svc_bg'
BF_UNITS=(bugfixer.service bugfixer-watchdog.service)

LM_DIRS=(
    /opt/lm /opt/lm-manager /opt/netbox-app /opt/hub /opt/bugfixer
    /opt/client-sim-dashboard /opt/proxmox-agent-installer
    /var/lib/lm /var/lib/pxmx /var/lib/client-sim /var/lib/hub
    /var/lib/webui-watchdog /var/lib/proxmox-watchdog
    /var/log/lm
    /etc/lm /etc/lm-le /etc/lm-agent /etc/lm-cs-agent /etc/lm-netbox-agent
    /etc/bugfixer /etc/client-sim
    /usr/src/wifi-drivers /usr/local/scripts /usr/scripts /etc/pve/scripts
)
LM_FILES=(
    /var/log/bugfixer.log /var/log/bugfixer_watchdog.log
    /var/log/client-sim-sync.log /var/log/client-sim-dashboard-install.log
    /var/log/client-sim-proxmox-agent.log
    /etc/logrotate.d/lm
    /etc/sysctl.d/99-lm-pxmx-watchdog.conf /etc/modules-load.d/lm-pxmx-watchdog.conf
    /etc/cron.d/client-sim-sync
    /etc/dnsmasq.d/client-sim.conf
    /etc/systemd/system/dnsmasq.service.d/wait-for-interface.conf
)
LM_BIN_GLOBS=(/usr/local/bin/lm-* /usr/local/bin/bugfixer-*)
LM_SUDOERS=(/etc/sudoers.d/lm /etc/sudoers.d/lm-agent /etc/sudoers.d/lm-netbox
            /etc/sudoers.d/lm-component-update /etc/sudoers.d/bugfixer
            /etc/sudoers.d/client-sim-dashboard)
# svc_lm/svc_bg are LM-specific; sim-user/dashboard removed only if their units were found.
LM_USERS_ALWAYS=(svc_lm svc_bg)
NGINX_SITES=(/etc/nginx/sites-available/netbox /etc/nginx/sites-enabled/netbox)
LE_DIRS=(/etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt)

# ── Discovery helpers (portable: no assoc-arrays / mapfile) ──
existing_paths() { local p; for p in "$@"; do [ -e "$p" ] && printf '%s\n' "$p"; done; }
collect() { local __l; while IFS= read -r __l; do [ -n "$__l" ] && eval "$1+=(\"\$__l\")"; done; }
in_list() { local n="$1"; shift; local x; for x in "$@"; do [ "$x" = "$n" ] && return 0; done; return 1; }

discover_units() {
    local seen=" " u f b
    _emit() { case "$seen" in *" $1 "*) return ;; esac; seen="$seen$1 "; printf '%s\n' "$1"; }
    # Exact known units (skip bugfixer here — gated separately)
    for u in "${LM_UNITS_EXACT[@]}"; do
        if [ -e "$UNIT_DIR/$u" ] || systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; then
            # Generic names (netbox/hub) only if content confirms LM ownership.
            case "$u" in
                netbox.service|netbox-rq.service|hub.service)
                    [ -e "$UNIT_DIR/$u" ] && grep -qE "$LM_CONTENT_RE" "$UNIT_DIR/$u" 2>/dev/null && _emit "$u" ;;
                *) _emit "$u" ;;
            esac
        fi
    done
    # Distinctive globs
    for g in "${LM_UNIT_GLOBS[@]}"; do
        for f in "$UNIT_DIR"/$g.service "$UNIT_DIR"/$g.timer; do
            [ -e "$f" ] && _emit "$(basename "$f")"
        done
    done
    # Content-based (catches any generically-named unit referencing LM roots)
    for f in "$UNIT_DIR"/*.service "$UNIT_DIR"/*.timer; do
        [ -e "$f" ] || continue
        grep -qE "$LM_CONTENT_RE" "$f" 2>/dev/null && _emit "$(basename "$f")"
    done
}

FOUND_UNITS=();   collect FOUND_UNITS   < <(discover_units)
FOUND_DIRS=();    collect FOUND_DIRS    < <(existing_paths "${LM_DIRS[@]}")
FOUND_FILES=();   collect FOUND_FILES   < <(existing_paths "${LM_FILES[@]}")
FOUND_SUDO=();    collect FOUND_SUDO    < <(existing_paths "${LM_SUDOERS[@]}")
FOUND_BINS=();    for f in "${LM_BIN_GLOBS[@]}"; do [ -e "$f" ] && FOUND_BINS+=("$f"); done

# BugFixer (on by default; --keep-bugfixer skips)
FOUND_BF_UNITS=()
if [ "$KEEP_BUGFIXER" -eq 0 ]; then
    for u in "${BF_UNITS[@]}"; do
        { [ -e "$UNIT_DIR/$u" ] || systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; } \
            && ! in_list "$u" "${FOUND_UNITS[@]}" && FOUND_BF_UNITS+=("$u")
    done
fi

# Users to remove: the always-LM ones that exist, plus sim-user/dashboard iff their unit was found.
FOUND_USERS=()
for un in "${LM_USERS_ALWAYS[@]}"; do id "$un" >/dev/null 2>&1 && FOUND_USERS+=("$un"); done
in_list client-sim-agent.service "${FOUND_UNITS[@]}"     && id sim-user  >/dev/null 2>&1 && FOUND_USERS+=("sim-user")
in_list client-sim-dashboard.service "${FOUND_UNITS[@]}" && id dashboard >/dev/null 2>&1 && FOUND_USERS+=("dashboard")

# Env values outside removed dirs.
FOUND_ENVFILES=()
for f in /etc/default/lm /etc/default/lm-agent /etc/profile.d/lm.sh /etc/profile.d/lm-agent.sh \
         /etc/default/lm-* /etc/profile.d/lm-*.sh; do
    [ -e "$f" ] && FOUND_ENVFILES+=("$f")
done
ENV_PREFIXES='LM_|LABMANAGER_|BF_|BUGFIXER_'
ENV_HAS_LM=0
grep -qE "^[[:space:]]*($ENV_PREFIXES)[A-Z0-9_]+=" /etc/environment 2>/dev/null && ENV_HAS_LM=1

# Opt-in shared-infra targets present on this box.
OLLAMA_OVERRIDE=/etc/systemd/system/ollama.service.d
FOUND_OLLAMA_UNIT=0; [ "$DO_OLLAMA" -eq 1 ] && { [ -e "$UNIT_DIR/ollama.service" ] || systemctl list-unit-files ollama.service 2>/dev/null | grep -q '^ollama'; } && FOUND_OLLAMA_UNIT=1
BF_OLLAMA_OVERRIDE=0; [ "$KEEP_BUGFIXER" -eq 0 ] && [ "$DO_OLLAMA" -eq 0 ] && [ -d "$OLLAMA_OVERRIDE" ] && BF_OLLAMA_OVERRIDE=1
FOUND_LE_DIRS=(); [ "$DO_LE" -eq 1 ] && collect FOUND_LE_DIRS < <(existing_paths "${LE_DIRS[@]}")
FOUND_NGINX=();   { [ "$DO_NGINX" -eq 1 ] || [ "$DO_NBDB" -eq 1 ]; } && for f in "${NGINX_SITES[@]}"; do [ -e "$f" ] && FOUND_NGINX+=("$f"); done

# Detect shared infra present, to WARN about (informational only).
SHARED_PRESENT=()
_svc_present() { systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1" && SHARED_PRESENT+=("$2"); }
_svc_present postgresql.service "postgresql (netbox DB)"
_svc_present redis-server.service "redis-server (netbox)"
_svc_present nginx.service "nginx (netbox site)"
_svc_present unbound.service "unbound (dns role)"
_svc_present slapd.service "slapd/openldap (ldap role)"
_svc_present ollama.service "ollama (bugfixer LLM)"
_svc_present dnsmasq.service "dnsmasq (cs dashboard)"
for k in kea-dhcp4-server kea-ctrl-agent; do systemctl list-unit-files "$k.service" 2>/dev/null | grep -q "^$k" && SHARED_PRESENT+=("$k (dhcp/cs/netbox)"); done
[ -d /etc/letsencrypt ] && SHARED_PRESENT+=("/etc/letsencrypt (le certs)")

# ── Report ───────────────────────────────────────────────────────────
echo
echo "${C_BOLD}${C_CYAN}=== Lab Manager MASTER Uninstaller ===${C_RESET}"
[ "$DRY_RUN" -eq 1 ] && echo "${C_YELLOW}(dry-run — nothing will be changed)${C_RESET}"
echo
_report_list() { local t="$1"; shift; [ "$#" -eq 0 ] && return; echo "${C_BOLD}$t${C_RESET}"; printf '  %s\n' "$@"; echo; }
echo "${C_BOLD}Services/timers to stop + remove:${C_RESET}"
if [ "${#FOUND_UNITS[@]}" -eq 0 ] && [ "${#FOUND_BF_UNITS[@]}" -eq 0 ]; then echo "  ${C_DIM}(none)${C_RESET}"; echo
else printf '  %s\n' "${FOUND_UNITS[@]}" "${FOUND_BF_UNITS[@]}"; echo; fi
_report_list "Directories to delete:"        "${FOUND_DIRS[@]}"
_report_list "Files to delete:"              "${FOUND_FILES[@]}"
_report_list "Helper binaries to delete:"    "${FOUND_BINS[@]}"
_report_list "Sudoers to remove:"            "${FOUND_SUDO[@]}"
_report_list "nginx site to remove:"         "${FOUND_NGINX[@]}"
_report_list "letsencrypt dirs to remove:"   "${FOUND_LE_DIRS[@]}"
_report_list "Users to remove:"              "${FOUND_USERS[@]}"
if [ "${#FOUND_ENVFILES[@]}" -gt 0 ] || [ "$ENV_HAS_LM" -eq 1 ] || [ "$BF_OLLAMA_OVERRIDE" -eq 1 ] || [ "$FOUND_OLLAMA_UNIT" -eq 1 ]; then
    echo "${C_BOLD}Env / shared-opt-in to clear:${C_RESET}"
    [ "${#FOUND_ENVFILES[@]}" -gt 0 ] && printf '  %s\n' "${FOUND_ENVFILES[@]}"
    [ "$ENV_HAS_LM" -eq 1 ]        && echo "  ${ENV_PREFIXES//|/, }* lines in /etc/environment"
    [ "$BF_OLLAMA_OVERRIDE" -eq 1 ] && echo "  $OLLAMA_OVERRIDE (bugfixer ollama override)"
    [ "$FOUND_OLLAMA_UNIT" -eq 1 ]  && echo "  ollama.service (--ollama)"
    [ "$DO_NBDB" -eq 1 ]            && echo "  ${C_RED}DROP${C_RESET} netbox Postgres database + role (--netbox-db)"
    echo
fi

echo "${C_RED}${C_BOLD}⚠  DESTROYS all LM state (encrypted state, certs, keys, logs, netbox app). Irreversible.${C_RESET}"
[ "$KEEP_BUGFIXER" -eq 1 ] && echo "${C_DIM}   BugFixer kept (--keep-bugfixer).${C_RESET}"
if [ "${#SHARED_PRESENT[@]}" -gt 0 ]; then
    echo
    echo "${C_YELLOW}${C_BOLD}Shared infrastructure detected — LEFT IN PLACE (remove manually if unused):${C_RESET}"
    printf "  ${C_YELLOW}•${C_RESET} %s\n" "${SHARED_PRESENT[@]}"
    echo "${C_DIM}   Opt in with --ollama / --letsencrypt / --netbox-db / --nginx-site.${C_RESET}"
    echo "${C_DIM}   Host networking (cs vmbr255 bridge, /etc/network/interfaces) is NEVER touched — revert by hand.${C_RESET}"
fi

# Nothing to do?
_total=$(( ${#FOUND_UNITS[@]} + ${#FOUND_BF_UNITS[@]} + ${#FOUND_DIRS[@]} + ${#FOUND_FILES[@]} \
        + ${#FOUND_BINS[@]} + ${#FOUND_SUDO[@]} + ${#FOUND_USERS[@]} + ${#FOUND_ENVFILES[@]} \
        + ${#FOUND_NGINX[@]} + ${#FOUND_LE_DIRS[@]} + ENV_HAS_LM + BF_OLLAMA_OVERRIDE + FOUND_OLLAMA_UNIT ))
if [ "$_total" -eq 0 ]; then echo; echo "${C_GREEN}Nothing LM-related found on this box. Done.${C_RESET}"; exit 0; fi

# ── Confirm ──
if [ "$DRY_RUN" -eq 1 ]; then echo; echo "${C_YELLOW}Dry-run complete — no changes made.${C_RESET}"; exit 0; fi
if [ "$ASSUME_YES" -eq 0 ]; then
    echo
    if [ ! -t 0 ]; then echo "${C_RED}No TTY — re-run with --yes to confirm non-interactively.${C_RESET}"; exit 1; fi
    read -rp "${C_BOLD}Type ${C_RED}REMOVE${C_RESET}${C_BOLD} to wipe everything above: ${C_RESET}" ans || ans=""
    [ "$ans" = "REMOVE" ] || { echo "Aborted — nothing changed."; exit 1; }
fi

# ── Teardown ──
echo; echo "${C_BOLD}Removing…${C_RESET}"
stop_and_remove_unit() {
    local u="$1"
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    systemctl stop "$u"           >/dev/null 2>&1 || true
    rm -f  "$UNIT_DIR/$u" "$UNIT_DIR"/*/"$u" 2>/dev/null || true
    rm -rf "$UNIT_DIR/$u.d" 2>/dev/null || true    # drop-in Environment= override
    echo "  ${C_GREEN}✓${C_RESET} unit $u"
}

# Optional: drop the netbox Postgres DB/role BEFORE stopping services.
if [ "$DO_NBDB" -eq 1 ] && id postgres >/dev/null 2>&1; then
    sudo -u postgres psql -tAc "SELECT 1" >/dev/null 2>&1 && {
        sudo -u postgres dropdb   netbox 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} dropped Postgres DB netbox"   || true
        sudo -u postgres dropuser netbox 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} dropped Postgres role netbox" || true
    }
fi

for u in "${FOUND_UNITS[@]}" "${FOUND_BF_UNITS[@]}"; do stop_and_remove_unit "$u"; done
[ "$FOUND_OLLAMA_UNIT" -eq 1 ] && stop_and_remove_unit ollama.service
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed  2>/dev/null || true

# Kill stragglers still holding LM roots (best-effort).
pkill -f '/opt/lm(-manager)?/|/opt/bugfixer/|/opt/netbox-app/|/opt/hub/|/opt/client-sim|/opt/proxmox-agent-installer/' 2>/dev/null || true

for d in "${FOUND_DIRS[@]}" "${FOUND_LE_DIRS[@]}"; do
    rm -rf "$d" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} dir  $d" || echo "  ${C_YELLOW}!${C_RESET} could not remove $d"
done
for f in "${FOUND_FILES[@]}" "${FOUND_BINS[@]}" "${FOUND_SUDO[@]}" "${FOUND_NGINX[@]}"; do
    rm -f "$f" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} file $f"
done

# Env values outside removed dirs.
for f in "${FOUND_ENVFILES[@]}"; do rm -f "$f" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} env  $f"; done
if [ "$ENV_HAS_LM" -eq 1 ]; then
    cp -a /etc/environment /etc/environment.lm-uninstall.bak 2>/dev/null || true
    sed -i -E "/^[[:space:]]*($ENV_PREFIXES)[A-Z0-9_]+=/d" /etc/environment 2>/dev/null \
        && echo "  ${C_GREEN}✓${C_RESET} stripped ${ENV_PREFIXES//|/, }* from /etc/environment ${C_DIM}(backup .lm-uninstall.bak)${C_RESET}"
fi
if [ "$BF_OLLAMA_OVERRIDE" -eq 1 ]; then
    rm -rf "$OLLAMA_OVERRIDE" 2>/dev/null && echo "  ${C_GREEN}✓${C_RESET} env  $OLLAMA_OVERRIDE (ollama override)"
    systemctl daemon-reload 2>/dev/null || true; systemctl restart ollama 2>/dev/null || true
fi

# Reload nginx if we removed its site.
[ "${#FOUND_NGINX[@]}" -gt 0 ] && systemctl reload nginx 2>/dev/null || true

# Users last (after all their units/dirs are gone).
for un in "${FOUND_USERS[@]}"; do
    userdel "$un" >/dev/null 2>&1 && echo "  ${C_GREEN}✓${C_RESET} user $un" \
        || echo "  ${C_YELLOW}!${C_RESET} could not remove user $un (still in use? reboot + re-run)"
done

echo
echo "${C_GREEN}${C_BOLD}Lab Manager removed.${C_RESET}"
[ "${#SHARED_PRESENT[@]}" -gt 0 ] && echo "${C_DIM}Shared infra left in place — see the WARN list above.${C_RESET}"
echo "${C_DIM}Any '!' above = a process still held it; reboot and re-run to finish.${C_RESET}"
