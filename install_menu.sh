#!/usr/bin/env bash
# ======================================================================
# Lab Manager — Menu-Driven Installer (bootstrap)
#
# One interactive entry point for two deployment shapes:
#
#   1) HUB        — this box becomes the LM hub (+ WebUI, always), with an
#                   optional checklist of spokes to co-locate. Runs the latest
#                   install_all.sh with --exclude for the spokes you didn't pick.
#
#   2) GENERIC    — a role-capable agent that calls home to a hub and morphs
#                   into a role (netbox / ldap / dns / opnsense / …) via the hub
#                   WebUI (Load Role). Runs the latest agent/install_agent.sh
#                   (the BaseSpoke-based GenericAgent — the legacy
#                   generic_agent leaf couldn't adopt a session key or handle
#                   LOAD_ROLE, so role activation timed out). Supports --clone
#                   for building template images that shouldn't start the
#                   service until first boot (each clone's id follows its own
#                   hostname and inherits the template's PSK).
#
# The Hub + WebUI are ALWAYS installed by install_all.sh; the hub menu only
# chooses which spokes to add alongside them.
#
# Two ways to run:
#   1) One-liner (clones lm fresh, runs the latest installer):
#        curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_menu.sh | bash
#   2) From a clone / container (uses the local installers — no re-clone):
#        git clone https://github.com/lbockenstedt/lm.git && cd lm && bash install_menu.sh
#
# Extra flags pass through to the chosen installer, e.g.:
#        bash install_menu.sh --reinstall        # hub path
#
# Env:
#   LM_BRANCH  — lm branch to clone when bootstrapping (default: main)
# ======================================================================
set -euo pipefail

BRANCH="${LM_BRANCH:-main}"
REPO_URL="https://github.com/lbockenstedt/lm.git"
SELF_URL="https://raw.githubusercontent.com/lbockenstedt/lm/${BRANCH}/install_menu.sh"

# ── Spoke modules co-locatable on a hub (order = display; matches install_all.sh) ──
#   id | label | description
MODULES=(
    "cs|Client Simulator|isolated DHCP sim network on a 2nd NIC (dnsmasq)"
    "pxmx|Proxmox|hypervisor agent — VM/LXC + USB auto-provisioning"
    "opnsense|OPNsense|firewall — aliases/NAT/routes/leases"
    "cppm|ClearPass|NAC — endpoint profiling + auth source"
    "netbox|NetBox|IPAM — device/VM/IP/MAC registry"
    "ldap|LDAP|directory service"
    "dns|DNS|name service (unbound/dnsmasq)"
    "dhcp|DHCP|address service (Kea)"
    "nw|Network Watcher|MAC/ARP discovery + switch inventory"
)

# ── Colors (degrade gracefully when not a terminal) ──
if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_GREEN=$'\033[32m'; C_CYAN=$'\033[36m'
    C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_DIM=""; C_GREEN=""; C_CYAN=""; C_YELLOW=""; C_RESET=""
fi

#======================================================================
# When piped (`curl ... | bash`), stdin is the script itself, not a TTY,
# so the menu's `read` would consume script lines. Re-exec ourselves from a
# temp file with stdin on /dev/tty so the menu works from the one-liner.
#======================================================================
if [ ! -t 0 ]; then
    if [ -t 1 ] && [ -e /dev/tty ]; then
        _tmp=$(mktemp)
        trap 'rm -f "$_tmp"' EXIT
        if curl -sSL "$SELF_URL" -o "$_tmp" 2>/dev/null; then
            exec bash "$_tmp" "$@" </dev/tty
        fi
    fi
    echo "install_menu: no TTY available — aborting (menu needs a terminal)." >&2
    echo "Install the hub non-interactively instead:" >&2
    echo "  curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_all.sh | bash" >&2
    exit 1
fi

#======================================================================
# Locate the lm repo: prefer the dir this script lives in (clone/container
# case); otherwise clone lm fresh. Sets CLONE_ROOT.
#======================================================================
locate_clone() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || script_dir=""
    if [ -n "$script_dir" ] && [ -f "$script_dir/install_all.sh" ] && [ -f "$script_dir/agent/install_agent.sh" ]; then
        CLONE_ROOT="$script_dir"
        CLONE_SRC="local clone ($script_dir)"
        return 0
    fi
    local clone_dir
    clone_dir="$(mktemp -d)"
    CLONE_DIR="$clone_dir"
    echo "${C_DIM}Cloning lm (branch ${BRANCH}) to ${clone_dir}...${C_RESET}"
    if ! git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$clone_dir" >/dev/null 2>&1; then
        git clone "$REPO_URL" "$clone_dir" >/dev/null 2>&1 || { echo "install_menu: failed to clone $REPO_URL" >&2; exit 1; }
        git -C "$clone_dir" checkout "$BRANCH" >/dev/null 2>&1 || true
    fi
    CLONE_ROOT="$clone_dir"
    CLONE_SRC="fresh clone ($clone_dir)"
    [ -f "$CLONE_ROOT/install_all.sh" ] || { echo "install_menu: install_all.sh not found in clone" >&2; exit 1; }
}

#======================================================================
# Top-level menu: Hub vs Generic agent
#======================================================================
top_menu() {
    local choice
    echo
    echo "${C_BOLD}${C_CYAN}=== Lab Manager Installer ===${C_RESET}"
    echo "  1) ${C_BOLD}Hub${C_RESET}        — this box runs the LM hub (+ WebUI); optionally co-locate spokes"
    echo "  2) ${C_BOLD}Generic agent${C_RESET} — leaf spoke that calls home, morphs into a role later (netbox/ldap/…)"
    echo "  q) Quit"
    while true; do
        read -rp "Select [1/2/q]: " choice || choice=""
        case "$choice" in
            1|h|H|hub)     MODE="hub";     return 0 ;;
            2|g|G|generic) MODE="generic"; return 0 ;;
            q|Q|quit|exit) echo "Aborted."; exit 0 ;;
            *) echo "  (enter 1, 2, or q)" ;;
        esac
    done
}

#======================================================================
# Hub path: spoke checklist → install_all.sh --exclude <unselected>
#======================================================================
render_module_menu() {
    local i id label desc mark
    echo
    echo "${C_BOLD}${C_CYAN}--- Hub: choose co-located spokes ---${C_RESET}"
    echo "${C_DIM}Hub + WebUI are always installed. Toggle the spokes to add:${C_RESET}"
    echo
    for i in "${!MODULES[@]}"; do
        IFS='|' read -r id label desc <<< "${MODULES[$i]}"
        if [ "${SELECTED[$i]}" -eq 1 ]; then mark="${C_GREEN}[x]${C_RESET}"; else mark="${C_DIM}[ ]${C_RESET}"; fi
        printf "  %s %2d) %-16s %s\n" "$mark" "$((i+1))" "$label" "${C_DIM}${desc}${C_RESET}"
    done
    echo
    echo "${C_DIM}Toggle by number(s) (e.g. 3 5),  a=all  n=none  i=invert  ENTER=install${C_RESET}"
}

module_menu_loop() {
    SELECTED=()
    local i
    for i in "${!MODULES[@]}"; do SELECTED+=("1"); done   # default: all (matches install_all.sh)
    local ans
    while true; do
        render_module_menu
        read -rp "Choice: " ans || ans=""
        ans="$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]' | xargs)"
        case "$ans" in
            "") break ;;
            a|all)    for i in "${!MODULES[@]}"; do SELECTED[$i]=1; done ;;
            n|none)   for i in "${!MODULES[@]}"; do SELECTED[$i]=0; done ;;
            i|invert) for i in "${!MODULES[@]}"; do SELECTED[$i]=$((1-${SELECTED[$i]})); done ;;
            *)
                # shellcheck disable=SC2086
                for tok in $(printf '%s' "$ans" | tr ',' ' '); do
                    if [[ "$tok" =~ ^[0-9]+$ ]] && [ "$tok" -ge 1 ] && [ "$tok" -le "${#MODULES[@]}" ]; then
                        local idx=$((tok-1))
                        SELECTED[$idx]=$((1-${SELECTED[$idx]}))
                    fi
                done
                ;;
        esac
    done
}

run_hub_install() {
    local excludes=() chosen=() i id
    for i in "${!MODULES[@]}"; do
        IFS='|' read -r id _ _ <<< "${MODULES[$i]}"
        if [ "${SELECTED[$i]}" -eq 1 ]; then chosen+=("$id"); else excludes+=("$id"); fi
    done

    echo
    echo "${C_BOLD}Installer source :${C_RESET} $CLONE_SRC"
    if [ "${#excludes[@]}" -eq 0 ]; then
        echo "${C_BOLD}Spokes           :${C_RESET} ALL (no excludes)"
        local exclude_arg=()
    else
        echo "${C_BOLD}Co-locating      :${C_RESET} ${chosen[*]}"
        echo "${C_BOLD}Excluding        :${C_RESET} ${excludes[*]}"
        local exclude_arg=(--exclude "$(IFS=','; printf '%s' "${excludes[*]}")")
    fi
    [ "${#}" -gt 0 ] && echo "${C_BOLD}Extra flags      :${C_RESET} $*"
    echo

    reexec_root bash "$CLONE_ROOT/install_all.sh" "${exclude_arg[@]}" "$@"
}

#======================================================================
# Generic path: prompt hub URL / id / secret / clone-only → install_agent.sh
#======================================================================
run_generic_install() {
    echo
    echo "${C_BOLD}${C_CYAN}--- Generic agent: connection details ---${C_RESET}"
    echo "${C_DIM}This spoke calls home to an existing hub and is approved there, then${C_RESET}"
    echo "${C_DIM}morphs into its role (netbox/ldap/dns/…) via hub provisioning.${C_RESET}"
    echo

    local default_id="$(hostname -s 2>/dev/null || echo host)"
    local SPOKE_URL SPOKE_ID SPOKE_SECRET HUB_SECRET CLONE_ONLY
    CLONE_ONLY=0

    while true; do
        read -rp "Hub WebSocket URL [auto - discover via mDNS/DNS]: " SPOKE_URL || SPOKE_URL=""
        [ -z "$SPOKE_URL" ] && SPOKE_URL="auto"
        # 'auto' lets the agent discover the hub via mDNS/DNS and pick
        # wss://127.0.0.1:443/ws/spoke (same box) or wss://<hub>:443/ws/spoke
        # (remote) from the hub's advertisement. A concrete ws:// or wss:// URL
        # pins it (use wss://host:443/ws/spoke for the unified :443 hub).
        { [[ "$SPOKE_URL" == "auto" ]] || [[ "$SPOKE_URL" =~ ^wss?:// ]]; } && break
        echo "  (must be 'auto' or start with ws:// or wss://)"
    done

    # Ask clone-only UP FRONT. In clone-only mode the staged unit omits --id so
    # each cloned disk derives its spoke id from its OWN hostname at runtime
    # (socket.gethostname() in agent.py), while RETAINING this template's PSK
    # (secret) so the hub auto-approves the clone under its own hostname
    # (carryover — no admin re-approval). So the Spoke ID prompt is skipped in
    # clone-only; the secret prompt is still asked (the clone re-bakes the
    # template's PSK so it authenticates).
    local clone_ans
    read -rp "Clone-only mode? (stage for cloning — don't start; each clone's id follows its own hostname and inherits this template's approval) [y/N]: " clone_ans || clone_ans=""
    [[ "$clone_ans" =~ ^[Yy]$ ]] && CLONE_ONLY=1 || CLONE_ONLY=0

    SPOKE_ID=""
    if [ "$CLONE_ONLY" -eq 0 ]; then
        while true; do
            read -rp "Spoke ID [${default_id}]: " SPOKE_ID || SPOKE_ID=""
            [ -z "$SPOKE_ID" ] && SPOKE_ID="$default_id"
            [[ "$SPOKE_ID" =~ ^[A-Za-z0-9_.-]+$ ]] && break
            echo "  (letters, digits, . _ - only)"
        done
    else
        echo "${C_DIM}Clone-only: spoke id will be each clone's own hostname (evaluated at start).${C_RESET}"
    fi
    while true; do
        read -rp "First secret [optional — Enter to skip and await admin approval]: " SPOKE_SECRET || SPOKE_SECRET=""
        # No secret is a valid first-install state: the agent connects
        # unauthenticated and shows up as pending in the hub WebUI until an
        # admin approves it (then the hub negotiates its session secret). In
        # clone-only mode re-enter the TEMPLATE's PSK so each clone authenticates
        # and auto-approves under its own hostname (carryover).
        break
    done
    read -rp "Hub root secret [optional, Enter to skip]: " HUB_SECRET || HUB_SECRET=""

    # TLS cert verification is OFF by default (encrypt without authenticating
    # the self-signed hub cert). Opt in here only if you want the agent to
    # verify the hub cert — a co-located agent finds /opt/lm/certs/hub.crt
    # automatically; a remote agent must supply the hub CA cert path.
    local TLS_VERIFY=0 TLS_CA_CERT=""
    local tls_ans
    read -rp "Verify hub TLS certificate? (requires the hub CA cert) [y/N]: " tls_ans || tls_ans=""
    if [[ "$tls_ans" =~ ^[Yy]$ ]]; then
        TLS_VERIFY=1
        read -rp "Hub CA cert path [/opt/lm/certs/hub.crt]: " TLS_CA_CERT || TLS_CA_CERT=""
        [ -z "$TLS_CA_CERT" ] && TLS_CA_CERT="/opt/lm/certs/hub.crt"
    fi

    # Install the role-capable morphable agent (agent/install_agent.sh → the
    # BaseSpoke-based GenericAgent), NOT the legacy leaf (generic_agent). The
    # leaf used an incompatible frame format and couldn't adopt a session key,
    # sign frames, or handle LOAD_ROLE — so role activation on a menu-installed
    # node always timed out. The agent-spoke handles all of that and morphs
    # into opnsense/dns/… via LOAD_ROLE from the hub WebUI.
    #
    # Map menu prompts → install_agent.sh flags (--spoke-url becomes --hub).
    # Clone-only omits --id so each cloned disk derives its spoke id from its
    # own hostname at runtime; the PSK (--secret) is retained (carryover).
    local generic_args=(--hub "$SPOKE_URL")
    [ "$CLONE_ONLY" -eq 0 ] && generic_args+=(--id "$SPOKE_ID")
    [ -n "$SPOKE_SECRET" ] && generic_args+=(--secret "$SPOKE_SECRET")
    [ -n "$HUB_SECRET" ]  && generic_args+=(--hub-secret "$HUB_SECRET")
    [ "$TLS_VERIFY" -eq 1 ] && generic_args+=(--tls-verify --tls-ca-cert "$TLS_CA_CERT")
    [ "$CLONE_ONLY" -eq 1 ] && generic_args+=(--clone)

    local id_disp
    if [ "$CLONE_ONLY" -eq 1 ]; then
        id_disp="(derived from each clone's hostname at runtime)"
    else
        id_disp="$SPOKE_ID"
    fi
    echo
    echo "${C_BOLD}Installer source :${C_RESET} $CLONE_SRC"
    echo "${C_BOLD}Spoke URL        :${C_RESET} $SPOKE_URL"
    echo "${C_BOLD}Spoke ID         :${C_RESET} $id_disp"
    echo "${C_BOLD}Secret           :${C_RESET} $([ -n "$SPOKE_SECRET" ] && echo provided || echo 'none — will await admin approval')"
    echo "${C_BOLD}TLS verify       :${C_RESET} $([ "$TLS_VERIFY" -eq 1 ] && echo "yes (CA=$TLS_CA_CERT)" || echo 'no — encrypt without auth')"
    echo "${C_BOLD}Clone-only       :${C_RESET} $([ "$CLONE_ONLY" -eq 1 ] && echo yes || echo no)"
    echo

    # install_agent.sh expects to be run from the clone root (it clones lm
    # itself to /opt/lm; running the cloned copy guarantees the latest version).
    reexec_root bash "$CLONE_ROOT/agent/install_agent.sh" "${generic_args[@]}"
}

#======================================================================
# Re-exec the target installer as root if we aren't already.
#======================================================================
reexec_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "${C_YELLOW}install_menu: re-running as root (sudo) — installer requires root.${C_RESET}"
        exec sudo -E "$@"
    fi
    exec "$@"
}

#======================================================================
trap '[ -n "${CLONE_DIR:-}" ] && rm -rf "$CLONE_DIR"' EXIT

locate_clone
top_menu
if [ "$MODE" = "hub" ]; then
    module_menu_loop
    run_hub_install "$@"
else
    run_generic_install
fi