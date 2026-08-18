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
    "henet|HE.NET|public DNS — manage dns.he.net records (dynamic DNS)"
    "dhcp|DHCP|address service (Kea)"
    "nw|Network Watcher|MAC/ARP discovery + switch inventory"
    "le|Let's Encrypt|ACME cert issuance/distribution"
)

# ── Module id → agent ROLE name (mirrors install_all.sh MODULE_ROLE). The hub
# path passes module ids to install_all.sh (--exclude); the Agent path passes
# ROLE names to install_agent.sh (--roles), so map the two namespaces here.
# Keep in sync with install_all.sh's MODULE_ROLE + agent_spoke._ROLE_MAP.
declare -A MODULE_ROLE=(
    ["cs"]="simulation" ["pxmx"]="proxmox" ["opnsense"]="opnsense"
    ["cppm"]="cppm" ["netbox"]="netbox" ["ldap"]="ldap"
    ["dns"]="dns" ["dhcp"]="dhcp" ["henet"]="henet" ["nw"]="network" ["le"]="le"
)

# ── Colors (degrade gracefully when not a terminal) ──
if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_GREEN=$'\033[32m'; C_CYAN=$'\033[36m'
    C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_DIM=""; C_GREEN=""; C_CYAN=""; C_YELLOW=""; C_RED=""; C_RESET=""
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
    local clone_err
    if ! clone_err="$(git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$clone_dir" 2>&1)"; then
        # Some servers/mirrors reject shallow branch clones — retry full.
        if ! clone_err="$(git clone "$REPO_URL" "$clone_dir" 2>&1)"; then
            echo "install_menu: failed to clone $REPO_URL (branch $BRANCH)" >&2
            echo "  git said: ${clone_err:-<no output>}" >&2
            echo "  Common causes: no network/DNS to github.com, a proxy that blocks git" >&2
            echo "  (set it via: git config --global http.proxy http://host:port), or a stale CA bundle." >&2
            exit 1
        fi
        git -C "$clone_dir" checkout "$BRANCH" >/dev/null 2>&1 || true
    fi
    CLONE_ROOT="$clone_dir"
    CLONE_SRC="fresh clone ($clone_dir)"
    # Capture the version/commit just cloned so the operator can confirm they're
    # installing the latest copy (shown in the summary + after install).
    CLONE_VERSION="$(cat "$clone_dir/VERSION" 2>/dev/null || echo unknown)"
    CLONE_COMMIT="$(git -C "$clone_dir" rev-parse --short HEAD 2>/dev/null || echo '?')"
    CLONE_SRC="fresh clone ($clone_dir) — v${CLONE_VERSION} @ ${CLONE_COMMIT}"
    echo "${C_DIM}Cloned lm v${CLONE_VERSION} (commit ${CLONE_COMMIT}, branch ${BRANCH}).${C_RESET}"
    [ -f "$CLONE_ROOT/install_all.sh" ] || { echo "install_menu: install_all.sh not found in clone" >&2; exit 1; }
}

#======================================================================
# Top-level menu: Hub vs Agent
#======================================================================
top_menu() {
    local choice
    echo
    echo "${C_BOLD}${C_CYAN}=== Lab Manager Installer ===${C_RESET}"
    echo "  1) ${C_BOLD}Hub${C_RESET}        — this box runs the LM hub (+ WebUI); optionally co-locate spokes"
    echo "  2) ${C_BOLD}Agent${C_RESET}      — leaf spoke that calls home; pick the module role(s) to run (dns/ldap/cs/…)"
    echo "  3) ${C_BOLD}Proxmox Host Agent${C_RESET} — node-agent on a Proxmox host that reports to a pxmx/sim spoke"
    echo "  4) ${C_BOLD}${C_RED}Uninstall${C_RESET}  — remove LM components from this box"
    echo "  q) Quit"
    while true; do
        read -rp "Select [1/2/3/4/q]: " choice || choice=""
        case "$choice" in
            1|h|H|hub)       MODE="hub";       return 0 ;;
            2|g|G|generic)   MODE="generic";   return 0 ;;
            3|p|P|pxmx)      MODE="pxmx-agent"; return 0 ;;
            4|u|U|uninstall) MODE="uninstall"; return 0 ;;
            q|Q|quit|exit)   echo "Aborted."; exit 0 ;;
            *) echo "  (enter 1, 2, 3, 4, or q)" ;;
        esac
    done
}

#======================================================================
# Hub path: spoke checklist → install_all.sh --exclude <unselected>
#======================================================================
render_module_menu() {
    local i id label desc mark
    echo
    echo "${C_BOLD}${C_CYAN}--- ${MENU_TITLE:-Hub: choose co-located spokes} ---${C_RESET}"
    echo "${C_DIM}${MENU_HINT:-Hub + WebUI are always installed. Toggle the spokes to add:}${C_RESET}"
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
    MENU_TITLE="Hub: choose co-located spokes"
    MENU_HINT="Hub + WebUI are always installed. Toggle the spokes to add:"
    SELECTED=()
    local i
    for i in "${!MODULES[@]}"; do SELECTED+=("1"); done   # default: all (matches install_all.sh)
    _menu_toggle_loop
}

# Agent role checklist — same widget, but defaults to NONE (a bare agent is a
# valid shape: it loads roles later via the hub WebUI) and titled for roles.
role_menu_loop() {
    MENU_TITLE="Agent: choose module role(s) to run now"
    MENU_HINT="Leave all unchecked for a bare agent (load roles later in the hub WebUI). Toggle roles to pre-load:"
    SELECTED=()
    local i
    for i in "${!MODULES[@]}"; do SELECTED+=("0"); done   # default: none
    _menu_toggle_loop
}

_menu_toggle_loop() {
    local i ans
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
# Agent path: prompt hub URL / id / secret / clone-only → install_agent.sh
#======================================================================
run_generic_install() {
    echo
    echo "${C_BOLD}${C_CYAN}--- Agent: connection details ---${C_RESET}"
    echo "${C_DIM}This spoke calls home to an existing hub and is approved there. Pick the${C_RESET}"
    echo "${C_DIM}module role(s) to run now (dns/ldap/cs/…), or none to load them later.${C_RESET}"
    echo

    local default_id="$(hostname -s 2>/dev/null || echo host)"
    local SPOKE_URL SPOKE_ID SPOKE_SECRET HUB_SECRET CLONE_ONLY
    CLONE_ONLY=0

    read -rp "Hub WebSocket URL [auto - discover via mDNS/DNS, or just an IP/host]: " SPOKE_URL || SPOKE_URL=""
    [ -z "$SPOKE_URL" ] && SPOKE_URL="auto"
    # 'auto' lets the agent discover the hub via mDNS/DNS and pick
    # wss://127.0.0.1:443/ws/spoke (same box) or wss://<hub>:443/ws/spoke
    # (remote) from the hub's advertisement. Anything else is passed straight
    # through as --hub to install_agent.sh, which normalizes it
    # (BaseControlPlane._normalize_hub_url / _normalize_spoke_url): a bare IP
    # or hostname (e.g. "172.16.1.31") gets wss:// + :443 + /ws/spoke appended
    # automatically — only a scheme/port/path you actually want to override
    # needs typing out (e.g. ws://127.0.0.1:8765 for a legacy loopback).

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
    # Pick the module role(s) to run now (mapped to install_agent.sh --roles).
    # Leaving all unchecked installs a bare agent that loads roles later via the
    # hub WebUI (the original behavior). Selecting 'cs'/simulation makes THIS box
    # host the client-sim node-agent listener (install_agent.sh sets
    # LM_CS_AGENT_LISTENER=1 for a non-colocated simulation role), so a Proxmox
    # host-agent can report to it — no separate spoke needed.
    role_menu_loop
    local roles=() i id
    for i in "${!MODULES[@]}"; do
        IFS='|' read -r id _ _ <<< "${MODULES[$i]}"
        [ "${SELECTED[$i]}" -eq 1 ] && roles+=("${MODULE_ROLE[$id]}")
    done
    local roles_csv=""
    [ "${#roles[@]}" -gt 0 ] && roles_csv="$(IFS=','; printf '%s' "${roles[*]}")"

    local generic_args=(--hub "$SPOKE_URL")
    [ "$CLONE_ONLY" -eq 0 ] && generic_args+=(--id "$SPOKE_ID")
    [ -n "$SPOKE_SECRET" ] && generic_args+=(--secret "$SPOKE_SECRET")
    [ -n "$HUB_SECRET" ]  && generic_args+=(--hub-secret "$HUB_SECRET")
    [ "$TLS_VERIFY" -eq 1 ] && generic_args+=(--tls-verify --tls-ca-cert "$TLS_CA_CERT")
    [ "$CLONE_ONLY" -eq 1 ] && generic_args+=(--clone)
    [ -n "$roles_csv" ] && generic_args+=(--roles "$roles_csv")

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
    echo "${C_BOLD}Roles            :${C_RESET} ${roles_csv:-none (bare agent — load roles later in the WebUI)}"
    echo "${C_BOLD}Secret           :${C_RESET} $([ -n "$SPOKE_SECRET" ] && echo provided || echo 'none — will await admin approval')"
    echo "${C_BOLD}TLS verify       :${C_RESET} $([ "$TLS_VERIFY" -eq 1 ] && echo "yes (CA=$TLS_CA_CERT)" || echo 'no — encrypt without auth')"
    echo "${C_BOLD}Clone-only       :${C_RESET} $([ "$CLONE_ONLY" -eq 1 ] && echo yes || echo no)"
    echo

    # install_agent.sh expects to be run from the clone root (it clones lm
    # itself to /opt/lm; running the cloned copy guarantees the latest version).
    reexec_root bash "$CLONE_ROOT/agent/install_agent.sh" "${generic_args[@]}"
}

#======================================================================
# Proxmox Host Agent path: install/uninstall the pxmx NODE-AGENT (telemetry +
# CS command executor) that reports to a pxmx/simulation spoke's /ws/agent
# listener. This lives in the SEPARATE pxmx repo, so we drive its installer via
# curl (the one-liner from the My Devices "Proxmox Host Agent" card).
#======================================================================
PXMX_RAW="https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent"

run_pxmx_agent_install() {
    echo
    echo "${C_BOLD}${C_CYAN}--- Proxmox Host Agent (node-agent) ---${C_RESET}"
    echo "${C_DIM}Runs on a Proxmox HOST and reports to a spoke that hosts a /ws/agent${C_RESET}"
    echo "${C_DIM}listener — either a pxmx (proxmox-role) spoke, or a cs (simulation-role)${C_RESET}"
    echo "${C_DIM}spoke/agent with its listener enabled. It dials that spoke; the hub relays${C_RESET}"
    echo "${C_DIM}telemetry + client-sim commands to it. (Not an lm agent — separate repo.)${C_RESET}"
    echo
    local sub
    echo "  1) Install / update"
    echo "  2) ${C_RED}Uninstall${C_RESET}"
    echo "  b) Back"
    read -rp "Select [1/2/b]: " sub || sub=""
    case "$sub" in
        2|u|U)
            echo
            echo "${C_BOLD}${C_RED}Uninstalling the Proxmox host agent...${C_RESET}"
            reexec_root bash -c "curl -sSL '${PXMX_RAW}/uninstall_agent.sh' | bash"
            return 0 ;;
        b|B) return 0 ;;
        *) : ;;  # 1/anything → install
    esac

    local SPOKE_IP
    read -rp "Spoke IP/host the agent should report to [auto - discover on the LAN]: " SPOKE_IP || SPOKE_IP=""
    local args=()
    [ -n "$SPOKE_IP" ] && args=(--spoke-ip "$SPOKE_IP")
    echo
    echo "${C_BOLD}Target spoke     :${C_RESET} ${SPOKE_IP:-auto-discover}"
    echo "${C_DIM}If it reports \"no agent listener answered\", the target spoke isn't hosting${C_RESET}"
    echo "${C_DIM}a /ws/agent listener yet — install a pxmx role there, or (for sims) load the${C_RESET}"
    echo "${C_DIM}simulation role on that box so its cs listener binds, then re-run this.${C_RESET}"
    echo
    # Fetch the pxmx installer and pass any --spoke-ip through to it.
    if [ "${#args[@]}" -gt 0 ]; then
        reexec_root bash -c "curl -sSL '${PXMX_RAW}/install_agent.sh' | bash -s -- $(printf '%q ' "${args[@]}")"
    else
        reexec_root bash -c "curl -sSL '${PXMX_RAW}/install_agent.sh' | bash"
    fi
}

#======================================================================
# Uninstall path: hand off to uninstall.sh (discovery + guarded teardown).
#======================================================================
run_uninstall() {
    echo
    echo "${C_BOLD}${C_RED}--- Uninstall: remove ALL Lab Manager components ---${C_RESET}"
    echo "${C_DIM}Master teardown: hub + agent + every spoke/role + pxmx host agent + client-sim${C_RESET}"
    echo "${C_DIM}+ collab sink + BugFixer, plus their dirs/helpers/sudoers/users and LM env values.${C_RESET}"
    echo "${C_DIM}Shared infra (postgres/nginx/redis/ollama/certbot/kea/…) is WARNED, not removed.${C_RESET}"
    echo "${C_DIM}Asks you to type REMOVE first. Flags: --dry-run --keep-bugfixer --ollama${C_RESET}"
    echo "${C_DIM}--letsencrypt --netbox-db --nginx-site --yes.${C_RESET}"
    reexec_root bash "$CLONE_ROOT/uninstall.sh" "$@"
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
# Ensure the tools THIS bootstrap needs before it can do anything: git (to
# clone lm) and curl (to re-fetch this script under `curl | bash`). The FULL
# dependency set is installed by install_all.sh / install_agent.sh — but those
# live INSIDE the repo we must `git clone` first, so on a bare box without git
# the clone just failed with the unhelpful "failed to clone" and the operator
# never reached the real prerequisite installer. Install the minimum here so
# the bootstrap is self-sufficient on a fresh VM.
#======================================================================
ensure_bootstrap_deps() {
    local missing=()
    command -v git  >/dev/null 2>&1 || missing+=(git)
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    [ ${#missing[@]} -eq 0 ] && return 0

    echo "${C_DIM}Installing bootstrap prerequisites: ${missing[*]}...${C_RESET}"
    local SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            echo "${C_RED}install_menu: need to install ${missing[*]} but this box has neither root nor sudo." >&2
            echo "  Install them manually and re-run, e.g.: apt-get install -y ${missing[*]}${C_RESET}" >&2
            exit 1
        fi
    fi

    # `|| true` so a package-manager hiccup doesn't trip `set -e` before the
    # verify block below prints one clear, actionable message.
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -y || true
        $SUDO apt-get install -y "${missing[@]}" || true
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y "${missing[@]}" || true
    elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y "${missing[@]}" || true
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper --non-interactive install "${missing[@]}" || true
    elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add "${missing[@]}" || true
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm "${missing[@]}" || true
    else
        echo "${C_RED}install_menu: no supported package manager (apt/dnf/yum/zypper/apk/pacman) found." >&2
        echo "  Install ${missing[*]} manually and re-run.${C_RESET}" >&2
        exit 1
    fi

    # Verify the tools are actually present now — the single source of truth.
    local still=()
    for t in "${missing[@]}"; do
        command -v "$t" >/dev/null 2>&1 || still+=("$t")
    done
    if [ ${#still[@]} -ne 0 ]; then
        echo "${C_RED}install_menu: failed to install ${still[*]}. Install manually and re-run.${C_RESET}" >&2
        exit 1
    fi
}

#======================================================================
trap '[ -n "${CLONE_DIR:-}" ] && rm -rf "$CLONE_DIR"' EXIT

ensure_bootstrap_deps
locate_clone
top_menu
case "$MODE" in
    hub)        module_menu_loop; run_hub_install "$@" ;;
    generic)    run_generic_install ;;
    pxmx-agent) run_pxmx_agent_install ;;
    uninstall)  run_uninstall "$@" ;;
esac