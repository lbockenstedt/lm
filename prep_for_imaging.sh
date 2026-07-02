#!/bin/bash
# prep_for_imaging.sh — generalize this host's LM install so a cloned image
# boots as a fresh identity instead of a duplicate of the original.
#
# The spokes/agent carry a stable install UUID (INSTALL_UUID in their .env),
# minted at FIRST START, that the LM hub uses to correlate a cloned+renamed
# box with its original (so approval/tenant binding carry over). To instead
# clone this box as a CLEAN NEW identity (the common "gold image" case), strip
# that UUID before imaging — the clone then mints its own UUID on first boot.
#
# Default action: strip INSTALL_UUID from every installed module's .env.
# Optional: also clear secrets so the clone re-onboards, and/or drop the baked
# --id from the systemd unit so the clone derives <hostname>-spoke/-agent.
#
# SAFETY: never removes code, the venv, the repo, or shared /opt/lm/core.
# Re-runnable. Only edits .env files (and, with --rederive-id, the unit ExecStart).
#
# Usage:
#   bash prep_for_imaging.sh [--yes] [--module cs|pxmx|agent|all]
#                            [--clear-secrets] [--rederive-id] [--stop]
#
# One-liner from GitHub:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/prep_for_imaging.sh | sudo bash
#   # …to also clear secrets + re-derive ids + stop services first:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/prep_for_imaging.sh \
#     | sudo bash -s -- --yes --clear-secrets --rederive-id --stop
set -euo pipefail

LM_DIR="/opt/lm"
YES=0
MODULE="all"
CLEAR_SECRETS=0
REDERIVE_ID=0
STOP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)            YES=1; shift ;;
        --module)         MODULE="$2"; shift 2 ;;
        --clear-secrets)  CLEAR_SECRETS=1; shift ;;
        --rederive-id)    REDERIVE_ID=1; shift ;;
        --stop)           STOP=1; shift ;;
        -h|--help)
            sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "❌ Run as root (sudo)."; exit 1; }

# ── Module descriptors: .env path, systemd unit, the id line key, service ──
# Only cs / pxmx / the pxmx agent have the runtime hostname-derived id (Phase 4);
# for them --rederive-id can drop the baked --id. The other modules still bake a
# pinned --id, so --rederive-id is a no-op there (only INSTALL_UUID/secrets strip).
declare -a M=()
case "$MODULE" in
    cs)    M=("cs|/opt/lm/cs/.env|lm-cs.service|SPOKE_ID|lm-cs") ;;
    pxmx)  M=("pxmx|/opt/lm/pxmx/.env|lm-pxmx.service|SPOKE_ID|lm-pxmx") ;;
    agent) M=("agent|/opt/lm/pxmx/agent/.env|lm-pxmx-agent.service|AGENT_ID|lm-pxmx-agent") ;;
    all)   M=(
        "cs|/opt/lm/cs/.env|lm-cs.service|SPOKE_ID|lm-cs"
        "pxmx|/opt/lm/pxmx/.env|lm-pxmx.service|SPOKE_ID|lm-pxmx"
        "agent|/opt/lm/pxmx/agent/.env|lm-pxmx-agent.service|AGENT_ID|lm-pxmx-agent"
        "opnsense|/opt/lm/opnsense/.env|lm-opnsense.service|SPOKE_ID|lm-opnsense"
        "netbox|/opt/lm/netbox/.env|lm-netbox.service|SPOKE_ID|lm-netbox"
        "nw|/opt/lm/nw/.env|lm-nw.service|SPOKE_ID|lm-nw"
        "dhcp|/opt/lm/dhcp/.env|lm-dhcp.service|SPOKE_ID|lm-dhcp"
        "dns|/opt/lm/dns/.env|lm-dns.service|SPOKE_ID|lm-dns"
        "ldap|/opt/lm/ldap/.env|lm-ldap.service|SPOKE_ID|lm-ldap"
        "kvm|/opt/lm/kvm/.env|lm-kvm.service|SPOKE_ID|lm-kvm"
        "cppm|/opt/lm/cppm/.env|lm-cppm.service|SPOKE_ID|lm-cppm"
    ) ;;
    *) echo "❌ --module must be cs|pxmx|agent|all"; exit 1 ;;
esac

echo "=== LM Prep-for-Imaging ==="
echo "  Module       : $MODULE"
echo "  Strip UUID   : yes (default)"
echo "  Clear secrets: $([[ $CLEAR_SECRETS -eq 1 ]] && echo yes || echo no)"
echo "  Re-derive id : $([[ $REDERIVE_ID -eq 1 ]] && echo yes || echo no)"
echo "  Stop services: $([[ $STOP -eq 1 ]] && echo yes || echo no)"
echo

if [[ $YES -eq 0 ]] && [ -t 0 ]; then
    read -rp "Proceed with prep-for-imaging? [y/N]: " _confirm
    [[ "$_confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi
# Non-TTY (curl|bash) proceeds without a prompt — the pipe is consent.

# strip_key <file> <KEY>  — delete every `KEY=` line from a .env (best-effort).
strip_key() {
    local f="$1" k="$2"
    [[ -f "$f" ]] || return 0
    sed -i "/^${k}=/d" "$f" 2>/dev/null || true
}

# strip_id_arg <unit-file>  — drop `--id <token>` from the ExecStart so the
# clone re-derives <hostname>-spoke/-agent at startup. Idempotent.
strip_id_arg() {
    local unit="$1"
    [[ -f "$unit" ]] || return 0
    # Matches `--id word` and `--id $VAR` (pxmx unit uses a systemd var).
    sed -i -E 's/[[:space:]]+--id [^ ]+//g' "$unit" 2>/dev/null || true
}

if [[ $STOP -eq 1 ]]; then
    echo "Stopping LM services (so the image is quiescent)..."
    for desc in "${M[@]}"; do
        IFS='|' read -r _ _ _ _ svc <<< "$desc"
        systemctl stop "$svc" 2>/dev/null && echo "  Stopped: $svc" || true
    done
fi

echo "Stripping per-install identity from .env files..."
for desc in "${M[@]}"; do
    IFS='|' read -r mod env unit idkey svc <<< "$desc"
    [[ -f "$env" ]] || { echo "  $mod: no .env at $env — skipped"; continue; }

    # Always strip the install UUID → clone mints a fresh one on first boot.
    strip_key "$env" "INSTALL_UUID"

    # Optionally clear secrets so the clone re-onboards (hub-side re-approval).
    if [[ $CLEAR_SECRETS -eq 1 ]]; then
        strip_key "$env" "SPOKE_SECRET"
        strip_key "$env" "HUB_SECRET"
        strip_key "$env" "AGENT_SECRET"
    fi

    # Optionally drop the baked --id so the clone derives its id from the new
    # hostname. Strips the id line from .env AND the --id arg from the unit
    # (only meaningful for cs/pxmx/agent, which have the derive code).
    if [[ $REDERIVE_ID -eq 1 ]]; then
        strip_key "$env" "$idkey"
        strip_id_arg "/etc/systemd/system/${unit}"
        systemctl daemon-reload 2>/dev/null || true
    fi

    echo "  $mod: prepped $env$([[ $REDERIVE_ID -eq 1 && -f /etc/systemd/system/${unit} ]] && echo " + $unit (re-derive id)")"
done

cat <<EOF

=== Prep-for-imaging complete ===
  The install UUID$([[ $CLEAR_SECRETS -eq 1 ]] && echo " + secrets")$([[ $REDERIVE_ID -eq 1 ]] && echo " + baked --id") ha(s) been stripped.
  Shut this host down now and take the image/clone. On first boot each clone
  mints its own INSTALL_UUID$([[ $REDERIVE_ID -eq 1 ]] && echo " and derives <hostname>-spoke/-agent"), so the hub
  treats it as a fresh entity (no correlation to the original).

  Reminder: if you intend to run the original AND the clone simultaneously,
  prepping is required — otherwise they share the UUID and the hub migrates
  approval away from whichever connected first.
EOF