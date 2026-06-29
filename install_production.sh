#!/usr/bin/env bash
# Lab Manager — Production Installer
#
# Installs the Hub + all spokes:
#   CS (Client Simulator), NetBox (IPAM), Proxmox (hypervisor),
#   OPNsense (firewall), ClearPass (NAC), LDAP (directory)
#
# The CS spoke is included by default — it provides the isolated DHCP network
# (dnsmasq on a second NIC) for simulations. Pass --exclude cs to skip it.
#
# Usage (one-liner from GitHub):
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_production.sh | sudo bash
#
# Or with options:
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_production.sh \
#     | sudo bash -s -- --reinstall

set -euo pipefail

BRANCH="${LM_BRANCH:-main}"
INSTALL_ALL_URL="https://raw.githubusercontent.com/lbockenstedt/lm/${BRANCH}/install_all.sh"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "⬇️  Fetching install_all.sh from GitHub (branch: ${BRANCH})..."
curl -sSL "$INSTALL_ALL_URL" -o "$TMP"
chmod +x "$TMP"

exec bash "$TMP" "$@"
