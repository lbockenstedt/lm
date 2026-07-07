#!/bin/bash
#
# DEPRECATED / RETIRED — do not use.
#
# This lm-root wrapper was a standalone root installer that cloned/pulled
# repos as root. It chowned the TLS key/cert and the agent config to svc_lm
# but NEVER chowned /opt/lm/pxmx/.git, so the module code's .git stayed
# root-owned while the service ran as svc_lm and the in-service self-update
# ("git pull") failed with "insufficient permission for adding an object to
# repository database". It is superseded and unused by all live code (the
# hub/agent flow uses pxmx/install_pxmx.sh in the module repo; full deploys
# use install_all.sh).
#
# It performs NO git operations now, so it can no longer reintroduce that
# permission drift.
#
# Use instead:
#   * Full/coordinated deploy (keeps .git, chowns to svc_lm):
#         sudo ./install_all.sh
#   * Single Proxmox agent/spoke (cert + loopback modes, what the flow uses):
#         sudo pxmx/install_pxmx.sh --hub wss://<hub>:443/ws/agent ...
#
echo "install_pxmx.sh (lm root) is RETIRED — see the header of this file." >&2
echo "Run 'sudo ./install_all.sh' or the module-repo 'pxmx/install_pxmx.sh' instead." >&2
exit 1
