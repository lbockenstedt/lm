#!/bin/bash
#
# DEPRECATED / RETIRED — do not use.
#
# This lm-root wrapper was a standalone root installer that cloned/pulled
# repos as root and never chowned the resulting .git back to the service
# user (svc_lm). That left /opt/lm/*/.git root-owned while the service ran
# as svc_lm, so the in-service self-update ("git pull") failed with
# "insufficient permission for adding an object to repository database" and
# the module could not update itself. It is superseded and left unused by
# all live code (the hub/agent install flow uses opnsense/install_opnsense.sh
# in the module repo, and full deploys use install_all.sh).
#
# It performs NO git operations now, so it can no longer reintroduce that
# permission drift.
#
# Use instead:
#   * Full/coordinated deploy (keeps .git, chowns to svc_lm):
#         sudo ./install_all.sh
#   * Single OPNsense module (what the hub/agent flow invokes):
#         sudo opnsense/install_opnsense.sh --hub wss://<hub>:443/ws/spoke ...
#
echo "install_opnsense.sh (lm root) is RETIRED — see the header of this file." >&2
echo "Run 'sudo ./install_all.sh' or the module-repo 'opnsense/install_opnsense.sh' instead." >&2
exit 1
