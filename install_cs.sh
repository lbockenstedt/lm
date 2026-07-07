#!/bin/bash
#
# DEPRECATED / RETIRED — do not use.
#
# This lm-root wrapper was a minimal standalone root installer that cloned/
# pulled repos as root and never chowned the resulting .git back to the
# service user (svc_lm). That left /opt/lm/*/.git root-owned while the
# service ran as svc_lm, so the in-service self-update ("git pull") failed
# with "insufficient permission for adding an object to repository database".
# It also predated the cs-owned Kea sim / second-NIC provisioning that the
# real installer does. It is superseded and unused by all live code (the
# hub/agent flow uses cs/lm-spoke/install_cs.sh; full deploys use
# install_all.sh).
#
# It performs NO git operations now, so it can no longer reintroduce that
# permission drift.
#
# Use instead:
#   * Full/coordinated deploy (keeps .git, chowns to svc_lm):
#         sudo ./install_all.sh
#   * Single CS module (full sim/NIC provisioning, what the flow invokes):
#         sudo cs/lm-spoke/install_cs.sh --hub wss://<hub>:443/ws/spoke ...
#
echo "install_cs.sh (lm root) is RETIRED — see the header of this file." >&2
echo "Run 'sudo ./install_all.sh' or the module-repo 'cs/lm-spoke/install_cs.sh' instead." >&2
exit 1
