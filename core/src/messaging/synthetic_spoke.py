"""Base class for synthetic spokes: the test-feed and load-test spoke clients.

``scripts/hub_feed.py`` (the Test Data Feed) and ``scripts/loadtest_spokes.py``
run many spoke clients in one process. They reuse ``BaseControlPlane`` so the
wire protocol is the real one, but they have no host of their own: the process
runs on whichever box started it. The Test Data Feed is a child process of the
Dev/QA hub (``routes/test_feed.py``) with the hub's working directory and
environment, so a base handler that acts on "this host" would act on the hub's
own box, under a production spoke's name.

``SyntheticSpoke`` keeps such a spoke off the host:

* It never writes ``.env``, the healthy marker or the host's cert directory.
  The TLS-verify ratchet marker and hub TLS policy live in a private temp dir
  instead, so a load test cannot overwrite the host spoke's ratchet.
* It never presents the host's mTLS client cert. Under a synthetic id the hub
  would reject it as ``cert-identity-mismatch`` and report a threat anomaly,
  or, with enforcement off, bind the host's cert to every synthetic id.
* It never starts the base ``run()`` loop, whose watchdogs restart the process
  or reboot the machine; ``run()`` raises.
* It sorts every base system command into one of three groups:

  - ``PASS_THROUGH``: the base handler only changes this process's memory
    (with the overrides above), so it runs as usual.
  - ``SKIPPED``: hub pushes and fan-outs that would write files or certs or
    restart the process. Answered SUCCESS with a "skipped" message, as the
    base does for role sub-spokes, so a fan-out does not count them as failed.
    A current hub sends a marked spoke only Clear Logs and a cert revoke from
    this group; the others still arrive from an older hub, or as a push queued
    while the spoke was offline (the hub marks connected spokes only).
  - ``REFUSED``: commands an operator aims at a node's host (OS updates and
    reboot, Remote Console, hostname, the mTLS key and its status). Answered
    ERROR.

  Any other command returns None without calling the base handler. A module
  command behaves as before (these spokes have no modules), and a base command
  added later does nothing until it is classified here;
  ``tests/test_synthetic_spoke.py`` fails until it is.

The spoke also sends ``synthetic: 1`` in its auth frame. The hub records it
(``LabManagerHub.synthetic_spokes``) and leaves these spokes out of OS Updates,
Remote Console, mTLS cert issuance and pushes, the mTLS readiness card, the
hub URL, watchdog and TLS-verify pushes (listed as ``skipped`` on save), and
code updates. The marker only removes hub actions; it never exempts a spoke
from mTLS.
"""
# asyncio: stopping the scripts' spoke tasks (stop_all).
import asyncio
# atexit/shutil/tempfile: the private scratch dir and its cleanup.
import atexit
import functools
import logging
import shutil
import tempfile
# uuid: in-memory install id.
import uuid

# Same dual import layout as the other messaging modules.
try:
    from .control_plane import BaseControlPlane
except ImportError:  # bare-module layout (messaging.* top-level, no repo root)
    from control_plane import BaseControlPlane  # type: ignore

logger = logging.getLogger("SyntheticSpoke")

# Base commands whose handler only changes this process's memory.
PASS_THROUGH = frozenset({
    "HUB_PING", "NODE_CANARY_SET", "GET_AGENTS", "GET_NODE_STATS",
    "PXMX_LIST_VMS", "GET_VM_LIST", "AGENT_GET_VM_LIST",
    "SPOKE_SET_LOG_LEVEL", "SET_LOG_LEVEL", "SPOKE_GET_STATUS",
    "SPOKE_SET_HUB_SECRET", "SPOKE_SET_RECOVERY_PSK", "SPOKE_UPDATE_SESSION_KEY",
})
# Hub pushes and fan-outs that would write to the host or restart the process.
SKIPPED = frozenset({
    "SPOKE_UPDATE", "SPOKE_SET_WATCHDOG", "SPOKE_SET_TLS_VERIFY",
    "SPOKE_SET_HUB_URL", "SPOKE_SET_MTLS_MATERIALS",
    "SPOKE_SET_MTLS_CLIENT_CERT", "SPOKE_CLEAR_MTLS_CLIENT_CERT", "CLEAR_LOGS",
})
# Commands an operator aims at a node's host.
REFUSED = frozenset({
    "OS_UPDATE_CHECK", "OS_UPDATE_APPLY", "OS_UPDATE_APPLY_PACKAGES",
    "OS_REBOOT", "OS_FIX_ACCESS", "RUN_COMMAND", "SPOKE_SET_HOSTNAME",
    "SPOKE_MTLS_CSR", "SPOKE_GET_MTLS_STATUS",
})
# Seconds stop_all waits for the spoke tasks before it cancels the rest again.
# websockets' default close_timeout, so a close the hub answers is not cut short.
_RECANCEL_S = 10


@functools.cache
def _scratch_dir() -> str:
    """This process's private scratch dir, created on first use.

    atexit removes it. Both scripts turn SIGTERM, which the hub's Stop sends,
    into a clean exit, so only a forced kill (SIGKILL) leaves it behind."""
    d = tempfile.mkdtemp(prefix="lm-synthetic-spoke-")
    atexit.register(shutil.rmtree, d, True)
    return d


class SyntheticSpoke(BaseControlPlane):
    """A spoke client with no host of its own (test feed, load test).

    Subclasses run ``_connect_and_serve`` from their own reconnect loop, and
    the scripts end those loops with ``stop_all``; ``run()`` raises (see
    ``run``)."""

    @staticmethod
    async def stop_all(tasks, stop_evt):
        """Stop a script's spoke tasks: set stop_evt, then cancel them until all have ended.

        A single cancel can be lost. On Python 3.11 ``asyncio.wait_for`` drops
        a cancel that arrives after the call it waits on has finished, and
        returns that call's result instead. The TLS probe in
        ``_connect_and_serve`` connects through ``wait_for``, and a hub that
        is not listening refuses at once, inside that window. The spoke's
        reconnect loop then ran on, and ``asyncio.run`` waited for it forever.
        Setting stop_evt ends such a loop at its next check. Cancelling again
        every ``_RECANCEL_S`` seconds ends a task that lost its cancel inside
        a session, where the loop does not check stop_evt."""
        stop_evt.set()
        pending = set(tasks)
        while pending:
            for t in pending:
                t.cancel()
            _done, pending = await asyncio.wait(pending, timeout=_RECANCEL_S)
        # All have ended. Collect their results, as the scripts' gather did, so
        # an error a spoke ended with is not logged as never retrieved at exit.
        await asyncio.gather(*tasks, return_exceptions=True)

    async def run(self):
        """Refuse to start the base main loop.

        ``BaseControlPlane.run`` also starts the code-drift and hub-contact
        watchdogs (and, with ``LM_SPOKE_SELF_UPDATE=1``, the self-update
        timer), which exit the process for a restart or reboot the machine it
        runs on. The feeder inherits the hub's environment, so an
        ``LM_HUB_CONTACT_WATCHDOG=1`` there would arm the reboot stage on the
        hub's own box."""
        raise RuntimeError(f"{type(self).__name__} is a synthetic spoke: run "
                           "_connect_and_serve from the script's own loop, not run()")

    def _extra_auth_fields(self) -> dict:
        """Mark the connection as synthetic so the hub leaves it out of host actions."""
        # Older hubs ignore the unknown field.
        return {**super()._extra_auth_fields(), "synthetic": 1}

    async def handle_system_command(self, cmd_type, data):
        """Run, skip or refuse a base system command (see the module docstring)."""
        # Process-local commands: the base handles them.
        if cmd_type in PASS_THROUGH:
            return await super().handle_system_command(cmd_type, data)
        # Hub pushes: acknowledge without touching the host.
        if cmd_type in SKIPPED:
            return {"status": "SUCCESS",
                    "message": f"skipped (synthetic spoke) — {cmd_type} has no host to apply to"}
        # Host actions: refuse. Never log ``data``: OS_FIX_ACCESS carries a password.
        if cmd_type in REFUSED:
            logger.warning("%s refused %s: synthetic spoke, no host of its own",
                           self.spoke_id, cmd_type)
            return {"status": "ERROR",
                    "message": f"{cmd_type} is not supported on a synthetic spoke — "
                               "it has no host of its own"}
        # Module commands and unclassified base commands are not handled here.
        return None

    def _ensure_install_uuid(self) -> str:
        """A random in-memory install id (the base reads and writes the host's .env)."""
        return uuid.uuid4().hex

    def _persist_secret_to_env(self, key, value):
        """Write nothing: every base .env write (secrets, PSK, hub URL) goes through here."""

    def _touch_healthy_marker(self):
        """Write no healthy-marker file (it is the host's update-watchdog signal)."""

    def _clear_healthy_marker(self):
        """Remove no healthy-marker file."""

    def _mtls_material_dir(self) -> str:
        """The private scratch dir instead of the host's cert dir."""
        return _scratch_dir()

    def _present_client_cert(self, ctx):
        """Present no client cert: the only one on disk belongs to the host spoke."""
        return ctx
