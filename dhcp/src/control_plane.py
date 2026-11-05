"""Entry point and control plane for the standalone DHCP spoke.

Connects to the Hub, registers the DHCP module, and (only for a Kea HA pair) opens the
/ws/agent listener that the two Kea worker agents connect to.
"""
# asyncio runs the control plane's async main loop.
import asyncio
# argparse reads the spoke id, secrets and Hub URL from the command line.
import argparse
# Standard-library logging for startup messages.
import logging
# os reads environment-variable settings.
import os

# The agent-hosting control plane lives at a different import path in dev vs deployed layouts.
try:
    from core.src.messaging.agent_hosting import AgentHostingControlPlane
# Deployed layout: core/src is on sys.path directly.
except ImportError:
    from messaging.agent_hosting import AgentHostingControlPlane

# The DHCP module that will be registered with the control plane.
from dhcp_spoke import DHCPSpoke

# Prefer the shared logging setup; the import path differs between deployed and dev layouts.
try:
    from logging_setup import configure_logging
# Not found at top level: try the package path used in the source tree.
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    # Neither location exists: define a minimal stand-in with the same signature.
    except ImportError:
        import logging as _logging
        # Log line format and timestamp format, matching the shared logging setup.
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            """Fallback logging setup: log to stderr, and also to log_file when one is given."""
            # Write to both a file and the console when a log file was requested.
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            # force=True replaces any handlers another import may have already installed.
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# Configure logging now so every message below uses the standard format.
configure_logging()
# One named logger for this control-plane module.
logger = logging.getLogger("DHCPControlPlane")


class DHCPControlPlane(AgentHostingControlPlane):
    """Standalone DHCP spoke.

    Subclasses ``AgentHostingControlPlane`` so an HA deployment can host its two
    Kea workers on a DHCP-specific ``/ws/agent`` port (8770 — distinct from pxmx
    8766 / cs 8767 / hub-self 8768 / dns 8769 so the roles coexist on one box).
    The listener is opt-in and only comes up once the DHCP module declares an HA
    pair, so a single-host install binds nothing and behaves exactly as before.
    """

    # Module type reported to the Hub.
    MODULE_TYPE = "dhcp"
    # Environment variable names that override the agent port, loopback mode and listener.
    AGENT_PORT_ENV = "LM_DHCP_AGENT_PORT"
    AGENT_LOOPBACK_ENV = "LM_DHCP_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_DHCP_AGENT_LISTENER"
    # Where the agent listener's settings are stored on disk.
    AGENT_CONFIG_PATH = "/etc/lm-dhcp/agent.json"
    # The listener is off unless explicitly enabled (see _agent_listener_enabled).
    AGENT_LISTENER_OPT_IN = True
    # Workers authenticate by sending the shared PSK in their first frame, so
    # this listener never serves plaintext on a public interface: with no cert
    # it leaves the port closed and says why.
    AGENT_LISTENER_REQUIRE_TLS = True
    # Role-specific TLS env so a box hosting BOTH cluster roles gives each
    # listener its own certificate (the shared LM_TLS_CERT stays the fallback).
    AGENT_TLS_CERT_ENV = "LM_DHCP_TLS_CERT"
    AGENT_TLS_KEY_ENV = "LM_DHCP_TLS_KEY"
    # All agent ports default to 8770, which is reserved for the DHCP role.
    AGENT_LOOPBACK_PORT = 8770
    AGENT_WSS_PORT = 8770
    AGENT_FALLBACK_PORT = 8770

    def get_service_name(self) -> str:
        """Return the systemd service name for this spoke."""
        return "lm-dhcp"

    def _agent_listener_enabled(self) -> bool:
        """Serve ``/ws/agent`` only for a real Kea HA pair (or an explicit
        ``LM_DHCP_AGENT_LISTENER=1`` override)."""
        # An explicit env override forces the listener on.
        if os.environ.get(self.AGENT_LISTENER_ENV, "").strip() in ("1", "true", "True"):
            return True
        # Otherwise enable it only when the module has declared an HA pair.
        return self._cluster_listener_required()

    async def run(self):
        """Register the DHCP module, start the agent listener if needed, then run the Hub loop."""
        # Announce which Hub we are connecting to and tag this process as a DHCP spoke.
        logger.info("Starting DHCP spoke → %s", self.hub_url)
        self.module_type = "dhcp"
        # Kea Control Agent URL; defaults to the local agent on port 8001.
        config = {
            "kea_ca_url": os.environ.get("KEA_CA_URL", "http://localhost:8001")
        }
        # Build the DHCP module.
        spoke = DHCPSpoke(self.spoke_id, config)
        # Wire the back-reference BEFORE registration — see the DNS spoke's
        # equivalent.
        spoke.control_plane = self
        # Make the module reachable by Hub commands under the "dhcp" name.
        self.register_module("dhcp", spoke)
        # For an HA pair, make sure an agent PSK exists and start the /ws/agent server.
        if self._agent_listener_enabled():
            self._ensure_agent_secret()
            self._start_agent_server_task()
        # Hand control to the shared message loop.
        await super().run()


# Only run the spoke when executed as a script, not when imported.
if __name__ == "__main__":
    # Everything defaults from the unit's EnvironmentFile ($INSTALL_DIR/dhcp/.env).
    # The secret is deliberately NOT passed on the command line — argv is world
    # readable via `ps`, and the unit never passed it, so `--secret required=True`
    # crash-looped every fresh install before the first hub connection. An empty
    # SPOKE_SECRET is the legitimate zero-touch case.
    # Each option falls back to an environment variable from the unit's EnvironmentFile.
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         default=os.environ.get("SPOKE_ID", ""))
    parser.add_argument("--secret",     default=os.environ.get("SPOKE_SECRET", ""))
    # --hub-secret may be given with no value, which means an empty secret.
    parser.add_argument("--hub-secret", nargs='?',
                        default=os.environ.get("HUB_SECRET", ""), const="")
    # "auto" lets the control plane discover the Hub address.
    parser.add_argument("--hub",        default=os.environ.get("HUB_URL") or "auto")
    # Parse the command line into args.
    args = parser.parse_args()
    # A spoke id is mandatory; stop with a usage error if missing.
    if not args.id:
        parser.error("--id is required (or SPOKE_ID in the environment)")

    # Build the control plane and run it until the process is stopped.
    cp = DHCPControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
