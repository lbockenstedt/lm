"""Entry point and control plane for the standalone DNS spoke.

Connects to the Hub, registers the DNS module, and (only for a resolver cluster) opens the
/ws/agent listener that the resolver worker agents connect to.
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

# The DNS module that will be registered with the control plane.
from dns_spoke import DNSSpoke

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
logger = logging.getLogger("DNSControlPlane")


class DNSControlPlane(AgentHostingControlPlane):
    """Standalone DNS spoke.

    Subclasses ``AgentHostingControlPlane`` so a clustered deployment can host
    its resolver workers on a DNS-specific ``/ws/agent`` port (8769 — distinct
    from pxmx 8766 / cs 8767 / hub-self 8768 so the roles coexist on one box).
    The listener is opt-in and only comes up once the DNS module declares 2+
    cluster members, so a single-host install binds nothing and behaves exactly
    as it did before.
    """

    # Module type reported to the Hub.
    MODULE_TYPE = "dns"
    # Environment variable names that override the agent port, loopback mode and listener.
    AGENT_PORT_ENV = "LM_DNS_AGENT_PORT"
    AGENT_LOOPBACK_ENV = "LM_DNS_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_DNS_AGENT_LISTENER"
    # Where the agent listener's settings are stored on disk.
    AGENT_CONFIG_PATH = "/etc/lm-dns/agent.json"
    # The listener is off unless explicitly enabled (see _agent_listener_enabled).
    AGENT_LISTENER_OPT_IN = True
    # Workers authenticate by sending the shared PSK in their first frame, so
    # this listener never serves plaintext on a public interface: with no cert
    # it leaves the port closed and says why.
    AGENT_LISTENER_REQUIRE_TLS = True
    # Role-specific TLS env so a box hosting BOTH cluster roles gives each
    # listener its own certificate (the shared LM_TLS_CERT stays the fallback).
    AGENT_TLS_CERT_ENV = "LM_DNS_TLS_CERT"
    AGENT_TLS_KEY_ENV = "LM_DNS_TLS_KEY"
    # All agent ports default to 8769, which is reserved for the DNS role.
    AGENT_LOOPBACK_PORT = 8769
    AGENT_WSS_PORT = 8769
    AGENT_FALLBACK_PORT = 8769

    def get_service_name(self) -> str:
        """Return the systemd service name for this spoke."""
        return "lm-dns"

    def _agent_listener_enabled(self) -> bool:
        """Serve ``/ws/agent`` only for a real resolver cluster (or an explicit
        ``LM_DNS_AGENT_LISTENER=1`` override)."""
        # An explicit env override forces the listener on.
        if os.environ.get(self.AGENT_LISTENER_ENV, "").strip() in ("1", "true", "True"):
            return True
        # Otherwise enable it only when the module has declared 2+ cluster members.
        return self._cluster_listener_required()

    async def run(self):
        """Register the DNS module, start the agent listener and background loops, then run the Hub
        loop.
        """
        # Announce which Hub we are connecting to and tag this process as a DNS spoke.
        logger.info("Starting DNS spoke → %s", self.hub_url)
        # Path to the generated Unbound config file; defaults to the standard conf.d location.
        self.module_type = "dns"
        config = {
            "unbound_conf": os.environ.get(
                "UNBOUND_CONF", "/etc/unbound/conf.d/lm-netbox.conf"
            )
        }
        # Build the DNS module.
        spoke = DNSSpoke(self.spoke_id, config)
        # Wire the back-reference BEFORE registration: the module's cluster
        # transport resolves ``control_plane`` to reach connected workers, and
        # ``_cluster_listener_required`` is consulted the moment the module is
        # registered.
        spoke.control_plane = self
        # Make the module reachable by Hub commands under the "dns" name.
        self.register_module("dns", spoke)
        # For a resolver cluster, make sure an agent PSK exists and start the /ws/agent server.
        if self._agent_listener_enabled():
            self._ensure_agent_secret()
            self._start_agent_server_task()
        # Start the module's periodic background tasks now that it is wired up.
        spoke.start_background_loops()
        # Hand control to the shared message loop.
        await super().run()


# Only run the spoke when executed as a script, not when imported.
if __name__ == "__main__":
    # Everything defaults from the unit's EnvironmentFile ($INSTALL_DIR/dns/.env).
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
    cp = DNSControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
