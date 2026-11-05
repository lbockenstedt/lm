"""Entry point and control plane for the HE.NET (Hurricane Electric DNS) spoke.

Connects to the Hub and registers the henet module, which manages DNS records hosted
at dns.he.net.
"""
# asyncio runs the control plane's async main loop.
import asyncio
# argparse reads the spoke id, secrets and Hub URL from the command line.
import argparse
# Standard-library logging for startup messages.
import logging
# os reads environment-variable settings.
import os

# The control plane base class lives at a different import path in dev vs deployed layouts.
try:
    from core.src.messaging.control_plane import BaseControlPlane
# Deployed layout: core/src is on sys.path directly.
except ImportError:
    from messaging.control_plane import BaseControlPlane

# The HE.NET module that will be registered with the control plane.
from henet_spoke import HENetSpoke

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
logger = logging.getLogger("HENetControlPlane")


class HENetControlPlane(BaseControlPlane):
    """Control plane for the HE.NET spoke; wires the henet module into the Hub connection."""
    def get_service_name(self) -> str:
        """Return the systemd service name for this spoke."""
        return "lm-henet"

    async def run(self):
        """Register the HE.NET module, then run the Hub message loop."""
        # Announce which Hub we are connecting to and tag this process as an henet spoke.
        logger.info("Starting HE.NET spoke → %s", self.hub_url)
        self.module_type = "henet"
        # Where the managed-record state file lives; overridable via HENET_STATE.
        config = {
            "henet_state": os.environ.get("HENET_STATE", "/etc/lm-henet/records.json"),
        }
        # Build the module and make it reachable by Hub commands under the "henet" name.
        spoke = HENetSpoke(self.spoke_id, config)
        self.register_module("henet", spoke)
        # Hand control to the shared message loop.
        await super().run()


# Only run the spoke when executed as a script, not when imported.
if __name__ == "__main__":
    # Define the command-line options; --hub-secret may be given with no value (empty).
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         required=True)
    parser.add_argument("--secret",     required=True)
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",        required=True)
    # Parse the command line into args.
    args = parser.parse_args()

    # Build the control plane and run it until the process is stopped.
    cp = HENetControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
