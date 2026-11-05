"""Entry point for the Client Simulation spoke process.

Parses command-line arguments, configures logging, connects to the Hub control plane and
registers the client-sim module so it can receive commands.
"""
# asyncio runs the control plane's async main loop.
import asyncio
# Standard-library logging for startup messages.
import logging
# argparse reads the spoke id, secrets and Hub URL from the command line.
import argparse
# BaseControlPlane handles the Hub connection, authentication and message routing.
from core.src.messaging.control_plane import BaseControlPlane
# The client-sim module that will be registered with the control plane.
from client_sim_spoke import ClientSimSpoke

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
# One named logger for this entry-point module.
logger = logging.getLogger("ClientSimMain")

class ClientSimControlPlane(BaseControlPlane):
    """Control plane for the client-sim spoke; wires the CS module into the Hub connection."""
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        """Connect settings for the Hub and register the client-sim module.

        Args:
            spoke_id: Identifier of this spoke as known to the Hub.
            secret: This spoke's shared secret.
            hub_secret: Optional secret used to verify messages from the Hub.
            hub_url: Address of the Hub to connect to.
        """
        # Let the base class store connection details.
        super().__init__(spoke_id, secret, hub_secret, hub_url)

        # Register the simulation module
        self.register_module("cs", ClientSimSpoke(spoke_id, {}))

    async def run(self):
        """Log startup and run the base control-plane loop until it exits."""
        # Announce which Hub we are connecting to.
        logger.info(f"Client Simulation Spoke starting... Connected to {self.hub_url}")
        # Hand control to the shared message loop.
        await super().run()

# Only run the spoke when executed as a script, not when imported.
if __name__ == "__main__":
    # Define the required command-line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--hub-secret")
    parser.add_argument("--hub", required=True)
    # Parse the command line into args.
    args = parser.parse_args()

    # Build the control plane and run it until the process is stopped.
    cp = ClientSimControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
