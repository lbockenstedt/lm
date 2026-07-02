import asyncio
import argparse
import logging
import os

try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

from agent_spoke import GenericAgent, _ROLE_MAP

try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
configure_logging()
logger = logging.getLogger("GenericAgentControlPlane")


class AgentControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-agent"

    def __init__(self, spoke_id, secret, hub_secret="", hub_url="", startup_role=""):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self._startup_role = startup_role
        # Default module_type; overridden when a role is loaded
        self.module_type = "agent"
        if startup_role and startup_role in _ROLE_MAP:
            _, _, mtype = _ROLE_MAP[startup_role]
            self.module_type = mtype

    async def run(self):
        logger.info("Starting Generic Agent → %s  (role=%s)", self.hub_url,
                    self._startup_role or "none")
        config = {"role": self._startup_role} if self._startup_role else {}
        agent = GenericAgent(self.spoke_id, config)
        self.register_module("agent", agent)
        await super().run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",     required=True)
    parser.add_argument("--secret", default=None,
                        help="Session secret. Omit for zero-touch provisioning — the hub will send it after admin approval.")
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",    required=True)
    parser.add_argument("--role",   default=os.environ.get("STARTUP_ROLE", ""),
                        help="Pre-load a role at startup: dns, dhcp, ...")
    args = parser.parse_args()

    cp = AgentControlPlane(args.id, args.secret, args.hub_secret, args.hub, args.role)
    asyncio.run(cp.run())
