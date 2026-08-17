import asyncio
import argparse
import logging
import os

try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

from henet_spoke import HENetSpoke

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
logger = logging.getLogger("HENetControlPlane")


class HENetControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-henet"

    async def run(self):
        logger.info("Starting HE.NET spoke → %s", self.hub_url)
        self.module_type = "henet"
        config = {
            "henet_state": os.environ.get("HENET_STATE", "/etc/lm-henet/records.json"),
        }
        spoke = HENetSpoke(self.spoke_id, config)
        self.register_module("henet", spoke)
        await super().run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         required=True)
    parser.add_argument("--secret",     required=True)
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",        required=True)
    args = parser.parse_args()

    cp = HENetControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
