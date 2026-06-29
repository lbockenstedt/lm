import asyncio
import argparse
import logging
import os

try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

from dns_spoke import DNSSpoke

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("DNSControlPlane")


class DNSControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-dns"

    async def run(self):
        logger.info("Starting DNS spoke → %s", self.hub_url)
        self.module_type = "dns"
        config = {
            "unbound_conf": os.environ.get(
                "UNBOUND_CONF", "/etc/unbound/conf.d/lm-netbox.conf"
            )
        }
        spoke = DNSSpoke(self.spoke_id, config)
        self.register_module("dns", spoke)
        await super().run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         required=True)
    parser.add_argument("--secret",     required=True)
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",        required=True)
    args = parser.parse_args()

    cp = DNSControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
