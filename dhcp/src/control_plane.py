import asyncio
import argparse
import logging
import os

try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

from dhcp_spoke import DHCPSpoke

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("DHCPControlPlane")


class DHCPControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-dhcp"

    async def run(self):
        logger.info("Starting DHCP spoke → %s", self.hub_url)
        self.module_type = "dhcp"
        config = {
            "kea_ca_url": os.environ.get("KEA_CA_URL", "http://localhost:8001")
        }
        spoke = DHCPSpoke(self.spoke_id, config)
        self.register_module("dhcp", spoke)
        await super().run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         required=True)
    parser.add_argument("--secret",     required=True)
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",        required=True)
    args = parser.parse_args()

    cp = DHCPControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
