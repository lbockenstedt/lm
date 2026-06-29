import asyncio
import logging
import argparse
from core.src.messaging.control_plane import BaseControlPlane
from client_sim_spoke import ClientSimSpoke

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ClientSimMain")

class ClientSimControlPlane(BaseControlPlane):
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)

        # Register the simulation module
        self.register_module("cs", ClientSimSpoke(spoke_id, {}))

    async def run(self):
        logger.info(f"Client Simulation Spoke starting... Connected to {self.hub_url}")
        await super().run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--hub-secret")
    parser.add_argument("--hub", required=True)
    args = parser.parse_args()

    cp = ClientSimControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
