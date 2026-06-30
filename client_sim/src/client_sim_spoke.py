import logging
import asyncio
from typing import Dict, Any
from core.src.base_spoke import BaseSpoke
from client_sim_engine import ClientSimEngine

logger = logging.getLogger("ClientSimSpoke")

class ClientSimSpoke(BaseSpoke):
    """
    Client Simulation Spoke for Lab Manager.
    Translates Hub commands into Simulation control actions.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)

        # Initialize the simulation engine
        self.engine = ClientSimEngine(config)

        # Caching and state
        self._cache = {}

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        normalized_cmd = command_type.upper()

        logger.info(f"Handling ClientSim Command: {command_type}")

        if normalized_cmd == "UPDATE_CONFIG":
            return await self.engine.update_sim_config(data)

        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if normalized_cmd == "CS_START_SIMULATION":
            profile = data.get("profile", "default")
            return await self.engine.start_simulation(profile)

        if normalized_cmd == "CS_STOP_SIMULATION":
            return await self.engine.stop_simulation()

        if normalized_cmd == "CS_GET_STATUS":
            return await self.engine.get_simulation_status()

        if normalized_cmd == "CS_GET_TELEMETRY":
            vm_id = data.get("vm_id")
            if not vm_id:
                return {"status": "ERROR", "message": "Missing vm_id"}
            return await self.engine.get_telemetry_correlation(vm_id)

        return {"status": "ERROR", "message": f"Command {command_type} not supported by client-sim module"}

    def get_version(self) -> str:
        """Returns the current version of the Client Simulation module (from the VERSION file)."""
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"

    async def get_status(self) -> Dict[str, Any]:
        status = await self.engine.get_simulation_status()
        return {
            "spoke_id": self.spoke_id,
            "module": "client-sim",
            "sim_state": status.get("data", {}).get("state", "UNKNOWN"),
            "active_vms": status.get("data", {}).get("active_count", 0),
            "connection": "CONNECTED"
        }
