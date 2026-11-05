"""Client simulation spoke.

Lab Manager module that receives Hub commands (prefixed CS_) and forwards them to the
ClientSimEngine, which manages the simulated client VMs.
"""
# Standard-library logging for command tracing.
import logging
# Type hints only; they document the shape of command payloads and results.
from typing import Dict, Any
# BaseSpoke is the common parent class every Lab Manager module extends.
from core.src.base_spoke import BaseSpoke
# The engine that actually runs the simulation and talks to Aruba Central.
from client_sim_engine import ClientSimEngine

# One named logger so all client-sim spoke messages can be filtered together.
logger = logging.getLogger("ClientSimSpoke")

class ClientSimSpoke(BaseSpoke):
    """
    Client Simulation Spoke for Lab Manager.
    Translates Hub commands into Simulation control actions.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        """Set up the spoke and create its simulation engine.

        Args:
            spoke_id: Identifier of this spoke as known to the Hub.
            config: Module settings passed straight through to the engine.
        """
        # Let BaseSpoke store the id/config and do its common setup.
        super().__init__(spoke_id, config)

        # Initialize the simulation engine
        self.engine = ClientSimEngine(config)

        # Caching and state
        # Spare cache dict for module-level state (currently unused).
        self._cache = {}

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one Hub command to the matching engine action.

        Args:
            command_type: Command name such as CS_START_SIMULATION (case-insensitive).
            data: Command payload from the Hub.

        Returns:
            A result dict with at least a "status" key.
        """
        # Upper-case the command so matching below is case-insensitive.
        normalized_cmd = command_type.upper()

        # Log every command received for troubleshooting.
        logger.info(f"Handling ClientSim Command: {command_type}")

        # Hub pushed new settings: apply them to the engine.
        if normalized_cmd == "UPDATE_CONFIG":
            return await self.engine.update_sim_config(data)

        # Hub asked which version of this module is installed.
        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # Start a simulation, using the "default" profile if none was given.
        if normalized_cmd == "CS_START_SIMULATION":
            profile = data.get("profile", "default")
            return await self.engine.start_simulation(profile)

        # Stop every running simulation VM.
        if normalized_cmd == "CS_STOP_SIMULATION":
            return await self.engine.stop_simulation()

        # Report current simulation state.
        if normalized_cmd == "CS_GET_STATUS":
            return await self.engine.get_simulation_status()

        # Correlate one VM with Aruba Central; a vm_id is required.
        if normalized_cmd == "CS_GET_TELEMETRY":
            vm_id = data.get("vm_id")
            if not vm_id:
                return {"status": "ERROR", "message": "Missing vm_id"}
            return await self.engine.get_telemetry_correlation(vm_id)

        # Any other command is not something this module understands.
        return {"status": "ERROR", "message": f"Command {command_type} not supported by client-sim module"}

    def get_version(self) -> str:
        """Returns the current version of the Client Simulation module (from the VERSION file)."""
        # pathlib is imported lazily because only this method needs it.
        from pathlib import Path
        # Read the VERSION file two directories up; a missing/unreadable file is not fatal.
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        # No VERSION file (e.g. dev checkout): report "unknown" instead of failing.
        except Exception:
            return "unknown"

    async def get_status(self) -> Dict[str, Any]:
        """Return a short health/status summary of this spoke for the Hub dashboard."""
        # Ask the engine for its full status, then pick out the headline fields.
        status = await self.engine.get_simulation_status()
        return {
            "spoke_id": self.spoke_id,
            "module": "client-sim",
            "sim_state": status.get("data", {}).get("state", "UNKNOWN"),
            "active_vms": status.get("data", {}).get("active_count", 0),
            "connection": "CONNECTED"
        }
