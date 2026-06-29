import logging
import asyncio
import httpx
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ClientSimEngine")

class ClientSimEngine:
    """
    Core interaction layer for Client Simulation.
    Manages the state and lifecycle of simulation VMs and their telemetry.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.sim_state = "IDLE" # IDLE, RUNNING, ERROR, STOPPING
        self.active_sims = {} # { vm_id: { "status": "...", "last_heartbeat": ... } }

        # Aruba Central API settings
        self.aruba_host = config.get("aruba_host")
        self.aruba_key = config.get("aruba_api_key")

        # Token management state
        self.central_token = {
            "access_token": None,
            "refresh_token": None,
            "expires_at": 0
        }
        self.central_auth_error = None
        self._token_task = None

        # Watchdog state
        self._watchdog_task = None
        self.watchdog_events = [] # List of recent recovery actions

    async def start_simulation(self, sim_profile: str) -> Dict[str, Any]:
        """
        Triggers the start of a client simulation based on a profile.
        """
        logger.info(f"Starting simulation with profile: {sim_profile}")

        # Start token refresh loop
        if not self._token_task:
            self._token_task = asyncio.create_task(self._central_token_manager())

        # Start simulation watchdog
        if not self._watchdog_task:
            self._watchdog_task = asyncio.create_task(self._simulation_watchdog())

        self.sim_state = "RUNNING"

        # Simulate VM spawning/starting
        self.active_sims = {
            "sim-vm-1": {"status": "ONLINE", "ip": "172.16.10.10", "profile": sim_profile},
            "sim-vm-2": {"status": "ONLINE", "ip": "172.16.10.11", "profile": sim_profile},
        }

        return {"status": "SUCCESS", "message": f"Simulation {sim_profile} started", "vms": list(self.active_sims.keys())}

    async def stop_simulation(self) -> Dict[str, Any]:
        """Stops all active simulation VMs."""
        logger.info("Stopping all simulation VMs...")
        self.sim_state = "STOPPING"

        if self._token_task:
            self._token_task.cancel()
            self._token_task = None

        if self._watchdog_task:
            self._watchdog_task.cancel()
            self._watchdog_task = None

        self.active_sims = {}
        self.sim_state = "IDLE"

        return {"status": "SUCCESS", "message": "All simulations stopped."}

    async def get_simulation_status(self) -> Dict[str, Any]:
        """Returns the current state of the simulation environment."""
        return {
            "status": "SUCCESS",
            "data": {
                "state": self.sim_state,
                "active_count": len(self.active_sims),
                "vms": self.active_sims,
                "central_status": "ERROR" if self.central_auth_error else "OK",
                "central_error": self.central_auth_error,
                "watchdog_events": self.watchdog_events[-10:] # Last 10 events
            }
        }

    async def get_telemetry_correlation(self, vm_id: str) -> Dict[str, Any]:
        """
        Correlates local VM state with Aruba Central telemetry.
        """
        if vm_id not in self.active_sims:
            return {"status": "ERROR", "message": "VM not active in simulation"}

        logger.info(f"Correlating telemetry for {vm_id}...")

        try:
            token = self.central_token.get("access_token")
            if not token:
                return {"status": "ERROR", "message": "Aruba Central token not available. Check configuration."}

            # Use the actual Aruba Central API
            # Based on the ported logic: base_url/network-monitoring/v1alpha1/devices
            base_url = self.aruba_host.rstrip("/") if self.aruba_host else ""
            if not base_url:
                return {"status": "ERROR", "message": "Aruba Central host not configured."}

            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient() as client:
                # In a real scenario, we would filter by VM ID or MAC
                # For now we probe the devices endpoint to verify connectivity
                resp = await client.get(f"{base_url}/network-monitoring/v1alpha1/devices", headers=headers, timeout=15)

                if resp.status_code == 401:
                    return {"status": "ERROR", "message": "Aruba Central token expired or invalid."}

                if resp.status_code != 200:
                    return {"status": "ERROR", "message": f"Aruba Central API returned {resp.status_code}"}

                # Mock the specific VM telemetry based on API success
                return {
                    "status": "SUCCESS",
                    "data": {
                        "vm_id": vm_id,
                        "aruba_status": "CONNECTED",
                        "signal_strength": "-65dBm",
                        "last_seen": f"{int(time.time())}s ago",
                        "api_verified": True
                    }
                }

        except Exception as e:
            logger.error(f"Telemetry correlation error: {e}")
            return {"status": "ERROR", "message": str(e)}

    async def _simulation_watchdog(self) -> None:
        """
        Monitors the desired state of simulation VMs and performs recoveries.
        """
        logger.info("Simulation watchdog started.")
        while True:
            try:
                if self.sim_state == "RUNNING" and self.active_sims:
                    # Check each VM's health
                    for vm_id, info in list(self.active_sims.items()):
                        # In a real system, we would call the hypervisor API here
                        # e.g., await self.proxmox.get_vm_status(vm_id)

                        # Simulate a random failure for demonstration purposes
                        import random
                        if random.random() < 0.05: # 5% chance of "failure" per check
                            logger.warning(f"Watchdog detected failure in {vm_id}. Attempting recovery...")
                            self.active_sims[vm_id]["status"] = "RECOVERING"

                            # Simulate recovery delay
                            await asyncio.sleep(2)

                            self.active_sims[vm_id]["status"] = "ONLINE"
                            event = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Recovered {vm_id} from failure."
                            self.watchdog_events.append(event)
                            logger.info(f"Watchdog successfully recovered {vm_id}.")

                # Maintain a reasonable event history length
                if len(self.watchdog_events) > 100:
                    self.watchdog_events = self.watchdog_events[-100:]

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Watchdog error: {e}")

            await asyncio.sleep(60) # Check every 60 seconds

    async def _central_token_manager(self) -> None:

        """Background task: keep Aruba Central token valid."""
        while True:
            try:
                if self.aruba_host and self.aruba_key:
                    no_token = not self.central_token.get("access_token")
                    expiring = time.time() >= self.central_token.get("expires_at", 0) - 300

                    if no_token:
                        await self._fetch_central_token()
                    elif expiring:
                        await self._refresh_central_token()

                # Update service health (conceptual, can be linked to Hub status)
                self.central_auth_error = None if self.central_token.get("access_token") else "Token missing"
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception(f"Central token manager error: {exc}")
                self.central_auth_error = str(exc)

            await asyncio.sleep(300)

    async def _fetch_central_token(self) -> bool:
        """Obtain the access token using the provided API key (simplified flow)."""
        try:
            base_url = self.aruba_host.rstrip("/")
            # Using the API key as a bearer token for initial fetch if it's a static key,
            # or implementing the OAuth2 flow if keys are client_id/secret.
            # Given the provided snippet, it supports both.

            async with httpx.AsyncClient() as client:
                # Simple probe to see if the key works
                resp = await client.get(f"{base_url}/platform/v1/customer_id",
                                      headers={"Authorization": f"Bearer {self.aruba_key}"},
                                      timeout=15)

                if resp.status_code == 200:
                    self.central_token["access_token"] = self.aruba_key
                    self.central_token["expires_at"] = time.time() + 7200
                    return True

                return False
        except Exception as e:
            logger.error(f"Token fetch failed: {e}")
            return False

    async def _refresh_central_token(self) -> bool:
        """Refresh the access token using the refresh token."""
        # Simplified refresh logic as actual OAuth2 credentials
        # (client_id/secret) are typically handled via a separate config.
        if not self.central_token.get("refresh_token"):
            return await self._fetch_central_token()

        try:
            base_url = self.aruba_host.rstrip("/")
            async with httpx.AsyncClient() as client:
                data = {
                    "grant_type": "refresh_token",
                    "refresh_token": self.central_token["refresh_token"],
                    "client_id": self.config.get("client_id", ""),
                    "client_secret": self.config.get("client_secret", ""),
                }
                resp = await client.post(f"{base_url}/oauth2/token", data=data, timeout=15)
                if resp.status_code == 200:
                    payload = resp.json()
                    self.central_token["access_token"] = payload["access_token"]
                    self.central_token["refresh_token"] = payload.get("refresh_token", self.central_token["refresh_token"])
                    self.central_token["expires_at"] = time.time() + payload.get("expires_in", 7200)
                    return True
                return False
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return False

    async def update_sim_config(self, new_config: Dict[str, Any]):
        """Updates simulation settings."""
        self.config.update(new_config)
        self.aruba_host = self.config.get("aruba_host")
        self.aruba_key = self.config.get("aruba_api_key")
        logger.info("Simulation configuration updated.")
        return {"status": "SUCCESS"}
