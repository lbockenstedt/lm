"""Client simulation engine.

Tracks simulated client VMs, runs a watchdog that "recovers" failed VMs, and keeps an
Aruba Central API token fresh so VM state can be correlated with Central telemetry.
"""
# Standard-library logging for status and error messages.
import logging
# asyncio runs the background watchdog and token-refresh loops.
import asyncio
# httpx is the async HTTP client used to talk to the Aruba Central API.
import httpx
# time supplies wall-clock timestamps for token expiry and event logs.
import time
# Type hints only; they document the shape of config and result dicts.
from typing import Dict, Any

# One named logger so all client-sim engine messages can be filtered together.
logger = logging.getLogger("ClientSimEngine")

class ClientSimEngine:
    """
    Core interaction layer for Client Simulation.
    Manages the state and lifecycle of simulation VMs and their telemetry.
    """
    def __init__(self, config: Dict[str, Any]):
        """Store the config and initialise simulation, token and watchdog state.

        Args:
            config: Settings dict; reads aruba_host, aruba_api_key, client_id, client_secret.
        """
        # Keep the full config so later lookups (e.g. OAuth client credentials) can read it.
        self.config = config
        # Overall simulation lifecycle state, and a map of VMs currently being simulated.
        self.sim_state = "IDLE" # IDLE, RUNNING, ERROR, STOPPING
        self.active_sims = {} # { vm_id: { "status": "...", "last_heartbeat": ... } }

        # Pull the Central host and API key out of the config for quick access.
        # Aruba Central API settings
        self.aruba_host = config.get("aruba_host")
        self.aruba_key = config.get("aruba_api_key")

        # Holds the current Central OAuth token, its refresh token, and its expiry epoch time.
        # Token management state
        self.central_token = {
            "access_token": None,
            "refresh_token": None,
            "expires_at": 0
        }
        # Last authentication error text (None when healthy) and the refresh-loop task handle.
        self.central_auth_error = None
        self._token_task = None

        # Handle for the watchdog task and a rolling list of recovery messages shown in the UI.
        # Watchdog state
        self._watchdog_task = None
        self.watchdog_events = [] # List of recent recovery actions

    async def start_simulation(self, sim_profile: str) -> Dict[str, Any]:
        """
        Triggers the start of a client simulation based on a profile.
        """
        # Record which profile is being launched.
        logger.info(f"Starting simulation with profile: {sim_profile}")

        # Start the token refresh loop once; skip if it is already running.
        # Start token refresh loop
        if not self._token_task:
            self._token_task = asyncio.create_task(self._central_token_manager())

        # Start the watchdog once; skip if it is already running.
        # Start simulation watchdog
        if not self._watchdog_task:
            self._watchdog_task = asyncio.create_task(self._simulation_watchdog())

        # Mark the simulation as running so the watchdog begins checking VMs.
        self.sim_state = "RUNNING"

        # Pretend two VMs came online; real VM provisioning is not implemented yet.
        # Simulate VM spawning/starting
        self.active_sims = {
            "sim-vm-1": {"status": "ONLINE", "ip": "172.16.10.10", "profile": sim_profile},
            "sim-vm-2": {"status": "ONLINE", "ip": "172.16.10.11", "profile": sim_profile},
        }

        # Tell the caller the simulation started and which VM ids are part of it.
        return {"status": "SUCCESS", "message": f"Simulation {sim_profile} started", "vms": list(self.active_sims.keys())}

    async def stop_simulation(self) -> Dict[str, Any]:
        """Stops all active simulation VMs."""
        # Mark the simulation as stopping while background tasks are torn down.
        logger.info("Stopping all simulation VMs...")
        self.sim_state = "STOPPING"

        # Cancel the token refresh loop if it is running and forget its handle.
        if self._token_task:
            self._token_task.cancel()
            self._token_task = None

        # Cancel the watchdog if it is running and forget its handle.
        if self._watchdog_task:
            self._watchdog_task.cancel()
            self._watchdog_task = None

        # Drop all simulated VMs and return to the idle state.
        self.active_sims = {}
        self.sim_state = "IDLE"

        # Confirm to the caller that everything stopped.
        return {"status": "SUCCESS", "message": "All simulations stopped."}

    async def get_simulation_status(self) -> Dict[str, Any]:
        """Returns the current state of the simulation environment."""
        # Build a snapshot of state, VM list, Central auth health and recent watchdog events.
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
        # Refuse to correlate a VM that is not part of the current simulation.
        if vm_id not in self.active_sims:
            return {"status": "ERROR", "message": "VM not active in simulation"}

        # Log the start of the correlation attempt.
        logger.info(f"Correlating telemetry for {vm_id}...")

        # Any network/API failure below is caught and returned as an ERROR result.
        try:
            # Without a Central token we cannot call the API, so report that instead.
            token = self.central_token.get("access_token")
            if not token:
                return {"status": "ERROR", "message": "Aruba Central token not available. Check configuration."}

            # Use the actual Aruba Central API
            # Based on the ported logic: base_url/network-monitoring/v1alpha1/devices
            base_url = self.aruba_host.rstrip("/") if self.aruba_host else ""
            if not base_url:
                return {"status": "ERROR", "message": "Aruba Central host not configured."}

            # Send the token as an HTTP bearer authorization header.
            headers = {"Authorization": f"Bearer {token}"}
            # Open a short-lived async HTTP client for this request.
            async with httpx.AsyncClient() as client:
                # In a real scenario, we would filter by VM ID or MAC
                # For now we probe the devices endpoint to verify connectivity
                resp = await client.get(f"{base_url}/network-monitoring/v1alpha1/devices", headers=headers, timeout=15)

                # 401 means Central rejected the token.
                if resp.status_code == 401:
                    return {"status": "ERROR", "message": "Aruba Central token expired or invalid."}

                # Any other non-200 status is reported back with its code.
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

        # Network or parsing errors: log them and return them as an ERROR result.
        except Exception as e:
            logger.error(f"Telemetry correlation error: {e}")
            return {"status": "ERROR", "message": str(e)}

    async def _simulation_watchdog(self) -> None:
        """
        Monitors the desired state of simulation VMs and performs recoveries.
        """
        # Announce that the watchdog loop has begun.
        logger.info("Simulation watchdog started.")
        # Loop forever until the task is cancelled by stop_simulation().
        while True:
            # Errors inside one check must not kill the loop, so they are caught below.
            try:
                # Only check VMs while a simulation is actually running.
                if self.sim_state == "RUNNING" and self.active_sims:
                    # Check each VM's health
                    # Iterate over a copy so the dict can be modified safely during the loop.
                    for vm_id, info in list(self.active_sims.items()):
                        # In a real system, we would call the hypervisor API here
                        # e.g., await self.proxmox.get_vm_status(vm_id)

                        # Simulate a random failure for demonstration purposes
                        # random is only needed for the simulated failure below.
                        import random
                        # 5% chance of a fake failure each check, to exercise the recovery path.
                        if random.random() < 0.05: # 5% chance of "failure" per check
                            # Flag the VM as recovering so the status view shows it.
                            logger.warning(f"Watchdog detected failure in {vm_id}. Attempting recovery...")
                            self.active_sims[vm_id]["status"] = "RECOVERING"

                            # Simulate recovery delay
                            await asyncio.sleep(2)

                            # Mark the VM healthy again and record a timestamped recovery event.
                            self.active_sims[vm_id]["status"] = "ONLINE"
                            event = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Recovered {vm_id} from failure."
                            self.watchdog_events.append(event)
                            logger.info(f"Watchdog successfully recovered {vm_id}.")

                # Maintain a reasonable event history length
                if len(self.watchdog_events) > 100:
                    self.watchdog_events = self.watchdog_events[-100:]

            # Cancellation means stop_simulation() asked us to exit; leave the loop.
            except asyncio.CancelledError:
                break
            # Any other error is logged with a traceback and the loop keeps going.
            except Exception as e:
                logger.exception(f"Watchdog error: {e}")

            # Wait a minute before the next health check.
            await asyncio.sleep(60) # Check every 60 seconds

    async def _central_token_manager(self) -> None:

        """Background task: keep Aruba Central token valid."""
        # Loop forever until the task is cancelled by stop_simulation().
        while True:
            # Errors are caught below so one bad refresh does not stop the loop.
            try:
                # Only manage a token when Central host and key are both configured.
                if self.aruba_host and self.aruba_key:
                    # Decide whether we have no token yet or one that expires within 5 minutes.
                    no_token = not self.central_token.get("access_token")
                    expiring = time.time() >= self.central_token.get("expires_at", 0) - 300

                    # No token: fetch a new one. Nearly expired: refresh the existing one.
                    if no_token:
                        await self._fetch_central_token()
                    elif expiring:
                        await self._refresh_central_token()

                # Update service health (conceptual, can be linked to Hub status)
                self.central_auth_error = None if self.central_token.get("access_token") else "Token missing"
            # Cancellation means stop_simulation() asked us to exit; leave the loop.
            except asyncio.CancelledError:
                break
            # Other errors are logged and surfaced as the current auth error.
            except Exception as exc:
                logger.exception(f"Central token manager error: {exc}")
                self.central_auth_error = str(exc)

            # Re-check every 5 minutes.
            await asyncio.sleep(300)

    async def _fetch_central_token(self) -> bool:
        """Obtain the access token using the provided API key (simplified flow)."""
        # Network errors are caught below and reported as a failed fetch.
        try:
            # Strip a trailing slash so URL joins below do not produce "//".
            base_url = self.aruba_host.rstrip("/")
            # Using the API key as a bearer token for initial fetch if it's a static key,
            # or implementing the OAuth2 flow if keys are client_id/secret.
            # Given the provided snippet, it supports both.

            # Open a short-lived async HTTP client for the probe request.
            async with httpx.AsyncClient() as client:
                # Simple probe to see if the key works
                resp = await client.get(f"{base_url}/platform/v1/customer_id",
                                      headers={"Authorization": f"Bearer {self.aruba_key}"},
                                      timeout=15)

                # Success: treat the API key itself as the token, valid for 2 hours.
                if resp.status_code == 200:
                    self.central_token["access_token"] = self.aruba_key
                    self.central_token["expires_at"] = time.time() + 7200
                    return True

                # Any other status means the key did not work.
                return False
        # Network or HTTP errors: log and report failure.
        except Exception as e:
            logger.error(f"Token fetch failed: {e}")
            return False

    async def _refresh_central_token(self) -> bool:
        """Refresh the access token using the refresh token."""
        # Simplified refresh logic as actual OAuth2 credentials
        # (client_id/secret) are typically handled via a separate config.
        # No refresh token available, so fall back to a full fetch.
        if not self.central_token.get("refresh_token"):
            return await self._fetch_central_token()

        # Network errors are caught below and reported as a failed refresh.
        try:
            # Strip a trailing slash so URL joins below do not produce "//".
            base_url = self.aruba_host.rstrip("/")
            # Open a short-lived async HTTP client for the token request.
            async with httpx.AsyncClient() as client:
                # Standard OAuth2 refresh_token grant body.
                data = {
                    "grant_type": "refresh_token",
                    "refresh_token": self.central_token["refresh_token"],
                    "client_id": self.config.get("client_id", ""),
                    "client_secret": self.config.get("client_secret", ""),
                }
                # Ask Central's OAuth endpoint for a fresh access token.
                resp = await client.post(f"{base_url}/oauth2/token", data=data, timeout=15)
                # On success, store the new tokens and compute the new expiry time.
                if resp.status_code == 200:
                    payload = resp.json()
                    self.central_token["access_token"] = payload["access_token"]
                    self.central_token["refresh_token"] = payload.get("refresh_token", self.central_token["refresh_token"])
                    self.central_token["expires_at"] = time.time() + payload.get("expires_in", 7200)
                    return True
                # Any other status means the refresh failed.
                return False
        # Network or JSON errors: log and report failure.
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return False

    async def update_sim_config(self, new_config: Dict[str, Any]):
        """Updates simulation settings."""
        # Merge the new settings into the stored config.
        self.config.update(new_config)
        # Re-read the Central host and key in case they changed.
        self.aruba_host = self.config.get("aruba_host")
        self.aruba_key = self.config.get("aruba_api_key")
        # Log the change and confirm success.
        logger.info("Simulation configuration updated.")
        return {"status": "SUCCESS"}
