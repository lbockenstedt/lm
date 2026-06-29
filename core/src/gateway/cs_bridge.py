"""CSBridgePoller — the hub bridge between the cs (Client-Simulation) spoke's
command queue and the unified pxmx agents (Phase D2).

Architecture invariant (see the unify plan): a pxmx agent opens exactly one
socket — to the pxmx spoke. It never contacts the cs spoke. The hub mediates.
This loop is the mediator's "command delivery + USB-config sync" half
(``_relay_cs_event`` in ``main.py`` is the other half — agent events → cs spoke).

Each tick (``CS_POLL_INTERVAL_S``, default 5s):

  1. Resolve the connected pxmx (hypervisor) spoke; if none, idle.
  2. ``GET_AGENTS`` on it for the connected-agent list (with hostnames).
  3. For every agent whose ``agent_config[aid].client_simulation.enabled`` is
     true, resolve its cs spoke (``get_client_sim_spoke(tenant_id)``) and
     ``CS_POLL_AGENT_INBOX{hostname}`` — the cs spoke returns pending commands
     (already marked ``delivered``) and resets stale (>30s, unacked) ones.
  4. Relay each command to the agent as ``CS_COMMAND`` through the pxmx spoke's
     ``SPOKE_RELAY`` (``{target_agent_id, command:"CS_COMMAND", data}``). The
     spoke's ``send_to_agent`` enforces a 15s sync window, so the relay waits
     up to ``CS_RELAY_TIMEOUT_S`` (16s). Fast commands return
     ``{status:SUCCESS|ERROR}``; long ops return ``{status:ACCEPTED}`` (Phase E
     streams ``CS_PROGRESS`` + a terminal ``CS_COMMAND_RESULT`` that the agent
     emits up and the D1 relay maps to ``CS_INGEST_COMMAND_RESULT`` → ack).
  5. On a synchronous terminal result, ``CS_ACK_COMMAND{id, status, message}``
     back to the cs spoke (``completed``/``failed``). ``ACCEPTED`` is left
     ``delivered`` (no ack) for Phase E to close out.

Every ``CS_USB_CONFIG_INTERVAL_S`` (default 60s) per agent, ``CS_GET_USB_CONFIG``
is fetched from the cs spoke, diffed against the last pushed blob, and on change
pushed to the agent via ``SET_AGENT_CONFIG`` → ``UPDATE_CONFIG`` so
``agent.config["client_simulation"]["usb_config"]`` stays in sync. The cs spoke
is authoritative for USB-provision knobs; the hub store is not touched (the
spoke persists the merged config spoke-side for reconnect re-push).

Best-effort throughout: a missing pxmx/cs spoke, an offline agent, or a relay
failure is logged at debug and skipped — it never breaks the loop or the
agent's own telemetry/heartbeat.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("CSBridge")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except Exception:
        return default


def _unwrap(result: Any) -> Dict[str, Any]:
    """Unwrap a spoke reply the way api.py does: result["payload"]["data"]."""
    if isinstance(result, dict):
        data = result.get("payload", {}).get("data", result)
        return data if isinstance(data, dict) else (result if isinstance(result, dict) else {})
    return {}


class CSBridgePoller:
    """One long-lived hub task. Polls the cs spoke's inbox for every
    CS-enabled connected pxmx agent and relays commands + USB config."""

    def __init__(self, hub) -> None:
        self.hub = hub
        self.poll_interval = _env_int("CS_POLL_INTERVAL_S", 5, 2)
        self.usb_interval = _env_int("CS_USB_CONFIG_INTERVAL_S", 60, 30)
        # Slightly above the pxmx spoke's send_to_agent 15s sync window so a
        # slow-but-successful fast command isn't falsely timed out by the hub.
        self.relay_timeout = _env_int("CS_RELAY_TIMEOUT_S", 16, 5) + 0.0
        # Per-agent USB-config sync state.
        self._last_usb_cfg: Dict[str, str] = {}   # agent_id -> canonical blob sig
        self._last_usb_push: Dict[str, float] = {}  # agent_id -> ts

    # ── main loop ──────────────────────────────────────────────────────────

    async def run(self) -> None:
        # Let spokes/agents connect before the first poll.
        await asyncio.sleep(5)
        logger.info("CS bridge loop started (poll=%ds, usb=%ds)",
                    self.poll_interval, self.usb_interval)
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("CS bridge tick error: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _tick(self) -> None:
        hub = self.hub
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            return  # no pxmx spoke connected; nothing to relay to

        agents = await self._connected_agents(pxmx_spoke)
        if not agents:
            return

        now = time.time()
        for a in agents:
            aid = a.get("agent_id")
            hostname = a.get("hostname") or aid
            if not aid:
                continue
            cs_cfg = self._client_simulation(aid)
            if not cs_cfg.get("enabled"):
                continue
            tenant_id = cs_cfg.get("tenant_id") or self._spoke_tenant(pxmx_spoke)
            cs_spoke = hub.get_client_sim_spoke(tenant_id)
            if not cs_spoke:
                continue

            await self._relay_inbox(pxmx_spoke, cs_spoke, aid, hostname)

            if now - self._last_usb_push.get(aid, 0.0) >= self.usb_interval:
                await self._sync_usb_config(pxmx_spoke, cs_spoke, aid, hostname, now)

    # ── helpers ────────────────────────────────────────────────────────────

    async def _connected_agents(self, pxmx_spoke: str) -> list:
        resp = await self.hub.request_response(pxmx_spoke, "GET_AGENTS", {}, timeout=5.0)
        data = _unwrap(resp)
        agents = data.get("agents", []) if isinstance(data, dict) else []
        return [a for a in agents if isinstance(a, dict) and a.get("agent_id")]

    def _client_simulation(self, agent_id: str) -> Dict[str, Any]:
        try:
            ac = (self.hub.state.system_state.get("agent_config", {}) or {}).get(agent_id, {})
            return ac.get("client_simulation") or {}
        except Exception:
            return {}

    def _spoke_tenant(self, spoke_id: str) -> Optional[str]:
        try:
            return self.hub.state.get_spoke_tenant(spoke_id)
        except Exception:
            return None

    async def _relay_inbox(self, pxmx_spoke: str, cs_spoke: str,
                           agent_id: str, hostname: str) -> None:
        hub = self.hub
        inbox = await hub.request_response(cs_spoke, "CS_POLL_AGENT_INBOX",
                                           {"hostname": hostname}, timeout=5.0)
        data = _unwrap(inbox)
        commands = data.get("commands", []) if isinstance(data, dict) else []
        if not commands:
            return
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            await self._relay_one(pxmx_spoke, cs_spoke, agent_id, cmd)

    async def _relay_one(self, pxmx_spoke: str, cs_spoke: str,
                         agent_id: str, cmd: Dict[str, Any]) -> None:
        hub = self.hub
        cmd_id = cmd.get("id")
        action = cmd.get("action")
        if not cmd_id or not action:
            return
        # Carry the cs queue id so the agent's CS_COMMAND dispatch can
        # correlate a later CS_COMMAND_RESULT back to this command (Phase E).
        relay_data: Dict[str, Any] = {"cs_cmd_id": cmd_id, "action": action}
        args = cmd.get("args") or {}
        if isinstance(args, dict):
            relay_data.update(args)

        try:
            raw = await hub.request_response(
                pxmx_spoke, "SPOKE_RELAY",
                {"target_agent_id": agent_id, "command": "CS_COMMAND", "data": relay_data},
                timeout=self.relay_timeout,
            )
        except Exception as exc:  # noqa: BLE001
            await self._ack(cs_spoke, cmd_id, "failed", f"relay error: {exc}")
            return

        data = _unwrap(raw)
        status = str(data.get("status", "") or "").upper()
        message = data.get("message", "")

        # Long ops acknowledge "accepted" and stream progress + a terminal
        # CS_COMMAND_RESULT later (Phase E). Leave delivered; do not ack now.
        if status in ("ACCEPTED", "PENDING", "QUEUED"):
            logger.debug("CS bridge: %s %s accepted by %s (long-op; ack deferred)",
                         cmd_id, action, agent_id)
            return

        if status == "SUCCESS":
            ack_status, ack_msg = "completed", message or ""
        elif status in ("ERROR", "FAILED", "TIMEOUT"):
            ack_status, ack_msg = "failed", message or f"agent returned {status}"
        else:
            # Unknown / empty (e.g. timed-out request_response) → failed.
            ack_status, ack_msg = "failed", message or "agent command did not complete"

        await self._ack(cs_spoke, cmd_id, ack_status, ack_msg)

    async def _ack(self, cs_spoke: str, cmd_id: str, status: str, message: str) -> None:
        try:
            await self.hub.request_response(
                cs_spoke, "CS_ACK_COMMAND",
                {"id": cmd_id, "status": status, "message": message},
                timeout=5.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: ack %s (%s) failed: %s", cmd_id, status, exc)

    async def _sync_usb_config(self, pxmx_spoke: str, cs_spoke: str,
                               agent_id: str, hostname: str, now: float) -> None:
        hub = self.hub
        try:
            resp = await hub.request_response(cs_spoke, "CS_GET_USB_CONFIG",
                                              {"hostname": hostname}, timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: usb config fetch for %s failed: %s", agent_id, exc)
            self._last_usb_push[agent_id] = now
            return
        data = _unwrap(resp)
        cfg = data.get("usb_config") if isinstance(data, dict) else None
        if not isinstance(cfg, dict):
            self._last_usb_push[agent_id] = now
            return

        sig = json.dumps(cfg, sort_keys=True, separators=(",", ":"), default=str)
        if self._last_usb_cfg.get(agent_id) == sig:
            self._last_usb_push[agent_id] = now  # unchanged; nothing to push
            return

        # Build the full agent config (preserve display_name/enabled/tenant_id)
        # and merge the fresh usb_config into client_simulation. The cs spoke is
        # authoritative for USB knobs; the hub store is not modified (the spoke
        # persists the merged config spoke-side for reconnect re-push).
        ac = (hub.state.system_state.get("agent_config", {}) or {}).get(agent_id, {})
        merged = dict(ac) if isinstance(ac, dict) else {}
        cs_cfg = dict(merged.get("client_simulation") or {})
        cs_cfg["usb_config"] = cfg
        # Keep the guard set in sync if the cs spoke publishes one (optional).
        protected = cfg.get("protected_vmids") if isinstance(cfg, dict) else None
        if protected:
            cs_cfg["protected_vmids"] = protected
        merged["client_simulation"] = cs_cfg

        try:
            await hub.request_response(pxmx_spoke, "SET_AGENT_CONFIG",
                                       {"agent_id": agent_id, "config": merged},
                                       timeout=5.0)
            self._last_usb_cfg[agent_id] = sig
            logger.info("CS bridge: pushed usb_config to %s (tenant cs spoke %s)",
                        agent_id, cs_spoke)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CS bridge: usb_config push to %s failed: %s", agent_id, exc)
        finally:
            self._last_usb_push[agent_id] = now