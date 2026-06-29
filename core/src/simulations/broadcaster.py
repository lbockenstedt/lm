"""Simulations (cs) WebSocket fan-out — ``SimulationsBroadcaster``.

Multiplexes cs telemetry from spokes to WebUI clients. Subscribers are tracked
per tenant (plus a separate admin set that receives every tenant's stream).
The Hub owns one instance; the cs relay pushes spoke telemetry in and the
WebUI /sim WS endpoints subscribe/unsubscribe on connect/disconnect.
Audience: Hub developers.
"""

import logging
from typing import Any, Dict, Set

logger = logging.getLogger("SimulationsBroadcaster")


class SimulationsBroadcaster:
    """Per-tenant + admin WebSocket multiplexer for cs telemetry."""

    def __init__(self):
        # tenant_id -> Set[WebSocket]
        self._subscribers: Dict[str, Set] = {}
        # admin_subscribers: Set[WebSocket]
        self._admins: Set = set()

    async def broadcast(self, spoke_id: str, data: Dict[str, Any], tenant_id: str = None):
        """Broadcast telemetry to subscribers of its tenant and to all admins.

        ``tenant_id`` may be passed explicitly (the hub's CS_TELEMETRY handler
        does this — see ``main.py`` ``handle_connection`` / ``_handle_cs_telemetry``,
        which calls ``self.state.get_spoke_tenant(spoke_id)``) or carried inside
        ``data["tenant_id"]``; the explicit arg wins. If neither is present the
        frame is dropped — telemetry can't be routed without a tenant.

        Each subscriber send is isolated: a dead/closed socket raises, is logged
        and skipped, but does NOT abort the fan-out to the remaining subscribers.
        (Previously there was no try/except, so one stale socket aborted the whole
        broadcast with no log — silently killing telemetry delivery to everyone.)
        """
        # Explicit arg wins; fall back to the tenant carried in the payload.
        if not tenant_id:
            tenant_id = data.get("tenant_id")
        if not tenant_id:
            logger.debug("simulations broadcast: no tenant for spoke %s, dropping", spoke_id)
            return

        message = {
            "type": "telemetry",
            "spoke_id": spoke_id,
            "data": data
        }

        # Tenant subscribers — iterate a snapshot so a socket dropping mid-loop
        # (or a subscriber set mutating) can't break the fan-out.
        for ws in list(self._subscribers.get(tenant_id, set())):
            try:
                await ws.send_json(message)
            except Exception as exc:
                logger.warning(
                    "simulations broadcast: tenant subscriber send failed "
                    "(spoke=%s tenant=%s): %s", spoke_id, tenant_id, exc)

        # Admins receive every tenant's stream.
        for ws in list(self._admins):
            try:
                await ws.send_json(message)
            except Exception as exc:
                logger.warning(
                    "simulations broadcast: admin subscriber send failed "
                    "(spoke=%s tenant=%s): %s", spoke_id, tenant_id, exc)

    def subscribe(self, websocket, tenant_id: str, is_admin: bool = False):
        """Register a WebUI socket for a tenant's stream (or the admin stream)."""
        if is_admin:
            self._admins.add(websocket)
        else:
            if tenant_id not in self._subscribers:
                self._subscribers[tenant_id] = set()
            self._subscribers[tenant_id].add(websocket)

    def unsubscribe(self, websocket, tenant_id: str = None, is_admin: bool = False):
        """Drop a WebUI socket from its tenant stream (or the admin stream)."""
        if is_admin:
            self._admins.discard(websocket)
        elif tenant_id and tenant_id in self._subscribers:
            self._subscribers[tenant_id].discard(websocket)
