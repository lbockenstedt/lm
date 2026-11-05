"""Simulations (cs) WebSocket fan-out — ``SimulationsBroadcaster``.

Multiplexes cs telemetry from spokes to WebUI clients. Subscribers are tracked
per tenant (plus a separate admin set that receives every tenant's stream).
The Hub owns one instance; the cs relay pushes spoke telemetry in and the
WebUI /sim WS endpoints subscribe/unsubscribe on connect/disconnect.
Audience: Hub developers.
"""

# Standard-library logging so failed sends can be reported without crashing the fan-out.
import logging
# Type hints only; they document the shape of the subscriber maps and telemetry payloads.
from typing import Any, Dict, Set

# One named logger so all broadcaster messages can be filtered together.
logger = logging.getLogger("SimulationsBroadcaster")


class SimulationsBroadcaster:
    """Per-tenant + admin WebSocket multiplexer for cs telemetry."""

    def __init__(self):
        """Start with no tenant subscribers and no admin subscribers."""
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
        # Neither the caller nor the payload named a tenant, so there is nowhere safe to route it.
        if not tenant_id:
            logger.debug("simulations broadcast: no tenant for spoke %s, dropping", spoke_id)
            return

        # Wrap the raw telemetry in an envelope so the browser knows its type and source spoke.
        message = {
            "type": "telemetry",
            "spoke_id": spoke_id,
            "data": data
        }

        # Tenant subscribers — iterate a snapshot so a socket dropping mid-loop
        # (or a subscriber set mutating) can't break the fan-out.
        for ws in list(self._subscribers.get(tenant_id, set())):
            # Send to this subscriber; one failure must not stop delivery to the others.
            try:
                await ws.send_json(message)
            # A closed or broken socket raises here; log it and move on to the next subscriber.
            except Exception as exc:
                logger.warning(
                    "simulations broadcast: tenant subscriber send failed "
                    "(spoke=%s tenant=%s): %s", spoke_id, tenant_id, exc)

        # Admins receive every tenant's stream.
        for ws in list(self._admins):
            # Same isolation as above: a dead admin socket is logged and skipped.
            try:
                await ws.send_json(message)
            except Exception as exc:
                logger.warning(
                    "simulations broadcast: admin subscriber send failed "
                    "(spoke=%s tenant=%s): %s", spoke_id, tenant_id, exc)

    def subscribe(self, websocket, tenant_id: str, is_admin: bool = False):
        """Register a WebUI socket for a tenant's stream (or the admin stream)."""
        # Admin sockets go into the shared admin set that sees every tenant.
        if is_admin:
            self._admins.add(websocket)
        # Tenant sockets go into that tenant's set, creating the set on first subscribe.
        else:
            if tenant_id not in self._subscribers:
                self._subscribers[tenant_id] = set()
            self._subscribers[tenant_id].add(websocket)

    def unsubscribe(self, websocket, tenant_id: str = None, is_admin: bool = False):
        """Drop a WebUI socket from its tenant stream (or the admin stream)."""
        # Admin sockets live in the admin set; discard() is a no-op if already removed.
        if is_admin:
            self._admins.discard(websocket)
        # Tenant sockets are removed only if the tenant still has a subscriber set.
        elif tenant_id and tenant_id in self._subscribers:
            self._subscribers[tenant_id].discard(websocket)
