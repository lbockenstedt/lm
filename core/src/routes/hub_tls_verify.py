"""Fleet hub-TLS-verification policy (Setup → Sync → Hub TLS Verification).

Lets an admin turn on (or relax) spoke/agent verification of the hub's TLS cert
after install, without re-running installers. Stored in
``global_config["hub_tls_verify"]`` and pushed (``SPOKE_SET_TLS_VERIFY``) to every
spoke/agent on save and on every reconnect. Each node persists it locally (it
outranks the install-time ``LM_HUB_TLS_VERIFY``) and restarts only when its
effective mode changes. ``on`` is refused per node if the hub cert does not
verify from that node, so the switch cannot lock a node out.

Modes: ``install`` (default — keep each node's install-time setting), ``auto``
(verify when possible; required once it has verified), ``on``, ``off``.

Under ``/setup/`` so the access-control middleware admin-gates it.
"""
from __future__ import annotations

from api import HTTPException, Request, logger

MODES = ("install", "auto", "on", "off")


def register(app, hub, ctx):
    def _mode() -> str:
        m = str(hub.state.get_global_config().get("hub_tls_verify") or "install").lower()
        return m if m in MODES else "install"

    @app.get("/setup/hub-tls-verify")
    async def get_hub_tls_verify():
        return {"mode": _mode(), "modes": list(MODES)}

    @app.post("/setup/hub-tls-verify")
    async def set_hub_tls_verify(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        mode = str((body or {}).get("mode") or "").strip().lower()
        if mode not in MODES:
            raise HTTPException(status_code=400, detail=f"mode must be one of {', '.join(MODES)}")
        gc = hub.state.get_global_config()
        gc["hub_tls_verify"] = mode
        hub.state._mark_dirty()
        try:
            fanout = await hub.push_tls_verify_to_all_spokes(mode)
        except Exception as e:  # noqa: BLE001
            logger.warning("hub-tls-verify: fan-out failed: %s", e)
            fanout = {"status": "ERROR", "error": str(e)}
        return {"status": "ok", "mode": mode, "fanout": fanout}
