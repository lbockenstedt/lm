"""Hub-contact watchdog config route (Setup → Sync → Hub-Contact Watchdog).

Fleet-wide setting: when a spoke/agent can't reach the hub, escalate self-recovery
(restart the service → reboot the host → sleep → give up). Stored in
``global_config["hub_contact_watchdog"]`` and pushed to every spoke on save (and
reconciled on every connect via ``push_config_to_spoke``). The spoke persists it
locally so it applies even when the hub is unreachable — the case it recovers from.

Under ``/setup/`` so the access-control middleware admin-gates it.
"""
from __future__ import annotations

from api import HTTPException, Request, logger

_FIELDS = ("enabled", "service_s", "reboot_s", "reboot_grace_s", "sleep_s", "max_runs")
_DEFAULTS = {"enabled": False, "service_s": 300, "reboot_s": 900,
             "reboot_grace_s": 300, "sleep_s": 3600, "max_runs": 3}


def register(app, hub, ctx):
    def _cfg() -> dict:
        c = dict(_DEFAULTS)
        c.update((hub.state.get_global_config().get("hub_contact_watchdog") or {}))
        return c

    @app.get("/setup/hub-watchdog")
    async def get_hub_watchdog():
        return {"config": _cfg()}

    @app.post("/setup/hub-watchdog")
    async def set_hub_watchdog(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        cur = _cfg()
        cur["enabled"] = bool(incoming.get("enabled", cur["enabled"]))
        # reboot_s must exceed service_s (reboot is the escalation AFTER the restart)
        for k in ("service_s", "reboot_s", "reboot_grace_s", "sleep_s"):
            if incoming.get(k) is not None:
                try:
                    cur[k] = max(1, int(incoming[k]))
                except (TypeError, ValueError):
                    cur[k] = _DEFAULTS[k]
        if incoming.get("max_runs") is not None:
            try:
                cur["max_runs"] = max(1, int(incoming["max_runs"]))
            except (TypeError, ValueError):
                cur["max_runs"] = _DEFAULTS["max_runs"]
        if cur["reboot_s"] <= cur["service_s"]:
            raise HTTPException(status_code=400,
                                detail="reboot threshold must be greater than the service-restart threshold")
        clean = {k: cur[k] for k in _FIELDS}
        gc = hub.state.get_global_config()
        gc["hub_contact_watchdog"] = clean
        hub.state.save_state()
        # Fan out to every approved spoke now; later-connecting spokes reconcile
        # via push_config_to_spoke.
        fanout = {}
        try:
            fanout = await hub.push_watchdog_to_all_spokes(clean)
        except Exception as e:  # noqa: BLE001
            logger.warning("hub-watchdog: fan-out failed: %s", e)
            fanout = {"status": "ERROR", "error": str(e)}
        return {"status": "ok", "config": clean, "fanout": fanout}
