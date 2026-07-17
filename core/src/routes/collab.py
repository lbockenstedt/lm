"""Collab traffic-sim admin route (Setup).

Config + the per-app port registry for the Teams/Zoom/WebEx UDP media
simulation. The hub runs a passive UDP sink (lm-collab-sink, installed by
collab_sink/install_collab_sink.sh) and the cs simulation clients send raw
UDP to it over the wired/USB path. This route is the management surface:
which apps are enabled, the default bandwidth, and the port sets the WebUI
uses to build the firewall alias + allow rule.

The client-side knobs live in the cs repo (configs/simulation.conf:
collab=off / collab_app / collab_bw / collab_time / collab_server); this
hub config is informational + drives the firewall-apply port set. The actual
firewall alias/rule is created by the WebUI tile via the EXISTING
/api/firewall/{id}/aliases + /rules endpoints (correct tenant-scoped authz)
— no new firewall dispatch here.
"""
from __future__ import annotations

from api import Request, logger

# App -> {ports, label}. The single source of truth for the port sets used by
# the client sender (cs collab.py mirrors these) and the firewall alias the
# WebUI builds. Modeled on the IPAM_SOURCES registry pattern.
COLLAB_APP_PORTS: dict[str, dict] = {
    "teams": {"ports": [3478, 3481, 3479], "label": "Microsoft Teams"},
    "zoom":  {"ports": [8801, 8802, 8803], "label": "Zoom"},
    "webex": {"ports": [9000, 5004, 5006], "label": "Cisco WebEx"},
}

_CFG_FIELDS = ("enabled", "default_app", "default_bw", "collab_server", "apps")


def _cfg(gc: dict) -> dict:
    cur = dict(gc.get("collab", {}) or {})
    cur.setdefault("enabled", False)
    cur.setdefault("default_app", "teams")
    cur.setdefault("default_bw", "1M")
    cur.setdefault("collab_server", "")
    apps = cur.get("apps") or {}
    # Default: every app enabled.
    cur["apps"] = {a: bool(apps.get(a, True)) for a in COLLAB_APP_PORTS}
    return cur


def register(app, hub, ctx):
    @app.get("/setup/collab")
    async def get_collab():
        gc = hub.state.system_state.get("global_config", {})
        return {"config": _cfg(gc), "apps": COLLAB_APP_PORTS}

    @app.post("/setup/collab")
    async def set_collab(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        gc = hub.state.system_state.get("global_config", {})
        cur = _cfg(gc)
        for k in _CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        cur["enabled"] = bool(cur.get("enabled", False))
        app_choice = str(cur.get("default_app") or "teams").strip().lower()
        cur["default_app"] = app_choice if app_choice in COLLAB_APP_PORTS else "teams"
        cur["default_bw"] = str(cur.get("default_bw") or "1M").strip() or "1M"
        cur["collab_server"] = str(cur.get("collab_server") or "").strip()
        apps_in = incoming.get("apps") if isinstance(incoming.get("apps"), dict) else None
        if apps_in is not None:
            cur["apps"] = {a: bool(apps_in.get(a, cur["apps"].get(a, True)))
                           for a in COLLAB_APP_PORTS}
        gc["collab"] = {k: cur[k] for k in _CFG_FIELDS}
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        logger.info("collab config saved: enabled=%s app=%s bw=%s",
                    cur["enabled"], cur["default_app"], cur["default_bw"])
        return {"status": "ok", "config": cur}