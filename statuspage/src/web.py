"""FastAPI app for the public status page (served by StatusPageSpoke's own
uvicorn — mirrors the cs lm-spoke client-API pattern).

Routes:
  GET  /                 — the status page SPA (public)
  GET  /api/status       — overall + components + 90-day uptime bars (public)
  GET  /api/clients      — clients + demo scenarios   [auth seam]
  POST /api/demo         — trigger a demo on a client  [auth seam]
  /static/*              — page assets

AUTH SEAM: ``require_clients_access`` gates the Clients view + demo endpoint.
In dev mode it is a NO-OP (open). To turn auth on later, implement the check in
ONE place here (token/session) — no route changes needed. The read-only status
surface (/, /api/status) is ALWAYS public by design.
"""
import logging
from pathlib import Path

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger("StatusPageSpoke")

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


async def require_clients_access(request: Request):
    """Auth seam for the Clients view + demo trigger.

    DEV MODE: open — returns None (no gate). LATER: enforce here (e.g. a signed
    token cookie / query param) and raise HTTPException(401) to lock the Clients
    page while leaving the public status page untouched. This is the single point
    to flip auth on; do not scatter checks across routes.
    """
    return None


def build_status_app(spoke) -> FastAPI:
    app = FastAPI(title="Simulation Status", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/")
    async def index():
        idx = _STATIC_DIR / "index.html"
        if idx.exists():
            return FileResponse(str(idx))
        return JSONResponse({"error": "status page assets missing"}, status_code=500)

    @app.get("/api/status")
    async def api_status():
        """Public read-only: overall banner + components + 90-day uptime bars."""
        snap = spoke.snapshot()
        return {
            "tenant_name": snap.get("tenant_name"),
            "overall": snap.get("overall"),
            "components": snap.get("components") or [],
            "generated_at": snap.get("generated_at"),
            "uptime": spoke.uptime_bars(),
        }

    @app.get("/api/clients")
    async def api_clients(_=Depends(require_clients_access)):
        """Clients list + demo scenario catalog for the demo dropdown."""
        snap = spoke.snapshot()
        return {
            "clients": snap.get("clients") or [],
            "scenarios": snap.get("scenarios") or {},
        }

    @app.post("/api/demo")
    async def api_demo(request: Request, _=Depends(require_clients_access)):
        """Trigger a demo (named failure scenario) on a client for 2h. The HUB
        forces the tenant + validates the client; we relay only hostname +
        scenario."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        hostname = str((body or {}).get("hostname") or "").strip()
        scenario = str((body or {}).get("scenario") or "").strip()
        if not hostname or not scenario:
            raise HTTPException(status_code=400, detail="missing hostname/scenario")
        result = await spoke.trigger_demo(hostname, scenario)
        if result.get("status") == "ERROR":
            raise HTTPException(status_code=502, detail=result.get("message") or "relay failed")
        return result

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return app
