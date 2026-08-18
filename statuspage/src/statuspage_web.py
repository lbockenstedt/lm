"""FastAPI app for the public status page (served by StatusPageSpoke's own
uvicorn — mirrors the cs lm-spoke client-API pattern).

Routes:
  GET  /                 — the status page SPA (public)
  GET  /api/status       — overall + components + 90-day uptime bars (public)
  GET  /api/clients      — clients + demo scenarios   [auth seam]
  POST /api/demo         — trigger a demo on a client  [auth seam]
  /static/*              — page assets

AUTH SEAM: ``require_clients_access`` gates the Clients view + demo endpoint.
It accepts the status-page clients token via Bearer, X-Status-Token, query token,
or lm_status_token cookie. The read-only status surface (/, /api/status) is
ALWAYS public by design.
"""
import logging
import secrets
from pathlib import Path

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger("StatusPageSpoke")

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


async def require_clients_access(request: Request):
    """Require the configured clients/demo token; fail closed if absent."""
    spoke = getattr(request.app.state, "spoke", None)
    expected = (getattr(spoke, "clients_token", "") or "").strip()
    if not expected:
        raise HTTPException(status_code=401, detail="clients access token is not configured")

    auth = request.headers.get("authorization", "")
    supplied = ""
    if auth.lower().startswith("bearer "):
        supplied = auth.split(None, 1)[1].strip()
    supplied = (supplied or request.headers.get("x-status-token")
                or request.query_params.get("token")
                or request.cookies.get("lm_status_token") or "").strip()
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="clients access required")
    return None


def build_status_app(spoke) -> FastAPI:
    app = FastAPI(title="Simulation Status", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.spoke = spoke

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
