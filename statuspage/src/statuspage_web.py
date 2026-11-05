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
# Standard-library logging (logger defined below).
import logging
# secrets.compare_digest checks tokens without leaking timing information.
import secrets
# Path locates the static assets folder.
from pathlib import Path

# FastAPI web framework pieces: app, request, dependency injection and HTTP errors.
from fastapi import FastAPI, Request, Depends, HTTPException
# Response helpers for serving the HTML file and JSON errors.
from fastapi.responses import FileResponse, JSONResponse
# Serves the /static assets folder.
from fastapi.staticfiles import StaticFiles

# Shares the status-page spoke's logger so messages appear together.
logger = logging.getLogger("StatusPageSpoke")

# Folder holding index.html and page assets, one level above this src directory.
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


async def require_clients_access(request: Request):
    """Require the configured clients/demo token; fail closed if absent."""
    # Fetch the token configured on the spoke attached to this app.
    spoke = getattr(request.app.state, "spoke", None)
    expected = (getattr(spoke, "clients_token", "") or "").strip()
    # No token configured means the endpoint is locked, not open (fail closed).
    if not expected:
        raise HTTPException(status_code=401, detail="clients access token is not configured")

    # Accept "Authorization: Bearer <token>" first.
    auth = request.headers.get("authorization", "")
    supplied = ""
    if auth.lower().startswith("bearer "):
        supplied = auth.split(None, 1)[1].strip()
    # Otherwise fall back to the X-Status-Token header, ?token= query, or cookie.
    supplied = (supplied or request.headers.get("x-status-token")
                or request.query_params.get("token")
                or request.cookies.get("lm_status_token") or "").strip()
    # Missing or wrong token: reject with 401.
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="clients access required")
    # Token matched; the dependency has nothing to return.
    return None


def build_status_app(spoke) -> FastAPI:
    """Build the FastAPI app for the status page.

    Args:
        spoke: The StatusPageSpoke providing snapshot(), uptime_bars() and trigger_demo().

    Returns:
        The configured FastAPI application.
    """
    # Create the app with the interactive API docs disabled, since this is a public site.
    app = FastAPI(title="Simulation Status", docs_url=None, redoc_url=None, openapi_url=None)
    # Attach the spoke so dependencies (require_clients_access) can reach it.
    app.state.spoke = spoke

    # Serve the single-page status UI at the root URL.
    @app.get("/")
    async def index():
        """Return index.html, or a 500 JSON error if the page assets are missing."""
        # Serve the page if it exists, otherwise explain what is missing.
        idx = _STATIC_DIR / "index.html"
        if idx.exists():
            return FileResponse(str(idx))
        return JSONResponse({"error": "status page assets missing"}, status_code=500)

    # Public JSON endpoint behind the page's status view.
    @app.get("/api/status")
    async def api_status():
        """Public read-only: overall banner + components + 90-day uptime bars."""
        # Take the latest snapshot and return only the public fields plus uptime bars.
        snap = spoke.snapshot()
        return {
            "tenant_name": snap.get("tenant_name"),
            "overall": snap.get("overall"),
            "components": snap.get("components") or [],
            "generated_at": snap.get("generated_at"),
            "uptime": spoke.uptime_bars(),
        }

    # Clients endpoint; requires the clients token via the dependency.
    @app.get("/api/clients")
    async def api_clients(_=Depends(require_clients_access)):
        """Clients list + demo scenario catalog for the demo dropdown."""
        # Return the client list and scenario catalog from the latest snapshot.
        snap = spoke.snapshot()
        return {
            "clients": snap.get("clients") or [],
            "scenarios": snap.get("scenarios") or {},
        }

    # Demo trigger endpoint; requires the clients token via the dependency.
    @app.post("/api/demo")
    async def api_demo(request: Request, _=Depends(require_clients_access)):
        """Trigger a demo (named failure scenario) on a client for 2h. The HUB
        forces the tenant + validates the client; we relay only hostname +
        scenario."""
        # Parse the JSON body; a missing or malformed body is treated as empty.
        try:
            body = await request.json()
        # Bad JSON: fall through with an empty body so validation below rejects it.
        except Exception:
            body = {}
        # Pull out and trim the two required fields.
        hostname = str((body or {}).get("hostname") or "").strip()
        scenario = str((body or {}).get("scenario") or "").strip()
        # Both are required.
        if not hostname or not scenario:
            raise HTTPException(status_code=400, detail="missing hostname/scenario")
        # Ask the spoke to relay the demo to the Hub.
        result = await spoke.trigger_demo(hostname, scenario)
        # A relay failure is reported as 502 Bad Gateway, since the Hub is upstream.
        if result.get("status") == "ERROR":
            raise HTTPException(status_code=502, detail=result.get("message") or "relay failed")
        return result

    # Serve page assets under /static only when the folder exists.
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Hand back the finished app.
    return app
