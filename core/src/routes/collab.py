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
# Postpone evaluation of type hints (allows "str | None" on older Pythons).
from __future__ import annotations

# Filesystem paths and file ops for the stored capture.
import os
# sys.path, so the sibling collab_sink parser can be imported.
import sys
# Upload timestamp for the capture metadata.
import time

# Shared Hub helpers: file download response, HTTP error type, request and logger.
from api import FileResponse, HTTPException, Request, logger

# App -> {ports, label}. The single source of truth for the port sets used by
# the client sender (cs collab.py mirrors these) and the firewall alias the
# WebUI builds. Modeled on the IPAM_SOURCES registry pattern.
COLLAB_APP_PORTS: dict[str, dict] = {
    "teams": {"ports": [3478, 3481, 3479], "label": "Microsoft Teams"},
    "zoom":  {"ports": [8801, 8802, 8803], "label": "Zoom"},
    "webex": {"ports": [9000, 5004, 5006], "label": "Cisco WebEx"},
}

# The config keys that are stored (anything else in the POST is ignored).
_CFG_FIELDS = ("enabled", "default_app", "default_bw", "collab_server",
               "apps", "responder_enabled", "pcap")

# The uploaded replay capture lives under the hub state dir; the sink reads it
# via LM_COLLAB_PCAP (install_collab_sink.sh points at the same relative path).
_PCAP_RELPATH = os.path.join("collab", "replay.pcap")
_PCAP_MAX_BYTES = 64 * 1024 * 1024   # 64 MB — captures are short clips


def _cfg(gc: dict) -> dict:
    """Return a copy of the collab config from ``gc`` with defaults filled in."""
    cur = dict(gc.get("collab", {}) or {})
    # Fill in defaults for any missing settings.
    cur.setdefault("enabled", False)
    cur.setdefault("default_app", "teams")
    cur.setdefault("default_bw", "1M")
    cur.setdefault("collab_server", "")
    cur.setdefault("responder_enabled", True)
    cur.setdefault("pcap", None)   # metadata dict once a capture is uploaded
    apps = cur.get("apps") or {}
    # Default: every app enabled.
    cur["apps"] = {a: bool(apps.get(a, True)) for a in COLLAB_APP_PORTS}
    # Hand back the completed config.
    return cur


def _pcap_path(hub) -> str | None:
    """Absolute path to the stored replay capture (None if no state dir)."""
    # Find the hub state dir; without one there's nowhere to store the capture.
    data_dir = getattr(getattr(hub, "state", None), "data_dir", None)
    if not data_dir:
        return None
    return os.path.join(data_dir, _PCAP_RELPATH)


def _summarize_pcap(path: str) -> dict | None:
    """Parse a capture into stats via the shared collab_pcap parser (lives in
    the sibling collab_sink/ dir, off the app import path — add it lazily). None
    if the parser or file is unavailable/unparseable."""
    # Make the collab_sink dir importable, then summarise the capture.
    try:
        cs_dir = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "collab_sink"))
        if cs_dir not in sys.path:
            sys.path.insert(0, cs_dir)
        import collab_pcap  # noqa: PLC0415
        return collab_pcap.summarize(path)
    # Any failure (missing parser or a bad file) is logged and gives None.
    except Exception as e:  # noqa: BLE001
        logger.warning("collab: could not summarize pcap %s: %s", path, e)
        return None


def register(app, hub, ctx):
    """Register the Setup -> Collab routes and the capture download routes."""
    # Session and admin-check helpers from the shared route context.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request: Request):
        """Return the session user, or raise 403 if they are not an admin."""
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    # Read the collab config plus the app -> port registry.
    @app.get("/setup/collab")
    async def get_collab():
        """Return the collab config and the per-app port sets."""
        gc = hub.state.system_state.get("global_config", {})
        return {"config": _cfg(gc), "apps": COLLAB_APP_PORTS}

    # Save the collab config.
    @app.post("/setup/collab")
    async def set_collab(request: Request):
        """Merge the posted config into the stored one, clean it up and save it."""
        # Read the JSON body (defaulting to {}); accept {"config": {...}} or a bare config.
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        # Start from the stored config and copy over the allowed fields.
        gc = hub.state.system_state.get("global_config", {})
        cur = _cfg(gc)
        for k in _CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        # Clean up types; an unknown default app falls back to Teams, bandwidth to 1M.
        cur["enabled"] = bool(cur.get("enabled", False))
        cur["responder_enabled"] = bool(cur.get("responder_enabled", True))
        app_choice = str(cur.get("default_app") or "teams").strip().lower()
        cur["default_app"] = app_choice if app_choice in COLLAB_APP_PORTS else "teams"
        cur["default_bw"] = str(cur.get("default_bw") or "1M").strip() or "1M"
        cur["collab_server"] = str(cur.get("collab_server") or "").strip()
        # Update the per-app switches only when an "apps" dict was sent.
        apps_in = incoming.get("apps") if isinstance(incoming.get("apps"), dict) else None
        if apps_in is not None:
            cur["apps"] = {a: bool(apps_in.get(a, cur["apps"].get(a, True)))
                           for a in COLLAB_APP_PORTS}
        # `pcap` metadata is owned by the upload/delete endpoints — never let a
        # plain config POST forge or clobber it. Preserve the stored value.
        cur["pcap"] = _cfg(gc).get("pcap")
        # Store it, mark hub state for saving and log the new settings.
        gc["collab"] = {k: cur[k] for k in _CFG_FIELDS}
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        logger.info("collab config saved: enabled=%s app=%s bw=%s responder=%s",
                    cur["enabled"], cur["default_app"], cur["default_bw"],
                    cur["responder_enabled"])
        # Return the saved config.
        return {"status": "ok", "config": cur}

    @app.post("/setup/collab/pcap")
    async def upload_collab_pcap(request: Request):
        """Upload the replay capture used by the sim: the CLIENT replays its
        client→server datagrams at the sink, and the hub sink replays the
        capture's server→client datagrams back (its "responses"). Multipart
        field ``file`` (falls back to a raw body)."""
        # Admins only; we need a state dir to store the file in.
        _require_admin(request)
        path = _pcap_path(hub)
        if not path:
            raise HTTPException(status_code=500, detail="no writable state dir for pcap")
        # Read the file from a multipart "file" field, or the raw body (?name= for its name).
        filename, data = "", b""
        ctype = (request.headers.get("content-type") or "").lower()
        try:
            if "multipart/form-data" in ctype:
                form = await request.form()
                up = form.get("file")
                if up is None:
                    raise HTTPException(status_code=400, detail="no 'file' field in the upload")
                filename = getattr(up, "filename", "") or "replay.pcap"
                data = await up.read()
            else:
                data = await request.body()
                filename = request.query_params.get("name", "") or "replay.pcap"
        # Our own errors pass through; any other read failure is a 400.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        # Reject empty uploads and anything over the size limit.
        if not data:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(data) > _PCAP_MAX_BYTES:
            raise HTTPException(status_code=413, detail="capture exceeds 64 MB limit")
        # Persist to a temp file first, validate it parses to real UDP media,
        # then atomically swap in — a bad upload never replaces a good capture.
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"could not save upload: {e}")
        # A capture with no usable UDP media is deleted and refused.
        stats = _summarize_pcap(tmp)
        if not stats or (stats.get("c2s_packets", 0) + stats.get("s2c_packets", 0)) == 0:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise HTTPException(status_code=400,
                                detail="not a valid pcap/pcapng, or no UDP media flows found")
        # Swap the new capture in and build its metadata.
        os.replace(tmp, path)
        meta = {
            "filename": filename, "size": len(data), "uploaded_at": time.time(),
            "stats": stats,
        }
        # Store the metadata in the collab config and mark hub state for saving.
        gc = hub.state.system_state.get("global_config", {})
        cur = _cfg(gc)
        cur["pcap"] = meta
        gc["collab"] = {k: cur[k] for k in _CFG_FIELDS}
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Log the upload and return its metadata.
        logger.info("collab pcap uploaded: %s (%d B) c2s=%d s2c=%d dur=%ss",
                    filename, len(data), stats.get("c2s_packets", 0),
                    stats.get("s2c_packets", 0), stats.get("duration_s"))
        return {"status": "ok", "pcap": meta}

    # Admin download of the stored capture.
    @app.get("/setup/collab/pcap")
    async def download_collab_pcap(request: Request):
        """Return the stored capture (admin UI download + the source the clients
        pull for replay)."""
        # Admins only; 404 if no capture is stored.
        _require_admin(request)
        path = _pcap_path(hub)
        gc = hub.state.system_state.get("global_config", {})
        meta = _cfg(gc).get("pcap")
        if not path or not os.path.isfile(path) or not meta:
            raise HTTPException(status_code=404, detail="no capture uploaded")
        # Send the file under its original name.
        return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                            filename=meta.get("filename") or "replay.pcap")

    # Client-facing (no login) download of the capture.
    @app.get("/sim/collab/pcap")
    async def serve_collab_pcap():
        """Unauthenticated client-facing download of the replay capture. The sim
        clients reach this over the trusted wired/USB path (same transport as
        their UDP media) to pull the capture they replay; the payload is
        non-sensitive synthetic/lab media. 404 when no capture is set."""
        # 404 if no capture is stored, else send it as replay.pcap.
        path = _pcap_path(hub)
        gc = hub.state.system_state.get("global_config", {})
        meta = _cfg(gc).get("pcap")
        if not path or not os.path.isfile(path) or not meta:
            raise HTTPException(status_code=404, detail="no capture uploaded")
        return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                            filename="replay.pcap")

    # Delete the stored capture.
    @app.delete("/setup/collab/pcap")
    async def delete_collab_pcap(request: Request):
        """Delete the stored capture file and clear its metadata (admins only)."""
        # Admins only; remove the file if it exists (a failure is a 500).
        _require_admin(request)
        path = _pcap_path(hub)
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError as e:
                raise HTTPException(status_code=500, detail=f"could not delete: {e}")
        # Clear the capture metadata, save, and log it.
        gc = hub.state.system_state.get("global_config", {})
        cur = _cfg(gc)
        cur["pcap"] = None
        gc["collab"] = {k: cur[k] for k in _CFG_FIELDS}
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        logger.info("collab pcap deleted")
        return {"status": "ok"}