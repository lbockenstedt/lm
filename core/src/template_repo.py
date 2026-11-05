"""Hub-local repository of Proxmox template backups (vzdump .vma.zst).

A Global Admin triggers a backup of a Proxmox template; the owning node's agent
runs ``vzdump`` and streams the resulting archive to the hub, where it is stored
on local disk (the hub is a full VM now) alongside operator-editable metadata
(version / OS / purpose / tenant). Later phases will let an operator pull a stored
template back down to a Proxmox node.

Layout — one directory per template::

    <data_dir>/template-repo/<id>/
        image.vma.zst     the vzdump archive (streamed in)
        meta.json         the record (single source of truth)

``meta.json`` is authoritative: the in-memory index is rebuilt from it on load, so
a hub restart recovers the full repo. A per-backup one-time ``_upload_token`` gates
the agent's streamed upload (agents have no browser session); it is consumed when
the upload finalizes and never leaves the hub in the public view.
"""
from __future__ import annotations

# json/os/shutil for on-disk records; threading guards the index; uuid makes ids/tokens.
import json
import os
import shutil
import threading
import uuid
# UTC timestamps; type hints.
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Keys never exposed in the public (WebUI/API) view of a record.
_PRIVATE_KEYS = {"_upload_token", "_refresh_token"}
# Metadata fields an operator may edit after upload. ``tenant`` is NOT here — it
# is DERIVED from the source PXMX host's tenant binding at backup time and is
# authoritative (the repo is tenant-driven, per host), so it can't be re-typed.
_EDITABLE = {"version", "os", "purpose", "name"}


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    # Timezone-aware so stored timestamps compare correctly.
    return datetime.now(timezone.utc).isoformat()


class TemplateRepo:
    """On-disk store of Proxmox template archives with an in-memory index rebuilt from meta.json."""
    def __init__(self, data_dir: str):
        """Create the repo root under data_dir and load existing records."""
        # Repo root directory, created if needed.
        self.root = os.path.join(data_dir, "template-repo")
        os.makedirs(self.root, exist_ok=True)
        # Reentrant lock around the index, then load records from disk.
        self._lock = threading.RLock()
        self._index: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ── persistence ─────────────────────────────────────────────────────────
    def _load(self) -> None:
        """Rebuild the index from every <id>/meta.json; unreadable files are skipped."""
        # Each subdirectory may hold a meta.json.
        for name in os.listdir(self.root):
            mp = os.path.join(self.root, name, "meta.json")
            if os.path.isfile(mp):
                # Load it; keep only dicts with an id.
                try:
                    with open(mp, encoding="utf-8") as f:
                        rec = json.load(f)
                    if isinstance(rec, dict) and rec.get("id"):
                        self._index[rec["id"]] = rec
                # Corrupt record: ignore it.
                except Exception:
                    pass

    def _dir(self, tid: str) -> str:
        """Return the directory for template tid."""
        # One directory per template id.
        return os.path.join(self.root, tid)

    def _persist(self, tid: str) -> None:
        """Write the record for tid to meta.json atomically (temp file, then replace)."""
        # Unknown id: nothing to write.
        rec = self._index.get(tid)
        if rec is None:
            return
        # Make sure the directory exists.
        d = self._dir(tid)
        os.makedirs(d, exist_ok=True)
        # Write a temp file, then rename it over meta.json.
        tmp = os.path.join(d, "meta.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        os.replace(tmp, os.path.join(d, "meta.json"))

    def image_path(self, tid: str) -> str:
        """Return the path of the archive file for template tid."""
        # Stored filename, or the default.
        rec = self._index.get(tid) or {}
        return os.path.join(self._dir(tid), rec.get("filename") or "image.vma.zst")

    # ── views ───────────────────────────────────────────────────────────────
    @staticmethod
    def _public(rec: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of rec without the private token keys."""
        # Drop the private keys.
        return {k: v for k, v in rec.items() if k not in _PRIVATE_KEYS}

    def get(self, tid: str, *, public: bool = True) -> Optional[Dict[str, Any]]:
        """Return the record for tid (public view unless public=False), or None."""
        # Look up under the lock.
        with self._lock:
            rec = self._index.get(tid)
            if rec is None:
                return None
            # Public view or a full copy.
            return self._public(rec) if public else dict(rec)

    def list(self) -> List[Dict[str, Any]]:
        """Return public views of all records, newest first."""
        # Sort by created_at descending, under the lock.
        with self._lock:
            return sorted((self._public(r) for r in self._index.values()),
                          key=lambda r: r.get("created_at") or "", reverse=True)

    # ── lifecycle ───────────────────────────────────────────────────────────
    def create_pending(self, *, name: str, source_vmid: Any, source_node: str,
                        source_agent: str, source_spoke: str, created_by: str,
                        tenant: str = "", tenant_id: str = "") -> Dict[str, Any]:
        """Register a pending template + one-time upload token. Returns the FULL
        record (including the token) so the caller can hand it to the agent."""
        # Create the record under the lock.
        with self._lock:
            # New id and the initial record, including the upload token.
            tid = uuid.uuid4().hex
            rec: Dict[str, Any] = {
                "id": tid,
                "name": str(name or f"vmid-{source_vmid}"),
                "source_vmid": source_vmid,
                "source_node": str(source_node or ""),
                "source_agent": str(source_agent or ""),
                "source_spoke": str(source_spoke or ""),
                "filename": "image.vma.zst",
                "size": 0,
                "sha256": "",
                "status": "pending",   # pending → uploading → complete | failed
                "error": "",
                "progress": 0,
                "created_at": _now(),
                "created_by": str(created_by or ""),
                "updated_at": _now(),
                # operator-editable metadata
                "version": "",
                "os": "",
                "purpose": "",
                # tenant — DERIVED from the source PXMX host (authoritative, not
                # editable). tenant = display name, tenant_id = stable id.
                "tenant": str(tenant or ""),
                "tenant_id": str(tenant_id or ""),
                # private
                "_upload_token": uuid.uuid4().hex,
            }
            # Make its directory, index it, persist it, and return a copy.
            os.makedirs(self._dir(tid), exist_ok=True)
            self._index[tid] = rec
            self._persist(tid)
            return dict(rec)

    def verify_token(self, tid: str, token: str) -> bool:
        """Return True if token matches the upload token for tid."""
        # Needs a record, a non-empty token, and a match.
        with self._lock:
            rec = self._index.get(tid)
            return bool(rec) and bool(token) and rec.get("_upload_token") == token

    def set_status(self, tid: str, status: str, *, error: str = "",
                   progress: Optional[int] = None) -> None:
        """Set the status for tid (plus error and progress when given) and persist it."""
        # Unknown id: nothing to update.
        with self._lock:
            rec = self._index.get(tid)
            if not rec:
                return
            # Status and timestamp.
            rec["status"] = status
            rec["updated_at"] = _now()
            # Error, truncated to 500 characters.
            if error:
                rec["error"] = str(error)[:500]
            # Progress clamped to 0..100; invalid values are ignored.
            if progress is not None:
                try:
                    rec["progress"] = max(0, min(100, int(progress)))
                except (TypeError, ValueError):
                    pass
            # Save it.
            self._persist(tid)

    def finalize(self, tid: str, *, size: int, sha256: str) -> None:
        """Mark an upload complete and CONSUME the one-time token."""
        # Unknown id: nothing to do.
        with self._lock:
            rec = self._index.get(tid)
            if not rec:
                return
            # Mark complete with size and hash, drop the token, and persist.
            rec.update(size=int(size), sha256=str(sha256), status="complete",
                       progress=100, error="", updated_at=_now())
            rec.pop("_upload_token", None)
            self._persist(tid)

    # ── refresh (restore to a host) ─────────────────────────────────────────
    def mint_refresh_token(self, tid: str) -> Optional[str]:
        """Mint a fresh token the target agent presents to DOWNLOAD the archive
        during a refresh. Not one-time (a resumed download may re-GET); a new
        refresh overwrites it. Returns None if the template isn't complete."""
        # Local uuid import.
        import uuid as _uuid
        # Only complete templates get a token.
        with self._lock:
            rec = self._index.get(tid)
            if rec is None or rec.get("status") != "complete":
                return None
            # New token, saved on the record.
            tok = _uuid.uuid4().hex
            rec["_refresh_token"] = tok
            self._persist(tid)
            return tok

    def verify_refresh_token(self, tid: str, token: str) -> bool:
        """Return True if token matches the refresh token for tid."""
        # Needs a record, a non-empty token, and a match.
        with self._lock:
            rec = self._index.get(tid)
            return bool(rec) and bool(token) and rec.get("_refresh_token") == token

    def set_refresh_status(self, tid: str, status: str, *, step: str = "",
                           error: str = "") -> None:
        """Track a refresh in progress on the record so the WebUI can show
        'killing VMs…', 'restoring…', etc. (status = pending/pausing/killing/
        downloading/restoring/resuming/complete/failed)."""
        # Unknown id: nothing to update.
        with self._lock:
            rec = self._index.get(tid)
            if not rec:
                return
            # Refresh fields and timestamp, then persist.
            rec["refresh_status"] = status
            rec["refresh_step"] = step
            rec["refresh_error"] = str(error)[:500] if error else ""
            rec["refresh_updated_at"] = _now()
            self._persist(tid)

    def update_meta(self, tid: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Apply the editable fields for tid, persist, and return the public view (None if unknown)."""
        # Unknown id: return None.
        with self._lock:
            rec = self._index.get(tid)
            if rec is None:
                return None
            # Copy only editable fields, as strings.
            for k, v in (fields or {}).items():
                if k in _EDITABLE:
                    rec[k] = "" if v is None else str(v)
            # Stamp, save, and return the public view.
            rec["updated_at"] = _now()
            self._persist(tid)
            return self._public(rec)

    def delete(self, tid: str) -> bool:
        """Remove template tid from the index and delete its directory; False if unknown."""
        # Remove from the index under the lock.
        with self._lock:
            rec = self._index.pop(tid, None)
            if rec is None:
                return False
        # Delete the files outside the lock.
        shutil.rmtree(self._dir(tid), ignore_errors=True)
        return True
