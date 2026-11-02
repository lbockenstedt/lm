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

import json
import os
import shutil
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Keys never exposed in the public (WebUI/API) view of a record.
_PRIVATE_KEYS = {"_upload_token", "_refresh_token"}
# Metadata fields an operator may edit after upload. ``tenant`` is NOT here — it
# is DERIVED from the source PXMX host's tenant binding at backup time and is
# authoritative (the repo is tenant-driven, per host), so it can't be re-typed.
_EDITABLE = {"version", "os", "purpose", "name"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TemplateRepo:
    def __init__(self, data_dir: str):
        self.root = os.path.join(data_dir, "template-repo")
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.RLock()
        self._index: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ── persistence ─────────────────────────────────────────────────────────
    def _load(self) -> None:
        for name in os.listdir(self.root):
            mp = os.path.join(self.root, name, "meta.json")
            if os.path.isfile(mp):
                try:
                    with open(mp, encoding="utf-8") as f:
                        rec = json.load(f)
                    if isinstance(rec, dict) and rec.get("id"):
                        self._index[rec["id"]] = rec
                except Exception:
                    pass

    def _dir(self, tid: str) -> str:
        return os.path.join(self.root, tid)

    def _persist(self, tid: str) -> None:
        rec = self._index.get(tid)
        if rec is None:
            return
        d = self._dir(tid)
        os.makedirs(d, exist_ok=True)
        tmp = os.path.join(d, "meta.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        os.replace(tmp, os.path.join(d, "meta.json"))

    def image_path(self, tid: str) -> str:
        rec = self._index.get(tid) or {}
        return os.path.join(self._dir(tid), rec.get("filename") or "image.vma.zst")

    # ── views ───────────────────────────────────────────────────────────────
    @staticmethod
    def _public(rec: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in rec.items() if k not in _PRIVATE_KEYS}

    def get(self, tid: str, *, public: bool = True) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._index.get(tid)
            if rec is None:
                return None
            return self._public(rec) if public else dict(rec)

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted((self._public(r) for r in self._index.values()),
                          key=lambda r: r.get("created_at") or "", reverse=True)

    # ── lifecycle ───────────────────────────────────────────────────────────
    def create_pending(self, *, name: str, source_vmid: Any, source_node: str,
                        source_agent: str, source_spoke: str, created_by: str,
                        tenant: str = "", tenant_id: str = "") -> Dict[str, Any]:
        """Register a pending template + one-time upload token. Returns the FULL
        record (including the token) so the caller can hand it to the agent."""
        with self._lock:
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
            os.makedirs(self._dir(tid), exist_ok=True)
            self._index[tid] = rec
            self._persist(tid)
            return dict(rec)

    def verify_token(self, tid: str, token: str) -> bool:
        with self._lock:
            rec = self._index.get(tid)
            return bool(rec) and bool(token) and rec.get("_upload_token") == token

    def set_status(self, tid: str, status: str, *, error: str = "",
                   progress: Optional[int] = None) -> None:
        with self._lock:
            rec = self._index.get(tid)
            if not rec:
                return
            rec["status"] = status
            rec["updated_at"] = _now()
            if error:
                rec["error"] = str(error)[:500]
            if progress is not None:
                try:
                    rec["progress"] = max(0, min(100, int(progress)))
                except (TypeError, ValueError):
                    pass
            self._persist(tid)

    def finalize(self, tid: str, *, size: int, sha256: str) -> None:
        """Mark an upload complete and CONSUME the one-time token."""
        with self._lock:
            rec = self._index.get(tid)
            if not rec:
                return
            rec.update(size=int(size), sha256=str(sha256), status="complete",
                       progress=100, error="", updated_at=_now())
            rec.pop("_upload_token", None)
            self._persist(tid)

    # ── refresh (restore to a host) ─────────────────────────────────────────
    def mint_refresh_token(self, tid: str) -> Optional[str]:
        """Mint a fresh token the target agent presents to DOWNLOAD the archive
        during a refresh. Not one-time (a resumed download may re-GET); a new
        refresh overwrites it. Returns None if the template isn't complete."""
        import uuid as _uuid
        with self._lock:
            rec = self._index.get(tid)
            if rec is None or rec.get("status") != "complete":
                return None
            tok = _uuid.uuid4().hex
            rec["_refresh_token"] = tok
            self._persist(tid)
            return tok

    def verify_refresh_token(self, tid: str, token: str) -> bool:
        with self._lock:
            rec = self._index.get(tid)
            return bool(rec) and bool(token) and rec.get("_refresh_token") == token

    def set_refresh_status(self, tid: str, status: str, *, step: str = "",
                           error: str = "") -> None:
        """Track a refresh in progress on the record so the WebUI can show
        'killing VMs…', 'restoring…', etc. (status = pending/pausing/killing/
        downloading/restoring/resuming/complete/failed)."""
        with self._lock:
            rec = self._index.get(tid)
            if not rec:
                return
            rec["refresh_status"] = status
            rec["refresh_step"] = step
            rec["refresh_error"] = str(error)[:500] if error else ""
            rec["refresh_updated_at"] = _now()
            self._persist(tid)

    def update_meta(self, tid: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._index.get(tid)
            if rec is None:
                return None
            for k, v in (fields or {}).items():
                if k in _EDITABLE:
                    rec[k] = "" if v is None else str(v)
            rec["updated_at"] = _now()
            self._persist(tid)
            return self._public(rec)

    def delete(self, tid: str) -> bool:
        with self._lock:
            rec = self._index.pop(tid, None)
            if rec is None:
                return False
        shutil.rmtree(self._dir(tid), ignore_errors=True)
        return True
