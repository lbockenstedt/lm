"""Hurricane Electric (dns.he.net) public-DNS record manager for the henet spoke.

The public-address-space analogue of ``unbound_manager`` (the DNS module):
instead of writing records into a local Unbound conf and reloading, this pushes
A/AAAA records to Hurricane Electric's **free DNS** hosting over HE's officially
documented **dynamic-DNS update** protocol (``https://dyn.dns.he.net/nic/update``).

HE's dyndns endpoint authenticates each record with a per-record **DDNS key**
(the "Enable entry for dynamic DNS" key you generate in the dns.he.net UI). The
key is a SECRET and — exactly like the LE module's DNS-01 credentials — is NEVER
stored on this spoke. It lives in the hub-side **Credential Vault**; the hub
resolves it unattended (``cred_vault.automation_get``) and injects it into each
HENET_* command as ``ddns_key`` (or a per-record ``key``). This manager only ever
receives the key as a call argument for the duration of one push.

Because HE's dyndns endpoint has no "list" or "delete" verb, the set of records
this module manages is tracked in a small local JSON state file (the moral
equivalent of unbound's conf file) so the WebUI can list what's under management
and show each record's last push result. Deleting a record removes it from local
management (HE keeps the zone entry — dyndns cannot delete it).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("HENetManager")

DYN_UPDATE_URL = "https://dyn.dns.he.net/nic/update"
STATE_PATH = "/etc/lm-henet/records.json"

# HE dyndns response first-token → meaning. "good"/"nochg" are the two success
# tokens; everything else is an error we surface verbatim.
_OK_TOKENS = ("good", "nochg")


class HENetManager:
    """Manage HE.NET public A/AAAA records via the dyndns update API.

    ``http_post`` is injectable so unit tests can drive the manager without
    touching the network; it takes ``(url, form_dict)`` and returns HE's raw
    response body (str)."""

    def __init__(self, state_path: str = STATE_PATH,
                 http_post: Optional[Callable[[str, Dict[str, str]], str]] = None):
        self.state_path = state_path
        self._post = http_post or self._default_post
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────

    def list_records(self) -> List[Dict[str, Any]]:
        """The records this module currently manages (from local state)."""
        return self._load()

    def sync(self, records: List[Dict[str, Any]], ddns_key: str = "") -> Dict[str, Any]:
        """Replace the managed set with ``records`` and push every A/AAAA to HE.

        Each record: ``{"name","type","value","ttl"?, "key"?}``. A per-record
        ``key`` overrides the shared ``ddns_key``. Records are persisted with the
        outcome of their push so the UI can show what succeeded."""
        managed: List[Dict[str, Any]] = []
        pushed = 0
        errors: List[str] = []
        for r in records:
            entry = self._normalize(r)
            if not entry:
                continue
            ok, detail = self._push(entry, r.get("key") or ddns_key)
            entry["last_push_status"] = "ok" if ok else "error"
            entry["last_push_detail"] = detail
            entry["last_pushed_at"] = int(time.time())
            if ok:
                pushed += 1
            else:
                errors.append(f"{entry['name']}: {detail}")
            managed.append(entry)
        self._save(managed)
        logger.info("Synced %d HE.NET records (%d pushed, %d error)",
                    len(managed), pushed, len(errors))
        result = {"status": "SUCCESS", "records_written": len(managed), "pushed": pushed}
        if errors:
            result["status"] = "PARTIAL"
            result["errors"] = errors
        return result

    def add_record(self, name: str, rtype: str, value: str, ttl: int = 300,
                   ddns_key: str = "", key: str = "", tenant_id: str = "") -> Dict[str, Any]:
        existing = [r for r in self._load()
                    if not (r["name"] == name and r["type"] == rtype.upper())]
        existing.append({"name": name, "type": rtype, "value": value, "ttl": ttl,
                         "tenant_id": tenant_id,
                         **({"key": key} if key else {})})
        return self.sync(existing, ddns_key=ddns_key)

    def update_record(self, name: str, rtype: str, value: str, ttl: int = 300,
                      ddns_key: str = "", key: str = "", tenant_id: str = "") -> Dict[str, Any]:
        # Upsert semantics identical to add — HE dyndns "update" is just another
        # push of the new IP for the same hostname.
        return self.add_record(name, rtype, value, ttl, ddns_key=ddns_key, key=key, tenant_id=tenant_id)

    def import_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge externally-discovered A/AAAA records into local management
        WITHOUT pushing them to HE (they already exist in the zone).

        Used by the hub's "Import from HE.NET" action: the hub scrapes the
        dns.he.net web panel and hands the zone's existing A/AAAA records here so
        they become visible + manageable. A record LM already manages is left
        untouched (LM's copy — and its last-push status — wins); only records not
        already under management are added, tagged ``imported`` so the UI can
        show they came from the zone rather than a LM push."""
        managed = self._load()
        index = {(r.get("name"), str(r.get("type", "")).upper()) for r in managed}
        imported = 0
        skipped = 0
        for r in records:
            entry = self._normalize(r)
            if not entry:
                skipped += 1
                continue
            if entry["type"] not in ("A", "AAAA"):
                skipped += 1
                continue
            key = (entry["name"], entry["type"])
            if key in index:
                skipped += 1
                continue
            entry["last_push_status"] = "imported"
            entry["last_push_detail"] = "imported from HE.NET zone (not pushed by LM)"
            entry["last_pushed_at"] = None
            entry["source"] = "he-import"
            managed.append(entry)
            index.add(key)
            imported += 1
        self._save(managed)
        logger.info("Imported %d HE.NET record(s) into management (%d skipped)",
                    imported, skipped)
        return {"status": "SUCCESS", "imported": imported, "skipped": skipped,
                "records_written": len(managed)}

    def record_web_writes(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Upsert local management state to reflect writes the HUB already made
        via the HE.NET web panel (account-login path) — this NEVER pushes to HE
        itself (the hub did the write); it only records the outcome so the UI
        lists the record with its new value + status.

        Each item: ``{name, type, value, ttl?, tenant_id?, ok?, detail?}``. An
        existing record of the same name+type is replaced (its tenant is kept
        when the item doesn't set one, so a re-push doesn't silently un-home a
        tenant record)."""
        managed = self._load()
        by_key = {(r.get("name"), str(r.get("type", "")).upper()): r for r in managed}
        written = 0
        for r in records:
            entry = self._normalize(r)
            if not entry:
                continue
            key = (entry["name"], entry["type"])
            prior = by_key.get(key)
            if prior and not str(r.get("tenant_id") or "").strip():
                entry["tenant_id"] = prior.get("tenant_id", "") or ""
            ok = bool(r.get("ok", True))
            entry["last_push_status"] = "ok" if ok else "error"
            entry["last_push_detail"] = r.get("detail") or (
                "updated via HE.NET web panel" if ok else "HE.NET web update failed")
            entry["last_pushed_at"] = int(time.time())
            entry["source"] = "he-web"
            managed = [m for m in managed if (m.get("name"), str(m.get("type", "")).upper()) != key]
            managed.append(entry)
            by_key[key] = entry
            written += 1
        self._save(managed)
        logger.info("Recorded %d HE.NET web-panel write(s) into management", written)
        return {"status": "SUCCESS", "records_written": len(managed), "written": written}

    def set_tenant(self, name: str, rtype: Optional[str] = None,
                   tenant_id: str = "") -> Dict[str, Any]:
        """Re-home a managed record to a tenant WITHOUT pushing to HE.

        This is a METADATA-only change: the HE zone entry (and its last push
        result) is untouched — it only changes which tenant scope/tab owns the
        local record. Used by the hub's admin "move to tenant" action so records
        can be organised into per-tenant tabs even when the dyndns endpoint is
        unreachable (a push would need each record's own key and would error).
        ``rtype`` None matches every type for ``name``. ``tenant_id`` "" = move
        back to the Global/admin scope."""
        target = str(name).strip().rstrip(".")
        rt = rtype.upper() if rtype else None
        tid = str(tenant_id or "").strip()
        records = self._load()
        updated = 0
        for r in records:
            if r.get("name") == target and (rt is None or str(r.get("type", "")).upper() == rt):
                r["tenant_id"] = tid
                updated += 1
        self._save(records)
        logger.info("Re-homed %d HE.NET record(s) for %s to tenant %r",
                    updated, target, tid)
        return {"status": "SUCCESS", "updated": updated, "tenant_id": tid}

    def delete_record(self, name: str, rtype: Optional[str] = None) -> Dict[str, Any]:
        """Drop a record from LOCAL management. HE's dyndns API has no delete
        verb, so the zone entry itself remains at HE — remove it in the dns.he.net
        UI if you want it gone. Returns the pruned local record count."""
        rt = rtype.upper() if rtype else None
        kept = [r for r in self._load()
                if not (r["name"] == name and (rt is None or r["type"] == rt))]
        self._save(kept)
        return {"status": "SUCCESS", "records_written": len(kept),
                "note": "removed from local management (HE zone entry unchanged — "
                        "delete it in the dns.he.net UI if desired)"}

    def status(self) -> Dict[str, Any]:
        """Reachability of the HE dyndns endpoint + managed-record count.

        ``detail`` carries WHY the probe failed (transport/TLS/DNS error) so the
        operator can tell an egress/network block apart from an auth problem
        instead of an opaque "unreachable"."""
        reachable, detail = self._endpoint_reachable()
        return {
            "reachable": reachable,
            "record_count": len(self._load()),
            "endpoint": DYN_UPDATE_URL,
            "state_path": self.state_path,
            "detail": detail,
        }

    # ── Helpers ───────────────────────────────────────────────────────

    def _normalize(self, r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = str(r.get("name", "")).strip().rstrip(".")
        rtype = str(r.get("type", "A")).upper()
        value = str(r.get("value", "")).strip()
        try:
            ttl = int(r.get("ttl", 300))
        except (TypeError, ValueError):
            ttl = 300
        if not name or not value:
            return None
        # "" (unset/absent) = a Global-Admin-managed / shared record; any other
        # value is the owning tenant's id. Opaque here — the spoke has no
        # tenant concept of its own; the hub enforces ownership on writes and
        # filters a non-admin's /api/henet/records read to their own tenant.
        tenant_id = str(r.get("tenant_id") or "").strip()
        return {"name": name, "type": rtype, "value": value, "ttl": ttl, "tenant_id": tenant_id}

    def _push(self, entry: Dict[str, Any], key: str) -> tuple:
        """Push one A/AAAA record to HE dyndns. Returns ``(ok, detail)``."""
        rtype = entry["type"]
        if rtype not in ("A", "AAAA"):
            return (False, f"HE dyndns can only update A/AAAA records, not {rtype}")
        try:
            ipaddress.ip_address(entry["value"])
        except ValueError:
            return (False, f"{entry['value']!r} is not a valid IP address")
        if not key:
            return (False, "no DDNS key supplied (add an HE.NET credential to the "
                           "Credential Vault and select it)")
        form = {"hostname": entry["name"], "password": key, "myip": entry["value"]}
        try:
            body = (self._post(DYN_UPDATE_URL, form) or "").strip()
        except Exception as exc:  # noqa: BLE001 — network/transport
            logger.warning("HE.NET push failed for %s: %s", entry["name"], exc)
            return (False, f"request failed: {exc}")
        first = body.split()[0] if body else ""
        return (first in _OK_TOKENS, body or "empty response")

    def _endpoint_reachable(self) -> tuple:
        """``(reachable, detail)``. ``detail`` is "" on success, else the
        transport error string (surfaced by :meth:`status` for diagnostics)."""
        try:
            # A keyless GET returns HE's "badauth"/usage body — enough to prove
            # the endpoint is reachable without sending any credential.
            self._post(DYN_UPDATE_URL, {})
            return (True, "")
        except HTTPError as exc:
            # HE now answers a keyless/empty probe with an HTTP-level auth error
            # (401 Authorization Required) instead of a 200 "badauth" body. That
            # is still a response FROM the endpoint — it's reachable; only the
            # (absent) credential was rejected. Treating it as unreachable made
            # the status line read "HE dyndns unreachable (HTTP Error 401 …)"
            # even though the endpoint is fine. Any HTTP status = reachable;
            # only genuine transport failures below count as unreachable.
            logger.debug("henet: keyless probe returned HTTP %s (endpoint reachable)", exc.code)
            return (True, "")
        except Exception as exc:  # noqa: BLE001 — surface WHY, don't swallow it
            return (False, f"{type(exc).__name__}: {exc}")

    def _default_post(self, url: str, form: Dict[str, str]) -> str:
        data = urlencode(form).encode("utf-8")
        req = Request(url, data=data, method="POST",
                      headers={"User-Agent": "lm-henet/1.0"})
        with urlopen(req, timeout=10) as resp:  # noqa: S310 — fixed HE endpoint
            return resp.read().decode("utf-8", "replace")

    def _load(self) -> List[Dict[str, Any]]:
        try:
            with open(self.state_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except FileNotFoundError:
            return []
        except Exception as exc:  # noqa: BLE001 — corrupt state → start empty
            logger.warning("henet: could not read %s: %s", self.state_path, exc)
            return []

    def _save(self, records: List[Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        os.replace(tmp, self.state_path)
