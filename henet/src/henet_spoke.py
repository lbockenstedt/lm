import asyncio
import logging
from typing import Any, Dict

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from henet_manager import HENetManager
except ImportError:  # loaded as a package (src.X) by a sibling entrypoint
    from src.henet_manager import HENetManager

logger = logging.getLogger("HENetSpoke")


class HENetSpoke(BaseSpoke):
    """
    Hurricane Electric (dns.he.net) public-DNS spoke.

    The public-address-space analogue of the Unbound DNS spoke: it manages
    A/AAAA records in a Hurricane Electric free-DNS zone over HE's dynamic-DNS
    update API. The HE **DDNS key** is a secret and is NEVER stored here — the
    hub resolves it from the Credential Vault and injects it into each write
    command as ``ddns_key`` (or a per-record ``key``), mirroring how the LE
    module receives a vault-resolved ``dns_vault_credential``.

    Commands:
      GET_VERSION     — spoke/version string
      HENET_LIST      — return all managed records (from local state)
      HENET_SYNC      — replace the managed set + push each A/AAAA to HE
      HENET_ADD       — upsert a single record and push it
      HENET_UPDATE    — re-push an existing record with a new IP
      HENET_DELETE    — remove a record from local management (HE zone untouched)
      HENET_IMPORT    — merge existing zone A/AAAA records (scraped by the hub)
                        into local management without pushing them
      HENET_STATUS    — HE dyndns endpoint reachability + record count
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        state_path = config.get("henet_state", "/etc/lm-henet/records.json")
        self.mgr = HENetManager(state_path=state_path)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the HE.NET manager.

        Every manager call is offloaded via ``asyncio.to_thread``: the HE dyndns
        push is a synchronous HTTP round-trip and this spoke may share one event
        loop with sibling sub-spokes, so a slow HE response must not block it."""
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "HENET_LIST":
            records = await asyncio.to_thread(self.mgr.list_records)
            return {"status": "SUCCESS", "records": records}

        if cmd == "HENET_SYNC":
            records = data.get("records", [])
            ddns_key = data.get("ddns_key", "")
            return await asyncio.to_thread(self.mgr.sync, records, ddns_key)

        if cmd in ("HENET_ADD", "HENET_UPDATE"):
            name = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl = int(data.get("ttl", 300))
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            fn = self.mgr.update_record if cmd == "HENET_UPDATE" else self.mgr.add_record
            return await asyncio.to_thread(
                fn, name, rtype, value, ttl, data.get("ddns_key", ""), data.get("key", ""))

        if cmd == "HENET_DELETE":
            name = data.get("name")
            rtype = data.get("type")
            if not name:
                return {"status": "ERROR", "message": "name is required"}
            return await asyncio.to_thread(self.mgr.delete_record, name, rtype)

        if cmd == "HENET_IMPORT":
            records = data.get("records", [])
            if not isinstance(records, list):
                return {"status": "ERROR", "message": "records must be a list"}
            return await asyncio.to_thread(self.mgr.import_records, records)

        if cmd == "HENET_STATUS":
            s = await asyncio.to_thread(self.mgr.status)
            return {"status": "SUCCESS", **s}

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        s = await asyncio.to_thread(self.mgr.status)
        return {
            "spoke_id":     self.spoke_id,
            "module":       "henet",
            "he_dyndns":    "reachable" if s["reachable"] else "unreachable",
            "record_count": s["record_count"],
            "status":       "HEALTHY" if s["reachable"] else "DEGRADED",
        }

    def get_version(self) -> str:
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
