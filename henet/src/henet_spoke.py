"""HE.NET spoke: Lab Manager module for public DNS records hosted at dns.he.net.

Translates Hub HENET_* commands into calls on HENetManager, running each blocking call
in a worker thread so the shared event loop stays responsive.
"""
# asyncio.to_thread runs the blocking manager calls off the event loop.
import asyncio
# Standard-library logging (logger defined below).
import logging
# Type hints only; they document the shape of command payloads and results.
from typing import Any, Dict

# BaseSpoke lives at a different import path in deployed vs source-tree layouts.
try:
    from base_spoke import BaseSpoke
# Source-tree layout: import it through the core package.
except ImportError:
    from core.src.base_spoke import BaseSpoke

# Import the manager directly when this directory is on sys.path.
try:
    from henet_manager import HENetManager
except ImportError:  # loaded as a package (src.X) by a sibling entrypoint
    from src.henet_manager import HENetManager

# One named logger so all HE.NET spoke messages can be filtered together.
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
        """Set up the spoke and its record manager.

        Args:
            spoke_id: Identifier of this spoke as known to the Hub.
            config: Module settings; henet_state is the path of the local record state file.
        """
        # Let BaseSpoke store the id/config and do its common setup.
        super().__init__(spoke_id, config)
        # Where managed records are persisted locally (default under /etc/lm-henet).
        state_path = config.get("henet_state", "/etc/lm-henet/records.json")
        # The manager does the real work: state file I/O and HE dyndns pushes.
        self.mgr = HENetManager(state_path=state_path)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the HE.NET manager.

        Every manager call is offloaded via ``asyncio.to_thread``: the HE dyndns
        push is a synchronous HTTP round-trip and this spoke may share one event
        loop with sibling sub-spokes, so a slow HE response must not block it."""
        # Upper-case the command so matching below is case-insensitive.
        cmd = command_type.upper()

        # Hub asked which version of this module is installed.
        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # Return every record currently under local management.
        if cmd == "HENET_LIST":
            records = await asyncio.to_thread(self.mgr.list_records)
            return {"status": "SUCCESS", "records": records}

        # Replace the whole managed set and push each record, using the vault-supplied key.
        if cmd == "HENET_SYNC":
            records = data.get("records", [])
            ddns_key = data.get("ddns_key", "")
            return await asyncio.to_thread(self.mgr.sync, records, ddns_key)

        # Add or re-push one record; name and value are mandatory, TTL defaults to 300 s.
        if cmd in ("HENET_ADD", "HENET_UPDATE"):
            name = data.get("name")
            rtype = data.get("type", "A")
            value = data.get("value")
            ttl = int(data.get("ttl", 300))
            # Reject requests missing the record name or IP value.
            if not name or not value:
                return {"status": "ERROR", "message": "name and value are required"}
            # Pick update vs add, then call it with the shared DDNS key, optional per-record key
            # and owning tenant.
            fn = self.mgr.update_record if cmd == "HENET_UPDATE" else self.mgr.add_record
            return await asyncio.to_thread(
                fn, name, rtype, value, ttl, data.get("ddns_key", ""), data.get("key", ""),
                data.get("tenant_id", ""))

        # Stop managing a record (the HE zone itself is left untouched).
        if cmd == "HENET_DELETE":
            name = data.get("name")
            rtype = data.get("type")
            # Reject requests without a record name.
            if not name:
                return {"status": "ERROR", "message": "name is required"}
            return await asyncio.to_thread(self.mgr.delete_record, name, rtype)

        # Change which tenant owns a managed record.
        if cmd == "HENET_SET_TENANT":
            name = data.get("name")
            # Reject requests without a record name.
            if not name:
                return {"status": "ERROR", "message": "name is required"}
            return await asyncio.to_thread(
                self.mgr.set_tenant, name, data.get("type"), data.get("tenant_id", ""))

        # Merge records the Hub scraped from the HE zone into local management (no push).
        if cmd == "HENET_IMPORT":
            records = data.get("records", [])
            # Guard against a malformed payload before handing it to the manager.
            if not isinstance(records, list):
                return {"status": "ERROR", "message": "records must be a list"}
            return await asyncio.to_thread(self.mgr.import_records, records)

        # Record writes that the Hub performed through the HE web UI so local state matches.
        if cmd == "HENET_WEB_RECORD":
            records = data.get("records", [])
            # Guard against a malformed payload before handing it to the manager.
            if not isinstance(records, list):
                return {"status": "ERROR", "message": "records must be a list"}
            return await asyncio.to_thread(self.mgr.record_web_writes, records)

        # Report HE dyndns reachability and record count.
        if cmd == "HENET_STATUS":
            s = await asyncio.to_thread(self.mgr.status)
            return {"status": "SUCCESS", **s}

        # Any other command is not something this module understands.
        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        """Return a health summary for the Hub dashboard (DEGRADED if HE is unreachable)."""
        # Ask the manager for reachability and record count, then shape it for the Hub.
        s = await asyncio.to_thread(self.mgr.status)
        return {
            "spoke_id":     self.spoke_id,
            "module":       "henet",
            "he_dyndns":    "reachable" if s["reachable"] else "unreachable",
            "record_count": s["record_count"],
            "status":       "HEALTHY" if s["reachable"] else "DEGRADED",
        }

    def get_version(self) -> str:
        """Return this module's version from its VERSION file, or "unknown"."""
        # pathlib is imported lazily because only this method needs it.
        from pathlib import Path
        # Read the VERSION file two directories up; a missing/unreadable file is not fatal.
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        # No VERSION file (e.g. dev checkout): report "unknown" instead of failing.
        except Exception:
            return "unknown"
