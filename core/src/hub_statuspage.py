"""Public status-page role support for the LM Hub — ``StatusPageMixin``.

Pure textual extraction from ``main.py``: the `statuspage` sub-spoke snapshot
builder + push loop mixed into ``LabManagerHub``. Every method uses only
``self`` state and cross-mixin ``self`` calls (get_client_sim_spoke,
request_response, ...); ``simulations.service`` helpers are imported locally in
the methods exactly as before. No behavior change — ``LabManagerHub`` inherits
these unchanged.
"""

# asyncio paces the periodic snapshot push loop.
import asyncio
# time stamps snapshots and computes last-seen ages and demo expiries.
import time
# logging reports push/snapshot problems (debug level; never fatal).
import logging
# Type hints for the snapshot dictionaries and lists.
from typing import Any, Dict, List

# Share the hub's logger so these messages appear with other hub logs.
logger = logging.getLogger("Hub")


class StatusPageMixin:
    """`statuspage` role support (public per-tenant status page) for the Hub."""

    # A `statuspage` sub-spoke is a thin public presenter bound to ONE tenant. It
    # holds no tenant authority and no Central creds: the hub resolves the bound
    # tenant, builds a REDACTED snapshot, and pushes it down (STATUS_SNAPSHOT);
    # public demo clicks come back up as STATUS_RUN_DEMO and are tenant-forced here.

    def _statuspage_spokes(self) -> List[str]:
        """Connected `statuspage` role sub-spokes."""
        # Keep spokes registered as "statuspage" that are connected right now.
        return [sid for sid, mt in self.spoke_module_types.items()
                if mt == "statuspage" and sid in self.active_connections]

    @staticmethod
    def _status_tone(status: Any) -> str:
        """Map a check status bucket to the public page's three tones. The hub
        poller has ALREADY applied the inverted-error semantics (ok = expected
        error present), so we just bucket: pass→operational, fail→down, else
        degraded."""
        # Pull out the status string whether given a dict or a bare value.
        from simulations.service import _PASS, _FAIL  # local: avoid import cycle
        s = str((status.get("status") if isinstance(status, dict) else status) or "").lower()
        # Passing checks render as operational, failing as down, anything else as degraded.
        if s in _PASS:
            return "operational"
        if s in _FAIL:
            return "down"
        return "degraded"

    @staticmethod
    def _status_last_seen_secs(val: Any) -> Any:
        """Best-effort seconds-since-last-seen from a client row's last_seen
        (epoch number, numeric string, or ISO-8601). None when unparseable — the
        page shows a dash rather than a wrong number."""
        # Missing or placeholder values have no meaningful age.
        if val is None or val == "—" or val == "":
            return None
        # Reference "now" once for every branch below.
        now = time.time()
        try:
            # Epoch seconds as a number.
            if isinstance(val, (int, float)):
                return max(0, int(now - float(val)))
            # Epoch seconds as a numeric string.
            sval = str(val).strip()
            if sval.replace(".", "", 1).isdigit():
                return max(0, int(now - float(sval)))
            # Otherwise treat it as an ISO-8601 timestamp ("Z" mapped to UTC offset for Python).
            from datetime import datetime
            dt = datetime.fromisoformat(sval.replace("Z", "+00:00"))
            return max(0, int(now - dt.timestamp()))
        except Exception:  # noqa: BLE001
            # Unparseable value: show a dash instead of a wrong number.
            return None

    # Static demo scenario catalog (mirrors routes.cs_demo_scenarios fallback +
    # cs/lm-spoke demo_scenarios.build_scenarios). Used so the push loop doesn't
    # do an extra spoke round-trip just to populate the demo dropdown.
    # Fault flags a demo scenario can turn on; each maps to one scenario.
    _STATUS_DEMO_FLAGS = ("dns_fail", "dhcp_fail", "assoc_fail", "auth_fail",
                          "ssidpw_fail", "mac_auth_fail", "port_flap")

    def _status_scenarios(self) -> Dict[str, Any]:
        """Build the demo scenario catalog: "normal" plus one scenario per fault flag."""
        # "normal" turns every flag off.
        canon = {"normal": {f: "off" for f in self._STATUS_DEMO_FLAGS}}
        # Each other scenario turns on exactly its own flag.
        for f in self._STATUS_DEMO_FLAGS:
            canon[f] = {x: ("on" if x == f else "off") for x in self._STATUS_DEMO_FLAGS}
        return canon

    def _status_client_hostnames(self, tenant_id: str) -> set:
        """The hostnames the tenant's cached clients present — the allowlist a
        public demo trigger is validated against (defense in depth)."""
        # Use the simulations service to find the tenant's spokes and cached clients.
        from simulations.service import SimulationsService
        svc = SimulationsService(self)
        hosts = set()
        # Collect each client's hostname (or id) from every spoke serving the tenant.
        for _sid, data in svc._spokes_for_tenant(tenant_id):
            for c in (data.get("clients") or []):
                h = (c or {}).get("hostname") or (c or {}).get("id")
                if h:
                    hosts.add(str(h))
        return hosts

    async def _build_status_snapshot(self, tenant_id: str) -> Dict[str, Any]:
        """Build the REDACTED, tenant-scoped snapshot pushed to a statuspage
        sub-spoke. Surfaces ONLY: tenant display name, per-check component
        statuses (real site/check names), client name/status/last-seen, and the
        demo catalog. Strips spoke ids/names/hostnames, VM/client internal ids,
        raw client counts, site_mappings, and all Central creds — none of that is
        assembled into the returned dict."""
        # Simulations service gives access to the tenant's spokes and client data.
        from simulations.service import SimulationsService
        svc = SimulationsService(self)

        # Tenant display name.
        # Default the display name to the id, then try the tenant record's friendly name.
        tenant_name = tenant_id
        try:
            trec = self.state.get_tenant(tenant_id) if hasattr(self.state, "get_tenant") else None
            if trec:
                tenant_name = trec.get("name") or tenant_id
        except Exception:  # noqa: BLE001
            # Tenant lookup failure just keeps the id as the name.
            pass

        # Collect the raw central status maps: centralized hub poller + any
        # distributed spokes' own central blocks. {site: {check: {status,message}}}
        # Hub-side poller result for this tenant, if any.
        status_maps: List[Dict[str, Any]] = []
        hub_central = (getattr(self, "central_hub_status", {}) or {}).get(tenant_id)
        if hub_central is not None:
            status_maps.append(hub_central.get("status") or {})
        # Plus any status block reported directly by the tenant's spokes.
        for _sid, data in svc._spokes_for_tenant(tenant_id):
            cst = (data.get("central") or {}).get("status") or {}
            if cst:
                status_maps.append(cst)

        # Per-check components (each monitored check = a status-page component).
        # Severity order so the overall status is the worst component status.
        _RANK = {"operational": 0, "degraded": 1, "down": 2}
        overall = "operational"
        components: List[Dict[str, Any]] = []
        # Walk every site and check in every status map.
        for smap in status_maps:
            for site, checks_map in (smap or {}).items():
                site_s = str(site or "")
                # Prefix check names with the site only when there are real per-site entries.
                multi = site_s and site_s.lower() not in ("all", "all sites", "")
                for chk, info in (checks_map or {}).items():
                    # Map the check result to a tone and keep its message as detail.
                    tone = self._status_tone(info)
                    detail = ""
                    if isinstance(info, dict):
                        detail = str(info.get("message") or "")
                    name = f"{site_s} · {chk}" if multi else str(chk)
                    components.append({"name": name, "status": tone, "detail": detail})
                    # Escalate the overall status if this component is worse.
                    if _RANK[tone] > _RANK[overall]:
                        overall = tone
        # No checks at all means the status is unknown, not operational.
        if not components:
            overall = "unknown"

        # Clients (for the demo view) — redacted to name/status/last-seen.
        clients: List[Dict[str, Any]] = []
        try:
            # Fetch client data and keep only redacted name/status/last-seen fields.
            cdata = await svc.get_clients_data(tenant_id)
            for c in (cdata.get("clients") if isinstance(cdata, dict) else cdata) or []:
                clients.append({
                    "name": c.get("hostname") or "",
                    "hostname": c.get("hostname") or "",
                    "status": "up" if c.get("online") else "down",
                    "last_seen_secs": self._status_last_seen_secs(c.get("last_seen")),
                })
        except Exception as e:  # noqa: BLE001
            # Client data is optional; the page still renders without it.
            logger.debug("status snapshot clients failed for %s: %s", tenant_id, e)

        # Active demos (scenario + expiry) — one best-effort round-trip so the
        # public page can show ⚡ + a countdown on running clients.
        try:
            # Ask the tenant's Client-Sim spoke which demos are currently running.
            sid = self.get_client_sim_spoke(tenant_id) if hasattr(self, "get_client_sim_spoke") else None
            if sid:
                res = await self.request_response(sid, "CS_GET_DEMO_ACTIVE", {}, timeout=8.0)
                # Unwrap the response envelope to the data dict.
                adata = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
                by_host = {}
                # Index active demos by hostname, deriving expiry or remaining time from the other.
                for a in (adata.get("active") if isinstance(adata, dict) else []) or []:
                    h = a.get("hostname")
                    if not h:
                        continue
                    exp_at = a.get("expires_at")
                    rem = a.get("remaining")
                    if exp_at is None and rem is not None:
                        exp_at = time.time() + float(rem)
                    if rem is None and exp_at is not None:
                        rem = max(0, float(exp_at) - time.time())
                    by_host[str(h)] = {"scenario": a.get("scenario") or "",
                                       "expires_at": exp_at, "expires_in": rem}
                # Attach the active demo info to the matching client rows.
                for cl in clients:
                    if cl["hostname"] in by_host:
                        cl["demo_active"] = by_host[cl["hostname"]]
        except Exception as e:  # noqa: BLE001
            # Demo status is optional; ignore failures.
            logger.debug("status snapshot demo-active failed for %s: %s", tenant_id, e)

        # One-time-per-tenant shape log so a fresh deploy can confirm the snapshot
        # populated correctly (component/client counts, how many last_seen values
        # parsed to minutes-ago, how many clients have a resolved active demo) —
        # then it goes quiet so the 15s push loop doesn't spam. Samples one
        # component + one client so the field shapes are visible in the hub log.
        try:
            # Lazily create the set of tenants already logged.
            logged = getattr(self, "_status_snap_logged", None)
            if logged is None:
                logged = self._status_snap_logged = set()
            # Log only the first snapshot per tenant.
            if tenant_id not in logged:
                logged.add(tenant_id)
                ls_parsed = sum(1 for c in clients if c.get("last_seen_secs") is not None)
                demos = sum(1 for c in clients if c.get("demo_active"))
                logger.info(
                    "STATUS_SNAPSHOT[%s] overall=%s components=%d clients=%d "
                    "last_seen_parsed=%d/%d demo_active=%d sample_component=%s "
                    "sample_client=%s",
                    tenant_id, overall, len(components), len(clients),
                    ls_parsed, len(clients), demos,
                    (components[0] if components else None),
                    ({k: clients[0].get(k) for k in ("name", "status", "last_seen_secs", "demo_active")}
                     if clients else None))
        except Exception:  # noqa: BLE001 — logging must never break the snapshot
            # Logging failure must never break the snapshot.
            pass

        # The redacted snapshot pushed to the public page.
        return {
            "tenant_name": tenant_name,
            "overall": overall,
            "components": components,
            "clients": clients,
            "scenarios": self._status_scenarios(),
            "generated_at": int(time.time()),
        }

    async def _handle_status_run_demo(self, spoke_id: str, data: Dict[str, Any]) -> None:
        """Handle a public demo trigger relayed up by a statuspage sub-spoke.
        Tenant is forced from the sub-spoke binding (never the payload); the
        client is validated against that tenant before the cs relay fires."""
        # Tenant always comes from the sub-spoke's binding, never the request payload.
        try:
            tenant_id = self.state.get_spoke_tenant(self._primary_key(spoke_id))
        except Exception:  # noqa: BLE001
            # No binding resolvable: treat as unbound.
            tenant_id = None
        # Refuse demo triggers from an unbound status page.
        if not tenant_id:
            logger.warning("STATUS_RUN_DEMO from %s: no tenant binding — dropping", spoke_id)
            return
        # Read and trim the requested client and scenario.
        hostname = str((data or {}).get("hostname") or "").strip()
        scenario = str((data or {}).get("scenario") or "").strip()
        # Both are required.
        if not hostname or not scenario:
            return
        # Only allow clients that actually belong to this tenant.
        if hostname not in self._status_client_hostnames(tenant_id):
            logger.warning("STATUS_RUN_DEMO from %s: client %r not in tenant %s — refusing",
                           spoke_id, hostname, tenant_id)
            return
        # Find the Client-Sim spoke that runs the demo.
        sid = self.get_client_sim_spoke(tenant_id) if hasattr(self, "get_client_sim_spoke") else None
        if not sid:
            logger.info("STATUS_RUN_DEMO: no Client-Sim spoke for tenant %s", tenant_id)
            return
        # Relay the demo request to the Client-Sim spoke.
        try:
            await self.request_response(sid, "CS_DEMO_SCENARIO",
                                        {"hostname": hostname, "scenario": scenario,
                                         "triggered_by": "public-status"}, timeout=15.0)
            logger.info("Public status demo: tenant=%s client=%s scenario=%s",
                        tenant_id, hostname, scenario)
        except Exception as e:  # noqa: BLE001
            # Relay failure is only logged; the public page has no way to retry anyway.
            logger.debug("STATUS_RUN_DEMO cs relay failed: %s", e)

    async def run_statuspage_push_loop(self):
        """Push a redacted per-tenant snapshot to each connected statuspage
        sub-spoke every ~15s. Best-effort + never fatal."""
        await asyncio.sleep(15)  # let spokes connect + telemetry warm
        # Run forever; each cycle pushes one snapshot to every status page spoke.
        while True:
            try:
                # Push to each connected statuspage sub-spoke.
                for sid in self._statuspage_spokes():
                    # Find the tenant this sub-spoke is bound to; skip unbound ones.
                    try:
                        tenant_id = self.state.get_spoke_tenant(sid)
                    except Exception:  # noqa: BLE001
                        tenant_id = None
                    if not tenant_id:
                        continue
                    # Build and push the snapshot; a failure only affects this spoke.
                    try:
                        snap = await self._build_status_snapshot(tenant_id)
                        await self.request_response(sid, "STATUS_SNAPSHOT", snap, timeout=10.0)
                    except Exception as e:  # noqa: BLE001
                        logger.debug("statuspage push to %s failed: %s", sid, e)
            except Exception as e:  # noqa: BLE001 — never fatal
                # Any cycle-level failure is logged and the loop continues.
                logger.debug("statuspage push loop cycle failed: %s", e)
            # Wait before the next push cycle.
            await asyncio.sleep(15)
