"""Realtime alert engine — edge-triggered per-tenant alert routing.

Rather than hook every monitored subsystem, a periodic loop (``run_alert_loop``,
started from main.py) evaluates each tenant's alert-eligible sources every ~60s
and fires ONE email on a transition into a bad state and ONE on recovery
(edge-triggered via ``_state``) — a still-bad item stays silent.

Sources (matched against ``store.get_alert_rules``):
  * ``dashboard_check`` — a monitored dashboard CHECK is warning/error.
  * ``vm_offline``      — a hypervisor/simulation spoke or agent is out of contact.
  * ``spoke_offline``   — any OTHER spoke/agent is out of contact.
  * ``quota_unmet``     — a site's client-count check is ERROR (the sim client
                          requirement isn't being met).

Emails route through the same provider-aware ``notifications.send_email`` the hub
alerts + scheduled reports use. State is in-memory: after a restart a still-bad
item re-alerts once (arguably useful — confirms it's still down).
"""
import asyncio
import logging
from typing import Any, Dict

logger = logging.getLogger("AlertEngine")

SOURCES = ("dashboard_check", "vm_offline", "quota_unmet", "spoke_offline")
_LABEL = {
    "dashboard_check": "Dashboard check",
    "vm_offline": "VM / hypervisor offline",
    "quota_unmet": "Quota engine — requirement unmet",
    "spoke_offline": "Spoke / agent offline",
}
_POLL_S = 60
_HYPERVISOR_TYPES = ("hypervisor", "simulation")


def _esc(s: Any) -> str:
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class AlertEngine:
    def __init__(self, hub) -> None:
        self.hub = hub
        self._state: Dict[tuple, bool] = {}  # (tenant, source, item) -> currently-bad

    async def evaluate(self, tenant: str, source: str, item: str,
                       is_bad: bool, detail: str = "") -> None:
        """Fire on a transition only. ``is_bad`` True on the way into a bad state
        (BREACHED), False on recovery (RECOVERED); no-op when unchanged."""
        key = (tenant, source, item)
        was = self._state.get(key, False)
        if bool(is_bad) == was:
            return
        self._state[key] = bool(is_bad)
        try:
            rules = await self.hub.simulations_store.get_alert_rules(tenant)
        except Exception:  # noqa: BLE001
            return
        recips = []
        for r in rules:
            if r.get("enabled") and r.get("source") == source:
                recips.extend(r.get("recipients") or [])
        recips = sorted({x for x in recips if x})
        if not recips:
            return
        label = _LABEL.get(source, source)
        state = "BREACHED" if is_bad else "RECOVERED"
        subject = f"[LM {'ALERT' if is_bad else 'OK'}] {label}: {item}"
        text = (f"{state}\n\nTenant: {tenant}\nSource: {label}\nItem: {item}\n"
                + (f"Detail: {detail}\n" if detail else ""))
        html = (f'<div style="font-family:Arial,sans-serif;font-size:14px">'
                f'<p style="font-weight:bold;color:{"#c0322a" if is_bad else "#0f7a58"}">'
                f'{label} {state}</p>'
                f'<p><b>Tenant:</b> {_esc(tenant)}<br><b>Item:</b> {_esc(item)}'
                + (f'<br><b>Detail:</b> {_esc(detail)}' if detail else '')
                + '</p></div>')
        try:
            import notifications as _n
            await _n.send_email(self.hub, subject, text, to_emails=recips, html=html)
            logger.info("alert %s: %s/%s '%s' -> %d recipient(s)",
                        state, tenant, source, item, len(recips))
        except Exception as e:  # noqa: BLE001
            logger.warning("alert send failed (%s/%s %s): %s", tenant, source, item, e)


async def _eval_tenant(engine: "AlertEngine", service, tenant: str, needed: set) -> None:
    hub = engine.hub
    # dashboard_check + quota_unmet — from the tenant's aggregated central data.
    if needed & {"dashboard_check", "quota_unmet"}:
        try:
            data = await service.get_central_data(tenant)
        except Exception:  # noqa: BLE001
            data = {}
        for sp in (data.get("spokes") or []):
            cst = sp.get("central_status") or {}
            if "dashboard_check" in needed:
                for site, cmap in (cst.get("status") or {}).items():
                    for cid, info in (cmap or {}).items():
                        if not isinstance(info, dict):
                            continue
                        st = str(info.get("status") or "").lower()
                        await engine.evaluate(tenant, "dashboard_check", f"{site} · {cid}",
                                              st in ("warning", "error"),
                                              info.get("message") or st)
            if "quota_unmet" in needed:
                for site, entry in (cst.get("client_count_status") or {}).items():
                    if not isinstance(entry, dict):
                        continue
                    st = str(entry.get("status") or "").lower()
                    await engine.evaluate(tenant, "quota_unmet", site, st == "error",
                                          entry.get("message") or "client requirement not met")
    # vm_offline / spoke_offline — from the spoke out-of-contact tiers.
    if needed & {"vm_offline", "spoke_offline"}:
        try:
            alerts = {a["spoke_id"]: a.get("tier") for a in hub.get_active_spoke_alerts()}
        except Exception:  # noqa: BLE001
            alerts = {}
        md = hub.state.system_state.get("module_metadata", {}) or {}
        for sid, meta in md.items():
            meta = meta or {}
            if (meta.get("tenant_id") or "") not in ("", tenant):
                continue  # bound to a different tenant
            mtype = (hub.spoke_module_types.get(sid) or meta.get("module_type") or "").lower()
            source = "vm_offline" if mtype in _HYPERVISOR_TYPES else "spoke_offline"
            if source not in needed:
                continue
            tier = alerts.get(sid, "none")
            await engine.evaluate(tenant, source, meta.get("display_name") or sid,
                                  tier in ("warning", "error"), f"out of contact ({tier})")


async def run_alert_loop(hub) -> None:
    """Every ~60s: for each tenant with enabled alert rules, evaluate the needed
    sources and fire breach/recovery emails on transitions. Started from main.py."""
    from simulations.service import SimulationsService
    service = SimulationsService(hub)
    engine = hub.alert_engine
    store = hub.simulations_store
    while True:
        try:
            for tid in store.tenant_ids():
                try:
                    rules = await store.get_alert_rules(tid)
                    needed = {r.get("source") for r in rules if r.get("enabled")}
                    if needed:
                        await _eval_tenant(engine, service, tid, needed)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("alert eval tenant %s: %s", tid, exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("alert loop error: %s", exc)
        await asyncio.sleep(_POLL_S)
