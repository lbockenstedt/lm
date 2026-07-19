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
  * ``cert_issue_failed``  — a cert ISSUE attempt failed (ledger last_issue_error).
  * ``cert_renew_failed``  — a cert RENEWAL failed (ledger last_error); pushed
                             realtime via the LE_CERT_RENEW_FAILED event.
  * ``cert_deploy_failed`` — a cert DEPLOY to a target failed (per-target
                             last_status == ERROR).

Emails route through the same provider-aware ``notifications.send_email`` the hub
alerts + scheduled reports use. State is in-memory: after a restart a still-bad
item re-alerts once (arguably useful — confirms it's still down).
"""
import asyncio
import logging
from typing import Any, Dict

logger = logging.getLogger("AlertEngine")

SOURCES = ("dashboard_check", "vm_offline", "quota_unmet", "spoke_offline",
           "cert_issue_failed", "cert_renew_failed", "cert_deploy_failed")
_LABEL = {
    "dashboard_check": "Dashboard check",
    "vm_offline": "VM / hypervisor offline",
    "quota_unmet": "Quota engine — requirement unmet",
    "spoke_offline": "Spoke / agent offline",
    "cert_issue_failed": "Certificate Request Failed",
    "cert_renew_failed": "Certificate Renewal Failed",
    "cert_deploy_failed": "Certificate Deploy Failed",
}
_POLL_S = 60
_HYPERVISOR_TYPES = ("hypervisor", "simulation")


def _esc(s: Any) -> str:
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _human_body(label, state, tenant, item, sev, detail, ts, is_bad, extra):
    """A formatted, dashboard-styled alert email (text + HTML). Includes the item's
    status pill, a 30-day health-trend strip (``extra['daily']``) and/or client-
    count trend numbers (``extra['trend']``) when available — the same visual
    language as the scheduled report / dashboard."""
    P = "font-family:Arial,Helvetica,sans-serif"
    hdr = "#c0322a" if is_bad else "#0f7a58"
    try:
        from simulations.email_report import _strip, _pill  # reuse the report's widgets
    except Exception:  # noqa: BLE001
        _strip = lambda d: ""  # noqa: E731
        _pill = lambda s: _esc(s)  # noqa: E731
    pill = _pill(sev) if sev in ("ok", "warning", "error", "no_data") else _esc(sev)
    strip_html = ""
    if isinstance(extra, dict) and extra.get("daily"):
        strip_html = (f'<div style="{P};font-size:11px;color:#6b7280;margin-top:14px;'
                      f'text-transform:uppercase;letter-spacing:.04em">30-day trend</div>'
                      f'<div style="margin-top:5px">{_strip(extra["daily"])}</div>'
                      f'<div style="{P};font-size:10px;color:#6b7280;margin-top:5px">'
                      f'<span style="color:#10b981">■</span> healthy '
                      f'<span style="color:#f59e0b">■</span> degraded '
                      f'<span style="color:#ef4444">■</span> failing '
                      f'<span style="color:#cbd5e1">■</span> no data</div>')
    trend_html = ""
    tr = extra.get("trend") if isinstance(extra, dict) else None
    if isinstance(tr, dict):
        pairs = [("Current", tr.get("current")), ("Wired", tr.get("wired")),
                 ("Wireless", tr.get("wireless")), ("Hour avg", tr.get("hourly_avg")),
                 ("Drop %", tr.get("drop_pct")), ("7-day peak", tr.get("max_7day")),
                 ("30-day peak", tr.get("max_30day"))]
        cells = "".join(
            f'<tr><td style="color:#6b7280;padding:2px 14px 2px 0">{k}</td>'
            f'<td style="color:#1f2937;font-weight:bold">{_esc(v)}</td></tr>'
            for k, v in pairs if v is not None)
        if cells:
            trend_html = f'<table role="presentation" style="{P};font-size:12px;margin-top:12px;border-collapse:collapse">{cells}</table>'
    row = lambda k, v: (f'<tr><td style="color:#6b7280;padding:3px 14px 3px 0">{k}</td>'  # noqa: E731
                        f'<td style="color:#1f2937">{v}</td></tr>')
    html = (f'<div style="background:#f5f7f6;padding:20px 0;{P}">'
            f'<div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e8ecea;border-radius:10px;overflow:hidden">'
            f'<div style="padding:16px 20px;border-bottom:3px solid {hdr}">'
            f'<div style="{P};font-size:15px;font-weight:bold;color:{hdr}">{_esc(label)} — {state.upper()}</div>'
            f'<div style="{P};font-size:12px;color:#6b7280;margin-top:2px">{_esc(item)}</div></div>'
            f'<div style="padding:16px 20px">'
            f'<table role="presentation" style="{P};font-size:12px;border-collapse:collapse">'
            + row("Tenant", _esc(tenant)) + row("Status", pill)
            + (row("Detail", _esc(detail)) if detail else "") + row("Time", _esc(ts))
            + f'</table>{trend_html}{strip_html}</div></div></div>')
    text = (f"{label} {state.upper()}\nTenant: {tenant}\nItem: {item}\nStatus: {sev}\n"
            + (f"Detail: {detail}\n" if detail else "") + f"Time: {ts}\n")
    return text, html


class AlertEngine:
    def __init__(self, hub) -> None:
        self.hub = hub
        self._state: Dict[tuple, bool] = {}  # (tenant, source, item) -> currently-bad

    async def evaluate(self, tenant: str, source: str, item: str,
                       is_bad: bool, detail: str = "", severity: str = "",
                       extra: Dict[str, Any] = None) -> None:
        """Fire on a transition only (edge-triggered). Sends each matching rule's
        recipients ONE email in that rule's ``format``: ``human`` (formatted, with
        the 30-day trend strip + stats like the dashboard) or ``raw`` (a compact
        JSON body for automation to ingest). ``extra`` may carry ``daily`` (30-day
        health buckets for the trend strip) and/or ``trend`` (client-count numbers)."""
        key = (tenant, source, item)
        was = self._state.get(key, False)
        if bool(is_bad) == was:
            return
        self._state[key] = bool(is_bad)
        try:
            rules = await self.hub.simulations_store.get_alert_rules(tenant)
        except Exception:  # noqa: BLE001
            return
        matching = [r for r in rules if r.get("enabled") and r.get("source") == source
                    and r.get("recipients")]
        if not matching:
            return
        label = _LABEL.get(source, source)
        state = "breached" if is_bad else "recovered"
        sev = (severity or ("error" if is_bad else "ok")).lower()
        import datetime as _dt
        ts = _dt.datetime.now().isoformat(timespec="seconds")
        # Group recipients by requested format so each set gets ONE email.
        by_fmt: Dict[str, set] = {}
        for r in matching:
            fmt = "raw" if str(r.get("format") or "human").lower() == "raw" else "human"
            by_fmt.setdefault(fmt, set()).update(x for x in (r.get("recipients") or []) if x)
        import notifications as _n
        import json as _json
        for fmt, recips in by_fmt.items():
            recips = sorted(recips)
            if not recips:
                continue
            try:
                if fmt == "raw":
                    payload = {"event": "lm_alert", "state": state, "tenant": tenant,
                               "source": source, "item": item, "severity": sev,
                               "detail": detail, "ts": ts}
                    if isinstance(extra, dict) and isinstance(extra.get("trend"), dict):
                        payload["trend"] = {k: v for k, v in extra["trend"].items()
                                            if isinstance(v, (int, float, str))}
                    await _n.send_email(self.hub, f"lm.alert {source} {state} {item}",
                                        _json.dumps(payload, separators=(",", ":")),
                                        to_emails=recips)
                else:
                    subj = f"[LM {'ALERT' if is_bad else 'OK'}] {label}: {item}"
                    text, html = _human_body(label, state, tenant, item, sev, detail, ts, is_bad, extra)
                    await _n.send_email(self.hub, subj, text, to_emails=recips, html=html)
            except Exception as e:  # noqa: BLE001
                logger.warning("alert send failed (%s/%s %s, %s): %s",
                               tenant, source, item, fmt, e)
        logger.info("alert %s: %s/%s '%s' -> %s", state.upper(), tenant, source, item,
                    {f: len(r) for f, r in by_fmt.items()})


async def _eval_tenant(engine: "AlertEngine", service, tenant: str, needed: set) -> None:
    hub = engine.hub
    # dashboard_check + quota_unmet — from the tenant's aggregated central data.
    if needed & {"dashboard_check", "quota_unmet"}:
        try:
            data = await service.get_central_data(tenant)
        except Exception:  # noqa: BLE001
            data = {}
        # 30-day health history (site -> check -> daily buckets) for the trend strip.
        health = {}
        hh = getattr(getattr(hub, "central_hub_poller", None), "_health", None)
        if hh is not None:
            try:
                health = dict(hh.summary(tenant) or {})
            except Exception:  # noqa: BLE001
                health = {}
        for sp in (data.get("spokes") or []):
            cst = sp.get("central_status") or {}
            if "dashboard_check" in needed:
                for site, cmap in (cst.get("status") or {}).items():
                    for cid, info in (cmap or {}).items():
                        if not isinstance(info, dict):
                            continue
                        st = str(info.get("status") or "").lower()
                        daily = ((health.get(site) or {}).get(cid)) or []
                        await engine.evaluate(tenant, "dashboard_check", f"{site} · {cid}",
                                              st in ("warning", "error"),
                                              info.get("message") or st,
                                              severity=st, extra={"daily": daily})
            if "quota_unmet" in needed:
                for site, entry in (cst.get("client_count_status") or {}).items():
                    if not isinstance(entry, dict):
                        continue
                    st = str(entry.get("status") or "").lower()
                    await engine.evaluate(tenant, "quota_unmet", site, st == "error",
                                          entry.get("message") or "client requirement not met",
                                          severity=st, extra={"trend": entry})
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
            mtype = (hub.spoke_module_types.get(hub._primary_key(sid)) or meta.get("module_type") or "").lower()
            source = "vm_offline" if mtype in _HYPERVISOR_TYPES else "spoke_offline"
            if source not in needed:
                continue
            tier = alerts.get(sid, "none")
            await engine.evaluate(tenant, source, meta.get("display_name") or sid,
                                  tier in ("warning", "error"), f"out of contact ({tier})",
                                  severity=tier)
    # cert_issue_failed / cert_renew_failed / cert_deploy_failed — from the hub's
    # le_cache mirror of the le spoke's ledger (LE_LIST_CERTS). This is the
    # restart re-fire + dedup-consistency path; cert_renew_failed is ALSO pushed
    # realtime by the LE_CERT_RENEW_FAILED event (main.py dispatch calls evaluate
    # directly). The cache is JSON-persisted + warm-loaded, so a hub restart
    # re-alerts a still-bad cert within one tick. Per-tenant: a cert's
    # tenant_id must match (default "" → "default").
    if needed & {"cert_issue_failed", "cert_renew_failed", "cert_deploy_failed"}:
        certs = []
        try:
            cl = hub.le_cache_get("certs") if hasattr(hub, "le_cache_get") else None
            clist = cl.get("certs") if isinstance(cl, dict) else None
            if isinstance(clist, list):
                certs = [c for c in clist if isinstance(c, dict)
                         and (c.get("tenant_id") or "default") == tenant]
        except Exception:  # noqa: BLE001
            certs = []
        for c in certs:
            domain = c.get("domain") or "<unknown>"
            if "cert_issue_failed" in needed:
                ie = c.get("last_issue_error")
                await engine.evaluate(tenant, "cert_issue_failed", domain,
                                      bool(ie), ie or "",
                                      severity="error" if ie else "ok")
            if "cert_renew_failed" in needed:
                rerr = c.get("last_error")
                await engine.evaluate(tenant, "cert_renew_failed", domain,
                                      bool(rerr), rerr or "",
                                      severity="error" if rerr else "ok")
            if "cert_deploy_failed" in needed:
                for t in (c.get("targets") or []):
                    if not isinstance(t, dict):
                        continue
                    mt = t.get("module_type") or ""
                    ident = t.get("identifier") or ""
                    item = f"{domain}/{mt}" + (f"/{ident}" if ident else "")
                    bad = str(t.get("last_status") or "").upper() == "ERROR"
                    await engine.evaluate(tenant, "cert_deploy_failed", item,
                                          bad, t.get("last_message") or "",
                                          severity="error" if bad else "ok")


async def run_alert_loop(hub) -> None:
    """Every ~60s: for each tenant with enabled alert rules, evaluate the needed
    sources and fire breach/recovery emails on transitions. Started from main.py.
    Runs on the shared run_sync_loop skeleton (same error-tolerant shape)."""
    from simulations.service import SimulationsService
    from sync_loop import run_sync_loop
    service = SimulationsService(hub)
    engine = hub.alert_engine
    store = hub.simulations_store

    async def _body():
        for tid in store.tenant_ids():
            try:
                rules = await store.get_alert_rules(tid)
                needed = {r.get("source") for r in rules if r.get("enabled")}
                if needed:
                    await _eval_tenant(engine, service, tid, needed)
            except Exception as exc:  # noqa: BLE001
                logger.debug("alert eval tenant %s: %s", tid, exc)

    await run_sync_loop(stagger=0, body=_body, delay=lambda: _POLL_S,
                        on_error=lambda e: logger.warning("alert loop error: %s", e),
                        error_delay=_POLL_S)
