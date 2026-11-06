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
# asyncio is the event-loop library this async engine runs on.
import asyncio
# Standard-library logging for send failures and transitions.
import logging
# Type hints only.
from typing import Any, Dict
# Resolves a spoke/agent id to its friendly display name for alert subjects.
from display_names import node_name  # sibling leaf

# One named logger so alert-engine messages can be filtered together.
logger = logging.getLogger("AlertEngine")

# Every alert source name a tenant alert rule may subscribe to.
SOURCES = ("dashboard_check", "vm_offline", "quota_unmet", "adaptive_quota_maxed",
           "spoke_offline", "cert_issue_failed", "cert_renew_failed", "cert_deploy_failed",
           "bulk_dongle_failure", "single_bus_failing")
# Human-readable title for each source, used in email subjects/headers.
_LABEL = {
    "dashboard_check": "Dashboard check",
    "vm_offline": "VM / hypervisor offline",
    "quota_unmet": "Quota engine — requirement unmet",
    "adaptive_quota_maxed": "Adaptive quota — at max, alert not firing",
    "spoke_offline": "Spoke / agent offline",
    "cert_issue_failed": "Certificate Request Failed",
    "cert_renew_failed": "Certificate Renewal Failed",
    "cert_deploy_failed": "Certificate Deploy Failed",
    "bulk_dongle_failure": "Dongle quarantine — bulk client failure",
    "single_bus_failing": "Dongle quarantine — single bus failing",
}
# How often (seconds) the loop re-evaluates every tenant.
_POLL_S = 60
# Module types whose outage is reported as "vm_offline" rather than "spoke_offline".
_HYPERVISOR_TYPES = ("hypervisor", "simulation")


def _esc(s: Any) -> str:
    """HTML-escape a value (None becomes "") so it is safe to embed in an email body."""
    # Replace &, < and > with their HTML entities (& first so entities are not double-escaped).
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _human_body(label, state, tenant, item, sev, detail, ts, is_bad, extra):
    """A formatted, dashboard-styled alert email (text + HTML). Includes the item's
    status pill, a 30-day health-trend strip (``extra['daily']``) and/or client-
    count trend numbers (``extra['trend']``) when available — the same visual
    language as the scheduled report / dashboard."""
    # HPE Design System colors/font, shared with the scheduled report (inline:
    # email clients ignore stylesheets).
    from simulations import email_report as R
    P = R.FONT
    # Header colour: red for a breach, green for a recovery.
    hdr = R.CRIT_TEXT if is_bad else R.OK_TEXT
    _pill = R._pill
    # The report's 30-day trend strip, when that widget exists.
    _strip = getattr(R, "_strip", None) or (lambda d: "")
    # Coloured pill for known statuses; plain escaped text otherwise.
    pill = _pill(sev) if sev in ("ok", "warning", "error", "no_data") else _esc(sev)
    # Optional 30-day trend strip, only when daily history was supplied.
    strip_html = ""
    if isinstance(extra, dict) and extra.get("daily"):
        strip_html = (f'<div style="{P};font-size:12px;font-weight:bold;color:{R.WEAK};margin-top:14px">30-day trend</div>'
                      f'<div style="margin-top:5px">{_strip(extra["daily"])}</div>'
                      f'<div style="{P};font-size:12px;color:{R.WEAK};margin-top:5px">'
                      f'<span style="color:{R.OK}">■</span> healthy '
                      f'<span style="color:{R.WARN}">■</span> degraded '
                      f'<span style="color:{R.CRIT}">■</span> failing '
                      f'<span style="color:{R.NONE}">■</span> no data</div>')
    # Optional client-count trend table, only when trend numbers were supplied.
    trend_html = ""
    tr = extra.get("trend") if isinstance(extra, dict) else None
    if isinstance(tr, dict):
        # Label/value pairs to show, in display order.
        pairs = [("Current", tr.get("current")), ("Wired", tr.get("wired")),
                 ("Wireless", tr.get("wireless")), ("Hour avg", tr.get("hourly_avg")),
                 ("Drop %", tr.get("drop_pct")), ("7-day peak", tr.get("max_7day")),
                 ("30-day peak", tr.get("max_30day"))]
        # One table row per value that is present.
        cells = "".join(
            f'<tr><td style="color:{R.WEAK};padding:2px 14px 2px 0">{k}</td>'
            f'<td style="color:{R.TEXT};font-weight:bold">{_esc(v)}</td></tr>'
            for k, v in pairs if v is not None)
        # Only render the table if at least one row exists.
        if cells:
            trend_html = f'<table role="presentation" style="{P};font-size:13px;margin-top:12px;border-collapse:collapse">{cells}</table>'
    # Small helper that renders one label/value table row.
    row = lambda k, v: (f'<tr><td style="color:{R.WEAK};padding:3px 14px 3px 0">{k}</td>'  # noqa: E731
                        f'<td style="color:{R.TEXT}">{v}</td></tr>')
    # Assemble the full HTML email: header bar, details table, then trend table and strip.
    html = (f'<div style="background:{R.BG};padding:20px 0;{P}">'
            f'<div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid {R.BORDER};border-radius:12px;overflow:hidden">'
            f'<div style="background:{R.NAVY};padding:12px 20px;border-bottom:3px solid {R.BRAND};{P};font-size:14px;color:#fff">'
            f'<b>HPE</b> &nbsp;|&nbsp; Lab Manager alert</div>'
            f'<div style="padding:16px 20px;border-bottom:3px solid {hdr}">'
            f'<div style="{P};font-size:16px;font-weight:bold;color:{hdr}">{_esc(label)} — {_esc(state.capitalize())}</div>'
            f'<div style="{P};font-size:13px;color:{R.WEAK};margin-top:2px">{_esc(item)}</div></div>'
            f'<div style="padding:16px 20px">'
            f'<table role="presentation" style="{P};font-size:13px;border-collapse:collapse">'
            + row("Tenant", _esc(tenant)) + row("Status", pill)
            + (row("Detail", _esc(detail)) if detail else "") + row("Time", _esc(ts))
            + f'</table>{trend_html}{strip_html}</div></div></div>')
    # Plain-text alternative for email clients that do not render HTML.
    text = (f"{label} {state.upper()}\nTenant: {tenant}\nItem: {item}\nStatus: {sev}\n"
            + (f"Detail: {detail}\n" if detail else "") + f"Time: {ts}\n")
    # Return both bodies.
    return text, html


class AlertEngine:
    """Edge-triggered alert router: emails rule recipients only when an item changes state."""
    def __init__(self, hub) -> None:
        """Keep a reference to the hub and start with no known bad items."""
        # The hub provides the alert-rule store and the email sender.
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
        # Unique identity of the monitored item.
        key = (tenant, source, item)
        # Was it bad last time? Unknown items count as good.
        was = self._state.get(key, False)
        # No change in state: stay silent (this is what makes it edge-triggered).
        if bool(is_bad) == was:
            return
        # Remember the new state before sending, so a send failure does not cause a re-fire storm.
        self._state[key] = bool(is_bad)
        # Load this tenant's alert rules; if that fails, skip this transition.
        try:
            rules = await self.hub.simulations_store.get_alert_rules(tenant)
        except Exception:  # noqa: BLE001
            return
        # Rules that are enabled, match this source and have someone to email.
        matching = [r for r in rules if r.get("enabled") and r.get("source") == source
                    and r.get("recipients")]
        # Nobody subscribed: nothing to send.
        if not matching:
            return
        # Human title, transition word, and normalised severity for the message.
        label = _LABEL.get(source, source)
        state = "breached" if is_bad else "recovered"
        sev = (severity or ("error" if is_bad else "ok")).lower()
        # Imported lazily; only needed when an email is actually sent.
        import datetime as _dt
        # Timestamp shown in the email.
        now = _dt.datetime.now().astimezone()
        ts = now.isoformat(timespec="seconds")              # raw JSON: ISO 8601 with offset
        ts_human = now.strftime("%Y-%m-%d %H:%M:%S %Z")     # email: shows the time zone
        # Group recipients by requested format so each set gets ONE email.
        by_fmt: Dict[str, set] = {}
        # Each rule asks for "raw" (JSON) or "human" (formatted) emails; collect recipients per
        # format.
        for r in matching:
            fmt = "raw" if str(r.get("format") or "human").lower() == "raw" else "human"
            by_fmt.setdefault(fmt, set()).update(x for x in (r.get("recipients") or []) if x)
        # Imported lazily: the hub's email sender and a JSON encoder for raw payloads.
        import notifications as _n
        import json as _json
        # Send one email per format.
        for fmt, recips in by_fmt.items():
            # Stable recipient order; skip if empty.
            recips = sorted(recips)
            if not recips:
                continue
            # A failed send is logged so other formats/recipients still get their email.
            try:
                # Raw format: a compact JSON body for automated consumers.
                if fmt == "raw":
                    payload = {"event": "lm_alert", "state": state, "tenant": tenant,
                               "source": source, "item": item, "severity": sev,
                               "detail": detail, "ts": ts}
                    # Include only simple trend values so the payload stays JSON-friendly.
                    if isinstance(extra, dict) and isinstance(extra.get("trend"), dict):
                        payload["trend"] = {k: v for k, v in extra["trend"].items()
                                            if isinstance(v, (int, float, str))}
                    # Send the JSON payload with a machine-friendly subject.
                    await _n.send_email(self.hub, f"lm.alert {source} {state} {item}",
                                        _json.dumps(payload, separators=(",", ":")),
                                        to_emails=recips)
                # Human format: formatted subject and text+HTML body.
                else:
                    subj = f"[LM {'ALERT' if is_bad else 'OK'}] {label}: {item}"
                    text, html = _human_body(label, state, tenant, item, sev, detail, ts_human, is_bad, extra)
                    await _n.send_email(self.hub, subj, text, to_emails=recips, html=html)
            # Log the failure and carry on.
            except Exception as e:  # noqa: BLE001
                logger.warning("alert send failed (%s/%s %s, %s): %s",
                               tenant, source, item, fmt, e)
        # Log the transition and how many recipients got each format.
        logger.info("alert %s: %s/%s '%s' -> %s", state.upper(), tenant, source, item,
                    {f: len(r) for f, r in by_fmt.items()})


async def _eval_tenant(engine: "AlertEngine", service, tenant: str, needed: set) -> None:
    """Evaluate every alert source the tenant's rules need, firing transitions via ``engine``."""
    # The hub holds state, caches and spoke alerts.
    hub = engine.hub
    # dashboard_check + quota_unmet — from the tenant's aggregated central data.
    if needed & {"dashboard_check", "quota_unmet"}:
        # Fetch the tenant's aggregated Central data; on failure treat it as empty.
        try:
            data = await service.get_central_data(tenant)
        except Exception:  # noqa: BLE001
            data = {}
        # 30-day health history (site -> check -> daily buckets) for the trend strip.
        # Per-site/per-check daily health history, if the Central poller is running.
        health = {}
        hh = getattr(getattr(hub, "central_hub_poller", None), "_health", None)
        if hh is not None:
            # History lookup is optional; any failure just means no trend strip.
            try:
                health = dict(hh.summary(tenant) or {})
            except Exception:  # noqa: BLE001
                health = {}
        # Walk each Central spoke's status report.
        for sp in (data.get("spokes") or []):
            # That spoke's status block.
            cst = sp.get("central_status") or {}
            # Dashboard checks: one alert item per site/check pair.
            if "dashboard_check" in needed:
                for site, cmap in (cst.get("status") or {}).items():
                    for cid, info in (cmap or {}).items():
                        # Skip malformed entries.
                        if not isinstance(info, dict):
                            continue
                        # Normalised status and the matching 30-day history.
                        st = str(info.get("status") or "").lower()
                        daily = ((health.get(site) or {}).get(cid)) or []
                        # Bad when warning or error; message shown as detail.
                        await engine.evaluate(tenant, "dashboard_check", f"{site} · {cid}",
                                              st in ("warning", "error"),
                                              info.get("message") or st,
                                              severity=st, extra={"daily": daily})
            # Quota: one alert item per site's client-count check.
            if "quota_unmet" in needed:
                for site, entry in (cst.get("client_count_status") or {}).items():
                    # Skip malformed entries.
                    if not isinstance(entry, dict):
                        continue
                    # Normalised status; only "error" counts as unmet.
                    st = str(entry.get("status") or "").lower()
                    await engine.evaluate(tenant, "quota_unmet", site, st == "error",
                                          entry.get("message") or "client requirement not met",
                                          severity=st, extra={"trend": entry})
    # vm_offline / spoke_offline — from the spoke out-of-contact tiers.
    if needed & {"vm_offline", "spoke_offline"}:
        # Current out-of-contact tier per spoke id; on failure treat all as healthy.
        try:
            alerts = {a["spoke_id"]: a.get("tier") for a in hub.get_active_spoke_alerts()}
        except Exception:  # noqa: BLE001
            alerts = {}
        # All known spokes/agents and their metadata.
        md = hub.state.system_state.get("module_metadata", {}) or {}
        # Check each one.
        for sid, meta in md.items():
            # Guard against a stored None.
            meta = meta or {}
            if (meta.get("tenant_id") or "") not in ("", tenant):
                continue  # bound to a different tenant
            # Work out its module type (live registry first, then stored metadata).
            mtype = (hub.spoke_module_types.get(hub._primary_key(sid)) or meta.get("module_type") or "").lower()
            # Hypervisor/simulation outages are reported as vm_offline; everything else as
            # spoke_offline.
            source = "vm_offline" if mtype in _HYPERVISOR_TYPES else "spoke_offline"
            # Skip if no rule for that source.
            if source not in needed:
                continue
            # Its current alert tier ("none" if not alerting).
            tier = alerts.get(sid, "none")
            # Bad when warning or error; named by its friendly display name.
            await engine.evaluate(tenant, source, node_name(hub.state.system_state, sid),
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
        # Certificates for this tenant from the hub's cached copy of the LE ledger.
        certs = []
        # Cache problems just mean no certs to check this round.
        try:
            cl = hub.le_cache_get("certs") if hasattr(hub, "le_cache_get") else None
            clist = cl.get("certs") if isinstance(cl, dict) else None
            if isinstance(clist, list):
                # Keep only well-formed certs belonging to this tenant.
                certs = [c for c in clist if isinstance(c, dict)
                         and (c.get("tenant_id") or "default") == tenant]
        except Exception:  # noqa: BLE001
            certs = []
        # Evaluate each certificate.
        for c in certs:
            # Domain is the alert item name.
            domain = c.get("domain") or "<unknown>"
            # Issue failure: bad while last_issue_error is set.
            if "cert_issue_failed" in needed:
                ie = c.get("last_issue_error")
                await engine.evaluate(tenant, "cert_issue_failed", domain,
                                      bool(ie), ie or "",
                                      severity="error" if ie else "ok")
            # Renewal failure: bad while last_error is set.
            if "cert_renew_failed" in needed:
                rerr = c.get("last_error")
                await engine.evaluate(tenant, "cert_renew_failed", domain,
                                      bool(rerr), rerr or "",
                                      severity="error" if rerr else "ok")
            # Deploy failure: one alert item per deployment target.
            if "cert_deploy_failed" in needed:
                for t in (c.get("targets") or []):
                    # Skip malformed targets.
                    if not isinstance(t, dict):
                        continue
                    # Item name combines domain, target module type and optional identifier.
                    mt = t.get("module_type") or ""
                    ident = t.get("identifier") or ""
                    item = f"{domain}/{mt}" + (f"/{ident}" if ident else "")
                    # Bad when the last deploy status is ERROR.
                    bad = str(t.get("last_status") or "").upper() == "ERROR"
                    await engine.evaluate(tenant, "cert_deploy_failed", item,
                                          bad, t.get("last_message") or "",
                                          severity="error" if bad else "ok")
    # bulk_dongle_failure / single_bus_failing — from each CS spoke's relayed
    # ``qt_state`` (populated by the spoke's dongle-quarantine detection sweep;
    # see sim_quota_engine._quarantine_sweep). The spoke decides; the hub only
    # alarms. ``bulk_dongle_failure`` = a host with >20% of its T2 clients never
    # connecting (infrastructure — a switch/AP/downlink — not individual
    # dongles, so the sweep suppresses the per-dongle shed there).
    # ``single_bus_failing`` = a single USB bus accumulating quarantine strikes
    # (a flaky port/dongle — the storm-guard counterpart to the bulk case).
    if needed & {"bulk_dongle_failure", "single_bus_failing"}:
        # Raw status frames for this tenant's CS spokes; on failure treat as none.
        try:
            raw_spokes = service._spokes_for_tenant(tenant)  # [(sid, raw_frame)]
        except Exception:  # noqa: BLE001
            raw_spokes = []
        # Inspect each spoke's quarantine state.
        for sid, data in raw_spokes:
            # Skip spokes that did not report qt_state.
            qt = data.get("qt_state") if isinstance(data, dict) else None
            if not isinstance(qt, dict):
                continue
            # Friendly spoke name for the alert item (fallback to id).
            spk = (data.get("spoke_name") if isinstance(data, dict) else None) or sid
            # Bulk failure: bad while any host is listed in bulk_hosts.
            if "bulk_dongle_failure" in needed:
                bulk = qt.get("bulk_hosts") or []
                bad = bool(bulk)
                detail = ("hosts with >20% of T2 clients never connecting: "
                          + ", ".join(map(str, bulk))) if bad else ""
                await engine.evaluate(tenant, "bulk_dongle_failure", spk,
                                      bad, detail,
                                      severity="error" if bad else "ok")
            if "single_bus_failing" in needed:
                # A bus with ≥3 accumulated fails on one spoke = a single flaky
                # bus (not a one-off). The sweep counts per-bus fails per tick;
                # a persistent flapper crosses this across sweeps.
                flaky = [b for b, n in (qt.get("per_bus_fails") or {}).items()
                         if int(n or 0) >= 3]
                bad = bool(flaky)
                detail = ("buses with repeated quarantine fails: "
                          + ", ".join(map(str, flaky))) if bad else ""
                await engine.evaluate(tenant, "single_bus_failing", spk,
                                      bad, detail,
                                      severity="error" if bad else "ok")


async def run_alert_loop(hub) -> None:
    """Every ~60s: for each tenant with enabled alert rules, evaluate the needed
    sources and fire breach/recovery emails on transitions. Started from main.py.
    Runs on the shared run_sync_loop skeleton (same error-tolerant shape)."""
    # Imported lazily to avoid circular imports at module load.
    from simulations.service import SimulationsService
    from sync_loop import run_sync_loop
    # Service for tenant data, the shared engine, and the store holding alert rules.
    service = SimulationsService(hub)
    engine = hub.alert_engine
    store = hub.simulations_store

    async def _body():
        """One loop cycle: evaluate every tenant that has enabled alert rules."""
        # Visit each tenant.
        for tid in store.tenant_ids():
            # One tenant's failure is logged and must not stop the others.
            try:
                # Collect the sources this tenant's enabled rules care about.
                rules = await store.get_alert_rules(tid)
                needed = {r.get("source") for r in rules if r.get("enabled")}
                # Only evaluate when at least one source is needed.
                if needed:
                    await _eval_tenant(engine, service, tid, needed)
            # Log quietly and move on.
            except Exception as exc:  # noqa: BLE001
                logger.debug("alert eval tenant %s: %s", tid, exc)

    # Run the cycle every 60 s with error tolerance.
    await run_sync_loop(stagger=0, body=_body, delay=lambda: _POLL_S,
                        on_error=lambda e: logger.warning("alert loop error: %s", e),
                        error_delay=_POLL_S)
