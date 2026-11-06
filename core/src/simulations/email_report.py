"""Scheduled email compliance report.

Renders the SAME data the WebUI shows on Dashboard → Compliance (and optionally
Client Count) as email-safe, inline-styled HTML (flexbox / <style> are stripped
by many mail clients, so everything is inline + table-based) and sends it via the tenant's own
SMTP settings (the notifications config). Per-tenant enable/disable + section
toggles + schedule live in ``store.get_email_report``. A background loop
(``run_loop``, started from main.py) fires each due report once per period.

The report is tenant-scoped: it renders only the tenant's own sites (the same
central_status the dashboard shows for that tenant).
"""
# Allow modern type-hint syntax on older Python versions.
from __future__ import annotations

# asyncio drives the background scheduler loop.
import asyncio
# Dates for the report header and for schedule/period calculations.
import datetime
# Standard-library logging for delivery results and errors.
import logging
# Type hints only.
from typing import Any, Dict, List, Tuple

# The read service that shapes cached telemetry into dashboard data.
from .service import SimulationsService

# One named logger for the email report feature.
logger = logging.getLogger("EmailReport")

# How often (seconds) the scheduler wakes up to check for due reports.
_POLL_S = 300  # scheduler tick (fires when the configured hour is reached)

# status -> (label, bg, fg) — the pill colors, matching the WebUI badges.
_PILL = {
    "ok": ("OK", "#e7f7f0", "#0f7a58"),
    "warning": ("Warning", "#fdf2df", "#9a6a06"),
    "error": ("Failing", "#fdeaea", "#c0322a"),
    "no_data": ("No data", "#eef2f1", "#5c6b65"),
}


def _esc(s: Any) -> str:
    """HTML-escape a value (None becomes "") so it is safe to embed in the email."""
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pill(status: str) -> str:
    """Render a status as a colored pill badge, like the WebUI."""
    # Look up label and colors; unknown statuses render as "No data".
    label, bg, fg = _PILL.get(str(status).lower(), _PILL["no_data"])
    return (f'<span style="display:inline-block;font-family:Arial,sans-serif;font-size:11px;'
            f'font-weight:bold;text-transform:uppercase;color:{fg};background:{bg};'
            f'padding:2px 9px;border-radius:10px;white-space:nowrap">{label}</span>')


def _num(v: Any) -> str:
    """Escape a number for display, or show an em dash when it is missing."""
    return _esc(v) if v is not None else "—"


def _pct(v: Any) -> str:
    """Success-% cell: colored green/amber/red by band, '—' when no graded samples."""
    # No graded samples: show a grey dash.
    if v is None:
        return '<span style="color:#9ca3af">—</span>'
    # Green at >=99%, amber at >=95%, red below.
    col = "#10b981" if v >= 99 else ("#b8860b" if v >= 95 else "#ef4444")
    # Show whole numbers without a trailing ".0".
    n = int(v) if float(v).is_integer() else v
    return f'<span style="color:{col};font-weight:bold">{n}%</span>'


def _html_to_text(html: str) -> str:
    """Crude plain-text fallback for the multipart email (clients render the
    HTML; this is the text/plain alternative)."""
    # Imported locally because only this helper needs regular expressions.
    import re as _re
    # Remove style/script blocks entirely, including their contents.
    txt = _re.sub(r"<(style|script)[^>]*>.*?</\1>", " ", html or "", flags=_re.S | _re.I)
    # Replace every remaining tag with a space and decode non-breaking spaces.
    txt = _re.sub(r"<[^>]+>", " ", txt).replace("&nbsp;", " ")
    # Collapse runs of spaces and blank lines into clean plain text.
    return _re.sub(r"[ \t]*\n\s*", "\n", _re.sub(r"[ \t]{2,}", " ", txt)).strip()


async def build_report(hub, service: SimulationsService, tenant_id: str,
                       cfg: Dict[str, Any]) -> Tuple[str, str]:
    """Return (subject, html) for the tenant's report per ``cfg['sections']``.
    ``checks`` = the Dashboard → Compliance view; ``clients`` = Client Count."""
    sections = cfg.get("sections") or {"checks": True, "clients": True}
    tenant_name = tenant_id
    try:
        t = (hub.state.tenant_state or {}).get("tenants", {}).get(tenant_id) or {}
        tenant_name = t.get("name") or tenant_id
    # Missing hub state (e.g. in tests) just keeps the tenant id as the name.
    except Exception:  # noqa: BLE001
        pass

    from .central_hub_poller import gather_compliance
    comp = gather_compliance(hub, service, tenant_id)
    month = (comp["overall"].get("d30") or {}).get("pct")
    today = datetime.datetime.now().strftime("%a, %b %d, %Y")

    # ── HTML (inline styles only; mail clients ignore <style>) ─────────────
    P = 'font-family:Arial,Helvetica,sans-serif'
    th = f'style="{P};font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;font-weight:bold;text-align:left;padding:6px 8px;border-bottom:1px solid #e8ecea"'
    thr = th.replace("text-align:left", "text-align:right")
    td = f'style="{P};font-size:12px;color:#1f2937;padding:8px;border-bottom:1px solid #f0f2f1"'
    tdn = f'style="{P};font-size:12px;color:#1f2937;padding:8px;border-bottom:1px solid #f0f2f1;text-align:right"'
    h2 = f'style="{P};font-size:13px;font-weight:bold;color:#1f2937;margin-bottom:8px"'

    parts: List[str] = []
    parts.append(f'''
<div style="background:#f5f7f6;padding:20px 0;{P}">
 <div style="max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #e8ecea;border-radius:10px;overflow:hidden">
  <div style="padding:20px 22px 16px;border-bottom:3px solid #01A982">
   <table role="presentation" width="100%"><tr>
     <td style="{P};font-size:15px;font-weight:bold;color:#1f2937">◈ LM Compliance Report</td>
     <td style="{P};font-size:11px;color:#6b7280;text-align:right">As of<br><b>{today}</b></td>
   </tr></table>
   <div style="{P};font-size:19px;font-weight:bold;color:#1f2937;margin-top:12px">Simulation compliance — {_esc(tenant_name)}</div>
   <div style="{P};font-size:12px;color:#6b7280;margin-top:2px">Share of check polls that were OK · week, month, quarter and year</div>
  </div>''')

    if sections.get("checks", True):
        parts.append(_compliance_html(comp, P, th, thr, td, tdn, h2))

    if sections.get("clients", True):
        parts.append(await _clients_html(service, tenant_id, P, th, td, tdn, h2))

    parts.append(f'''
  <div style="padding:14px 22px 20px;border-top:1px solid #f0f2f1;background:#f5f7f6;{P};font-size:11px;color:#6b7280">
    Sent by <b>LM</b> because Email Reports is on for your tenant · manage in Setup → Notifications.
  </div>
 </div>
</div>''')

    month_txt = f"{_fmt(month)}% this month" if month is not None else "no data yet"
    subject = f"LM Compliance Report — {tenant_name} — {month_txt}"
    return subject, "".join(parts)


# (key, label, span) for the period cards and table columns.
_WINDOWS = (("d7", "Week", "7 days"), ("d30", "Month", "30 days"),
            ("d90", "Quarter", "90 days"), ("y1", "Year", "365 days"))
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _fmt(v: Any) -> str:
    """99.0 -> "99", 98.5 -> "98.5"."""
    return str(int(v)) if float(v).is_integer() else str(v)


def _color(v: Any) -> str:
    """Green at >=99%, amber at >=95%, red below, grey when unknown."""
    if v is None:
        return "#cbd5e1"
    return "#10b981" if v >= 99 else ("#f59e0b" if v >= 95 else "#ef4444")


def _delta(cur: Any, prev: Any) -> str:
    """"▲ 0.4 pts vs previous" line under a period card."""
    if cur is None or prev is None:
        return '<span style="color:#9ca3af">no previous period yet</span>'
    d = round(cur - prev, 1)
    if d == 0:
        return '<span style="color:#6b7280">no change vs previous</span>'
    col, arrow = ("#10b981", "▲") if d > 0 else ("#ef4444", "▼")
    return f'<span style="color:{col}">{arrow} {_fmt(abs(d))} pts vs previous</span>'


def _compliance_html(comp: Dict[str, Any], P: str, th: str, thr: str,
                     td: str, tdn: str, h2: str) -> str:
    """The Dashboard → Compliance view as email-safe HTML: period cards,
    12-month bars, quarters and every check's % per period."""
    o = comp["overall"]
    cards = ""
    for k, label, span in _WINDOWS:
        w = o.get(k) or {}
        pct = w.get("pct")
        days = w.get("days") or 0
        cover = f"based on {days} day{'' if days == 1 else 's'} of data" if days else "no data"
        cards += (f'<td width="25%" valign="top" style="padding:4px"><div style="border:1px solid #e8ecea;border-radius:8px;padding:10px">'
                  f'<div style="{P};font-size:10px;text-transform:uppercase;color:#6b7280;font-weight:bold">{label}'
                  f' <span style="font-weight:normal;text-transform:none">· last {span}</span></div>'
                  f'<div style="{P};font-size:24px;font-weight:bold;color:{_color(pct)};margin-top:4px">{_fmt(pct) + "%" if pct is not None else "—"}</div>'
                  f'<div style="{P};font-size:10px;margin-top:2px">{_delta(pct, w.get("prev"))}</div>'
                  f'<div style="{P};font-size:10px;color:#9ca3af;margin-top:2px">{cover}</div></div></td>')

    # 12 vertical bars; bar height is the month's % of a 100px column.
    bars, labels = "", ""
    for m in comp["months"]:
        pct = m.get("pct")
        h = 0 if pct is None else max(2, int(round(pct)))
        y, mo = m["m"].split("-")
        bars += (f'<td valign="bottom" align="center" style="padding:0 2px;height:118px">'
                 f'<div style="{P};font-size:9px;font-weight:bold;color:{_color(pct)}">{_fmt(pct) + "%" if pct is not None else ""}</div>'
                 f'<div style="background:{_color(pct)};height:{h}px;line-height:{h}px;font-size:0;border-radius:3px 3px 0 0">&nbsp;</div></td>')
        labels += f'<td align="center" style="{P};font-size:9px;color:#6b7280;padding-top:3px">{_MONTHS[int(mo) - 1]} {y[2:]}</td>'

    quarters = "".join(
        f'<td width="25%" align="center" style="padding:4px"><div style="border:1px solid #e8ecea;border-radius:8px;padding:8px">'
        f'<div style="{P};font-size:11px;color:#6b7280;font-weight:bold">{_esc(q["q"])}</div>'
        f'<div style="{P};font-size:16px;font-weight:bold;color:{_color(q.get("pct"))}">{_fmt(q["pct"]) + "%" if q.get("pct") is not None else "—"}</div></div></td>'
        for q in comp["quarters"])

    def row(name: str, sites: str, vals: List[Any], bold: bool = False) -> str:
        bg = "background:#f5f7f6;font-weight:bold;" if bold else ""
        return (f'<tr style="{bg}"><td {td}>{name}</td><td {tdn}>{sites}</td>'
                + "".join(f"<td {tdn}>{_pct(v)}</td>" for v in vals) + "</tr>")

    keys = [k for k, _, _ in _WINDOWS]
    rows = row("Overall", "", [(o.get(k) or {}).get("pct") for k in keys], bold=True)
    for c in comp["checks"]:
        tag = (f'<span style="font-size:9px;text-transform:uppercase;color:#9ca3af">{_esc(c["product"])}</span> '
               if c.get("product") else "")
        rows += row(f'{tag}<span style="font-family:monospace;font-size:11px">{_esc(c["check"])}</span>',
                    str(c.get("sites") or ""), [c.get(k) for k in keys])
    heads = "".join(f"<th {thr}>{label}</th>" for _, label, _ in _WINDOWS)

    since = ""
    if comp.get("since"):
        since = datetime.datetime.utcfromtimestamp(comp["since"]).strftime("%Y-%m-%d")
        since = f"History starts {since}; longer periods fill in as data accumulates. "

    return f'''
  <div style="padding:16px 18px 4px">
   <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>{cards}</tr></table>
  </div>
  <div style="padding:12px 22px 4px">
   <div {h2}>Last 12 months</div>
   <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="table-layout:fixed"><tr>{bars}</tr><tr>{labels}</tr></table>
  </div>
  <div style="padding:12px 18px 4px">
   <div {h2} style="padding-left:4px">Quarters</div>
   <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>{quarters}</tr></table>
  </div>
  <div style="padding:12px 22px 8px">
   <div {h2}>All checks <span style="font-weight:normal;color:#6b7280;font-size:11px">· worst month first</span></div>
   <table role="presentation" width="100%" style="border-collapse:collapse">
     <tr><th {th}>Check</th><th {thr}>Sites</th>{heads}</tr>
     {rows}
   </table>
   <div style="{P};font-size:10px;color:#6b7280;padding:8px 0 4px">
     <span style="color:#10b981">■</span> ≥ 99% &nbsp; <span style="color:#f59e0b">■</span> 95–99% &nbsp;
     <span style="color:#ef4444">■</span> &lt; 95% &nbsp;·&nbsp; {since}Compliance = share of polls where the check was OK
     (polls with no data are left out). Months and quarters are UTC calendar periods.</div>
  </div>'''


async def _clients_html(service: SimulationsService, tenant_id: str, P: str,
                        th: str, td: str, tdn: str, h2: str) -> str:
    """Client Count section: one row per site from the latest poll."""
    data = await service.get_central_data(tenant_id)
    ccrows: List[Dict[str, Any]] = []
    for s in (data.get("spokes") or []):
        for site, entry in ((s.get("central_status") or {}).get("client_count_status") or {}).items():
            if isinstance(entry, dict):
                ccrows.append({"site": site, **entry})
    rows = []
    for r in sorted(ccrows, key=lambda x: x.get("site_name") or x.get("site") or ""):
        # Highlight a client-count drop in amber; otherwise grey.
        drop = r.get("drop_pct")
        dcol = "#b8860b" if (drop or 0) > 0 else "#6b7280"
        rows.append(
            f'<tr><td {td}><span style="font-family:monospace;font-size:11px;color:#374151">{_esc(r.get("site_name") or r.get("site"))}</span></td>'
            f'<td {td}>{_pill(r.get("status") or "no_data")}</td>'
            f'<td {tdn}><b>{_num(r.get("current"))}</b></td><td {tdn}>{_num(r.get("wired"))}</td>'
            f'<td {tdn}>{_num(r.get("wireless"))}</td><td {tdn}>{_num(r.get("hourly_avg"))}</td>'
            f'<td style="{P};font-size:12px;color:{dcol};padding:8px;border-bottom:1px solid #f0f2f1;text-align:right">{_num(drop)}{"%" if drop is not None else ""}</td>'
            f'<td {tdn}>{_num(r.get("max_7day"))}</td><td {tdn}>{_num(r.get("max_30day"))}</td></tr>')
    return f'''
  <div style="padding:8px 22px 8px">
   <div {h2}>Client Count
     <span style="font-weight:normal;color:#6b7280;font-size:11px">· per site · last poll</span></div>
   <table role="presentation" width="100%" style="border-collapse:collapse">
     <tr><th {th}>Site</th><th {th}>Status</th><th {th} style="text-align:right">Current</th><th {th} style="text-align:right">Wired</th>
       <th {th} style="text-align:right">Wireless</th><th {th} style="text-align:right">Hourly avg</th>
       <th {th} style="text-align:right">Drop</th><th {th} style="text-align:right">7d peak</th><th {th} style="text-align:right">30d peak</th></tr>
     {"".join(rows) or f'<tr><td {td} colspan="9">No client-count data.</td></tr>'}
   </table>
  </div>'''


def _period_key(now: datetime.datetime, freq: str) -> str:
    """Return a string that identifies the current schedule period for the frequency."""
    # Daily reports key on the date.
    if freq == "daily":
        return now.strftime("%Y-%m-%d")
    # Monthly reports key on year-month.
    if freq == "monthly":
        return now.strftime("%Y-%m")
    # Weekly (default) reports key on ISO year and week number.
    iso = now.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"  # weekly


def _due(now: datetime.datetime, sch: Dict[str, Any]) -> bool:
    """Return True when the schedule says a report should go out at this time."""
    # Not before the configured hour of the day (default 7am).
    if now.hour < int(sch.get("hour", 7) or 7):
        return False
    # Weekly reports also need the right weekday (0 = Monday).
    freq = sch.get("freq", "weekly")
    if freq == "weekly" and now.weekday() != int(sch.get("dow", 0) or 0):
        return False
    # Monthly reports also need the right day of the month.
    if freq == "monthly" and now.day != int(sch.get("dom", 1) or 1):
        return False
    return True


async def send_now(hub, tenant_id: str, cfg: Dict[str, Any]) -> None:
    """Build + send immediately (the 'Send test now' path)."""
    # Imported lazily; it is the same provider-aware sender used for hub alerts.
    import notifications as _n  # leaf, lazy — same provider-aware sender as hub alerts
    # Build the report for this tenant.
    service = SimulationsService(hub)
    subject, html = await build_report(hub, service, tenant_id, cfg)
    # Send both the HTML and a plain-text alternative.
    ok = await _n.send_email(hub, subject, _html_to_text(html),
                             to_emails=cfg.get("recipients") or [], html=html)
    # Surface a clear error so the UI can tell the user what to check.
    if not ok:
        raise RuntimeError("send failed — check Setup → Notifications "
                           "(provider enabled, From address + recipient(s) set)")


def get_reports(hub) -> List[Dict[str, Any]]:
    """The GLOBAL list of scheduled email reports. Each entry ``{id, name, tenant,
    sections, recipients, schedule, enabled, last_sent}`` carries its own target
    ``tenant`` so a Global Admin manages reports for any tenant from one list.
    Stored in ``global_config['email_reports']``."""
    # Reports live in global config; return a copy so callers can edit it freely.
    gc = hub.state.system_state.get("global_config", {}) or {}
    return list(gc.get("email_reports", []) or [])


def save_reports(hub, reports: List[Dict[str, Any]]) -> None:
    """Store the global list of email reports and mark hub state for saving."""
    # Create the global config section if missing, then replace the list.
    gc = hub.state.system_state.setdefault("global_config", {})
    gc["email_reports"] = list(reports or [])
    # Mark state dirty so the hub persists it.
    hub.state._mark_dirty()


async def _migrate_legacy(hub) -> None:
    """One-time: fold any pre-list per-tenant email_report config into the global
    list so an existing schedule isn't lost when this ships."""
    # Migration runs only once; a flag in global config records that it is done.
    gc = hub.state.system_state.setdefault("global_config", {})
    if gc.get("email_reports_migrated"):
        return
    # Start from the existing global list and note which tenants already have a report.
    store = hub.simulations_store
    reports = get_reports(hub)
    have = {r.get("tenant") for r in reports}
    # Copy each tenant's old config into the list if it had recipients and no report yet.
    try:
        for tid in store.tenant_ids():
            old = await store.get_email_report(tid)
            if isinstance(old, dict) and old.get("recipients") and tid not in have:
                # Build a global-list entry from the old per-tenant settings, with defaults.
                reports.append({
                    "id": "legacy-" + str(tid), "name": str(tid) + " dashboard",
                    "tenant": tid,
                    "sections": old.get("sections") or {"checks": True, "clients": True},
                    "recipients": old.get("recipients") or [],
                    "schedule": old.get("schedule") or {"freq": "weekly", "dow": 0, "dom": 1, "hour": 7},
                    "enabled": bool(old.get("enabled")),
                    "last_sent": old.get("last_sent"),
                })
    # Migration is best-effort; a store error must not stop the scheduler.
    except Exception:  # noqa: BLE001
        pass
    # Save the merged list and set the "migrated" flag so this never runs again.
    save_reports(hub, reports)
    gc["email_reports_migrated"] = True
    hub.state._mark_dirty()


async def run_loop(hub) -> None:
    """Fire each due report in the global list once per period. Started from main.py."""
    # Service instance reused for every report build.
    service = SimulationsService(hub)
    # Fold any legacy per-tenant configs into the global list first.
    try:
        await _migrate_legacy(hub)
    # A failed migration is logged and the loop still runs.
    except Exception as exc:  # noqa: BLE001
        logger.debug("email report migration skipped: %s", exc)
    # Run forever, checking for due reports every _POLL_S seconds.
    while True:
        try:
            # Snapshot the time and the report list for this tick.
            now = datetime.datetime.now()
            reports = get_reports(hub)
            changed = False
            # Imported lazily, same sender as hub alerts.
            import notifications as _n
            # Consider each report independently.
            for r in reports:
                try:
                    # Skip disabled reports.
                    if not r.get("enabled"):
                        continue
                    # Skip reports whose scheduled time has not arrived.
                    sch = r.get("schedule") or {}
                    if not _due(now, sch):
                        continue
                    # Skip reports already sent in this period.
                    period = _period_key(now, sch.get("freq", "weekly"))
                    if r.get("last_sent") == period:
                        continue
                    # Build and send the report for its target tenant.
                    tid = r.get("tenant") or "default"
                    subject, html = await build_report(hub, service, tid, r)
                    sent = await _n.send_email(hub, subject, _html_to_text(html),
                                               to_emails=r.get("recipients") or [], html=html)
                    # Delivery was refused (no provider/From/recipients): log and retry next tick.
                    if not sent:
                        logger.warning("email report '%s' (tenant %s) not sent "
                                       "(notifications disabled / no From / no recipients)",
                                       r.get("name"), tid)
                        continue
                    # Record the period so the report is not sent again until the next one.
                    r["last_sent"] = period
                    changed = True
                    logger.info("email report '%s' delivered (tenant %s, %s)",
                                r.get("name"), tid, period)
                # One failing report must never block the others.
                except Exception as exc:  # noqa: BLE001 — one report never blocks the rest
                    logger.warning("email report '%s' failed: %s", r.get("name"), exc)
            # Persist last_sent stamps only when something was delivered.
            if changed:
                save_reports(hub, reports)
        # Cancellation (hub shutdown) must propagate to stop the loop.
        except asyncio.CancelledError:
            raise
        # Any other error is logged and the loop keeps going.
        except Exception as exc:  # noqa: BLE001
            logger.warning("email report loop error: %s", exc)
        # Wait until the next scheduler tick.
        await asyncio.sleep(_POLL_S)
