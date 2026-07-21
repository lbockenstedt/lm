"""Scheduled email health report.

Renders the SAME data the WebUI shows on Dashboard → Checks and Client Count as
email-safe, inline-styled HTML (flexbox / <style> are stripped by many mail
clients, so everything is inline + table-based) and sends it via the tenant's own
SMTP settings (the notifications config). Per-tenant enable/disable + section
toggles + schedule live in ``store.get_email_report``. A background loop
(``run_loop``, started from main.py) fires each due report once per period.

The report is tenant-scoped: it renders only the tenant's own sites (the same
central_status the dashboard shows for that tenant).
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Tuple

from .service import SimulationsService

logger = logging.getLogger("EmailReport")

_POLL_S = 300  # scheduler tick (fires when the configured hour is reached)

# status -> (label, bg, fg) — the pill colors, matching the WebUI badges.
_PILL = {
    "ok": ("OK", "#e7f7f0", "#0f7a58"),
    "warning": ("Warning", "#fdf2df", "#9a6a06"),
    "error": ("Failing", "#fdeaea", "#c0322a"),
    "no_data": ("No data", "#eef2f1", "#5c6b65"),
}
_HCOLOR = ("#10b981", "#f59e0b", "#ef4444", "#e2e8f0")  # ok / warn / err / none
_RANK = {"error": 0, "warning": 1, "ok": 2}  # worst-first ordering


def _esc(s: Any) -> str:
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pill(status: str) -> str:
    label, bg, fg = _PILL.get(str(status).lower(), _PILL["no_data"])
    return (f'<span style="display:inline-block;font-family:Arial,sans-serif;font-size:11px;'
            f'font-weight:bold;text-transform:uppercase;color:{fg};background:{bg};'
            f'padding:2px 9px;border-radius:10px;white-space:nowrap">{label}</span>')


def _strip(daily: List[Dict[str, Any]]) -> str:
    """30-day green/yellow/red strip as a fixed cell table (email-safe)."""
    cells = ['<td style="background:#eef2f6;width:5px;height:14px;font-size:0;line-height:0">&nbsp;</td>'
             for _ in range(max(0, 30 - len(daily)))]
    for d in (daily or [])[-30:]:
        e, w, o = int(d.get("e", 0)), int(d.get("w", 0)), int(d.get("o", 0))
        idx = 2 if e else (1 if w else (0 if o else 3))
        cells.append(f'<td style="background:{_HCOLOR[idx]};width:5px;height:14px;font-size:0;line-height:0">&nbsp;</td>')
    return ('<table role="presentation" cellpadding="0" cellspacing="1" border="0" '
            f'style="border-collapse:separate"><tr>{"".join(cells)}</tr></table>')


def _num(v: Any) -> str:
    return _esc(v) if v is not None else "—"


def _pct(v: Any) -> str:
    """Success-% cell: colored green/amber/red by band, '—' when no graded samples."""
    if v is None:
        return '<span style="color:#9ca3af">—</span>'
    col = "#10b981" if v >= 99 else ("#b8860b" if v >= 95 else "#ef4444")
    n = int(v) if float(v).is_integer() else v
    return f'<span style="color:{col};font-weight:bold">{n}%</span>'


def _html_to_text(html: str) -> str:
    """Crude plain-text fallback for the multipart email (clients render the
    HTML; this is the text/plain alternative)."""
    import re as _re
    txt = _re.sub(r"<(style|script)[^>]*>.*?</\1>", " ", html or "", flags=_re.S | _re.I)
    txt = _re.sub(r"<[^>]+>", " ", txt).replace("&nbsp;", " ")
    return _re.sub(r"[ \t]*\n\s*", "\n", _re.sub(r"[ \t]{2,}", " ", txt)).strip()


async def build_report(hub, service: SimulationsService, tenant_id: str,
                       cfg: Dict[str, Any]) -> Tuple[str, str]:
    """Return (subject, html) for the tenant's report per ``cfg['sections']``."""
    sections = cfg.get("sections") or {"checks": True, "clients": True}
    tenant_name = tenant_id
    try:
        t = (hub.state.tenant_state or {}).get("tenants", {}).get(tenant_id) or {}
        tenant_name = t.get("name") or tenant_id
    except Exception:  # noqa: BLE001
        pass

    data = await service.get_central_data(tenant_id)
    checks: List[Dict[str, Any]] = []
    ccrows: List[Dict[str, Any]] = []
    for s in (data.get("spokes") or []):
        cst = s.get("central_status") or {}
        for site, cmap in (cst.get("status") or {}).items():
            for cid, info in (cmap or {}).items():
                if isinstance(info, dict):
                    checks.append({"site": site, "check": cid,
                                   "status": str(info.get("status") or "no_data").lower()})
        for site, entry in (cst.get("client_count_status") or {}).items():
            if isinstance(entry, dict):
                ccrows.append({"site": site, **entry})

    # 30-day health (centralized hub poller + relayed distributed spokes)
    health: Dict[str, Dict[str, Any]] = {}
    success: Dict[str, Dict[str, Any]] = {}
    hh = getattr(getattr(hub, "central_hub_poller", None), "_health", None)
    if hh is not None:
        try:
            health = dict(hh.summary(tenant_id) or {})
        except Exception:  # noqa: BLE001
            health = {}
        try:
            success = dict(hh.success_stats(tenant_id) or {})
        except Exception:  # noqa: BLE001
            success = {}
    for _sid, sd in service._spokes_for_tenant(tenant_id):
        sp = ((sd or {}).get("central") or {}).get("health") or {}
        for site, cm in sp.items():
            health.setdefault(site, {}).update(cm)
    # Success-% per check over 24h·7d·4w. Centralized = hourly-accurate; distributed
    # checks (daily-only) fall back to their daily buckets so every row gets a score.
    from .central_hub_poller import success_from_daily
    for site, cm in health.items():
        for cid, dlist in (cm or {}).items():
            if success.get(site, {}).get(cid) is None:
                success.setdefault(site, {})[cid] = success_from_daily(dlist)

    checks.sort(key=lambda r: (_RANK.get(r["status"], 3), r["site"], r["check"]))
    n_fail = sum(1 for c in checks if c["status"] == "error")
    n_warn = sum(1 for c in checks if c["status"] == "warning")
    n_ok = sum(1 for c in checks if c["status"] == "ok")
    n_clients = sum(int(r.get("current") or 0) for r in ccrows)
    today = datetime.datetime.now().strftime("%a, %b %d, %Y")

    # ── HTML (inline styles only) ──────────────────────────────────────────
    P = 'font-family:Arial,Helvetica,sans-serif'
    th = f'style="{P};font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;font-weight:bold;text-align:left;padding:6px 8px;border-bottom:1px solid #e8ecea"'
    td = f'style="{P};font-size:12px;color:#1f2937;padding:8px;border-bottom:1px solid #f0f2f1"'
    tdn = f'style="{P};font-size:12px;color:#1f2937;padding:8px;border-bottom:1px solid #f0f2f1;text-align:right"'

    parts: List[str] = []
    parts.append(f'''
<div style="background:#f5f7f6;padding:20px 0;{P}">
 <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e8ecea;border-radius:10px;overflow:hidden">
  <div style="padding:20px 22px 16px;border-bottom:3px solid #01A982">
   <table role="presentation" width="100%"><tr>
     <td style="{P};font-size:15px;font-weight:bold;color:#1f2937">◈ LM Health Report</td>
     <td style="{P};font-size:11px;color:#6b7280;text-align:right">30 days ending<br><b>{today}</b></td>
   </tr></table>
   <div style="{P};font-size:19px;font-weight:bold;color:#1f2937;margin-top:12px">Simulation health — {_esc(tenant_name)}</div>
   <div style="{P};font-size:12px;color:#6b7280;margin-top:2px">{len(ccrows)} site(s) monitored</div>
  </div>
  <table role="presentation" width="100%" style="background:#f5f7f6;border-bottom:1px solid #e8ecea"><tr>
    <td style="padding:14px 22px">
      {_stat(n_fail, "Failing", "#ef4444")}{_stat(n_warn, "Warning", "#b8860b")}{_stat(n_ok, "OK", "#10b981")}{_stat(n_clients, "Clients", "#1f2937")}
    </td>
  </tr></table>''')

    if sections.get("checks", True):
        rows = []
        for c in checks:
            daily = ((health.get(c["site"]) or {}).get(c["check"])) or []
            sx = ((success.get(c["site"]) or {}).get(c["check"])) or {}
            rows.append(f'<tr><td {td}><span style="font-family:monospace;font-size:11px;color:#374151">{_esc(c["site"])}</span></td>'
                        f'<td {td}>{_esc(c["check"])}</td><td {td}>{_pill(c["status"])}</td>'
                        f'<td {tdn}>{_pct(sx.get("h24"))}</td><td {tdn}>{_pct(sx.get("d7"))}</td><td {tdn}>{_pct(sx.get("w4"))}</td>'
                        f'<td {td}>{_strip(daily)}</td></tr>')
        parts.append(f'''
  <div style="padding:18px 22px 8px">
   <div style="{P};font-size:13px;font-weight:bold;color:#1f2937;margin-bottom:8px">Dashboard Checks
     <span style="font-weight:normal;color:#6b7280;font-size:11px">· {len(checks)} monitored · worst first · % = polls OK</span></div>
   <table role="presentation" width="100%" style="border-collapse:collapse">
     <tr><th {th}>Site</th><th {th}>Check</th><th {th}>Status</th><th {th} style="text-align:right">24h</th><th {th} style="text-align:right">7d</th><th {th} style="text-align:right">4w</th><th {th}>30-day trend</th></tr>
     {"".join(rows) or f'<tr><td {td} colspan="7">No checks reported.</td></tr>'}
   </table>
   <div style="{P};font-size:10px;color:#6b7280;padding:8px 0 4px">
     <span style="color:#10b981">■</span> firing (healthy) &nbsp; <span style="color:#f59e0b">■</span> degraded &nbsp;
     <span style="color:#ef4444">■</span> not detected &nbsp; <span style="color:#cbd5e1">■</span> no data</div>
  </div>''')

    if sections.get("clients", True):
        rows = []
        for r in sorted(ccrows, key=lambda x: x.get("site_name") or x.get("site") or ""):
            drop = r.get("drop_pct")
            dcol = "#b8860b" if (drop or 0) > 0 else "#6b7280"
            rows.append(
                f'<tr><td {td}><span style="font-family:monospace;font-size:11px;color:#374151">{_esc(r.get("site_name") or r.get("site"))}</span></td>'
                f'<td {td}>{_pill(r.get("status") or "no_data")}</td>'
                f'<td {tdn}><b>{_num(r.get("current"))}</b></td><td {tdn}>{_num(r.get("wired"))}</td>'
                f'<td {tdn}>{_num(r.get("wireless"))}</td><td {tdn}>{_num(r.get("hourly_avg"))}</td>'
                f'<td style="{P};font-size:12px;color:{dcol};padding:8px;border-bottom:1px solid #f0f2f1;text-align:right">{_num(drop)}{"%" if drop is not None else ""}</td>'
                f'<td {tdn}>{_num(r.get("max_7day"))}</td><td {tdn}>{_num(r.get("max_30day"))}</td></tr>')
        parts.append(f'''
  <div style="padding:8px 22px 8px">
   <div style="{P};font-size:13px;font-weight:bold;color:#1f2937;margin-bottom:8px">Client Count
     <span style="font-weight:normal;color:#6b7280;font-size:11px">· per site · last poll</span></div>
   <table role="presentation" width="100%" style="border-collapse:collapse">
     <tr><th {th}>Site</th><th {th}>Status</th><th {th} style="text-align:right">Current</th><th {th} style="text-align:right">Wired</th>
       <th {th} style="text-align:right">Wireless</th><th {th} style="text-align:right">Hourly avg</th>
       <th {th} style="text-align:right">Drop</th><th {th} style="text-align:right">7d peak</th><th {th} style="text-align:right">30d peak</th></tr>
     {"".join(rows) or f'<tr><td {td} colspan="9">No client-count data.</td></tr>'}
   </table>
  </div>''')

    parts.append(f'''
  <div style="padding:14px 22px 20px;border-top:1px solid #f0f2f1;background:#f5f7f6;{P};font-size:11px;color:#6b7280">
    Sent by <b>LM</b> because Email Reports is on for your tenant · manage in Setup → Notifications.
  </div>
 </div>
</div>''')

    subject = f"LM Health Report — {tenant_name} — {n_fail} failing, {n_warn} warning"
    return subject, "".join(parts)


def _stat(n: Any, label: str, color: str) -> str:
    return (f'<span style="display:inline-block;background:#ffffff;border:1px solid #e8ecea;border-radius:8px;'
            f'padding:8px 12px;margin-right:8px;font-family:Arial,sans-serif">'
            f'<span style="font-size:18px;font-weight:bold;color:{color}">{_esc(n)}</span>'
            f'<span style="font-size:10px;text-transform:uppercase;color:#6b7280;display:block;margin-top:2px">{label}</span></span>')


def send_report(notif: Dict[str, Any], recipients: List[str], subject: str, html: str) -> None:
    """Send the report HTML via the tenant's SMTP (notifications config). Raises on
    failure so the caller can log + retry next period."""
    to_addrs = [a.strip() for a in (recipients or []) if a and a.strip()]
    if not to_addrs:
        raise ValueError("no recipients configured")
    host = notif.get("smtp_host") or ""
    if not host:
        raise ValueError("SMTP not configured (Setup → Notifications)")
    sender = notif.get("smtp_from") or notif.get("smtp_user") or "lm-report@localhost"
    msg = MIMEMultipart("alternative")
    msg["From"] = sender
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    msg.attach(MIMEText("Your mail client can't show HTML — view this report in the LM WebUI.", "plain"))
    msg.attach(MIMEText(html, "html"))
    port = int(notif.get("smtp_port", 587) or 587)
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.ehlo()
        if port != 25:
            try:
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass
        user, pwd = notif.get("smtp_user") or "", notif.get("smtp_password") or ""
        if user and pwd:
            smtp.login(user, pwd)
        smtp.sendmail(sender, to_addrs, msg.as_string())
    logger.info("email report sent to %s", to_addrs)


def _period_key(now: datetime.datetime, freq: str) -> str:
    if freq == "daily":
        return now.strftime("%Y-%m-%d")
    if freq == "monthly":
        return now.strftime("%Y-%m")
    iso = now.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"  # weekly


def _due(now: datetime.datetime, sch: Dict[str, Any]) -> bool:
    if now.hour < int(sch.get("hour", 7) or 7):
        return False
    freq = sch.get("freq", "weekly")
    if freq == "weekly" and now.weekday() != int(sch.get("dow", 0) or 0):
        return False
    if freq == "monthly" and now.day != int(sch.get("dom", 1) or 1):
        return False
    return True


async def send_now(hub, tenant_id: str, cfg: Dict[str, Any]) -> None:
    """Build + send immediately (the 'Send test now' path)."""
    import notifications as _n  # leaf, lazy — same provider-aware sender as hub alerts
    service = SimulationsService(hub)
    subject, html = await build_report(hub, service, tenant_id, cfg)
    ok = await _n.send_email(hub, subject, _html_to_text(html),
                             to_emails=cfg.get("recipients") or [], html=html)
    if not ok:
        raise RuntimeError("send failed — check Setup → Notifications "
                           "(provider enabled, From address + recipient(s) set)")


def get_reports(hub) -> List[Dict[str, Any]]:
    """The GLOBAL list of scheduled email reports. Each entry ``{id, name, tenant,
    sections, recipients, schedule, enabled, last_sent}`` carries its own target
    ``tenant`` so a Global Admin manages reports for any tenant from one list.
    Stored in ``global_config['email_reports']``."""
    gc = hub.state.system_state.get("global_config", {}) or {}
    return list(gc.get("email_reports", []) or [])


def save_reports(hub, reports: List[Dict[str, Any]]) -> None:
    gc = hub.state.system_state.setdefault("global_config", {})
    gc["email_reports"] = list(reports or [])
    hub.state._mark_dirty()


async def _migrate_legacy(hub) -> None:
    """One-time: fold any pre-list per-tenant email_report config into the global
    list so an existing schedule isn't lost when this ships."""
    gc = hub.state.system_state.setdefault("global_config", {})
    if gc.get("email_reports_migrated"):
        return
    store = hub.simulations_store
    reports = get_reports(hub)
    have = {r.get("tenant") for r in reports}
    try:
        for tid in store.tenant_ids():
            old = await store.get_email_report(tid)
            if isinstance(old, dict) and old.get("recipients") and tid not in have:
                reports.append({
                    "id": "legacy-" + str(tid), "name": str(tid) + " dashboard",
                    "tenant": tid,
                    "sections": old.get("sections") or {"checks": True, "clients": True},
                    "recipients": old.get("recipients") or [],
                    "schedule": old.get("schedule") or {"freq": "weekly", "dow": 0, "dom": 1, "hour": 7},
                    "enabled": bool(old.get("enabled")),
                    "last_sent": old.get("last_sent"),
                })
    except Exception:  # noqa: BLE001
        pass
    save_reports(hub, reports)
    gc["email_reports_migrated"] = True
    hub.state._mark_dirty()


async def run_loop(hub) -> None:
    """Fire each due report in the global list once per period. Started from main.py."""
    service = SimulationsService(hub)
    try:
        await _migrate_legacy(hub)
    except Exception as exc:  # noqa: BLE001
        logger.debug("email report migration skipped: %s", exc)
    while True:
        try:
            now = datetime.datetime.now()
            reports = get_reports(hub)
            changed = False
            import notifications as _n
            for r in reports:
                try:
                    if not r.get("enabled"):
                        continue
                    sch = r.get("schedule") or {}
                    if not _due(now, sch):
                        continue
                    period = _period_key(now, sch.get("freq", "weekly"))
                    if r.get("last_sent") == period:
                        continue
                    tid = r.get("tenant") or "default"
                    subject, html = await build_report(hub, service, tid, r)
                    sent = await _n.send_email(hub, subject, _html_to_text(html),
                                               to_emails=r.get("recipients") or [], html=html)
                    if not sent:
                        logger.warning("email report '%s' (tenant %s) not sent "
                                       "(notifications disabled / no From / no recipients)",
                                       r.get("name"), tid)
                        continue
                    r["last_sent"] = period
                    changed = True
                    logger.info("email report '%s' delivered (tenant %s, %s)",
                                r.get("name"), tid, period)
                except Exception as exc:  # noqa: BLE001 — one report never blocks the rest
                    logger.warning("email report '%s' failed: %s", r.get("name"), exc)
            if changed:
                save_reports(hub, reports)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("email report loop error: %s", exc)
        await asyncio.sleep(_POLL_S)
