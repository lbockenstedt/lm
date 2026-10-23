"""Cert Expiry Monitor alerting — edge-triggered breach + recovery emails.

The Cert Monitor counterpart of the Simulation module's realtime alert rules
(``alert_engine.py``): an operator defines rules (trigger + recipients +
human/raw format); one email goes out when hosts newly breach a rule and one
when they recover. A still-bad host stays silent.

Differences from the per-tenant sim engine, because Cert Monitor is a hub-wide,
Global-Admin-only feature that checks ~160 hosts that often share one cert:
  * rules are global (``global_config["cert_monitor_alerts"]["rules"]``);
  * each rule sends ONE digest per evaluation listing every newly breached /
    recovered host, not one email per host;
  * the edge state is persisted (``$LM_STATE_DIR/cert_monitor_alert_state.json``)
    so a hub restart does not re-alert every expiring cert, and a rule's state
    only advances once its email was actually sent (a failed send retries on
    the next tick).

Triggers:
  * ``expiring`` — days left < the rule's ``threshold_days`` (expired included).
  * ``error``    — the host could not be checked (DNS / timeout / handshake).
  * ``untrusted`` — the cert did not validate against the system trust store
                   (private device-CA endpoints are expected to match this).

Hosts the operator marked ignored (``cert_monitor.IGNORE_KEY``) never breach
any rule.
"""
from __future__ import annotations

import datetime as _dt
import html as _html
import json
import logging
import os
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

import cert_monitor as cm

logger = logging.getLogger("Hub")

CONFIG_KEY = "cert_monitor_alerts"
STATE_FILE = "cert_monitor_alert_state.json"
TRIGGERS = ("expiring", "error", "untrusted")
TRIGGER_LABELS = {
    "expiring": "Certificate expiring",
    "error": "Endpoint unreachable / check failed",
    "untrusted": "Certificate untrusted (chain verification failed)",
}
DEFAULT_THRESHOLD_DAYS = cm.RED_DAYS
MAX_RULES = 50
MAX_RECIPIENTS = 20
MAX_HOSTS_IN_EMAIL = 100


def service_names() -> List[str]:
    seen: List[str] = []
    for h in cm.BUILTIN_HOSTS:
        if h["service"] not in seen:
            seen.append(h["service"])
    return seen + ["Custom"]


# ── rules ───────────────────────────────────────────────────────────────────

def clean_rule(body: Dict[str, Any], existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    body = body if isinstance(body, dict) else {}
    trig = str(body.get("trigger") or "")
    trig = trig if trig in TRIGGERS else TRIGGERS[0]
    try:
        days = int(body.get("threshold_days", DEFAULT_THRESHOLD_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_THRESHOLD_DAYS
    known = set(service_names())
    services = [s for s in (body.get("services") or []) if isinstance(s, str) and s in known]
    recips = body.get("recipients") or []
    if isinstance(recips, str):
        recips = recips.replace(";", ",").split(",")
    return {
        "id": (existing or {}).get("id") or uuid.uuid4().hex[:12],
        "name": (str(body.get("name") or "").strip() or TRIGGER_LABELS[trig])[:80],
        "trigger": trig,
        "threshold_days": max(1, min(days, 825)),
        "services": sorted(set(services)),
        "recipients": [str(r).strip() for r in recips if str(r).strip()][:MAX_RECIPIENTS],
        "enabled": bool(body.get("enabled", True)),
        "format": "raw" if str(body.get("format") or "human").lower() == "raw" else "human",
    }


def get_rules(hub) -> List[Dict[str, Any]]:
    gc = hub.state.system_state.get("global_config", {}) or {}
    rules = ((gc.get(CONFIG_KEY) or {}).get("rules")) or []
    return [dict(r) for r in rules if isinstance(r, dict) and r.get("id")]


async def save_rules(hub, rules: List[Dict[str, Any]]) -> None:
    gc = hub.state.system_state.setdefault("global_config", {})
    gc[CONFIG_KEY] = {"rules": list(rules)[:MAX_RULES]}
    hub.state._mark_dirty()
    saver = getattr(hub.state, "save_state_now", None)
    if saver:
        try:
            await saver()
        except Exception as e:  # noqa: BLE001
            logger.warning("[certmon] alert rule save failed: %s", e)


# ── evaluation (pure) ───────────────────────────────────────────────────────

def item_key(r: Dict[str, Any]) -> str:
    return cm.cert_key(r)


def _in_scope(rule: Dict[str, Any], r: Dict[str, Any]) -> bool:
    svcs = rule.get("services") or []
    return not svcs or (r.get("service") or "") in svcs


def is_bad(rule: Dict[str, Any], r: Dict[str, Any]) -> Optional[bool]:
    """True/False for a host this rule can judge; None when it can't (e.g. an
    unreachable host has no days-left, so an ``expiring`` rule keeps its
    previous verdict rather than flapping to "recovered")."""
    trig = rule.get("trigger")
    if trig == "error":
        return r.get("status") == "error"
    if trig == "untrusted":
        if r.get("error") or r.get("days_left") is None:
            return None
        return not r.get("trusted")
    dl = r.get("days_left")
    if dl is None:
        return None
    return dl < int(rule.get("threshold_days") or DEFAULT_THRESHOLD_DAYS)


def evaluate_rule(rule: Dict[str, Any], results: List[Dict[str, Any]],
                  prev_bad: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """→ (newly breached results, recovered results, new bad-key list).
    Hosts no longer monitored, out of the rule's scope or ignored by the
    operator drop out silently (no recovery email)."""
    prev = set(prev_bad or [])
    breached, recovered, bad_now = [], [], set()
    for r in results or []:
        if r.get("ignored") or not _in_scope(rule, r):
            continue
        k = item_key(r)
        verdict = is_bad(rule, r)
        if verdict is None:
            if k in prev:
                bad_now.add(k)
            continue
        if verdict:
            bad_now.add(k)
            if k not in prev:
                breached.append(r)
        elif k in prev:
            recovered.append(r)
    return breached, recovered, sorted(bad_now)


# ── state ───────────────────────────────────────────────────────────────────

def state_path(state_dir: Optional[str] = None) -> str:
    return os.path.join(state_dir or cm.STATE_DIR, STATE_FILE)


def load_state(state_dir: Optional[str] = None) -> Dict[str, List[str]]:
    try:
        with open(state_path(state_dir), "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: list(v) for k, v in (data.get("bad") or {}).items() if isinstance(v, list)}
    except FileNotFoundError:
        return {}
    except Exception as e:  # noqa: BLE001
        logger.warning("[certmon] could not read %s: %s", state_path(state_dir), e)
        return {}


def save_state(bad: Dict[str, List[str]], state_dir: Optional[str] = None) -> None:
    path = state_path(state_dir)
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cert_monitor_alert_state.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"bad": bad}, f, indent=2)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reset_rule_state(rule_id: str, state_dir: Optional[str] = None) -> None:
    state = load_state(state_dir)
    if state.pop(rule_id, None) is not None:
        save_state(state, state_dir)


# ── email ───────────────────────────────────────────────────────────────────

def _esc(s: Any) -> str:
    return _html.escape(str(s if s is not None else ""), quote=False)


def _host_label(r: Dict[str, Any]) -> str:
    port = int(r.get("port") or 443)
    return f"{r.get('host', '')}" + (f":{port}" if port != 443 else "")


def _detail(rule: Dict[str, Any], r: Dict[str, Any]) -> str:
    if rule.get("trigger") == "error":
        return r.get("error") or "check failed"
    if rule.get("trigger") == "untrusted":
        return r.get("verify_error") or ("trusted" if r.get("trusted") else "untrusted")
    dl = r.get("days_left")
    if dl is None:
        return "no certificate data"
    when = (r.get("not_after") or "")[:10]
    return (f"EXPIRED {-dl} d ago" if dl < 0 else f"{dl} d left") + (f" ({when})" if when else "")


def _raw_host(rule: Dict[str, Any], r: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("host", "port", "service", "region", "role", "status", "days_left",
            "not_after", "provider", "issuer_cn", "subject_cn", "trusted", "error")
    out = {k: r.get(k) for k in keys}
    out["detail"] = _detail(rule, r)
    return out


def build_email(rule: Dict[str, Any], breached: List[Dict[str, Any]],
                recovered: List[Dict[str, Any]], ts: str = "",
                test: bool = False) -> Tuple[str, str, str]:
    """→ (subject, text body, html body). ``html`` is "" for the raw format."""
    ts = ts or _dt.datetime.now().isoformat(timespec="seconds")
    trig = rule.get("trigger") or "expiring"
    label = TRIGGER_LABELS.get(trig, trig)
    if trig == "expiring":
        label = f"{label} (< {rule.get('threshold_days')} days)"
    tag = "TEST" if test else ("ALERT" if breached else "OK")
    if rule.get("format") == "raw":
        payload = {"event": "lm_certmon_alert", "test": test, "rule": rule.get("name"),
                   "rule_id": rule.get("id"), "trigger": trig,
                   "threshold_days": rule.get("threshold_days") if trig == "expiring" else None,
                   "breached": [_raw_host(rule, r) for r in breached[:MAX_HOSTS_IN_EMAIL]],
                   "recovered": [_raw_host(rule, r) for r in recovered[:MAX_HOSTS_IN_EMAIL]],
                   "ts": ts}
        subj = (f"lm.certmon {trig} {'test' if test else ''}"
                f" breached={len(breached)} recovered={len(recovered)}").replace("  ", " ")
        return subj, json.dumps(payload, separators=(",", ":")), ""

    parts = []
    if breached:
        parts.append(f"{len(breached)} breached")
    if recovered:
        parts.append(f"{len(recovered)} recovered")
    subj = f"[LM {tag}] Cert Monitor — {label}: {', '.join(parts) or 'no matching hosts'}"

    def _text_block(title, rows):
        if not rows:
            return ""
        lines = [f"{title} ({len(rows)}):"]
        for r in rows[:MAX_HOSTS_IN_EMAIL]:
            lines.append(f"  - {_host_label(r)} [{r.get('service', '')}] {_detail(rule, r)}")
        if len(rows) > MAX_HOSTS_IN_EMAIL:
            lines.append(f"  … and {len(rows) - MAX_HOSTS_IN_EMAIL} more")
        return "\n".join(lines) + "\n"

    text = (f"Cert Monitor {label}{' (TEST)' if test else ''}\nRule: {rule.get('name')}\n"
            f"Time: {ts}\n\n" + _text_block("BREACHED", breached)
            + _text_block("RECOVERED", recovered))

    P = "font-family:Arial,Helvetica,sans-serif"
    hdr = "#c0322a" if breached else "#0f7a58"

    def _html_block(title, rows, color):
        if not rows:
            return ""
        trs = "".join(
            f'<tr><td style="padding:3px 10px 3px 0;font-family:monospace;color:#1f2937">{_esc(_host_label(r))}</td>'
            f'<td style="padding:3px 10px 3px 0;color:#6b7280">{_esc(r.get("service", ""))}'
            f'{(" · " + _esc(r.get("region"))) if r.get("region") else ""}</td>'
            f'<td style="padding:3px 0;color:{color};font-weight:bold">{_esc(_detail(rule, r))}</td></tr>'
            for r in rows[:MAX_HOSTS_IN_EMAIL])
        more = (f'<div style="{P};font-size:11px;color:#6b7280">… and {len(rows) - MAX_HOSTS_IN_EMAIL} more</div>'
                if len(rows) > MAX_HOSTS_IN_EMAIL else "")
        return (f'<div style="{P};font-size:11px;color:#6b7280;margin-top:14px;text-transform:uppercase;'
                f'letter-spacing:.04em">{_esc(title)} ({len(rows)})</div>'
                f'<table role="presentation" style="{P};font-size:12px;border-collapse:collapse;margin-top:4px">{trs}</table>{more}')

    html = (f'<div style="background:#f5f7f6;padding:20px 0;{P}">'
            f'<div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e8ecea;border-radius:10px;overflow:hidden">'
            f'<div style="padding:16px 20px;border-bottom:3px solid {hdr}">'
            f'<div style="{P};font-size:15px;font-weight:bold;color:{hdr}">Cert Monitor — {_esc(label)}{" (TEST)" if test else ""}</div>'
            f'<div style="{P};font-size:12px;color:#6b7280;margin-top:2px">Rule: {_esc(rule.get("name"))} · {_esc(ts)}</div></div>'
            f'<div style="padding:4px 20px 18px">'
            + (_html_block("Breached", breached, "#c0322a") + _html_block("Recovered", recovered, "#0f7a58")
               or f'<p style="{P};font-size:12px;color:#6b7280">No hosts currently match this rule.</p>')
            + '</div></div></div>')
    return subj, text, html


async def _send(hub, rule, subj, text, html) -> bool:
    import notifications as _n
    return await _n.send_email(hub, subj, text, to_emails=rule.get("recipients") or [],
                               html=html)


async def send_test(hub, rule: Dict[str, Any], results: List[Dict[str, Any]]) -> bool:
    """Test send: the rule's current matches, in the rule's format. No state change."""
    matches = [r for r in results or []
               if not r.get("ignored") and _in_scope(rule, r) and is_bad(rule, r)]
    subj, text, html = build_email(rule, matches, [], test=True)
    return await _send(hub, rule, subj, text, html)


async def run_alerts(hub, results: List[Dict[str, Any]],
                     state_dir: Optional[str] = None) -> Dict[str, Dict[str, int]]:
    """Evaluate every enabled rule against ``results`` (days_left already
    refreshed) and send breach/recovery digests. Returns per-rule counts."""
    rules = get_rules(hub)
    state = load_state(state_dir)
    new_state: Dict[str, List[str]] = {}
    sent: Dict[str, Dict[str, int]] = {}
    for rule in rules:
        rid = rule["id"]
        prev = state.get(rid, [])
        if not rule.get("enabled") or not rule.get("recipients"):
            new_state[rid] = prev
            continue
        breached, recovered, bad_now = evaluate_rule(rule, results, prev)
        if not breached and not recovered:
            new_state[rid] = bad_now
            continue
        subj, text, html = build_email(rule, breached, recovered)
        ok = False
        try:
            ok = await _send(hub, rule, subj, text, html)
        except Exception as e:  # noqa: BLE001
            logger.warning("[certmon] alert send failed (%s): %s", rule.get("name"), e)
        # Only advance the edge once delivered, so a failed send retries next tick.
        new_state[rid] = bad_now if ok else prev
        sent[rid] = {"breached": len(breached), "recovered": len(recovered), "sent": int(ok)}
        logger.info("[certmon] alert rule '%s': breached=%d recovered=%d sent=%s",
                    rule.get("name"), len(breached), len(recovered), ok)
    if new_state != state:
        save_state(new_state, state_dir)
    return sent
