"""Cert Expiry Monitor alerting — breach, reminder and recovery emails.

The Cert Monitor counterpart of the Simulation module's realtime alert rules
(``alert_engine.py``): an operator defines rules (trigger + recipients +
human/raw format); one email goes out when hosts newly breach a rule and one
when they recover. A still-bad host is reminded about on the rule's schedule:
  * ``repeat_hours`` — re-send every N hours while the host stays bad
    (0 = never, i.e. one email per breach);
  * ``reminders`` (``expiring`` rules only) — an escalation ladder of
    ``{"days": D, "every_hours": H}`` steps: once fewer than D days are left
    (0 = expired) remind every H hours (0 = just once on entering the step).
    The most urgent matching step wins, and entering a more urgent step sends
    a reminder right away.

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
# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# datetime supplies timestamps for emails and reminder timing.
import datetime as _dt
# html.escape makes host names/details safe to embed in the HTML email.
import html as _html
# json reads/writes the persisted alert state and the raw-format email body.
import json
# Standard-library logging for send/save problems.
import logging
# os builds the state file path and does atomic file replacement.
import os
# tempfile creates a unique temp file next to the state file for atomic writes.
import tempfile
# uuid generates ids for new rules.
import uuid
# Type hints only.
from typing import Any, Dict, List, Optional, Tuple

# The Cert Monitor itself: host list, thresholds, state dir and cert keys.
import cert_monitor as cm

# Use the hub's main logger so [certmon] lines appear with other hub output.
logger = logging.getLogger("Hub")

# global_config key under which the alert rules are stored.
CONFIG_KEY = "cert_monitor_alerts"
# File (in the state dir) holding which hosts are bad per rule and when they were emailed.
STATE_FILE = "cert_monitor_alert_state.json"
# Trigger types a rule can use.
TRIGGERS = ("expiring", "error", "untrusted")
# Human-readable title for each trigger, used in subjects and default rule names.
TRIGGER_LABELS = {
    "expiring": "Certificate expiring",
    "error": "Endpoint unreachable / check failed",
    "untrusted": "Certificate untrusted (chain verification failed)",
}
# Default "expiring" threshold: the monitor's own red (critical) days-left level.
DEFAULT_THRESHOLD_DAYS = cm.RED_DAYS
# Safety caps: rules, recipients per rule, hosts listed per email, ladder steps, repeat hours.
MAX_RULES = 50
MAX_RECIPIENTS = 20
MAX_HOSTS_IN_EMAIL = 100
MAX_REMINDER_STEPS = 10
MAX_REPEAT_HOURS = 24 * 30
# Alerts are evaluated every 15 min; send a reminder that is due within this
# slack now rather than a whole tick late, so "every 24h" doesn't drift.
REMINDER_SLACK_S = 10 * 60


def service_names() -> List[str]:
    """Return the distinct service names of the built-in hosts, plus "Custom", in first-seen
    order.
    """
    # Unique service names in first-seen order.
    seen: List[str] = []
    for h in cm.BUILTIN_HOSTS:
        if h["service"] not in seen:
            seen.append(h["service"])
    # "Custom" covers hosts the operator added by hand.
    return seen + ["Custom"]


# ── rules ───────────────────────────────────────────────────────────────────

def _int(v, default: int, lo: int, hi: int) -> int:
    """Return ``v`` as an int clamped to [lo, hi], or ``default`` if it is not a number."""
    # Clamp to the allowed range; non-numbers fall back to the default.
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default


def clean_reminders(steps: Any) -> List[Dict[str, int]]:
    """Validated escalation ladder, least urgent (most days) first, one step per day count."""
    # days -> every_hours; a later duplicate day count overwrites an earlier one.
    out: Dict[int, int] = {}
    # Walk the supplied steps (anything but a list is treated as empty).
    for st in steps if isinstance(steps, list) else []:
        # Skip malformed steps and steps without a day count.
        if not isinstance(st, dict) or st.get("days") in (None, ""):
            continue
        # Clamp days (negative = already expired) and the repeat interval.
        days = _int(st.get("days"), 0, -365, 825)
        out[days] = _int(st.get("every_hours"), 0, 0, MAX_REPEAT_HOURS)
    # Sort most-days first and cap the ladder length.
    ladder = [{"days": d, "every_hours": h} for d, h in sorted(out.items(), reverse=True)]
    return ladder[:MAX_REMINDER_STEPS]


def clean_rule(body: Dict[str, Any], existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate an incoming rule body into a clean rule dict (keeping ``existing``'s id on edit)."""
    # Treat a non-dict body as empty.
    body = body if isinstance(body, dict) else {}
    # Trigger must be one of TRIGGERS; default to "expiring".
    trig = str(body.get("trigger") or "")
    trig = trig if trig in TRIGGERS else TRIGGERS[0]
    # Threshold days; fall back to the default if not a number.
    try:
        days = int(body.get("threshold_days", DEFAULT_THRESHOLD_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_THRESHOLD_DAYS
    # Only accept service names the monitor actually knows.
    known = set(service_names())
    services = [s for s in (body.get("services") or []) if isinstance(s, str) and s in known]
    # Recipients may come as a list or a comma/semicolon separated string.
    recips = body.get("recipients") or []
    if isinstance(recips, str):
        recips = recips.replace(";", ",").split(",")
    # Build the clean rule with defaults and limits applied.
    return {
        "id": (existing or {}).get("id") or uuid.uuid4().hex[:12],
        "name": (str(body.get("name") or "").strip() or TRIGGER_LABELS[trig])[:80],
        "trigger": trig,
        "threshold_days": max(1, min(days, 825)),
        "services": sorted(set(services)),
        "recipients": [str(r).strip() for r in recips if str(r).strip()][:MAX_RECIPIENTS],
        "enabled": bool(body.get("enabled", True)),
        "format": "raw" if str(body.get("format") or "human").lower() == "raw" else "human",
        "repeat_hours": _int(body.get("repeat_hours"), 0, 0, MAX_REPEAT_HOURS),
        "reminders": clean_reminders(body.get("reminders")) if trig == "expiring" else [],
    }


def get_rules(hub) -> List[Dict[str, Any]]:
    """Return copies of all stored alert rules that have an id."""
    # Read the rules list from global_config.
    gc = hub.state.system_state.get("global_config", {}) or {}
    rules = ((gc.get(CONFIG_KEY) or {}).get("rules")) or []
    # Copy each valid rule so callers cannot mutate stored state by accident.
    return [dict(r) for r in rules if isinstance(r, dict) and r.get("id")]


async def save_rules(hub, rules: List[Dict[str, Any]]) -> None:
    """Store ``rules`` (capped) in global_config and persist hub state immediately."""
    # Replace the rules list.
    gc = hub.state.system_state.setdefault("global_config", {})
    gc[CONFIG_KEY] = {"rules": list(rules)[:MAX_RULES]}
    # Mark state changed, then save right away if the state supports it.
    hub.state._mark_dirty()
    saver = getattr(hub.state, "save_state_now", None)
    if saver:
        # A save failure is logged; the in-memory rules still apply.
        try:
            await saver()
        except Exception as e:  # noqa: BLE001
            logger.warning("[certmon] alert rule save failed: %s", e)


# ── evaluation (pure) ───────────────────────────────────────────────────────

def item_key(r: Dict[str, Any]) -> str:
    """Return the stable key identifying a monitored host (same key the monitor uses)."""
    return cm.cert_key(r)


def _in_scope(rule: Dict[str, Any], r: Dict[str, Any]) -> bool:
    """Return True if host result ``r`` falls within the rule's service filter (empty = all)."""
    # No service filter means the rule applies to every host.
    svcs = rule.get("services") or []
    return not svcs or (r.get("service") or "") in svcs


def is_bad(rule: Dict[str, Any], r: Dict[str, Any]) -> Optional[bool]:
    """True/False for a host this rule can judge; None when it can't (e.g. an
    unreachable host has no days-left, so an ``expiring`` rule keeps its
    previous verdict rather than flapping to "recovered")."""
    # Which trigger this rule uses.
    trig = rule.get("trigger")
    # "error" rules: bad when the host check failed.
    if trig == "error":
        return r.get("status") == "error"
    # "untrusted" rules: undecidable without cert data; bad when the chain did not verify.
    if trig == "untrusted":
        if r.get("error") or r.get("days_left") is None:
            return None
        return not r.get("trusted")
    # "expiring" rules: undecidable without days-left; bad when under the threshold.
    dl = r.get("days_left")
    if dl is None:
        return None
    return dl < int(rule.get("threshold_days") or DEFAULT_THRESHOLD_DAYS)


def evaluate_rule(rule: Dict[str, Any], results: List[Dict[str, Any]],
                  prev_bad: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """→ (newly breached results, recovered results, new bad-key list).
    Hosts no longer monitored, out of the rule's scope or ignored by the
    operator drop out silently (no recovery email)."""
    # Hosts that were bad before.
    prev = set(prev_bad or [])
    # Accumulators for this evaluation.
    breached, recovered, bad_now = [], [], set()
    # Judge each host result.
    for r in results or []:
        # Ignored, deprecated or out-of-scope hosts are skipped entirely.
        if r.get("ignored") or r.get("deprecated") or not _in_scope(rule, r):
            continue
        # Host key and verdict.
        k = item_key(r)
        verdict = is_bad(rule, r)
        # Undecidable: keep its previous bad/ok state.
        if verdict is None:
            if k in prev:
                bad_now.add(k)
            continue
        # Bad now: note it, and report it as newly breached if it was not bad before.
        if verdict:
            bad_now.add(k)
            if k not in prev:
                breached.append(r)
        # Good now but bad before: it recovered.
        elif k in prev:
            recovered.append(r)
    # Return the edges and the sorted current bad list.
    return breached, recovered, sorted(bad_now)


def reminder_step(rule: Dict[str, Any], r: Dict[str, Any]) -> Tuple[Optional[int], int]:
    """→ (step days or None, repeat every N hours) for a host that breaches
    ``rule``: the most urgent ladder step it is in, else the rule's repeat."""
    # Days left on the cert (None if unknown).
    dl = r.get("days_left")
    # Expiring rules: find the most urgent ladder step (fewest days) the host is inside.
    if rule.get("trigger") == "expiring" and dl is not None:
        for st in sorted(rule.get("reminders") or [], key=lambda s: s["days"]):
            if dl < st["days"]:
                return st["days"], st["every_hours"]
    # Otherwise use the rule's flat repeat interval.
    return None, int(rule.get("repeat_hours") or 0)


def due_reminders(rule: Dict[str, Any], results: List[Dict[str, Any]], prev_bad: List[str],
                  sent: Dict[str, List[Any]], now: float) -> List[Dict[str, Any]]:
    """Hosts that were already bad, still are, and are due a reminder: their
    repeat interval has passed since the last email, or they moved into a
    more urgent ladder step. ``sent`` maps host key → [last email ts, step]."""
    # Hosts that were bad last time.
    prev = set(prev_bad or [])
    # Hosts due a reminder.
    due = []
    # Check each host result.
    for r in results or []:
        # Skip ignored/deprecated/out-of-scope hosts and those not currently bad.
        if r.get("ignored") or r.get("deprecated") or not _in_scope(rule, r) or not is_bad(rule, r):
            continue
        # Host key.
        k = item_key(r)
        if k not in prev:
            continue  # a new breach, reported as such
        # Current ladder step and repeat interval for this host.
        step, every = reminder_step(rule, r)
        # When we last emailed about it and at which step.
        last_ts, last_step = (sent.get(k) or [None, None])[:2]
        # Never emailed (e.g. state from an older version): remind if any schedule applies.
        if last_ts is None:
            if every or step is not None:
                due.append(r)
            continue
        # Escalated: entered a more urgent (fewer-days) step than last time.
        escalated = step is not None and (last_step is None or step < last_step)
        # Repeat: the interval has elapsed (with slack so it does not drift a whole tick late).
        repeat = every > 0 and now - float(last_ts) >= every * 3600 - REMINDER_SLACK_S
        # Either reason makes it due.
        if escalated or repeat:
            due.append(r)
    # Return the due hosts.
    return due


# ── state ───────────────────────────────────────────────────────────────────

def state_path(state_dir: Optional[str] = None) -> str:
    """Return the full path of the alert state file."""
    # Defaults to the Cert Monitor's state directory.
    return os.path.join(state_dir or cm.STATE_DIR, STATE_FILE)


def _load_file(state_dir: Optional[str] = None) -> Dict[str, Any]:
    """Read the alert state file; returns {} if missing or unreadable."""
    # Parse the JSON file; only a dict is accepted.
    try:
        with open(state_path(state_dir), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    # No file yet: empty state.
    except FileNotFoundError:
        return {}
    # Corrupt/unreadable: warn and start empty.
    except Exception as e:  # noqa: BLE001
        logger.warning("[certmon] could not read %s: %s", state_path(state_dir), e)
        return {}


def load_state(state_dir: Optional[str] = None) -> Dict[str, List[str]]:
    """rule id → keys of the hosts currently breaching it."""
    # The "bad" section of the state file.
    bad = _load_file(state_dir).get("bad") or {}
    # Keep only list values (copied).
    return {k: list(v) for k, v in bad.items() if isinstance(v, list)}


def load_sent(state_dir: Optional[str] = None) -> Dict[str, Dict[str, List[Any]]]:
    """rule id → host key → [ts of the last email about it, ladder step]."""
    # The "sent" section of the state file.
    sent = _load_file(state_dir).get("sent") or {}
    # Keep only dict values (copied).
    return {k: dict(v) for k, v in sent.items() if isinstance(v, dict)}


def save_state(bad: Dict[str, List[str]], state_dir: Optional[str] = None,
               sent: Optional[Dict[str, Dict[str, List[Any]]]] = None) -> None:
    """Atomically write the bad-host lists and email timestamps to the state file."""
    # If not given, keep the previously saved "sent" records.
    if sent is None:
        sent = load_sent(state_dir)
    # Only hosts that are still bad need a "last emailed" record.
    sent = {rid: {k: v for k, v in hosts.items() if k in set(bad.get(rid) or [])}
            for rid, hosts in sent.items() if rid in bad}
    # Drop rules left with no records.
    sent = {rid: hosts for rid, hosts in sent.items() if hosts}
    # Make sure the state directory exists.
    path = state_path(state_dir)
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    # Unique temp file in the same directory so the final rename is atomic.
    fd, tmp = tempfile.mkstemp(prefix=".cert_monitor_alert_state.", dir=d)
    # Write, restrict permissions, then atomically replace the old file.
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"bad": bad, "sent": sent}, f, indent=2)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    # On any failure remove the temp file, then re-raise.
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reset_rule_state(rule_id: str, state_dir: Optional[str] = None) -> None:
    """Forget a rule's bad-host list (e.g. after it is edited or deleted)."""
    # Load, remove the rule's entry, and save only if something was removed.
    state = load_state(state_dir)
    if state.pop(rule_id, None) is not None:
        save_state(state, state_dir)


# ── email ───────────────────────────────────────────────────────────────────

def _esc(s: Any) -> str:
    """HTML-escape a value (None becomes "") for safe embedding in the email."""
    # quote=False: only &, < and > need escaping in element text.
    return _html.escape(str(s if s is not None else ""), quote=False)


def _host_label(r: Dict[str, Any]) -> str:
    """Return "host" or "host:port" (port shown only when not 443)."""
    # Default HTTPS port is 443.
    port = int(r.get("port") or 443)
    return f"{r.get('host', '')}" + (f":{port}" if port != 443 else "")


def _detail(rule: Dict[str, Any], r: Dict[str, Any]) -> str:
    """Return a short human-readable reason why this host matches the rule."""
    # Error rules: show the check error.
    if rule.get("trigger") == "error":
        return r.get("error") or "check failed"
    # Untrusted rules: show the verification error.
    if rule.get("trigger") == "untrusted":
        return r.get("verify_error") or ("trusted" if r.get("trusted") else "untrusted")
    # Expiring rules: show days left (or how long ago it expired) and the expiry date.
    dl = r.get("days_left")
    if dl is None:
        return "no certificate data"
    when = (r.get("not_after") or "")[:10]
    return (f"EXPIRED {-dl} d ago" if dl < 0 else f"{dl} d left") + (f" ({when})" if when else "")


def _raw_host(rule: Dict[str, Any], r: Dict[str, Any]) -> Dict[str, Any]:
    """Return the selected fields of a host result for the raw (JSON) email format."""
    # Fields copied into the raw payload.
    keys = ("host", "port", "service", "region", "role", "status", "days_left",
            "not_after", "provider", "issuer_cn", "subject_cn", "trusted", "error")
    # Copy them and add the human-readable detail.
    out = {k: r.get(k) for k in keys}
    out["detail"] = _detail(rule, r)
    return out


def build_email(rule: Dict[str, Any], breached: List[Dict[str, Any]],
                recovered: List[Dict[str, Any]], ts: str = "",
                test: bool = False,
                reminders: Optional[List[Dict[str, Any]]] = None) -> Tuple[str, str, str]:
    """→ (subject, text body, html body). ``html`` is "" for the raw format.
    ``reminders`` are hosts that were already reported and are still bad."""
    # Normalise inputs and pick a timestamp.
    reminders = reminders or []
    ts = ts or _dt.datetime.now().isoformat(timespec="seconds")
    # Trigger and its human label (with the threshold for expiring rules).
    trig = rule.get("trigger") or "expiring"
    label = TRIGGER_LABELS.get(trig, trig)
    if trig == "expiring":
        label = f"{label} (< {rule.get('threshold_days')} days)"
    # Subject tag: TEST, ALERT (new breaches), REMINDER, or OK (only recoveries).
    tag = "TEST" if test else ("ALERT" if breached else ("REMINDER" if reminders else "OK"))
    # Raw format: machine-readable JSON body, no HTML.
    if rule.get("format") == "raw":
        payload = {"event": "lm_certmon_alert", "test": test, "rule": rule.get("name"),
                   "rule_id": rule.get("id"), "trigger": trig,
                   "threshold_days": rule.get("threshold_days") if trig == "expiring" else None,
                   "breached": [_raw_host(rule, r) for r in breached[:MAX_HOSTS_IN_EMAIL]],
                   "recovered": [_raw_host(rule, r) for r in recovered[:MAX_HOSTS_IN_EMAIL]],
                   "reminder": [_raw_host(rule, r) for r in reminders[:MAX_HOSTS_IN_EMAIL]],
                   "ts": ts}
        subj = (f"lm.certmon {trig} {'test' if test else ''}"
                f" breached={len(breached)} recovered={len(recovered)}"
                f"{f' reminder={len(reminders)}' if reminders else ''}").replace("  ", " ")
        return subj, json.dumps(payload, separators=(",", ":")), ""

    # Human format: summarise the counts in the subject.
    parts = []
    if breached:
        parts.append(f"{len(breached)} breached")
    if reminders:
        parts.append(f"{len(reminders)} still bad")
    if recovered:
        parts.append(f"{len(recovered)} recovered")
    subj = f"[LM {tag}] Cert Monitor — {label}: {', '.join(parts) or 'no matching hosts'}"

    def _text_block(title, rows):
        """Return a plain-text section listing ``rows`` under ``title`` ("" if empty)."""
        # Empty sections are omitted.
        if not rows:
            return ""
        # Heading line, then one line per host (capped), then an "and N more" line if needed.
        lines = [f"{title} ({len(rows)}):"]
        for r in rows[:MAX_HOSTS_IN_EMAIL]:
            lines.append(f"  - {_host_label(r)} [{r.get('service', '')}] {_detail(rule, r)}")
        if len(rows) > MAX_HOSTS_IN_EMAIL:
            lines.append(f"  … and {len(rows) - MAX_HOSTS_IN_EMAIL} more")
        # Join the lines into one block.
        return "\n".join(lines) + "\n"

    # Assemble the plain-text body from its sections.
    text = (f"Cert Monitor {label}{' (TEST)' if test else ''}\nRule: {rule.get('name')}\n"
            f"Time: {ts}\n\n" + _text_block("BREACHED", breached)
            + _text_block("STILL BAD (reminder)", reminders)
            + _text_block("RECOVERED", recovered))

    # Shared inline CSS font stack (email clients ignore stylesheets).
    P = "font-family:Arial,Helvetica,sans-serif"
    # Header colour: red if anything is bad, green if only recoveries.
    hdr = "#c0322a" if (breached or reminders) else "#0f7a58"

    def _html_block(title, rows, color):
        """Return an HTML section listing ``rows`` under ``title`` with detail text in ``color``."""
        # Empty sections are omitted.
        if not rows:
            return ""
        # One table row per host (capped): host, service/region, detail.
        trs = "".join(
            f'<tr><td style="padding:3px 10px 3px 0;font-family:monospace;color:#1f2937">{_esc(_host_label(r))}</td>'
            f'<td style="padding:3px 10px 3px 0;color:#6b7280">{_esc(r.get("service", ""))}'
            f'{(" · " + _esc(r.get("region"))) if r.get("region") else ""}</td>'
            f'<td style="padding:3px 0;color:{color};font-weight:bold">{_esc(_detail(rule, r))}</td></tr>'
            for r in rows[:MAX_HOSTS_IN_EMAIL])
        # "and N more" note when the list was capped.
        more = (f'<div style="{P};font-size:11px;color:#6b7280">… and {len(rows) - MAX_HOSTS_IN_EMAIL} more</div>'
                if len(rows) > MAX_HOSTS_IN_EMAIL else "")
        # Section heading followed by the table.
        return (f'<div style="{P};font-size:11px;color:#6b7280;margin-top:14px;text-transform:uppercase;'
                f'letter-spacing:.04em">{_esc(title)} ({len(rows)})</div>'
                f'<table role="presentation" style="{P};font-size:12px;border-collapse:collapse;margin-top:4px">{trs}</table>{more}')

    # Assemble the full HTML email (a placeholder paragraph if no sections).
    html = (f'<div style="background:#f5f7f6;padding:20px 0;{P}">'
            f'<div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e8ecea;border-radius:10px;overflow:hidden">'
            f'<div style="padding:16px 20px;border-bottom:3px solid {hdr}">'
            f'<div style="{P};font-size:15px;font-weight:bold;color:{hdr}">Cert Monitor — {_esc(label)}{" (TEST)" if test else ""}</div>'
            f'<div style="{P};font-size:12px;color:#6b7280;margin-top:2px">Rule: {_esc(rule.get("name"))} · {_esc(ts)}</div></div>'
            f'<div style="padding:4px 20px 18px">'
            + (_html_block("Breached", breached, "#c0322a")
               + _html_block("Still bad (reminder)", reminders, "#c0322a")
               + _html_block("Recovered", recovered, "#0f7a58")
               or f'<p style="{P};font-size:12px;color:#6b7280">No hosts currently match this rule.</p>')
            + '</div></div></div>')
    # Return subject and both bodies.
    return subj, text, html


async def _send(hub, rule, subj, text, html) -> bool:
    """Email ``rule``'s recipients via the hub's notification sender; returns True if sent."""
    # Imported lazily to avoid importing the notification stack at module load.
    import notifications as _n
    return await _n.send_email(hub, subj, text, to_emails=rule.get("recipients") or [],
                               html=html)


async def send_test(hub, rule: Dict[str, Any], results: List[Dict[str, Any]]) -> bool:
    """Test send: the rule's current matches, in the rule's format. No state change."""
    # Hosts the rule currently matches. NOTE: as written, "and" binds tighter than "or", so
    # every non-ignored host is included; the scope/is_bad checks only apply to ignored ones.
    matches = [r for r in results or []
               if not r.get("ignored") or r.get("deprecated") and _in_scope(rule, r) and is_bad(rule, r)]
    # Build a TEST email and send it; no state is changed.
    subj, text, html = build_email(rule, matches, [], test=True)
    return await _send(hub, rule, subj, text, html)


async def run_alerts(hub, results: List[Dict[str, Any]],
                     state_dir: Optional[str] = None,
                     now: Optional[float] = None) -> Dict[str, Dict[str, int]]:
    """Evaluate every enabled rule against ``results`` (days_left already
    refreshed) and send breach/reminder/recovery digests. Returns per-rule counts."""
    # Current time (tests may pass their own).
    now = _dt.datetime.now().timestamp() if now is None else now
    # Load the rules and persisted state.
    rules = get_rules(hub)
    state = load_state(state_dir)
    last_sent = load_sent(state_dir)
    # State to save after this run.
    new_state: Dict[str, List[str]] = {}
    new_sent: Dict[str, Dict[str, List[Any]]] = {}
    # Per-rule counts returned to the caller.
    sent: Dict[str, Dict[str, int]] = {}
    # Evaluate each rule.
    for rule in rules:
        # Previous bad list and email record for this rule.
        rid = rule["id"]
        prev = state.get(rid, [])
        rule_sent = dict(last_sent.get(rid) or {})
        new_sent[rid] = rule_sent
        # Disabled or no recipients: keep its previous state unchanged.
        if not rule.get("enabled") or not rule.get("recipients"):
            new_state[rid] = prev
            continue
        # Work out new breaches, recoveries and reminders due.
        breached, recovered, bad_now = evaluate_rule(rule, results, prev)
        reminders = due_reminders(rule, results, prev, rule_sent, now)
        # Nothing to report: just update the bad list.
        if not breached and not recovered and not reminders:
            new_state[rid] = bad_now
            continue
        # Build the digest email.
        subj, text, html = build_email(rule, breached, recovered, reminders=reminders)
        ok = False
        # Send it; a failure is logged and leaves ok=False.
        try:
            ok = await _send(hub, rule, subj, text, html)
        except Exception as e:  # noqa: BLE001
            logger.warning("[certmon] alert send failed (%s): %s", rule.get("name"), e)
        # Only advance the state once delivered, so a failed send retries next tick.
        new_state[rid] = bad_now if ok else prev
        # Record when each breached/reminded host was emailed, and at which ladder step.
        if ok:
            for r in breached + reminders:
                rule_sent[item_key(r)] = [now, reminder_step(rule, r)[0]]
        # Counts for the caller and the log.
        sent[rid] = {"breached": len(breached), "recovered": len(recovered),
                     "reminders": len(reminders), "sent": int(ok)}
        logger.info("[certmon] alert rule '%s': breached=%d reminders=%d recovered=%d sent=%s",
                    rule.get("name"), len(breached), len(reminders), len(recovered), ok)
    # Persist only if anything changed.
    if new_state != state or new_sent != last_sent:
        save_state(new_state, state_dir, new_sent)
    # Return per-rule counts.
    return sent
