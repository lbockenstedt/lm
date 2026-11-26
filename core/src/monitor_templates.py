"""Zabbix templates for device types LM does not know yet.

NW leaves ``profile.sys_descr`` on a host that answered SNMP but is not a
platform it classifies (a PDU, a UPS, ...). Such a device used to get the
generic SNMP template. Now, once per device type:

1. the monitoring spoke searches Zabbix for a template for that vendor/model
   (``MON_TEMPLATE_FIND``);
2. the LLM (through the AppBuilder relay) picks one of them, or writes a new
   SNMP-only template (``{"action": "create", "template_yaml": ...}``);
3. a new template is installed (``MON_TEMPLATE_INSTALL``, validated again on
   the spoke) and the decision is cached in ``gc["monitor_templates"]``;
4. the next monitoring sync carries ``template`` on every device of that type,
   so the spoke links it.

A failure is cached too and retried after a day, so a model that keeps
failing is not asked every sync. ``resolve`` is the only part with I/O.
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Hub")

# Knobs in the global config (``monitor_templates``): the switch, and how many
# new device types one pass may take (each can cost an LLM call).
DEFAULTS = {"enabled": True, "max_per_pass": 2}
# A failed decision is retried after this long.
RETRY_S = 86400.0
# Evidence words kept in a device-type signature.
_SIG_WORDS = 6
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b", re.I)
# Firmware and build versions change per unit; the model does not.
_VERSION = re.compile(r"^[a-z]?:?v?\d+(?:[._-]\d+)+\W*$", re.I)

SYSTEM = (
    "You pick or write a Zabbix SNMP monitoring template for one network device type. "
    "Reply with ONE JSON object and nothing else.\n"
    "If one of the candidate templates fits the device, reply "
    '{"action":"use","template":"<exact candidate name>"}.\n'
    "Otherwise write a new template and reply "
    '{"action":"create","template_yaml":"<Zabbix YAML export>"}. Rules for the YAML: '
    "format version of the given Zabbix server; exactly one template, named "
    "'<Vendor> <Model or family> by SNMP'; every item and discovery rule has "
    "`type: SNMP_AGENT` (or DEPENDENT/CALCULATED); use standard MIB OIDs or the vendor's "
    "documented OIDs; add a few triggers on availability and the main health values; "
    "no hosts, macros with secrets, scripts or external checks.\n"
    'If you cannot do either, reply {"action":"none"}.'
)


def settings(global_config: Dict[str, Any]) -> Dict[str, Any]:
    """The knobs with defaults filled in and values coerced."""
    raw = (global_config or {}).get("monitor_templates_config")
    raw = raw if isinstance(raw, dict) else {}
    try:
        cap = max(0, int(raw.get("max_per_pass", DEFAULTS["max_per_pass"])))
    except (TypeError, ValueError):
        cap = DEFAULTS["max_per_pass"]
    return {"enabled": bool(raw.get("enabled", DEFAULTS["enabled"])), "max_per_pass": cap}


def scrub(text: Any) -> str:
    """sysDescr without addresses: it is sent to the LLM."""
    return " ".join(_MAC.sub("", _IPV4.sub("", str(text or ""))).split())[:300]


def signature(sys_descr: Any) -> str:
    """Stable id of a device type: the leading words of sysDescr minus versions
    and addresses, lower-cased. Empty when there is no sysDescr."""
    words = [w for w in scrub(sys_descr).lower().split() if not _VERSION.match(w)]
    return " ".join(words[:_SIG_WORDS])


def is_unclassified(entry: Dict[str, Any]) -> bool:
    """True for a seen host that answered SNMP but nothing classified: no object
    type, and not an appliance LM already knows (TrueNAS)."""
    descr = str((entry.get("profile") or {}).get("sys_descr") or "").lower()
    return (bool(descr) and not entry.get("object_type")
            and not descr.startswith(("truenas", "freenas")))


def chosen(gc: Dict[str, Any], sig: str) -> str:
    """The template decided for a device type, or ''."""
    return str((((gc or {}).get("monitor_templates") or {}).get(sig) or {}).get("template") or "")


def needs_decision(gc: Dict[str, Any], sig: str, now: float) -> bool:
    """True when the type has no decision, or only a failed one older than RETRY_S."""
    rec = ((gc or {}).get("monitor_templates") or {}).get(sig)
    if not rec:
        return True
    return not rec.get("template") and now - float(rec.get("ts") or 0) >= RETRY_S


def parse_reply(text: str) -> Dict[str, str]:
    """The LLM's JSON answer as ``{action, template, template_yaml}``; ``none``
    when it is not usable."""
    m = re.search(r"\{.*\}", str(text or ""), re.S)
    try:
        obj = json.loads(m.group(0)) if m else {}
    except ValueError:
        obj = {}
    if not isinstance(obj, dict) or obj.get("action") not in ("use", "create"):
        return {"action": "none"}
    return {"action": obj["action"], "template": str(obj.get("template") or "").strip(),
            "template_yaml": str(obj.get("template_yaml") or "")}


def build_prompt(sys_descr: str, found: Dict[str, Any]) -> str:
    """The user turn: the device evidence, the Zabbix version and the candidates."""
    names = "\n".join(f"- {n}" for n in (found.get("templates") or [])[:60]) or "(none found)"
    return (f"Device sysDescr: {scrub(sys_descr)}\n"
            f"Zabbix server version: {found.get('zabbix_version') or 'unknown'}\n"
            f"Candidate templates already in Zabbix:\n{names}")


async def _decide(hub, spoke: str, agent: str, sys_descr: str) -> Dict[str, str]:
    """Find, ask, install for one device type; returns ``{template, source}`` or ``{error}``."""
    from routes.console_llm_identify import _ask_llm, _unwrap
    found = _unwrap(await hub.request_response(
        spoke, "MON_TEMPLATE_FIND", {"sys_descr": sys_descr}, timeout=60.0)) or {}
    if found.get("status") != "SUCCESS":
        return {"error": str(found.get("message") or "template search failed")}
    reply = parse_reply(await _ask_llm(
        hub, agent, SYSTEM, build_prompt(sys_descr, found), timeout=600.0, role="final"))
    candidates = set(found.get("templates") or [])
    if reply["action"] == "use":
        # Only a template Zabbix really has; an invented name is a failure.
        if reply["template"] in candidates:
            return {"template": reply["template"], "source": "existing"}
        return {"error": "the LLM named a template Zabbix does not have"}
    if reply["action"] == "create":
        res = _unwrap(await hub.request_response(
            spoke, "MON_TEMPLATE_INSTALL", {"template_yaml": reply["template_yaml"]},
            timeout=120.0)) or {}
        if res.get("template") and (res.get("installed") or res.get("exists")):
            return {"template": res["template"],
                    "source": "generated" if res.get("installed") else "existing"}
        return {"error": str(res.get("error") or res.get("message") or "template install failed")}
    return {"error": "the LLM had no template for this device type"}


async def resolve(hub, pending: Dict[str, str]) -> int:
    """Decide up to ``max_per_pass`` of the ``{signature: sys_descr}`` types and
    cache each outcome. Returns how many types got a template."""
    gc = hub.state.system_state.setdefault("global_config", {})
    cfg = settings(gc)
    spoke = hub.get_spoke_by_type("monitoring")
    from routes.console_llm_identify import find_ab
    agent = find_ab(hub)
    if not (cfg["enabled"] and spoke and agent):
        return 0
    now, done = time.time(), 0
    todo = [(s, d) for s, d in pending.items() if needs_decision(gc, s, now)][:cfg["max_per_pass"]]
    store = gc.setdefault("monitor_templates", {})
    for sig, descr in todo:
        try:
            out = await _decide(hub, spoke, agent, descr)
        except Exception as e:  # noqa: BLE001 - one type failing must not stop the rest
            out = {"error": str(e)[:200]}
        store[sig] = {**out, "ts": time.time()}
        if out.get("template"):
            done += 1
            logger.info("monitor-templates: %r -> %s (%s)", sig, out["template"], out["source"])
        else:
            logger.warning("monitor-templates: %r not resolved: %s", sig, out.get("error"))
        hub.state._mark_dirty()
        await asyncio.sleep(0)
    return done
