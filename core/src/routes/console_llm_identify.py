"""LLM-driven console device identification (hub-orchestrated).

When the built-in fingerprint profiles can't recognize a device, this pipeline
relays its console output to the LLM (via the BugFixer agent's HELP_ASK path) and
asks it to either identify the device outright or propose READ-ONLY commands to
run. Any proposed commands are executed on the spoke through
``CONSOLE_LLM_COLLECT`` — which re-validates every command against the read-only
allowlist (``fingerprint.is_readonly_command``) before it touches the line — and
the outputs are fed back for a final identity extraction.

The whole feature is gated off by default: the hub endpoint checks
``LM_CONSOLE_LLM_IDENTIFY`` and the spoke checks its ``console_llm_identify``
config, so nothing runs until an operator explicitly enables both sides.
"""
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SYS_IDENTIFY = (
    "You are a network-device identification assistant. You are given raw console "
    "output captured from an UNKNOWN device on a serial line (boot log, banner, "
    "prompt, or partial text). Identify the vendor, model, and OS.\n"
    "Respond with ONLY a single JSON object and no other text.\n"
    "- If you can already identify it, respond: {\"identified\": true, \"vendor\": "
    "\"...\", \"model\": \"...\", \"os\": \"...\", \"confidence\": 0.0-1.0}.\n"
    "- If you need more information, respond: {\"identified\": false, \"commands\": "
    "[\"show version\", ...]} listing up to 6 READ-ONLY commands (only show/"
    "display/get/cat style — NEVER configuration or state-changing commands) that "
    "would reveal the device identity. Prefer a small, broadly-compatible set."
)
_SYS_EXTRACT = (
    "You are a network-device identification assistant. Given the console output "
    "and the outputs of the read-only commands below, identify the device. Respond "
    "with ONLY a single JSON object and no other text: {\"identified\": bool, "
    "\"vendor\": \"...\", \"model\": \"...\", \"os\": \"...\", \"serial\": \"...\", "
    "\"hostname\": \"...\", \"confidence\": 0.0-1.0}. Use null for unknown fields."
)

_IDENTITY_FIELDS = ("model", "os", "serial", "hostname", "confidence")


def hub_llm_identify_enabled() -> bool:
    """Whether the hub side of LLM identify is switched on (env, default off)."""
    return str(os.getenv("LM_CONSOLE_LLM_IDENTIFY", "")).strip().lower() in (
        "1", "true", "yes", "on")


def find_bugfixer(hub) -> Optional[str]:
    """The connected BugFixer agent's spoke_id (the LLM relay), or None. Mirrors
    help_assistant._bugfixer_agent."""
    conns = getattr(hub, "active_connections", {}) or {}
    try:
        if hub._primary_key("bugfixer") in conns:
            return "bugfixer"
    except Exception:  # noqa: BLE001
        pass
    for sid in conns:
        if "bugfixer" in str(sid).lower():
            return sid
    return None


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort: pull the first JSON object out of an LLM reply (handles code
    fences and surrounding prose). Returns None if nothing parses."""
    if not text:
        return None
    s = text.strip()
    # Strip a ```json ... ``` (or bare ```) fence if present.
    m = re.search(r"```(?:json)?\s*(.+?)```", s, re.DOTALL | re.IGNORECASE)
    if m:
        s = m.group(1).strip()
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        pass
    # Fall back to the first balanced {...} span.
    start = s.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(s[start:i + 1])
                        return obj if isinstance(obj, dict) else None
                    except Exception:  # noqa: BLE001
                        break
        start = s.find("{", start + 1)
    return None


def _user_capture(capture: str) -> str:
    return "=== CAPTURED CONSOLE OUTPUT ===\n" + (capture or "(no output captured)")[-6000:]


def _user_outputs(capture: str, outputs: Dict[str, str]) -> str:
    parts = [_user_capture(capture), "\n=== COMMAND OUTPUTS ==="]
    for cmd, out in (outputs or {}).items():
        parts.append(f"\n$ {cmd}\n{(out or '')[-3000:]}")
    return "\n".join(parts)


def _finalize(result: Dict[str, Any], js: Dict[str, Any]) -> Dict[str, Any]:
    """Fold a parsed LLM identity object into the running result."""
    if not isinstance(js, dict):
        return result
    vendor = js.get("vendor")
    identity = {k: js[k] for k in _IDENTITY_FIELDS if js.get(k) not in (None, "")}
    if vendor:
        result["vendor"] = vendor
    if identity:
        result["identity"] = identity
    if js.get("identified") or vendor or identity:
        result["identified"] = True
    return result


def _unwrap(res) -> Dict[str, Any]:
    if isinstance(res, dict):
        return res.get("payload", {}).get("data", res)
    return {}


async def _ask_llm(hub, agent, system: str, user: str, timeout: float = 90.0) -> str:
    """One tool-free LLM turn via the BugFixer HELP_ASK relay → assistant text."""
    res = await hub.request_response(
        agent, "HELP_ASK",
        {"messages": [{"role": "user", "content": user}], "tools": None, "system": system},
        timeout=timeout)
    data = _unwrap(res)
    if not isinstance(data, dict) or data.get("status") != "SUCCESS":
        raise RuntimeError((data or {}).get("message") or "LLM relay error")
    return (data.get("assistant") or {}).get("content") or ""


async def orchestrate(hub, agent: str, sid: str, port_id: str,
                      cmd_cap: int = 6) -> Dict[str, Any]:
    """Run the two-round LLM identify for one port. Returns a result dict:
    ``{status, identified, vendor, identity, commands_run, rejected, rounds}``.
    ``status`` is OK / INCONCLUSIVE / ERROR."""
    result: Dict[str, Any] = {"status": "OK", "identified": False, "vendor": None,
                              "identity": {}, "commands_run": [], "rejected": [],
                              "logged_in": False, "rounds": 0}

    # 1. Grab whatever the device has emitted (passive capture or last banner).
    cap_res = _unwrap(await hub.request_response(sid, "CONSOLE_GET_CAPTURE",
                                                 {"port_id": port_id}, timeout=15.0))
    capture = cap_res.get("capture") or ""

    # 2. Round one: identify outright, or ask for read-only commands.
    content = await _ask_llm(hub, agent, _SYS_IDENTIFY, _user_capture(capture))
    result["rounds"] = 1
    js = _extract_json(content) or {}
    if js.get("identified") and (js.get("vendor") or js.get("model")):
        _finalize(result, js)
        await _persist(hub, sid, port_id, capture, result)
        return result

    cmds: List[str] = [c.strip() for c in (js.get("commands") or [])
                       if isinstance(c, str) and c.strip()][:cmd_cap]
    if not cmds:
        result["status"] = "INCONCLUSIVE"
        return result

    # 3. Run the proposed commands (spoke re-validates each read-only).
    coll = _unwrap(await hub.request_response(sid, "CONSOLE_LLM_COLLECT",
                                              {"port_id": port_id, "commands": cmds},
                                              timeout=120.0))
    if coll.get("status") == "ERROR" or coll.get("error"):
        result["status"] = "ERROR"
        result["message"] = coll.get("message") or coll.get("error")
        return result
    outputs = coll.get("outputs") or {}
    result["commands_run"] = list(outputs.keys())
    result["rejected"] = coll.get("rejected") or []
    result["logged_in"] = bool(coll.get("logged_in"))
    capture = coll.get("banner") or capture

    # 4. Round two: extract the final identity from the command outputs.
    content2 = await _ask_llm(hub, agent, _SYS_EXTRACT, _user_outputs(capture, outputs))
    result["rounds"] = 2
    _finalize(result, _extract_json(content2) or {})
    if not result["identified"]:
        result["status"] = "INCONCLUSIVE"
        return result
    await _persist(hub, sid, port_id, capture, result)
    return result


async def _persist(hub, sid: str, port_id: str, banner: str, result: Dict[str, Any]) -> None:
    """Store the LLM-derived identity on the spoke (best-effort)."""
    try:
        await hub.request_response(sid, "CONSOLE_LLM_STORE", {
            "port_id": port_id, "vendor": result.get("vendor"),
            "identity": result.get("identity") or {}, "banner": (banner or "")[-2000:],
            "logged_in": bool(result.get("logged_in")),
        }, timeout=15.0)
    except Exception as e:  # noqa: BLE001
        logger.warning("console LLM identify: persist failed for %s/%s: %s", sid, port_id, e)
