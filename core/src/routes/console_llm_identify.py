"""LLM-driven console device identification (hub-orchestrated).

When the built-in fingerprint profiles can't recognize a device, this pipeline
relays its console output to the LLM (via the AppBuilder agent's HELP_ASK path) and
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

from . import console_learn

logger = logging.getLogger(__name__)

# ── Privacy scrubber ───────────────────────────────────────────────────────────
# Everything sent to the (external) LLM for device identification passes through
# _ask_llm, so we redact sensitive site data here — the LLM only needs vendor/
# model/OS cues (banners, version strings, prompt shape), never the operator's
# addressing, credentials, or hostnames. Local fingerprinting (detect_vendor) runs
# on the RAW output on the spoke, so scrubbing never weakens built-in detection.
_RE_HASH = re.compile(r"\$[0-9a-zA-Z]{1,3}\$[^\s'\"]{3,}")            # $1$/$5$/$6$/$2y$ …
_RE_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
                     r"|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b")   # colon/dash or Cisco dotted
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b")
# IPv6: ≥4 hextets (≥3 colons) or a ``::`` compressed form — avoids eating hh:mm:ss.
_RE_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){3,}[0-9A-Fa-f]{1,4}\b"
                      r"|\b(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:?)+\b")
_RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# key/value secrets: redact the value after a secret-ish keyword.
_RE_SECRET = re.compile(
    r"(?i)\b(pass(?:word|wd|phrase)?|secret|pre-?shared-?key|psk|community|"
    r"wpa-?psk|auth(?:entication)?-?key|priv(?:acy)?-?key|snmp\S*community)\b"
    r"(\s*[:=]?\s*)(\S+)")
# hostname references (config directive OR inline banner text like
# "System hostname: edge-1") → redact the value, keep the keyword.
_RE_HOSTNAME = re.compile(r"(?i)\b(host-?name|sysname|switchname)\b(\s*[:=]?\s*)(\S+)")
# a bare device prompt line (``hostname#`` / ``hostname(config)#`` / ``hostname>``)
# → redact the hostname but keep the mode/terminator (the vendor cue).
_RE_PROMPT_HOST = re.compile(r"(?m)^([A-Za-z0-9][\w.\-]{0,63})(\([^)]*\))?\s*([>#])\s*$")

_PLACEHOLDERS = ("[IP]", "[IPV6]", "[MAC]", "[HOST]", "[EMAIL]", "[REDACTED")

# Terminal escape sequences (VT100/ANSI CSI cursor moves, OSC, scroll-region,
# show/hide-cursor) that pollute raw serial captures from full-screen menu CLIs
# (e.g. ArubaOS-Switch). Stripped before scrubbing so the LLM sees clean text.
_RE_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_RE_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_RE_ANSI_MISC = re.compile(r"\x1b[()#][0-9A-Za-z]|\x1b[=>78McDEHF]")
_RE_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _strip_ansi(text: str) -> str:
    s = _RE_ANSI_OSC.sub("", text)
    s = _RE_ANSI_CSI.sub("", s)
    s = _RE_ANSI_MISC.sub("", s)
    s = _RE_CTRL.sub("", s)
    return s.replace("\r\n", "\n").replace("\r", "\n")


def scrub_for_llm(text: Optional[str]) -> str:
    """Redact site-sensitive data (IPv4/IPv6, MACs, password/secret/community
    values, credential hashes, e-mail, and hostnames) from console output before
    it is sent to the LLM. Order matters: hashes and MACs are removed before the
    IPv4/IPv6 passes so their colon groups aren't mistaken for addresses."""
    if not text:
        return ""
    s = _strip_ansi(str(text))
    s = _RE_HASH.sub("[REDACTED-HASH]", s)
    s = _RE_MAC.sub("[MAC]", s)
    s = _RE_IPV4.sub("[IP]", s)
    s = _RE_IPV6.sub("[IPV6]", s)
    s = _RE_EMAIL.sub("[EMAIL]", s)
    s = _RE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2) or ' '}[REDACTED]", s)
    s = _RE_HOSTNAME.sub(lambda m: f"{m.group(1)}{m.group(2) or ' '}[HOST]", s)
    s = _RE_PROMPT_HOST.sub(lambda m: f"[HOST]{m.group(2) or ''}{m.group(3)}", s)
    return s

_SYS_IDENTIFY = (
    "You are a network-device identification assistant. You are given raw console "
    "output captured from an UNKNOWN device on a serial line (boot log, banner, "
    "prompt, or partial text). Identify the vendor, model, OS, and device type.\n"
    "Respond with ONLY a single JSON object and no other text.\n"
    "- If you can already identify it, respond: {\"identified\": true, \"vendor\": "
    "\"...\", \"model\": \"...\", \"os\": \"...\", \"type\": \"...\", \"confidence\": "
    "0.0-1.0}. \"model\" should be the specific product (e.g. \"Aruba CX 6300M\", "
    "\"Aruba 2930F-24G\", \"Juniper SRX340\", \"Cisco Catalyst 9300\"); \"type\" is "
    "the role: one of Switch, Router, Firewall, Access Point, Gateway, Server, Load "
    "Balancer, or Other.\n"
    "- If you need more information, respond: {\"identified\": false, \"commands\": "
    "[\"show version\", ...]} listing up to 6 READ-ONLY commands (only show/"
    "display/get/cat style — NEVER configuration or state-changing commands) that "
    "would reveal the device identity. Prefer a small, broadly-compatible set."
)
_SYS_EXTRACT = (
    "You are a network-device identification assistant. Given the console output "
    "and the outputs of the read-only commands below, identify the device. Respond "
    "with ONLY a single JSON object and no other text: {\"identified\": bool, "
    "\"vendor\": \"...\", \"model\": \"...\", \"os\": \"...\", \"type\": \"...\", "
    "\"serial\": \"...\", \"hostname\": \"...\", \"confidence\": 0.0-1.0}. \"model\" "
    "is the specific product (e.g. \"Aruba CX 6300M\", \"Juniper SRX340\"); \"type\" "
    "is the role: one of Switch, Router, Firewall, Access Point, Gateway, Server, "
    "Load Balancer, or Other. Use null for unknown fields."
)
_SYS_CREDS = (
    "You are a network-device credential assistant. You are given raw console "
    "output from a device sitting at a login/password prompt whose stored "
    "credentials did not work. Propose the most likely FACTORY-DEFAULT or "
    "well-known login credentials for that device/vendor.\n"
    "Respond with ONLY a single JSON object and no other text: {\"credentials\": "
    "[{\"username\": \"...\", \"password\": \"...\"}, ...]} — up to 6 ordered "
    "guesses, most likely first. Use an empty string for a blank password. Do not "
    "propose destructive actions or commentary."
)

_IDENTITY_FIELDS = ("model", "os", "type", "serial", "hostname", "confidence")


def hub_llm_identify_enabled(hub=None) -> bool:
    """Whether the hub side of LLM identify is switched on. A persisted hub
    setting (the admin UI toggle) is authoritative once set; otherwise fall back
    to the LM_CONSOLE_LLM_IDENTIFY env default (both default off)."""
    if hub is not None:
        try:
            v = hub.state.system_state.get("console_llm_identify_enabled")
        except Exception:  # noqa: BLE001
            v = None
        if v is not None:
            return bool(v)
    return str(os.getenv("LM_CONSOLE_LLM_IDENTIFY", "")).strip().lower() in (
        "1", "true", "yes", "on")


def find_ab(hub) -> Optional[str]:
    """The connected AppBuilder agent's spoke_id (the LLM relay), or None. Mirrors
    help_assistant._ab_agent."""
    conns = getattr(hub, "active_connections", {}) or {}
    try:
        if hub._primary_key("ab") in conns:
            return "ab"
    except Exception:  # noqa: BLE001
        pass
    for sid in conns:
        if "ab" in str(sid).lower():
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
    identity = {k: js[k] for k in _IDENTITY_FIELDS
                if js.get(k) not in (None, "")
                and not any(ph in str(js[k]) for ph in _PLACEHOLDERS)}
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
    """One tool-free LLM turn via the AppBuilder HELP_ASK relay → assistant text.
    The user content is scrubbed of site-sensitive data before it leaves the hub."""
    res = await hub.request_response(
        agent, "HELP_ASK",
        {"messages": [{"role": "user", "content": scrub_for_llm(user)}],
         "tools": None, "system": system},
        timeout=timeout)
    data = _unwrap(res)
    if not isinstance(data, dict) or data.get("status") != "SUCCESS":
        raise RuntimeError((data or {}).get("message") or "LLM relay error")
    return (data.get("assistant") or {}).get("content") or ""


async def _ask_llm_credentials(hub, agent, capture: str) -> List[Dict[str, str]]:
    """Ask the LLM for likely factory-default credentials for a device stuck at a
    login prompt. Returns an ordered list of ``{username, password}`` (best-effort;
    empty on any failure). These are tried once each — never re-hammered."""
    try:
        content = await _ask_llm(hub, agent, _SYS_CREDS, _user_capture(capture))
    except Exception:  # noqa: BLE001
        return []
    js = _extract_json(content) or {}
    out: List[Dict[str, str]] = []
    for c in (js.get("credentials") or [])[:6]:
        if isinstance(c, dict) and c.get("username") is not None:
            out.append({"username": str(c.get("username", "")),
                        "password": str(c.get("password", ""))})
    return out


async def orchestrate(hub, agent: str, sid: str, port_id: str,
                      cmd_cap: int = 6) -> Dict[str, Any]:
    """Run the LLM-guided identify for one port. Returns a result dict:
    ``{status, identified, vendor, identity, commands_run, rejected, rounds}``.
    ``status`` is OK / INCONCLUSIVE / ERROR.

    A locally-learned fingerprint DB (``console_learn``) is consulted first: if a
    device with this prompt signature has been seen before we reuse its known
    read-only commands (and vendor), skipping the first LLM round entirely. Every
    successful round teaches the DB, so identification gets faster over time."""
    result: Dict[str, Any] = {"status": "OK", "identified": False, "vendor": None,
                              "identity": {}, "commands_run": [], "rejected": [],
                              "logged_in": False, "rounds": 0}

    # 1. Grab whatever the device has emitted (passive capture or last banner).
    cap_res = _unwrap(await hub.request_response(sid, "CONSOLE_GET_CAPTURE",
                                                 {"port_id": port_id}, timeout=15.0))
    capture = cap_res.get("capture") or ""
    sig = console_learn.signature(capture)
    learned = console_learn.lookup(hub, sig)

    # 2. Round one: reuse a learned fingerprint if we have one, otherwise ask the
    #    LLM to identify outright or propose read-only commands.
    cmds: List[str] = []
    if learned and learned.get("commands"):
        result["learned"] = True
        result["rounds"] = 0
        # A previously-resolved device with the same signature: short-circuit.
        if learned.get("vendor") or learned.get("identity"):
            result["vendor"] = learned.get("vendor")
            result["identity"] = learned.get("identity") or {}
            result["identified"] = True
        cmds = [c for c in learned["commands"] if isinstance(c, str) and c.strip()][:cmd_cap]
    else:
        content = await _ask_llm(hub, agent, _SYS_IDENTIFY, _user_capture(capture))
        result["rounds"] = 1
        js = _extract_json(content) or {}
        if js.get("identified") and (js.get("vendor") or js.get("model")):
            _finalize(result, js)
            console_learn.learn_identity(hub, sig, result.get("vendor"),
                                         result.get("identity"))
            await _persist(hub, sid, port_id, capture, result)
            return result
        cmds = [c.strip() for c in (js.get("commands") or [])
                if isinstance(c, str) and c.strip()][:cmd_cap]

    if not cmds:
        result["status"] = "INCONCLUSIVE"
        return result

    # 3. Run the proposed/learned commands (spoke re-validates each read-only).
    coll = _unwrap(await hub.request_response(sid, "CONSOLE_LLM_COLLECT",
                                              {"port_id": port_id, "commands": cmds},
                                              timeout=120.0))
    if coll.get("status") == "ERROR" or coll.get("error"):
        result["status"] = "ERROR"
        result["message"] = coll.get("message") or coll.get("error")
        return result

    # 3b. Stuck at a login prompt? The stored + factory-default credentials all
    #     failed, so ask the LLM for likely credentials and retry the collect once
    #     with those guesses before we give up on logging in.
    diag = coll.get("diag") or {}
    if (not coll.get("logged_in")
            and (diag.get("login_prompt_seen") or diag.get("password_prompt_seen"))):
        guesses = await _ask_llm_credentials(hub, agent, coll.get("banner") or capture)
        if guesses:
            result["llm_credentials_tried"] = len(guesses)
            retry = _unwrap(await hub.request_response(
                sid, "CONSOLE_LLM_COLLECT",
                {"port_id": port_id, "commands": cmds, "credentials": guesses},
                timeout=120.0))
            if retry.get("status") != "ERROR" and not retry.get("error"):
                coll = retry

    outputs = coll.get("outputs") or {}
    result["commands_run"] = list(outputs.keys())
    result["rejected"] = coll.get("rejected") or []
    result["logged_in"] = bool(coll.get("logged_in"))
    capture = coll.get("banner") or capture

    # Learn: these commands drew output from a device with this signature.
    if outputs:
        console_learn.learn_commands(hub, sig, list(outputs.keys()), capture)

    # A learned+already-resolved device that just re-ran its commands is done.
    if result["identified"]:
        await _persist(hub, sid, port_id, capture, result)
        return result

    # 4. Final round: extract the identity from the command outputs.
    content2 = await _ask_llm(hub, agent, _SYS_EXTRACT, _user_outputs(capture, outputs))
    result["rounds"] = (result.get("rounds") or 0) + 1
    _finalize(result, _extract_json(content2) or {})
    if not result["identified"]:
        result["status"] = "INCONCLUSIVE"
        return result
    # Teach the DB the resolved identity so next time we skip straight to it.
    console_learn.learn_identity(hub, sig, result.get("vendor"), result.get("identity"))
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
