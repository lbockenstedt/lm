"""Log-redaction helpers and per-connection rate limiter for the LM Hub.

Pure, framework-free helpers extracted verbatim from ``main.py`` (no ``self``):

- The secret-hygiene policy for DEBUG-mode ``request_response`` logging
  (``_redact`` + its allow/deny constants). ``_redact`` is called for every
  request data dict AND every response payload before it's written to
  hub.log → Azure Log Analytics, so the policy here is what stops a secret
  from reaching the log.
- ``_project_nw_devices`` — normalize the nw_devices list for an UPDATE_CONFIG
  push (kept here as a pure projection helper).
- ``TokenBucket`` — per-connection token-bucket rate limiter.
- ``_fit_log_payload`` — trim a log list to fit under a WS frame ceiling.

These are imported back into ``main.py`` so behavior is unchanged.
"""

import json
import logging
import time
from typing import Dict, Any

logger = logging.getLogger("Hub")

# Secret-hygiene for DEBUG-mode ``request_response`` logging. ``_redact`` is
# called for every request data dict AND every response payload before it's
# written to hub.log → Azure Log Analytics, so the policy here is what stops a
# secret from reaching the log.
#
# This is an ALLOW-LIST (default redact), not a deny-list: a NEW secret-bearing
# command — SET_PASSWORD, CONSOLE_PUSH_CONFIG, or an ARBITRARY agent command
# relayed via ``/api/agent/{spoke_id}/command`` (whose ``command`` type is
# user-supplied and not enumerable) — is redacted by default instead of leaking
# verbatim because it was absent from a deny-list.
#
#   * ``_LOGSAFE_COMMANDS``  — verifiably-secret-free types (telemetry, status,
#     health, acks, list ops) logged VERBATIM for the debug trail.
#   * ``_FULLY_REDACT_COMMANDS`` + the PASSWORD/PUSH_CONFIG heuristic — types
#     whose payload carries inline secrets in arbitrary fields / a config BLOB
#     (console configs with enable passwords/PSKs, password resets). The whole
#     data dict is replaced with a marker; field-name stripping can't reach a
#     secret buried in a ``config`` string.
#   * everything else — known secret FIELDS are dropped (top-level + nested
#     ``result``), the rest is kept. Catches SPOKE_UPDATE_SESSION_KEY /
#     SPOKE_SET_HUB_SECRET / CS_TOKEN_RESULT (secret in a named field) and any
#     future command whose secret sits in a ``_REDACT_FIELDS`` name.
_LOGSAFE_COMMANDS = frozenset({
    # Heartbeat / liveness / telemetry (no secret payloads)
    "HEARTBEAT", "AGENT_HEARTBEAT", "AGENT_TELEMETRY", "CS_TELEMETRY",
    "SPOKE_LOG", "AGENT_LOG", "AGENT_RELAY_UP", "AGENT_RELAY_DOWN",
    "CS_INGEST_TELEMETRY", "CS_INGEST_LOG", "CS_INGEST_PROGRESS",
    "CS_INGEST_WATCHDOG_EVENT", "CS_WATCHDOG_EVENT", "CS_HW_RESET_EVENT",
    "CS_INGEST_HW_RESET", "CS_PROGRESS", "CS_LOG",
    # Onboarding / approval / handshake (no secret payloads)
    "APPROVAL_REQUIRED", "APPROVED", "HUB_OK", "HUB_VERIFIED", "CONNECTED",
    "DISCONNECTED", "INSTALL_UUID",
    # Backpressure / ack / probe / status
    "LM_BACKPRESSURE", "COMMAND_RESULT", "ACK", "GET_SPOKE_STATUS",
    "GET_AGENTS", "GET_STATUS", "HEALTH_CHECK", "PING", "PONG",
    "CONSOLE_PROBE_RESULT", "CONSOLE_READY", "CONSOLE_CLOSED",
})

# Types whose ENTIRE payload is replaced with a marker (the secret is inline in
# a config blob / arbitrary field, not a named ``_REDACT_FIELDS`` key). The
# ``PASSWORD`` / ``PUSH_CONFIG`` substring heuristic catches the arbitrary
# agent-command relay's user-supplied types too (e.g. NETBOX_RESET_ADMIN_PASSWORD).
_FULLY_REDACT_COMMANDS = frozenset({
    "SET_PASSWORD", "SET_USER_PASSWORD", "RESET_PASSWORD", "CONSOLE_PUSH_CONFIG",
})
_FULLY_REDACT_SUBSTRINGS = ("PASSWORD", "PUSH_CONFIG")

# Known secret-bearing command types (kept for documentation + the secret-
# hygiene test contract). Field-dropping below applies to ALL non-allow-listed
# types regardless, so membership here is descriptive, not the gating control.
_REDACT_COMMANDS = frozenset({"CS_STORE_PROXMOX_TOKEN", "CS_CREATE_PROXMOX_TOKEN",
                              "CS_TOKEN_RESULT", "SPOKE_UPDATE_SESSION_KEY",
                              "SPOKE_SET_HUB_SECRET", "SET_PASSWORD",
                              "SET_USER_PASSWORD", "RESET_PASSWORD",
                              "CONSOLE_PUSH_CONFIG"})

# Field keys dropped outright from a redacted payload (the value is still
# forwarded to the spoke — only the log line is redacted). Covers every secret
# field name used across the command types above plus the latent hub_secret
# field so a future request_response carrying {"hub_secret": ...} can't leak
# the hub root secret at DEBUG. Kept as the canonical explicit list (and the
# secret-hygiene test contract); the drop below ALSO applies a substring match
# (``_SECRET_SUBSTRINGS``) so compound names the exact list misses —
# ``client_secret``, ``userPassword``/``unicodePwd``, ``api_key``/``apikey``,
# ``LDAP_ADMIN_PW``/``admin_pw``, ``access_token``, ``private_key``,
# ``credential`` — are redacted too.
_REDACT_FIELDS = ("token", "secret", "password", "api_token", "hub_secret",
                  "new_secret", "psk", "onboarding_psk", "enable_secret",
                  "enable_password", "community", "snmp_community")

# Substring indicators — a field name CONTAINING any of these (case-insensitive)
# is treated as secret-bearing and dropped from DEBUG logs. Over-redaction is
# the safe direction (the value still reaches the spoke; only the log line is
# masked), so the list is intentionally broad on secret-ish tokens and avoids
# only the dangerous false-positives ("key"/"auth"/"id" alone match too many
# benign fields, so they're excluded — "api_key"/"private_key" carry enough
# context to be safe).
_SECRET_SUBSTRINGS = ("token", "secret", "password", "passwd", "pw",
                      "apikey", "api_key", "private_key", "credential", "psk",
                      "community")


def _is_secret_field(key: str) -> bool:
    """True if ``key`` names a secret-bearing field (exact ``_REDACT_FIELDS``
    match OR a ``_SECRET_SUBSTRINGS`` substring). Case-insensitive."""
    k = (key or "").lower()
    if not k:
        return False
    return k in _REDACT_FIELDS or any(s in k for s in _SECRET_SUBSTRINGS)


def _scrub_secret_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of ``d`` with every secret-bearing field removed.
    Non-mutating (the caller may forward the original to the spoke)."""
    out = dict(d or {})
    for k in list(out.keys()):
        if _is_secret_field(k):
            out.pop(k, None)
    return out


def _redact(command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a log-safe view of ``data`` for ``request_response`` DEBUG logs.

    Allow-list policy (default redact):
      * ``_LOGSAFE_COMMANDS`` → returned unchanged (full debug trail).
      * ``_FULLY_REDACT_COMMANDS`` (or a PASSWORD/PUSH_CONFIG type name) →
        replaced with ``{"<redacted>": True}`` (inline-secret blob).
      * otherwise → secret-bearing fields (``_REDACT_FIELDS`` exact OR a
        ``_SECRET_SUBSTRINGS`` substring, e.g. ``client_secret``/``userPassword``/
        ``api_key``) dropped from the top level AND from the two nested shapes a
        ``request_response`` payload can take: the legacy ``result`` key and the
        real wire shape ``payload.data`` (a COMMAND_RESULT response is logged as
        the full message ``{"header":…, "payload":{"type":"COMMAND_RESULT",
        "data":{…}}}``; the secret lives at ``payload.data.<field>``, NOT at top
        level — so the response side reaches it here). The value is still
        forwarded to the spoke — only the log line is redacted."""
    ct = (command_type or "").upper()
    if ct in _LOGSAFE_COMMANDS:
        return data
    if ct in _FULLY_REDACT_COMMANDS or any(s in ct for s in _FULLY_REDACT_SUBSTRINGS):
        return {"<redacted>": True}
    safe = dict(data or {})
    for k in list(safe.keys()):
        if _is_secret_field(k):
            safe.pop(k, None)
    # Nested ``result`` (legacy / hypothetical response shape).
    res = safe.get("result")
    if isinstance(res, dict):
        safe["result"] = _scrub_secret_fields(res)
    # Nested ``payload.data`` — the ACTUAL response wire shape logged at the
    # request_response DEBUG line (response_cache stores the full message dict,
    # so ``data`` here is ``{"header":…, "payload":{"type":"COMMAND_RESULT",
    # "data":{…}}}``). The secret sits at ``payload.data.<field>``; reach it.
    # ``data`` may be a dict (one object) or a list of dicts (a query result).
    pl = safe.get("payload")
    if isinstance(pl, dict):
        pdata = pl.get("data")
        if isinstance(pdata, dict):
            safe["payload"] = {**pl, "data": _scrub_secret_fields(pdata)}
        elif isinstance(pdata, list):
            safe["payload"] = {
                **pl,
                "data": [_scrub_secret_fields(x) if isinstance(x, dict) else x
                         for x in pdata],
            }
    return safe


def _project_nw_devices(devices):
    """Project the nw_devices list into the UPDATE_CONFIG payload for a spoke.

    One nw spoke manages a fleet (many devices), unlike the per-instance
    modules above. Credentials are kept — the spoke needs them to reach the
    devices, and ``system.json`` (where nw_devices lives) is runtime-only and
    never committed. This helper is the single place to normalize the device
    shape on push so the on-connect push and a manual Save push identical
    payloads (mirrors the _INSTANCE_CONFIG_SOURCES project contract).
    """
    if not isinstance(devices, list):
        return []
    return [d for d in devices if isinstance(d, dict)]


class TokenBucket:
    """Simple thread-safe-ish token bucket for per-connection rate limiting.

    Refills ``fill_rate`` tokens/sec up to ``capacity``; ``consume`` returns
    True when ``amount`` tokens are available (and debits them), else False.
    Used to throttle noisy spokes/agents on the control plane.
    """

    def __init__(self, capacity: float, fill_rate: float):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, amount: float = 1.0) -> bool:
        """Return True and debit ``amount`` tokens if available, else False."""
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
        self.last_update = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


def _fit_log_payload(all_logs: list, max_bytes: int) -> list:
    """Trim ``all_logs`` to the newest entries whose ``{"logs": …}`` JSON fits
    under ``max_bytes``. Used by ``collect_all_logs`` to cap the GET_LOGS payload
    below the 16 MiB WS frame ceiling.

    Binary-searches the tail length (O(log N) json.dumps passes) instead of the
    prior `while … pop(0)` loop, which re-serialized the whole list on every pop
    (O(N²) in log lines — at 100s of spokes × 1000-line deques this stalled the
    event loop on every BugFixer poll). Keeps the newest entries (drops oldest).
    """
    try:
        if len(json.dumps({"logs": all_logs})) <= max_bytes:
            return all_logs
        lo, hi = 0, len(all_logs)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps({"logs": all_logs[-mid:]})) <= max_bytes:
                lo = mid
            else:
                hi = mid - 1
        return all_logs[-lo:] if lo else []
    except Exception as e:
        logger.warning(f"_fit_log_payload size-cap failed: {e}")
        return all_logs[-1000:]  # safe fallback
