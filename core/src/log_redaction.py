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

# json measures how large a log payload is when serialised.
import json
# logging reports helper failures.
import logging
# time drives the token bucket's refill calculation.
import time
# Type hints for payload dicts.
from typing import Dict, Any

# Share the hub's logger so these messages appear with other hub logs.
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
    "CONSOLE_TAKEOVER", "CONSOLE_DOWNGRADED",
})

# Types whose ENTIRE payload is replaced with a marker (the secret is inline in
# a config blob / arbitrary field, not a named ``_REDACT_FIELDS`` key). The
# ``PASSWORD`` / ``PUSH_CONFIG`` substring heuristic catches the arbitrary
# agent-command relay's user-supplied types too (e.g. NETBOX_RESET_ADMIN_PASSWORD).
_FULLY_REDACT_COMMANDS = frozenset({
    "SET_PASSWORD", "SET_USER_PASSWORD", "RESET_PASSWORD", "CONSOLE_PUSH_CONFIG",
    # The AD connection (with its bind password) rides nested in ``ad``.
    "AD_DISCOVER", "AD_TEST", "AD_SEARCH_USERS",
})
# Command-name fragments that also trigger full redaction (catches user-supplied types).
_FULLY_REDACT_SUBSTRINGS = ("PASSWORD", "PUSH_CONFIG")

# Known secret-bearing command types (kept for documentation + the secret-
# hygiene test contract). Field-dropping below applies to ALL non-allow-listed
# types regardless, so membership here is descriptive, not the gating control.
_REDACT_COMMANDS = frozenset({"CS_STORE_PROXMOX_TOKEN", "CS_CREATE_PROXMOX_TOKEN",
                              "CS_TOKEN_RESULT", "SPOKE_UPDATE_SESSION_KEY",
                              "SPOKE_SET_HUB_SECRET", "SET_PASSWORD",
                              "SET_USER_PASSWORD", "RESET_PASSWORD",
                              "CONSOLE_PUSH_CONFIG", "CS_DOT1X_CREDENTIAL",
                              "CPPM_CREATE_LOCAL_USER", "CPPM_SET_LOCAL_USER_PASSWORD"})

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
    # Compare case-insensitively; an empty name is never secret.
    k = (key or "").lower()
    if not k:
        return False
    # Exact known field name, or any secret-ish substring.
    return k in _REDACT_FIELDS or any(s in k for s in _SECRET_SUBSTRINGS)


def _scrub_secret_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of ``d`` with every secret-bearing field removed.
    Non-mutating (the caller may forward the original to the spoke)."""
    # Copy, then drop every secret-bearing key from the copy.
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
    # Compare command names in upper case.
    ct = (command_type or "").upper()
    # Allow-listed, secret-free commands are logged as-is.
    if ct in _LOGSAFE_COMMANDS:
        return data
    # Commands whose secrets may hide anywhere are replaced entirely by a marker.
    if ct in _FULLY_REDACT_COMMANDS or any(s in ct for s in _FULLY_REDACT_SUBSTRINGS):
        return {"<redacted>": True}
    # Everything else: copy and drop secret-bearing top-level fields.
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
    # Anything that is not a list becomes an empty list.
    if not isinstance(devices, list):
        return []
    # Keep only dict entries (drops malformed rows).
    return [d for d in devices if isinstance(d, dict)]


# Ordered subject-field allowlist for the Request Timeout log line. Replaces
# the opaque per-request ``msg_id`` UUID with the *subject* the request
# operates on — the sim-client hostname a CS_POLL_AGENT_INBOX poll timed out
# on, the appliance a TRUENAS_GET_POOLS fetch timed out on, the device a
# NW_GET_ARP pull timed out on — so the operator reads a NAME, not a random
# correlation id (the recurring "UUID instead of a name" complaint). The full
# ``msg_id`` stays in the DEBUG request/response lines for exact correlation;
# the ERROR line keeps a short ``req=<first8>`` hint when no subject is
# derivable. Fields are ordered most-identifying/least-sensitive first; bare
# ``id`` is deliberately excluded (usually a UUID — the very thing being
# replaced) in favor of named fields. None of these are secret-bearing (the
# secret fields are already in ``_REDACT_FIELDS`` / ``_SECRET_SUBSTRINGS`` and
# are never picked here).
_REQUEST_SUBJECT_FIELDS = ("hostname", "name", "appliance_id", "device_id",
                            "vmid", "spoke_id", "tenant_id", "mac", "ip")


def _request_subject(command_type: str, data: Any) -> str:
    """A short human-meaningful label for the subject of a request, for the
    Request Timeout ERROR log (replaces the opaque ``msg_id`` UUID). Returns
    ``"<field>=<value>"`` for the first matching allowlist field in ``data``,
    or ``""`` when no subject is derivable (the caller falls back to a short
    ``msg_id`` prefix). Never raises."""
    # Only dict payloads can carry subject fields.
    if not isinstance(data, dict):
        return ""
    # Return the first allow-listed field that has a non-empty value.
    for k in _REQUEST_SUBJECT_FIELDS:
        v = data.get(k)
        if v not in (None, "", []):
            return f"{k}={v}"
    # No subject found; the caller falls back to a short request id.
    return ""


class TokenBucket:
    """Simple thread-safe-ish token bucket for per-connection rate limiting.

    Refills ``fill_rate`` tokens/sec up to ``capacity``; ``consume`` returns
    True when ``amount`` tokens are available (and debits them), else False.
    Used to throttle noisy spokes/agents on the control plane.
    """

    def __init__(self, capacity: float, fill_rate: float):
        """Start with a full bucket that refills at ``fill_rate`` tokens per second."""
        # Maximum tokens, refill rate, current tokens, and when tokens were last updated.
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, amount: float = 1.0) -> bool:
        """Return True and debit ``amount`` tokens if available, else False."""
        # Add tokens for the time elapsed since the last update, capped at capacity.
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
        self.last_update = now
        # Spend the tokens if enough are available.
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


def _tail_lines(path: str, n: int, _block: int = 65536) -> list:
    """Return the last ``n`` lines of ``path`` without reading the whole file.

    ``collect_all_logs`` tails every ``/var/log/lm/*.log`` on every GET_LOGS poll
    (AppBuilder polls this ~hourly, plus the WebUI Logs page). The prior
    ``deque(f, maxlen=n)`` iterated the ENTIRE file to keep the last ``n`` lines —
    O(file size) per call. Once hub.log grew into the hundreds of MB / millions
    of lines, a single poll spent seconds just walking hub.log, pushing the
    round-trip past AppBuilder's 20s HUB_REQUEST timeout ("cannot read hub logs").

    This seeks from the end and reads fixed-size blocks backward until ``n``
    newlines are collected — O(n) regardless of file size. Returns stripped lines
    oldest→newest, matching the old deque semantics.
    """
    try:
        # os provides the SEEK_END constant for seeking from the end of the file.
        import os
        # Open in binary mode so seeking by byte offset is exact.
        with open(path, "rb") as f:
            # Find the file size; an empty file has no lines.
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if end == 0:
                return []
            # Bytes read so far (from the end) and the current read position.
            data = b""
            pos = end
            # Read blocks backwards until we have more than n newlines or reach the start.
            while pos > 0 and data.count(b"\n") <= n:
                read = min(_block, pos)
                pos -= read
                f.seek(pos)
                data = f.read(read) + data
            # Drop the trailing newline so it does not produce an empty last line.
            if data.endswith(b"\n"):
                data = data[:-1]
            # Split into lines and keep only the last n.
            lines = data.split(b"\n")
            tail = lines[-n:] if len(lines) > n else lines
            # Decode each line as UTF-8 (replacing bad bytes) and trim it.
            out = []
            for raw in tail:
                try:
                    out.append(raw.decode("utf-8", "replace").strip())
                except Exception:  # noqa: BLE001
                    # Fallback representation if decoding somehow fails.
                    out.append(str(raw).strip())
            # Drop blank lines.
            return [ln for ln in out if ln]
    except Exception as e:  # noqa: BLE001
        # Unreadable file: log and return nothing.
        logger.warning(f"_tail_lines({path}) failed: {e}")
        return []


def _fit_log_payload(all_logs: list, max_bytes: int) -> list:
    """Trim ``all_logs`` to the newest entries whose ``{"logs": …}`` JSON fits
    under ``max_bytes``. Used by ``collect_all_logs`` to cap the GET_LOGS payload
    below the 16 MiB WS frame ceiling.

    Binary-searches the tail length (O(log N) json.dumps passes) instead of the
    prior `while … pop(0)` loop, which re-serialized the whole list on every pop
    (O(N²) in log lines — at 100s of spokes × 1000-line deques this stalled the
    event loop on every AppBuilder poll). Keeps the newest entries (drops oldest).
    """
    try:
        # Everything already fits: return as-is.
        if len(json.dumps({"logs": all_logs})) <= max_bytes:
            return all_logs
        # Binary-search the largest number of newest entries that still fit.
        lo, hi = 0, len(all_logs)
        while lo < hi:
            # Try keeping "mid" newest entries; grow or shrink the range based on the size.
            mid = (lo + hi + 1) // 2
            if len(json.dumps({"logs": all_logs[-mid:]})) <= max_bytes:
                lo = mid
            else:
                hi = mid - 1
        # Return the newest entries that fit (none if even one does not).
        return all_logs[-lo:] if lo else []
    except Exception as e:
        # Serialisation failure: fall back to the newest 1000 entries.
        logger.warning(f"_fit_log_payload size-cap failed: {e}")
        return all_logs[-1000:]  # safe fallback


# Loggers whose lines never leave the hub for AppBuilder. Their lines name the
# threat monitor's decoy paths, tripwires and blocked IPs. AB files issues in
# PUBLIC GitHub repos from what it is sent, so these lines must not reach it:
# that would show attackers the decoys exist and what they look like (the decoy
# set is kept in a private repo for the same reason; see repo_policy.py). Security
# events are already handled by the threat monitor (auto-block, Security page).
_AB_HIDDEN_LOGGERS = (" - Security - ", " - ThreatMonitor - ")


def is_security_line(line) -> bool:
    """True if ``line`` comes from a security logger and must not be sent to AB."""
    text = line.get("log", "") if isinstance(line, dict) else str(line or "")
    return any(tag in text for tag in _AB_HIDDEN_LOGGERS)


def drop_security_lines(lines: list) -> list:
    """``lines`` without security-logger lines (plain strings or {"log": …} entries)."""
    return [ln for ln in lines if not is_security_line(ln)]
