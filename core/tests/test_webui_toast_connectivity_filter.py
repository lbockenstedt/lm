"""WebUI: showToast's connectivity-noise filter must not eat real errors.

``showToast`` drops error toasts that look like the hub blinking out mid
update/restart ("Failed to fetch" / "Load failed"), because a sticky "an update
or restart is in progress" toast already covers that and the rest is noise.

The test it used was an UNANCHORED search, so it matched the phrase anywhere in
the message — including inside a server-reported failure that happens to quote a
connection error of its own. A 502 from the DHCP module reads:

    Kea CA unreachable: HTTPConnectionPool(host='localhost', port=8001): ...
    Failed to establish a new connection: [Errno 111] Connection refused

which contains "Connection refused", so the toast was swallowed. Observed live:
"Convert lease to reservation" POSTed, got a 502, showed the operator nothing,
and they clicked three more times in three seconds because the button looked
dead. These tests pin that a bare browser error is still dropped while any
server-reported message gets through.
"""

import os
import re

MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _filter_regex():
    """The connectivity-noise regex literal out of showToast, as a Python re.

    Plain alternation + anchors + \\b + \\w, which mean the same in both
    engines, so matching here is a faithful stand-in for the browser.
    """
    src = open(MAIN_JS, encoding="utf-8").read()
    start = src.index("function showToast(")
    body = src[start:start + 2000]
    m = re.search(r"if \(/(\^.+?)/i\.test\(bare\)\)", body)
    assert m, "could not find the anchored connectivity filter in showToast"
    return re.compile(m.group(1), re.I)


def _swallowed(message):
    """Mirror showToast: strip an 'Error: ' prefix, then test the remainder."""
    bare = re.sub(r"^\s*error:\s*", "", str(message or ""), flags=re.I).strip()
    return bool(_filter_regex().match(bare))


# ── the noise it is supposed to drop still gets dropped ─────────────────────

def test_bare_browser_fetch_errors_are_still_swallowed():
    for msg in ("Failed to fetch",                              # Chrome
                "Load failed",                                  # Safari
                "NetworkError when attempting to fetch resource.",  # Firefox
                "Error: Failed to fetch",                       # via catch(e)
                "  error:   Load failed  "):
        assert _swallowed(msg), f"should still be treated as noise: {msg!r}"


# ── the regression: server-reported failures must reach the operator ────────

def test_kea_ca_unreachable_502_is_not_swallowed():
    detail = ("Error: Kea CA unreachable: HTTPConnectionPool(host='localhost', "
              "port=8001): Max retries exceeded with url: / (Caused by "
              "NewConnectionError(\"HTTPConnection(host='localhost', port=8001): "
              "Failed to establish a new connection: [Errno 111] Connection "
              "refused\"))")
    assert not _swallowed(detail), \
        "the DHCP 502 the operator needs to see was swallowed as noise"


def test_other_server_errors_quoting_a_connection_failure_survive():
    for msg in ("Error: Unbound could not connect to the forwarder",
                "Error: spoke rejected DNS_ADD_RECORD: connection refused by resolver",
                "Error: upstream reported net::ERR_CONNECTION_REFUSED"):
        assert not _swallowed(msg), f"server-reported error was swallowed: {msg!r}"


def test_filter_is_anchored_not_a_bare_search():
    # The whole bug was an unanchored test; keep it anchored.
    pat = _filter_regex().pattern
    assert pat.startswith("^") and pat.endswith("$"), \
        f"connectivity filter must match the whole message, got {pat!r}"


def test_filter_only_applies_to_error_toasts():
    src = open(MAIN_JS, encoding="utf-8").read()
    start = src.index("function showToast(")
    body = src[start:start + 2000]
    assert "if (type === 'error')" in body, \
        "success toasts must never be filtered as connectivity noise"
