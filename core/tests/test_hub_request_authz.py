"""H1: gate the reverse HUB_REQUEST channel to a pinned BugFixer client cert.

``handle_hub_request`` was reachable by ANY approved, signed spoke, and exposed
fleet-wide RCE (``TRIGGER_ALL_UPDATES`` fans ``SPOKE_UPDATE`` to every spoke/agent),
cross-tenant log harvest (``GET_LOGS``), and the full fleet roster
(``GET_SPOKE_STATUS``). It's BugFixer's tool — but nothing restricted it to
BugFixer, so a malicious tenant-added spoke (or a compromised box) escalated to
fleet-wide action.

The gate is **cert-bound**, not ``spoke_id``-bound: ``spoke_id`` is
hostname-derived and spoofable (name a box ``bugfixer``), and casing is a
nuisance, so identity is the verified TLS client cert. An operator labels a
specific Let's Encrypt-issued cert as "the BugFixer cert" (the LE-module
checkbox → ``global_config['bugfixer_cert_identities']``, a list of DNS names);
``_hub_request_authorized`` pins that cert's identity and authorizes a
HUB_REQUEST **only** when the calling connection presented that cert over mTLS.

Rule: ``BugFixer rights ⟺ mTLS on AND the connection's verified client cert
matches the pinned BugFixer cert. Anything else → denied.``

These exercise the REAL helper + the REAL denial branch of
``handle_hub_request`` against a minimal stub (the denial path only touches
``state.get_global_config`` + ``record_spoke_event``).
"""

import asyncio

import main  # noqa: E402  (core/src on sys.path via conftest)


class _FakeState:
    def __init__(self, gc=None):
        self._gc = gc or {}
    def get_global_config(self):
        return self._gc


def _hub(gc=None, extra=None):
    """Stub exposing only what the authz + denial paths touch."""
    class _H:
        pass
    h = _H()
    h.state = _FakeState(gc)
    h.events = []
    h.record_spoke_event = lambda sid, ev, detail="": h.events.append((sid, ev, detail))
    if extra:
        for k, v in extra.items():
            setattr(h, k, v)
    # Bind the real unbound methods so the tests exercise production code.
    h._hub_request_authorized = main.LabManagerHub._hub_request_authorized.__get__(h, _H)
    h.handle_hub_request = main.LabManagerHub.handle_hub_request.__get__(h, _H)
    return h


# ── _hub_request_authorized (cert-bound) ─────────────────────────────────────

def test_pinned_cert_match_authorizes():
    """The happy path: a pinned BugFixer cert presented over mTLS authorizes the
    channel. ``peer_cert_identity`` is the tuple of SAN DNS names extracted from
    the verified client cert."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    assert h._hub_request_authorized("bugfixer", ("bugfixer.lm.io",)) is True


def test_no_pinned_cert_denies_even_for_bugfixer_spoke_id():
    """Fail-closed default: with no cert designated as BugFixer, the channel is
    CLOSED — even a spoke literally named 'bugfixer' is denied. BugFixer is
    dormant until the operator issues + labels a dedicated cert."""
    h = _hub()
    assert h._hub_request_authorized("bugfixer", ("bugfixer.lm.io",)) is False
    # An empty list is the same as absent.
    h2 = _hub({"bugfixer_cert_identities": []})
    assert h2._hub_request_authorized("bugfixer", ("bugfixer.lm.io",)) is False


def test_no_peer_cert_denies():
    """No client cert presented (mTLS off / plaintext / extraction failed) →
    denied, even when a BugFixer cert is pinned. The spoke_id alone is NOT a
    credential."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    assert h._hub_request_authorized("bugfixer", None) is False
    assert h._hub_request_authorized("bugfixer", ()) is False
    # A spoke that merely claims the bugfixer id but presents no cert is denied.
    assert h._hub_request_authorized("bugfixer", None) is False


def test_cert_mismatch_denies():
    """A valid fleet cert that is NOT the pinned BugFixer cert is denied — every
    spoke presents the same LE wildcard, so chain-validity alone can't distinguish
    BugFixer. Only the pinned identity authorizes."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    assert h._hub_request_authorized("netbox-server", ("*.lm.io",)) is False
    assert h._hub_request_authorized("bugfixer", ("hub.lm.io",)) is False


def test_spoke_id_alone_never_authorizes():
    """The hostname-spoof hole this closes: a box named 'bugfixer' (or
    'x-bugfixer-y') presenting the generic fleet cert is NOT authorized — identity
    is the cert, not the spoke_id claim. spoke_id is ignored entirely."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    for sid in ("bugfixer", "BUGFIXER", "BugFixer", "x-bugfixer-y", "my-bugfixer-1"):
        assert h._hub_request_authorized(sid, ("*.lm.io",)) is False


def test_any_pinned_name_matching_multi_san_cert_authorizes():
    """A cert may carry several SAN DNS names; a match on ANY of them (against
    any pinned name) authorizes. Covers a BugFixer cert issued with both an apex
    and a wildcard / alias SAN."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io", "fixer.lm.io"]})
    assert h._hub_request_authorized("bugfixer", ("bugfixer.lm.io", "fixer.lm.io")) is True
    # Match on the second pinned name alone.
    assert h._hub_request_authorized("bugfixer", ("fixer.lm.io", "other.lm.io")) is True


def test_pinned_match_is_case_sensitive():
    """DNS names are case-sensitive here (the LE checkbox stores the cert's
    domain verbatim; the peer-cert identity is the cert's SAN verbatim). A
    cert presenting 'BugFixer.LM.IO' does not match a pinned 'bugfixer.lm.io'."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    assert h._hub_request_authorized("bugfixer", ("BugFixer.LM.IO",)) is False
    assert h._hub_request_authorized("bugfixer", ("bugfixer.lm.io",)) is True


# ── handle_hub_request denial branch (end-to-end) ──────────────────────────────

def test_handle_hub_request_denies_non_authorized_and_records_event():
    """A spoke presenting the generic fleet cert (not the pinned BugFixer cert)
    is refused BEFORE any handler runs — no fleet action, no log harvest — and
    the refusal is surfaced as a lifecycle event + an error result the spoke
    sees."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    r = asyncio.run(
        h.handle_hub_request("netbox-server", {"type": "TRIGGER_ALL_UPDATES"},
                             ("*.lm.io",)))
    assert r["status"] == "error"
    assert "not authorized" in r["message"]
    # Denial recorded (visible in Setup → diagnostics).
    assert any(ev[1] == "hub_request_denied" for ev in h.events)
    assert ("netbox-server", "hub_request_denied") == (h.events[-1][0], h.events[-1][1])


def test_handle_hub_request_denies_get_logs_without_pinned_cert():
    """GET_LOGS (cross-tenant) is the cross-tenant leak vector — denied to a
    plain spoke even though it's an approved, signed sender with a valid fleet
    cert, because that cert isn't the pinned BugFixer cert."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    r = asyncio.run(
        h.handle_hub_request("cs-spoke-A", {"type": "GET_LOGS"},
                             ("hub.lm.io",)))
    assert r["status"] == "error"
    assert "not authorized" in r["message"]


def test_handle_hub_request_denies_when_no_cert_presented():
    """mTLS off / no client cert → denied before dispatch, even for a spoke named
    'bugfixer'. The cert is the credential, not the spoke_id."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]})
    r = asyncio.run(
        h.handle_hub_request("bugfixer", {"type": "GET_LOGS"}, None))
    assert r["status"] == "error"
    assert "not authorized" in r["message"]


def test_handle_hub_request_allows_pinned_bugfixer_get_logs_to_proceed():
    """BugFixer presenting the pinned cert still gets through to the GET_LOGS
    handler (it needs every tenant's logs to find problems). collect_all_logs is
    stubbed so the handler runs to completion and returns its result."""
    h = _hub({"bugfixer_cert_identities": ["bugfixer.lm.io"]},
             extra={"collect_all_logs": lambda: {"logs": {"bugfixer": ["line1"]}}})
    r = asyncio.run(
        h.handle_hub_request("bugfixer", {"type": "GET_LOGS"},
                             ("bugfixer.lm.io",)))
    assert r == {"logs": {"bugfixer": ["line1"]}}
    # No denial event for the authorized caller.
    assert all(ev[1] != "hub_request_denied" for ev in h.events)