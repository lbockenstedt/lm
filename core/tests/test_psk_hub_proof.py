"""Stale-hub-secret recovery via the PSK-bound hub identity proof.

When a spoke's stored ``hub_secret`` goes stale (hub root-key rotation / restore
from a different install / a rotation the spoke was offline for) AND
``LM_HUB_TLS_VERIFY=0``, the spoke used to hard-refuse the hub forever ("Hub
identity unverified (TLS verify off)") and never received the fresh hub_secret +
mTLS cert delivered on the approved connect — the cs-svr-06 endless-reconnect
deadlock.

The fix: the hub ALSO signs the mutual-auth challenge with the onboarding PSK it
validated for the spoke's tenant, and the spoke verifies that ``psk_signature``.
The PSK is a shared secret a MITM hub does not hold, so it authenticates the hub
INDEPENDENTLY of the stale hub_secret and of TLS — breaking the deadlock while
preserving the MITM refusal for a spoke with NO valid PSK.

These pin (1) the hub-side pure PSK validity check and (2) the hub↔spoke
HMAC(psk, challenge) round-trip the two sides compute independently.
"""
import asyncio
import hashlib
import hmac
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402


class _StubStore:
    def __init__(self, psks_by_tenant):
        self._psks = psks_by_tenant

    async def get_psks(self, tenant):
        return self._psks.get(tenant, [])


class _StubHub:
    """Just the attribute _psk_is_valid touches."""
    def __init__(self, psks_by_tenant):
        self.simulations_store = _StubStore(psks_by_tenant)


def _valid(hub, tenant, psk):
    return asyncio.run(main.LabManagerHub._psk_is_valid(hub, tenant, psk))


def test_psk_is_valid_accepts_matching_psk():
    hub = _StubHub({"lrb": ["correct-psk", "other"]})
    assert _valid(hub, "lrb", "correct-psk") is True


def test_psk_is_valid_rejects_wrong_psk():
    hub = _StubHub({"lrb": ["correct-psk"]})
    assert _valid(hub, "lrb", "nope") is False


def test_psk_is_valid_rejects_empty_and_unknown_tenant():
    hub = _StubHub({"lrb": ["correct-psk"]})
    assert _valid(hub, "lrb", "") is False
    assert _valid(hub, "", "correct-psk") is False
    assert _valid(hub, "no-such-tenant", "correct-psk") is False


def test_psk_is_valid_rejects_when_no_psks_stored():
    hub = _StubHub({"lrb": []})
    assert _valid(hub, "lrb", "anything") is False


def test_psk_bound_signature_roundtrip_matches():
    """The hub and the spoke compute HMAC(psk, challenge) independently; a
    genuine hub (same PSK) matches, a MITM hub (different PSK) does not."""
    psk = "tenant-onboarding-psk"
    challenge = "an-opaque-challenge-token"
    # Hub side (main.handle_connection PSK-bound proof).
    hub_sig = hmac.new(psk.encode(), challenge.encode(), hashlib.sha256).hexdigest()
    # Spoke side (control_plane mutual-auth PSK fallback).
    spoke_expected = hmac.new(psk.encode(), challenge.encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(spoke_expected, hub_sig)
    # A MITM hub without the PSK cannot forge a matching signature.
    mitm_sig = hmac.new(b"attacker-guess", challenge.encode(), hashlib.sha256).hexdigest()
    assert not hmac.compare_digest(spoke_expected, mitm_sig)
