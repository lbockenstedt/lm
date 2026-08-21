"""Agent-hardening shield: an ALREADY-APPROVED install that presents a stale
session secret on a cold reconnect (VM reboot, hub restart, or a key rotation
that outlived the success-grace window) must NOT be counted as a credential
brute-force.

A generic agent fans out several role sub-spokes (``{base}-{role}``) from one
IP; without this shield a reboot makes each fail ``invalid_secret`` and the
shared IP crosses the threat-monitor threshold, NSG-blocking the whole agent.
``LabManagerHub._is_approved_install_reconnect`` exempts exactly the case where
the peer proves its identity with a matching, hub-minted 128-bit
``install_uuid`` — something a real guessing attacker cannot forge.

The predicate is fail-closed: anything short of a uuid that maps to the SAME,
APPROVED identity still records the failure so real attacks are caught.
"""
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import main  # noqa: E402


class _FakeHub:
    """Minimal stand-in exposing only what the shield reads.

    ``_primary_key`` is identity here (no rename migration in play), matching the
    default hub behavior before the Phase-2b guid migration fires.
    """
    def __init__(self, uuid_index, approved):
        self.install_uuid_index = uuid_index
        self.approved_modules = approved

    def _primary_key(self, spoke_id):
        return spoke_id


def _check(hub, spoke_id, install_uuid):
    return main.LabManagerHub._is_approved_install_reconnect(hub, spoke_id, install_uuid)


_UUID = "a" * 32  # a hub-minted 128-bit install id (hex)


def test_approved_install_reconnect_is_exempt():
    # uuid maps to THIS identity and it is approved → exempt (no threat feed).
    hub = _FakeHub({_UUID: "dns-agent-1"}, {"dns-agent-1": True})
    assert _check(hub, "dns-agent-1", _UUID) is True


def test_missing_uuid_is_not_exempt():
    # A real guesser has no install_uuid → failure must still be recorded.
    hub = _FakeHub({_UUID: "dns-agent-1"}, {"dns-agent-1": True})
    assert _check(hub, "dns-agent-1", "") is False
    assert _check(hub, "dns-agent-1", None) is False


def test_unknown_uuid_is_not_exempt():
    # A forged/never-minted uuid resolves to no owner → not exempt.
    hub = _FakeHub({_UUID: "dns-agent-1"}, {"dns-agent-1": True})
    assert _check(hub, "dns-agent-1", "f" * 32) is False


def test_uuid_owned_by_different_identity_is_not_exempt():
    # A stolen uuid presented under a DIFFERENT spoke_id must not launder the
    # attempt: the uuid must map back to the connecting identity.
    hub = _FakeHub({_UUID: "dns-agent-1"}, {"dns-agent-1": True, "evil-agent-9": True})
    assert _check(hub, "evil-agent-9", _UUID) is False


def test_known_but_unapproved_install_is_not_exempt():
    # Identity matches but was never approved → still a failure signal.
    hub = _FakeHub({_UUID: "dns-agent-1"}, {"dns-agent-1": False})
    assert _check(hub, "dns-agent-1", _UUID) is False


def test_shield_fails_closed_on_error():
    class _Broken:
        install_uuid_index = {_UUID: "dns-agent-1"}
        def _primary_key(self, s):
            raise RuntimeError("boom")
    # An internal error must never grant the exemption.
    assert main.LabManagerHub._is_approved_install_reconnect(_Broken(), "x", _UUID) is False


# ── reconnect exemption budget (rate cap) ───────────────────────────────────

class _BudgetHub:
    _RECONNECT_EXEMPTION_WINDOW_S = main.LabManagerHub._RECONNECT_EXEMPTION_WINDOW_S
    _RECONNECT_EXEMPTION_CAP = main.LabManagerHub._RECONNECT_EXEMPTION_CAP

    def __init__(self):
        self._known_install_glitches = {}


def _budget(hub, ip):
    return main.LabManagerHub._within_reconnect_exemption_budget(hub, ip)


def test_reconnect_budget_allows_a_reboot_burst():
    # A 15-role agent rebooting (with retries) stays well under the cap.
    hub = _BudgetHub()
    assert all(_budget(hub, "10.0.0.5") for _ in range(45)) is True


def test_reconnect_budget_blocks_a_sustained_stream():
    # A leaked-uuid guessing loop from one IP eventually blows the budget →
    # further attempts are no longer exempt (fall back to invalid_secret).
    hub = _BudgetHub()
    cap = main.LabManagerHub._RECONNECT_EXEMPTION_CAP
    exempt = [_budget(hub, "203.0.113.9") for _ in range(cap + 5)]
    assert exempt[:cap] == [True] * cap          # within budget
    assert exempt[cap] is False                   # first over-budget attempt
    assert exempt[-1] is False                    # stays blocked


def test_reconnect_budget_is_per_ip():
    # One noisy IP must not consume another IP's budget.
    hub = _BudgetHub()
    cap = main.LabManagerHub._RECONNECT_EXEMPTION_CAP
    for _ in range(cap + 5):
        _budget(hub, "203.0.113.9")
    assert _budget(hub, "10.0.0.6") is True


def test_reconnect_budget_fails_open_without_ip():
    hub = _BudgetHub()
    assert _budget(hub, "") is True
    assert _budget(hub, None) is True

