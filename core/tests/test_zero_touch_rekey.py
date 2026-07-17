"""CC3: gate the zero-touch re-key of an approved, secret-less spoke on proof.

A spoke that was already approved and reconnects with NO session secret used
to be silently re-keyed on a bare ``spoke_id`` claim — and ``spoke_id``s are
hostname-derived and predictable. Anyone who opened a WS to the hub claiming an
approved ``spoke_id`` with no secret, while the real spoke was briefly offline
(restart / ``SPOKE_UPDATE`` / watchdog reboot), received a freshly minted
session key and was bound to the victim's tenant until evicted.

``LabManagerHub._zero_touch_rekey_proven`` is the gate: the re-key is allowed
only if the connecting box proves it is the original (its ``install_uuid`` is
the one the hub indexed for that ``spoke_id``) OR it presented a valid tenant
onboarding PSK this connection. Otherwise the re-key is refused and the spoke
re-onboards (PSK / admin approval).

This exercises the real helper against a stub ``install_uuid_index`` (the only
attribute it reads), mirroring the ``min_client_check``-style pure-helper
tests.
"""

import main  # noqa: E402  (core/src on sys.path via conftest)


def _hub(index):
    """A stub exposing only ``install_uuid_index`` (all the helper reads)."""
    class _H:
        pass
    h = _H()
    h.install_uuid_index = index
    # Bind the real unbound method so the test exercises production code.
    h._zero_touch_rekey_proven = main.LabManagerHub._zero_touch_rekey_proven.__get__(h, _H)
    return h


# ── proof accepted → re-key would proceed ───────────────────────────────────

def test_uuid_matching_recorded_index_proves_rekey():
    """The original box lost its secret but kept its .env UUID: the UUID it
    presents is the one the hub indexed for this spoke_id → re-key allowed."""
    hub = _hub({"UUID-1": "spoke-A"})
    assert hub._zero_touch_rekey_proven("spoke-A", "UUID-1", psk_proven=False)


def test_valid_psk_proves_rekey_regardless_of_uuid():
    """A spoke that self-provisioned via a valid tenant PSK this connection is
    re-keyed even with no / mismatched install_uuid (PSK is tenant proof)."""
    hub = _hub({})
    assert hub._zero_touch_rekey_proven("spoke-B", "", psk_proven=True)
    assert hub._zero_touch_rekey_proven("spoke-B", "wrong-uuid", psk_proven=True)


# ── proof missing → rekey refused (the takeover is blocked) ──────────────────

def test_bare_id_no_uuid_no_psk_refused():
    """The headline CC3 case: a stranger claims a predictable approved
    spoke_id with no secret and no UUID → refused (no key minted)."""
    hub = _hub({"UUID-1": "spoke-A"})
    assert hub._zero_touch_rekey_proven("spoke-A", "", psk_proven=False) is False


def test_wrong_uuid_refused():
    """A spoke_id claimed with a UUID the hub does NOT index for it → refused."""
    hub = _hub({"UUID-1": "spoke-A"})
    assert hub._zero_touch_rekey_proven("spoke-A", "UUID-OTHER", psk_proven=False) is False
    # An unknown UUID (not indexed at all) is also refused.
    assert hub._zero_touch_rekey_proven("spoke-A", "never-seen", psk_proven=False) is False


def test_empty_recorded_uuid_refused():
    """A spoke whose UUID was never recorded (pre-UUID-tracking / degraded .env)
    can't be proven by a keyless reconnect → refused (re-onboard)."""
    hub = _hub({})
    assert hub._zero_touch_rekey_proven("legacy-spoke", "", psk_proven=False) is False
    # Even a presented UUID can't prove anything if nothing is indexed for it.
    assert hub._zero_touch_rekey_proven("legacy-spoke", "some-uuid", psk_proven=False) is False


# ── the residual, accepted tradeoff ──────────────────────────────────────────

def test_copied_victim_uuid_passes_accepted_tradeoff():
    """CC3 (b)/(c) residual: an attacker who copied the victim's INSTALL_UUID
    out of its .env passes the uuid proof. Documented + accepted — it raises the
    bar from a predictable hostname to the box's private UUID, and CC2 already
    blocks the rename-migration path."""
    hub = _hub({"UUID-1": "spoke-A"})
    # Attacker claims spoke-A's id AND its copied UUID, no secret, no PSK.
    assert hub._zero_touch_rekey_proven("spoke-A", "UUID-1", psk_proven=False) is True


# ── index is the source, not metadata → survives an empty-uuid probe ──────────

def test_empty_uuid_probe_does_not_grant_rekey_but_index_intact():
    """An empty-uuid connection (attacker or degraded box) must not be re-keyed,
    and crucially the index entry for the real box is untouched so the real box
    can still reclaim on a later uuid-matching reconnect. (The handle_connection
    refusal path uses this helper, not module_metadata, for exactly this reason.)"""
    index = {"UUID-1": "spoke-A"}
    hub = _hub(index)
    # Empty-uuid probe is refused.
    assert hub._zero_touch_rekey_proven("spoke-A", "", psk_proven=False) is False
    # The index is unchanged — the real box can still prove itself.
    assert index == {"UUID-1": "spoke-A"}
    assert hub._zero_touch_rekey_proven("spoke-A", "UUID-1", psk_proven=False) is True