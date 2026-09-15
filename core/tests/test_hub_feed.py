"""hub_feed.py — production→branch-hub replay feeder.

The risky half of this script is not the replay, it is the scrub. Anything that
slips through ``scrub_snapshot`` gets shipped from the production hub to a lab
hub that is, by definition, less hardened. These tests pin the scrub, the
same-hub refusal, and the sharding that decides how the target sees the fleet.

Pure functions only — the replay half needs the lm core on disk and a live hub,
which is why ``hub_feed`` defers that import into ``_load_feed_spoke``.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

import hub_feed  # noqa: E402


SALT = "test-salt"


# --------------------------------------------------------------------------
# Scrubbing
# --------------------------------------------------------------------------

def test_identifying_fields_are_replaced():
    out = hub_feed.scrub_snapshot({
        "hostname": "mipbe-svcs01",
        "mac": "a4:bb:6d:11:22:33",
        "ip": "172.16.1.31",
        "serial": "CN12345678",
    }, SALT)
    assert out["hostname"] != "mipbe-svcs01"
    assert out["mac"] != "a4:bb:6d:11:22:33"
    assert out["ip"] != "172.16.1.31"
    assert out["serial"] != "CN12345678"


def test_pseudonyms_are_stable_within_a_salt():
    """The hub dedups clients by hostname — a value that churned every poll
    would inflate the target's roster instead of mirroring production."""
    a = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, SALT)
    b = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, SALT)
    assert a == b


def test_pseudonyms_differ_across_salts():
    """Two feeds must not be correlatable back to the same real fleet."""
    a = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, "salt-a")
    b = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, "salt-b")
    assert a != b


def test_distinct_inputs_get_distinct_pseudonyms():
    vals = {hub_feed._pseudonym(f"host-{i}", SALT) for i in range(200)}
    assert len(vals) > 150, "pseudonym space is collapsing; roster shape would distort"


def test_secret_bearing_fields_are_dropped_not_pseudonymised():
    """A pseudonym of a secret is still a secret-shaped value. Drop, don't map."""
    out = hub_feed.scrub_snapshot({
        "hostname": "box1",
        "password": "hunter2",
        "api_key": "sk-live-abc",
        "hub_secret": "rotating-root",
        "session_token": "eyJ...",
    }, SALT)
    assert "password" not in out
    assert "api_key" not in out
    assert "hub_secret" not in out
    assert "session_token" not in out
    assert "hostname" in out


def test_scrub_is_recursive_through_lists_and_nesting():
    out = hub_feed.scrub_snapshot({
        "clients": [{"hostname": "a", "config": {"wsite": "denver", "mac": "aa:bb"}}],
    }, SALT)
    c = out["clients"][0]
    assert c["hostname"] != "a"
    assert c["config"]["wsite"] != "denver"
    assert c["config"]["mac"] != "aa:bb"


def test_structure_is_preserved_exactly():
    """Shape is the payload — counts and nesting must survive untouched."""
    snap = {"clients": [{"hostname": f"h{i}", "vmid": 90000 + i, "online": True}
                        for i in range(7)]}
    out = hub_feed.scrub_snapshot(snap, SALT)
    assert len(out["clients"]) == 7
    assert [c["vmid"] for c in out["clients"]] == [90000 + i for i in range(7)]
    assert all(c["online"] is True for c in out["clients"])


def test_long_tail_key_names_are_caught():
    """Schema additions upstream must not silently start leaking."""
    out = hub_feed.scrub_snapshot({
        "primary_hostname": "real-box",
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "mgmt_ip": "10.0.0.5",
        "user_email": "someone@example.com",
    }, SALT)
    assert out["primary_hostname"] != "real-box"
    assert out["client_mac"] != "aa:bb:cc:dd:ee:ff"
    assert out["mgmt_ip"] != "10.0.0.5"
    assert out["user_email"] != "someone@example.com"


def test_synthetic_ips_and_macs_are_non_routable():
    """Scrubbed values must be safe if they ever escape: RFC 5737 TEST-NET-3
    and a locally-administered MAC, never a real vendor OUI."""
    assert hub_feed._pseudonym("10.1.2.3", SALT, "ip").startswith("203.0.113.")
    assert hub_feed._pseudonym("aa:bb:cc:dd:ee:ff", SALT, "mac").startswith("02:")


def test_non_string_values_are_left_alone():
    out = hub_feed.scrub_snapshot({"vm_count": 3, "online": False, "ratio": 0.5,
                                   "tags": None}, SALT)
    assert out == {"vm_count": 3, "online": False, "ratio": 0.5, "tags": None}


# --------------------------------------------------------------------------
# Same-hub refusal
# --------------------------------------------------------------------------

def test_refuses_when_source_and_target_are_the_same_hub():
    """Feeding production its own scrubbed data would write synthetic spokes
    into real state — the one mistake with no clean undo."""
    with pytest.raises(SystemExit):
        hub_feed._assert_distinct("https://hub.example.com", "wss://hub.example.com:443")


def test_refuses_across_scheme_and_case_differences():
    with pytest.raises(SystemExit):
        hub_feed._assert_distinct("https://HUB.example.com:443", "wss://hub.example.com")


def test_allows_genuinely_distinct_hubs():
    hub_feed._assert_distinct("https://prod.example.com", "wss://qa.example.com:443")


def test_same_host_different_port_is_allowed():
    """A branch hub on an alternate port of one box is a legitimate setup."""
    hub_feed._assert_distinct("https://hub.example.com:443", "wss://hub.example.com:8443")


# --------------------------------------------------------------------------
# Sharding / payload assembly
# --------------------------------------------------------------------------

def test_clients_are_grouped_back_into_per_spoke_buckets():
    snap = {"clients": [{"hostname": "a", "spoke_id": "s1"},
                        {"hostname": "b", "spoke_id": "s1"},
                        {"hostname": "c", "spoke_id": "s2"}]}
    buckets = hub_feed.shard_by_spoke(snap)
    assert len(buckets["s1"]["clients"]) == 2
    assert len(buckets["s2"]["clients"]) == 1


def test_unattributed_rows_are_kept_not_dropped():
    """Better one catch-all spoke than a silently smaller fleet."""
    buckets = hub_feed.shard_by_spoke({"clients": [{"hostname": "a"}]})
    assert len(buckets["unattributed"]["clients"]) == 1


def test_aggregate_endpoints_wrapped_in_an_envelope_are_unwrapped():
    buckets = hub_feed.shard_by_spoke({"clients": {"clients": [{"spoke_id": "s1"}]}})
    assert "s1" in buckets


def test_build_payloads_prefixes_every_spoke_id():
    """The prefix is how these get bulk-deleted from the target afterwards."""
    payloads = hub_feed.build_payloads(
        {"clients": [{"hostname": "a", "spoke_id": "s1"}]}, SALT, "feed-")
    assert payloads
    assert all(sid.startswith("feed-") for sid in payloads)


def test_build_payloads_emits_the_cs_telemetry_shape():
    payloads = hub_feed.build_payloads(
        {"clients": [{"hostname": "a", "spoke_id": "s1"}],
         "proxmox": [{"vmid": 90001, "spoke_id": "s1"}]}, SALT, "feed-")
    body = next(iter(payloads.values()))
    assert set(body) >= {"clients", "proxmox_vms", "vm_count", "usb_count"}
    assert body["vm_count"] == 1


def test_build_payloads_scrubs_before_emitting():
    """The scrub must happen on the way out, not as a later step someone can
    forget to call."""
    payloads = hub_feed.build_payloads(
        {"clients": [{"hostname": "mipbe-svcs01", "spoke_id": "s1"}]}, SALT, "feed-")
    blob = repr(payloads)
    assert "mipbe-svcs01" not in blob


def test_real_spoke_ids_do_not_survive_into_target_ids():
    payloads = hub_feed.build_payloads(
        {"clients": [{"spoke_id": "cs-svr-01"}]}, SALT, "feed-")
    assert all("cs-svr-01" not in sid for sid in payloads)
