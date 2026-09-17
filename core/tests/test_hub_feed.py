"""hub_feed.py — production→branch-hub replay feeder.

The feed is VERBATIM by default: the point is to duplicate a production fleet
so an issue reproduces against the identifiers actually seen in the field, and
pseudonyms defeat that. Anonymising is an opt-in on the source
(``pseudonymise=True``). These tests pin BOTH modes, plus the one rule that
holds in either — secrets are never forwarded — and the same-hub refusal and
sharding that decide how the target sees the fleet.

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

def test_identifying_fields_are_replaced_when_anonymising():
    out = hub_feed.scrub_snapshot({
        "hostname": "mipbe-svcs01",
        "mac": "a4:bb:6d:11:22:33",
        "ip": "172.16.1.31",
        "serial": "CN12345678",
    }, SALT, pseudonymise=True)
    assert out["hostname"] != "mipbe-svcs01"
    assert out["mac"] != "a4:bb:6d:11:22:33"
    assert out["ip"] != "172.16.1.31"
    assert out["serial"] != "CN12345678"


def test_pseudonyms_are_stable_within_a_salt():
    """The hub dedups clients by hostname — a value that churned every poll
    would inflate the target's roster instead of mirroring production."""
    a = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, SALT, pseudonymise=True)
    b = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, SALT, pseudonymise=True)
    assert a == b


def test_pseudonyms_differ_across_salts():
    """Two feeds must not be correlatable back to the same real fleet."""
    a = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, "salt-a", pseudonymise=True)
    b = hub_feed.scrub_snapshot({"hostname": "cs-svr-01"}, "salt-b", pseudonymise=True)
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


def test_anonymising_is_recursive_through_lists_and_nesting():
    out = hub_feed.scrub_snapshot({
        "clients": [{"hostname": "a", "config": {"wsite": "denver", "mac": "aa:bb"}}],
    }, SALT, pseudonymise=True)
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


def test_long_tail_key_names_are_caught_when_anonymising():
    """Schema additions upstream must not silently start leaking."""
    out = hub_feed.scrub_snapshot({
        "primary_hostname": "real-box",
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "mgmt_ip": "10.0.0.5",
        "user_email": "someone@example.com",
    }, SALT, pseudonymise=True)
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


def test_build_payloads_drops_secrets_before_emitting():
    """The one rule that holds in BOTH modes, and it must happen on the way
    out — not as a later step someone can forget to call."""
    payloads = hub_feed.build_payloads(
        {"clients": [{"hostname": "mipbe-svcs01", "spoke_id": "s1",
                      "password": "hunter2", "api_key": "sk-live"}]}, SALT, "feed-")
    blob = repr(payloads)
    assert "hunter2" not in blob
    assert "sk-live" not in blob


def test_real_spoke_ids_do_not_survive_into_target_ids():
    payloads = hub_feed.build_payloads(
        {"clients": [{"spoke_id": "cs-svr-01"}]}, SALT, "feed-")
    assert all("cs-svr-01" not in sid for sid in payloads)


def test_spoke_attribution_inside_rows_is_anonymised_too():
    """Regression: SimulationsService._meta stamps spoke_id/spoke_name/
    spoke_hostname onto EVERY client row. Pseudonymising only the synthetic
    envelope id left the real fleet's spoke names in the payload body — so when
    anonymising IS on, these must be covered too."""
    scrubbed = hub_feed.scrub_snapshot({"clients": [{
        "spoke_id": "cs-svr-01",
        "spoke_name": "Denver Lab",
        "spoke_hostname": "cs-svr-01.lab.internal",
        "hostname": "realbox",
    }]}, SALT, pseudonymise=True)
    blob = repr(scrubbed)
    for leaked in ("cs-svr-01", "Denver Lab", "cs-svr-01.lab.internal", "realbox"):
        assert leaked not in blob, f"{leaked!r} survived anonymisation"


def test_proxmox_node_names_are_anonymised():
    scrubbed = hub_feed.scrub_snapshot(
        {"proxmox": [{"node": "pve-denver-01", "vmid": 90001, "spoke_id": "s1"}]},
        SALT, pseudonymise=True)
    assert "pve-denver-01" not in repr(scrubbed)


# --------------------------------------------------------------------------
# Verbatim — the default
# --------------------------------------------------------------------------

def test_verbatim_is_the_default():
    """The feature exists to duplicate a production fleet. A default that
    rewrote identifiers would quietly defeat that for anyone who did not find
    the toggle."""
    out = hub_feed.scrub_snapshot({
        "hostname": "mipbe-svcs01",
        "mac": "a4:bb:6d:11:22:33",
        "ip": "172.16.1.31",
        "serial": "CN12345678",
        "spoke_name": "Denver Lab",
    }, SALT)
    assert out["hostname"] == "mipbe-svcs01"
    assert out["mac"] == "a4:bb:6d:11:22:33"
    assert out["ip"] == "172.16.1.31"
    assert out["serial"] == "CN12345678"
    assert out["spoke_name"] == "Denver Lab"


def test_secrets_are_dropped_even_verbatim():
    """The one thing verbatim mode does NOT include. Faithful fleet data never
    requires live credentials, and the receiving hub is less hardened."""
    out = hub_feed.scrub_snapshot({
        "hostname": "realbox",
        "password": "hunter2",
        "api_key": "sk-live-abc",
        "hub_secret": "rotating-root",
        "session_token": "eyJ...",
        "private_key": "-----BEGIN...",
    }, SALT)
    assert out == {"hostname": "realbox"}


def test_verbatim_preserves_structure_and_non_strings():
    snap = {"clients": [{"hostname": f"h{i}", "vmid": 90000 + i, "online": True}
                        for i in range(7)]}
    out = hub_feed.scrub_snapshot(snap, SALT)
    assert out == snap


def test_build_payloads_is_verbatim_end_to_end():
    """The receiver re-runs the scrub on the way in; with verbatim as the
    default that must be a pass-through, not a second chance to rewrite."""
    payloads = hub_feed.build_payloads(
        {"clients": [{"hostname": "mipbe-svcs01", "spoke_id": "cs-svr-01",
                      "ip": "172.16.1.31"}]}, SALT, "feed-")
    body = next(iter(payloads.values()))
    assert body["clients"][0]["hostname"] == "mipbe-svcs01"
    assert body["clients"][0]["ip"] == "172.16.1.31"


def test_booleans_alongside_scrubbed_keys_are_untouched():
    """spoke_online is a bool on the same rows — scrubbing must not coerce it."""
    payloads = hub_feed.build_payloads(
        {"clients": [{"spoke_id": "s1", "spoke_online": True, "online": False}]},
        SALT, "feed-")
    row = next(iter(payloads.values()))["clients"][0]
    assert row["spoke_online"] is True
    assert row["online"] is False


# --------------------------------------------------------------------------
# Access-token rotation
# --------------------------------------------------------------------------

class _Resp(__import__("io").BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _mk_source(monkeypatch, token="t0", refresh="r0"):
    return hub_feed.SourceHub("https://src", token=token, refresh_token=refresh)


def test_expired_access_token_is_rotated_and_the_call_retried(monkeypatch):
    """A 401 mid-feed must refresh and retry, not kill the feed."""
    import json
    import urllib.error
    src = _mk_source(monkeypatch)
    calls = {"get": 0}

    def _open(req, *a, **kw):
        url = req.full_url
        if url.endswith("/auth/token/refresh"):
            return _Resp(json.dumps({"access_token": "t1", "refresh_token": "r1"}).encode())
        calls["get"] += 1
        if calls["get"] == 1:
            raise urllib.error.HTTPError(url, 401, "expired", {}, None)
        return _Resp(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(src.opener, "open", _open)
    assert src._get_json("/api/test-feed/snapshot") == {"ok": True}
    assert src.token == "t1"
    assert src.refresh_token == "r1", "the rotated refresh token must replace the spent one"


def test_rotation_emits_the_token_sentinel_when_asked(monkeypatch, capsys):
    """With --emit-token-rotations, a successful rotation prints one sentinel
    line carrying the new pair so the parent hub can persist it. The parser on
    the hub side keys off TOKEN_ROTATION_SENTINEL, so it must be present and the
    JSON must round-trip."""
    import json
    import urllib.error
    src = hub_feed.SourceHub("https://src", token="t0", refresh_token="r0",
                             emit_rotations=True)
    calls = {"get": 0}

    def _open(req, *a, **kw):
        url = req.full_url
        if url.endswith("/auth/token/refresh"):
            return _Resp(json.dumps({"access_token": "t1", "refresh_token": "r1"}).encode())
        calls["get"] += 1
        if calls["get"] == 1:
            raise urllib.error.HTTPError(url, 401, "expired", {}, None)
        return _Resp(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(src.opener, "open", _open)
    src._get_json("/api/test-feed/snapshot")
    lines = [l for l in capsys.readouterr().out.splitlines()
             if l.startswith(hub_feed.TOKEN_ROTATION_SENTINEL)]
    assert len(lines) == 1
    pair = json.loads(lines[0][len(hub_feed.TOKEN_ROTATION_SENTINEL):])
    assert pair == {"access": "t1", "refresh": "r1"}


def test_rotation_is_silent_when_not_asked(monkeypatch, capsys):
    """Default off: a human running the feeder by hand must never see tokens
    printed to their terminal."""
    import json
    import urllib.error
    src = _mk_source(monkeypatch)  # emit_rotations defaults False
    calls = {"get": 0}

    def _open(req, *a, **kw):
        url = req.full_url
        if url.endswith("/auth/token/refresh"):
            return _Resp(json.dumps({"access_token": "t1", "refresh_token": "r1"}).encode())
        calls["get"] += 1
        if calls["get"] == 1:
            raise urllib.error.HTTPError(url, 401, "expired", {}, None)
        return _Resp(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(src.opener, "open", _open)
    src._get_json("/api/test-feed/snapshot")
    assert hub_feed.TOKEN_ROTATION_SENTINEL not in capsys.readouterr().out


def test_a_spent_refresh_token_is_not_reused(monkeypatch):
    """Refresh tokens are single-use and reuse revokes the whole family — a
    retry that re-sent the spent token would lock the feed out for good."""
    import urllib.error
    src = _mk_source(monkeypatch)
    seen = []

    def _open(req, *a, **kw):
        if req.full_url.endswith("/auth/token/refresh"):
            seen.append(1)
            raise urllib.error.HTTPError(req.full_url, 401, "spent", {}, None)
        raise urllib.error.HTTPError(req.full_url, 401, "expired", {}, None)

    monkeypatch.setattr(src.opener, "open", _open)
    with pytest.raises(urllib.error.HTTPError):
        src._get_json("/api/test-feed/snapshot")
    assert src.refresh_token == "", "a rejected refresh token must be discarded"
    # A second call must not attempt the refresh again.
    with pytest.raises(urllib.error.HTTPError):
        src._get_json("/api/test-feed/snapshot")
    assert len(seen) == 1


def test_without_a_refresh_token_a_401_propagates(monkeypatch):
    """No silent infinite retry against a genuinely revoked token."""
    import urllib.error
    src = _mk_source(monkeypatch, refresh="")

    def _open(req, *a, **kw):
        raise urllib.error.HTTPError(req.full_url, 401, "revoked", {}, None)

    monkeypatch.setattr(src.opener, "open", _open)
    with pytest.raises(urllib.error.HTTPError):
        src._get_json("/api/test-feed/snapshot")


def test_non_401_errors_are_not_retried(monkeypatch):
    """A 500 on the source is not an auth problem; rotating on it would burn a
    refresh token for nothing."""
    import urllib.error
    src = _mk_source(monkeypatch)
    tried = {"refresh": 0}

    def _open(req, *a, **kw):
        if req.full_url.endswith("/auth/token/refresh"):
            tried["refresh"] += 1
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    monkeypatch.setattr(src.opener, "open", _open)
    with pytest.raises(urllib.error.HTTPError):
        src._get_json("/api/test-feed/snapshot")
    assert tried["refresh"] == 0


# --------------------------------------------------------------------------
# Preserve-mode tenant routing (_resolve_tenant)
# --------------------------------------------------------------------------

def test_preserve_maps_source_tenant_to_local():
    """A spoke carrying its source tenant is routed to the mapped local tenant
    so a multi-tenant fleet keeps its shape on the receiver."""
    m = {"acme": "acme-local", "globex": "globex-local"}
    assert hub_feed._resolve_tenant({"tenant": "acme"}, m, "fallback") == "acme-local"
    assert hub_feed._resolve_tenant({"tenant": "globex"}, m, "fallback") == "globex-local"


def test_preserve_unmapped_source_tenant_falls_back():
    """A source tenant with no local match uses the fallback rather than
    onboarding into a tenant the receiver never registered a PSK for."""
    assert hub_feed._resolve_tenant({"tenant": "unknown"}, {"acme": "acme"},
                                    "shared") == "shared"


def test_preserve_unattributed_spoke_uses_fallback():
    """A spoke with no source tenant (older/anonymised source) uses fallback."""
    assert hub_feed._resolve_tenant({}, {"acme": "acme"}, "shared") == "shared"
    assert hub_feed._resolve_tenant({"tenant": ""}, {"acme": "acme"}, "shared") == "shared"


def test_without_a_map_every_spoke_uses_the_single_tenant():
    """Non-preserve mode (empty map) ignores any per-spoke tenant and binds the
    whole fleet to --tenant — the historical behaviour."""
    assert hub_feed._resolve_tenant({"tenant": "acme"}, {}, "the-one") == "the-one"


def test_no_tenant_at_all_onboards_unbound():
    """No map and no default means bind nothing (None) rather than the empty
    string, which would be a real, wrong tenant id."""
    assert hub_feed._resolve_tenant({"tenant": "acme"}, {}, "") is None


def test_tenant_map_arg_is_parsed_and_exposed(monkeypatch):
    """--tenant-map arrives as a JSON string on argv; main() must parse it into
    args._tenant_map as str→str with empty targets dropped."""
    seen = {}

    class _FakeSource:
        def __init__(self, *a, **kw): pass
        def login(self, *a, **kw): pass

    def _fake_run(args, source, salt):
        seen["map"] = getattr(args, "_tenant_map", None)

    monkeypatch.setattr(hub_feed, "SourceHub", _FakeSource)
    monkeypatch.setattr(hub_feed, "_run", _fake_run)
    monkeypatch.setattr(hub_feed.asyncio, "run", lambda coro: None)
    argv = ["hub_feed.py", "--source", "https://src", "--target", "wss://dst:443",
            "--token", "t", "--tenant", "fb",
            "--tenant-map", '{"acme": "acme-local", "skip": ""}']
    monkeypatch.setattr(sys, "argv", argv)
    hub_feed.main()
    assert seen["map"] == {"acme": "acme-local"}


def test_bad_tenant_map_is_rejected(monkeypatch):
    """Invalid JSON in --tenant-map is an operator error, surfaced by argparse
    (SystemExit) rather than silently ignored."""
    class _FakeSource:
        def __init__(self, *a, **kw): pass
        def login(self, *a, **kw): pass

    monkeypatch.setattr(hub_feed, "SourceHub", _FakeSource)
    argv = ["hub_feed.py", "--source", "https://src", "--target", "wss://dst:443",
            "--token", "t", "--tenant-map", "{not json"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        hub_feed.main()
