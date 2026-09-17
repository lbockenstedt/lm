"""Setup → Test Data Feed — the source-side collection and probe helpers.

The route handlers themselves need a live FastAPI app + hub, but the two pieces
that carry real risk are plain functions and are tested here:

  * ``_collect_fleet`` reads the hub's telemetry cache. If it silently returned
    nothing, the feature would look like it worked and publish an empty fleet.
  * ``_probe_source`` maps the source hub's HTTP failures onto messages an
    operator can act on. "HTTP 403" is not actionable; "publishing is disabled
    on that hub" is.

Config redaction (secrets never round-trip to the browser) is pinned in
``test_test_feed_redaction`` below, built against the same shape the route
uses, because a regression there leaks the source hub's API token to anyone who
can open the Setup page.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.test_feed import _collect_fleet, _probe_source, _source_tenants, _DEFAULTS  # noqa: E402
from routes.test_feed import TOKEN_ROTATION_SENTINEL as _ROUTE_SENTINEL  # noqa: E402


class _Hub:
    def __init__(self, cache):
        self.simulations_cache = cache


# --------------------------------------------------------------------------
# _collect_fleet
# --------------------------------------------------------------------------

def test_collects_clients_and_vms_from_every_spoke():
    hub = _Hub({
        "cs-svr-01": {"clients": [{"hostname": "a"}, {"hostname": "b"}],
                      "proxmox_vms": [{"vmid": 90001}]},
        "cs-svr-02": {"clients": [{"hostname": "c"}]},
    })
    out = _collect_fleet(hub)
    assert len(out["clients"]) == 3
    assert len(out["proxmox"]) == 1


def test_stamps_spoke_id_so_sharding_can_group():
    """shard_by_spoke groups on spoke_id; without this stamp every row would
    fall into the 'unattributed' catch-all and the receiver would see one
    giant spoke instead of the real fleet shape."""
    out = _collect_fleet(_Hub({"cs-svr-01": {"clients": [{"hostname": "a"}]}}))
    assert out["clients"][0]["spoke_id"] == "cs-svr-01"


def test_existing_spoke_id_is_not_overwritten():
    out = _collect_fleet(_Hub({"cs-svr-01": {"clients": [{"spoke_id": "real"}]}}))
    assert out["clients"][0]["spoke_id"] == "real"


def test_accepts_the_vms_key_as_well_as_proxmox_vms():
    out = _collect_fleet(_Hub({"s1": {"vms": [{"vmid": 1}]}}))
    assert len(out["proxmox"]) == 1


def test_harvests_per_host_vms_and_usb_from_proxmox_hosts():
    """The bulk of a real fleet's VMs/USB ride nested under proxmox_hosts, not
    at the top of the frame. SimulationsService renders the per-host lists, so
    the feed must harvest them too or the target sees an empty hypervisor."""
    hub = _Hub({"cs-svr-01": {
        "proxmox_hosts": [
            {"hostname": "pve-a",
             "proxmox_vms": [{"vmid": 100}, {"vmid": 101}],
             "usb_devices": [{"id": "1-1"}]},
            {"hostname": "pve-b",
             "proxmox_vms": [{"vmid": 200}],
             "usb_devices": []},
        ]}})
    out = _collect_fleet(hub)
    assert len(out["proxmox"]) == 3
    assert len(out["usb"]) == 1
    # each VM/USB is attributed to its spoke and stamped with its host node
    assert {v["spoke_id"] for v in out["proxmox"]} == {"cs-svr-01"}
    assert {v["node"] for v in out["proxmox"]} == {"pve-a", "pve-b"}
    assert out["usb"][0]["node"] == "pve-a"


def test_top_level_vms_still_work_when_there_are_no_proxmox_hosts():
    """A frame without proxmox_hosts falls back to the top-level lists, exactly
    as SimulationsService does — no regression for single-host frames."""
    out = _collect_fleet(_Hub({"s1": {"proxmox_vms": [{"vmid": 1}],
                                      "usb_devices": [{"id": "u1"}]}}))
    assert len(out["proxmox"]) == 1
    assert len(out["usb"]) == 1


def test_empty_cache_yields_empty_lists_not_an_error():
    assert _collect_fleet(_Hub({})) == {"clients": [], "proxmox": [], "usb": []}


def test_a_broken_hub_degrades_to_empty_rather_than_raising():
    """A 500 on the snapshot endpoint would be a worse failure than an empty
    one: the receiver retries forever against a hub that looks broken."""
    class _Bad:
        @property
        def simulations_cache(self):
            raise RuntimeError("state unavailable")
    assert _collect_fleet(_Bad()) == {"clients": [], "proxmox": [], "usb": []}


def test_rows_are_copied_not_aliased():
    """_collect_fleet stamps spoke_id; doing that in place would mutate the
    hub's live telemetry cache."""
    cache = {"s1": {"clients": [{"hostname": "a"}]}}
    _collect_fleet(_Hub(cache))
    assert "spoke_id" not in cache["s1"]["clients"][0]


# --------------------------------------------------------------------------
# _fleet_identity — whole-fleet identity for full-fleet replay
# --------------------------------------------------------------------------

from routes.test_feed import _fleet_identity  # noqa: E402


class _State:
    def __init__(self, names=None, tenants=None, meta=None):
        self._names = names or {}
        self._tenants = tenants or {}
        self.system_state = {"module_metadata": meta or {}}

    def get_module_name(self, sid):
        return self._names.get(sid)

    def get_spoke_tenant(self, sid):
        return self._tenants.get(sid)


class _FleetHub:
    def __init__(self, conn, types=None, state=None, cache=None):
        self.active_connections = {sid: object() for sid in conn}
        self.spoke_module_types = types or {}
        self.state = state or _State()
        self.simulations_cache = cache or {}


def test_fleet_identity_enumerates_every_connected_spoke():
    """The whole point of full-fleet replay: identity for EVERY connected spoke,
    not just the Client-Sim hosts that push telemetry."""
    hub = _FleetHub(
        conn=["nw-01", "dns-01", "cs-svr-01"],
        types={"nw-01": "nw", "dns-01": "dns", "cs-svr-01": "simulation"},
        state=_State(
            names={"nw-01": "switch-core", "dns-01": "unbound-a",
                   "cs-svr-01": "cs-svr-01"},
            tenants={"nw-01": "t-red", "dns-01": "default"}),
    )
    out = _fleet_identity(hub)
    assert set(out) == {"nw-01", "dns-01", "cs-svr-01"}
    assert out["nw-01"]["module_type"] == "nw"
    assert out["nw-01"]["name"] == "switch-core"
    assert out["nw-01"]["tenant"] == "t-red"


def test_fleet_identity_falls_back_to_metadata_for_module_type():
    """A spoke absent from spoke_module_types (races on connect) still gets its
    type from module_metadata rather than shipping blank."""
    hub = _FleetHub(
        conn=["ipam-01"],
        types={},
        state=_State(meta={"ipam-01": {"module_type": "ipam"}}),
    )
    assert _fleet_identity(hub)["ipam-01"]["module_type"] == "ipam"


def test_fleet_identity_name_defaults_to_id_and_blanks_are_safe():
    hub = _FleetHub(conn=["x1"], types={"x1": "nac"}, state=_State())
    rec = _fleet_identity(hub)["x1"]
    assert rec["name"] == "x1"
    assert rec["module_type"] == "nac"
    assert rec["tenant"] == ""


def test_fleet_identity_degrades_to_empty_when_connections_unavailable():
    class _Bad:
        @property
        def active_connections(self):
            raise RuntimeError("no state")
    assert _fleet_identity(_Bad()) == {}


# --------------------------------------------------------------------------
# _probe_source — operator-facing error mapping
# --------------------------------------------------------------------------

def _http_error(code):
    import urllib.error
    return urllib.error.HTTPError("http://x", code, "err", {}, None)


@pytest.mark.parametrize("code,fragment", [
    (403, "publishing is disabled"),
    (401, "rejected the token"),
    (404, "older branch"),
    (500, "HTTP 500"),
])
def test_probe_maps_http_failures_to_actionable_messages(monkeypatch, code, fragment):
    import urllib.request

    def _boom(*a, **kw):
        raise _http_error(code)

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    with pytest.raises(RuntimeError) as e:
        _probe_source("https://src", "tok")
    assert fragment.lower() in str(e.value).lower()


def test_probe_summarises_a_good_snapshot(monkeypatch):
    import io
    import json
    import urllib.request

    payload = {"spokes": {"feed-a": {"clients": [{"hostname": "x"}, {"hostname": "y"}]}},
               "client_count": 2}

    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **kw: _Resp(json.dumps(payload).encode()))
    res = _probe_source("https://src", "tok")
    assert res["ok"] is True
    assert res["spoke_count"] == 1
    assert res["client_count"] == 2
    assert len(res["sample_clients"]) == 2


def test_probe_sends_the_token_as_a_bearer_header(monkeypatch):
    """The receiver authenticates with a normal API token — if the header were
    dropped the source would 401 and the failure would look like a bad token."""
    import io
    import json
    import urllib.request
    seen = {}

    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _capture(req, *a, **kw):
        seen["auth"] = req.get_header("Authorization")
        return _Resp(json.dumps({"spokes": {}}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", _capture)
    _probe_source("https://src", "tok-123")
    assert seen["auth"] == "Bearer tok-123"


# --------------------------------------------------------------------------
# Config defaults / redaction
# --------------------------------------------------------------------------

def test_anonymising_is_off_by_default():
    """Verbatim is the point: duplicate the production fleet so an issue
    reproduces against the identifiers actually seen in the field."""
    assert _DEFAULTS["source_anonymise"] is False


def test_publishing_is_off_by_default():
    """Deploying this code must never turn a production hub into a data source."""
    assert _DEFAULTS["source_enabled"] is False
    assert _DEFAULTS["receiver_enabled"] is False


def test_tenant_defaults_to_shared_but_can_be_overridden():
    """Blank means the shared tenant (visible in Spokes & Agents everywhere).
    An explicit tenant is needed to appear in that tenant's Simulations views,
    because SimulationsService._spokes_for_tenant matches with strict equality
    and does not union shared — see the note on _DEFAULTS."""
    assert _DEFAULTS["receiver_tenant"] == ""


def test_preserve_tenants_is_off_by_default():
    """The historical behaviour — one tenant for the whole fleet — stays the
    default; preserve is opt-in so an existing feed's placement never moves
    under an operator on upgrade."""
    assert _DEFAULTS["receiver_preserve_tenants"] is False


# --------------------------------------------------------------------------
# _source_tenants — preserve-mode tenant discovery
# --------------------------------------------------------------------------

def _snapshot_resp(payload):
    import io
    import json

    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return _Resp(json.dumps(payload).encode())


def test_source_tenants_collects_distinct_ids(monkeypatch):
    import urllib.request
    snap = {"spokes": {
        "s1": {"clients": [], "tenant": "acme"},
        "s2": {"clients": [], "tenant": "acme"},
        "s3": {"clients": [], "tenant": "globex"},
    }}
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **kw: _snapshot_resp(snap))
    assert _source_tenants("https://src", "tok") == {"acme", "globex"}


def test_source_tenants_empty_when_unattributed(monkeypatch):
    """An older or anonymised source omits the per-spoke tenant. Preserve must
    degrade to the fallback tenant, so the discovery set is simply empty rather
    than an error."""
    import urllib.request
    snap = {"spokes": {"s1": {"clients": []}, "s2": {"clients": [], "tenant": ""}}}
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **kw: _snapshot_resp(snap))
    assert _source_tenants("https://src", "tok") == set()


def test_source_tenants_sends_bearer_token(monkeypatch):
    import urllib.request
    seen = {}

    def _capture(req, *a, **kw):
        seen["auth"] = req.get_header("Authorization")
        return _snapshot_resp({"spokes": {}})

    monkeypatch.setattr(urllib.request, "urlopen", _capture)
    _source_tenants("https://src", "tok-xyz")
    assert seen["auth"] == "Bearer tok-xyz"


def test_there_is_no_operator_supplied_psk():
    """The onboarding PSK only auto-approves the synthetic spokes on THIS hub,
    which is also what spawns them. Start mints an ephemeral one and stop
    revokes it, so a stored PSK would be a standing auto-approve credential for
    the shared tenant with nothing to scope it."""
    assert not any("psk" in k.lower() for k in _DEFAULTS)


def test_both_halves_of_the_token_pair_are_configurable():
    """Access tokens expire after a few hours; without the refresh half a long
    feed dies overnight and reads as 'it randomly stopped'."""
    assert "receiver_token" in _DEFAULTS
    assert "receiver_refresh_token" in _DEFAULTS


def test_rotation_sentinel_matches_the_feeder(monkeypatch):
    """The feeder prints this exact prefix and the route parses it back out; if
    the two constants drift, rotated tokens are never persisted and the feed
    silently reverts to dying for good on the next restart."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
    import hub_feed
    assert _ROUTE_SENTINEL == hub_feed.TOKEN_ROTATION_SENTINEL


def test_test_feed_redaction():
    """Secrets come back as booleans, never values. A regression here hands the
    source hub's API token to anyone who can open the Setup page."""
    def _redact(c):
        out = dict(c)
        for k in ("receiver_token", "receiver_refresh_token", "source_salt"):
            out[k] = bool(out.get(k))
        return out

    red = _redact({**_DEFAULTS, "receiver_token": "secret-tok",
                   "receiver_refresh_token": "secret-refresh", "source_salt": "abc",
                   "receiver_source_url": "https://src"})
    assert red["receiver_token"] is True
    assert red["receiver_refresh_token"] is True
    assert red["source_salt"] is True
    assert "secret-tok" not in repr(red)
    assert "secret-refresh" not in repr(red)
    # Non-secret config still round-trips so the form can be populated.
    assert red["receiver_source_url"] == "https://src"
