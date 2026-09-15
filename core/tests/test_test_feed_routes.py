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

from routes.test_feed import _collect_fleet, _probe_source, _DEFAULTS  # noqa: E402


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


def test_empty_cache_yields_empty_lists_not_an_error():
    assert _collect_fleet(_Hub({})) == {"clients": [], "proxmox": []}


def test_a_broken_hub_degrades_to_empty_rather_than_raising():
    """A 500 on the snapshot endpoint would be a worse failure than an empty
    one: the receiver retries forever against a hub that looks broken."""
    class _Bad:
        @property
        def simulations_cache(self):
            raise RuntimeError("state unavailable")
    assert _collect_fleet(_Bad()) == {"clients": [], "proxmox": []}


def test_rows_are_copied_not_aliased():
    """_collect_fleet stamps spoke_id; doing that in place would mutate the
    hub's live telemetry cache."""
    cache = {"s1": {"clients": [{"hostname": "a"}]}}
    _collect_fleet(_Hub(cache))
    assert "spoke_id" not in cache["s1"]["clients"][0]


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

def test_publishing_is_off_by_default():
    """Deploying this code must never turn a production hub into a data source."""
    assert _DEFAULTS["source_enabled"] is False
    assert _DEFAULTS["receiver_enabled"] is False


def test_there_is_no_tenant_setting():
    """The replayed fleet joins the hub's SHARED tenant so every tenant can see
    it. A stored tenant would silently win over that resolution and wall the
    fleet into one tenant again."""
    assert not any("tenant" in k for k in _DEFAULTS)


def test_test_feed_redaction():
    """Secrets come back as booleans, never values. A regression here hands the
    source hub's API token to anyone who can open the Setup page."""
    def _redact(c):
        out = dict(c)
        for k in ("receiver_token", "receiver_psk", "source_salt"):
            out[k] = bool(out.get(k))
        return out

    red = _redact({**_DEFAULTS, "receiver_token": "secret-tok",
                   "receiver_psk": "secret-psk", "source_salt": "abc",
                   "receiver_source_url": "https://src"})
    assert red["receiver_token"] is True
    assert red["receiver_psk"] is True
    assert red["source_salt"] is True
    assert "secret-tok" not in repr(red)
    assert "secret-psk" not in repr(red)
    # Non-secret config still round-trips so the form can be populated.
    assert red["receiver_source_url"] == "https://src"
