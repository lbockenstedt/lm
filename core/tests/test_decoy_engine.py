"""Generic hub-side decoy engine: shadow safety, inertness, and trip reporting.

The engine is what lets an install serve honeypot routes without holding the
private sensor code — the mechanism is public, the paths arrive as data. These
tests pin the two properties that make that safe to deploy:

* it is **inert** until a set is applied (no set → no behaviour change), and
* it can never **shadow a real route**. Middleware runs before routing, so a
  decoy always wins; a set containing a live endpoint would answer legitimate
  clients with decoy junk. That is an outage caused by the defence, so the
  refusal is enforced against each route's compiled regex (templated routes
  included), not merely against literal path strings.
"""

import os
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from security.decoy_engine import (  # noqa: E402
    DecoyEngine,
    normalize_path,
    register_decoy_middleware,
    routable_matchers,
)


def _app():
    app = FastAPI()

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/spokes/{spoke_id}")
    def spoke(spoke_id: str):
        return {"spoke": spoke_id}

    return app


def _entry(path, **kw):
    return dict({"path": path, "body": "junk", "status": 200}, **kw)


# ── inertness ────────────────────────────────────────────────────────────────

def test_engine_ships_inert():
    """Zero endpoints until a set is applied — an install that never enables
    decoys must behave exactly as it did before the engine existed."""
    e = DecoyEngine()
    assert e.is_active() is False
    assert e.match("/anything") is None


def test_clear_returns_to_inert():
    e = DecoyEngine()
    e.set_config([_entry("/.env")])
    assert e.is_active() is True
    e.clear()
    assert e.is_active() is False
    assert e.match("/.env") is None


def test_empty_or_none_config_clears():
    e = DecoyEngine()
    e.set_config([_entry("/.env")])
    assert e.set_config(None) == 0
    assert e.is_active() is False


# ── route shadowing: the outage-causing failure mode ─────────────────────────

def test_refuses_a_decoy_that_shadows_a_literal_route():
    """``/api/health`` is served for real. As a decoy it would answer every
    legitimate caller with junk, because middleware precedes routing."""
    e = DecoyEngine()
    n = e.set_config([_entry("/api/health"), _entry("/.env")],
                     reserved=routable_matchers(_app()))
    assert n == 1
    assert e.match("/api/health") is None
    assert e.match("/.env") is not None
    assert any("shadow" in why for _, why in e.rejected())


def test_refuses_a_decoy_that_shadows_a_TEMPLATED_route():
    """The subtle case: ``/api/spokes/{spoke_id}`` makes ``/api/spokes/foo``
    routable even though that literal string appears nowhere. A shape-only
    check (comparing against literal route strings) misses this entirely."""
    e = DecoyEngine()
    e.set_config([_entry("/api/spokes/foo")], reserved=routable_matchers(_app()))
    assert e.match("/api/spokes/foo") is None
    assert e.rejected()[0][1] == "would shadow a real route"


def test_shadow_check_survives_trailing_slash_variation():
    e = DecoyEngine()
    e.set_config([_entry("/api/health/")], reserved=routable_matchers(_app()))
    assert e.count() == 0


def test_without_reserved_nothing_is_refused_as_shadowing():
    """The guard is opt-in by argument; callers that pass no route set get the
    old permissive behaviour rather than a silently empty sensor."""
    e = DecoyEngine()
    assert e.set_config([_entry("/api/health")]) == 1


# ── malformed input ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["", "relative/path", "   "])
def test_non_absolute_paths_are_refused(bad):
    e = DecoyEngine()
    assert e.set_config([_entry(bad)]) == 0


def test_one_bad_entry_does_not_discard_the_set():
    """A feed-supplied set is only as good as its worst record; dropping the
    whole push would let one bad entry disable the sensor."""
    e = DecoyEngine()
    assert e.set_config([_entry("relative"), _entry("/.env"), _entry("/.git/config")]) == 2


def test_duplicate_paths_collapse():
    e = DecoyEngine()
    assert e.set_config([_entry("/.env"), _entry("/.env")]) == 1


def test_body_is_capped():
    """Bodies arrive from a feed. Uncapped, a bad or hostile push would turn
    every scan into an amplification response."""
    e = DecoyEngine()
    e.set_config([_entry("/.env", body="A" * (200 * 1024))])
    assert len(e.match("/.env")["body"]) == 64 * 1024


def test_normalization_matches_case_and_slash_variants():
    e = DecoyEngine()
    e.set_config([_entry("/.ENV/")])
    assert e.match("/.env") is not None
    assert e.match("/.env?x=1") is not None
    assert normalize_path("/A/?q=1") == "/a"


# ── serving behaviour ────────────────────────────────────────────────────────

def test_decoy_is_served_and_reported_not_reset():
    """Answer with a plausible body rather than a reset or 404: killing the
    connection gives a scanner a per-path oracle to diff decoys from real 404s
    and map the set."""
    app = _app()
    e = DecoyEngine()
    e.set_config([_entry("/.env", body="SECRET_KEY=abc", tier="default_decoy")],
                 reserved=routable_matchers(app))
    trips = []
    register_decoy_middleware(app, e, on_trip=lambda **kw: trips.append(kw))

    r = TestClient(app).get("/.env")
    assert r.status_code == 200
    assert r.text == "SECRET_KEY=abc"
    assert trips[0]["tier"] == "default_decoy"
    assert trips[0]["path"] == "/.env"


def test_real_routes_are_untouched_when_decoys_are_active():
    app = _app()
    e = DecoyEngine()
    e.set_config([_entry("/.env")], reserved=routable_matchers(app))
    register_decoy_middleware(app, e)
    c = TestClient(app)
    assert c.get("/api/health").json() == {"ok": True}
    assert c.get("/api/spokes/s1").json() == {"spoke": "s1"}


def test_non_decoy_miss_still_404s_normally():
    app = _app()
    e = DecoyEngine()
    e.set_config([_entry("/.env")], reserved=routable_matchers(app))
    register_decoy_middleware(app, e)
    assert TestClient(app).get("/nope").status_code == 404


def test_loopback_trips_and_serves_but_is_flagged_exempt():
    """The private sensor passes loopback straight through, which leaves no way
    to exercise it end to end — from loopback you get a real 404, from anywhere
    else you lock yourself out. Here loopback still matches, serves and reports;
    it is only marked exempt so the caller can decline to treat it as an
    attacker. That keeps a safe local test path without creating a bypass."""
    app = _app()
    e = DecoyEngine()
    e.set_config([_entry("/.env")], reserved=routable_matchers(app))
    trips = []
    register_decoy_middleware(app, e, on_trip=lambda **kw: trips.append(kw))

    assert TestClient(app, client=("127.0.0.1", 5555)).get("/.env").status_code == 200
    assert trips[0]["loopback"] is True


def test_an_unparseable_peer_host_is_never_treated_as_loopback():
    """Loopback is an exemption, so it must fail SAFE: a transport that reports
    a non-IP host (or none) must not inherit the exemption."""
    app = _app()
    e = DecoyEngine()
    e.set_config([_entry("/.env")], reserved=routable_matchers(app))
    trips = []
    register_decoy_middleware(app, e, on_trip=lambda **kw: trips.append(kw))

    assert TestClient(app).get("/.env").status_code == 200
    assert trips[0]["loopback"] is False


def test_a_failing_trip_sink_does_not_change_the_response():
    """If reporting could alter the reply, the response itself would leak
    whether the trip was recorded — an oracle."""
    app = _app()
    e = DecoyEngine()
    e.set_config([_entry("/.env", body="junk")], reserved=routable_matchers(app))

    def _boom(**kw):
        raise RuntimeError("sink down")

    register_decoy_middleware(app, e, on_trip=_boom)
    r = TestClient(app).get("/.env")
    assert r.status_code == 200 and r.text == "junk"


def test_paths_are_not_leaked_into_trip_reports_by_default():
    """``paths()`` exists for local bookkeeping only. The decoy set is the
    sensor; publishing it burns it."""
    e = DecoyEngine()
    e.set_config([_entry("/.env"), _entry("/.git/config")])
    assert e.paths() == {"/.env", "/.git/config"}
