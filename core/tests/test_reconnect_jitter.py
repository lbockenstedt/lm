"""Pin the ±20% reconnect-jitter contract.

The reconnect loop (`BaseControlPlane.run`) sleeps
`_jittered_reconnect_delay(base)` instead of a bare `base` so a fleet-wide
disconnect (e.g. an Azure hub restart) doesn't stampede the hub on identical
5s/10s/20s/... cadences. The deterministic `base` still drives the exponential
ladder and the 300s cap; only the actual sleep is jittered.

These tests pin the range and the non-negativity clamp without exercising the
infinite `run()` loop itself.
"""
import random

from core.src.messaging.control_plane import BaseControlPlane


def _samples(base, n=4000):
    return [BaseControlPlane._jittered_reconnect_delay(base) for _ in range(n)]


def test_jitter_within_plus_minus_20_percent():
    for base in (5, 10, 20, 60, 300):
        lo, hi = base * 0.8, base * 1.2
        for v in _samples(base):
            assert lo <= v <= hi, f"{base=} → {v} outside [{lo}, {hi}]"


def test_jitter_is_actually_random():
    # 4000 draws at base=5 should produce more than one distinct value; else
    # the jitter is a no-op (constant) and the stampede-prevention goal fails.
    assert len(set(_samples(5))) > 1


def test_jitter_preserves_mean_near_base():
    # ±20% symmetric jitter → mean should sit close to the base.
    for base in (5, 300):
        mean = sum(_samples(base)) / 4000
        assert abs(mean - base) < base * 0.05, f"{base=} mean {mean:.2f} drifted"


def test_jitter_clamps_negative_base_to_zero():
    # Defensive: a bad base (e.g. a future bug producing a negative delay) must
    # not yield a negative sleep — asyncio.sleep(neg) raises on some versions.
    assert BaseControlPlane._jittered_reconnect_delay(-100) == 0.0


def test_jitter_zero_base_stays_zero():
    assert BaseControlPlane._jittered_reconnect_delay(0) == 0.0


def test_monkeypatchable_in_run_loop():
    """The run() loop calls the static helper, so a test harness can monkeypatch
    it to assert the reconnect path uses jitter. Verify the symbol is callable
    off the class (not a closure buried in run())."""
    assert callable(BaseControlPlane._jittered_reconnect_delay)
    # And determinism: seeding reproduces a draw (sanity, not a contract).
    random.seed(1)
    a = BaseControlPlane._jittered_reconnect_delay(5)
    random.seed(1)
    b = BaseControlPlane._jittered_reconnect_delay(5)
    assert a == b