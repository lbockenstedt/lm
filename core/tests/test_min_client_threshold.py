"""Per-site minimum-client floor for Central site monitoring.

When an operator sets a "Minimum clients" floor on a monitored site (Monitor
button → input), the hub poller raises a ``Minimum Client Threshold`` check
(direct semantics: below the floor = error) IN ADDITION to the existing %
drop check. These tests cover the pure ``min_client_check`` decision so the
threshold logic is verified without constructing the poller (which would pull
in the hub + Aruba client + at-rest encryption).
"""
from simulations.central_hub_poller import min_client_check


def test_below_floor_is_error():
    chk = min_client_check(12, 50)
    assert chk["status"] == "error"
    assert "below minimum 50" in chk["message"]
    assert "12" in chk["message"]


def test_at_floor_is_ok():
    # Equal to the floor is OK (the floor is a minimum, inclusive).
    chk = min_client_check(50, 50)
    assert chk["status"] == "ok"
    assert "min 50" in chk["message"]


def test_above_floor_is_ok():
    chk = min_client_check(120, 50)
    assert chk["status"] == "ok"


def test_no_floor_emits_no_check():
    """A site with no threshold behaves exactly as before — no extra check is
    added to its status, so the dashboard tally is unchanged."""
    assert min_client_check(0, None) is None
    assert min_client_check(5, 0) is None


def test_floor_must_be_positive():
    # A zero or negative floor is treated as "no floor" (defensive — the route
    # sanitizer already drops these, but the helper guards on its own).
    assert min_client_check(5, -1) is None


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))