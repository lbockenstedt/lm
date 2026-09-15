"""A DHCP sync that applied NOTHING must not report a bare "ok".

Why this exists: on the live fleet the hub sent 123 reservations and the Kea
spoke applied 0 of them (``reservations_skipped: 123``). Every layer reported
success — the spoke did exactly what it was told, there was simply no
DHCP-enabled prefix containing those addresses — so the WebUI showed an empty
reservation list, which is indistinguishable from "you have no reservations".
The operator's only recourse was diffing ``kea-dhcp4.conf`` by hand.

``dhcp_skip_warning`` turns that silent drop into a stated one, and the sync
status carries it so the UI can render it. The properties pinned here: a real
drop is always reported, a clean sync is never polluted with a warning, and
the message names the actual fix (tick ``dhcp_enabled`` on the prefix).
"""
import pytest

from dns_dhcp_sync import dhcp_skip_warning


def test_a_total_drop_is_reported():
    out = dhcp_skip_warning({"reservations": 0, "reservations_skipped": 123})
    assert out["reservations_skipped"] == 123
    assert "every reservation" in out["warning"]


def test_the_warning_names_the_actual_fix():
    """A warning an operator cannot act on is just noise."""
    out = dhcp_skip_warning({"reservations": 0, "reservations_skipped": 123})
    assert "dhcp_enabled" in out["warning"]
    assert "prefix" in out["warning"]


def test_a_partial_drop_reports_the_proportion():
    out = dhcp_skip_warning({"reservations": 7, "reservations_skipped": 3})
    assert out["reservations_skipped"] == 3
    assert "3 of 10" in out["warning"]


def test_a_clean_sync_produces_no_warning():
    """Must stay empty so ``**dhcp_skip_warning(...)`` adds no keys at all."""
    assert dhcp_skip_warning({"reservations": 10, "reservations_skipped": 0}) == {}


def test_a_spoke_result_without_counts_is_not_a_warning():
    assert dhcp_skip_warning({"status": "SUCCESS"}) == {}
    assert dhcp_skip_warning(None) == {}
    assert dhcp_skip_warning("nonsense") == {}


def test_counts_are_summed_across_a_multi_spoke_push():
    """``spoke_result`` is a LIST when more than one dhcp spoke is connected."""
    out = dhcp_skip_warning([
        {"reservations": 0, "reservations_skipped": 5},
        {"reservations": 0, "reservations_skipped": 7},
    ])
    assert out["reservations_skipped"] == 12
    assert "every reservation" in out["warning"]


def test_a_partial_drop_across_spokes_is_not_called_total():
    out = dhcp_skip_warning([
        {"reservations": 4, "reservations_skipped": 1},
        {"reservations": 0, "reservations_skipped": 0},
    ])
    assert "every reservation" not in out["warning"]
    assert "1 of 5" in out["warning"]


def test_malformed_counts_do_not_raise():
    """A diagnostic that explodes on bad input is worse than none."""
    assert dhcp_skip_warning({"reservations_skipped": "lots"}) == {}
    out = dhcp_skip_warning([
        {"reservations_skipped": None},
        {"reservations": 0, "reservations_skipped": 2},
    ])
    assert out["reservations_skipped"] == 2


def test_negative_counts_are_ignored():
    assert dhcp_skip_warning({"reservations": 1, "reservations_skipped": -3}) == {}


def test_status_record_carries_the_warning_to_the_ui():
    """End-to-end on the shape the WebUI actually reads."""
    status = {"status": "ok", "subnets_synced": 3, "reservations_synced": 123,
              **dhcp_skip_warning({"reservations": 0, "reservations_skipped": 123})}
    # Still "ok" (the push DID succeed) but no longer silent about the drop.
    assert status["status"] == "ok"
    assert "warning" in status


def test_a_clean_status_record_has_no_warning_key():
    status = {"status": "ok", "subnets_synced": 3, "reservations_synced": 10,
              **dhcp_skip_warning({"reservations": 10, "reservations_skipped": 0})}
    assert "warning" not in status
