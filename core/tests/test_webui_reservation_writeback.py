"""WebUI surface for the DHCP reservation NetBox write-back.

A reservation written to Kea is invisible to NetBox, but ``core.dns_dhcp_sync``
rebuilds Kea's entire ``subnet4`` from NetBox alone and ``config-set``s it — so
a reservation whose MAC never landed on a NetBox IP object is deleted by the
next sync. The add returns SUCCESS and the row appears in the list, so the loss
looks like the reservation vanished on its own minutes later. ("I had a
reservation for 172.17.1.199" — it was never in NetBox, so the sync dropped it.)

The API already reports this: ``_with_writeback`` attaches ``netbox_writeback``
to every reservation reply precisely so the operator can be told, and its
docstring says so outright. The WebUI simply never read the field — it showed a
clean success either way. These tests pin that the warning is surfaced.
"""

import os
import re


MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _fn(name):
    src = open(MAIN_JS, encoding="utf-8").read()
    start = src.index(f"function {name}(")
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"unbalanced {name} function")


# ── the helper exists and reads the field the API actually sends ─────────────

def test_helper_reads_netbox_writeback():
    body = _fn("_reservationWritebackWarning")
    assert "netbox_writeback" in body


def test_clean_writeback_produces_no_warning():
    """'ok' (MAC written) and 'unchanged' (already correct) are both successes;
    warning on those would cry wolf on every normal save."""
    body = _fn("_reservationWritebackWarning")
    assert "'ok'" in body
    assert "'unchanged'" in body
    assert "return ''" in body


def test_missing_netbox_ip_object_is_called_out_by_address():
    """The 172.17.1.199 case: Kea took it, NetBox has no such IP object."""
    body = _fn("_reservationWritebackWarning")
    assert "not_found" in body
    assert "NetBox has no IP object for" in body


def test_warning_says_the_reservation_will_be_dropped():
    """The operator needs the consequence, not just the fact of a failure."""
    body = _fn("_reservationWritebackWarning")
    assert "will drop this reservation" in body


def test_delete_path_warns_the_reservation_may_come_back():
    """A write-back that failed to CLEAR the MAC leaves NetBox still holding
    it, so the next sync recreates the reservation just deleted — the opposite
    failure, and it needs the opposite message."""
    body = _fn("_reservationWritebackWarning")
    assert "may restore this reservation" in body


def test_falls_back_to_reason_or_error_text():
    """'skipped' (no ipam spoke) and 'error' carry their own explanation."""
    body = _fn("_reservationWritebackWarning")
    assert "w.reason" in body
    assert "w.error" in body


# ── both call sites actually surface it ──────────────────────────────────────

def test_save_surfaces_the_warning_on_success():
    body = _fn("saveDhcpReservation")
    assert "_reservationWritebackWarning(d)" in body
    # it must fire on the SUCCESS branch — that is the silent-loss case
    success = body[body.index("d.status === 'SUCCESS'"):]
    assert "_reservationWritebackWarning" in success[:400]


def test_delete_surfaces_the_warning_with_the_removing_flag():
    body = _fn("deleteDhcpReservation")
    assert "_reservationWritebackWarning(d, true)" in body


def test_warnings_are_shown_as_toasts():
    for name in ("saveDhcpReservation", "deleteDhcpReservation"):
        body = _fn(name)
        assert re.search(r"if \(w\) showToast\(w,", body), name


def test_delete_still_refreshes_the_list():
    """Regression guard: the refresh must not be lost to the new branch."""
    body = _fn("deleteDhcpReservation")
    assert "loadDHCPData('Reservations')" in body


def test_lease_delete_keeps_its_confirmation_prompt():
    """deleteDhcpLease sits next to the edited code; its confirm must survive."""
    body = _fn("deleteDhcpLease")
    assert "showConfirmToast" in body
