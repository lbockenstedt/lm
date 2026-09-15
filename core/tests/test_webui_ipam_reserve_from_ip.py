"""WebUI: reserve a DHCP address straight from the IPAM IP Addresses table.

The IPAM IP Addresses view listed NetBox IP records with Edit/Release only. An
address allocated in NetBox is not pinned to the client — only a DHCP
reservation does that — so the operator had to leave IPAM, go to DHCP, and
retype the address and MAC by hand.

The MAC was already being fetched (``custom_fields.mac_address``, which the
discovery sync writes and the IPAM→CPPM endpoint sync consumes) but never
shown. These tests pin that it is displayed, that Reserve is offered only when
a MAC exists to match on, and that it opens the shared reservation modal in
*prefill* mode — a plain Add, not an edit of a reservation that does not exist
and not a lease conversion that would try to purge a lease that may not exist.
"""

import os
import re

MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _src():
    return open(MAIN_JS, encoding="utf-8").read()


def _fn(name):
    src = _src()
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


def _ip_addresses_branch():
    """The `subMenu === 'IP Addresses'` render branch of loadNetboxData."""
    body = _fn("loadNetboxData")
    start = body.index("subMenu === 'IP Addresses'")
    return body[start:]


# ── the MAC is surfaced ─────────────────────────────────────────────────────

def test_mac_column_is_rendered():
    branch = _ip_addresses_branch()
    assert "'MAC'" in branch, "IP Addresses table must show a MAC column"
    assert "mac_address" in branch, \
        "MAC must come from the NetBox custom field the discovery sync writes"


# ── Reserve is gated on having a MAC ────────────────────────────────────────

def test_reserve_button_offered_when_a_mac_is_known():
    assert "reserveNetboxIP(" in _ip_addresses_branch(), \
        "IP Addresses rows must offer a Reserve action"


def test_reserve_is_not_clickable_without_a_mac():
    branch = _ip_addresses_branch()
    # The no-MAC arm must not wire up a click, and must say why.
    assert "cursor-not-allowed" in branch
    no_mac_arm = branch[branch.index("cursor-not-allowed") - 400:
                        branch.index("cursor-not-allowed") + 200]
    assert "onclick=\"reserveNetboxIP" not in no_mac_arm, \
        "a row with no MAC must not offer a live Reserve button"


def test_handler_refuses_a_row_with_no_mac():
    body = _fn("reserveNetboxIP")
    assert "if (!mac)" in body and "showToast" in body, \
        "reserveNetboxIP must refuse (and explain) when the IP has no MAC"


def test_handler_strips_the_cidr_mask():
    # NetBox stores "172.17.1.199/24"; Kea wants the bare host address.
    body = _fn("reserveNetboxIP")
    assert ".split('/')[0]" in body, \
        "the NetBox CIDR must be reduced to a host address for Kea"


def test_handler_opens_the_modal_in_prefill_mode():
    body = _fn("reserveNetboxIP")
    assert re.search(r"showDhcpReservationModal\(\s*\{", body)
    assert "false, true)" in body.replace("\n", " ").replace("  ", " "), \
        "must pass isConvert=false, prefillOnly=true"


# ── prefill mode is a plain Add ─────────────────────────────────────────────

def test_prefill_mode_is_not_treated_as_an_edit():
    body = _fn("showDhcpReservationModal")
    assert "prefillOnly = false" in body, "modal must accept a prefillOnly mode"
    assert "const editing = !isConvert && !prefillOnly && !!editItem" in body, \
        "a prefilled Add must not be treated as editing an existing reservation"


def test_prefill_mode_does_not_set_an_old_lease_to_purge():
    body = _fn("showDhcpReservationModal")
    # oldLeaseIp drives the lease purge; it must stay tied to the convert flow.
    assert "if (isConvert && editItem?.ip) modal.dataset.oldLeaseIp" in body, \
        "only a lease conversion may request the old lease be purged"


def test_existing_convert_and_edit_callers_still_work():
    assert "showDhcpReservationModal({" in _fn("convertLeaseToReservation")
    assert "}, true);" in _fn("convertLeaseToReservation"), \
        "convert must still pass isConvert=true"
    assert "showDhcpReservationModal(item);" in _fn("editDhcpReservation"), \
        "edit must still pass a bare editItem"


# ── scope preselection ──────────────────────────────────────────────────────

def test_subnet_is_preselected_by_containment_when_no_subnet_id():
    body = _fn("_loadDhcpSubnetOptions")
    assert "preferredIp" in body, "loader must accept the address being reserved"
    assert "_isIPInCIDR(preferredIp" in body, \
        "must pick the scope that actually contains the address"


def test_subnet_id_still_wins_over_containment():
    body = _fn("_loadDhcpSubnetOptions")
    pref = body.index("preferredSubnetId != null")
    by_ip = body.index("byIp")
    assert pref < body.index("} else if (byIp)"), \
        "an explicit subnet-id must take priority over the containment guess"
    assert by_ip > 0


def test_modal_forwards_the_address_to_the_loader():
    body = _fn("showDhcpReservationModal")
    assert "editItem?._spoke, editItem?.ip)" in body, \
        "the modal must pass the address through for scope preselection"
