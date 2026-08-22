"""Unit tests for ``routes.nw.validate_nw_address`` — the shared management-IP
validator used by BOTH the admin ``/setup/nw-devices`` and the tenant-admin
``/tenant/devices/nw-devices`` CRUD paths. A network device's address must be
present AND a properly-formatted IPv4 address; anything else fails opaquely on
the spoke (``Name or service not known``), so it is rejected up front with 400.
"""
import pytest
from fastapi import HTTPException

from routes.nw import validate_nw_address


@pytest.mark.parametrize("addr", [
    "172.16.1.90", "10.0.0.1", "0.0.0.0", "255.255.255.255",
    "  172.16.0.90  ",  # surrounding whitespace is trimmed
])
def test_valid_ipv4_addresses_pass(addr):
    validate_nw_address(addr)  # does not raise


@pytest.mark.parametrize("addr,needle", [
    (None, "required"),
    ("", "required"),
    ("   ", "required"),
])
def test_missing_address_is_required(addr, needle):
    with pytest.raises(HTTPException) as ei:
        validate_nw_address(addr)
    assert ei.value.status_code == 400
    assert needle in ei.value.detail.lower()


@pytest.mark.parametrize("addr", [
    "1721.6.1.90",       # the real-world typo that started this
    "256.1.1.1",         # octet > 255
    "01.2.3.4",          # leading-zero octet
    "10.0.0",            # too few octets
    "1.2.3.4.5",         # too many octets
    "switch.lab.local",  # hostname, not an IP
    "::1",               # IPv6 is not accepted
    "not-an-ip",
])
def test_malformed_addresses_are_rejected(addr):
    with pytest.raises(HTTPException) as ei:
        validate_nw_address(addr)
    assert ei.value.status_code == 400
    assert "valid ipv4" in ei.value.detail.lower()
