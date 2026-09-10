"""The DNS and DHCP module views expose live service diagnostics."""

from pathlib import Path


MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def test_dns_and_dhcp_navigation_include_diagnostics():
    src = MAIN_JS.read_text(encoding="utf-8")
    assert "dns: ['Records', 'Statistics', 'Diagnostics', 'Forwarders', 'External DNS']" in src
    assert "dhcp: ['Overview', 'Diagnostics', 'Subnets', 'Leases', 'Reservations']" in src


def test_diagnostics_views_call_the_read_only_endpoints():
    src = MAIN_JS.read_text(encoding="utf-8")
    # Scoped to the tenant picker: these endpoints resolve WHICH module spoke
    # answers from the caller's effective tenant, so an unscoped request would
    # silently land on whichever spoke connected first.
    assert "_spokeFetch('/api/dns/diagnostics' + _tenantQS())" in src
    assert "_spokeFetch('/api/dhcp/diagnostics' + _tenantQS())" in src
    assert "Port 53 listeners" in src
    assert "Recent service warnings/errors" in src
