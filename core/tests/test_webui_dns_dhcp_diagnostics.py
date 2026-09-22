"""The DNS and DHCP module views expose live service diagnostics."""

import ast
import re
from pathlib import Path


MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def _submenu(view, src):
    """The VIEW_SUBMENUS entry for ``view`` as a Python list.

    Parsed rather than string-matched so a reorder doesn't have to be mirrored
    as a brittle literal in the assertion below."""
    m = re.search(r"^\s*%s:\s*(\[[^\]]*\])," % re.escape(view), src, re.M)
    assert m, "no VIEW_SUBMENUS entry for %r" % view
    return ast.literal_eval(m.group(1))


def test_dns_and_dhcp_navigation_include_diagnostics():
    src = MAIN_JS.read_text(encoding="utf-8")
    assert "Diagnostics" in _submenu("dns", src)
    assert "Diagnostics" in _submenu("dhcp", src)


def test_diagnostics_is_the_last_tab():
    """Diagnostics is a troubleshooting destination, not a daily one, so it
    sits at the END of the strip — matching `settings`, which already lists it
    last. It previously sat 3rd (DNS) and 2nd (DHCP), pushing the day-to-day
    record/lease tabs to the right."""
    src = MAIN_JS.read_text(encoding="utf-8")
    for view in ("dns", "dhcp"):
        assert _submenu(view, src)[-1] == "Diagnostics", (
            "%s: Diagnostics must be the last tab" % view)


def test_overview_stays_the_default_tab():
    """setSubView defaults to element [0], so the first entry is the landing
    tab — reordering must not make Diagnostics the default."""
    src = MAIN_JS.read_text(encoding="utf-8")
    for view in ("dns", "dhcp"):
        assert _submenu(view, src)[0] == "Overview"


def test_no_tabs_were_lost_in_the_reorder():
    src = MAIN_JS.read_text(encoding="utf-8")
    assert sorted(_submenu("dns", src)) == sorted(
        ["Overview", "Records", "Forwarders", "External DNS", "Diagnostics"])
    assert sorted(_submenu("dhcp", src)) == sorted(
        ["Overview", "Subnets", "Leases", "Reservations", "Diagnostics"])


def test_diagnostics_views_call_the_read_only_endpoints():
    src = MAIN_JS.read_text(encoding="utf-8")
    # Scoped to the tenant picker: these endpoints resolve WHICH module spoke
    # answers from the caller's effective tenant, so an unscoped request would
    # silently land on whichever spoke connected first.
    assert "_spokeFetch('/api/dns/diagnostics' + _tenantQS())" in src
    assert "_spokeFetch('/api/dhcp/diagnostics' + _tenantQS())" in src
    assert "Port 53 listeners" in src
    assert "Recent service warnings/errors" in src


def test_global_admin_dhcp_view_auto_discovers_the_ha_pair():
    src = MAIN_JS.read_text(encoding="utf-8")
    assert "isAdmin()) {" in src
    assert "'/api/dhcp/ha/discover' + _tenantQS()" in src
    assert "loadDHCPData(subMenu, true)" in src


def test_dhcp_configuration_tile_renders_details_button_and_modal():
    src = MAIN_JS.read_text(encoding="utf-8")
    assert "_showDhcpConfigDetailsModal" in src
    assert "dhcp-cfg-details-modal" in src
    assert "check('Configuration', !!cfg.ok, cfgSub, cfgAction)" in src
    assert "syntax valid" in src

