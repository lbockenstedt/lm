"""WebUI wiring for adding persistent DNS forwarders."""

from pathlib import Path


MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def _source():
    return MAIN_JS.read_text(encoding="utf-8")


def test_forwarder_add_button_is_global_admin_only():
    """"+ Add Forwarder" renders into the shared #top-nav-actions strip
    (pinned next to the help "i" icon), gated to global admins and the
    Forwarders tab only, rather than a page-body button toggled via its
    own id."""
    source = _source()
    load_fn = source.split("async function loadDNSData(subMenu", 1)[1]
    load_fn = load_fn.split("\nasync function ", 1)[0]
    assert "const addForwarderBtn = (subMenu === 'Forwarders' && isAdmin())" in load_fn
    assert 'id="dns-forwarder-add-btn"' in load_fn
    assert "navActions.innerHTML = addRecordBtn + addForwarderBtn" in load_fn


def test_forwarder_modal_posts_zone_and_upstreams():
    source = _source()
    assert "function showDnsForwarderModal()" in source
    assert "async function saveDnsForwarder()" in source
    assert "'/api/dns/forwarders' + _tenantQS()" in source
    assert "JSON.stringify({ zone, upstreams })" in source


def test_forwarder_add_refreshes_the_forwarders_tab():
    """``saveDnsForwarder`` must reload the Forwarders tab it just wrote to,
    not some other DNS tab, or a successful add renders nothing new."""
    source = _source()
    save_fn = source.split("async function saveDnsForwarder()", 1)[1]
    save_fn = save_fn.split("\nasync function ", 1)[0]
    assert "loadDNSData('Forwarders')" in save_fn


def test_dns_worker_discovery_rerender_targets_the_live_tab_not_a_stale_closure():
    """Regression: ``loadDNSData``'s auto-discovery fetch is un-awaited and
    deduped on a single ``window._dnsWorkerDiscovery`` flag, so a discovery
    kicked off from an EARLIER tab (or an earlier call for the SAME tab) can
    still be in flight when the operator switches tabs — e.g. adds a
    forwarder, which correctly renders, then a beat later the earlier
    discovery call resolves and used to blindly call
    ``loadDNSData(subMenu, true)`` with ITS OWN closed-over ``subMenu``,
    silently overwriting whatever tab (Forwarders, freshly showing the new
    entry) is actually on screen with a different one — no error, the
    forwarder just "disappears" until the tab is reloaded. The fix reads the
    live ``currentView``/``currentSubView`` globals (the same ones
    ``setSubView`` maintains for nav highlighting) at resolution time instead
    of the stale ``subMenu`` parameter, and no-ops entirely once the operator
    has left the DNS view."""
    source = _source()
    load_fn = source.split("async function loadDNSData(subMenu", 1)[1]
    discovery_block = load_fn.split("_dnsWorkerDiscovery = null", 1)[0]
    assert "loadDNSData(currentSubView, true)" in discovery_block
    assert "currentView === 'dns'" in discovery_block
    # The regression: re-rendering unconditionally with the stale parameter.
    assert "loadDNSData(subMenu, true)" not in discovery_block


def test_forwarders_tab_surfaces_member_errors():
    """A per-member fanout failure (dns_spoke.py's ``_cluster_forwarders``
    always returns top-level status SUCCESS + a ``member_errors`` map so a
    dropped member doesn't masquerade as "no forwarders configured") must be
    shown to the operator — previously ``member_errors`` was computed
    server-side but never read by the UI, so a resolver that failed to
    answer the LIST fanout silently shrank the table with no indication
    anything was wrong."""
    source = _source()
    fwd_block = source.split("if (subMenu === 'Forwarders') {", 1)[1]
    fwd_block = fwd_block.split("\n        // ── Records", 1)[0]
    assert "d.member_errors" in fwd_block
    assert "memberErrors" in fwd_block
