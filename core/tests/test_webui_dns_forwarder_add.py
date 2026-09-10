"""WebUI wiring for adding persistent DNS forwarders."""

from pathlib import Path


MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def _source():
    return MAIN_JS.read_text(encoding="utf-8")


def test_forwarder_add_button_is_global_admin_only():
    source = _source()
    assert "${isAdmin() ? `<button id=\"dns-forwarder-add-btn\"" in source
    assert "addForwarderBtn.classList.toggle('hidden', subMenu !== 'Forwarders')" in source


def test_forwarder_modal_posts_zone_and_upstreams():
    source = _source()
    assert "function showDnsForwarderModal()" in source
    assert "async function saveDnsForwarder()" in source
    assert "'/api/dns/forwarders' + _tenantQS()" in source
    assert "JSON.stringify({ zone, upstreams })" in source
