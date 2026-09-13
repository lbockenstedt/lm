"""WebUI wiring for the DHCP scope options on the NetBox "Allocate/Edit
Subnet" modal (Gateway/DNS/Search Domain always visible, everything else
behind an "Advanced options" toggle), and the removal of the self-service
"+ Add Server" button from the DNS and DHCP nav-action strips (both modules
are provisioned by loading a role onto a host, not by self-service spoke
onboarding).
"""

from pathlib import Path


MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def _source():
    return MAIN_JS.read_text(encoding="utf-8")


def _modal_fn():
    source = _source()
    fn = source.split("async function showNetboxAllocatePrefixModal(editItem)", 1)[1]
    return fn.split("\nasync function submitNetboxAllocatePrefix()", 1)[0]


def _submit_fn():
    source = _source()
    fn = source.split("async function submitNetboxAllocatePrefix()", 1)[1]
    return fn.split("\nasync function deleteNetboxPrefix", 1)[0]


def test_modal_renders_common_option_fields_always_visible():
    fn = _modal_fn()
    for field_id in ("nb-p-gateway", "nb-p-dns", "nb-p-search"):
        assert f"opt('{field_id}'" in fn
    # These sit above the advanced toggle, not inside the hidden container.
    common_block = fn.split("commonOptionFields = `", 1)[1].split("`;", 1)[0]
    assert "nb-p-gateway" in common_block
    assert "nb-p-dns" in common_block
    assert "nb-p-search" in common_block


def test_modal_renders_advanced_option_fields_behind_toggle():
    fn = _modal_fn()
    advanced_block = fn.split("advancedOptionFields = `", 1)[1].split("`;", 1)[0]
    for field_id in ("nb-p-domain", "nb-p-ntp", "nb-p-tftp", "nb-p-bootfile",
                     "nb-p-netbios", "nb-p-bcast", "nb-p-lease"):
        assert f"opt('{field_id}'" in advanced_block
    assert 'id="nb-p-advanced" class="hidden' in fn
    assert "Show advanced options" in fn


def test_submit_includes_all_dhcp_option_fields_in_custom_fields_for_create_and_edit():
    fn = _submit_fn()
    for cf_key in ("gateway", "dns_servers", "search_domain", "domain_name",
                   "ntp_servers", "tftp_server_name", "boot_file_name",
                   "netbios_name_servers", "broadcast_address", "lease_time"):
        assert cf_key in fn
    # Shared object spread into BOTH the edit PUT payload and the create POST
    # payload, so the two paths can never drift.
    assert fn.count("custom_fields: { dhcp_enabled: dhcpEnabled, ...dhcpOptionFields }") == 2


def test_dns_nav_actions_has_no_add_server_button():
    source = _source()
    load_fn = source.split("async function loadDNSData(subMenu", 1)[1]
    load_fn = load_fn.split("\nasync function ", 1)[0]
    assert "addServerButtonHtml" not in load_fn


def test_dhcp_nav_actions_has_no_add_server_button():
    source = _source()
    load_fn = source.split("async function loadDHCPData(subMenu", 1)[1]
    load_fn = load_fn.split("\nasync function ", 1)[0]
    assert "addServerButtonHtml" not in load_fn


def test_add_server_button_still_used_elsewhere():
    """The helper itself must stay intact — it's still used by the
    Network Devices (nw) and ClearPass (cppm) panels, which ARE
    self-service-onboarded spokes."""
    source = _source()
    assert "function addServerButtonHtml(role, label)" in source
    assert "addServerButtonHtml('nw', 'Network Devices')" in source
    assert "addServerButtonHtml('cppm', 'ClearPass')" in source


def test_dd_member_evidence_renders_full_dns_evidence_per_member():
    """Regression: the DNS Diagnostics cluster panel used to render the full
    interfaces/local-IPv4/access-controls/listeners/probes evidence tiles
    from only ONE named "source" member (``d.configured_interfaces`` etc.),
    so a 2nd/3rd healthy resolver's own evidence was never shown even though
    the backend's ``members`` map already carries it per-node
    (dns_spoke.py's ``_cluster_diagnostics``/unbound_manager's
    ``diagnostics()``). ``_ddMemberEvidence`` must render each member's own
    interfaces/IPv4s/access-controls/listeners/probes when called with the
    'dns' kind, not just a healthy/recommendations summary card.
    """
    source = _source()
    fn = source.split("function _ddMemberEvidence(members, kind)", 1)[1]
    fn = fn.split("\nfunction _tenantQS", 1)[0]
    assert "diag.configured_interfaces" in fn
    assert "diag.local_ipv4s" in fn
    assert "diag.access_controls" in fn
    assert "diag.probes" in fn
    assert "kind === 'dns'" in fn


def test_dns_diagnostics_passes_dns_kind_to_member_evidence():
    source = _source()
    assert "_ddMemberEvidence(d.members, 'dns')" in source


def test_dhcp_ha_diagnostics_uses_summary_only_evidence_not_dns_kind():
    """Kea's diagnostics shape differs from Unbound's (leases/CA vs.
    interfaces/probes) — DHCP HA member evidence intentionally keeps the old
    summary-only rendering (no explicit 'dns' kind) unless/until DHCP gets
    its own per-member evidence tiles."""
    source = _source()
    assert "_ddMemberEvidence(d.members)" in source
