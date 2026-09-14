"""A permanently-offline Kea node must be retirable from the tab that shows it.

The DHCP Diagnostics tab is where an operator watches a node fail, but the
Kea HA member table had no action at all: the only way to drop a node was the
admin-only "Edit cluster" modal, whose "Delete cluster" button dissolves BOTH
nodes. DNS has had a per-member remove on its own cluster table for exactly
this case ("a host whose DNS Server role was uninstalled/decommissioned and
will never converge again"); these tests hold DHCP to the same contract.

They also pin the two things that are easy to get wrong in a copy of the DNS
control: the column count must grow with the extra action cell, and only
configuration (id/host) — never live reporting fields — may be posted back
into the topology.
"""

from pathlib import Path

MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def _source():
    return MAIN_JS.read_text(encoding="utf-8")


def _panel():
    src = _source()
    return src.split("function _dhcpHaPanel(c) {", 1)[1].split(
        "\n// Drop a single Kea node", 1)[0]


def _remove_fn():
    src = _source()
    return src.split("async function removeDhcpHaMember(id) {", 1)[1].split(
        "\n// Per-member evidence blocks", 1)[0]


def test_the_ha_member_table_offers_a_per_node_remove():
    panel = _panel()
    assert "removeDhcpHaMember('${eId}')" in panel


def test_the_remove_control_is_admin_only():
    panel = _panel()
    assert "const admin = typeof isAdmin === 'function' && isAdmin();" in panel
    # The action cell and the header slot that carries it are both gated, so a
    # non-admin sees the table exactly as before.
    assert "${admin ? `<td" in panel
    assert ".concat(admin ? [''] : [])" in panel


def test_the_header_gains_a_column_so_the_action_cell_is_not_orphaned():
    panel = _panel()
    head = panel.split("tableHead([", 1)[1].split("]", 1)[0]
    # Seven data columns; the eighth is the admin-only action slot added by
    # the concat above, not a hardcoded label.
    assert head.count("'") == 14


def test_remove_posts_only_the_remaining_members():
    fn = _remove_fn()
    assert "current.filter(m => m && m.id !== id)" in fn
    assert "JSON.stringify({ members: remaining })" in fn


def test_remove_posts_only_configuration_not_live_reporting_fields():
    fn = _remove_fn()
    mapped = fn.split(".map(m => ({", 1)[1].split("}))", 1)[0]
    assert "id: m.id" in mapped
    assert "host: m.host" in mapped
    for live in ("health", "ha_state", "config_digest", "scopes", "ha_role",
                 "remote_state"):
        assert live not in mapped


def test_remove_is_tenant_scoped():
    fn = _remove_fn()
    # An unscoped call lands on whichever dhcp module connected first — a
    # different tenant's pair.
    assert "'/api/dhcp/ha' + _tenantQS()" in fn


def test_remove_warns_that_dropping_a_node_ends_ha():
    fn = _remove_fn()
    assert "confirm(" in fn
    assert "stands down" in fn
    # It must not imply the host itself is deleted.
    assert "does not delete the host's spoke record" in fn


def test_remove_refuses_an_id_that_is_not_in_the_current_report():
    fn = _remove_fn()
    victim = fn.split("const victim =", 1)[1].split("\n", 1)[0]
    assert "current.find(m => m && m.id === id)" in victim
    assert "if (!victim) {" in fn


def test_remove_surfaces_partial_rather_than_reporting_success():
    fn = _remove_fn()
    assert "data.status === 'PARTIAL'" in fn
    assert "data.status === 'ERROR'" in fn


def test_remove_refreshes_the_diagnostics_tab():
    fn = _remove_fn()
    assert "loadDHCPData('Diagnostics')" in fn
