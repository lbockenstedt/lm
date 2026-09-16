"""A Kea pair applying a freshly-synced config must read "updating", not "degraded".

A NetBox -> Kea sync sends ``config-set``, which re-initialises Kea's HA hook.
Kea then deliberately takes the node out of service (``HA_LOCAL_DHCP_DISABLE
... while in the WAITING state``) and walks WAITING -> SYNCING -> READY ->
HOT-STANDBY -- about 30 seconds, inside one never-restarted process. For that
whole window both nodes are out of sync, so the page said

    Kea HA pair needs attention        configuration MISMATCHED

which reads as a simultaneous two-node failure during a routine push.

The spoke now reports ``updating`` / ``serving`` (see dhcp/src/kea_ha.py).
These tests hold the *hub* to its two jobs:

1. the redaction filter must let the new fields through, or a non-admin gets
   the old alarming view with nothing to explain it; and
2. the WebUI must actually consume them -- blue, not amber, and with wording
   that tells the operator no action is needed.
"""

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAIN_JS = ROOT / "WebUI" / "main.js"
NET_SERVICES = ROOT / "core" / "src" / "routes" / "net_services.py"


def _redactor():
    """Pull the nested ``_redact_dhcp_cluster`` out of ``register`` and run it.

    It is defined inside ``register(app, hub, ctx)``, so it cannot be imported.
    Extracting and exec'ing the real source keeps this a behavioural test of
    the shipped code rather than a spelling check on a tuple literal.
    """
    src = NET_SERVICES.read_text(encoding="utf-8")
    start = src.index("    def _redact_dhcp_cluster(cluster):")
    rest = src[start:]
    end = rest.index("\n    def ", 1)
    ns = {}
    exec(textwrap.dedent(rest[:end]), ns)
    return ns["_redact_dhcp_cluster"]


def _full_report():
    return {
        "enabled": True, "mode": "hot-standby", "state": "updating",
        "healthy": False, "updating": True, "serving": True,
        "serving_count": 1, "updating_members": ["a"],
        "config_converged": False, "member_count": 2, "healthy_count": 0,
        "members": [
            {"id": "a", "display_name": "kea-1", "connected": True,
             "health": "updating", "ha_state": "syncing", "ha_enabled": True,
             "serving": False, "ha_trust_anchor": "SECRET"},
            {"id": "b", "display_name": "kea-2", "connected": True,
             "health": "healthy", "ha_state": "hot-standby",
             "ha_enabled": True, "serving": True, "ha_key": "SECRET"},
        ],
    }


# --- the hub must not strip the explanation -------------------------------

def test_a_non_admin_still_learns_the_pair_is_updating():
    out = _redactor()(_full_report())
    assert out["updating"] is True
    assert out["state"] == "updating"


def test_the_non_admin_view_keeps_the_serving_counts():
    # Without these the UI cannot say "1/2 serving" and falls back to
    # "0/2 in sync", which is the alarming reading we are removing.
    out = _redactor()(_full_report())
    assert out["serving"] is True
    assert out["serving_count"] == 1


def test_the_non_admin_view_keeps_which_nodes_are_updating():
    out = _redactor()(_full_report())
    assert out["updating_members"] == ["a"]


def test_each_member_carries_its_own_serving_flag():
    out = _redactor()(_full_report())
    assert [m["serving"] for m in out["members"]] == [False, True]


def test_redaction_still_drops_the_ha_tls_material():
    # The whole point of the filter. Widening the keep-list must not leak.
    blob = repr(_redactor()(_full_report()))
    assert "SECRET" not in blob
    for m in _redactor()(_full_report())["members"]:
        assert "ha_trust_anchor" not in m and "ha_key" not in m


def test_a_degraded_report_is_unchanged_by_the_widened_keep_list():
    bad = dict(_full_report(), state="degraded", healthy=False,
               updating=False, serving=False, serving_count=0,
               updating_members=[])
    out = _redactor()(bad)
    assert out["state"] == "degraded"
    assert out["updating"] is False and out["serving"] is False


# --- the WebUI must consume them ------------------------------------------

def _js():
    return MAIN_JS.read_text(encoding="utf-8")


def _fn(name, end_marker):
    src = _js()
    return src.split(name, 1)[1].split(end_marker, 1)[0]


def test_the_updating_badge_is_blue_not_amber():
    body = _fn("function _ddClusterBadge(state) {", "\n}\n")
    m = re.search(r"updating:\s*\[([^\]]*)\]", body)
    assert m, "_ddClusterBadge has no `updating` tone"
    tone = m.group(1)
    assert "sky" in tone
    assert "amber" not in tone and "red" not in tone, (
        "an updating pair is doing what the sync asked; warning colours here "
        "are what made a routine NetBox push look like an outage"
    )


def test_a_degraded_pair_is_still_amber():
    # Guard the guard: the new tier must not have softened the real one.
    body = _fn("function _ddClusterBadge(state) {", "\n}\n")
    assert re.search(r"degraded:\s*\[[^\]]*amber", body)
    assert re.search(r"down:\s*\[[^\]]*red", body)


def test_the_member_tone_map_knows_updating():
    body = _fn("const _DD_MEMBER_TONE = {", "};")
    assert "updating:" in body and "sky" in body


def test_the_ha_panel_says_converging_instead_of_mismatched_while_updating():
    body = _fn("function _dhcpHaPanel(c) {", "\n// Drop a single Kea node")
    assert "CONVERGING" in body
    assert "MISMATCHED" in body, "a genuine split must still say MISMATCHED"
    assert "c.updating" in body


def test_the_ha_panel_explains_that_no_action_is_needed():
    body = _fn("function _dhcpHaPanel(c) {", "\n// Drop a single Kea node")
    assert "No action needed" in body
    assert "30 seconds" in body


def test_the_diagnostics_header_reports_updating_rather_than_needs_attention():
    src = _js()
    head = src.split("const haPanel = _dhcpHaPanel(haCluster);", 1)[1][:3000]
    assert "Kea HA pair updating" in head
    assert "Kea HA pair needs attention" in head, (
        "a genuinely broken pair must still say needs attention"
    )


def test_a_serving_pair_mid_update_is_not_painted_red():
    src = _js()
    block = src.split("const dhcp4 = units['kea-dhcp4-server']", 1)[0]
    decl = block.rsplit("const good =", 1)[1]
    assert "updating" in decl and "serving" in decl, (
        "DHCP diagnostics `good` must consider serving-while-updating"
    )


def test_member_evidence_marks_updating_nodes_instead_of_needs_attention():
    body = _fn("function _ddMemberEvidence(", "\n}\n")
    assert "updatingIds" in body
    assert "updating</span>" in body
    assert "needs attention</span>" in body, (
        "an unhealthy node with no apply in flight still needs attention"
    )


def test_the_dhcp_tab_passes_the_updating_members_through():
    src = _js()
    assert "_ddMemberEvidence(d.members, 'dhcp', haCluster.updating_members)" in src


def test_the_ui_tolerates_a_spoke_that_never_sends_the_new_fields():
    # The two sides deploy independently, so every read must be optional-safe:
    # no `c.updating.` / `d.serving.` dereferences anywhere.
    src = _js()
    assert not re.search(r"\b[cd]\.(updating|serving)\.", src)
    assert not re.search(r"\bhaCluster\.updating_members\.", src)


# --- twin parity ----------------------------------------------------------

def test_the_bundled_dhcp_spoke_matches_the_dhcp_repo_contract():
    # dhcp/ <-> lm/dhcp/ is a byte-identical twin pair (dual-copy-guard #6).
    # If this copy lost the new states the hub would ship a UI for data the
    # bundled spoke never sends.
    kea_ha = (ROOT / "dhcp" / "src" / "kea_ha.py").read_text(encoding="utf-8")
    assert "TRANSITIONAL_HA_STATES" in kea_ha
    assert '"updating_members": updating_ids' in kea_ha
    spoke = (ROOT / "dhcp" / "src" / "dhcp_spoke.py").read_text(encoding="utf-8")
    assert 'or report.get("serving")' in spoke
