"""A 2-resolver DNS cluster must show BOTH resolvers, and sum BOTH resolvers.

Two separate defects with the same root cause -- the clustered views were built
around ONE "source" member (``diagnostics_source``) and quietly ignored the
rest:

1. **Diagnostics.** The four PASS/FAIL tiles (Unbound Service / Configuration /
   Port 53 / LAN Listener) and the interfaces / detected-IPv4 / access-control /
   listener / probe blocks were rendered once, from the source member only. On
   a 2-resolver cluster that printed .11's evidence *twice* (once in its member
   card, once at the bottom) and .12's verdicts *never* -- even though every
   member's reply already carries its own copy.

2. **Statistics.** ``_cluster_stats`` summed the counters but never carried
   ``recursion_time_avg`` at all, so the clustered page reported "avg 0s" no
   matter what either resolver measured. It is an average, so it cannot be
   summed -- it has to be weighted by the recursions each member served.

A single-host (non-clustered) module must render exactly as before.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAIN_JS = ROOT / "WebUI" / "main.js"
DNS_SPOKE = ROOT / "dns" / "src" / "dns_spoke.py"


def _js():
    return MAIN_JS.read_text(encoding="utf-8")


def _member_evidence():
    src = _js()
    return src.split("function _ddMemberEvidence(", 1)[1].split("\nfunction _tenantQS", 1)[0]


def _dns_diagnostics():
    src = _js()
    body = src.split("// \u2500\u2500 Diagnostics: explain installed-but-not-queryable Unbound", 1)[1]
    return body.split("// \u2500\u2500 Forwarders:", 1)[0]


def _dns_statistics():
    src = _js()
    return src.split("if (subMenu === 'Statistics') {", 1)[1].split(
        "// \u2500\u2500 Diagnostics:", 1)[0]


# --- Diagnostics: every resolver gets its own verdicts --------------------

def test_each_member_card_carries_its_own_four_checks():
    body = _member_evidence()
    for label in ("Unbound Service", "Configuration", "Port 53", "LAN Listener"):
        assert f"'{label}'" in body, f"per-member tile missing: {label}"


def test_the_per_member_checks_read_that_members_own_reply():
    # The whole bug was reading top-level `d.*` (the source member) instead of
    # the member's own `diag.*`.
    body = _member_evidence()
    assert "diag.service" in body and "diag.config" in body
    assert "diag.sockets" in body
    assert not re.search(r"\bd\.(service|config|sockets|probes)\b", body), (
        "member evidence must never fall back to the source member's payload"
    )


def test_the_clustered_page_does_not_reprint_the_source_members_evidence():
    body = _dns_diagnostics()
    # The duplicated blocks are now gated behind `cluster ? '' : ...`.
    for marker in ("Configured interfaces", "Detected local IPv4 addresses",
                   "Local DNS query probes"):
        idx = body.index(marker)
        preceding = body[:idx]
        assert "${cluster ? '' : `" in preceding, (
            f"{marker!r} is still rendered unconditionally from the source member"
        )


def test_a_single_host_module_still_renders_the_full_evidence():
    # Only the CLUSTERED path changed. A standalone resolver has no member
    # cards, so losing these blocks would blank its Diagnostics tab.
    body = _dns_diagnostics()
    assert "d.configured_interfaces" in body
    assert "d.local_ipv4s" in body
    assert "d.access_controls" in body
    assert "check('Unbound Service'" in body


def test_the_header_no_longer_claims_the_evidence_is_from_one_node():
    body = _dns_diagnostics()
    assert "evidence below is from" not in body, (
        "the clustered page now shows every resolver's own evidence"
    )
    assert "each resolver's own checks and evidence" in body


def test_member_evidence_stays_on_the_global_table_helpers():
    # Guard shared with test_webui_dd_member_evidence_scope: `tw`/`th` are
    # function-local aliases and are NOT in this top-level helper's scope.
    body = _member_evidence()
    assert not re.search(r"(?<![\w.$])(tw|th)\s*\(", body)


# --- Statistics: combine both resolvers ----------------------------------

def _cluster_stats_src():
    src = DNS_SPOKE.read_text(encoding="utf-8")
    start = src.index("    async def _cluster_stats(")
    return src[start:].split("\n    async def _cluster_forwarders", 1)[0]


def test_recursion_time_average_is_carried_at_all():
    # It was produced per-member (unbound_manager.diagnostics/stats) and then
    # dropped on the floor, so the tile always said "avg 0s".
    assert "recursion_time_avg" in _cluster_stats_src()


def test_the_recursion_average_is_weighted_not_summed():
    body = _cluster_stats_src()
    assert "recursion_time_weighted" in body
    assert 'num_recursive' in body
    assert re.search(r"recursion_time_weighted\s*/\s*totals\[\"num_recursive\"\]", body), (
        "an average must be weighted by each member's recursion count, "
        "not summed or naively meaned"
    )


def test_a_cluster_that_served_no_recursions_does_not_divide_by_zero():
    body = _cluster_stats_src()
    assert 'if totals["num_recursive"] else 0.0' in body


def test_a_member_that_did_not_answer_is_recorded_not_silently_dropped():
    body = _cluster_stats_src()
    assert "member_errors" in body
    assert "members_reporting" in body


def test_the_statistics_tab_says_how_many_resolvers_fed_the_totals():
    body = _dns_statistics()
    assert "members_reporting" in body
    assert "Combined across" in body


def test_the_statistics_tab_warns_when_a_resolver_is_missing():
    body = _dns_statistics()
    assert "did not report statistics" in body
    assert "d.member_errors" in body


def test_the_statistics_tab_tolerates_a_spoke_without_the_new_fields():
    # The two sides deploy independently; an older spoke sends neither key.
    body = _dns_statistics()
    assert not re.search(r"\bd\.(member_errors|members_reporting|member_count)\.", body)
    assert "d.member_errors && typeof d.member_errors === 'object'" in body


def test_the_single_host_statistics_view_gains_no_cluster_chrome():
    body = _dns_statistics()
    assert "d.cluster ?" in body, (
        "the 'Combined across N resolver(s)' line must be cluster-only"
    )
