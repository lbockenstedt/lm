"""WebUI invariants for the clustered DNS / Kea-HA surfaces.

Asserted against ``main.js`` text, the same way
``test_webui_hide_loaded_agent_roles.py`` does — there is no build step and no
JS test runner in this project.

Three round-2 blockers are locked in here:

* **#14** every cluster / HA / diagnostic request carries the tenant picker's
  selection. These endpoints resolve WHICH module spoke answers from the
  caller's effective tenant, so an unscoped request silently lands on whichever
  spoke connected first — another tenant's.
* **#2** the worker secret is required on first enablement and is never
  generated client-side.
* **#3/#4** the DHCP form collects write-only HA credentials + peer addresses,
  and offers hot-standby only.
"""

import os
import re

MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _src():
    with open(MAIN_JS, encoding="utf-8") as fh:
        return fh.read()


def _function(name):
    src = _src()
    start = src.index(name)
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"unbalanced {name}")


# ── #14: tenant scoping ────────────────────────────────────────────────────

def test_a_tenant_query_helper_exists():
    body = _function("function _tenantQS(")
    assert "currentTenant" in body
    assert "encodeURIComponent" in body
    # Empty selection must produce an empty suffix, not "?tenant=".
    assert "t ? `${prefix}tenant=" in body


CLUSTER_ENDPOINTS = [
    "/api/dns/cluster/reconcile",
    "/api/dhcp/ha/apply",
    "/api/dns/diagnostics",
    "/api/dns/stats",
    "/api/dns/forwarders",
    "/api/dhcp/diagnostics",
    "/api/dhcp/stats",
]


def test_every_cluster_and_diagnostic_request_passes_the_tenant():
    src = _src()
    for endpoint in CLUSTER_ENDPOINTS:
        for match in re.finditer(re.escape(f"'{endpoint}'"), src):
            tail = src[match.end():match.end() + 40]
            assert "_tenantQS()" in tail, \
                f"{endpoint} is requested without the tenant scope"


def test_the_cluster_summary_scopes_both_status_calls():
    body = _function("async function loadServiceClusterSummary(")
    assert "'/api/dns/cluster' + _tenantQS()" in body
    assert "'/api/dhcp/ha' + _tenantQS()" in body


def test_the_topology_save_scopes_its_post():
    body = _function("async function saveServiceCluster(")
    assert "+ _tenantQS()" in body


# ── #2: the worker secret is operator-supplied, never generated ────────────

def test_no_client_side_secret_generation():
    src = _src()
    window = src[src.index("// ─── Cluster / HA topology editor"):
                 src.index("async function reconcileDnsCluster(")]
    for banned in ("crypto.randomUUID", "getRandomValues", "Math.random"):
        assert banned not in window, \
            f"the worker secret must never be generated client-side ({banned})"


def test_first_enablement_requires_a_secret():
    body = _function("async function saveServiceCluster(")
    assert "members.length >= 2 && !secret && !alreadyEnabled" in body
    assert "A worker secret is required" in body


def test_the_secret_field_is_write_only_and_marked_required():
    body = _function("function openServiceClusterModal(")
    assert "type=\"password\"" in body
    assert "alreadyEnabled" in body
    assert "required to enable the cluster" in body
    assert "never displayed again" in body


# ── #3: HA credentials + peer addresses ────────────────────────────────────

def test_the_dhcp_form_collects_ha_credentials_and_peers():
    body = _function("function openServiceClusterModal(")
    assert "svc-cl-hauser" in body
    assert "svc-cl-hapass" in body
    assert "svc-cl-hapeers" in body
    assert "--ha-user" in body and "--ha-password" in body
    assert "--ha-peer" in body


def test_blank_ha_credentials_are_omitted_so_the_spoke_preserves_them():
    body = _function("async function saveServiceCluster(")
    assert "if (haUser) member.ha_user = haUser;" in body
    assert "if (haPass) member.ha_password = haPass;" in body
    assert "payload.ha_peers = peers" in body


def test_the_ha_password_placeholder_reflects_a_stored_value():
    body = _function("function openServiceClusterModal(")
    assert "ha_password_set" in body


# ── #4: hot-standby only ───────────────────────────────────────────────────

def test_load_balancing_is_not_offered():
    body = _function("function openServiceClusterModal(")
    assert 'value="load-balancing"' not in body
    assert 'value="hot-standby" selected' in body
    assert "disabled" in body
    assert "class" in body   # the explanation names the missing pool split


def test_the_save_always_sends_hot_standby():
    body = _function("async function saveServiceCluster(")
    assert "payload.mode = 'hot-standby';" in body


# ── PARTIAL results must not read as success ───────────────────────────────

def test_a_partial_save_is_surfaced_as_an_error_toast():
    body = _function("async function saveServiceCluster(")
    assert "data.status === 'PARTIAL'" in body
    assert "'error'" in body


# ── Round 3, #4: the form emits canonical, build_peers-valid TLS paths ─────

def test_the_form_uses_the_canonical_installer_tls_layout():
    src = _src()
    assert "const SVC_HA_TLS_DIR = '/etc/kea/ha-tls';" in src


def test_the_payload_always_carries_the_tls_material():
    """REGRESSION: the payload omitted it entirely, so build_peers rejected
    every pair created from the UI."""
    body = _function("async function saveServiceCluster(")
    assert "member.ha_trust_anchor = `${haTlsDir}/ha-ca.pem`" in body
    assert "member.ha_cert = `${haTlsDir}/node.crt`" in body
    assert "member.ha_key = `${haTlsDir}/node.key`" in body
    # ...unconditionally, not only when the operator typed something.
    assert "if (haTlsDir)" not in body


def test_the_form_exposes_the_tls_directory_for_a_non_default_install():
    body = _function("function openServiceClusterModal(")
    assert "svc-cl-hatls" in body
    assert "ha-ca.pem" in body and "node.crt" in body and "node.key" in body


def test_the_tls_directory_defaults_and_is_trailing_slash_safe():
    body = _function("async function saveServiceCluster(")
    assert "|| SVC_HA_TLS_DIR" in body
    assert ".replace(/\\/+$/, '')" in body


# ── Round 4, #1: the HA password is required on first enablement ───────────

def test_the_ha_password_is_required_before_the_pair_can_be_enabled():
    """REGRESSION: a passwordless pair came up looking configured and could
    never heartbeat — the Kea HA control agent rejects an unauthenticated
    peer."""
    body = _function("async function saveServiceCluster(")
    assert "!haCredsStored" in body
    assert "(!haUser || !haPass)" in body
    assert "HA control credentials are required" in body
    assert "unauthenticated peer" in body


def test_the_password_field_is_marked_required_until_one_is_stored():
    body = _function("function openServiceClusterModal(")
    assert "ha_password_set ? '' : ' <span class=\"text-red-600\">(required)</span>'" in body
    assert "required to enable the pair" in body


def test_the_stored_credential_flag_is_passed_to_the_save():
    body = _function("function openServiceClusterModal(")
    assert "saveServiceCluster('${escapeHtml(kind)}', ${alreadyEnabled}, ${!!m(0).ha_password_set})" in body


def test_a_blank_password_is_still_omitted_so_the_spoke_preserves_it():
    """Required on FIRST enablement, preserved on every re-save."""
    body = _function("async function saveServiceCluster(")
    assert "if (haPass) member.ha_password = haPass;" in body
