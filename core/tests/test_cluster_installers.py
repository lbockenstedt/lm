"""Installer invariants for the clustered DNS / Kea-HA deployments.

These are shell scripts, so the guarantees are asserted against their text —
the same approach ``test_webui_hide_loaded_agent_roles.py`` uses for main.js.
Three release-blocking properties are locked in here:

* **The Kea control agent stays loopback-only.** It is unauthenticated, so
  binding it to ``0.0.0.0`` would expose ``config-set`` to the network. HA peer
  traffic uses a SEPARATE, basic-auth-protected agent on its own port, firewalled
  to the declared partner.
* **Worker PSKs never travel over plaintext.** Both installers default the
  coordinator URL to ``wss://`` and reject a ``ws://`` URL to a remote host.
* **Coordinator state/config dirs exist and are owned by the service account**,
  or the fail-closed persistence blocks every change on a fresh box.
"""

import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DNS_SH = os.path.join(ROOT, "dns", "install_dns.sh")
DHCP_SH = os.path.join(ROOT, "dhcp", "install_dhcp.sh")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ── Review #1: the loopback CA is never published ──────────────────────────

def test_kea_control_agent_stays_loopback_only():
    src = _read(DHCP_SH)
    # The single-host CA config written by the installer.
    assert '"http-host": "127.0.0.1"' in src
    assert '"http-port": 8001' in src
    # ...and nothing rewrites it to 0.0.0.0 for HA members.
    assert 'cfg.setdefault("Control-agent", {})["http-host"] = "0.0.0.0"' not in src
    assert "kea-ctrl-agent.conf" in src
    ca_block = src[src.index("KEA_CA_CONF="):src.index("KEACONF", src.index("KEA_CA_CONF="))]
    assert "0.0.0.0" not in ca_block


def test_ha_peer_traffic_uses_a_separate_https_agent():
    """REGRESSION (round 2, #5): HTTPS with mutual certificate verification.
    Basic-auth credentials ride inside that session; there is no plaintext
    HTTP fallback for peer traffic."""
    src = _read(DHCP_SH)
    assert 'HA_AGENT_CONF="/etc/kea/kea-ha-agent.conf"' in src
    assert 'HA_PORT="8002"' in src
    assert '"trust-anchor": "${HA_CA}"' in src
    assert '"cert-file": "${HA_CERT}"' in src
    assert '"key-file": "${HA_KEY}"' in src
    assert '"cert-required": true' in src
    assert '"type": "basic"' in src
    assert '"user": "${HA_USER}", "password": "${HA_PASSWORD}"' in src
    # A dedicated unit serves it, so the loopback agent is untouched.
    assert "kea-ctrl-agent -c ${HA_AGENT_CONF}" in src
    assert 'HA_AGENT_SERVICE="kea-ha-agent"' in src


def test_ha_tls_material_is_mandatory():
    src = _read(DHCP_SH)
    assert "--ha-ca, --ha-cert and --ha-key are required" in src
    assert "--ha-ca)" in src and "--ha-cert)" in src and "--ha-key)" in src


def test_an_ha_member_without_a_password_is_refused():
    src = _read(DHCP_SH)
    assert 'if [[ -z "$HA_PASSWORD" ]]; then' in src
    assert "--ha-password is required" in src


def test_the_ha_port_firewall_is_persistent():
    """REGRESSION (round 2, #5): runtime-only rules vanished on the first
    reboot — exactly when nobody is watching."""
    src = _read(DHCP_SH)
    assert "--ha-peer)" in src
    assert "/etc/nftables.d/lm-kea-ha.nft" in src
    assert 'include "/etc/nftables.d/*.nft"' in src
    assert "systemctl enable nftables" in src
    assert "netfilter-persistent save" in src
    assert "iptables-persistent" in src
    assert "iptables -A LM_KEA_HA -j DROP" in src


def test_stand_down_stops_the_worker_and_ha_agent():
    """REGRESSION (round 2, #13): a removed node must stop dialling its old
    coordinator and close the HA port."""
    src = _read(DHCP_SH)
    assert "--stand-down)" in src
    assert "systemctl disable --now lm-dhcp-worker" in src
    assert "systemctl disable --now kea-ha-agent" in src
    assert "rm -f /etc/nftables.d/lm-kea-ha.nft" in src


def test_hook_libraries_come_from_kea_common_and_a_resolved_path():
    """REGRESSION (round 2, #6): there is no 'kea-hooks' package, and the hook
    dir carries the architecture triplet."""
    src = _read(DHCP_SH)
    assert "apt-get install -y -qq kea-common" in src
    # The non-existent package must not be installed anywhere (the only
    # remaining mentions are explanatory comments/messages).
    assert "install -y -qq kea-hooks" not in src
    assert "for cand in /usr/lib/*/kea/hooks /usr/lib/kea/hooks" in src
    assert 'libdhcp_ha.so' in src


# ── Review #2: worker PSKs never cross a plaintext hop ─────────────────────

def test_both_installers_default_the_coordinator_url_to_wss():
    for path, port in ((DNS_SH, "8769"), (DHCP_SH, "8770")):
        src = _read(path)
        assert f'COORDINATOR="wss://${{COORDINATOR}}:{port}"' in src, path
        assert 'COORDINATOR="wss://${COORDINATOR}"' in src, path
        assert f'COORDINATOR="ws://${{COORDINATOR}}:{port}"' not in src, path


def test_both_installers_reject_remote_plaintext_coordinators():
    for path in (DNS_SH, DHCP_SH):
        src = _read(path)
        assert "Refusing plaintext ws:// to a remote coordinator" in src, path
        # Loopback stays allowed (TLS terminates upstream on all-in-one).
        assert "ws://localhost*|ws://127.*|ws://[::1]*" in src, path


# ── Review #4: coordinator state/config dirs exist and are writable ────────

def test_dns_installer_creates_and_chowns_the_coordinator_dirs():
    src = _read(DNS_SH)
    assert 'COORD_DIRS=("/etc/lm-dns" "/var/lib/lm-dns")' in src
    assert 'SVC_USER="svc_lm"' in src
    assert re.search(r'install -d -m 0750 "\$d"', src)
    assert 'chown "$SVC_USER":"$SVC_USER" "$d"' in src


def test_dhcp_installer_creates_and_chowns_the_coordinator_dirs():
    src = _read(DHCP_SH)
    assert 'COORD_DIRS=("/etc/lm-dhcp" "/var/lib/lm-dhcp")' in src
    assert 'SVC_USER="svc_lm"' in src
    assert re.search(r'install -d -m 0750 "\$d"', src)
    assert 'chown "$SVC_USER":"$SVC_USER" "$d"' in src


def test_the_dir_creation_runs_on_the_normal_spoke_install_not_only_the_worker():
    """The dirs belong to the COORDINATOR, which is the spoke/role install —
    creating them only in the worker branch would leave the coordinator unable
    to persist anything."""
    for path in (DNS_SH, DHCP_SH):
        src = _read(path)
        dirs_at = src.index("COORD_DIRS[@]")
        worker_at = src.index('if [[ -n "$MEMBER_ID"')
        assert dirs_at < worker_at, path


def test_worker_units_are_installed_for_both_modules():
    assert 'WORKER_SERVICE="lm-dns-worker"' in _read(DNS_SH)
    assert 'WORKER_SERVICE="lm-dhcp-worker"' in _read(DHCP_SH)


# ── Review #3: the in-repo dns/dhcp entrypoints wire the plane first ────────

import ast


def _run_body(path, class_name):
    tree = ast.parse(open(path, encoding="utf-8").read())
    cls = next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == class_name)
    run = next(n for n in cls.body
               if isinstance(n, ast.AsyncFunctionDef) and n.name == "run")
    return run.body


def _line_of(body, needle):
    for node in body:
        if needle in ast.dump(node):
            return node.lineno
    raise AssertionError(f"{needle} not found")


def test_lm_dns_control_plane_attaches_before_registering():
    body = _run_body(os.path.join(ROOT, "dns", "src", "control_plane.py"),
                     "DNSControlPlane")
    assert _line_of(body, "attr='control_plane'") < \
        _line_of(body, "attr='register_module'")


def test_lm_dhcp_control_plane_attaches_before_registering():
    body = _run_body(os.path.join(ROOT, "dhcp", "src", "control_plane.py"),
                     "DHCPControlPlane")
    assert _line_of(body, "attr='control_plane'") < \
        _line_of(body, "attr='register_module'")


def test_lm_dns_control_plane_starts_the_reconcile_loop():
    body = _run_body(os.path.join(ROOT, "dns", "src", "control_plane.py"),
                     "DNSControlPlane")
    assert any("start_background_loops" in ast.dump(n) for n in body)



# ── Review round 2, #1: coordinator TLS + worker trust anchor ──────────────

def test_both_installers_provision_a_coordinator_certificate():
    """The cluster listener refuses to bind plaintext, so a coordinator with no
    cert would simply never come up."""
    for path, tls_dir in ((DNS_SH, "/etc/lm-dns/tls"),
                          (DHCP_SH, "/etc/lm-dhcp/tls")):
        src = _read(path)
        assert f'TLS_DIR="{tls_dir}"' in src, path
        assert "provision_coordinator_tls() {" in src, path
        assert "provision_coordinator_tls\n" in src, f"{path}: never invoked"
        assert "openssl req -x509" in src, path
        assert "subjectAltName=" in src, path
        assert 'Environment="LM_TLS_CERT=$TLS_CERT"' in src, path
        assert 'Environment="LM_TLS_KEY=$TLS_KEY"' in src, path
        assert "--tls-cert)" in src and "--tls-key)" in src, path


def test_both_installers_require_a_worker_trust_anchor():
    for path, ca in ((DNS_SH, "/etc/lm-dns-worker/coordinator-ca.pem"),
                     (DHCP_SH, "/etc/lm-dhcp-worker/coordinator-ca.pem")):
        src = _read(path)
        assert f'WORKER_CA_PATH="{ca}"' in src, path
        assert '"$(readlink -f "$WORKER_CA")" != "$(readlink -f "$WORKER_CA_PATH")"' in src, path
        assert "--ca-cert is required" in src, path
        assert "LM_CLUSTER_CA_CERT=$WORKER_CA_PATH" in src, path
        assert "--ca-cert)" in src, path


def test_no_installer_disables_verification():
    """LM_CLUSTER_TLS_VERIFY no longer exists; only the hostname check may be
    relaxed for a self-signed-by-IP coordinator."""
    for path in (DNS_SH, DHCP_SH):
        src = _read(path)
        assert "LM_CLUSTER_TLS_VERIFY" not in src, path
        assert "LM_CLUSTER_TLS_CHECK_HOSTNAME=0" in src, path


# ── Round 3, #8: --stand-down must run BEFORE the hub validation ───────────

def test_stand_down_is_processed_before_the_hub_requirement():
    """REGRESSION: the documented recovery command exited with a usage error,
    because a node being REMOVED from a pair has no hub to name."""
    for path, unit in ((DHCP_SH, "lm-dhcp-worker"), (DNS_SH, "lm-dns-worker")):
        src = _read(path)
        stand_down_at = src.index('if [[ "$STAND_DOWN" == true ]]; then')
        usage_at = src.index('echo "Usage: $0 --hub')
        assert stand_down_at < usage_at, f"{path}: --stand-down is gated by --hub"
        assert f"systemctl disable --now {unit}" in src, path
        assert "--stand-down)" in src, path


def test_standalone_stand_down_does_not_touch_the_service_itself():
    """A removed node keeps serving: stopping Unbound/Kea would blackhole every
    client still pointed at it."""
    dns = _read(DNS_SH)
    block = dns[dns.index('if [[ "$STAND_DOWN" == true ]]; then'):]
    block = block[:block.index("fi\n")]
    assert "disable --now unbound" not in block
    assert "Unbound and its records are untouched" in dns

    dhcp = _read(DHCP_SH)
    block = dhcp[dhcp.index('if [[ "$STAND_DOWN" == true ]]; then'):]
    block = block[:block.index("fi\n")]
    assert "kea-dhcp4-server" not in block
    assert "Kea itself is still serving its own scopes." in dhcp


def test_dhcp_stand_down_removes_the_persistent_firewall_rules():
    src = _read(DHCP_SH)
    block = src[src.index('if [[ "$STAND_DOWN" == true ]]; then'):]
    assert "rm -f /etc/nftables.d/lm-kea-ha.nft" in block
    assert "nft delete table inet lm_kea_ha" in block
    assert "iptables -X LM_KEA_HA" in block


# ── Round 3, #2: the generic-agent installer provisions hosted certs ───────

AGENT_SH = os.path.join(ROOT, "agent", "install_agent.sh")


def test_the_agent_installer_mints_hosted_cluster_listener_certs():
    """A hosted dns/dhcp cluster role has no installer of its own, and its
    listener refuses to serve plaintext."""
    src = _read(AGENT_SH)
    assert "for _mod in dns dhcp; do" in src
    assert '_tls="/etc/lm-${_mod}/tls"' in src
    assert "openssl req -x509" in src
    assert "subjectAltName=" in src
    assert 'chmod 0600 "$_tls/coordinator.key"' in src


# ── Round 4, #3: per-role listener TLS env ────────────────────────────────

def test_the_cluster_planes_declare_role_specific_tls_env():
    """REGRESSION: a shared LM_TLS_CERT made co-loaded dns + dhcp listeners
    serve each other's certificate."""
    for path, cert_env, key_env in (
            (os.path.join(ROOT, "dns", "src", "control_plane.py"),
             "LM_DNS_TLS_CERT", "LM_DNS_TLS_KEY"),
            (os.path.join(ROOT, "dhcp", "src", "control_plane.py"),
             "LM_DHCP_TLS_CERT", "LM_DHCP_TLS_KEY")):
        src = _read(path)
        assert f'AGENT_TLS_CERT_ENV = "{cert_env}"' in src, path
        assert f'AGENT_TLS_KEY_ENV = "{key_env}"' in src, path


def test_the_hosted_roles_declare_role_specific_tls_env():
    src = _read(os.path.join(ROOT, "agent", "src", "control_plane.py"))
    assert '"AGENT_TLS_CERT_ENV": "LM_DNS_TLS_CERT"' in src
    assert '"AGENT_TLS_CERT_ENV": "LM_DHCP_TLS_CERT"' in src
    assert '"AGENT_TLS_KEY_ENV": "LM_DNS_TLS_KEY"' in src
    assert '"AGENT_TLS_KEY_ENV": "LM_DHCP_TLS_KEY"' in src


def test_provisioning_never_writes_the_process_environment():
    src = _read(os.path.join(ROOT, "core", "src", "messaging", "agent_hosting.py"))
    assert 'os.environ.setdefault("LM_TLS_CERT"' not in src
    assert "self._listener_cert = cert" in src
    assert "self._listener_key = key" in src


def test_the_agent_installer_mints_a_cert_per_role():
    src = _read(os.path.join(ROOT, "agent", "install_agent.sh"))
    assert "for _mod in dns dhcp; do" in src
    assert '_tls="/etc/lm-${_mod}/tls"' in src
    assert src.index("retire_legacy_agent\n") < src.index("for _mod in dns dhcp; do")


# ── Round 4, #5: the LM twin's reservation update is atomic ───────────────

def test_the_lm_kea_manager_update_is_a_single_write():
    """REGRESSION: delete-then-add left the reservation gone when the second
    write failed."""
    src = _read(os.path.join(ROOT, "dhcp", "src", "kea_manager.py"))
    body = src[src.index("def update_reservation("):]
    body = body[:body.index("def delete_reservation(")]
    assert body.count("self._set_config(") == 1, "must be ONE config write"
    assert "self.add_reservation(" not in body, "no second write"
    assert "Subnet {subnet_id} not found" in body
