"""Service-level diagnostics for the embedded Unbound and Kea role managers."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dns_manager = _load("lm_dns_diag_manager", "dns/src/unbound_manager.py")
dhcp_manager = _load("lm_dhcp_diag_manager", "dhcp/src/kea_manager.py")


def _result(ok=True, output="", error=""):
    return {"ok": ok, "exit_code": 0 if ok else 1,
            "output": output, "error": error}


def test_dns_diagnostics_detects_resolved_only_port_53(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))

    def run(cmd, timeout=5):
        if cmd[0] == "ss":
            return _result(output=(
                "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* "
                'users:(("systemd-resolve",pid=1,fd=1))'))
        return _result(output="active")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_local_ipv4s", lambda: ["10.0.0.5"])
    monkeypatch.setattr(mgr, "_dns_probe", lambda server: {
        "server": server, "responded": server == "127.0.0.1",
        "rcode": 0 if server == "127.0.0.1" else None,
        "answers": 1 if server == "127.0.0.1" else 0,
        "latency_ms": 1, "error": "" if server == "127.0.0.1" else "timed out",
    })

    result = mgr.diagnostics()
    assert result["healthy"] is False
    assert result["sockets"]["has_port_53_listener"] is True
    assert result["sockets"]["has_lan_listener"] is False
    assert any("loopback" in item for item in result["recommendations"])


def test_dns_diagnostics_self_heals_failed_unbound_unit(monkeypatch, tmp_path):
    """Mirrors ``KeaManager``'s DHCP-side ``_heal_inactive_units()`` test
    coverage: a crash-looped/killed ``unbound`` unit (systemd reports it
    loaded but failed) used to require an operator to notice and manually
    restart it (or uninstall/reinstall the whole DNS role). ``diagnostics()``
    must now restart it itself and surface the repair in ``self_healed`` /
    the recommendations, exactly once per failing call."""
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    restarts = []

    def run(cmd, timeout=5):
        if cmd == ["systemctl", "is-active", "unbound"]:
            return _result(ok=False, error="failed")
        if cmd[:2] == ["systemctl", "show"]:
            return _result(output=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "NRestarts=3\nExecMainStatus=1"))
        if cmd[:2] == ["systemctl", "restart"]:
            restarts.append(cmd[2])
            return _result(ok=True)
        if cmd[0] == "ss":
            return _result(output="")
        return _result(output="active")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_local_ipv4s", lambda: [])
    monkeypatch.setattr(mgr, "_dns_probe", lambda server: {
        "server": server, "responded": False, "rcode": None,
        "answers": 0, "latency_ms": None, "error": "timed out"})

    result = mgr.diagnostics()
    assert restarts == ["unbound"]
    assert result["self_healed"] == ["restarted unbound (was failed)"]
    assert any(item.startswith("Self-healed: restarted unbound")
               for item in result["recommendations"])


def test_dns_diagnostics_does_not_restart_healthy_unbound(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    restarts = []

    def run(cmd, timeout=5):
        if cmd[:2] == ["systemctl", "show"]:
            return _result(output=(
                "LoadState=loaded\nActiveState=active\nSubState=running\n"
                "NRestarts=0\nExecMainStatus=0"))
        if cmd[:2] == ["systemctl", "restart"]:
            restarts.append(cmd[2])
            return _result(ok=True)
        if cmd[0] == "ss":
            return _result(output="")
        return _result(output="active")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_local_ipv4s", lambda: [])
    monkeypatch.setattr(mgr, "_dns_probe", lambda server: {
        "server": server, "responded": False, "rcode": None,
        "answers": 0, "latency_ms": None, "error": "timed out"})

    result = mgr.diagnostics()
    assert restarts == []
    assert result["self_healed"] == []


def test_dns_diagnostics_reports_healthy_lan_probe(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))


    def run(cmd, timeout=5):
        if cmd[0] == "ss":
            return _result(output="udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*")
        return _result(output="active")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_local_ipv4s", lambda: ["10.0.0.5"])
    monkeypatch.setattr(mgr, "_dns_probe", lambda server: {
        "server": server, "responded": True, "rcode": 0,
        "answers": 1, "latency_ms": 1, "error": "",
    })
    assert mgr.diagnostics()["healthy"] is True


def test_dns_stats_sum_threaded_query_type_counters(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    output = "\n".join([
        "total.num.queries=9",
        "thread0.num.query.type.A=4",
        "thread1.num.query.type.A=2",
        "thread1.num.query.type.AAAA=3",
    ])
    monkeypatch.setattr(
        dns_manager.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=output, stderr=""))

    assert mgr.get_stats()["query_types"] == {"A": 6, "AAAA": 3}


def test_dns_ensure_query_logging_chowns_log_dir_to_unbound_user(monkeypatch, tmp_path):
    # Regression test: the query-log directory must be owned by the "unbound"
    # system user (the daemon that actually opens/writes the logfile), not
    # whoever runs the coordinator process — otherwise unbound silently drops
    # the logfile directive and per-destination query stats stay empty
    # forever. See unbound_manager._ensure_query_logging().
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    log_path = tmp_path / "unbound-logs" / "lm-queries.log"
    monkeypatch.setattr(dns_manager, "QUERY_LOG", str(log_path))
    monkeypatch.setattr(dns_manager, "LOGGING_CONF", str(tmp_path / "lm-logging.conf"))

    chown_calls = []
    chmod_calls = []
    monkeypatch.setattr(dns_manager.os, "chown",
                         lambda path, uid, gid: chown_calls.append((path, uid, gid)))
    monkeypatch.setattr(dns_manager.os, "chmod",
                         lambda path, mode: chmod_calls.append((path, mode)))

    class FakePwEntry:
        pw_uid = 123
        pw_gid = 456

    import pwd
    monkeypatch.setattr(pwd, "getpwnam", lambda name: FakePwEntry())

    mgr._ensure_query_logging()

    assert chown_calls == [(str(log_path.parent), 123, 456)]
    assert chmod_calls == [(str(log_path.parent), 0o755)]


def test_dns_ensure_query_logging_tolerates_missing_unbound_user(monkeypatch, tmp_path):
    # On a host with no "unbound" system user (e.g. a test/dev box), the
    # self-heal chown must be skipped quietly rather than raising.
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    log_path = tmp_path / "unbound-logs" / "lm-queries.log"
    monkeypatch.setattr(dns_manager, "QUERY_LOG", str(log_path))
    monkeypatch.setattr(dns_manager, "LOGGING_CONF", str(tmp_path / "lm-logging.conf"))

    import pwd

    def raise_keyerror(name):
        raise KeyError(name)
    monkeypatch.setattr(pwd, "getpwnam", raise_keyerror)

    # Should not raise despite no "unbound" user existing.
    mgr._ensure_query_logging()
    assert log_path.parent.is_dir()


def test_dns_add_forwarder_persists_config_and_reloads(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    # list_forwarders is called twice by add_forwarder: once before the write
    # (duplicate check, no forwarders yet) and once after reload (confirming
    # the new zone actually took effect) — mirror real Unbound by reading the
    # zone back from the managed conf file rather than always answering "[]",
    # which would make add_forwarder's own success confirmation impossible to
    # exercise and mask the real reload silently not applying a change.
    monkeypatch.setattr(
        mgr, "list_forwarders",
        lambda: {"status": "SUCCESS",
                 "forwarders": [{"zone": z["zone"], "class": "IN",
                                  "upstreams": z["upstreams"]}
                                 for z in mgr._managed_forwarders()]})
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": True, "error": ""})

    result = mgr.add_forwarder(".", ["1.1.1.1", "2606:4700:4700::1111"])

    assert result["status"] == "SUCCESS"
    text = (tmp_path / "lm-forwarders.conf").read_text()
    assert 'name: "."' in text
    assert "forward-addr: 1.1.1.1" in text
    assert "forward-addr: 2606:4700:4700::1111" in text


def test_dns_add_forwarder_reports_error_when_reload_silently_drops_it(
        monkeypatch, tmp_path):
    """Regression test: Unbound's ``unbound-control reload`` ACKs immediately
    and only re-parses/rebuilds the forwards tree afterward — a duplicate
    zone name defined elsewhere (e.g. distro-default unbound.conf) is
    silently dropped server-side with nothing surfaced over the control
    channel. Without a post-reload confirmation, add_forwarder previously
    reported SUCCESS even though the zone never actually took effect —
    exactly the "no error, but it doesn't show up" symptom reported by a
    user. add_forwarder must now confirm the zone is actually live before
    calling this a success."""
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    monkeypatch.setattr(mgr, "list_forwarders",
                        lambda: {"status": "SUCCESS", "forwarders": []})
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": True, "error": ""})

    result = mgr.add_forwarder(".", ["1.1.1.1"])

    assert result["status"] == "ERROR"
    assert result["changed"] is False
    assert "did not take effect" in result["message"]


def test_dns_add_forwarder_rejects_invalid_or_duplicate_values(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))

    assert mgr.add_forwarder("bad zone", ["1.1.1.1"])["status"] == "ERROR"
    assert mgr.add_forwarder(".", ["not-an-ip"])["status"] == "ERROR"

    monkeypatch.setattr(mgr, "list_forwarders", lambda: {
        "status": "SUCCESS",
        "forwarders": [{"zone": ".", "upstreams": ["8.8.8.8"]}],
    })
    duplicate = mgr.add_forwarder(".", ["1.1.1.1"])
    assert duplicate["status"] == "ERROR"
    assert "already exists" in duplicate["message"]


def test_dns_add_forwarder_restores_previous_file_when_reload_fails(
        monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    mgr.forwarders_path = str(tmp_path / "lm-forwarders.conf")
    original = '# existing\nforward-zone:\n    name: "old.example."\n'
    (tmp_path / "lm-forwarders.conf").write_text(original)
    monkeypatch.setattr(mgr, "list_forwarders",
                        lambda: {"status": "SUCCESS", "forwarders": []})
    reloads = iter([
        {"ok": False, "error": "invalid configuration"},
        {"ok": True, "error": ""},
    ])
    monkeypatch.setattr(mgr, "_reload", lambda: next(reloads))

    result = mgr.add_forwarder(".", ["1.1.1.1"])

    assert result["status"] == "ERROR"
    assert (tmp_path / "lm-forwarders.conf").read_text() == original


def test_dhcp_diagnostics_matches_kea_health_contract(monkeypatch):
    mgr = dhcp_manager.KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    def run(cmd, timeout=5):
        if cmd[0] == "ss":
            return _result(output=(
                "udp UNCONN 0 0 10.0.0.5:67 0.0.0.0:*\n"
                "tcp LISTEN 0 128 127.0.0.1:8001 0.0.0.0:*"))
        return _result(output="configuration check successful")

    def rpc(service, command, args=None):
        if command == "version-get":
            return {"version": "2.4.1"}
        if command == "config-get":
            return {"Dhcp4": {
                "interfaces-config": {"interfaces": ["eth0"]},
                "lease-database": {"name": "/var/lib/kea/kea-leases4.csv"},
                "subnet4": [{"id": 1, "subnet": "10.0.0.0/24",
                             "pools": [{"pool": "10.0.0.10 - 10.0.0.200"}]}],
            }}
        if command == "lease4-get-all":
            return {"leases": [{"ip": "10.0.0.10"}]}
        raise AssertionError(command)

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", rpc)
    monkeypatch.setattr(dhcp_manager.os.path, "exists", lambda path: True)

    result = mgr.diagnostics()
    assert result["healthy"] is True
    assert result["interfaces_configured"] == ["eth0"]
    assert result["lease_db"]["leases"] == 1
    assert result["listeners"]["dhcp4"]


def test_dhcp_diagnostics_is_unhealthy_when_config_retrieval_fails(monkeypatch):
    mgr = dhcp_manager.KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })
    monkeypatch.setattr(mgr, "_run_diag", lambda cmd, timeout=5: _result(
        output="udp UNCONN 0 0 10.0.0.5:67 0.0.0.0:*"
        if cmd[0] == "ss" else "configuration check successful"))

    def rpc(service, command, args=None):
        if command == "version-get":
            return {"version": "2.4.1"}
        if command == "lease4-get-all":
            return {"leases": []}
        raise RuntimeError("config denied")

    monkeypatch.setattr(mgr, "_rpc", rpc)
    result = mgr.diagnostics()
    assert result["healthy"] is False
    assert result["ca"]["reachable"] is True
    assert result["ca"]["config_loaded"] is False
    assert any("configuration retrieval failed" in item
               for item in result["recommendations"])


def test_dhcp_diagnostics_self_heals_empty_interfaces_config(monkeypatch):
    """A stock Debian kea-dhcp4.conf ships interfaces-config.interfaces == []
    ("listen on nothing"), and nothing in the LM sync path (interfaces-config
    is node-owned, see COORDINATOR_OWNED_KEYS in kea_ha.py) ever populates it.
    The node looks entirely healthy — service active, HA fine, control agent
    answering config-get — while Kea has never opened a DHCPv4 socket, which
    is exactly "Nothing is listening on DHCP server port UDP/67". diagnostics()
    must self-heal this by setting interfaces to ["*"] and restarting Kea so
    the new interface binding actually takes effect."""
    mgr = dhcp_manager.KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    restarted = []

    def run(cmd, timeout=5):
        if cmd[0] == "systemctl" and cmd[1] == "restart":
            restarted.append(cmd[2])
            return _result(output="")
        if cmd[0] == "ss":
            return _result(output="udp UNCONN 0 0 10.0.0.5:67 0.0.0.0:*")
        return _result(output="configuration check successful")

    state = {"interfaces": []}
    set_calls = []

    def rpc(service, command, args=None):
        if command == "version-get":
            return {"version": "2.4.1"}
        if command == "config-get":
            return {"Dhcp4": {
                "interfaces-config": {"interfaces": state["interfaces"]},
                "lease-database": {"name": "/var/lib/kea/kea-leases4.csv"},
                "subnet4": [],
            }}
        if command == "config-set":
            set_calls.append(args)
            state["interfaces"] = (args["Dhcp4"]["interfaces-config"]
                                    ["interfaces"])
            return {}
        if command == "config-write":
            return {}
        if command == "lease4-get-all":
            return {"leases": []}
        raise AssertionError(command)

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", rpc)
    monkeypatch.setattr(dhcp_manager.os.path, "exists", lambda path: True)

    result = mgr.diagnostics()

    assert set_calls, "expected config-set to be called to fix interfaces"
    assert set_calls[0]["Dhcp4"]["interfaces-config"]["interfaces"] == ["*"]
    assert restarted == ["kea-dhcp4-server"]
    assert result["self_healed"] == [
        "set interfaces-config to listen on all interfaces "
        "(was empty) and restarted kea-dhcp4-server"]
    # the healed config is what the SECOND config-get (post self-heal) sees
    assert result["interfaces_configured"] == ["*"]


def test_dhcp_diagnostics_does_not_touch_interfaces_when_already_set(monkeypatch):
    mgr = dhcp_manager.KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    def run(cmd, timeout=5):
        if cmd[0] == "ss":
            return _result(output="udp UNCONN 0 0 10.0.0.5:67 0.0.0.0:*")
        return _result(output="configuration check successful")

    def rpc(service, command, args=None):
        if command == "version-get":
            return {"version": "2.4.1"}
        if command == "config-get":
            return {"Dhcp4": {
                "interfaces-config": {"interfaces": ["eth0"]},
                "lease-database": {"name": "/var/lib/kea/kea-leases4.csv"},
                "subnet4": [],
            }}
        if command == "config-set":
            raise AssertionError("config-set must not be called")
        if command == "lease4-get-all":
            return {"leases": []}
        raise AssertionError(command)

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", rpc)
    monkeypatch.setattr(dhcp_manager.os.path, "exists", lambda path: True)

    result = mgr.diagnostics()
    assert result["self_healed"] == []


def test_dhcp_diagnostics_self_heals_blank_placeholder_interfaces_entry(
        monkeypatch):
    """Regression test: Kea's ``config-get`` has been observed to echo an
    unset ``interfaces`` list back as ``[""]`` (a single blank placeholder
    entry) rather than a truly empty ``[]``. A plain truthiness check on that
    list is fooled — ``[""]`` is a non-empty Python list — so the self-heal
    would silently skip a node that is still listening on nothing. The fix
    filters blank/whitespace-only entries before deciding, matching the same
    stricter filtering diagnostics() already applies to interfaces_configured."""
    mgr = dhcp_manager.KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    restarted = []

    def run(cmd, timeout=5):
        if cmd[0] == "systemctl" and cmd[1] == "restart":
            restarted.append(cmd[2])
            return _result(output="")
        if cmd[0] == "ss":
            return _result(output="udp UNCONN 0 0 10.0.0.5:67 0.0.0.0:*")
        return _result(output="configuration check successful")

    state = {"interfaces": [""]}
    set_calls = []

    def rpc(service, command, args=None):
        if command == "version-get":
            return {"version": "2.4.1"}
        if command == "config-get":
            return {"Dhcp4": {
                "interfaces-config": {"interfaces": state["interfaces"]},
                "lease-database": {"name": "/var/lib/kea/kea-leases4.csv"},
                "subnet4": [],
            }}
        if command == "config-set":
            set_calls.append(args)
            state["interfaces"] = (args["Dhcp4"]["interfaces-config"]
                                    ["interfaces"])
            return {}
        if command == "config-write":
            return {}
        if command == "lease4-get-all":
            return {"leases": []}
        raise AssertionError(command)

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", rpc)
    monkeypatch.setattr(dhcp_manager.os.path, "exists", lambda path: True)

    result = mgr.diagnostics()

    assert set_calls, ("expected config-set to be called — a blank "
                        "placeholder entry must not be treated as configured")
    assert set_calls[0]["Dhcp4"]["interfaces-config"]["interfaces"] == ["*"]
    assert restarted == ["kea-dhcp4-server"]
    assert result["interfaces_configured"] == ["*"]
