"""Service-level diagnostics for the embedded Unbound and Kea role managers."""

import importlib.util
from pathlib import Path


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


def test_dns_add_forwarder_persists_config_and_reloads(monkeypatch, tmp_path):
    mgr = dns_manager.UnboundManager(str(tmp_path / "records.conf"))
    monkeypatch.setattr(mgr, "list_forwarders",
                        lambda: {"status": "SUCCESS", "forwarders": []})
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": True, "error": ""})

    result = mgr.add_forwarder(".", ["1.1.1.1", "2606:4700:4700::1111"])

    assert result["status"] == "SUCCESS"
    text = (tmp_path / "lm-forwarders.conf").read_text()
    assert 'name: "."' in text
    assert "forward-addr: 1.1.1.1" in text
    assert "forward-addr: 2606:4700:4700::1111" in text


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
