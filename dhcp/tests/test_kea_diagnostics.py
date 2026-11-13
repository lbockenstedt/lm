from types import SimpleNamespace

import kea_manager
from kea_manager import KeaManager


def _result(ok=True, output="", error=""):
    return {"ok": ok, "exit_code": 0 if ok else 1,
            "output": output, "error": error}


def test_diagnostics_reports_service_interface_listener_and_leases(monkeypatch):
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    def run(cmd, timeout=5, limit=4000):
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
    monkeypatch.setattr(kea_manager.os.path, "exists", lambda path: True)

    result = mgr.diagnostics()
    assert result["healthy"] is True
    assert result["interfaces_configured"] == ["eth0"]
    assert result["lease_db"]["leases"] == 1
    assert result["listeners"]["dhcp4"]


def test_diagnostics_is_unhealthy_when_config_retrieval_fails(monkeypatch):
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })
    monkeypatch.setattr(mgr, "_run_diag", lambda cmd, timeout=5, limit=4000: _result(
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
# ── control-socket ownership self-heal ───────────────────────────────────────
#
# Kea's runtime directory is shared BY NAME (/run/kea). Anything else starting
# a Kea as root -- a co-located "-sim" stack, say -- creates it first as
# root:root 0750, and the packaged units, which run as _kea, can then not even
# traverse their own runtime dir. Every hub config-get/config-set comes back
# "unable to forward command to the dhcp4 service: Permission denied. The
# server is likely to be offline", so the whole cluster silently contributes no
# subnets, no reservations and no leases.
#
# _heal_inactive_units() is blind to it: BOTH units stay perfectly *active* --
# they are running, just locked out of their own socket. Seen in production on
# a cluster that looked healthy in systemd for a day.

def _own_env(monkeypatch, uids, restart_ok=True, after=None):
    """Build a KeaManager whose runtime dir/socket have the given owners.

    ``uids`` maps path -> uid before the restart, ``after`` (optional) maps
    path -> uid once a restart has happened.
    """
    mgr = kea_manager.KeaManager()
    monkeypatch.setattr(mgr, "_config_ctrl_socket_path",
                        lambda: "/run/kea/kea4-ctrl-socket")
    monkeypatch.setattr(kea_manager.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=996))
    state = {"restarted": []}

    def fake_stat(path):
        table = after if (state["restarted"] and after is not None) else uids
        if path not in table:
            raise OSError("no such path")
        return SimpleNamespace(st_uid=table[path])

    monkeypatch.setattr(kea_manager.os, "stat", fake_stat)

    def run(cmd, timeout=5):
        if cmd[:2] == ["systemctl", "restart"]:
            if restart_ok:
                state["restarted"].append(cmd[2])
                return _result()
            return _result(ok=False, error="job failed")
        return _result(output="active")

    monkeypatch.setattr(mgr, "_run_diag", run)
    return mgr, state


def test_root_owned_runtime_dir_is_healed_even_though_units_are_active(monkeypatch):
    wrong = {"/run/kea": 0, "/run/kea/kea4-ctrl-socket": 0}
    right = {"/run/kea": 996, "/run/kea/kea4-ctrl-socket": 996}
    mgr, state = _own_env(monkeypatch, wrong, after=right)

    actions = mgr._heal_control_socket_ownership()

    # systemd re-creates and re-chowns RuntimeDirectory= on start, so a plain
    # restart is a complete, data-safe repair.
    assert state["restarted"] == ["kea-dhcp4-server", "kea-ctrl-agent"]
    assert actions and "not owned by _kea" in actions[0]


def test_dhcp4_is_restarted_before_the_control_agent(monkeypatch):
    wrong = {"/run/kea": 0, "/run/kea/kea4-ctrl-socket": 0}
    right = {"/run/kea": 996, "/run/kea/kea4-ctrl-socket": 996}
    mgr, state = _own_env(monkeypatch, wrong, after=right)

    mgr._heal_control_socket_ownership()

    # dhcp4 owns the socket the CA connects to; restarting the CA first only
    # has it reconnect to the stale, still-misowned socket.
    assert state["restarted"].index("kea-dhcp4-server") < \
        state["restarted"].index("kea-ctrl-agent")


def test_correctly_owned_runtime_dir_is_left_alone(monkeypatch):
    right = {"/run/kea": 996, "/run/kea/kea4-ctrl-socket": 996}
    mgr, state = _own_env(monkeypatch, right)

    assert mgr._heal_control_socket_ownership() == []
    assert state["restarted"] == []


def test_a_re_clobbered_directory_is_reported_not_claimed_as_fixed(monkeypatch):
    """The root-owned process that took the directory may still be running and
    re-creating it — that needs an operator, so it must not read as repaired."""
    wrong = {"/run/kea": 0, "/run/kea/kea4-ctrl-socket": 0}
    mgr, state = _own_env(monkeypatch, wrong, after=wrong)

    actions = mgr._heal_control_socket_ownership()

    assert state["restarted"] == ["kea-dhcp4-server", "kea-ctrl-agent"]
    assert any("still not" in a and "root" in a for a in actions)


def test_a_failed_restart_is_surfaced(monkeypatch):
    wrong = {"/run/kea": 0, "/run/kea/kea4-ctrl-socket": 0}
    mgr, _ = _own_env(monkeypatch, wrong, restart_ok=False)

    actions = mgr._heal_control_socket_ownership()

    assert any("failed to restart kea-dhcp4-server" in a for a in actions)


def test_missing_kea_user_is_a_noop_not_a_crash(monkeypatch):
    wrong = {"/run/kea": 0, "/run/kea/kea4-ctrl-socket": 0}
    mgr, state = _own_env(monkeypatch, wrong)

    def boom(name):
        raise KeyError(name)

    monkeypatch.setattr(kea_manager.pwd, "getpwnam", boom)

    assert mgr._heal_control_socket_ownership() == []
    assert state["restarted"] == []


def test_absent_runtime_dir_is_left_to_the_inactive_unit_heal(monkeypatch):
    mgr, state = _own_env(monkeypatch, {})

    assert mgr._heal_control_socket_ownership() == []
    assert state["restarted"] == []


def test_socket_path_is_read_from_disk_not_through_the_broken_socket(monkeypatch,
                                                                    tmp_path):
    """Reading it via get_config() would mean an RPC through the very socket
    this check exists to validate — i.e. it fails exactly when it matters."""
    mgr = kea_manager.KeaManager()
    conf = tmp_path / "kea-dhcp4.conf"
    conf.write_text('{"Dhcp4": {"control-socket": '
                    '{"socket-name": "/run/kea-alt/sock"}}}')
    real_open = open

    def fake_open(path, *a, **k):
        if path == "/etc/kea/kea-dhcp4.conf":
            return real_open(str(conf), *a, **k)
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)

    def explode(*a, **k):
        raise AssertionError("must not talk to the control agent")

    monkeypatch.setattr(mgr, "get_config", explode)

    assert mgr._config_ctrl_socket_path() == "/run/kea-alt/sock"


def test_unreadable_config_falls_back_to_the_packaged_socket_path(monkeypatch):
    mgr = kea_manager.KeaManager()

    def boom(path, *a, **k):
        raise OSError("nope")

    monkeypatch.setattr("builtins.open", boom)

    assert mgr._config_ctrl_socket_path() == "/run/kea/kea4-ctrl-socket"


def test_self_heal_runs_the_ownership_check(monkeypatch):
    mgr = kea_manager.KeaManager()
    monkeypatch.setattr(mgr, "_heal_api_password_file", lambda: [])
    monkeypatch.setattr(mgr, "_heal_inactive_units", lambda: [])
    monkeypatch.setattr(mgr, "_heal_missing_interfaces", lambda: [])
    monkeypatch.setattr(mgr, "_heal_control_socket_ownership",
                        lambda: ["ownership repair"])

    assert "ownership repair" in mgr._self_heal()


def test_an_exploding_ownership_check_never_breaks_diagnostics(monkeypatch):
    mgr = kea_manager.KeaManager()
    monkeypatch.setattr(mgr, "_heal_api_password_file", lambda: [])
    monkeypatch.setattr(mgr, "_heal_inactive_units", lambda: [])
    monkeypatch.setattr(mgr, "_heal_missing_interfaces", lambda: [])

    def boom():
        raise RuntimeError("stat blew up")

    monkeypatch.setattr(mgr, "_heal_control_socket_ownership", boom)

    assert mgr._self_heal() == []


def test_recent_warnings_tail_the_journal_and_filter_here(monkeypatch):
    """journalctl -p warning scans the whole journal (seconds on a big one), so
    the warnings are taken from a plain tail and filtered on Kea's severity."""
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })
    calls = []

    def run(cmd, timeout=5, limit=4000):
        calls.append(cmd)
        if cmd[0] == "journalctl" and "kea-dhcp4-server" in cmd:
            return _result(output=(
                "2026-11-12T10:00:00 kea kea-dhcp4[1]: INFO  [kea-dhcp4.dhcp4] DHCP4_STARTED\n"
                "2026-11-12T10:00:01 kea kea-dhcp4[1]: WARN  [kea-dhcp4.dhcpsrv] DHCPSRV_NO_SOCKETS_OPEN\n"
                "2026-11-12T10:00:02 kea systemd[1]: kea-ctrl-agent.service: Failed with result 'exit-code'."))
        return _result(output="configuration check successful")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: {})
    result = mgr.diagnostics()
    journal = next(c for c in calls if c[0] == "journalctl" and "kea-dhcp4-server" in c)
    assert "-p" not in journal and "--since" not in journal
    assert [line.split(": ", 1)[1][:12] for line in result["last_errors"]] == [
        "WARN  [kea-d", "kea-ctrl-age"]


def test_a_failed_journal_query_is_not_reported_as_a_kea_warning(monkeypatch):
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    def run(cmd, timeout=5, limit=4000):
        if cmd[0] == "journalctl" and "kea-dhcp4-server" in cmd:
            return _result(ok=False, output="Failed to open journal: Permission denied",
                           error="Failed to open journal: Permission denied")
        return _result(output="configuration check successful")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: {})
    result = mgr.diagnostics()
    assert result["last_errors"] == []
    assert result["journal_error"] == "Failed to open journal: Permission denied"


def test_a_long_journal_keeps_its_newest_warning(monkeypatch):
    """journalctl prints oldest first; trimming the output must not drop the newest lines."""
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })
    old = "2026-11-12T10:00:00 kea kea-dhcp4[1]: INFO  [kea-dhcp4.packets] " + "x" * 250
    newest = "2026-11-12T11:00:00 kea kea-dhcp4[1]: WARN  [kea-dhcp4.dhcpsrv] NEWEST"

    def run(cmd, timeout=5, limit=4000):
        if cmd[0] == "journalctl" and "kea-dhcp4-server" in cmd:
            return _result(output="\n".join([old] * 299 + [newest])[:limit])
        return _result(output="configuration check successful")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: {})
    assert mgr.diagnostics()["last_errors"][-1].endswith("NEWEST")


def test_a_failed_control_agent_journal_is_not_shown_as_its_log(monkeypatch):
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "failed" if unit == "kea-ctrl-agent" else "active",
        "SubState": "failed", "NRestarts": "0", "ExecMainStatus": "1", "error": "",
    })

    def run(cmd, timeout=5, limit=4000):
        if cmd[0] == "journalctl":
            return _result(ok=False, output="Failed to open journal: Permission denied",
                           error="Failed to open journal: Permission denied")
        return _result(output="configuration check successful")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: {})
    result = mgr.diagnostics()
    assert not [r for r in result["recommendations"] if "recent log" in r]
    assert result["ca_recent_errors"] == []
    assert result["journal_error"] == "Failed to open journal: Permission denied"
    assert result["ca_journal_error"] == "Failed to open journal: Permission denied"


def test_a_failed_control_agent_tail_does_not_mark_the_kea_journal_unavailable(monkeypatch):
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_unit_status", lambda unit: {
        "ActiveState": "active", "SubState": "running",
        "NRestarts": "0", "ExecMainStatus": "0", "error": "",
    })

    def run(cmd, timeout=5, limit=4000):
        # Only the control-agent-only tail (no kea-dhcp4-server unit) fails.
        if cmd[0] == "journalctl" and "kea-dhcp4-server" not in cmd:
            return _result(ok=False, output="Failed to open journal: Permission denied",
                           error="Failed to open journal: Permission denied")
        return _result(output="configuration check successful")

    monkeypatch.setattr(mgr, "_run_diag", run)
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: {})
    result = mgr.diagnostics()
    assert result["journal_error"] == ""
    assert result["ca_journal_error"] == "Failed to open journal: Permission denied"
