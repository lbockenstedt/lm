"""Kea hook-library load-failure diagnostics and self-heal repair, on the
DHCP worker side (``dhcp/src/dhcp_worker.py``).

Covers the recurring production symptom: a Kea HA apply fails at the "apply"
stage with "One or more hook libraries failed to load" for EVERY hook
library, which a same-version ``apt-get --reinstall kea-common`` cannot fix
when the real cause is a version/ABI mismatch between kea-common and
kea-dhcp4-server.
"""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
DHCP_SRC = ROOT / "dhcp" / "src"


def _load_dhcp_worker():
    # dhcp_worker.py does `from kea_manager import KeaManager` /
    # `from kea_ha import ...` (bare, sibling-module imports), so dhcp/src
    # must be importable on sys.path before exec'ing it, same as the worker
    # does in production (it runs FROM that directory).
    if str(DHCP_SRC) not in sys.path:
        sys.path.insert(0, str(DHCP_SRC))
    spec = importlib.util.spec_from_file_location(
        "lm_dhcp_worker_hooktest", DHCP_SRC / "dhcp_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dhcp_worker = _load_dhcp_worker()


def _proc(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_installed_package_versions_reads_dpkg_query(monkeypatch):
    monkeypatch.setattr(dhcp_worker.shutil, "which", lambda name: "/usr/bin/dpkg-query")

    def run(cmd, **kwargs):
        pkg = cmd[-1]
        versions = {"kea-common": "2.6.1-1", "kea-dhcp4-server": "2.6.1-1",
                    "kea-ctrl-agent": "2.6.1-1"}
        return _proc(stdout=versions.get(pkg, ""))

    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)
    versions = dhcp_worker.DhcpWorkerOps._installed_package_versions()
    assert versions == {"kea-common": "2.6.1-1", "kea-dhcp4-server": "2.6.1-1",
                        "kea-ctrl-agent": "2.6.1-1"}


def test_installed_package_versions_empty_without_dpkg_query(monkeypatch):
    monkeypatch.setattr(dhcp_worker.shutil, "which", lambda name: None)
    assert dhcp_worker.DhcpWorkerOps._installed_package_versions() == {}


def test_repair_hook_libraries_realigns_mismatched_packages(monkeypatch, tmp_path):
    # kea-common and kea-dhcp4-server report DIFFERENT versions — the repair
    # must run `apt-get update` + install BOTH packages together (not a
    # same-version --reinstall of kea-common alone), since that is the only
    # way apt can actually change kea-common's version to match the daemon.
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir()
    (hook_dir / "libdhcp_ha.so").write_bytes(b"\x7fELF")
    (hook_dir / "libdhcp_lease_cmds.so").write_bytes(b"\x7fELF")

    monkeypatch.setattr(dhcp_worker.shutil, "which",
                         lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(dhcp_worker, "resolve_hook_dir", lambda hd: str(hook_dir))
    monkeypatch.setattr(dhcp_worker, "hook_paths", lambda hd: {
        "ha": str(hook_dir / "libdhcp_ha.so"),
        "lease_cmds": str(hook_dir / "libdhcp_lease_cmds.so")})
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_ldd_missing_deps",
                         staticmethod(lambda so_path: ""))

    call_log = []

    def fake_versions():
        return {"kea-common": "2.6.1-1", "kea-dhcp4-server": "2.6.2-1"}
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_installed_package_versions",
                         staticmethod(fake_versions))

    def run(cmd, **kwargs):
        call_log.append(cmd)
        return _proc()
    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)

    ok = dhcp_worker.DhcpWorkerOps._repair_hook_libraries(str(hook_dir))

    assert ok is True
    assert any(cmd[:2] == ["apt-get", "update"] for cmd in call_log), call_log
    assert any(
        cmd[:3] == ["apt-get", "install", "-y"] and
        "kea-common" in cmd and "kea-dhcp4-server" in cmd
        for cmd in call_log
    ), call_log
    # Must NOT take the plain same-version --reinstall path when mismatched.
    assert not any("--reinstall" in cmd for cmd in call_log)


def test_repair_hook_libraries_reinstalls_when_versions_already_match(monkeypatch, tmp_path):
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir()
    (hook_dir / "libdhcp_ha.so").write_bytes(b"\x7fELF")
    (hook_dir / "libdhcp_lease_cmds.so").write_bytes(b"\x7fELF")

    monkeypatch.setattr(dhcp_worker.shutil, "which",
                         lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(dhcp_worker, "resolve_hook_dir", lambda hd: str(hook_dir))
    monkeypatch.setattr(dhcp_worker, "hook_paths", lambda hd: {
        "ha": str(hook_dir / "libdhcp_ha.so"),
        "lease_cmds": str(hook_dir / "libdhcp_lease_cmds.so")})
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_ldd_missing_deps",
                         staticmethod(lambda so_path: ""))
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_installed_package_versions",
                         staticmethod(lambda: {"kea-common": "2.6.1-1",
                                               "kea-dhcp4-server": "2.6.1-1"}))

    call_log = []

    def run(cmd, **kwargs):
        call_log.append(cmd)
        return _proc()
    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)

    ok = dhcp_worker.DhcpWorkerOps._repair_hook_libraries(str(hook_dir))

    assert ok is True
    assert any("--reinstall" in cmd for cmd in call_log)
    assert not any(cmd[:2] == ["apt-get", "update"] for cmd in call_log)


def test_repair_hook_libraries_fails_when_dependency_still_unresolved(monkeypatch, tmp_path):
    # Files exist post-reinstall but ldd still reports a missing shared-lib
    # dependency — the repair must NOT be reported as successful (this is
    # exactly the gap that let the retry silently do nothing useful before).
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir()
    (hook_dir / "libdhcp_ha.so").write_bytes(b"\x7fELF")
    (hook_dir / "libdhcp_lease_cmds.so").write_bytes(b"\x7fELF")

    monkeypatch.setattr(dhcp_worker.shutil, "which",
                         lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(dhcp_worker, "resolve_hook_dir", lambda hd: str(hook_dir))
    monkeypatch.setattr(dhcp_worker, "hook_paths", lambda hd: {
        "ha": str(hook_dir / "libdhcp_ha.so"),
        "lease_cmds": str(hook_dir / "libdhcp_lease_cmds.so")})
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_installed_package_versions",
                         staticmethod(lambda: {"kea-common": "2.6.1-1",
                                               "kea-dhcp4-server": "2.6.1-1"}))
    monkeypatch.setattr(dhcp_worker.subprocess, "run", lambda cmd, **kw: _proc())
    monkeypatch.setattr(
        dhcp_worker.DhcpWorkerOps, "_ldd_missing_deps",
        staticmethod(lambda so_path: "libkea-cryptolink.so.28 => not found"))

    ok = dhcp_worker.DhcpWorkerOps._repair_hook_libraries(str(hook_dir))
    assert ok is False


def test_ldd_missing_deps_reports_not_found_libraries(monkeypatch, tmp_path):
    so_path = tmp_path / "libdhcp_ha.so"
    so_path.write_bytes(b"\x7fELF")
    monkeypatch.setattr(dhcp_worker.shutil, "which", lambda name: "/usr/bin/ldd")
    ldd_output = (
        "\tlinux-vdso.so.1 (0x00007ffe)\n"
        "\tlibkea-cryptolink.so.28 => not found\n"
        "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0)\n"
    )
    monkeypatch.setattr(dhcp_worker.subprocess, "run",
                         lambda cmd, **kw: _proc(stdout=ldd_output))
    result = dhcp_worker.DhcpWorkerOps._ldd_missing_deps(str(so_path))
    assert "libkea-cryptolink.so.28 => not found" in result


def test_ldd_missing_deps_empty_when_all_resolve(monkeypatch, tmp_path):
    so_path = tmp_path / "libdhcp_ha.so"
    so_path.write_bytes(b"\x7fELF")
    monkeypatch.setattr(dhcp_worker.shutil, "which", lambda name: "/usr/bin/ldd")
    monkeypatch.setattr(
        dhcp_worker.subprocess, "run",
        lambda cmd, **kw: _proc(stdout="\tlibc.so.6 => /lib/libc.so.6 (0x1)\n"))
    assert dhcp_worker.DhcpWorkerOps._ldd_missing_deps(str(so_path)) == ""


def test_ldd_missing_deps_empty_when_file_absent(tmp_path):
    assert dhcp_worker.DhcpWorkerOps._ldd_missing_deps(
        str(tmp_path / "nope.so")) == ""


def test_hook_load_failure_detail_includes_package_versions_and_ldd(monkeypatch, tmp_path):
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir()
    (hook_dir / "libdhcp_ha.so").write_bytes(b"\x7fELF")

    monkeypatch.setattr(dhcp_worker, "resolve_hook_dir", lambda hd: str(hook_dir))
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_installed_package_versions",
                         staticmethod(lambda: {"kea-common": "2.6.1-1",
                                               "kea-dhcp4-server": "2.6.2-1"}))
    monkeypatch.setattr(
        dhcp_worker.DhcpWorkerOps, "_ldd_missing_deps",
        staticmethod(lambda so_path: "libkea-cryptolink.so.28 => not found"))
    monkeypatch.setattr(
        dhcp_worker.subprocess, "run",
        lambda cmd, **kw: _proc(stdout="") if cmd[0] == "journalctl" else _proc())

    detail = dhcp_worker.DhcpWorkerOps._hook_load_failure_detail(
        "One or more hook libraries failed to load", str(hook_dir))

    assert "kea-common=2.6.1-1" in detail
    assert "kea-dhcp4-server=2.6.2-1" in detail
    assert "libkea-cryptolink.so.28 => not found" in detail


def test_hook_load_failure_detail_passthrough_for_unrelated_error(monkeypatch):
    # Non hook-related errors must be returned unchanged (no wasted apt/ldd
    # calls for every unrelated config-set rejection).
    detail = dhcp_worker.DhcpWorkerOps._hook_load_failure_detail(
        "some other config-set error", "/usr/lib/x86_64-linux-gnu/kea/hooks")
    assert detail == "some other config-set error"


def test_repair_ha_tls_permissions_chgrp_and_chmod(monkeypatch, tmp_path):
    ha_dir = tmp_path / "ha-tls"
    ha_dir.mkdir()
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_HA_TLS_DIR", str(ha_dir))
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return _proc(returncode=0)

    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)
    assert dhcp_worker.DhcpWorkerOps._repair_ha_tls_permissions() is True
    assert any(c[:2] == ["chgrp", "-R"] for c in calls)
    assert any(c[0] == "chmod" for c in calls)


def test_repair_ha_tls_permissions_false_when_dir_missing(tmp_path):
    missing = tmp_path / "does-not-exist"
    import unittest.mock as mock
    with mock.patch.object(dhcp_worker.DhcpWorkerOps, "_HA_TLS_DIR", str(missing)):
        assert dhcp_worker.DhcpWorkerOps._repair_ha_tls_permissions() is False


def test_repair_ha_tls_permissions_false_on_subprocess_error(monkeypatch, tmp_path):
    ha_dir = tmp_path / "ha-tls"
    ha_dir.mkdir()
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_HA_TLS_DIR", str(ha_dir))

    def run(cmd, **kwargs):
        raise OSError("permission denied running chgrp")

    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)
    assert dhcp_worker.DhcpWorkerOps._repair_ha_tls_permissions() is False


def test_ha_tls_permission_issue_detects_unreadable_dir(monkeypatch, tmp_path):
    # Reproduces the actual production root cause: /etc/kea/ha-tls created
    # root:root 0750 before the kea-common package (and its _kea user) ever
    # existed, so the daemon can never enter it — libdhcp_ha.so's load()
    # then fails reading the HA trust anchor with EACCES, which Kea only
    # ever surfaces as the generic "hook libraries failed to load".
    ha_dir = tmp_path / "ha-tls"
    ha_dir.mkdir(mode=0o750)
    import os as _os
    _os.chmod(str(ha_dir), 0o750)  # root:root-equivalent in this test's uid/gid
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_HA_TLS_DIR", str(ha_dir))

    class FakeGrp:
        @staticmethod
        def getgrnam(name):
            # A gid that will never match this dir's real gid in the test
            # environment, simulating "_kea can't read this directory".
            return SimpleNamespace(gr_gid=999999)

    monkeypatch.setitem(sys.modules, "grp", FakeGrp())
    issue = dhcp_worker.DhcpWorkerOps._ha_tls_permission_issue()
    assert "not readable by the _kea user" in issue


def test_ha_tls_permission_issue_empty_when_dir_absent(tmp_path):
    missing = tmp_path / "does-not-exist"
    import unittest.mock as mock
    with mock.patch.object(dhcp_worker.DhcpWorkerOps, "_HA_TLS_DIR", str(missing)):
        assert dhcp_worker.DhcpWorkerOps._ha_tls_permission_issue() == ""


def test_hook_load_failure_detail_prefers_error_line_over_benign_close(monkeypatch, tmp_path):
    # The real production log for this failure has an ERROR
    # (HA_CONFIGURATION_FAILED ... Permission denied) line followed by benign
    # "successfully closed" cleanup lines — picking the LAST hook-related
    # line (as this used to) surfaced the useless cleanup message instead of
    # the actual cause.
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir()
    monkeypatch.setattr(dhcp_worker, "resolve_hook_dir", lambda hd: str(hook_dir))
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_installed_package_versions",
                         staticmethod(lambda: {}))
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_ldd_missing_deps",
                         staticmethod(lambda so_path: ""))
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_ha_tls_permission_issue",
                         staticmethod(lambda: ""))
    journal = "\n".join([
        "kea-dhcp4[1]: ERROR HA_CONFIGURATION_FAILED failed to configure High "
        "Availability hooks library: bad TLS config: load of CA file "
        "'/etc/kea/ha-tls/ha-ca.pem' failed: Permission denied",
        "kea-dhcp4[1]: INFO  HOOKS_LIBRARY_CLOSED hooks library "
        "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so successfully closed",
    ])
    monkeypatch.setattr(
        dhcp_worker.subprocess, "run",
        lambda cmd, **kw: _proc(stdout=journal) if cmd[0] == "journalctl" else _proc())

    detail = dhcp_worker.DhcpWorkerOps._hook_load_failure_detail(
        "One or more hook libraries failed to load", str(hook_dir))

    assert "HA_CONFIGURATION_FAILED" in detail
    assert "Permission denied" in detail


def test_repair_kea_conf_permissions_chgrp_and_chmod(monkeypatch, tmp_path):
    conf = tmp_path / "kea-dhcp4.conf"
    conf.write_text("{}")
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_KEA_DHCP4_CONF", str(conf))
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return _proc(returncode=0)

    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)
    assert dhcp_worker.DhcpWorkerOps._repair_kea_conf_permissions() is True
    assert ["chgrp", "_kea", str(conf)] in calls
    assert ["chmod", "0660", str(conf)] in calls


def test_repair_kea_conf_permissions_false_when_file_missing(tmp_path):
    missing = tmp_path / "does-not-exist.conf"
    import unittest.mock as mock
    with mock.patch.object(dhcp_worker.DhcpWorkerOps, "_KEA_DHCP4_CONF", str(missing)):
        assert dhcp_worker.DhcpWorkerOps._repair_kea_conf_permissions() is False


def test_repair_kea_conf_permissions_false_on_subprocess_error(monkeypatch, tmp_path):
    conf = tmp_path / "kea-dhcp4.conf"
    conf.write_text("{}")
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_KEA_DHCP4_CONF", str(conf))

    def run(cmd, **kwargs):
        raise OSError("permission denied running chgrp")

    monkeypatch.setattr(dhcp_worker.subprocess, "run", run)
    assert dhcp_worker.DhcpWorkerOps._repair_kea_conf_permissions() is False


class _FakeMgrConfWrite:
    """Minimal KeaManager stand-in for apply()'s config-write self-heal path.

    ``apply_config`` scripts a fixed sequence of (set, written, error) outcomes
    (config-set always succeeds here; config-write fails with the permission
    message on the first call). ``write_config`` scripts the standalone retry
    used by the self-heal."""
    def __init__(self, write_config_result):
        self.get_config_calls = 0
        self._write_config_result = write_config_result
        self.write_config_calls = 0

    def get_config(self):
        self.get_config_calls += 1
        return {}

    def apply_config(self, cfg):
        return {"set": True, "written": False,
                "error": "Error during config-write: Unable to open file "
                        "/etc/kea/kea-dhcp4.conf for writing"}

    def write_config(self):
        self.write_config_calls += 1
        return self._write_config_result


def test_apply_self_heals_config_write_permission_and_succeeds(monkeypatch):
    worker = dhcp_worker.DhcpWorkerOps.__new__(dhcp_worker.DhcpWorkerOps)
    worker.mgr = _FakeMgrConfWrite({"written": True, "error": ""})
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_repair_kea_conf_permissions",
                        staticmethod(lambda: True))
    out = worker.apply({"config": {"subnet4": []}, "version": 7})
    assert out["status"] == "SUCCESS"
    assert out["self_healed"] == ["fixed /etc/kea/kea-dhcp4.conf permissions"]
    assert worker.mgr.write_config_calls == 1


def test_apply_falls_through_to_restore_when_conf_repair_fails(monkeypatch):
    worker = dhcp_worker.DhcpWorkerOps.__new__(dhcp_worker.DhcpWorkerOps)
    worker.mgr = _FakeMgrConfWrite({"written": False, "error": "still broken"})
    monkeypatch.setattr(dhcp_worker.DhcpWorkerOps, "_repair_kea_conf_permissions",
                        staticmethod(lambda: False))
    out = worker.apply({"config": {"subnet4": []}, "version": 7})
    # Repair not attempted (returns False immediately) -> falls through to the
    # existing restore-and-report path, still reporting an error/partial verdict.
    assert out["status"] in ("ERROR", "PARTIAL")
    assert worker.mgr.write_config_calls == 0
