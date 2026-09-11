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
