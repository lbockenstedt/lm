"""Fleet OS-package updates: eligibility, parsing, and the safety guarantees."""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import os_update  # noqa: E402


# ── eligibility: appliances must NEVER be apt-managed ────────────────────────
def test_truenas_is_refused_even_though_it_has_apt(monkeypatch):
    # TrueNAS SCALE is Debian underneath and DOES ship apt — an apt-first probe
    # would call it eligible and then break its own updater. Appliance markers
    # must be checked first.
    monkeypatch.setattr(os_update.os.path, "exists",
                        lambda p: p in ("/usr/bin/midclt",))
    monkeypatch.setattr(os_update.shutil, "which", lambda b: "/usr/bin/" + b)
    cap = os_update.detect_capability()
    assert cap["eligible"] is False and cap["flavor"] == "truenas"
    assert "appliance" in cap["reason"].lower()


def test_opnsense_is_refused(monkeypatch):
    monkeypatch.setattr(os_update.os.path, "exists",
                        lambda p: p == "/usr/local/sbin/opnsense-version")
    monkeypatch.setattr(os_update.shutil, "which", lambda b: None)
    assert os_update.detect_capability()["flavor"] == "opnsense"


def test_non_debian_host_is_refused(monkeypatch):
    monkeypatch.setattr(os_update.os.path, "exists", lambda p: False)
    monkeypatch.setattr(os_update.shutil, "which", lambda b: None)
    cap = os_update.detect_capability()
    assert cap["eligible"] is False and "apt-get" in cap["reason"]


def test_proxmox_and_plain_debian_are_eligible(monkeypatch):
    monkeypatch.setattr(os_update.os.path, "exists", lambda p: False)
    monkeypatch.setattr(os_update.shutil, "which", lambda b: "/usr/sbin/" + b)
    assert os_update.detect_capability() == {
        "eligible": True, "manager": "apt", "flavor": "proxmox", "reason": ""}
    monkeypatch.setattr(os_update.shutil, "which",
                        lambda b: None if b == "pveversion" else "/usr/bin/" + b)
    assert os_update.detect_capability()["flavor"] == "debian"


def test_apply_refuses_on_an_ineligible_node(monkeypatch):
    # The critical guarantee: apply must REFUSE, never improvise, on an appliance.
    monkeypatch.setattr(os_update, "detect_capability",
                        lambda: {"eligible": False, "manager": None,
                                 "flavor": "truenas", "reason": "appliance-managed"})
    called = []
    monkeypatch.setattr(os_update, "_run", lambda *a, **k: called.append(a))
    r = os_update.apply_updates()
    assert r["status"] == "ERROR" and r["eligible"] is False
    assert not called, "must not shell out on an ineligible node"


# ── parsing ──────────────────────────────────────────────────────────────────
def test_parses_and_flags_security():
    out = os_update._parse_upgradable(
        "Listing...\n"
        "libssl3/bookworm-security 3.0.14 amd64 [upgradable from: 3.0.13]\n"
        "pve-manager/stable 8.2.4 all [upgradable from: 8.2.2]\n")
    assert [p["package"] for p in out] == ["libssl3", "pve-manager"]
    assert out[0]["security"] is True and out[1]["security"] is False
    assert out[0]["current"] == "3.0.13" and out[0]["candidate"] == "3.0.14"


def test_malformed_lines_are_skipped_not_guessed():
    # A half-parsed package name in an approval UI is worse than a missing row.
    out = os_update._parse_upgradable(
        "Listing...\ngarbage\n\nnoslash 1.0\nok/stable 2.0 amd64 [upgradable from: 1.0]\n")
    assert [p["package"] for p in out] == ["ok"]


def test_empty_input():
    assert os_update._parse_upgradable("") == []
    assert os_update._parse_upgradable(None) == []


# ── no auto-reboot, ever ─────────────────────────────────────────────────────
def test_apply_never_invokes_reboot(monkeypatch):
    monkeypatch.setattr(os_update, "_is_root", lambda: True)
    monkeypatch.setattr(os_update, "detect_capability",
                        lambda: {"eligible": True, "manager": "apt",
                                 "flavor": "proxmox", "reason": ""})
    monkeypatch.setattr(os_update, "check_updates",
                        lambda refresh=True: {"count": 3})
    seen = []

    class _R:
        returncode = 0
        stdout = "done"
        stderr = ""

    def _fake(argv, timeout):
        seen.append(argv)
        return _R()
    monkeypatch.setattr(os_update, "_run", _fake)
    monkeypatch.setattr(os_update, "_reboot_required", lambda: True)
    r = os_update.apply_updates()
    assert r["status"] == "SUCCESS"
    assert r["reboot_required"] is True, "must REPORT the need"
    flat = " ".join(" ".join(a) for a in seen)
    assert "reboot" not in flat and "shutdown" not in flat, \
        "must never reboot the node itself"
    assert "dist-upgrade" in flat


def test_apply_uses_noninteractive_options(monkeypatch):
    # Without these a changed conffile prompts on stdin and hangs mid-upgrade.
    assert os_update._APT_ENV["DEBIAN_FRONTEND"] == "noninteractive"
    assert "--force-confold" in " ".join(os_update._APT_CONF)


# ── selective patching, privilege, reboot ────────────────────────────────────
_ELIGIBLE = {"eligible": True, "manager": "apt", "flavor": "debian", "reason": ""}


class _OkRun:
    returncode = 0
    stdout = ""
    stderr = ""


def _recording_run(monkeypatch):
    seen = []

    def _fake(argv, timeout):
        seen.append(argv)
        return _OkRun()
    monkeypatch.setattr(os_update, "_run", _fake)
    return seen


@pytest.fixture
def root_node(monkeypatch):
    monkeypatch.setattr(os_update, "_is_root", lambda: True)
    monkeypatch.setattr(os_update, "detect_capability", lambda: dict(_ELIGIBLE))
    monkeypatch.setattr(os_update, "_reboot_required", lambda: False)


def _pending(*names):
    return lambda refresh=True: {"count": len(names),
                                 "packages": [{"package": n} for n in names]}


def test_empty_package_list_is_refused_never_widened(root_node, monkeypatch):
    # The dangerous failure: [] silently becoming "upgrade everything".
    seen = _recording_run(monkeypatch)
    monkeypatch.setattr(os_update, "check_updates", _pending("openssl"))
    r = os_update.apply_updates([])
    assert r["status"] == "ERROR" and "no packages" in r["message"]
    assert not seen


def test_invalid_package_names_are_refused(root_node, monkeypatch):
    seen = _recording_run(monkeypatch)
    monkeypatch.setattr(os_update, "check_updates", _pending("openssl"))
    r = os_update.apply_updates(["-oAPT::Foo=1", "bash;reboot"])
    assert r["status"] == "ERROR" and "invalid package" in r["message"]
    assert not seen


def test_selected_packages_use_only_upgrade_and_skip_non_pending(root_node, monkeypatch):
    seen = _recording_run(monkeypatch)
    monkeypatch.setattr(os_update, "check_updates", _pending("openssl", "curl"))
    r = os_update.apply_updates(["openssl", "vim"])
    assert r["status"] == "SUCCESS" and r["mode"] == "packages"
    assert r["packages_applied"] == ["openssl"] and r["skipped"] == ["vim"]
    argv = seen[-1]
    assert argv[:3] == ["apt-get", "install", "--only-upgrade"]
    assert argv[-1] == "openssl" and "curl" not in argv
    assert "dist-upgrade" not in argv


def test_nothing_still_pending_is_a_noop_success(root_node, monkeypatch):
    seen = _recording_run(monkeypatch)
    monkeypatch.setattr(os_update, "check_updates", _pending("curl"))
    r = os_update.apply_updates(["openssl"])
    assert r["status"] == "SUCCESS" and r["applied"] == 0 and r["skipped"] == ["openssl"]
    assert not seen


def test_non_root_goes_through_the_sudo_helper(monkeypatch):
    monkeypatch.setattr(os_update, "_is_root", lambda: False)
    assert os_update._privileged("upgrade-only", ["openssl"]) == [
        "sudo", "-n", os_update.HELPER, "upgrade-only", "openssl"]
    assert os_update._privileged("reboot")[:4] == ["sudo", "-n", os_update.HELPER, "reboot"]


def test_non_root_without_helper_is_blocked_with_a_reason(monkeypatch):
    monkeypatch.setattr(os_update, "_is_root", lambda: False)
    monkeypatch.setattr(os_update.os.path, "exists", lambda p: False)
    monkeypatch.setattr(os_update, "detect_capability", lambda: dict(_ELIGIBLE))
    seen = _recording_run(monkeypatch)
    r = os_update.apply_updates()
    assert r["status"] == "ERROR" and "lm-os-update" in r["message"]
    assert os_update.reboot_node()["status"] == "ERROR"
    assert not seen


def test_check_reports_features_and_blocker(monkeypatch):
    monkeypatch.setattr(os_update, "_is_root", lambda: False)
    monkeypatch.setattr(os_update.os.path, "exists", lambda p: False)
    monkeypatch.setattr(os_update, "detect_capability", lambda: dict(_ELIGIBLE))

    class _R:
        returncode = 0
        stdout = "ok/stable 2.0 amd64 [upgradable from: 1.0]\n"
        stderr = ""
    seen = []
    monkeypatch.setattr(os_update, "_run", lambda argv, t: (seen.append(argv), _R())[1])
    r = os_update.check_updates(refresh=True)
    assert r["features"] == ["packages", "reboot"]
    assert "lm-os-update" in r["apply_blocker"]
    # Blocked node: no privileged refresh attempted, just the unprivileged list.
    assert seen == [["apt", "list", "--upgradable"]]
    assert r["count"] == 1


def test_reboot_is_delayed_and_refused_on_appliances(root_node, monkeypatch):
    seen = _recording_run(monkeypatch)
    r = os_update.reboot_node()
    assert r["status"] == "SUCCESS"
    assert seen[-1][:3] == ["shutdown", "-r", "+1"]
    monkeypatch.setattr(os_update, "detect_capability",
                        lambda: {"eligible": False, "reason": "appliance"})
    seen.clear()
    assert os_update.reboot_node()["status"] == "ERROR"
    assert not seen


def test_helper_script_rejects_bad_package_names_before_apt():
    import subprocess
    helper = Path(__file__).resolve().parents[2] / "scripts" / "lm-os-update"
    for bad in ("-oAPT::Foo=1", "a;reboot", "UPPER"):
        r = subprocess.run(["bash", str(helper), "upgrade-only", bad],
                           capture_output=True, text=True)
        assert r.returncode == 2 and "invalid package name" in r.stderr
    r = subprocess.run(["bash", str(helper), "rm"], capture_output=True, text=True)
    assert r.returncode == 2
