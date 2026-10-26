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
    assert r["features"] == ["packages", "reboot", "fix_access"]
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


# ── fix_access: one-time root/sudo login installs the helper ─────────────────

_FAKE_SU = r'''
import getpass, sys
pw = getpass.getpass("Password: ")
sys.exit(0 if pw == "s3cret" else 1)
'''


def test_password_is_typed_at_the_prompt_over_a_pty(tmp_path):
    script = tmp_path / "fake_su.py"
    script.write_text(_FAKE_SU)
    rc, out = os_update._run_with_password([sys.executable, str(script)], "s3cret", 1, 20)
    assert rc == 0
    assert "s3cret" not in out
    rc, _ = os_update._run_with_password([sys.executable, str(script)], "wrong", 1, 20)
    assert rc == 1


def test_a_second_prompt_beyond_the_limit_is_a_failure_not_a_hang(tmp_path):
    script = tmp_path / "reprompt.py"
    script.write_text("import getpass\nwhile True: getpass.getpass('Password: ')\n")
    rc, _ = os_update._run_with_password([sys.executable, str(script)], "x", 1, 20)
    assert rc == -1


def test_install_script_embeds_helper_and_validates_sudoers():
    s = os_update._install_script(b"#!/bin/bash\necho hi\n", "svc_lm")
    assert "base64 -d > /usr/local/bin/lm-os-update.new" in s
    assert "svc_lm ALL=(ALL) NOPASSWD: /usr/local/bin/lm-os-update *" in s
    assert s.index("visudo -cf") < s.index("mv -f /etc/sudoers.d/lm-os-update.new")
    # Helper last: a failed sudoers step must leave the node still "blocked".
    assert s.index("mv -f /etc/sudoers.d/lm-os-update.new") < s.index("mv -f /usr/local/bin/lm-os-update.new")


def _blocked(monkeypatch):
    state = {"blocked": True}
    monkeypatch.setattr(os_update, "_privilege_blocker",
                        lambda: "blocked" if state["blocked"] else "")
    return state


def test_fix_access_is_a_noop_when_not_blocked(monkeypatch):
    monkeypatch.setattr(os_update, "_privilege_blocker", lambda: "")
    assert os_update.fix_access("root", "pw")["status"] == "SUCCESS"


def test_fix_access_root_uses_su_and_one_prompt(monkeypatch):
    state = _blocked(monkeypatch)
    calls = []

    def _fake(argv, password, max_prompts, timeout):
        calls.append((argv, password, max_prompts))
        state["blocked"] = False
        return 0, ""

    class _R:
        returncode = 0
    monkeypatch.setattr(os_update, "_run_with_password", _fake)
    monkeypatch.setattr(os_update, "_run", lambda argv, t: _R())
    r = os_update.fix_access("root", "pw")
    assert r["status"] == "SUCCESS"
    argv, password, max_prompts = calls[0]
    assert argv[:3] == ["su", "root", "-c"] and argv[3].startswith("sh -c ")
    assert password == "pw" and max_prompts == 1
    assert "pw" not in argv[3].split()  # never on the command line


def test_fix_access_sudo_user_goes_through_sudo(monkeypatch):
    state = _blocked(monkeypatch)
    calls = []

    def _fake(argv, password, max_prompts, timeout):
        calls.append((argv, max_prompts))
        state["blocked"] = False
        return 0, ""

    class _R:
        returncode = 0
    monkeypatch.setattr(os_update, "_run_with_password", _fake)
    monkeypatch.setattr(os_update, "_run", lambda argv, t: _R())
    assert os_update.fix_access("admin", "pw")["status"] == "SUCCESS"
    argv, max_prompts = calls[0]
    assert argv[1] == "admin" and argv[3].startswith("sudo -S ") and max_prompts == 2


def test_fix_access_reports_a_wrong_password(monkeypatch):
    _blocked(monkeypatch)
    monkeypatch.setattr(os_update, "_run_with_password", lambda *a: (1, "su: Authentication failure"))
    r = os_update.fix_access("root", "bad")
    assert r["status"] == "ERROR" and "Authentication failure" in r["message"]


def test_fix_access_refuses_bad_input(monkeypatch):
    _blocked(monkeypatch)
    assert os_update.fix_access("root; rm -rf /", "pw")["status"] == "ERROR"
    assert os_update.fix_access("root", "")["status"] == "ERROR"
