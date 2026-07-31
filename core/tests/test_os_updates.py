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
