"""Regression tests for device-type misdetection and false "boot stuck" verdicts
seen on live console ports.

The fleet behind these consoles is only: ArubaOS gateways/controllers
(aruba-os), ArubaOS-Switch (hp-procurve), AOS-CX (aruba-cx), Juniper SRX/EX
(juniper-junos) and Juniper SSR (juniper-ssr). The banner fixtures below are
copied verbatim from the ``probe.banner`` tails in a live ports.json.
"""
import asyncio

import fingerprint as fp
import serial_manager as sm
from test_console_monitor import (  # noqa: F401 - `spoke` is a pytest fixture
    cs, spoke, _install_fake_boot_chan, _drive_boot)

# ── Live banners (verbatim) ──────────────────────────────────────────────────
SSR_OS_LOGIN = ("login: Oracle Linux Server 7.9 Kernel 4.18.0-553.16.1.el8_10.x86_64 "
                "on an x86_64 ar30260015 login:")
SSR_PCLI_PROMPT = "admin@node0.00900bef026b#"
CX_6300_CRED_CYCLE = ("0 login: cisco Password: Login incorrect 6300 login: Password: "
                      "Login incorrect 6300 login: aruba123 Password:")
CX_ACSW02 = ("ord: Login incorrect BO-SYDm-ACSW02 login: Password: Login incorrect "
             "BO-SYDm-ACSW02 login: aruba123 Password:")
CX_ACSW01 = "...*****\n\n BO-SYDm-ACSW01 login:"
CX_REGISTER_BANNER = ("...s * Special events Please register your products now at: "
                      "https://asp.arubanetworks.com DHCP-Rogue-Test login:")
CX_BAR_AGG = ('console User "admin" has logged in 3 times in the past 30 days '
              'BAR-AGG# admin Invalid input: admin BAR-AGG#')
CX_BAR_AGG_MODEL = "JL725A 6200F 24G CL4 4SFP+370W Swch"
ARUBAOS_USER_PROMPT = (" root Password: User: root Password: User: manager Password: "
                       "User: admin Password: User: ubnt Password: User:")
ARUBAOS_SETUP_DIALOG = ("...or PPPOE ip assignment. Uses activate for conductor information "
                        "Enter Option (partial string is acceptable):")


# ── Vendor detection ─────────────────────────────────────────────────────────

def test_ssr_os_login_is_ssr_not_linux():
    res = fp.passive_identify(SSR_OS_LOGIN)
    assert res["vendor"] == "juniper-ssr"
    # Was the literal word "hostname"; the login prompt names the box.
    assert res["identity"]["hostname"] == "ar30260015"


def test_ssr_pcli_prompt_is_ssr():
    assert fp.detect_vendor(SSR_PCLI_PROMPT)["name"] == "juniper-ssr"
    assert fp.passive_identify(SSR_PCLI_PROMPT)["identity"]["hostname"] == "node0.00900bef026b"


def test_cx_banners_are_cx_not_linux():
    assert fp.detect_vendor(CX_6300_CRED_CYCLE)["name"] == "aruba-cx"
    assert fp.passive_identify(CX_6300_CRED_CYCLE)["identity"]["hostname"] == "6300"
    assert fp.detect_vendor(CX_REGISTER_BANNER)["name"] == "aruba-cx"
    assert fp.passive_identify(CX_REGISTER_BANNER)["identity"]["hostname"] == "DHCP-Rogue-Test"


def test_bare_login_prompt_is_not_linux():
    # No CX-only text yet, but certainly not a Linux server: stays unknown
    # until a login or banner identifies it, and the name is still gleaned.
    for banner, host in ((CX_ACSW02, "BO-SYDm-ACSW02"), (CX_ACSW01, "BO-SYDm-ACSW01")):
        res = fp.passive_identify(banner)
        assert res["vendor"] != "linux"
        assert res["identity"]["hostname"] == host


def test_cx_login_history_beats_procurve_invalid_input():
    assert fp.detect_vendor(CX_BAR_AGG)["name"] == "aruba-cx"
    assert fp.is_cx_misfiled_as_procurve("hp-procurve", {"model": CX_BAR_AGG_MODEL}, "")
    assert fp.is_cx_misfiled_as_procurve("hp-procurve", {}, CX_BAR_AGG)
    # Unknown vendor with a CX model (live: ra BAR-AGG) is corrected too,
    # but a confident non-CX verdict is left alone.
    assert fp.is_cx_misfiled_as_procurve(None, {"model": CX_BAR_AGG_MODEL}, "")
    assert not fp.is_cx_misfiled_as_procurve("aruba-os", {"model": CX_BAR_AGG_MODEL}, "")
    assert fp.detect_vendor("R8N85A 6000 48G CL4 4SFP Swch")["name"] == "aruba-cx"


def test_procurve_stays_procurve():
    assert fp.detect_vendor("MIPBE-AJ18-L1SW-1# \r\nInvalid input: get")["name"] == "hp-procurve"
    for model in ("5406Rzl2 J9850A", "2540-24G-4SFP+ JL354A"):
        assert not fp.is_cx_misfiled_as_procurve("hp-procurve", {"model": model}, "")


def test_junos_still_detected():
    assert fp.detect_vendor("{primary:node0}\r\nadmin@BO-MIAm-CRFW01_node0> ")["name"] == "juniper-junos"
    assert fp.detect_vendor("\r\nsrx340 (ttyu0)\r\n\r\nlogin: ")["name"] == "juniper-junos"


def test_arubaos_gateway_user_prompt_and_setup_dialog():
    assert fp.detect_vendor(ARUBAOS_USER_PROMPT)["name"] == "aruba-os"
    assert fp.detect_vendor(ARUBAOS_SETUP_DIALOG)["name"] == "aruba-os"
    # ProCurve/Cisco "Username:" is not the ArubaOS "User:" prompt.
    assert fp.detect_vendor("Username: ") is None


def test_real_linux_still_linux():
    assert fp.detect_vendor("Ubuntu 22.04 LTS\r\nhost login: ")["name"] == "linux"


# ── Identity junk ────────────────────────────────────────────────────────────

def test_placeholder_hostnames_never_stored():
    assert fp.prompt_hostname("standby# ") == ""
    assert fp.scrub_identity({"hostname": "hostname"}) == {}
    assert fp.scrub_identity({"hostname": "standby", "model": "x"}) == {"model": "x"}
    assert fp.scrub_identity({"hostname": "BAR-AGG"}) == {"hostname": "BAR-AGG"}


def test_linux_commands_echo_and_pcli_prompt_not_parsed_as_identity():
    linux = next(p for p in fp.PROFILES if p["name"] == "linux")
    outputs = {
        "cat /sys/class/dmi/id/product_serial 2>/dev/null":
            "cat /sys/class/dmi/id/product_serial 2>/dev/null\r\n" + SSR_PCLI_PROMPT,
        "hostname": "hostname\r\n" + SSR_PCLI_PROMPT,
    }
    assert fp.parse_identity(linux, outputs) == {}
    # A real Linux reply is still parsed.
    assert fp.parse_identity(linux, {"hostname": "root@web1:~# hostname\r\nweb1\r\nroot@web1:~# "}) \
        == {"hostname": "web1"}


def test_prompt_shaped_serial_is_never_a_device_key():
    ident = fp.scrub_identity({"serial": SSR_PCLI_PROMPT})
    assert "serial" not in ident
    assert sm.DeviceCache.device_key(ident) is None
    assert fp.scrub_identity({"serial": "SG12KW1234"}) == {"serial": "SG12KW1234"}


def test_vendor_strength_rules():
    assert not fp.vendor_should_replace("aruba-cx", "linux")
    assert not fp.vendor_should_replace("juniper-junos", None)
    assert not fp.vendor_should_replace("aruba-cx", "hp-procurve")
    assert fp.vendor_should_replace("hp-procurve", "aruba-cx")
    assert fp.vendor_should_replace("linux", "juniper-ssr")
    assert fp.vendor_should_replace(None, "linux")
    assert fp.vendor_is_upgrade("linux", "aruba-cx")
    assert not fp.vendor_is_upgrade("hp-procurve", "aruba-cx")


# ── Boot-state helpers ───────────────────────────────────────────────────────

def test_setup_dialog_and_login_text_count_as_booted():
    assert fp.looks_like_prompt(ARUBAOS_SETUP_DIALOG)
    assert fp.looks_like_prompt("Press any key to continue")
    assert fp.looks_like_prompt("Enter System name [Aruba7008]:")
    for text in ("BO-SYDm-ACSW02 login: admin\r\n",
                 "Login incorrect\r\n",
                 "Login attempt timed out after 120 seconds.\r\n",
                 "Warning: Transient problem: timeout Will retry in 4 seconds\r\n",
                 "User: root\r\n"):
        assert fp.os_up_marker(text), text
    assert not fp.os_up_marker("U-Boot 2013.01\r\nStarting kernel ...\r\n")


def test_restart_reason_lines_are_not_boot_faults():
    assert fp.current_boot_fault("Last reboot reason: watchdog reset\r\nBooting...\r\n") == ""
    assert fp.current_boot_fault("Reset cause: watchdog reset\r\n") == ""
    # Genuine faults still count.
    assert "panic" in fp.current_boot_fault("Kernel panic - not syncing\r\n").lower()
    assert fp.current_boot_fault("watchdog reset\r\n") == "watchdog reset"


# ── Spoke: boot watcher ──────────────────────────────────────────────────────

def _boot_until_quiet(spoke, monkeypatch, text):
    clock = [1_700_000_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set(text)
    _drive_boot(spoke, "good", clock, chan, len(text))
    clock[0] += 60  # quiet, and well past stuck_secs
    _drive_boot(spoke, "good", clock, chan, len(text))
    return spoke._boot_info("good")


def test_gateway_at_setup_dialog_is_booted_not_stuck(spoke, monkeypatch):
    info = _boot_until_quiet(spoke, monkeypatch, ARUBAOS_SETUP_DIALOG)
    assert info["state"] == "booted"


def test_gateway_user_prompt_with_echoed_username_is_booted(spoke, monkeypatch):
    # The passive tail ends in a typed username, not at the prompt itself.
    text = "\r\nUser: root\r\nPassword:\r\nUser: admin"
    info = _boot_until_quiet(spoke, monkeypatch, text)
    assert info["state"] == "booted"


def test_cx_login_failure_tail_is_booted(spoke, monkeypatch):
    text = "\r\nBO-SYDm-ACSW02 login: admin\r\nPassword:\r\nLogin incorrect\r\n"
    info = _boot_until_quiet(spoke, monkeypatch, text)
    assert info["state"] == "booted"


def test_stuck_verdict_heals_when_a_prompt_appears(spoke, monkeypatch):
    clock = [1_700_000_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Booting...\r\nRebooting...\r\n")
    _drive_boot(spoke, "good", clock, chan, 30)
    assert spoke._boot_info("good")["state"] == "stuck"
    clock[0] += 10  # output keeps flowing (no new silence → no new episode)
    chan.set("Booting...\r\nRebooting...\r\nBO-SYDm-ACSW01 login: ")
    _drive_boot(spoke, "good", clock, chan, 60)
    info = spoke._boot_info("good")
    assert info["state"] == "booted" and info["stuck_reason"] == ""


def test_genuine_hang_without_prompt_still_stuck(spoke, monkeypatch):
    info = _boot_until_quiet(spoke, monkeypatch, "U-Boot 2013.01\r\nStarting kernel ...\r\n")
    assert info["state"] == "stuck"


def test_noise_only_stuck_verdict_clears(spoke, monkeypatch):
    # Live lrb: episodes started by unreadable line noise were left "stuck" for
    # weeks with an empty transcript. No readable output means no boot.
    clock = [1_700_000_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    spoke._health_rec("good")["boot"] = {
        "state": "stuck", "started_at": clock[0] - 86400, "last_output_at": clock[0] - 86400,
        "prompt_seen": False, "relocked": True, "transcript_tail": "",
        "stuck_reason": "no prompt within boot timeout", "reason": "confirmed stuck"}
    _drive_boot(spoke, "good", clock, chan, 0)
    info = spoke._boot_info("good")
    assert info["state"] == "idle" and info["stuck_reason"] == ""


# ── Spoke: stored vendor / identity ──────────────────────────────────────────

def _emit(spoke, pid, res):
    asyncio.run(spoke._emit_probe_result(pid, {"logged_in": False, "banner": "", **res}))


def test_weak_linux_verdict_does_not_overwrite_cx(spoke, tmp_path):
    spoke.devices = sm.DeviceCache(path=tmp_path / "devices.json")
    spoke.store.update("good", probe={"source": "active", "vendor": "aruba-cx",
                                      "identity": {"hostname": "BO-SYDm-ACSW01"}})
    _emit(spoke, "good", {"vendor": "linux", "identity": {}})
    assert spoke.store.get("good")["probe"]["vendor"] == "aruba-cx"


def test_legacy_linux_verdict_and_junk_identity_cleaned(spoke, tmp_path):
    spoke.devices = sm.DeviceCache(path=tmp_path / "devices.json")
    spoke.store.update("good", probe={"source": "active", "vendor": "linux",
                                      "banner": CX_ACSW02,
                                      "identity": {"hostname": "hostname",
                                                   "serial": SSR_PCLI_PROMPT}})
    _emit(spoke, "good", {"vendor": None, "identity": {}})
    probe = spoke.store.get("good")["probe"]
    assert probe["vendor"] is None
    assert probe["identity"] == {}


def test_passive_glean_fixes_legacy_linux_ssr(spoke):
    spoke._monitor_scan()
    spoke.store.update("good", probe={"source": "active", "vendor": "linux",
                                      "banner": SSR_OS_LOGIN,
                                      "identity": {"hostname": "hostname"}})
    spoke._passive_glean("good")
    probe = spoke.store.get("good")["probe"]
    assert probe["vendor"] == "juniper-ssr"
    assert probe["identity"]["hostname"] == "ar30260015"


def test_passive_glean_fixes_cx_stored_as_procurve(spoke):
    spoke._monitor_scan()
    spoke.store.update("good", probe={"source": "active", "vendor": "hp-procurve",
                                      "banner": "BAR-AGG# ",
                                      "identity": {"hostname": "BAR-AGG",
                                                   "model": CX_BAR_AGG_MODEL}})
    spoke._passive_glean("good")
    assert spoke.store.get("good")["probe"]["vendor"] == "aruba-cx"


def test_passive_glean_keeps_real_procurve(spoke):
    spoke._monitor_scan()
    spoke.store.update("good", probe={"source": "active", "vendor": "hp-procurve",
                                      "banner": "MIPBE-AJ18-L1SW-1# ",
                                      "identity": {"hostname": "MIPBE-AJ18-L1SW-1",
                                                   "model": "5406Rzl2 J9850A"}})
    spoke._passive_glean("good")
    assert spoke.store.get("good")["probe"]["vendor"] == "hp-procurve"
