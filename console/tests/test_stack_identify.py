"""End-to-end identify tests for VSF stack detection.

Drives :func:`fingerprint.run_identify` over a scripted serial channel that
replays what a real AOS-CX stack answers, so the profile wiring (which commands
are sent, and to which vendors) is covered as well as the parsing.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fingerprint as fp  # noqa: E402


class _FakeChan:
    """Scripted serial: pre-loaded banner + per-command responses keyed by the
    command substring seen in a write()."""

    def __init__(self, banner, responses):
        self.buf = bytearray(banner.encode())
        self.responses = list(responses)
        self.sent = []

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        s = b.decode(errors="replace")
        self.sent.append(s)
        for i, (trig, resp) in enumerate(self.responses):
            if trig and trig in s:
                self.buf += resp.encode()
                self.responses[i] = (None, "")
                return


_VSF_CONDUCTOR = (
    "\r\nMAC Address                : 8c:85:c1:4b:c7:80\r\n"
    "Topology                   : Ring\r\n\r\n"
    "Mbr Mac Address         type           Status\r\nID\r\n"
    "--- ------------------- -------------- ---------------\r\n"
    "1   8c:85:c1:4b:c7:80   JL662A         Conductor\r\n"
    "2   34:c5:15:9b:52:00   JL666A         Standby\r\n"
    "BO-SYDm-ACSW01#")

_VSF_STANDBY = (
    "\r\nThis Mbr ID              : 2\r\n\r\n"
    "Mbr Mac Address         type           Status\r\nID\r\n"
    "--- ------------------- -------------- ---------------\r\n"
    "1   8c:85:c1:4b:c7:80   JL662A         Conductor\r\n"
    "2   34:c5:15:9b:52:00   JL666A         Standby\r\nstandby#")

_SHOW_VERSION = ("\r\nAOS-CX\r\nVersion      : FL.10.13.1000\r\n"
                 "Service OS Version : FL.01.19.0002\r\n")


def test_conductor_port_reports_the_full_stack():
    """The conductor is the only member that accepts configuration, so its port
    must be labelled as such and carry the whole member list."""
    banner = "\r\nArubaOS-CX\r\nBO-SYDm-ACSW01# "
    chan = _FakeChan(banner, [
        ("no page", "\r\nBO-SYDm-ACSW01#"),
        ("show system", "\r\nHostname : BO-SYDm-ACSW01\r\n"
                        "Base MAC Address : 8c:85:c1:4b:c7:80\r\n"
                        "Serial Number : SG00KTEST1\r\nBO-SYDm-ACSW01#"),
        ("show interface mgmt", "\r\nIPv4 address : 172.16.38.20\r\nBO-SYDm-ACSW01#"),
        ("show vsf", _VSF_CONDUCTOR + _SHOW_VERSION),
        ("show version", _SHOW_VERSION + "\r\nBO-SYDm-ACSW01#"),
    ])
    res = fp.run_identify(chan.read, chan.write, [])

    assert res["vendor"] == "aruba-cx"
    stack = res["stack"]
    assert stack["is_stack"] is True
    assert stack["role"] == "conductor"
    assert stack["member_id"] == 1
    assert stack["topology"] == "Ring"
    assert stack["sw_version"] == "FL.10.13.1000"
    assert stack["conductor_mac"] == "8c:85:c1:4b:c7:80"
    assert [m["mac"] for m in stack["members"]] == [
        "8c:85:c1:4b:c7:80", "34:c5:15:9b:52:00"]


def test_standby_port_is_identified_and_names_its_conductor():
    """A standby prints no vendor banner and rejects the identity commands, so
    without the standby-prompt fallback the port would stay an unknown box.

    It must still come back with the conductor's MAC — that is the key the hub
    uses to point the operator at the console line that can configure the stack.
    """
    banner = "\r\n6300 login: "
    chan = _FakeChan(banner, [
        ("admin", "\r\nPassword: "),
        ("secret", "\r\nstandby# "),
        ("no page", "\r\nstandby#"),
        ("show system", "\r\nInvalid input: system\r\nstandby#"),
        ("show interface mgmt", "\r\nInvalid input: interface\r\nstandby#"),
        ("show vsf", _VSF_STANDBY),
        ("show version", _SHOW_VERSION + "\r\nstandby#"),
    ])
    res = fp.run_identify(chan.read, chan.write,
                          [{"username": "admin", "password": "secret"}])

    stack = res["stack"]
    assert stack["is_stack"] is True
    assert stack["role"] == "standby"
    assert stack["member_id"] == 2
    assert stack["conductor_mac"] == "8c:85:c1:4b:c7:80"
    # Its own member MAC becomes the port's identity: a standby has no hostname
    # and no `show system`, so this is the only stable reconciliation key.
    assert res["identity"]["mac"] == "34:c5:15:9b:52:00"


def test_standalone_switch_gets_no_stack_block():
    """A non-stacked switch still answers `show vsf` with a 1-member Standalone
    table; the probe must stay free of a misleading empty stack record."""
    banner = "\r\nArubaOS-CX\r\n6300# "
    chan = _FakeChan(banner, [
        ("no page", "\r\n6300#"),
        ("show system", "\r\nHostname : 6300\r\n6300#"),
        ("show interface mgmt", "\r\n6300#"),
        ("show vsf", "\r\nMAC Address                : 8c:85:c1:4b:c7:80\r\n"
                     "Topology                   : Standalone\r\n\r\n"
                     "Mbr Mac Address         type           Status\r\nID\r\n"
                     "--- ------------------- -------------- ---------------\r\n"
                     "1   8c:85:c1:4b:c7:80   JL662A         Conductor\r\n6300#"),
        ("show version", _SHOW_VERSION + "\r\n6300#"),
    ])
    res = fp.run_identify(chan.read, chan.write, [])
    assert res.get("stack", {}).get("is_stack") is not True


def test_non_aruba_vendor_is_never_asked_about_vsf():
    """`show vsf` is added to the Aruba profiles only. The safety contract is
    that a device is only ever sent its OWN matched profile's commands."""
    banner = "\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#"
    chan = _FakeChan(banner, [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID FTX9XYZ\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1  10.0.0.5  YES  up  up\r\nSwitch#"),
    ])
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "cisco-ios"
    assert not any("vsf" in s.lower() for s in chan.sent)
    assert "stack" not in res


def test_detect_stack_survives_a_cli_rejection():
    """A 2530 has no VSF at all and just rejects the command."""
    assert fp.detect_stack({"show vsf": "Invalid input: vsf"}, "switch# ") == {}
