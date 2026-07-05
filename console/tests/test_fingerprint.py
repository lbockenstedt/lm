"""Unit tests for the Console fingerprint engine (pyserial-free)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fingerprint as fp  # noqa: E402


def test_detect_vendor():
    assert fp.detect_vendor("Cisco IOS Software, Version 15.2(4)")["name"] == "cisco-ios"
    assert fp.detect_vendor("ArubaOS-CX GL.10.08")["name"] == "aruba-cx"
    assert fp.detect_vendor("HP ProCurve Switch 2530")["name"] == "hp-procurve"
    assert fp.detect_vendor("Ubuntu 22.04 LTS\r\nhost login: ")["name"] == "linux"
    assert fp.detect_vendor("\xff\xfe random line noise") is None


def test_normalize_mac():
    assert fp.normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert fp.normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert fp.normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert fp.normalize_mac("nope") == ""


def test_parse_identity_cisco():
    prof = fp.detect_vendor("Cisco IOS")
    outputs = {
        "terminal length 0": "Switch#",
        "show version": ("Cisco IOS Software\r\nProcessor board ID FTX1234ABCD\r\n"
                         "Base ethernet MAC Address : 0011.2233.4455\r\n"
                         "Switch uptime is 5 days\r\nCisco WS-C2960 processor\r\nVersion 15.2(4)E"),
        "show ip interface brief": "Interface   IP-Address\r\nVlan1  192.168.1.10  YES  up  up",
    }
    ident = fp.parse_identity(prof, outputs)
    assert ident["serial"] == "FTX1234ABCD"
    assert ident["mac"] == "00:11:22:33:44:55"
    assert ident["ip"] == "192.168.1.10"
    assert ident["hostname"] == "Switch"


class _FakeChan:
    """Scripted serial: pre-loaded banner + per-command responses keyed by the
    command substring seen in a write()."""
    def __init__(self, banner, responses):
        self.buf = bytearray(banner.encode())
        self.responses = list(responses)

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        s = b.decode(errors="replace")
        for i, (trig, resp) in enumerate(self.responses):
            if trig and trig in s:
                self.buf += resp.encode()
                self.responses[i] = (None, "")
                return


def test_run_identify_cisco_noauth():
    banner = "\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#"
    responses = [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID FTX9XYZ\r\n"
                         "Base ethernet MAC Address : 0011.2233.4455\r\n"
                         "Switch uptime is 1 day\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1  10.0.0.5  YES  up  up\r\nSwitch#"),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "cisco-ios"
    assert res["logged_in"] is True
    assert res["identity"]["serial"] == "FTX9XYZ"
    assert res["identity"]["mac"] == "00:11:22:33:44:55"
    assert res["identity"]["ip"] == "10.0.0.5"


def test_run_identify_login_then_harvest():
    banner = "\r\nCisco IOS Software\r\nUsername: "
    responses = [
        ("admin", "\r\nPassword: "),
        ("secret", "\r\nSwitch#"),
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID ABC123\r\nSwitch uptime is 2 days\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1 10.0.0.9 YES up up\r\nSwitch#"),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [{"username": "admin", "password": "secret"}])
    assert res["logged_in"] is True
    assert res["credential_index"] == 0
    assert res["identity"]["serial"] == "ABC123"
