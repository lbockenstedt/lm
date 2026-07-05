"""Unit tests for the Console serial layer's pyserial-free logic.

These run without pyserial installed (the module guards its import), covering
stable port_id derivation, baud-detect scoring, and the port settings store.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import serial_manager as m  # noqa: E402


def test_derive_port_id_usb_serial():
    assert m.derive_port_id("/dev/ttyUSB0", serial_number="FTX1") == "usb-FTX1"


def test_derive_port_id_vidpid_location():
    assert m.derive_port_id("/dev/ttyUSB1", vid=0x0403, pid=0x6001, location="1-1.2") == "usb-0403:6001@1-1.2"


def test_derive_port_id_uart_by_path():
    # On-board UARTs key on the fixed device path (stable hardware position).
    assert m.derive_port_id("/dev/ttyAMA0") == "uart-ttyAMA0"


def test_derive_port_id_is_stable_across_calls():
    a = m.derive_port_id("/dev/ttyUSB9", serial_number="ABC")
    b = m.derive_port_id("/dev/ttyUSB3", serial_number="ABC")  # different dev, same adapter
    assert a == b  # id follows the adapter, not the kernel-assigned ttyUSB number


def test_score_sample_prefers_printable_with_prompt():
    good = m.score_sample(b"Switch> \r\nlogin: ")
    noise = m.score_sample(bytes([0xFF, 0xFE, 0x00, 0x81, 0x9A]))
    empty = m.score_sample(b"")
    assert good > 1.0  # printable ratio (~1.0) + prompt bonus (0.5)
    assert noise == 0.0
    assert empty == 0.0


def test_port_store_roundtrip(tmp_path):
    store = m.PortStore(path=tmp_path / "ports.json")
    store.update("usb-FTX1", alias="core-sw-1", settings={"baud": 115200})
    # Defaults merge with saved overrides.
    s = store.settings("usb-FTX1")
    assert s["baud"] == 115200 and s["bytesize"] == 8 and s["parity"] == "N"
    assert store.get("usb-FTX1")["alias"] == "core-sw-1"
    # Persisted across instances.
    store2 = m.PortStore(path=tmp_path / "ports.json")
    assert store2.settings("usb-FTX1")["baud"] == 115200
    assert store2.get("usb-FTX1")["alias"] == "core-sw-1"


def test_port_store_partial_settings_update_keeps_others(tmp_path):
    store = m.PortStore(path=tmp_path / "ports.json")
    store.update("p1", settings={"baud": 9600, "flow": "rtscts"})
    store.update("p1", settings={"baud": 38400})  # change only baud
    s = store.settings("p1")
    assert s["baud"] == 38400 and s["flow"] == "rtscts"
