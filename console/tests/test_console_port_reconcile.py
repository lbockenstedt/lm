"""Spoke-level tests: a device's alias/tenant must carry forward automatically
when it reappears under a DIFFERENT port_id (reboot renumbered /dev/ttyUSBn,
or the cable moved to a different adapter), and an already-identified port
must be periodically re-verified rather than trusted forever — a cable can be
silently swapped to point at a different device without the port_id changing
at all.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

_bs = types.ModuleType("base_spoke")


class _BaseSpoke:
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


_bs.BaseSpoke = _BaseSpoke
sys.modules.setdefault("base_spoke", _bs)

import serial_manager as sm  # noqa: E402
import console_spoke as cs  # noqa: E402
from test_serial_manager import _FakeSerial  # noqa: E402


@pytest.fixture()
def spoke(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    _FakeSerial.Serial.instances = []
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": False, "auto_identify": False})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def _run(coro):
    return asyncio.run(coro)


# ── Reconciliation on identify ──────────────────────────────────────────────

def test_reappearing_device_carries_alias_forward_and_drops_old_record(spoke):
    spoke.store.update("old-pid", alias="MIA-SW-AOSS", tenant_id="lrb",
                       probe={"identity": {"hostname": "MIA-SW-AOSS", "serial": "TW94HKZ1Y2"}})

    _run(spoke._emit_probe_result("new-pid", {
        "vendor": "HP-PROCURVE",
        "identity": {"hostname": "MIA-SW-AOSS", "serial": "TW94HKZ1Y2"},
        "logged_in": True,
    }))

    assert spoke.store.get("new-pid")["alias"] == "MIA-SW-AOSS"
    assert spoke.store.get("new-pid")["tenant_id"] == "lrb"
    assert spoke.store.get("old-pid") == {}, "the orphaned old port_id record must be gone"


def test_reconcile_matches_on_mac_when_no_serial(spoke):
    spoke.store.update("old-pid", alias="OLKS-MGMTSW",
                       probe={"identity": {"mac": "38:21:c7:fc:8e:e0"}})

    _run(spoke._emit_probe_result("new-pid", {
        "identity": {"mac": "38:21:C7:FC:8E:E0"},  # case differs — must still match
        "logged_in": True,
    }))

    assert spoke.store.get("new-pid")["alias"] == "OLKS-MGMTSW"
    assert spoke.store.get("old-pid") == {}


def test_reconcile_never_overwrites_an_alias_already_set_on_the_new_port(spoke):
    spoke.store.update("old-pid", alias="stale-name",
                       probe={"identity": {"serial": "SN123"}})
    spoke.store.update("new-pid", alias="operator-set-this-already")

    _run(spoke._emit_probe_result("new-pid", {
        "identity": {"serial": "SN123"}, "logged_in": True,
    }))

    assert spoke.store.get("new-pid")["alias"] == "operator-set-this-already"
    assert spoke.store.get("old-pid") == {}, "old record still retires even though alias wasn't copied"


def test_no_reconcile_when_no_matching_prior_identity(spoke):
    _run(spoke._emit_probe_result("pid-1", {
        "identity": {"hostname": "brand-new-device", "serial": "SN999"}, "logged_in": True,
    }))
    assert spoke.store.get("pid-1")["probe"]["identity"]["serial"] == "SN999"
    assert spoke.store.get("pid-1").get("alias") is None


def test_no_reconcile_with_empty_identity(spoke):
    spoke.store.update("old-pid", alias="core-sw", probe={"identity": {"serial": "SN123"}})
    _run(spoke._emit_probe_result("new-pid", {"identity": {}, "logged_in": False}))
    # Nothing to match on — old record must survive untouched.
    assert spoke.store.get("old-pid")["alias"] == "core-sw"
    assert spoke.store.get("new-pid").get("alias") is None


# ── Periodic re-verify of an already-identified port ────────────────────────

def test_reverify_due_when_never_checked_this_process(spoke):
    assert spoke._reverify_due("some-pid") is True


def test_reverify_not_due_immediately_after_active_identify(monkeypatch, spoke):
    async def _fake_exclusive_probe(pid, fn, *a, **kw):
        return {"identity": {"hostname": "x"}, "logged_in": True}

    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_exclusive_probe)
    _run(spoke._active_identify("pid-1", "/dev/ttyUSB0"))
    assert spoke._reverify_due("pid-1") is False


def test_reverify_due_after_interval_elapses(monkeypatch, spoke):
    spoke.config["console_identify_reverify_secs"] = 10

    async def _fake_exclusive_probe(pid, fn, *a, **kw):
        return {"identity": {"hostname": "x"}, "logged_in": True}

    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_exclusive_probe)
    _run(spoke._active_identify("pid-1", "/dev/ttyUSB0"))
    assert spoke._reverify_due("pid-1") is False

    import time as _time
    real_monotonic = _time.monotonic
    monkeypatch.setattr(cs.time, "monotonic", lambda: real_monotonic() + 20)
    assert spoke._reverify_due("pid-1") is True


def test_autoprobe_reprobes_already_identified_port_when_reverify_due(monkeypatch, spoke):
    spoke.config["auto_identify"] = True
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "pid-1", "device": "/dev/ttyUSB0"},
    ])
    spoke.store.update("pid-1", probe={"identity": {"hostname": "x"}, "logged_in": True,
                                       "source": "active"})
    calls = []

    async def _fake_active_identify(pid, dev):
        calls.append(pid)
        return {}

    monkeypatch.setattr(spoke, "_active_identify", _fake_active_identify)
    # Never verified this process lifetime → due.
    _run(spoke._autoprobe_scan())
    assert calls == ["pid-1"]


def test_autoprobe_skips_already_identified_port_when_not_due(monkeypatch, spoke):
    spoke.config["auto_identify"] = True
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "pid-1", "device": "/dev/ttyUSB0"},
    ])
    spoke.store.update("pid-1", probe={"identity": {"hostname": "x"}, "logged_in": True,
                                       "source": "active"})
    spoke._identify_verify_ts["pid-1"] = __import__("time").monotonic()  # just checked
    calls = []

    async def _fake_active_identify(pid, dev):
        calls.append(pid)
        return {}

    monkeypatch.setattr(spoke, "_active_identify", _fake_active_identify)
    _run(spoke._autoprobe_scan())
    assert calls == []


def test_replug_under_same_port_id_forces_fresh_reverify(monkeypatch, spoke):
    """A disappear+reappear cycle on the SAME port_id might be a different
    device swapped onto the same cable — never trust it stayed put."""
    spoke.config["auto_identify"] = True
    spoke.store.update("pid-1", probe={"identity": {"hostname": "x"}, "logged_in": True,
                                       "source": "active"})
    spoke._identify_verify_ts["pid-1"] = __import__("time").monotonic()  # just checked
    spoke._seen_ports = {"pid-1"}

    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])  # vanished
    _run(spoke._autoprobe_scan())
    assert "pid-1" not in spoke._identify_verify_ts

    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "pid-1", "device": "/dev/ttyUSB0"},
    ])
    calls = []

    async def _fake_active_identify(pid, dev):
        calls.append(pid)
        return {}

    monkeypatch.setattr(spoke, "_active_identify", _fake_active_identify)
    _run(spoke._autoprobe_scan())
    assert calls == ["pid-1"]
