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
    sp.devices = sm.DeviceCache(path=tmp_path / "devices.json")
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


# ── DeviceCache fallback: alias/tenant survive even a ports.json WIPE ───────
# (e.g. a console-code update that changes derive_port_id's format, or the
# agent's state dir being recreated) — not just an ordinary port_id-preserving
# restart, which PortStore.find_by_identity alone already covers.

def test_emit_probe_result_populates_device_cache(spoke):
    _run(spoke._emit_probe_result("pid-1", {
        "vendor": "ARUBA-AOS-CX",
        "identity": {"hostname": "core-sw", "serial": "SN123"},
        "logged_in": True,
    }))
    cached = spoke.devices.lookup({"serial": "SN123"})
    assert cached is not None
    assert cached["port_id"] == "pid-1"


def test_reconcile_recovers_alias_from_device_cache_when_ports_json_has_no_match(spoke):
    # Simulate the gap: devices.json remembers the device from BEFORE an
    # upgrade that changed port_id derivation (or wiped ports.json outright),
    # but ports.json itself has no record of it under ANY port_id.
    spoke.devices.remember({"serial": "SN123"}, port_id="old-format-pid",
                           alias="core-sw", tenant_id="lrb")
    assert spoke.store.all_items() == {}

    _run(spoke._emit_probe_result("new-pid", {
        "identity": {"serial": "SN123"}, "logged_in": True,
    }))

    assert spoke.store.get("new-pid")["alias"] == "core-sw"
    assert spoke.store.get("new-pid")["tenant_id"] == "lrb"


def test_reconcile_prefers_ports_json_match_over_device_cache(spoke):
    # ports.json (keyed by port_id, same-session history) is the primary
    # source; the device cache is only consulted when ports.json has nothing.
    spoke.store.update("old-pid", alias="fresh-alias",
                       probe={"identity": {"serial": "SN123"}})
    spoke.devices.remember({"serial": "SN123"}, port_id="ancient-pid", alias="stale-alias")

    _run(spoke._emit_probe_result("new-pid", {
        "identity": {"serial": "SN123"}, "logged_in": True,
    }))

    assert spoke.store.get("new-pid")["alias"] == "fresh-alias"


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


# ── Last-known profile survives failed / blank probes (update restart wipe) ──

def _named(spoke, pid="pid-1"):
    _run(spoke._emit_probe_result(pid, {
        "vendor": "ARUBA-AOS-CX",
        "identity": {"hostname": "core-sw", "serial": "SN123", "model": "6300", "type": "switch"},
        "logged_in": True,
    }))


def test_failed_probe_keeps_last_known_identity(spoke):
    _named(spoke)
    _run(spoke._emit_probe_result("pid-1", {
        "identity": {}, "logged_in": False, "error": "no output after 6 Enter nudge(s) — silent"}))
    p = spoke.store.get("pid-1")["probe"]
    assert p["identity"]["hostname"] == "core-sw"
    assert p["identity"]["serial"] == "SN123"
    assert p["vendor"] == "ARUBA-AOS-CX"
    assert p["stale"] is True
    assert "silent" in p["error"]
    assert spoke._probe_identified(p) is False  # keep retrying until re-confirmed


def test_partial_probe_merges_field_by_field(spoke):
    _named(spoke)
    _run(spoke._emit_probe_result("pid-1", {"identity": {"hostname": "core-sw-renamed"},
                                            "logged_in": True}))
    p = spoke.store.get("pid-1")["probe"]
    assert p["identity"] == {"hostname": "core-sw-renamed", "serial": "SN123",
                             "model": "6300", "type": "switch"}
    assert p["vendor"] == "ARUBA-AOS-CX"
    assert not p.get("stale")
    assert spoke._probe_identified(p) is True


def test_swapped_device_replaces_identity_wholesale(spoke):
    _named(spoke)
    _run(spoke._emit_probe_result("pid-1", {"identity": {"hostname": "other", "serial": "SN999"},
                                            "logged_in": True}))
    p = spoke.store.get("pid-1")["probe"]
    assert p["identity"] == {"hostname": "other", "serial": "SN999"}
    assert p["vendor"] is None


def test_blank_probe_on_known_port_does_not_repush_to_hub(spoke):
    sent = []

    class _CP:
        async def send_to_hub(self, t, payload):
            sent.append(payload)

    spoke.control_plane = _CP()
    _named(spoke)
    _run(spoke._emit_probe_result("pid-1", {"identity": {}, "logged_in": False}))
    assert len(sent) == 1


def test_restore_last_known_from_port_cache_hostname_only(spoke):
    spoke.devices.remember({"hostname": "MIA-GW-01"}, port_id="pid-1", vendor="FORTIOS")
    spoke.store.update("pid-1", probe={"identity": {}, "vendor": None, "source": "active"})
    spoke._restore_last_known()
    p = spoke.store.get("pid-1")["probe"]
    assert p["identity"] == {"hostname": "MIA-GW-01"}
    assert p["vendor"] == "FORTIOS"
    assert p["stale"] is True and p["restored_from"] == "device_cache"
    assert spoke._probe_identified(p) is False


def test_restore_last_known_from_hostname_history(spoke):
    spoke.store.update("pid-2", probe={"identity": {}, "source": "active"})
    spoke._health["pid-2"] = {"identify": {"hostname_history": [
        {"host": "old", "ts": 1}, {"host": "Aruba7008_21_FE_CC", "ts": 2}]}}
    spoke._restore_last_known()
    p = spoke.store.get("pid-2")["probe"]
    assert p["identity"] == {"hostname": "Aruba7008_21_FE_CC"}
    assert p["restored_from"] == "hostname_history"


def test_restore_skips_a_name_another_port_holds(spoke):
    spoke.store.update("pid-1", probe={"identity": {"hostname": "MIA-SW-AOSS"}, "source": "active"})
    spoke.store.update("pid-2", probe={"identity": {}, "source": "active"})
    spoke._health["pid-2"] = {"identify": {"hostname_history": [{"host": "mia-sw-aoss", "ts": 1}]}}
    spoke._restore_last_known()
    assert spoke.store.get("pid-2")["probe"]["identity"] == {}


def test_restore_skips_a_name_several_ports_claim(spoke):
    for pid in ("pid-2", "pid-3"):
        spoke.store.update(pid, probe={"identity": {}, "source": "active"})
        spoke._health[pid] = {"identify": {"hostname_history": [{"host": "MIA-SW-AOSS", "ts": 1}]}}
    spoke.store.update("pid-4", probe={"identity": {}, "source": "active"})
    spoke._health["pid-4"] = {"identify": {"hostname_history": [{"host": "MIA-GW-01", "ts": 1}]}}
    spoke._restore_last_known()
    assert spoke.store.get("pid-2")["probe"]["identity"] == {}
    assert spoke.store.get("pid-3")["probe"]["identity"] == {}
    assert spoke.store.get("pid-4")["probe"]["identity"] == {"hostname": "MIA-GW-01"}


def test_restore_clears_an_earlier_duplicate_restore(spoke):
    spoke.store.update("pid-1", probe={"identity": {"hostname": "MIA-SW-AOSS"}, "source": "active"})
    spoke.store.update("pid-2", probe={"identity": {"hostname": "MIA-SW-AOSS"}, "source": "restored",
                                       "stale": True, "restored_from": "hostname_history"})
    spoke._health["pid-2"] = {"identify": {"hostname_history": [{"host": "MIA-SW-AOSS", "ts": 1}]}}
    spoke._restore_last_known()
    p = spoke.store.get("pid-2")["probe"]
    assert p["identity"] == {} and p["source"] == "active" and not p["stale"]


def test_restore_never_overrides_existing_identity(spoke):
    spoke.devices.remember({"hostname": "cached"}, port_id="pid-1")
    spoke.store.update("pid-1", probe={"identity": {"hostname": "live"}, "source": "active"})
    spoke._restore_last_known()
    assert spoke.store.get("pid-1")["probe"]["identity"] == {"hostname": "live"}


def test_device_cache_backfills_missing_fields_after_ports_json_wipe(spoke):
    spoke.devices.remember({"serial": "SN123", "hostname": "core-sw", "model": "6300"},
                           port_id="old-pid", vendor="ARUBA-AOS-CX")
    _run(spoke._emit_probe_result("new-pid", {"identity": {"serial": "SN123"}, "logged_in": True}))
    p = spoke.store.get("new-pid")["probe"]
    assert p["identity"]["hostname"] == "core-sw" and p["identity"]["model"] == "6300"
    assert p["vendor"] == "ARUBA-AOS-CX"


def test_restore_skips_placeholder_hostnames_in_history(spoke):
    spoke.store.update("pid-3", probe={"identity": {}, "source": "active"})
    spoke._health["pid-3"] = {"identify": {"hostname_history": [
        {"host": "BO-SYD-ACSW02", "ts": 1}, {"host": "hostname", "ts": 2}]}}
    spoke._restore_last_known()
    assert spoke.store.get("pid-3")["probe"]["identity"] == {"hostname": "BO-SYD-ACSW02"}


def test_restore_clears_a_previously_restored_placeholder(spoke):
    spoke.store.update("pid-4", probe={"identity": {"hostname": "hostname"}, "source": "restored",
                                       "stale": True, "restored_from": "hostname_history"})
    spoke._health["pid-4"] = {"identify": {"hostname_history": [{"host": "hostname", "ts": 2}]}}
    spoke._restore_last_known()
    p = spoke.store.get("pid-4")["probe"]
    assert p["identity"] == {} and not p.get("stale")


def test_placeholder_hostname_is_not_profiled(spoke):
    assert spoke._probe_identified({"source": "active", "identity": {"hostname": "hostname"}}) is False
    assert spoke._probe_identified({"source": "active", "identity": {"hostname": "SW1"}}) is True


def test_successful_reidentify_clears_stale_flag(spoke):
    _named(spoke)
    _run(spoke._emit_probe_result("pid-1", {"identity": {}, "logged_in": False}))
    assert spoke.store.get("pid-1")["probe"]["stale"] is True
    _run(spoke._emit_probe_result("pid-1", {"identity": {"hostname": "core-sw"}, "logged_in": True}))
    p = spoke.store.get("pid-1")["probe"]
    assert p["stale"] is False and p["restored_from"] == ""
    assert spoke._probe_identified(p) is True
