"""Spoke-level DPA knob: CONSOLE_SET_DPA / GET_DPA / SET_DPA_PORT and the
``dpa`` descriptor the WebUI renders on each console port row."""
import asyncio
import socket
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

asyncssh = pytest.importorskip("asyncssh")

import serial_manager as sm  # noqa: E402
import console_spoke as cs  # noqa: E402
import dpa_ssh  # noqa: E402
from test_serial_manager import _FakeSerial  # noqa: E402


def _free_base(span=4):
    for _ in range(50):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            base = s.getsockname()[1]
        if 1024 <= base <= 60000:
            return base
    pytest.skip("no usable free port")


def _make_spoke(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    monkeypatch.setattr(cs, "enumerate_ports",
                        lambda: [{"port_id": "p1", "device": "/dev/ttyUSB0", "product": "FTDI"}])
    monkeypatch.setattr(dpa_ssh, "ensure_asyncssh", lambda install=True: (asyncssh, None))
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": False, "auto_identify": False})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._dpa_cfg = cs.DpaConfigStore(tmp_path / "dpa.json")
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def test_dpa_off_by_default_no_descriptor(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path)

    async def run():
        res = await sp.handle_command("CONSOLE_LIST_PORTS", {})
        got = await sp.handle_command("CONSOLE_GET_DPA", {})
        return res, got

    res, got = asyncio.run(run())
    assert res["ports"][0].get("dpa") is None
    assert got["config"]["enabled"] is False


def test_enable_ssh_shows_host_port_and_override_rebinds(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path)
    base = _free_base()

    async def run():
        r = await sp.handle_command("CONSOLE_SET_DPA", {
            "enabled": True, "ssh_bind": "127.0.0.1", "ssh_base": base,
            "advertise_host": "con01.lab", "password": "s3cret-pass", "spoke_id": "x"})
        assert r["status"] == "SUCCESS", r
        assert r["config"]["has_password"] and "password_hash" not in r["config"]
        assert r["runtime"]["host_key_fingerprint"].startswith("SHA256:")
        ports = (await sp.handle_command("CONSOLE_LIST_PORTS", {}))["ports"]
        d = ports[0]["dpa"]
        assert d["host"] == "con01.lab" and d["ssh_port"] == base and d["proto"] == "ssh"
        assert d["ssh_override"] is False

        # real SSH login through the advertised port
        conn = await asyncssh.connect("127.0.0.1", base, known_hosts=None,
                                      username="any", password="s3cret-pass")
        proc = await conn.create_process(term_type="xterm", encoding=None)
        banner = await asyncio.wait_for(proc.stdout.read(4096), 5)
        assert b"DPA connected" in banner
        conn.close()

        # user override → rebinds to the pinned port
        newp = _free_base()
        r = await sp.handle_command("CONSOLE_SET_DPA_PORT",
                                    {"port_id": "p1", "proto": "ssh", "port": newp})
        assert r["status"] == "SUCCESS", r
        assert r["dpa"]["ssh_port"] == newp and r["dpa"]["ssh_override"] is True
        assert sp.store.get("p1")["dpa_ssh_port_override"] == newp

        bad = await sp.handle_command("CONSOLE_SET_DPA_PORT",
                                      {"port_id": "p1", "proto": "ssh", "port": 22})
        assert bad["status"] == "ERROR"

        # clear → back to auto
        r = await sp.handle_command("CONSOLE_SET_DPA_PORT",
                                    {"port_id": "p1", "proto": "ssh", "port": ""})
        assert r["dpa"]["ssh_override"] is False and r["dpa"]["ssh_port"] == base

        # disable → listeners gone, descriptor gone, persisted
        r = await sp.handle_command("CONSOLE_SET_DPA", {"enabled": False})
        assert r["runtime"]["ssh_listeners"] == 0
        ports = (await sp.handle_command("CONSOLE_LIST_PORTS", {}))["ports"]
        assert ports[0].get("dpa") is None
        if sp._dpa_task:
            sp._dpa_task.cancel()

    asyncio.run(run())
    assert cs.DpaConfigStore(tmp_path / "dpa.json").effective()["enabled"] is False


def test_set_dpa_rejects_invalid(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path)
    r = asyncio.run(sp.handle_command("CONSOLE_SET_DPA", {"enabled": True, "password": "x"}))
    assert r["status"] == "ERROR"
    assert sp._dpa_cfg.effective()["enabled"] is False
