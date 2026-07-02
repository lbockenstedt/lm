"""Hub mDNS broadcast — ``LabManagerHub`` registration lifecycle (Phase 6).

Covers ``_build_hub_service_info`` (ServiceInfo shape: port 8765, non-loopback
address, ``agent_port=8766`` TXT), ``_start_mdns_broadcast`` (registers once) /
``_stop_mdns_broadcast`` (unregisters + closes, idempotent), and the
graceful-degradation path when ``zeroconf`` is not importable (one-time warning,
no registration, no exception). A fake ``zeroconf`` module is injected into
``sys.modules`` so no real mDNS stack is needed.
"""

import os
import socket
import sys

# conftest puts core/src on sys.path so `main` imports flat.
import main  # noqa: E402


# ── fake zeroconf ────────────────────────────────────────────────────────────

class _FakeServiceInfo:
    """Captures the kwargs ServiceInfo was constructed with."""
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeZeroconf:
    instances = []

    def __init__(self):
        self.registered = []
        self.unregistered = []
        self.closed = False
        _FakeZeroconf.instances.append(self)

    def register_service(self, info):
        self.registered.append(info)

    def unregister_service(self, info):
        self.unregistered.append(info)

    def close(self):
        self.closed = True


def _fake_zeroconf_module():
    mod = type(sys)("zeroconf")
    mod.ServiceInfo = _FakeServiceInfo
    mod.Zeroconf = _FakeZeroconf
    return mod


def _make_hub(port=8765):
    """A bare LabManagerHub with just the attributes the broadcast needs."""
    hub = main.LabManagerHub.__new__(main.LabManagerHub)
    hub.port = port
    return hub


# ── _build_hub_service_info ──────────────────────────────────────────────────

def test_build_service_info_shape(monkeypatch):
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())
    hub = _make_hub(port=8765)

    info = hub._build_hub_service_info()

    assert info is not None
    kw = info.kwargs
    assert kw["type_"] == "_lm-hub._tcp.local."
    assert kw["name"] == "lm-hub._lm-hub._tcp.local."
    assert kw["port"] == 8765
    assert kw["server"] == "lm-hub.local."
    assert kw["properties"]["agent_port"] == "8766"
    assert "version" in kw["properties"]
    # At least one non-loopback IPv4 (the hub always advertises a reachable addr;
    # _local_ipv4s falls back to 127.0.0.1 only on a loopback-only box).
    addrs = kw["addresses"]
    assert len(addrs) >= 1
    # At least one advertised address is non-loopback (the UDP-connect trick in
    # _local_ipv4s finds the primary outbound interface on any routed host).
    assert any(not socket.inet_ntoa(a).startswith("127.") for a in addrs)


# ── start / stop lifecycle ───────────────────────────────────────────────────

def test_start_registers_and_stop_closes(monkeypatch):
    _FakeZeroconf.instances = []
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())
    hub = _make_hub(port=8765)

    hub._start_mdns_broadcast()

    assert hub._mdns_zconf is not None
    assert hub._mdns_info is not None
    assert len(hub._mdns_zconf.registered) == 1
    assert not hub._mdns_zconf.closed

    hub._stop_mdns_broadcast()

    assert hub._mdns_zconf is None
    assert hub._mdns_info is None
    zconf = _FakeZeroconf.instances[0]
    assert len(zconf.unregistered) == 1
    assert zconf.closed is True

    # Idempotent: a second stop is a no-op (no second close/unregister).
    hub._stop_mdns_broadcast()


def test_stop_without_start_is_noop(monkeypatch):
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    hub = _make_hub(port=8765)

    # Never started — _mdns_zconf stays None; stop must not raise.
    hub._stop_mdns_broadcast()
    assert hub._mdns_zconf is None


# ── graceful degradation (no zeroconf) ───────────────────────────────────────

def test_missing_zeroconf_skips_broadcast(monkeypatch, caplog):
    import logging
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    # `import zeroconf` raises ImportError (None in sys.modules).
    monkeypatch.setitem(sys.modules, "zeroconf", None)
    hub = _make_hub(port=8765)

    with caplog.at_level(logging.WARNING):
        info = hub._build_hub_service_info()
        hub._start_mdns_broadcast()

    assert info is None
    assert hub._mdns_zconf is None
    assert any("zeroconf not installed" in r.message for r in caplog.records)