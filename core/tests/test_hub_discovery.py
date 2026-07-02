"""LM hub auto-discovery — DNS name + mDNS broadcast (Phase 6).

Covers ``messaging.hub_discovery.discover_hub_url`` (the standalone helper
vendored into pxmx + the pxmx agent). The DNS path resolves ``lm-hub.<search
domain>`` from a tmp ``/etc/resolv.conf`` via a faked ``socket.getaddrinfo``; the
mDNS path browses ``_lm-hub._tcp.local.`` via a fake ``zeroconf`` module injected
into ``sys.modules``; ``port_override`` targets the agent listener (8766); the
``None`` case + graceful degradation (no ``zeroconf`` → DNS-only) round it out.
A bash ``-n`` check on the three touched install scripts guards the install-time
discovery wiring.
"""

import os
import socket
import sys
import tempfile

# conftest puts core/src on sys.path so `messaging.hub_discovery` imports flat.
from messaging import hub_discovery as hd  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _write_resolv(path: str, search_line: str) -> None:
    with open(path, "w") as f:
        f.write(search_line)


def _fake_getaddrinfo(hit_name, ip="10.0.0.7"):
    """A getaddrinfo that resolves only ``hit_name`` to a non-loopback IPv4."""
    def _ga(name, port, family, type_, *a, **k):
        if name == hit_name:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]
        return []
    return _ga


def _no_zeroconf(monkeypatch):
    """Simulate zeroconf-not-installed: `import zeroconf` raises ImportError."""
    monkeypatch.setitem(sys.modules, "zeroconf", None)


class _FakeServiceInfo:
    def __init__(self, ip, port):
        self.addresses = [socket.inet_aton(ip)]
        self.port = port


class _FakeZeroconf:
    def __init__(self):
        self.closed = False
        self.unregistered = []

    def get_service_info(self, type_, name, timeout=2000):
        return _FakeServiceInfo("10.0.0.5", 8765)

    def unregister_service(self, info):
        self.unregistered.append(info)

    def close(self):
        self.closed = True


class _FakeServiceBrowser:
    """Delivers the hub service to the listener synchronously on construction."""
    def __init__(self, zc, type_, listener):
        listener.add_service(zc, type_, "lm-hub._lm-hub._tcp.local.")


def _fake_zeroconf_module():
    mod = type(sys)("zeroconf")
    mod.Zeroconf = _FakeZeroconf
    mod.ServiceBrowser = _FakeServiceBrowser
    return mod


# ── DNS path ─────────────────────────────────────────────────────────────────

def test_dns_resolves_search_domain(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search example.com\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("lm-hub.example.com"))
    _no_zeroconf(monkeypatch)  # DNS-only path

    url = hd.discover_hub_url(timeout=2.0)

    assert url == "ws://lm-hub.example.com:8765"


def test_dns_port_override_targets_agent_listener(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search corp.local\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("lm-hub.corp.local"))
    _no_zeroconf(monkeypatch)

    url = hd.discover_hub_url(timeout=2.0, port_override=8766)

    assert url == "ws://lm-hub.corp.local:8766"


# ── mDNS path ────────────────────────────────────────────────────────────────

def test_mdns_path_when_dns_misses(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search example.com\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    # DNS resolves nothing (every candidate misses).
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("__none__"))
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())

    url = hd.discover_hub_url(timeout=2.0)

    assert url == "ws://10.0.0.5:8765"


def test_mdns_port_override_uses_agent_port(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search example.com\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("__none__"))
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())

    url = hd.discover_hub_url(timeout=2.0, port_override=8766)

    assert url == "ws://10.0.0.5:8766"


# ── None + graceful degradation ──────────────────────────────────────────────

def test_returns_none_when_nothing_resolves(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search example.com\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("__none__"))
    _no_zeroconf(monkeypatch)  # no DNS hit, no mDNS available

    assert hd.discover_hub_url(timeout=2.0) is None


def test_dns_only_works_without_zeroconf(monkeypatch, tmp_path):
    """Missing zeroconf degrades to DNS-only — the hub/spoke still function."""
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search example.com\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("lm-hub.example.com"))
    _no_zeroconf(monkeypatch)

    # No mDNS available, but DNS still locates the hub.
    assert hd.discover_hub_url(timeout=2.0) == "ws://lm-hub.example.com:8765"


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_main_cli_prints_url_or_none(monkeypatch, tmp_path, capsys):
    resolv = tmp_path / "resolv.conf"
    _write_resolv(str(resolv), "search example.com\n")
    monkeypatch.setattr(hd, "_RESOLV_CONF", str(resolv))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("lm-hub.example.com"))
    _no_zeroconf(monkeypatch)

    monkeypatch.setattr(sys, "argv", ["hub_discovery", "--timeout", "2"])
    rc = hd._main()
    out = capsys.readouterr().out.strip()

    assert rc == 0
    assert out == "ws://lm-hub.example.com:8765"


# ── install scripts parse cleanly ────────────────────────────────────────────

def test_install_scripts_syntax_clean():
    """bash -n the three installers touched by the discovery wiring."""
    import subprocess
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    scripts = [
        os.path.join(root, "cs", "lm-spoke", "install_cs.sh"),
        os.path.join(root, "pxmx", "install_pxmx.sh"),
        os.path.join(root, "pxmx", "agent", "install_agent.sh"),
    ]
    for s in scripts:
        assert os.path.isfile(s), f"missing installer: {s}"
        r = subprocess.run(["bash", "-n", s], capture_output=True, text=True)
        assert r.returncode == 0, f"bash -n failed for {s}:\n{r.stderr}"