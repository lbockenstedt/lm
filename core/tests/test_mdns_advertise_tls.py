"""Hub mDNS TXT advertisement — the ``advertise_tls`` gate (root cause of the
generic-leaf-agent ``ws://<hub>:443`` → ``InvalidMessage`` failure).

The hub always registers ``_lm-hub._tcp.local.`` on port 443 (``srv_port =
tls_port``), and ``discover_hub_url`` returns ``wss://`` ONLY when a ``tls_port``
TXT is present. That TXT was gated on ``tls_enabled`` (hub owns a cert), so a
reverse-proxy / TLS-termination deployment — hub serves plaintext behind the
proxy (no cert → ``tls_enabled`` False) yet callers dial ``wss://<proxy>:443``
— advertised no ``tls_port`` → discovery returned ``ws://<ip>:443`` → a plaintext
WebSocket handshake to a TLS port failed "did not receive a valid HTTP response".

Fix: ``advertise_tls`` (``tls_enabled`` OR ``LM_HUB_ADVERTISE_TLS=1``) gates the
``tls_port`` TXT, decoupling "callers reach me over TLS" from "I own the cert".
``_mdns_hub_properties`` is pure so the gate is testable without constructing a
LabManagerHub (which starts servers / needs LM_FERNET_KEY at construction).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from main import _mdns_hub_properties  # noqa: E402


def test_no_tls_advertised_when_neither_cert_nor_flag():
    p = _mdns_hub_properties("1.2.3", 8443, 443, advertise_tls=False)
    assert p == {"version": "1.2.3", "agent_port": "8443"}
    assert "tls_port" not in p   # → discovery returns ws://<ip>:443 (plaintext)


def test_tls_advertised_when_hub_owns_cert():
    p = _mdns_hub_properties("1.2.3", 8443, 443, advertise_tls=True)
    assert p["tls_port"] == "443"   # → discovery returns wss://<ip>:443


def test_tls_advertised_for_proxy_deployment_via_flag():
    """tls_enabled False (no cert) but LM_HUB_ADVERTISE_TLS=1 → still advertise
    tls_port so discovery returns wss:// for the proxy-terminated 443."""
    p = _mdns_hub_properties("1.2.3", 8443, 443, advertise_tls=True)
    assert p["tls_port"] == "443"


def test_agent_port_always_advertised():
    """pxmx agents read agent_port from the TXT regardless of TLS state."""
    for adv in (False, True):
        p = _mdns_hub_properties("v", 8766, 443, advertise_tls=adv)
        assert p["agent_port"] == "8766"