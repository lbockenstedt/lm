import asyncio
import os
import sys
import tempfile

os.environ.setdefault("LM_MTLS_CLIENT_CA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes import agents  # noqa: E402


class Hub:
    def __init__(self, proxy_ok=True):
        self.proxy_ok = proxy_ok
        self.state = self
        self.system_state = {}
        self.roles = {"pk-proxy": ["zbxproxy"], "pk-other": ["dns-server"]}
        self.tenants = {"pk-proxy": "lrb", "pk-node": "lrb", "pk-other": "lrb"}

    def _agent_roles_store(self):
        return self.roles

    def _primary_key(self, sid):
        return sid

    def get_spoke_tenant(self, pk):
        return self.tenants.get(pk)

    async def request_response(self, sid, cmd, data, timeout=0):
        if sid == "pk-proxy":
            if not self.proxy_ok:
                raise RuntimeError("offline")
            return {"payload": {"data": {"status": "SUCCESS", "ip": "10.1.2.3", "hostname": "px"}}}
        return {"payload": {"data": {"status": "SUCCESS", "ip": "10.1.2.9", "hostname": "pxmx-01"}}}


def test_agent_points_at_tenant_proxy():
    cfg = asyncio.run(agents._zbxagent_load_config(Hub(), {}, "pk-node"))
    assert cfg["proxy"] == "10.1.2.3:10051"
    assert cfg["hostname"] == "lrb--pxmx-01"
    assert cfg["tls_subject"] == "lrb--pxmx-01" and "BEGIN CERTIFICATE" in cfg["tls_cert_pem"]


def test_agent_without_proxy_is_rejected():
    try:
        asyncio.run(agents._zbxagent_load_config(Hub(proxy_ok=False), {}, "pk-node"))
    except Exception as e:  # noqa: BLE001
        assert "No online Monitoring Proxy" in str(e.detail)
    else:
        raise AssertionError("expected rejection")
