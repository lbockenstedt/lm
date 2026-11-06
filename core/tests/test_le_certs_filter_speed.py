"""The Certificates page with a tenant selected was slow: every load pulled
every DNS record and each firewall's DNS overrides (one firewall at a time)
to map cert SANs to the tenant's subnets — even when every cert had explicit
owners, which decide visibility without DNS.

``_filter_le_certs`` now skips the DNS lookup when no cert needs it, and
``_dns_hosts`` caches its result briefly. The closures are lifted out of
net_services with ``ast`` (same approach as test_le_certs_tenant_tagging)."""
import ast
import asyncio
import ipaddress
import os
import sys
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import le_cert_access as lca  # noqa: E402

_NS = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "net_services.py")


class _Hub:
    def __init__(self, owners):
        self.state = types.SimpleNamespace(
            system_state={"global_config": {lca.STORE_KEY: owners}},
            tenant_state={"tenants": {}})
        self.active_connections = {}
        self.dns_calls = 0

    def get_spoke_by_type(self, _t):
        return "le-1"


def _load(hub, monkeypatch):
    async def _relay_spoke(_sid, cmd, **_kw):
        hub.dns_calls += 1
        return {"records": [{"type": "A", "name": "web.ssplm.lab", "value": "10.9.0.5"}]}

    async def _prefixes(_hub, _tid):
        return ["10.9.0.0/24"]

    access = types.SimpleNamespace(
        filter_enabled=lambda _h, _m: True,
        resolve_prefixes_for_tenant=_prefixes,
        _norm_tenant_id=lambda t: t,
        tenant_left_shared=lambda *_a: False,
        spoke_owner_tenant=lambda *_a: None,
        is_admin=lambda _s: True,
        shared_tenant_id=lambda: None,
    )
    ns = {"hub": hub, "_lca": lca, "access": access, "asyncio": asyncio,
          "ipaddress": ipaddress, "time": time,
          "_session_user": lambda _r: {"user": {"tenants": ["ssplm"]}},
          "_effective_tenant": lambda _r, t: t,
          "_relay_spoke": _relay_spoke, "_get_dns_spoke": lambda _h: "dns-1",
          "_dns_hosts_cache": {}, "_DNS_HOSTS_TTL": 60.0}
    monkeypatch.setattr(lca.access, "is_admin", access.is_admin)
    monkeypatch.setattr(lca.access, "shared_tenant_id", access.shared_tenant_id)
    names = {"_le_certs_holder", "_le_with_certs", "_filter_le_certs",
             "_dns_hosts", "_dns_hosts_live"}
    for node in ast.walk(ast.parse(open(_NS).read())):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _NS, "exec"), ns)
    return ns


def _domains(out):
    return sorted(c["domain"] for c in out["certs"])


def test_owned_certs_skip_the_dns_lookup(monkeypatch):
    hub = _Hub({"a.ssplm.lab": ["ssplm"], "b.other.lab": ["other"]})
    ns = _load(hub, monkeypatch)
    data = {"certs": [{"domain": "a.ssplm.lab"}, {"domain": "b.other.lab"}]}
    out = asyncio.run(ns["_filter_le_certs"](object(), data, "ssplm"))
    assert _domains(out) == ["a.ssplm.lab"]
    assert hub.dns_calls == 0


def test_unowned_cert_uses_dns_and_caches_it(monkeypatch):
    hub = _Hub({})
    ns = _load(hub, monkeypatch)
    data = {"certs": [{"domain": "web.ssplm.lab", "domains": ["web.ssplm.lab"]},
                      {"domain": "x.elsewhere.lab", "domains": ["x.elsewhere.lab"]}]}
    for _ in range(3):
        out = asyncio.run(ns["_filter_le_certs"](object(), data, "ssplm"))
        assert _domains(out) == ["web.ssplm.lab"]
    assert hub.dns_calls == 1
