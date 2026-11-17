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


def _load(hub, monkeypatch, **access_overrides):
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
        source_owner_tenant=lambda *_a: None,
        is_admin=lambda _s: True,
        shared_tenant_id=lambda: None,
        shared_slice_prefixes=lambda _h, _t, prefixes, _m="": prefixes,
        tenant_in=lambda t, s: bool(t) and t == s,
    )
    for k, v in access_overrides.items():
        setattr(access, k, v)
    ns = {"hub": hub, "_lca": lca, "access": access, "asyncio": asyncio, "_certmon": __import__("cert_monitor"),
          "ipaddress": ipaddress, "time": time,
          "_session_user": lambda _r: {"user": {"tenants": ["ssplm"]}},
          "_effective_tenant": lambda _r, t: t,
          "_relay_spoke": _relay_spoke, "_get_dns_spoke": lambda _h: "dns-1",
          "_dns_hosts_cache": {}, "_DNS_HOSTS_TTL": 60.0}
    monkeypatch.setattr(lca.access, "is_admin", access.is_admin)
    monkeypatch.setattr(lca.access, "shared_tenant_id", access.shared_tenant_id)
    names = {"_le_certs_holder", "_le_with_certs", "_filter_le_certs",
             "_dns_hosts", "_dns_hosts_live", "_dns_prefix_nets"}
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


def test_vrf_tenant_matches_own_firewall_not_shared_dns(monkeypatch):
    # ssplm's 10.9.0.0/24 is only in its own VRF. The shared DNS module's
    # 10.9.0.5 is a different (global-table) host, so it must not count; the
    # tenant's own firewall serves its VRF, so its override does.
    hub = _Hub({})
    hub.state.system_state["global_config"]["firewalls"] = [{"spoke_id": "fw-own"}]
    hub.active_connections = {"fw-own": object()}
    hub._primary_key = lambda sid: sid

    async def _fw_records(_sid, _cmd, _payload, timeout=None):
        return {"data": [{"hostname": "fw.ssplm.lab", "ip": "10.9.0.7"}]}

    hub.request_response = _fw_records
    ns = _load(hub, monkeypatch,
               shared_slice_prefixes=lambda _h, _t, _p, _m="": [],
               source_owner_tenant=lambda _h, sid: "ssplm" if sid == "fw-own" else None)
    data = {"certs": [{"domain": "web.ssplm.lab", "domains": ["web.ssplm.lab"]},
                      {"domain": "fw.ssplm.lab", "domains": ["fw.ssplm.lab"]}]}
    out = asyncio.run(ns["_filter_le_certs"](object(), data, "ssplm"))
    assert _domains(out) == ["fw.ssplm.lab"]


def test_another_tenants_firewall_never_matches(monkeypatch):
    # Tenant "other" has its own firewall with a host at an address that is
    # inside ssplm's global-table prefix. That address lives in other's VRF, so
    # its hostname must not make the cert visible to ssplm.
    hub = _Hub({})
    hub.state.system_state["global_config"]["firewalls"] = [{"spoke_id": "fw-other"}]
    hub.active_connections = {"fw-other": object()}
    hub._primary_key = lambda sid: sid
    asked = []

    async def _fw_records(sid, _cmd, _payload, timeout=None):
        asked.append(sid)
        return {"data": [{"hostname": "secret.other.lab", "ip": "10.9.0.7"}]}

    hub.request_response = _fw_records
    ns = _load(hub, monkeypatch,
               source_owner_tenant=lambda _h, sid: "other" if sid == "fw-other" else None)
    data = {"certs": [{"domain": "web.ssplm.lab", "domains": ["web.ssplm.lab"]},
                      {"domain": "secret.other.lab", "domains": ["secret.other.lab"]}]}
    out = asyncio.run(ns["_filter_le_certs"](object(), data, "ssplm"))
    assert _domains(out) == ["web.ssplm.lab"]
    # The other tenant's firewall is never even asked.
    assert asked == []


def test_vrf_tenant_reads_its_own_resolver_when_not_first(monkeypatch):
    # The shared resolver and another tenant's resolver connected before
    # ssplm's own. ssplm's host must still count, and only its own resolver
    # (plus no foreign one) is asked.
    hub = _Hub({})
    hub.get_all_spokes_by_type = lambda _t: ["dns-shared", "dns-other", "dns-own"]
    owners = {"dns-other": "other", "dns-own": "ssplm"}
    records = {
        "dns-shared": [{"type": "A", "name": "web.ssplm.lab", "value": "10.9.0.5"}],
        "dns-other": [{"type": "A", "name": "secret.other.lab", "value": "10.9.0.6"}],
        "dns-own": [{"type": "A", "name": "own.ssplm.lab", "value": "10.9.0.7"}],
    }
    asked = []
    ns = _load(hub, monkeypatch,
               shared_slice_prefixes=lambda _h, _t, _p, _m="": [],
               source_owner_tenant=lambda _h, sid: owners.get(sid))

    async def _relay(sid, _cmd, **_kw):
        asked.append(sid)
        return {"records": records[sid]}

    ns["_relay_spoke"] = _relay
    data = {"certs": [{"domain": d, "domains": [d]}
                      for d in ("web.ssplm.lab", "secret.other.lab", "own.ssplm.lab")]}
    out = asyncio.run(ns["_filter_le_certs"](object(), data, "ssplm"))
    assert _domains(out) == ["own.ssplm.lab"]
    assert "dns-other" not in asked


def test_vrf_only_tenant_with_only_shared_dns_does_not_fail_open(monkeypatch):
    # ssplm's prefixes are all in its own VRF, the only DNS source is the
    # shared resolver, and no firewall is connected. Skipping the shared
    # resolver is a known "no hosts", not an outage, so no unowned cert shows.
    hub = _Hub({})
    hub.get_all_spokes_by_type = lambda _t: ["dns-shared"]
    ns = _load(hub, monkeypatch, shared_slice_prefixes=lambda _h, _t, _p, _m="": [])
    data = {"certs": [{"domain": "web.ssplm.lab", "domains": ["web.ssplm.lab"]},
                      {"domain": "x.other.lab", "domains": ["x.other.lab"]}]}
    out = asyncio.run(ns["_filter_le_certs"](object(), data, "ssplm"))
    assert _domains(out) == []


def _foreign_and_own_dns(hub, monkeypatch, sids):
    """Load with these DNS spokes: "dns-other" belongs to tenant other and
    "dns-own" to ssplm, whose own resolver is down."""
    hub.get_all_spokes_by_type = lambda _t: sids
    owners = {"dns-other": "other", "dns-own": "ssplm"}
    ns = _load(hub, monkeypatch, source_owner_tenant=lambda _h, sid: owners.get(sid))

    async def _relay(sid, _cmd, **_kw):
        assert sid != "dns-other"
        raise RuntimeError("resolver down")

    ns["_relay_spoke"] = _relay
    return ns


_TWO_CERTS = {"certs": [{"domain": "web.ssplm.lab", "domains": ["web.ssplm.lab"]},
                        {"domain": "x.other.lab", "domains": ["x.other.lab"]}]}


def test_own_resolver_outage_still_fails_open_beside_a_foreign_one(monkeypatch):
    # The tenant's own resolver is down; another tenant's (skipped) resolver
    # is no evidence the tenant's hosts were checked, so the outage fail-open
    # still applies.
    ns = _foreign_and_own_dns(_Hub({}), monkeypatch, ["dns-other", "dns-own"])
    out = asyncio.run(ns["_filter_le_certs"](object(), _TWO_CERTS, "ssplm"))
    assert _domains(out) == ["web.ssplm.lab", "x.other.lab"]


def test_own_resolver_outage_fails_open_beside_a_skipped_shared_one(monkeypatch):
    # VRF-only tenant: the shared resolver is cut (skipped) and its own
    # resolver is down. The skip must not hide the outage.
    hub = _Hub({})
    hub.get_all_spokes_by_type = lambda _t: ["dns-shared", "dns-own"]
    ns = _load(hub, monkeypatch, shared_slice_prefixes=lambda _h, _t, _p, _m="": [],
               source_owner_tenant=lambda _h, sid: {"dns-own": "ssplm"}.get(sid))

    async def _relay(sid, _cmd, **_kw):
        assert sid == "dns-own"
        raise RuntimeError("resolver down")

    ns["_relay_spoke"] = _relay
    out = asyncio.run(ns["_filter_le_certs"](object(), _TWO_CERTS, "ssplm"))
    assert _domains(out) == ["web.ssplm.lab", "x.other.lab"]


def test_resolver_outage_never_shows_another_tenants_owned_cert(monkeypatch):
    # The fail-open covers certs with no owners only: a cert explicitly owned
    # by another tenant stays hidden even while the tenant's resolver is down.
    hub = _Hub({"x.other.lab": ["other"]})
    ns = _foreign_and_own_dns(hub, monkeypatch, ["dns-own"])
    out = asyncio.run(ns["_filter_le_certs"](object(), _TWO_CERTS, "ssplm"))
    assert _domains(out) == ["web.ssplm.lab"]


def test_only_a_foreign_resolver_does_not_fail_open(monkeypatch):
    # The only resolver belongs to another tenant: there is nothing of this
    # tenant's to be down, so unowned certs stay hidden.
    ns = _foreign_and_own_dns(_Hub({}), monkeypatch, ["dns-other"])
    out = asyncio.run(ns["_filter_le_certs"](object(), _TWO_CERTS, "ssplm"))
    assert _domains(out) == []


def test_source_owner_tenant_reads_instance_records():
    # A spoke with no tenant binding is owned through the instance records
    # that point at it; records naming two tenants make it shared.
    hub = _Hub({})
    hub.state.get_spoke_tenant = lambda _sid: ""
    gc = hub.state.system_state["global_config"]
    gc["dns_instances"] = [{"tenant_id": "dxp", "spoke_id": "dns-own"}]
    gc["firewalls"] = [{"tenant_id": "a", "spoke_id": "fw-x"},
                       {"tenant_id": "b", "spoke_id": "fw-x"}]
    assert lca.access.source_owner_tenant(hub, "dns-own") == "dxp"
    assert lca.access.source_owner_tenant(hub, "fw-x") is None
    assert lca.access.source_owner_tenant(hub, "dns-shared") is None
