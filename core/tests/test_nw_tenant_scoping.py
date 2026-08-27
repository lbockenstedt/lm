"""Network Devices (nw) hub-route tenant scoping — Stage 4.

Exercises the REAL ``routes.nw.register`` route closures against a fake hub
whose ``request_response`` simulates per-tenant nw spokes (Stage 1 spoke-side
tenant filter) + an IPAM spoke for prefix resolution. The nw routes are
registered directly on a minimal FastAPI app with a hand-built ctx (the same
closures ``api.create_app`` builds), so the ``nw`` module-right middleware
gate, the route closures, and the ``NwCacheMixin`` integration all run without
mounting the simulations routes (which use 3.10+-only annotations and so
cannot run under the local 3.9 interpreter). Locks in:

  * GET /api/nw/devices — admin sees all; non-admin sees own + shared only
    (other-tenant rows never surface); the hub config is the authoritative
    visibility gate (a stale/leaky spoke row is dropped).
  * GET /api/nw/devices offline — the single global cache is served
    tenant-filtered (``nw_cache_get_fleet_filtered``), never whole to a
    non-admin (the leak regression).
  * GET /api/nw/{id}/{endpoint} — own-tenant device: ``full`` scope, no IP
    filter (returns all rows); shared device: ``filtered`` scope, ``_filter_nw``
    narrows to the viewer's in-prefix rows; other-tenant device: 403; unknown:
    404. The relay resolves the spoke from the record's ``spoke_id``
    (per-tenant), not the single global resolver.
  * POST /api/nw/{id}/config — admin-only; relays to the record's spoke.
"""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from types import SimpleNamespace

import api as api_mod
import access as access_mod
from nw_cache import NwCacheMixin


# ── Fakes ────────────────────────────────────────────────────────────────────

class _NwState:
    def __init__(self, data_dir, system_state, tenant_state=None):
        self.data_dir = data_dir
        self.system_state = system_state
        self.tenant_state = tenant_state or {"tenants": {}}

    def ensure_admin_lockout(self):
        return False

    def save_state(self):
        pass

    def _mark_dirty(self):
        pass

    async def _flush_if_dirty(self):
        pass

    def get_global_config(self):
        return self.system_state.get("global_config", {})

    def get_tenant(self, tid):
        return (self.tenant_state.get("tenants") or {}).get(tid)


class _NwHub(NwCacheMixin):
    """Fake hub: NwCacheMixin (real cache) + the registry + relay methods the
    nw routes touch. ``request_response`` simulates per-tenant nw spokes
    (applying the Stage 1 spoke-side tenant filter) + an IPAM spoke returning
    the acme tenant's prefixes for subnet filtering. The two ``get_nw_spoke_*``
    resolvers are faithful copies of ``hub_spoke_registry`` so the routes
    resolve per-tenant spokes without importing ``main`` (which needs a Fernet
    key at import time)."""

    def __init__(self, data_dir, system_state, tenant_state, spokes,
                 metadata, spoke_fleet, canned_rows, cache_dir):
        self.cache_dir = cache_dir
        self.state = _NwState(data_dir, system_state, tenant_state)
        self.nw_cache_init()
        self.active_connections = set(spokes) | {"ipam-spoke"}
        self.approved_modules = {s: True for s in self.active_connections}
        self.spoke_module_types = {s: "nw" for s in spokes}
        self.spoke_module_types["ipam-spoke"] = "ipam"
        self._metadata = metadata
        self._spoke_fleet = spoke_fleet          # {spoke_id: [fleet rows]}
        self._canned_rows = canned_rows          # {NW_GET cmd: [rows]}
        self.calls = []

    # ── registry ──
    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, t):
        if t == "ipam":
            return "ipam-spoke"
        nw = [s for s, m in self.spoke_module_types.items() if m == t]
        return nw[0] if nw else None

    def get_all_spokes_by_type(self, t):
        if t == "ipam":
            return ["ipam-spoke"] if "ipam-spoke" in self.active_connections else []
        return [s for s, m in self.spoke_module_types.items() if m == t]

    def get_nw_spoke_for_tenant(self, tenant_id=None):
        # Faithful copy of hub_spoke_registry.get_nw_spoke_for_tenant.
        if not tenant_id or tenant_id == "default":
            return self.get_spoke_by_type("nw")
        cands = [sid for sid in (self.get_all_spokes_by_type("nw") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        if not cands:
            return None
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
        return bound[0] if bound else None

    def get_nw_spoke_for_shared(self):
        # Faithful copy of hub_spoke_registry.get_nw_spoke_for_shared.
        sid = access_mod.shared_tenant_id()
        return self.get_nw_spoke_for_tenant(sid) if sid else self.get_spoke_by_type("nw")

    # ── relay ──
    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        self.calls.append((spoke_id, cmd, data))
        if cmd == "NW_LIST_DEVICES":
            tenant = (data or {}).get("tenant")
            rows = list(self._spoke_fleet.get(spoke_id, []))
            if tenant:
                shared = access_mod.shared_tenant_id()
                rows = [r for r in rows
                        if r.get("tenant_id") == tenant
                        or (bool(shared) and r.get("tenant_id") == shared)]
            return {"payload": {"data": {"status": "SUCCESS", "data": rows}}}
        if cmd == "NETBOX_GET_PREFIXES":
            # acme tenant's prefixes — 10.0.0.0/24 is in-tenant.
            return {"payload": {"data": {"prefixes": [{"prefix": "10.0.0.0/24"}]}}}
        if cmd.startswith("NW_GET"):
            return {"payload": {"data": {"status": "SUCCESS",
                                        "data": list(self._canned_rows.get(cmd, []))}}}
        if cmd == "NW_RUN_CONFIG":
            return {"payload": {"data": {"status": "SUCCESS",
                                         "applied": [], "errors": []}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _ensure_loop():
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    api_mod._sessions.clear()
    api_mod._login_attempts.clear()
    api_mod._login_ip_attempts.clear()
    api_mod._tenant_cache.clear()
    # No shared tenant unless a test opts in.
    monkeypatch.setattr(access_mod, "_SHARED_TENANT_ID", None)
    monkeypatch.setattr(access_mod, "shared_tenant_id", lambda: access_mod._SHARED_TENANT_ID)


def _mint(hub, uid, tenants, rights=("nw",), role=None, admin=False):
    perms = {}
    if admin:
        perms = {"role": "admin", "admin": True}
    elif role:
        perms = {"role": role}
        perms.update({r: True for r in rights})
    else:
        perms = {r: True for r in rights}
    user_data = {"user_id": uid, "auth_type": "local", "permissions": perms,
                 "tenants": list(tenants),
                 "tenant_id": tenants[0] if tenants else None, "protected": False}
    return api_mod._record_session(hub, user_data)


# The fleet: per-tenant nw spokes each holding their tenant's devices. acme
# spoke holds acme-sw; othercorp spoke holds other-sw; the shared spoke holds
# shared-sw. Each device record's spoke_id points at its owning spoke.
_ACME_SW = {"id": "acme-sw", "name": "acme", "object_type": "cx_switch",
            "address": "10.0.0.2", "tenant_id": "acme", "spoke_id": "nw-acme"}
_OTHER_SW = {"id": "other-sw", "name": "other", "object_type": "cx_switch",
             "address": "10.0.0.3", "tenant_id": "othercorp", "spoke_id": "nw-other"}
_SHARED_SW = {"id": "shared-sw", "name": "shared", "object_type": "cx_switch",
              "address": "10.0.0.4", "tenant_id": "shared", "spoke_id": "nw-shared"}

# Fleet rows as the spoke's list_devices would return them (with tenant_id +
# shared flags from Stage 1).
_R_ACME = {**{k: v for k, v in _ACME_SW.items() if k != "spoke_id"},
           "transport": "rest", "reachable": True, "latency_ms": 1, "shared": False}
_R_OTHER = {**{k: v for k, v in _OTHER_SW.items() if k != "spoke_id"},
            "transport": "rest", "reachable": True, "latency_ms": 1, "shared": False}
_R_SHARED = {**{k: v for k, v in _SHARED_SW.items() if k != "spoke_id"},
             "transport": "rest", "reachable": True, "latency_ms": 1, "shared": True}

# Per-device ARP rows (the live datum). 10.0.0.x is in acme's 10.0.0.0/24;
# 192.168.1.x is out-of-prefix (a shared-device row a non-admin should NOT see).
_ARP_ACME = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01", "interface": "1"},
             {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:02", "interface": "2"}]


def _build(monkeypatch, tmp_path, shared=False):
    """Construct the FakeHub + a minimal FastAPI app with the nw routes
    registered directly (bypassing ``create_app``, which mounts 3.10+-only
    simulations routes). ``shared=True`` registers a shared tenant (so shared
    devices are visible to every tenant) and wires the shared spoke +
    module_metadata binding."""
    from routes import nw as nw_routes

    spokes = ["nw-acme", "nw-other"]
    spoke_fleet = {"nw-acme": [_R_ACME], "nw-other": [_R_OTHER]}
    metadata = {"nw-acme": {"tenant_id": "acme"}, "nw-other": {"tenant_id": "othercorp"}}
    nw_devices = [_ACME_SW, _OTHER_SW]
    tenant_state = {"tenants": {
        "acme": {"netbox_tenant_slug": "acme"},
        "othercorp": {"netbox_tenant_slug": "othercorp"},
    }}
    if shared:
        monkeypatch.setattr(access_mod, "_SHARED_TENANT_ID", "shared")
        spokes.append("nw-shared")
        spoke_fleet["nw-shared"] = [_R_SHARED]
        metadata["nw-shared"] = {"tenant_id": "shared"}
        nw_devices.append(_SHARED_SW)
        tenant_state["tenants"]["shared"] = {"shared": True,
                                             "netbox_tenant_slug": "shared"}
    system_state = {
        "global_config": {"nw_devices": nw_devices},
        "module_metadata": metadata,
        "subnet_filter_modules": {"nw": True},   # enable the nw subnet filter
    }
    _ensure_loop()
    hub = _NwHub(str(tmp_path), system_state, tenant_state, spokes, metadata,
                spoke_fleet,
                {"NW_GET_ARP": _ARP_ACME, "NW_GET_DEVICE_INFO": [{"model": "X"}]},
                str(tmp_path))

    # The closures create_app builds — the nw routes close over these.
    _sessions = api_mod._sessions

    def _session_user(request):
        return access_mod.session_user(_sessions, request)

    def _is_admin(sess):
        return access_mod.is_admin(sess)

    def _is_tenant_admin(sess):
        return access_mod.is_tenant_admin(sess)

    async def _filter_nw(request, data, endpoint, explicit_tenant=None):
        return await access_mod.filter_nw(hub, _sessions, request, data,
                                          endpoint, explicit_tenant)

    app = FastAPI()
    app.state.hub = hub

    # Faithful copy of the /api/nw/* middleware gate (api.py:1093,1162):
    # authenticated session required, then admin OR the nw module right.
    @app.middleware("http")
    async def _nw_gate(request, call_next):
        path = request.url.path
        if path.startswith("/api/nw/"):
            sess = _session_user(request)
            if not sess:
                return JSONResponse(status_code=401,
                                    content={"detail": "Authentication required"})
            if not (_is_admin(sess) or access_mod.has_nw_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Network Devices access required"})
        return await call_next(request)

    ctx = SimpleNamespace(_session_user=_session_user, _is_admin=_is_admin,
                          _is_tenant_admin=_is_tenant_admin, _filter_nw=_filter_nw)
    nw_routes.register(app, hub, ctx)
    return TestClient(app), hub


# ── GET /api/nw/devices ─────────────────────────────────────────────────────

def test_list_admin_sees_all_devices(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw", "other-sw", "shared-sw"}


def test_list_admin_acting_as_tenant_scopes_to_that_tenant(monkeypatch, tmp_path):
    """Tenant selector: a Global Admin with an explicit ``?tenant=acme`` sees
    ONLY acme + shared devices — NOT othercorp's (the cross-tenant leak the
    selector is supposed to close). Mirrors the Simulations behavior."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices?tenant=acme", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw", "shared-sw"}   # NOT other-sw


def test_list_admin_default_tenant_is_global(monkeypatch, tmp_path):
    """``default`` is the built-in global/"All tenants" scope — an admin with
    ``?tenant=default`` still sees the whole fleet (no scoping)."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices?tenant=default", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw", "other-sw", "shared-sw"}


def test_list_admin_acting_as_empty_tenant_is_empty_not_fleet(monkeypatch, tmp_path):
    """Acting-as a tenant with no devices (and no shared tenant) yields an
    EMPTY list — the always-gate must not fall through to the unfiltered
    fleet when the scoped visible set is empty."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices?tenant=nobody", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert r.json()["data"] == []


def test_list_offline_cache_admin_acting_as_tenant_scoped(monkeypatch, tmp_path):
    """Offline cache path also honors the selector: an admin acting-as acme is
    served the whole-fleet cache TENANT-FILTERED to acme + shared."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    asyncio.get_event_loop().run_until_complete(
        hub.nw_cache_set_fleet({"status": "SUCCESS",
                                "data": [_R_ACME, _R_OTHER, _R_SHARED]}))
    hub.active_connections = {"ipam-spoke"}
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices?tenant=acme", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw", "shared-sw"}   # NOT other-sw


def test_list_non_admin_sees_own_plus_shared_only(monkeypatch, tmp_path):
    """An acme user sees acme + shared; othercorp's device never surfaces."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw", "shared-sw"}     # NOT other-sw


def test_list_non_admin_no_shared_tenant_excludes_shared(monkeypatch, tmp_path):
    """No shared tenant configured → an acme user sees acme only (the shared
    device isn't visible under any tenant filter)."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw"}


def test_list_authoritative_gate_drops_leaky_spoke_row(monkeypatch, tmp_path):
    """Defense-in-depth: if a spoke returns a row that passes its OWN
    tenant filter (same tenant_id) but is NOT in the reader's visible config
    set, the hub's authoritative visibility gate drops it — the spoke-side
    filter alone is not trusted (a stale/rogue spoke row can't surface a
    device the reader can't see)."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    # A ghost acme-tenant row on the acme spoke: passes the spoke-side tenant
    # filter (tenant_id == acme) but is absent from the hub config (nw_devices).
    ghost = {**_R_ACME, "id": "ghost-sw"}
    hub._spoke_fleet["nw-acme"].append(ghost)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw"}   # ghost-sw dropped by the config visibility gate


def test_list_offline_cache_filtered_for_non_admin_no_leak(monkeypatch, tmp_path):
    """Spokes offline + a whole-fleet cache populated → a non-admin is served
    the cache TENANT-FILTERED (own + shared only), never the whole cache (the
    cross-tenant leak this Stage closes)."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    # Populate the global cache with the WHOLE fleet (as an admin fetch would).
    asyncio.get_event_loop().run_until_complete(
        hub.nw_cache_set_fleet({"status": "SUCCESS",
                                "data": [_R_ACME, _R_OTHER, _R_SHARED]}))
    # Take every nw spoke offline (keep ipam up for prefix resolution paths).
    hub.active_connections = {"ipam-spoke"}
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("stale") is True
    ids = {d["id"] for d in body["data"]}
    assert ids == {"acme-sw", "shared-sw"}   # NOT other-sw (no leak)


def test_list_offline_cache_admin_sees_all(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    asyncio.get_event_loop().run_until_complete(
        hub.nw_cache_set_fleet({"status": "SUCCESS",
                                "data": [_R_ACME, _R_OTHER, _R_SHARED]}))
    hub.active_connections = {"ipam-spoke"}
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ids = {d["id"] for d in r.json()["data"]}
    assert ids == {"acme-sw", "other-sw", "shared-sw"}


def test_list_no_spoke_no_cache_is_503(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    hub.active_connections = {"ipam-spoke"}   # no nw spoke, empty cache
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 503


# ── GET /api/nw/{device_id}/{endpoint} ───────────────────────────────────────

def test_get_device_other_tenant_is_403(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/other-sw/arp", cookies={"lm_session": tok})
    assert r.status_code == 403


def test_get_device_unknown_is_404(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/nope/arp", cookies={"lm_session": tok})
    assert r.status_code == 404


def test_get_device_own_tenant_relays_to_record_spoke(monkeypatch, tmp_path):
    """The relay resolves the spoke from the device record's spoke_id
    (nw-acme), not the single global resolver. own-tenant → full scope → no
    IP filter → the whole ARP table (incl. the out-of-prefix row) is returned."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/acme-sw/arp", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ips = {row["ip"] for row in r.json()["data"]}
    assert ips == {"10.0.0.5", "192.168.1.5"}   # full scope: no filter
    # Relayed to the record's spoke (nw-acme), with the tenant passed through.
    relay_calls = [cl for cl in hub.calls if cl[1] == "NW_GET_ARP"]
    assert relay_calls and relay_calls[0][0] == "nw-acme"
    assert relay_calls[0][2].get("tenant") == "acme"


def test_get_device_dedicated_ignores_explicit_tenant_filter(monkeypatch, tmp_path):
    """A DEDICATED (single-tenant) device is never subnet-filtered — even under
    an explicit ``?tenant=`` (admin acting-as). Its whole dataset belongs to
    that tenant, so the out-of-prefix 192.168.1.5 row is kept, not dropped.
    Regression: a dedicated gateway whose owning tenant has no/non-covering
    NetBox prefixes must not fail closed to an empty view."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/acme-sw/arp?tenant=acme", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ips = {row["ip"] for row in r.json()["data"]}
    assert ips == {"10.0.0.5", "192.168.1.5"}   # dedicated: filter bypassed


def test_get_device_shared_relays_to_shared_spoke(monkeypatch, tmp_path):
    """A shared device resolves to the shared-tenant spoke and is visible to a
    non-admin (shared-tenant-flag invariant)."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/shared-sw/arp", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    relay_calls = [cl for cl in hub.calls if cl[1] == "NW_GET_ARP"]
    assert relay_calls and relay_calls[0][0] == "nw-shared"


def test_get_device_shared_scope_applies_subnet_filter(monkeypatch, tmp_path):
    """A shared device is ``filtered`` scope → _filter_nw narrows the ARP
    table to the viewer's in-prefix rows (10.0.0.0/24); the out-of-prefix
    192.168.1.x row (another tenant's subnet on shared infra) is dropped."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/shared-sw/arp", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ips = {row["ip"] for row in r.json()["data"]}
    assert ips == {"10.0.0.5"}   # filtered to acme's prefixes; 192.168.1.5 dropped


def test_get_device_offline_serves_filtered_cache(monkeypatch, tmp_path):
    """Spoke offline → the cached per-device envelope is served (stale),
    scope-filtered: a shared device's cached ARP is narrowed to the viewer's
    in-prefix rows (not the whole cached table)."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    asyncio.get_event_loop().run_until_complete(
        hub.nw_cache_set_device("shared-sw", "arp",
                                {"status": "SUCCESS", "data": _ARP_ACME}))
    hub.active_connections = {"ipam-spoke"}   # nw spokes offline
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.get("/api/nw/shared-sw/arp", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("stale") is True
    ips = {row["ip"] for row in body["data"]}
    assert ips == {"10.0.0.5"}   # filtered; 192.168.1.5 dropped from the cache too


# ── POST /api/nw/{device_id}/config ──────────────────────────────────────────

def test_run_config_admin_relays_to_record_spoke(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.post("/api/nw/acme-sw/config", json={"commands": ["show version"]},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    cfg_calls = [cl for cl in hub.calls if cl[1] == "NW_RUN_CONFIG"]
    assert cfg_calls and cfg_calls[0][0] == "nw-acme"


def test_run_config_non_admin_is_403(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-user", tenants=["acme"], rights=("nw",))
    r = c.post("/api/nw/acme-sw/config", json={"commands": ["show version"]},
               cookies={"lm_session": tok})
    assert r.status_code == 403


def test_run_config_tenant_admin_own_device_allowed(monkeypatch, tmp_path):
    """A tenant admin may configure a device DEDICATED to its own tenant."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/acme-sw/config", json={"commands": ["show version"]},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    cfg_calls = [cl for cl in hub.calls if cl[1] == "NW_RUN_CONFIG"]
    assert cfg_calls and cfg_calls[0][0] == "nw-acme"


def test_run_config_tenant_admin_other_tenant_is_403(monkeypatch, tmp_path):
    """A tenant admin may NOT configure another tenant's device."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/other-sw/config", json={"commands": ["show version"]},
               cookies={"lm_session": tok})
    assert r.status_code == 403


# ── POST /api/nw/{device_id}/poll ────────────────────────────────────────────

def test_poll_tenant_admin_own_device_allowed(monkeypatch, tmp_path):
    """A tenant admin may Poll Now a device it can see (own tenant)."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)

    async def _poll(device_id):
        return {"status": "SUCCESS", "device_id": device_id}
    hub.poll_nw_device = _poll

    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/acme-sw/poll", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text


def test_poll_tenant_admin_other_tenant_is_403(monkeypatch, tmp_path):
    """A tenant admin may NOT Poll Now another tenant's device."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)

    async def _poll(device_id):  # must never be reached
        raise AssertionError("poll_nw_device should not run when access is denied")
    hub.poll_nw_device = _poll

    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/other-sw/poll", cookies={"lm_session": tok})
    assert r.status_code == 403


def test_poll_non_admin_view_user_is_403(monkeypatch, tmp_path):
    """A plain nw view user (no edit) still cannot Poll — read_scope allows it
    only for own/shared; a view user with tenant acme CAN poll own devices, so
    use an out-of-tenant device to assert the deny path stays 403."""
    c, hub = _build(monkeypatch, tmp_path, shared=False)

    async def _poll(device_id):
        raise AssertionError("poll_nw_device should not run when access is denied")
    hub.poll_nw_device = _poll

    tok = _mint(hub, "other-user", tenants=["othercorp"], rights=("nw",))
    r = c.post("/api/nw/acme-sw/poll", cookies={"lm_session": tok})
    assert r.status_code == 403

# ── Per-tenant NW config: /api/nw/tenant-config + poll overlay ───────────────
# The tenant Scan tab reads/writes its OWN tenant's scan config, poll jitter/
# caps, and recurring-scan schedule via these routes. Overrides live under
# global_config.nw_tenant_cfg[tenant] and never touch the global admin config.

def _noop_push(hub):
    """Give the fake hub the send_to_spoke used by _nw_push_fleet (POST
    re-pushes the tenant's spoke). Records the pushed payloads."""
    hub.pushed = []

    async def _send(msg):
        hub.pushed.append(msg)
    hub.send_to_spoke = _send


def test_tenant_config_get_tenant_admin_own_tenant(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.get("/api/nw/tenant-config", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenant_id"] == "acme"
    assert "scan" in body and "poll" in body and "scan_schedule" in body
    # No override yet → schedule off, poll knobs not overridden.
    assert body["scan_schedule"]["enabled"] is False
    assert body["poll"]["overridden"] == {
        "default_interval": False, "jitter_frac": False,
        "max_per_tick": False, "max_concurrency": False}


def test_tenant_config_get_other_tenant_forbidden(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.get("/api/nw/tenant-config?tenant=othercorp", cookies={"lm_session": tok})
    assert r.status_code == 403


def test_tenant_config_post_scan_persists_without_clobbering_global(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    _noop_push(hub)
    gc = hub.state.system_state["global_config"]
    gc["nw_scan"] = {"enabled": True, "max_targets": 99}  # global admin config
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/tenant-config",
               json={"scan": {"crawl": True, "max_targets": 256,
                              "credential_ids": ["cred-1"]}},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    # Persisted under the tenant override, NOT the global config.
    ov = gc["nw_tenant_cfg"]["acme"]["scan"]
    assert ov["crawl"] is True and ov["max_targets"] == 256
    assert gc["nw_scan"] == {"enabled": True, "max_targets": 99}  # untouched
    # Effective config for acme now reflects the override.
    assert r.json()["scan"]["max_targets"] == 256


def test_tenant_config_post_poll_overlay_takes_effect(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    _noop_push(hub)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/tenant-config",
               json={"poll": {"jitter_frac": 0.3, "max_per_tick": 10}},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    eff = access_mod.nw_poll_cfg_for_tenant(hub, "acme")
    assert eff["poll_jitter_frac"] == 0.3
    assert eff["max_poll_per_tick"] == 10
    # Re-push happened for acme's bound spoke.
    assert hub.pushed  # UPDATE_CONFIG fanned to the tenant's spoke


def test_tenant_config_post_poll_null_clears_override(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    _noop_push(hub)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    c.post("/api/nw/tenant-config", json={"poll": {"jitter_frac": 0.3}},
           cookies={"lm_session": tok})
    r = c.post("/api/nw/tenant-config", json={"poll": {"jitter_frac": None}},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    ov = hub.state.system_state["global_config"]["nw_tenant_cfg"]["acme"].get("poll", {})
    assert "jitter_frac" not in ov  # cleared → inherits global


def test_tenant_config_scan_schedule_interval_floored_1h(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=False)
    _noop_push(hub)
    tok = _mint(hub, "acme-admin", tenants=["acme"], role="tenant_admin")
    # 60s requested → floored to 3600 (1h). 0 stays off.
    r = c.post("/api/nw/tenant-config",
               json={"scan_schedule": {"enabled": True, "interval_seconds": 60}},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert r.json()["scan_schedule"]["interval_seconds"] == 3600
    r2 = c.post("/api/nw/tenant-config",
                json={"scan_schedule": {"interval_seconds": 0}},
                cookies={"lm_session": tok})
    assert r2.json()["scan_schedule"]["interval_seconds"] == 0


def test_list_offline_marks_rows_unknown(monkeypatch, tmp_path):
    """Spoke offline → the cached rows still carry their last up/down, which is
    now UNKNOWABLE (the prober is gone). The route flips every served row to
    reachable=None (the UI's yellow 'unknown' badge) instead of a stale green,
    without mutating the shared cache."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    asyncio.get_event_loop().run_until_complete(
        hub.nw_cache_set_fleet({"status": "SUCCESS",
                                "data": [_R_ACME, _R_OTHER, _R_SHARED]}))
    hub.active_connections = {"ipam-spoke"}   # every nw spoke offline
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/devices", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("stale") is True
    assert all(d.get("reachable") is None for d in body["data"])
    assert all(d.get("latency_ms") is None for d in body["data"])
    # The shared cache is untouched (rows still carry their real reachability).
    cached = hub.nw_cache_get_fleet()["devices"]["data"]
    assert any(d.get("reachable") is True for d in cached)
