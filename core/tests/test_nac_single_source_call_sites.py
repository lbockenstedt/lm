"""Single-spoke NAC call sites must use the caller's NAC source.

Both routes below used ``hub.get_spoke_by_type("nac")``: whichever ClearPass
spoke happened to be connected, even one dedicated to another tenant.

* ``GET /vm/{vm_id}/details`` asked that spoke for the VM's ClearPass policy.
  The same IP can exist in several tenants' VRFs, so another tenant's
  appliance could answer. It now uses ``get_cppm_spoke_for_scope`` with the
  caller's effective tenant.
* ``POST /setup/cppm-config`` (legacy hub-wide ClearPass config, admin only)
  pushed ``update_config`` to that spoke alone, overwriting a tenant
  appliance's own instance config and leaving the other NAC spokes on the old
  one. It is now refused (409) while NAC instance records exist. Otherwise it
  re-sends every NAC spoke its config (``reconcile_nac_spokes``), as the
  connect push does: the push ledger tracks the legacy config as the hub's
  own record, so a spoke that does not confirm it is skipped, and a spoke
  bound to a tenant that holds it is never that tenant's own.
"""
import tempfile
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.cppm as cppm_routes
import routes.setup as setup_routes
from main import LabManagerHub
from messaging.protocol import Message, MessageHeader, MessagePayload
from routes import pxmx
from warm_cache import WarmCacheMixin

_ADMIN = {"user": {"permissions": {"admin": True}}}
_ACME_USER = {"user": {"tenant_id": "acme", "permissions": {}}}


class _VmHub(WarmCacheMixin):
    """One VM with a known IP; NAC sources per scope; records every relay."""

    def __init__(self, scope_spokes):
        self.state = SimpleNamespace(
            system_state={"resources": {"vm-1": {"metadata": {"ip": "10.0.0.5"}}}},
            data_dir=tempfile.mkdtemp(prefix="vm-nac-"))
        self.simulations_store = SimpleNamespace(get_all_protected_vms=lambda: set())
        self.cache_dir = tempfile.mkdtemp(prefix="vm-nac-cache-")
        self.warm_cache_init()
        self.scope_spokes = scope_spokes
        self.scopes = []
        self.relayed = []

    def get_hypervisor_spoke(self):
        """No hypervisor answers; the NAC lookup only needs the cached IP."""
        return None

    def get_all_spokes_by_type(self, module_type):
        """No firewall spokes."""
        return []

    def get_spoke_by_type(self, module_type):
        """The old tenant-blind pick: another tenant's ClearPass."""
        return "cppm-other-tenant" if module_type == "nac" else None

    def get_cppm_spoke_for_scope(self, tenant_id=None):
        """Record the scope asked for and return its NAC source."""
        self.scopes.append(tenant_id)
        return self.scope_spokes.get(tenant_id)

    async def request_response(self, sid, cmd, payload, timeout=35.0, signing_secret=None):
        """Answer a policy lookup with the spoke's name in it."""
        self.relayed.append((sid, cmd, payload))
        return {"payload": {"data": {"status": "SUCCESS", "policy": f"policy@{sid}"}}}


def _vm_client(hub, sess, admin):
    """The pxmx routes with a fixed session; the subnet filter keeps the VM."""
    async def _filter_tenant(request, data, module, ip_fields, explicit=None, **_kw):
        """Keep every record (ownership is not under test here)."""
        return data
    app = FastAPI()
    app.state.hub = hub
    pxmx.register(app, hub, SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: admin,
        _resolve_tenant=lambda request, explicit=None: explicit,
        _filter_tenant=_filter_tenant,
    ))
    return TestClient(app)


def test_vm_details_asks_the_tenants_own_nac_source():
    hub = _VmHub({"acme": "cppm-acme", None: "cppm-hub"})
    r = _vm_client(hub, _ACME_USER, admin=False).get("/vm/vm-1/details")
    assert r.status_code == 200
    assert hub.scopes == ["acme"]
    assert hub.relayed == [("cppm-acme", "CPPM_GET_POLICY_BY_IP", {"ip": "10.0.0.5"})]
    assert r.json()["cppm"]["policy"] == "policy@cppm-acme"


def test_vm_details_admin_without_tenant_uses_the_global_source():
    hub = _VmHub({"acme": "cppm-acme", None: "cppm-hub"})
    r = _vm_client(hub, _ADMIN, admin=True).get("/vm/vm-1/details")
    assert r.status_code == 200
    assert hub.scopes == [None]
    assert [sid for sid, _, _ in hub.relayed] == ["cppm-hub"]


def test_vm_details_admin_selected_tenant_uses_that_tenants_source():
    hub = _VmHub({"acme": "cppm-acme", None: "cppm-hub"})
    r = _vm_client(hub, _ADMIN, admin=True).get("/vm/vm-1/details?tenant=acme")
    assert r.status_code == 200
    assert hub.scopes == ["acme"]
    assert [sid for sid, _, _ in hub.relayed] == ["cppm-acme"]


def test_vm_details_without_a_nac_source_never_asks_another_tenant():
    hub = _VmHub({})
    r = _vm_client(hub, _ACME_USER, admin=False).get("/vm/vm-1/details")
    assert r.status_code == 200
    assert hub.relayed == []
    assert r.json()["cppm"] == {"status": "OFFLINE", "policy": "Unknown"}


class _SetupHub:
    """Hub for the legacy config route: the real NAC reconcile and push over
    a recorded send, and a record of the NAC cache namespaces dropped."""

    # The production reconcile and push: they pick each spoke's config,
    # send it and record what the spoke confirmed.
    reconcile_nac_spokes = LabManagerHub.reconcile_nac_spokes
    push_nac_config = LabManagerHub.push_nac_config
    _primary_key = LabManagerHub._primary_key

    def __init__(self, nac_spokes, nac_instances=None):
        gc = {"nac_instances": nac_instances} if nac_instances else {}
        self.state = SimpleNamespace(system_state={"global_config": gc},
                                     get_global_config=lambda: gc,
                                     _mark_dirty=lambda: None)
        self._nac_spokes = list(nac_spokes)
        self.approved_modules = {sid: True for sid in nac_spokes}
        self._nac_unconfigured_spokes = set()
        self._nac_push_locks = {}
        self.active_connections = {}
        self.spoke_id_alias = {}
        self.sent = []
        self.dropped = []
        # Each spoke's answer to UPDATE_CONFIG; CPPMSpoke answers SUCCESS.
        self.replies = {}

    def get_all_spokes_by_type(self, module_type):
        """Every connected NAC spoke, a tenant's included."""
        return list(self._nac_spokes) if module_type == "nac" else []

    async def request_response(self, spoke_id, cmd, payload, timeout=None):
        """Record the pushed message and answer with the spoke's reply."""
        self.sent.append(Message(header=MessageHeader(sender_id="hub", destination_id=spoke_id),
                                 payload=MessagePayload(type=cmd, data=payload)))
        return {"payload": {"data": self.replies.get(spoke_id, {"status": "SUCCESS"})}}

    def warm_drop(self, namespace, key_prefixes):
        """Record a dropped cache namespace."""
        self.dropped.append(namespace)
        return 0


def _post_cppm_config(hub, config=None):
    """POST a legacy ClearPass config as an admin; return the response."""
    app = FastAPI()
    app.state.hub = hub
    setup_routes.register(app, hub, SimpleNamespace(
        _session_user=lambda request: _ADMIN, _is_admin=lambda s: True))
    return TestClient(app).post("/setup/cppm-config",
                                json={"config": config or {"host": "cp.example"}})


def test_legacy_cppm_config_is_resent_to_every_nac_spoke():
    """Every NAC spoke is sent the legacy config on connect, so a save
    re-sends it to every one, through push_nac_config: a spoke the hub had
    marked unconfigured is usable again once it is sent a host, each spoke's
    confirmed config is remembered, and the NAC lists read from the old
    ClearPass are dropped."""
    hub = _SetupHub(["cppm-hub", "cppm-tenant"])
    hub._nac_unconfigured_spokes.add("cppm-hub")
    r = _post_cppm_config(hub)
    assert r.status_code == 200
    assert r.json()["pushed"] is True
    assert sorted(m.header.destination_id for m in hub.sent) == ["cppm-hub", "cppm-tenant"]
    assert {m.payload.type for m in hub.sent} == {"UPDATE_CONFIG"}
    assert all(m.payload.data == {"host": "cp.example"} for m in hub.sent)
    assert hub.state.system_state["global_config"]["cppm"] == {"host": "cp.example"}
    assert hub._nac_unconfigured_spokes == set()
    assert hub.state.system_state["nac_config_pushed"] == {
        "cppm-hub": "legacy-cppm@cp.example", "cppm-tenant": "legacy-cppm@cp.example"}
    assert hub.dropped == list(cppm_routes.NAC_CACHE_NAMESPACES)


def test_legacy_cppm_config_resends_a_spoke_that_did_not_confirm_the_last_save():
    """A spoke that refused a host change still holds the old ClearPass, so
    it is stale and no NAC read or write uses it. A re-save sends it the
    config again rather than skipping it as stale."""
    from hub_spoke_registry import nac_spoke_stale
    hub = _SetupHub(["cppm-hub"])
    hub.replies["cppm-hub"] = {"status": "ERROR", "message": "spoke command queue full"}
    r = _post_cppm_config(hub, {"host": "cp-2"})
    assert r.json()["pushed"] is False
    assert nac_spoke_stale(hub, "cppm-hub") is True
    hub.replies.clear()
    r = _post_cppm_config(hub, {"host": "cp-2"})
    assert r.json()["pushed"] is True
    assert [m.header.destination_id for m in hub.sent] == ["cppm-hub", "cppm-hub"]
    assert nac_spoke_stale(hub, "cppm-hub") is False


def test_legacy_cppm_config_with_no_nac_spoke_is_saved_but_not_pushed():
    hub = _SetupHub([])
    r = _post_cppm_config(hub)
    assert r.status_code == 200
    assert r.json()["pushed"] is False
    assert hub.sent == []
    assert hub.state.system_state["global_config"]["cppm"] == {"host": "cp.example"}


def test_legacy_cppm_config_without_a_host_is_saved_but_not_pushed():
    """A spoke sent a config with no host only answers "CPPM host not
    configured", so nothing is sent and the spoke is marked unconfigured."""
    hub = _SetupHub(["cppm-hub"])
    r = _post_cppm_config(hub, {"host": ""})
    assert r.status_code == 200
    assert r.json()["pushed"] is False
    assert hub.sent == []
    assert hub._nac_unconfigured_spokes == {"cppm-hub"}


def test_legacy_cppm_config_is_refused_while_nac_instances_exist():
    """push_nac_config sends a spoke its NAC instance record whenever one
    exists, so the legacy config would change nothing: 409, nothing saved,
    pushed or dropped."""
    hub = _SetupHub(["cppm-hub"], nac_instances=[{"id": "rec-1", "host": "cp-1"}])
    r = _post_cppm_config(hub)
    assert r.status_code == 409
    assert "NAC instances" in r.json()["detail"]
    assert "cppm" not in hub.state.system_state["global_config"]
    assert hub.sent == []
    assert hub.dropped == []
