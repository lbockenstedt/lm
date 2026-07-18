"""Feature B4: ``/tenant/devices/spokes`` emits ``spoke_guid``/``install_uuid``
so the WebUI spoke dropdown (``loadApprovedSpokes``) consumes one guid-keyed
row shape from BOTH ``/setup/pending_spokes`` (Global Admin) and the
session-scoped ``/tenant/devices/spokes`` mirror (tenant-admin).

After B1, ``spoke_id`` is the guid once armed; ``spoke_guid``/``install_uuid``
are the explicit guid for display + consistency hardening. This test pins the
tenant-admin mirror so the two endpoints can't drift.
"""
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import access
from access import resolve_effective_permissions  # noqa: F401  (import side-effect parity)
import routes.tenant_devices as tenant_devices


# ── session builders ───────────────────────────────────────────────────────
def _sess(*, role=None, admin=False, tenants=None, tenant_id=None, user_id="caller"):
    perms = {}
    if admin:
        perms["admin"] = True
    if role:
        perms["role"] = role
    return {"user": {
        "user_id": user_id,
        "tenants": tenants or [],
        "tenant_id": tenant_id,
        "permissions": perms,
    }}


def _tenant_admin(tenant="acme"):
    return _sess(role="tenant_admin", tenants=[tenant], tenant_id=tenant,
                 user_id=f"tadm-{tenant}")


# ── fake hub/state mirroring tenant_devices.py reads ───────────────────────
class _State:
    def __init__(self):
        self.system_state = {
            "known_modules": [],
            "module_names": {},
            "module_metadata": {},
            "approved_modules": {},
            "global_config": {},
        }

    def get_spoke_tenant(self, sid):
        return self.system_state.get("module_metadata", {}).get(sid, {}).get("tenant_id")

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self):
        self.state = _State()
        self.approved_modules = {}
        self.spoke_module_types = {}

    def _primary_key(self, sid):
        # Mirror the real resolve seam: alias wins, else raw id.
        return getattr(self, "spoke_id_alias", {}).get(sid, sid)


class _Ctx:
    def __init__(self, holder):
        self._session_user = lambda req: holder.current


class _Holder:
    def __init__(self):
        self.current = None


def _build():
    hub = _Hub()
    holder = _Holder()
    app = FastAPI()
    app.state.hub = hub
    tenant_devices.register(app, hub, _Ctx(holder))
    return TestClient(app), hub, holder


def _seed(hub, sid, *, guid=None, hostname="h", tenant_id=None, module_type="firewall",
          approved=True):
    hub.state.system_state["known_modules"].append(sid)
    hub.state.system_state["module_names"][sid] = sid  # display_name fallback
    meta = {"hostname": hostname, "module_type": module_type}
    if guid:
        meta["install_uuid"] = guid
    if tenant_id:
        meta["tenant_id"] = tenant_id
    hub.state.system_state["module_metadata"][sid] = meta
    hub.approved_modules[hub._primary_key(sid)] = approved
    if module_type:
        hub.spoke_module_types[hub._primary_key(sid)] = module_type


# ── spoke_guid / install_uuid in the bindable-spokes mirror ─────────────────

def test_bindable_spokes_emit_spoke_guid_and_install_uuid():
    c, hub, holder = _build()
    _seed(hub, "spoke-A", guid="GUID-1", tenant_id="acme")
    _seed(hub, "spoke-B", guid="GUID-2", tenant_id="acme")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/devices/spokes")
    assert r.status_code == 200
    spokes = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert set(spokes) == {"spoke-A", "spoke-B"}
    assert spokes["spoke-A"]["spoke_guid"] == "GUID-1"
    assert spokes["spoke-A"]["install_uuid"] == "GUID-1"
    assert spokes["spoke-B"]["spoke_guid"] == "GUID-2"
    assert spokes["spoke-B"]["install_uuid"] == "GUID-2"
    # Row shape mirrors /setup/pending_spokes so loadApprovedSpokes consumes it
    # unchanged (spoke_id/display_name/approved/module_type/tenant_id).
    for s in spokes.values():
        assert s["approved"] is True
        assert "display_name" in s and "module_type" in s and "tenant_id" in s


def test_bindable_spokes_blank_guid_when_no_install_uuid():
    """A spoke that has never connected (no install_uuid) still lists; the guid
    fields are blank strings (NOT missing) so the WebUI never sees an undefined
    key after B1 armed the connected ones."""
    c, hub, holder = _build()
    _seed(hub, "fresh-spoke", guid=None, tenant_id="acme")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/devices/spokes")
    spokes = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert spokes["fresh-spoke"]["spoke_guid"] == ""
    assert spokes["fresh-spoke"]["install_uuid"] == ""


def test_bindable_spokes_tenant_scoped():
    """A tenant-admin only sees spokes in their OWN tenant — a spoke assigned to
    another tenant is filtered out (can_bind_spoke gate), so neither its id nor
    its guid leaks across tenants."""
    c, hub, holder = _build()
    _seed(hub, "spoke-A", guid="GUID-1", tenant_id="acme")
    _seed(hub, "spoke-B", guid="GUID-2", tenant_id="other")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/devices/spokes")
    spokes = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert set(spokes) == {"spoke-A"}
    assert spokes["spoke-A"]["spoke_guid"] == "GUID-1"
    assert "spoke-B" not in spokes


def test_bindable_spokes_unapproved_excluded():
    c, hub, holder = _build()
    _seed(hub, "spoke-A", guid="GUID-1", tenant_id="acme", approved=True)
    _seed(hub, "spoke-B", guid="GUID-2", tenant_id="acme", approved=False)
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/devices/spokes")
    spokes = {s["spoke_id"] for s in r.json()["spokes"]}
    assert spokes == {"spoke-A"}