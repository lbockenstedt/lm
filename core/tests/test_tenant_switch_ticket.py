"""The hub's tenant-switch ticket: POST /setup/tenant/switch-ticket.

A Global Admin's tenant switch (WebUI setTenant) gets a ticket first and
sends it with POST /setup/tenant. The hub applies a ticketed switch only
while its ticket is the latest one issued, and uses the ticket up. A switch
POST the page gave up on (no answer in time, an error, a network failure)
may still reach the hub later; once the page has asked for a newer ticket,
that POST changes nothing (409). So the tenant the hub names with a ticket is
final for every ticketed switch sent before it. A POST without a ticket works
as before (fleet rule 3.3).
"""
import asyncio
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import access
import api as api_mod
import routes.tenants_users as tenants_users
from state.manager import StateManager
from test_auth_session_security import _FakeHub
from test_tenant_scoped_tenants import _Ctx, _Holder, _State, _global_admin

STALE = ("This tenant switch was not applied: a newer tenant switch was "
         "requested after it. Pick the tenant again.")


class _SwitchState(_State):
    """The tenant tests' state, with the hub's real active-tenant write."""
    set_active_tenant = StateManager.set_active_tenant


class _Hub:
    """A hub with the tenant tests' state and an active tenant."""

    def __init__(self, tenants, active):
        """Store ``tenants`` and make ``active`` the active tenant."""
        self.state = _SwitchState(tenants)
        self.state.system_state["active_tenant"] = active


@pytest.fixture(autouse=True)
def keep_tenant_cache(monkeypatch):
    """Restore access's cached tenant data after a route reloads it."""
    for name in ("_SHARED_TENANT_ID", "_GROUP_MEMBERS", "_AMBIGUOUS_TENANT_IDS"):
        monkeypatch.setattr(access, name, getattr(access, name, None), raising=False)


def _build(active="Beta"):
    """A Global Admin's client on the tenant routes, with the tenants acme
    and Beta stored and ``active`` the hub's active tenant."""
    hub = _Hub({"acme": {"name": "Acme Corp", "description": "original"},
                "Beta": {"name": "Beta"}}, active)
    holder = _Holder()
    holder.current = _global_admin()
    app = FastAPI()
    app.state.hub = hub
    tenants_users.register(app, hub, _Ctx(holder))
    return TestClient(app), hub


def _ticket(c):
    """A new switch ticket and the tenant the hub names with it."""
    r = c.post("/setup/tenant/switch-ticket")
    assert r.status_code == 200, r.text
    return r.json()


def _switch(c, tenant, ticket, **config):
    """The WebUI's switch POST to ``tenant``, carrying ``ticket``."""
    return c.post("/setup/tenant", json={"tenant_id": tenant, "config": {"active": True, **config},
                                         "switch_ticket": ticket})


def _snapshot(hub):
    """The active tenant and every stored tenant record."""
    return copy.deepcopy((hub.state.system_state["active_tenant"], hub.state.tenant_state["tenants"]))


def test_a_ticket_names_the_active_tenant_as_stored_and_switches_once():
    """A ticket names the active tenant as stored, a switch carrying it is
    applied, and the same ticket sent again changes nothing (409)."""
    c, hub = _build(active="Beta")
    first = _ticket(c)
    # The stored spelling, never folded: a legacy twin is another tenant.
    assert first["active_tenant"] == "Beta"
    assert isinstance(first["ticket"], str) and first["ticket"]
    r = _switch(c, "acme", first["ticket"])
    assert r.status_code == 200, r.text
    assert hub.state.system_state["active_tenant"] == "acme"
    before = _snapshot(hub)
    # The switch used the ticket up: sent again, it changes nothing.
    r = _switch(c, "Beta", first["ticket"], description="changed")
    assert r.status_code == 409 and r.json()["detail"] == STALE
    assert _snapshot(hub) == before
    # The next ticket names the tenant the switch made active.
    assert _ticket(c)["active_tenant"] == "acme"


def test_a_ticket_names_default_when_no_tenant_is_active():
    """With no active tenant stored, the ticket names "default", the tenant
    that then scopes requests that name none (access.get_tenant_scoping)."""
    c, _hub = _build(active=None)
    assert _ticket(c)["active_tenant"] == "default"


def test_an_older_ticket_changes_nothing_once_a_newer_one_is_issued():
    """A switch that arrives under a ticket a newer one has voided gets 409
    and changes nothing: no tenant record is created or updated, and the
    active tenant stays. The newer ticket still works."""
    c, hub = _build(active="Beta")
    t1 = _ticket(c)["ticket"]
    t2 = _ticket(c)["ticket"]
    assert t1 != t2
    before = _snapshot(hub)
    # Under the older ticket a switch to a new tenant creates no record, and
    # one to a stored tenant changes neither its record nor the active tenant.
    for tenant, config in (("gamma", {}), ("acme", {"description": "changed"})):
        r = _switch(c, tenant, t1, **config)
        assert r.status_code == 409 and r.json()["detail"] == STALE
        assert _snapshot(hub) == before
    # The older ticket's refusals left the newer one valid.
    r = _switch(c, "acme", t2)
    assert r.status_code == 200, r.text
    assert hub.state.system_state["active_tenant"] == "acme"


@pytest.mark.parametrize("issued", [False, True], ids=["none-issued", "one-issued"])
@pytest.mark.parametrize("ticket", ["", None, "not-a-ticket"], ids=["empty", "null", "unknown"])
def test_a_switch_with_no_valid_ticket_changes_nothing(issued, ticket):
    """An empty, null or unknown switch_ticket gets 409 and changes nothing,
    whether or not the hub has a ticket out, and does not use that one up."""
    c, hub = _build(active="Beta")
    current = _ticket(c)["ticket"] if issued else None
    before = _snapshot(hub)
    r = _switch(c, "acme", ticket)
    assert r.status_code == 409 and r.json()["detail"] == STALE
    assert _snapshot(hub) == before
    if current:
        # A wrong ticket does not use up the one the hub issued.
        assert _switch(c, "acme", current).status_code == 200


def test_a_refused_ticketed_switch_still_uses_up_its_ticket():
    """A ticketed switch refused for a blank tenant id (400) has used its
    ticket up: a retry with the same ticket gets 409 and changes nothing."""
    c, hub = _build(active="Beta")
    ticket = _ticket(c)["ticket"]
    before = _snapshot(hub)
    r = _switch(c, "  ", ticket)
    assert r.status_code == 400 and r.json()["detail"] == "Missing tenant_id"
    r = _switch(c, "acme", ticket)
    assert r.status_code == 409 and r.json()["detail"] == STALE
    assert _snapshot(hub) == before


@pytest.mark.parametrize("issued", [False, True], ids=["none-issued", "one-issued"])
def test_a_switch_without_a_ticket_works_as_before(issued):
    """A body with no switch_ticket key (an API caller) is applied as
    before, whether or not a ticket is out (fleet rule 3.3)."""
    c, hub = _build(active="Beta")
    if issued:
        _ticket(c)
    r = c.post("/setup/tenant", json={"tenant_id": "acme", "config": {"active": True}})
    assert r.status_code == 200, r.text
    assert hub.state.system_state["active_tenant"] == "acme"
    assert hub.state.tenant_state["tenants"]["acme"]["active"] is True


@pytest.mark.parametrize("permissions, status", [
    ({"role": "admin", "admin": True}, 200),
    ({"role": "admin", "admin": True, "read_only": True}, 403),
    ({"role": "tenant_admin"}, 403),
    ({"pxmx": True, "edit": True}, 403),
], ids=["global-admin", "read-only-admin", "tenant-admin", "write-user"])
def test_only_a_global_admin_who_may_write_gets_a_ticket(tmp_path, permissions, status):
    """Through create_app, with its access middleware: /setup/* is for Global
    Admins only, and a read-only account may change nothing. A refused call
    issues no ticket, so it cannot void the one a Global Admin's switch holds;
    another Global Admin's call does."""
    api_mod._sessions.clear()
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    hub = _FakeHub(str(tmp_path), {"users": {}, "active_tenant": "Beta"})
    try:
        app = api_mod.create_app(hub)

        def client(user_id, perms):
            """A client signed in as ``user_id`` with ``perms``."""
            token = api_mod._record_session(hub, {
                "user_id": user_id, "auth_type": "local", "permissions": perms,
                "tenants": ["acme"], "tenant_id": "acme", "protected": False})
            return TestClient(app, cookies={"lm_session": token})

        admin = client("admin", {"role": "admin", "admin": True})
        r = admin.post("/setup/tenant/switch-ticket")
        assert r.status_code == 200, r.text
        assert r.json()["active_tenant"] == "Beta" and r.json()["ticket"]
        held = r.json()["ticket"]

        r = client("caller", permissions).post("/setup/tenant/switch-ticket")
        assert r.status_code == status, r.text
        # The route refuses a blank tenant id (400) only after the ticket
        # check: 400 shows the held ticket was still the latest, 409 that the
        # caller's call voided it.
        r = admin.post("/setup/tenant", json={"tenant_id": " ", "switch_ticket": held})
        assert r.status_code == (409 if status == 200 else 400), r.text
    finally:
        api_mod._sessions.clear()
