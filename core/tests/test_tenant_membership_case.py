"""A stored tenant tag (a record's, spoke's or host's) belongs to a user when
it is one of the user's tenants compared as ``same_tenant`` compares:
case-insensitively, the way the hub's scope filters already decide it (fleet
rule 6.1). Each gate below used a raw ``in`` before, so a tenant admin
assigned "Straße" was refused a resource tagged "STRASSE"."""
import asyncio
from types import SimpleNamespace

import pytest

import access


def _tenant_admin(*tenants, primary=None):
    """A tenant-admin session assigned ``tenants`` (primary: the first)."""
    return {"user": {"user_id": "u", "tenants": list(tenants),
                     "tenant_id": primary or tenants[0],
                     "permissions": {"role": "tenant_admin"}}}


def _hub(bindings):
    """A hub whose spokes are bound to tenants as in ``bindings``."""
    return SimpleNamespace(state=SimpleNamespace(
        get_spoke_tenant=lambda sid: bindings.get(sid, "")))


@pytest.fixture(autouse=True)
def _shared(monkeypatch):
    # A fixed shared tenant, so "strict" can be checked against it.
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "shared-co")


def test_tenant_among_is_case_insensitive_and_strict():
    assert access.tenant_among("STRASSE", ["Straße"])
    assert access.tenant_among(" acme ", ["ACME"])
    # Blank never matches, not even a blank in the list.
    assert not access.tenant_among("", ["", "acme"])
    assert not access.tenant_among(None, ["acme"])
    assert not access.tenant_among("acme", None)
    # The shared tenant counts only when it is in the list.
    assert not access.tenant_among("shared-co", ["acme"])
    assert access.tenant_among("SHARED-CO", ["shared-co"])


def test_read_and_write_scope_own_tenant_in_any_spelling():
    sess = _tenant_admin("Straße")
    assert access.read_scope(sess, "STRASSE") == "full"
    assert access.write_scope(sess, "STRASSE") == "full"
    assert access.read_scope(sess, "other") == "deny"
    assert access.write_scope(sess, "other") == "deny"


def test_spoke_and_hypervisor_ownership_in_any_spelling():
    hub = _hub({"s1": "ACME", "s2": "other"})
    sess = _tenant_admin("acme")
    assert access.spoke_visible_to_session(sess, "ACME")
    assert access.can_bind_spoke(hub, sess, "s1")
    assert access.hypervisor_owned_by_caller(hub, sess, "s1")
    # Another tenant's spoke stays out of reach.
    assert not access.spoke_visible_to_session(sess, "other")
    assert not access.can_bind_spoke(hub, sess, "s2")
    assert not access.hypervisor_owned_by_caller(hub, sess, "s2")


def test_tenant_console_opt_in_on_own_bound_host_in_any_spelling():
    class _Store:
        async def get_hypervisors_config(self, tenant):
            """Every hypervisor has tenant console switched on."""
            return {"tenant_console_enabled": True}

    hub = _hub({"s1": "ACME", "s2": "other"})
    hub.simulations_store = _Store()
    sess = _tenant_admin("acme")
    assert asyncio.run(access.tenant_admin_console_allowed(hub, sess, "s1"))
    assert not asyncio.run(access.tenant_admin_console_allowed(hub, sess, "s2"))


def test_effective_tenant_resolves_to_the_users_own_spelling():
    sess = _tenant_admin("Alpha", "Straße", primary="Alpha")
    # A different capitalisation of an owned tenant selects it, in the user's
    # own spelling, so exact-key reads that follow still find its data.
    assert access.session_effective_tenant(sess, "STRASSE") == "Straße"
    assert access.session_effective_tenant(sess, "Straße") == "Straße"
    # A tenant the user doesn't own falls back to their primary tenant.
    assert access.session_effective_tenant(sess, "Other") == "Alpha"


def _keep_tenant_cache(monkeypatch):
    """Restore access's cached tenant data after a test reloads it."""
    for name in ("_SHARED_TENANT_ID", "_GROUP_MEMBERS", "_AMBIGUOUS_TENANT_IDS"):
        monkeypatch.setattr(access, name, getattr(access, name, None), raising=False)


def _state(tenants):
    """A real StateManager holding ``tenants`` (never saved)."""
    from state.manager import StateManager
    s = StateManager()
    s.tenant_state = {"tenants": tenants}
    return s


def test_tenants_differing_only_by_case_never_match_each_other(monkeypatch):
    # "ACME" and "acme" were both saved before tenant ids were kept unique.
    _keep_tenant_cache(monkeypatch)
    access.refresh_shared_tenant(SimpleNamespace(state=SimpleNamespace(
        tenant_state={"tenants": {"ACME": {}, "acme": {}, "other": {}}})))
    # Each is still its own tenant, by its exact spelling ...
    assert access.same_tenant("ACME", "ACME")
    assert access.tenant_among("acme", ["acme"])
    # ... but neither, nor a third spelling (spaces included), stands in for
    # the other.
    assert not access.same_tenant("ACME", " ACME ")
    assert not access.same_tenant("ACME", "acme")
    assert not access.tenant_among("ACME", ["acme"])
    assert not access.tenant_among("Acme", ["acme"])
    assert not access.tenant_slug_matches("ACME", "acme")
    assert access.write_scope(_tenant_admin("acme"), "ACME") == "deny"
    hub = _hub({"s1": "ACME", "s2": "acme"})
    assert not access.can_bind_spoke(hub, _tenant_admin("acme"), "s1")
    assert access.can_bind_spoke(hub, _tenant_admin("acme"), "s2")
    # Every other tenant still compares in any case.
    assert access.same_tenant("OTHER", "other")


def test_update_tenant_merges_another_spelling_into_the_stored_tenant():
    s = _state({"ACME": {"name": "Acme", "quotas": {"vm": 5}}})
    assert s.tenant_key(" acme ") == "ACME"
    s.update_tenant("acme", {"description": "d"})
    assert s.tenant_state["tenants"] == {
        "ACME": {"name": "Acme", "quotas": {"vm": 5}, "description": "d"}}
    # A new id is still created, under its own spelling.
    assert s.tenant_key("Beta") is None
    s.update_tenant("Beta", {})
    assert "Beta" in s.tenant_state["tenants"]


def test_tenant_key_refuses_to_guess_between_case_variants():
    s = _state({"ACME": {}, "acme": {}})
    # The exact spelling still names its own tenant ...
    assert s.tenant_key("acme") == "acme"
    s.update_tenant("ACME", {"x": 1})
    assert s.tenant_state["tenants"] == {"ACME": {"x": 1}, "acme": {}}
    # ... but a third spelling matches both, so it is refused, not guessed.
    with pytest.raises(ValueError):
        s.tenant_key("Acme")
    with pytest.raises(ValueError):
        s.update_tenant("Acme", {"x": 2})
    assert "Acme" not in s.tenant_state["tenants"]


def test_every_spelling_of_the_built_in_default_names_it():
    """The built-in Admin tenant ("default") exists before its record is
    stored, so another spelling merges into "default" instead of creating a
    tenant the access checks cannot tell from Admin."""
    s = _state({})
    assert s.tenant_key("Default") == "default"
    s.update_tenant(" DEFAULT ", {"name": "Admin"})
    assert s.tenant_state["tenants"] == {"default": {"name": "Admin"}}


def test_group_sync_updates_the_stored_spelling_of_a_netbox_group(monkeypatch):
    """A group stored as "group:ACME-GRP" is the NetBox group "acme-grp": it is
    updated in place, not pruned and re-created without its local fields."""
    import main
    _keep_tenant_cache(monkeypatch)
    state = _state({"group:ACME-GRP": {"is_tenant_group": True, "quotas": {"vm": 3}}})

    async def _reply(spoke_id, command, payload, timeout=None):
        """NetBox's answer: one tenant group, slug in lower case."""
        return {"payload": {"data": {"status": "SUCCESS", "groups": [
            {"slug": "acme-grp", "name": "Acme group", "tenant_slugs": ["acme"], "id": 7}]}}}

    hub = SimpleNamespace(state=state, request_response=_reply)
    asyncio.run(main.LabManagerHub._sync_tenant_groups(hub, "nb-1"))
    tenants = state.tenant_state["tenants"]
    assert list(tenants) == ["group:ACME-GRP"]
    assert tenants["group:ACME-GRP"]["member_tenant_slugs"] == ["acme"]
    assert tenants["group:ACME-GRP"]["quotas"] == {"vm": 3}


def _reports_client(user, monkeypatch):
    """The report routes for ``user``, with one report stored for "DXP"."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from simulations import email_report
    from simulations.routes import register_simulations_routes
    sent = []

    async def _send(hub, tenant, rep):
        """Record a test send instead of mailing it."""
        sent.append(tenant)

    monkeypatch.setattr(email_report, "send_now", _send)
    state = SimpleNamespace(
        system_state={"global_config": {"email_reports": [
            {"id": "r1", "name": "Weekly", "tenant": "DXP", "recipients": [], "enabled": False}]}},
        tenant_state={"tenants": {"DXP": {"name": "DXP Labs"}, "other": {"name": "Other"}}},
        _mark_dirty=lambda: None)
    hub = SimpleNamespace(state=state, simulations_cache={}, active_connections=set(),
                          simulations_store=None)
    app = FastAPI()
    register_simulations_routes(app, hub, session_user_fn=lambda req: user,
                                resolve_tenant_fn=lambda req: None,
                                is_admin_fn=access.is_admin)
    return TestClient(app), state, sent


def _report_user(tenant):
    """A non-admin session whose tenant is ``tenant``."""
    return {"user": {"user_id": "u-" + tenant, "tenant_id": tenant, "tenants": [tenant],
                     "permissions": {}}}


def test_reports_listed_in_any_case_may_be_edited_sent_and_deleted(monkeypatch):
    """A "dxp" user is listed the "DXP" report and offered "DXP" as its
    dashboard, so editing, test-sending and deleting it are allowed too."""
    c, state, sent = _reports_client(_report_user("dxp"), monkeypatch)
    assert [r["id"] for r in c.get("/api/reports/list").json()["reports"]] == ["r1"]
    assert [t["id"] for t in c.get("/api/reports/tenants").json()["tenants"]] == ["DXP"]
    assert c.post("/api/reports/r1/test").status_code == 200 and sent == ["DXP"]
    assert c.put("/api/reports/r1", json={"name": "Renamed"}).status_code == 200
    assert c.delete("/api/reports/r1").json() == {"removed": True}
    assert state.system_state["global_config"]["email_reports"] == []


def test_another_tenants_report_stays_hidden_and_locked(monkeypatch):
    """Another tenant's user is neither listed the report nor allowed to touch it."""
    c, state, sent = _reports_client(_report_user("other"), monkeypatch)
    assert c.get("/api/reports/list").json()["reports"] == []
    assert [t["id"] for t in c.get("/api/reports/tenants").json()["tenants"]] == ["other"]
    for r in (c.put("/api/reports/r1", json={"name": "x"}), c.delete("/api/reports/r1"),
              c.post("/api/reports/r1/test")):
        assert r.status_code == 403
    assert sent == [] and len(state.system_state["global_config"]["email_reports"]) == 1


def test_offline_alert_covers_a_spoke_bound_in_another_case():
    """A spoke tagged "DXP" is tenant "dxp"'s, so its outage is evaluated for
    that tenant; another tenant's spoke is not, and an unbound one still is."""
    import alert_engine as ae
    from display_names import node_name
    seen = []

    class _Engine:
        """Records each evaluated alert key."""
        async def evaluate(self, tenant, source, key, bad, msg, severity=None, extra=None):
            seen.append(key)

    md = {"s1": {"tenant_id": "DXP", "module_type": "nw", "display_name": "dxp-nw"},
          "s2": {"tenant_id": "other", "module_type": "nw", "display_name": "other-nw"},
          "s3": {"module_type": "nw", "display_name": "unbound-nw"}}
    engine = _Engine()
    engine.hub = SimpleNamespace(
        get_active_spoke_alerts=lambda: [{"spoke_id": s, "tier": "error"} for s in md],
        state=SimpleNamespace(system_state={"module_metadata": md}),
        spoke_module_types={}, _primary_key=lambda sid: sid)
    asyncio.run(ae._eval_tenant(engine, None, "dxp", {"spoke_offline"}))
    assert seen == [node_name(engine.hub.state.system_state, s) for s in ("s1", "s3")]


def test_a_stored_Default_is_not_the_built_in_admin_tenant(monkeypatch):
    # A legacy "Default" record differs from the built-in Admin tenant
    # "default" (which exists without a record) only by case.
    _keep_tenant_cache(monkeypatch)
    s = _state({"Default": {}, "other": {}})
    access.refresh_shared_tenant(SimpleNamespace(state=s))
    # Each keeps its exact spelling: the record gets no Admin scope ...
    assert not access.same_tenant("Default", "default")
    assert access.tenant_scope_ids("Default") == {"Default"}
    assert access.tenant_scope_ids("default") == {"", "default"}
    # ... and a third spelling names neither.
    assert s.tenant_key("default") == "default"
    assert s.tenant_key("Default") == "Default"
    with pytest.raises(ValueError):
        s.tenant_key("DEFAULT")


def test_tenants_differing_only_by_surrounding_spaces_are_told_apart(monkeypatch):
    # "ACME" and " ACME " were both saved before tenant ids were kept unique.
    _keep_tenant_cache(monkeypatch)
    s = _state({"ACME": {"n": 1}, " ACME ": {"n": 2}})
    s.system_state["users"] = {"u": {"tenants": ["ACME", " ACME "]}}
    access.refresh_shared_tenant(SimpleNamespace(state=s))
    assert not access.same_tenant("ACME", " ACME ")
    assert not access.tenant_among(" ACME ", ["ACME"])
    with pytest.raises(ValueError):
        s.tenant_key("acme")
    # A member of one is refused the other by the module-tenant resolver.
    assert access.resolve_module_tenant(False, [" ACME "], "ACME")[1] == 403
    assert access.resolve_module_tenant(False, ["ACME"], "ACME") == ("ACME", None, None)
    # Reads and deletes by the exact id reach that record, never its twin.
    assert s.get_tenant(" ACME ") == {"n": 2}
    assert s.get_tenant("ACME") == {"n": 1}
    assert s.delete_tenant(" ACME ") == ["u"]
    assert s.tenant_state["tenants"] == {"ACME": {"n": 1}}
    assert s.system_state["users"]["u"]["tenants"] == ["ACME"]


def test_a_blank_tenant_id_names_no_tenant():
    s = _state({"acme": {}})
    for blank in ("", "  ", None):
        with pytest.raises(ValueError):
            s.update_tenant(blank, {})
        with pytest.raises(ValueError):
            s.assign_user_to_tenant("u", blank)
    assert s.tenant_state["tenants"] == {"acme": {}}
    assert "u" not in s.system_state.get("users", {})
    # A blank-id record saved before that stays editable by its exact id, so
    # the single-shared sweep can still clear its flag.
    legacy = _state({" ": {"shared": True}})
    legacy.update_tenant(" ", {"shared": False})
    assert legacy.tenant_state["tenants"] == {" ": {"shared": False}}


def test_a_blank_tenant_selection_is_the_shared_tenant_alone():
    # No selection is an unscoped programmatic call; a selection of only
    # spaces (a legacy blank grant or record) fails closed instead of
    # widening to the whole fleet.
    assert access.tenant_scope_ids(None) is None
    assert access.tenant_scope_ids("") is None
    assert access.tenant_scope_ids("  ") == {"shared-co"}
    assert not access.in_tenant_scope("acme", access.tenant_scope_ids("  "))


def test_a_blank_tenant_flagged_shared_is_not_the_shared_tenant(monkeypatch):
    # A legacy record whose id is only spaces, flagged shared, names no
    # tenant. As the shared tenant it canonicalised to "" and put every
    # unassigned record in every tenant's scope.
    _keep_tenant_cache(monkeypatch)
    hub = SimpleNamespace(state=_state({"  ": {"shared": True}, "acme": {},
                                        "shared-co": {"shared": True}}))
    assert access.refresh_shared_tenant(hub) == "shared-co"
    scope = access.tenant_scope_ids("acme")
    assert access.in_tenant_scope("shared-co", scope)
    assert not access.in_tenant_scope("", scope)
    # Only the blank record flagged: there is no shared tenant.
    hub.state.tenant_state["tenants"]["shared-co"]["shared"] = False
    assert access.refresh_shared_tenant(hub) is None
    assert not access.in_tenant_scope("", access.tenant_scope_ids("acme"))
    # A blank shared id cached some other way still adds nothing.
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "  ")
    assert access.tenant_scope_ids("acme") == {"acme"}

