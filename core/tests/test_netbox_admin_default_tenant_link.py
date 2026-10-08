"""Creating a NetBox prefix/rack while the WebUI's "currently selected
tenant" is the built-in Admin tenant ("default") must still carry that
tenant's NetBox link.

Every other LM tenant is 1:1 with its own NetBox slug, so the WebUI stamps
``currentTenant`` straight into the create body's ``tenant`` field. 'default'
is excluded there -- it doubles as the unscoped/global sentinel -- so an
object created while "in" the Admin tenant always came back UNASSIGNED in
NetBox: the body carried no tenant at all, and nothing resolved one.

Note the Admin tenant is NOT itself a NetBox tenant and nothing in NetBox is
named/slugged "admin" -- LM's own ``/setup/tenants`` route hardcodes the
"ADMIN" label for tenant id "default" purely for display. The real NetBox
tenant it maps to is the one literally slugged "default" (whatever its
display name is in NetBox).

``_enforce_body_tenant`` now falls back to resolving the caller's selected
tenant context (``?tenant=`` query param -- the same convention every read
route already uses) through that tenant's configured ``netbox_tenant_slug``
when the body omits ``tenant`` (an explicit override always wins), and -- for
the built-in Admin tenant specifically -- further falls back to the literal
"default" slug when nothing is configured, so it links to NetBox's "default"
tenant without any manual setup step.
"""
import api as api_mod

from test_auth_session_security import _build, _mint_session


def _capture_request_response(hub, status="SUCCESS", extra=None):
    """Patch hub.request_response to record the outgoing payload and return a
    canned SUCCESS envelope (mirrors the real NetBox spoke reply shape)."""
    calls = []

    async def _fake(spoke_id, cmd, data, timeout=30.0):
        calls.append((cmd, data))
        body = {"status": status}
        if extra:
            body.update(extra)
        return {"payload": {"data": body}}

    hub.request_response = _fake
    return calls


def test_admin_create_prefix_resolves_configured_default_tenant_slug(tmp_path):
    # An explicit override (set via Edit Tenant) always wins over the
    # built-in "default" fallback.
    c, hub = _build({}, tmp_path)
    hub.state.get_tenant = lambda tid: (
        {"netbox_tenant_slug": "admin-lab"} if str(tid).strip() == "default" else None
    )
    calls = _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    r = c.post("/api/netbox/prefixes?tenant=default",
               json={"parent_prefix": "10.0.0.0/16", "prefix_length": 24},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text
    cmds = [c for c, _ in calls]
    assert "NETBOX_ALLOCATE_PREFIX" in cmds
    data = dict(calls)["NETBOX_ALLOCATE_PREFIX"]
    assert data["tenant"] == "admin-lab"


def test_admin_create_prefix_falls_back_to_literal_default_slug_when_unconfigured(tmp_path):
    # No netbox_tenant_slug configured for the Admin tenant: NetBox's actual
    # "default"-slugged tenant is used automatically, not left unassigned.
    c, hub = _build({}, tmp_path)
    hub.state.get_tenant = lambda tid: None  # no record / no configured slug
    calls = _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    r = c.post("/api/netbox/prefixes?tenant=default",
               json={"parent_prefix": "10.0.0.0/16", "prefix_length": 24},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text
    data = dict(calls)["NETBOX_ALLOCATE_PREFIX"]
    assert data["tenant"] == "default"


def test_admin_create_prefix_with_no_tenant_context_stays_unassigned(tmp_path):
    # No ?tenant= at all (e.g. a plain API call) -- unchanged legacy behavior:
    # the fallback only triggers once a tenant context is actually selected.
    c, hub = _build({}, tmp_path)
    hub.state.get_tenant = lambda tid: (
        {"netbox_tenant_slug": "admin-lab"} if str(tid).strip() == "default" else None
    )
    calls = _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    r = c.post("/api/netbox/prefixes",
               json={"parent_prefix": "10.0.0.0/16", "prefix_length": 24},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text
    data = dict(calls)["NETBOX_ALLOCATE_PREFIX"]
    assert data["tenant"] is None


def test_admin_explicit_body_tenant_still_wins_over_query_context(tmp_path):
    # A real (non-default) tenant selection is unaffected: the body tenant is
    # used verbatim regardless of any ?tenant= query context.
    c, hub = _build({}, tmp_path)
    hub.state.get_tenant = lambda tid: (
        {"netbox_tenant_slug": "admin-lab"} if str(tid).strip() == "default" else None
    )
    calls = _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    r = c.post("/api/netbox/prefixes?tenant=default",
               json={"parent_prefix": "10.0.0.0/16", "prefix_length": 24,
                     "tenant": "lrb"},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text
    data = dict(calls)["NETBOX_ALLOCATE_PREFIX"]
    assert data["tenant"] == "lrb"


def test_a_real_non_default_tenant_without_a_configured_slug_stays_unassigned(tmp_path):
    # The literal-"default"-slug fallback is scoped to the built-in Admin
    # tenant only; a real tenant with no netbox_tenant_slug configured must
    # NOT start getting a guessed slug.
    c, hub = _build({}, tmp_path)
    hub.state.get_tenant = lambda tid: None  # no record for "lrb" either
    calls = _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    r = c.post("/api/netbox/prefixes?tenant=lrb",
               json={"parent_prefix": "10.0.0.0/16", "prefix_length": 24},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text
    data = dict(calls)["NETBOX_ALLOCATE_PREFIX"]
    assert data["tenant"] is None

