"""The hub middleware lets Tenant Admins reach /api/os-updates (the routes scope
them to their own nodes); ordinary users are still refused."""
import api as api_mod
from test_auth_session_security import _build, _isolate  # noqa: F401 — autouse fixture


def _session(hub, perms):
    return api_mod._record_session(hub, {
        "user_id": "u", "auth_type": "local", "permissions": perms,
        "tenants": ["acme"], "tenant_id": "acme", "protected": False})


def test_tenant_admin_passes_the_os_updates_gate(tmp_path):
    c, hub = _build({}, tmp_path)
    c.cookies.set("lm_session", _session(hub, {"role": "tenant_admin"}))
    r = c.get("/api/os-updates")
    assert r.json().get("detail") != "Admin access required"


def test_plain_user_is_refused_os_updates(tmp_path):
    c, hub = _build({}, tmp_path)
    c.cookies.set("lm_session", _session(hub, {"ipam": True}))
    assert c.get("/api/os-updates").status_code == 403
