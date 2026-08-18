"""Regression: the per-cert tenant-assignment PUT (``le_set_cert_tenants`` in
``routes/net_services.py``) must SURFACE a failed durable write instead of
returning a false ``{"status":"ok"}``.

Bug: the handler persisted via a helper that swallowed a ``save_state_now``
failure and logged a warning, so the WebUI showed a green "Tenants updated"
toast even though the assignment never reached disk — and it was silently lost
on the next hub restart ("I get a success toast but when I go back in the cert
is not assigned to the tenant"). The fix persists like its sibling LE change
ops and raises HTTP 500 when the durable write fails.

The route is a decorated closure inside ``register``; we lift it with ``ast``
(dropping the decorator) and exec it in a namespace wired with fakes + the real
``le_cert_access`` module.
"""
import ast
import asyncio
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import le_cert_access as lca  # noqa: E402

_NS = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "net_services.py")


class _HTTPError(Exception):
    def __init__(self, status_code=400, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _State:
    def __init__(self, save_raises):
        self.system_state = {"global_config": {}}
        self.tenant_state = {"tenants": {"t1": {}, "t2": {}}}
        self._save_raises = save_raises
        self.saved = 0

    async def save_state_now(self):
        if self._save_raises:
            raise OSError("disk full / permission denied")
        self.saved += 1


class _Hub:
    def __init__(self, save_raises):
        self.state = _State(save_raises)


class _Req:
    def __init__(self, tenants):
        self._tenants = tenants

    async def json(self):
        return {"tenants": self._tenants}


@pytest.fixture(autouse=True)
def _access(monkeypatch):
    # le_cert_access calls access.is_admin / shared_tenant_id; force admin so
    # validate_tenant_edit accepts any existing-tenant set. monkeypatch RESTORES
    # these after each test so we don't pollute the shared ``access`` module for
    # the rest of the pytest session.
    import access
    monkeypatch.setattr(access, "is_admin", lambda sess: True)
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared")


def _load(hub):
    """Lift ``le_set_cert_tenants`` out of net_services with fakes injected."""
    src = open(_NS).read()
    tree = ast.parse(src)
    ns = {
        "Request": object,
        "HTTPException": _HTTPError,
        "logger": types.SimpleNamespace(
            warning=lambda *a, **k: None, info=lambda *a, **k: None,
            error=lambda *a, **k: None),
        "app": types.SimpleNamespace(state=types.SimpleNamespace(hub=hub)),
        "hub": hub,
        "_lca": lca,
        "_session_user": lambda request: {"user": {"tenants": ["t1"], "tenant_id": "t1"}},
        # Admin so validate_tenant_edit accepts any existing-tenant set.
        "_le_guard_change": lambda request, domain: None,
        "_tenant_exists": lambda tid: tid in hub.state.tenant_state["tenants"],
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "le_set_cert_tenants":
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _NS, "exec"), ns)
    return ns["le_set_cert_tenants"]


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_persist_success_returns_ok_and_stores():
    hub = _Hub(save_raises=False)
    fn = _load(hub)
    out = _run(fn("a.example.com", _Req(["t1", "t2"])))
    assert out["status"] == "ok"
    assert hub.state.saved == 1
    assert lca.get_tenants(hub, "a.example.com") == ["t1", "t2"]


def test_failed_persist_raises_500_not_false_ok():
    hub = _Hub(save_raises=True)
    fn = _load(hub)
    with pytest.raises(_HTTPError) as ei:
        _run(fn("a.example.com", _Req(["t1", "t2"])))
    assert ei.value.status_code == 500
    assert "saved" in ei.value.detail.lower() or "disk" in ei.value.detail.lower()
