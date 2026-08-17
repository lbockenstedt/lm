"""Tests for the Credential Vault bucket-listing route (``cv_buckets``).

A **Global Admin** must see a bucket for EVERY tenant — even tenants that have
no secrets/pass-phrase yet — plus the ``__admin__`` slot, so they can add or
remove credentials for any tenant when they hold that tenant's pass-phrase. A
**tenant-admin** only sees their own tenant buckets.

The route + helpers are closures inside ``routes/cred_vault.py``'s registration
function, so (like ``test_console_credentials_source``) we lift the relevant
FunctionDef nodes with ``ast``, strip their ``@app.get`` decorators, and exec
them in a namespace wired with in-memory fakes — no FastAPI app required.
"""
import ast
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_CV_ROUTES = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "cred_vault.py")
_WANTED = {"_all_tenants", "cv_buckets"}
_ADMIN = "__admin__"


def _load(ns_extra):
    src = open(_CV_ROUTES).read()
    tree = ast.parse(src)
    ns = {"Request": object, "HTTPException": Exception}
    ns.update(ns_extra)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _WANTED:
            node.decorator_list = []  # drop @app.get(...) so we can exec bare
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CV_ROUTES, "exec"), ns)
    return ns


class _Hub:
    def __init__(self, tenants):
        self.state = types.SimpleNamespace(tenant_state={"tenants": tenants})


class _FakeCV:
    ADMIN_BUCKET = _ADMIN

    def __init__(self, existing):
        self._existing = existing

    def list_buckets(self, hub):
        return self._existing

    def _vault_available(self, hub):
        return True


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _ns(hub, cv, sess, is_ga):
    return {
        "hub": hub, "_cv": cv,
        "_sess": lambda request: sess,
        "_is_global_admin": lambda s: is_ga,
        "_acting_tenants": lambda s: (s.get("user", {}).get("tenants") or []),
    }


def test_all_tenants_excludes_default_and_labels():
    hub = _Hub({"t-acme": {"display_name": "Acme Corp"},
                "t-globex": {"name": "Globex"},
                "t-bare": {},
                "default": {"name": "Unassigned"}})
    ns = _load(_ns(hub, _FakeCV([]), {}, True))
    got = ns["_all_tenants"](hub)
    assert got == {"t-acme": "Acme Corp", "t-globex": "Globex", "t-bare": "t-bare"}


def test_global_admin_sees_all_tenant_buckets_plus_admin_slot():
    hub = _Hub({"t-acme": {"display_name": "Acme Corp"}, "t-globex": {"name": "Globex"}})
    # Only t-acme has any secrets so far; t-globex has none yet.
    cv = _FakeCV([{"bucket": "t-acme", "has_psk": True, "secret_count": 2}])
    ns = _load(_ns(hub, cv, {"user": {"tenants": []}}, True))
    res = _run(ns["cv_buckets"](object()))
    buckets = {b["bucket"]: b for b in res["buckets"]}
    assert set(buckets) == {"t-acme", "t-globex", _ADMIN}
    assert res["is_global_admin"] is True
    # empty tenant bucket surfaces with no-pass-phrase defaults + friendly name
    assert buckets["t-globex"]["has_psk"] is False
    assert buckets["t-globex"]["secret_count"] == 0
    assert buckets["t-globex"]["name"] == "Globex"
    # existing bucket keeps its real status
    assert buckets["t-acme"]["has_psk"] is True and buckets["t-acme"]["secret_count"] == 2
    assert buckets[_ADMIN]["is_admin_slot"] is True
    assert buckets[_ADMIN]["name"] == "Global Admin slot"


def test_tenant_admin_only_sees_their_own_buckets():
    hub = _Hub({"t-acme": {"name": "Acme"}, "t-globex": {"name": "Globex"}})
    cv = _FakeCV([{"bucket": "t-acme", "has_psk": True, "secret_count": 1}])
    ns = _load(_ns(hub, cv, {"user": {"tenants": ["t-acme"]}}, False))
    res = _run(ns["cv_buckets"](object()))
    buckets = {b["bucket"] for b in res["buckets"]}
    assert buckets == {"t-acme"}          # no other tenant, no admin slot
    assert _ADMIN not in buckets
    assert res["is_global_admin"] is False
