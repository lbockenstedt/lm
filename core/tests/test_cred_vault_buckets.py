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

    def __init__(self, existing, psk_counts=None):
        self._existing = existing
        self._psk_counts = psk_counts or {}

    def list_buckets(self, hub):
        return self._existing

    def count_psk_secrets(self, hub, bucket):
        return self._psk_counts.get(bucket, 0)

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


def test_all_tenants_includes_default_and_labels():
    # ``default`` used to be excluded as a "system" bucket, but it is a real
    # tenant that owns real spokes (e.g. an nw agent bound to ``default``).
    # Hiding it meant a Global Admin could not create a vault entry for that
    # tenant, hence no scan-credential set for it, hence an nw agent on
    # ``default`` with no usable credentials and no way to fix it.
    hub = _Hub({"t-acme": {"display_name": "Acme Corp"},
                "t-globex": {"name": "Globex"},
                "t-bare": {},
                "default": {"name": "DEFAULT"}})
    ns = _load(_ns(hub, _FakeCV([]), {}, True))
    got = ns["_all_tenants"](hub)
    assert got == {"t-acme": "Acme Corp", "t-globex": "Globex",
                   "t-bare": "t-bare", "default": "DEFAULT"}


def test_default_tenant_gets_its_own_bucket():
    hub = _Hub({"default": {"name": "DEFAULT"}, "t-acme": {"name": "Acme"}})
    ns = _load(_ns(hub, _FakeCV([]), {"user": {"tenants": []}}, True))
    res = _run(ns["cv_buckets"](object()))
    buckets = {b["bucket"]: b for b in res["buckets"]}
    assert "default" in buckets
    assert buckets["default"]["name"] == "DEFAULT"
    assert buckets["default"]["is_orphan"] is False


def test_orphan_bucket_is_flagged_not_mistaken_for_the_admin_slot():
    # A bucket matching no tenant only shows up because it holds secrets.
    # Nothing tenant-scoped can reference it, so it must be flagged — otherwise
    # a stray bucket literally named "admin" renders next to "Global Admin slot"
    # and reads like a second admin scope.
    hub = _Hub({"t-acme": {"name": "Acme"}})
    cv = _FakeCV([{"bucket": "admin", "has_psk": True, "secret_count": 1},
                  {"bucket": "t-acme", "has_psk": True, "secret_count": 1}])
    ns = _load(_ns(hub, cv, {"user": {"tenants": []}}, True))
    res = _run(ns["cv_buckets"](object()))
    buckets = {b["bucket"]: b for b in res["buckets"]}
    assert buckets["admin"]["is_orphan"] is True
    assert buckets["admin"]["is_admin_slot"] is False
    assert buckets["admin"]["name"] == "admin"
    assert buckets[_ADMIN]["is_orphan"] is False   # the real slot is not orphaned
    assert buckets["t-acme"]["is_orphan"] is False


def test_psk_secret_count_is_reported_for_the_reset_impact_warning():
    hub = _Hub({"t-acme": {"name": "Acme"}})
    cv = _FakeCV([{"bucket": "t-acme", "has_psk": True, "secret_count": 3}],
                 psk_counts={"t-acme": 2})
    ns = _load(_ns(hub, cv, {"user": {"tenants": []}}, True))
    res = _run(ns["cv_buckets"](object()))
    acme = {b["bucket"]: b for b in res["buckets"]}["t-acme"]
    assert acme["psk_secret_count"] == 2


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
