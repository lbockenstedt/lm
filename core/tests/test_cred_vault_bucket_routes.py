"""Tests for the ``move-secret`` and ``delete-bucket`` route guards.

These two endpoints are the only destructive-by-design operations in the
Credential Vault, so the guards matter as much as the engine:

* Both are Global-Admin only, and answer **404** (not 403) for everyone else so
  the endpoint's existence is not advertised to tenant-admins.
* ``delete-bucket`` refuses any bucket that belongs to a LIVE tenant — those
  follow the tenant lifecycle. The endpoint exists to clear up ORPHANED
  buckets, which match no tenant and can therefore never be referenced.

Like ``test_cred_vault_buckets``, the routes are closures inside the
registration function, so we lift them with ``ast`` and exec them against
in-memory fakes rather than standing up FastAPI.
"""
import ast
import asyncio
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_CV_ROUTES = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "cred_vault.py")
_WANTED = {"_all_tenants", "cv_move_secret", "cv_delete_bucket"}


class _HTTPError(Exception):
    def __init__(self, status_code=500, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _load(ns_extra):
    src = open(_CV_ROUTES).read()
    tree = ast.parse(src)
    ns = {"Request": object, "HTTPException": _HTTPError}
    ns.update(ns_extra)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _WANTED:
            node.decorator_list = []  # drop @app.post(...) / @_guard
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CV_ROUTES, "exec"), ns)
    return ns


class _Hub:
    def __init__(self, tenants):
        self.state = types.SimpleNamespace(tenant_state={"tenants": tenants})


class _FakeCV:
    ADMIN_BUCKET = "__admin__"

    def __init__(self):
        self.moved = []
        self.deleted = []

    async def move_secret(self, hub, bucket, name, to_bucket, **kw):
        self.moved.append((bucket, name, to_bucket, kw))
        return {"name": name, "from": bucket, "to": to_bucket}

    async def delete_bucket(self, hub, bucket, **kw):
        self.deleted.append((bucket, kw))
        return {"bucket": bucket, "destroyed": []}


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _ns(hub, cv, *, is_ga=True):
    return {
        "hub": hub, "_cv": cv,
        "_sess": lambda request: {"user": {"username": "gadmin"}},
        "_is_global_admin": lambda s: is_ga,
        "_actor": lambda s: "gadmin",
        "_require_reach": lambda s, b: None,
        "_body": _fake_body,
    }


_BODY = {}


async def _fake_body(request):
    return dict(_BODY)


def _set_body(**kw):
    _BODY.clear()
    _BODY.update(kw)


TENANTS = {"default": {"name": "DEFAULT"}, "lrb": {"name": "LRB"}}


# ── move-secret ──────────────────────────────────────────────────────────────
def test_move_secret_forwards_both_passphrases():
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv))
    _set_body(bucket="orphan", name="acct", to_bucket="lrb",
              psk="src", to_psk="dst")

    res = _run(ns["cv_move_secret"](object()))

    assert res["status"] == "ok"
    bucket, name, to_bucket, kw = cv.moved[0]
    assert (bucket, name, to_bucket) == ("orphan", "acct", "lrb")
    assert kw["psk"] == "src" and kw["to_psk"] == "dst"


def test_move_secret_hidden_from_tenant_admins():
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv, is_ga=False))
    _set_body(bucket="orphan", name="acct", to_bucket="lrb")

    with pytest.raises(_HTTPError) as exc:
        _run(ns["cv_move_secret"](object()))

    assert exc.value.status_code == 404
    assert not cv.moved


# ── delete-bucket ────────────────────────────────────────────────────────────
def test_delete_bucket_allows_orphan():
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv))
    _set_body(bucket="admin", confirm_destroy=True)

    res = _run(ns["cv_delete_bucket"](object()))

    assert res["status"] == "ok"
    assert cv.deleted[0][0] == "admin"
    assert cv.deleted[0][1]["confirm_destroy"] is True


def test_delete_bucket_refuses_live_tenant_bucket():
    """A live tenant's bucket follows the tenant lifecycle — deleting it here
    would leave the tenant present but its credentials gone."""
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv))
    _set_body(bucket="lrb", confirm_destroy=True)

    with pytest.raises(_HTTPError) as exc:
        _run(ns["cv_delete_bucket"](object()))

    assert exc.value.status_code == 400
    assert not cv.deleted


def test_delete_bucket_refuses_default_tenant_bucket():
    """``default`` is a real tenant (it owns spokes), not a system bucket."""
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv))
    _set_body(bucket="default", confirm_destroy=True)

    with pytest.raises(_HTTPError):
        _run(ns["cv_delete_bucket"](object()))
    assert not cv.deleted


def test_delete_bucket_hidden_from_tenant_admins():
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv, is_ga=False))
    _set_body(bucket="admin")

    with pytest.raises(_HTTPError) as exc:
        _run(ns["cv_delete_bucket"](object()))

    assert exc.value.status_code == 404
    assert not cv.deleted


def test_delete_bucket_defaults_to_non_destructive():
    """Omitting the confirmation must not be read as consent to destroy."""
    cv = _FakeCV()
    ns = _load(_ns(_Hub(TENANTS), cv))
    _set_body(bucket="admin")

    _run(ns["cv_delete_bucket"](object()))

    assert cv.deleted[0][1]["confirm_destroy"] is False
