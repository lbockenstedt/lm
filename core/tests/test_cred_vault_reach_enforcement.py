"""Adversarial tests for Credential Vault *reach enforcement* on the read/write
endpoints (``cv_reveal`` and the shared ``_reachable``/``_require_reach``).

``test_cred_vault_buckets.py`` proves the bucket *listing* hides unreachable
buckets. That is cosmetic: an attacker does not use the UI list — they POST
straight at ``/tenant/cred-vault/reveal`` with an arbitrary ``bucket``. These
tests exercise that attack path and assert two things hold:

* a tenant-admin POSTing for the ``__admin__`` infrastructure slot, or for a
  tenant they do not own, is refused with a 404 (existence never leaks); and
* the refusal happens *before* ``_cv.reveal_secret`` runs — so no decrypt of a
  foreign secret is ever attempted (the enforcement is not merely a
  response-filter after the fact).

Like the sibling test, the route + helpers are closures inside
``routes/cred_vault.py``'s ``register`` function, so we lift the relevant
FunctionDef nodes with ``ast`` (dropping their decorators) and exec them in a
namespace wired with in-memory fakes — no FastAPI app required.
"""
import ast
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_CV_ROUTES = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "cred_vault.py")
_WANTED = {"_reachable", "_require_reach", "cv_reveal"}
_ADMIN = "__admin__"


class _HTTPException(Exception):
    def __init__(self, status_code=None, detail=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _FakeCV:
    ADMIN_BUCKET = _ADMIN

    def __init__(self):
        self.revealed = []  # records every (bucket, name) actually decrypted

    async def reveal_secret(self, hub, bucket, name, psk="", actor="?"):
        self.revealed.append((bucket, name))
        return "PLAINTEXT-" + bucket


def _load(ns_extra):
    src = open(_CV_ROUTES).read()
    tree = ast.parse(src)
    ns = {
        "Request": object,
        "HTTPException": _HTTPException,
        "JSONResponse": lambda content=None, headers=None: content,
        "logger": type("L", (), {"info": staticmethod(lambda *a, **k: None)})(),
        "_NO_STORE": {},
    }
    ns.update(ns_extra)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _WANTED:
            node.decorator_list = []  # drop @_guard / @app.post so we can exec bare
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CV_ROUTES, "exec"), ns)
    return ns


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _ns(cv, sess, is_ga, body):
    return {
        "hub": object(), "_cv": cv,
        "_sess": lambda request: sess,
        "_actor": lambda s: "attacker",
        "_body": lambda request: _coro(body),
        "_is_global_admin": lambda s: is_ga,
        "_acting_tenants": lambda s: (s.get("user", {}).get("tenants") or []),
    }


async def _coro(v):
    return v


# ── the pure predicate ──────────────────────────────────────────────────────
def test_reachable_predicate_denies_cross_tenant_and_admin_slot():
    ns = _load(_ns(_FakeCV(), {"user": {"tenants": ["t-acme"]}}, False, {}))
    reach = ns["_reachable"]
    sess = {"user": {"tenants": ["t-acme"]}}
    assert reach(sess, "t-acme") is True           # own tenant
    assert reach(sess, "t-globex") is False         # foreign tenant
    assert reach(sess, _ADMIN) is False             # infra slot
    assert reach(sess, "") is False                 # empty


def test_reachable_predicate_global_admin_reaches_everything():
    ns = _load(_ns(_FakeCV(), {"user": {"tenants": []}}, True, {}))
    reach = ns["_reachable"]
    sess = {"user": {"tenants": []}}
    assert reach(sess, "t-acme") is True
    assert reach(sess, "t-globex") is True
    assert reach(sess, _ADMIN) is True


# ── the live attack surface: POST straight at reveal ────────────────────────
def test_tenant_admin_reveal_admin_slot_is_404_and_no_decrypt():
    cv = _FakeCV()
    ns = _load(_ns(cv, {"user": {"tenants": ["t-acme"]}}, False,
                   {"bucket": _ADMIN, "name": "root_pw", "psk": "guess"}))
    try:
        _run(ns["cv_reveal"](object()))
        assert False, "expected refusal"
    except _HTTPException as e:
        assert e.status_code == 404
    assert cv.revealed == []  # decrypt of the infra secret NEVER attempted


def test_tenant_admin_reveal_foreign_tenant_is_404_and_no_decrypt():
    cv = _FakeCV()
    ns = _load(_ns(cv, {"user": {"tenants": ["t-acme"]}}, False,
                   {"bucket": "t-globex", "name": "api_key", "psk": "guess"}))
    try:
        _run(ns["cv_reveal"](object()))
        assert False, "expected refusal"
    except _HTTPException as e:
        assert e.status_code == 404
    assert cv.revealed == []


def test_tenant_admin_reveal_own_tenant_succeeds():
    cv = _FakeCV()
    ns = _load(_ns(cv, {"user": {"tenants": ["t-acme"]}}, False,
                   {"bucket": "t-acme", "name": "api_key", "psk": "correct"}))
    out = _run(ns["cv_reveal"](object()))
    assert out["value"] == "PLAINTEXT-t-acme"
    assert cv.revealed == [("t-acme", "api_key")]


def test_global_admin_reveal_admin_slot_succeeds():
    cv = _FakeCV()
    ns = _load(_ns(cv, {"user": {"tenants": []}}, True,
                   {"bucket": _ADMIN, "name": "root_pw", "psk": "correct"}))
    out = _run(ns["cv_reveal"](object()))
    assert out["value"] == "PLAINTEXT-__admin__"
    assert cv.revealed == [(_ADMIN, "root_pw")]
