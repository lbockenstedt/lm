"""Regression test for the vault secret-save guard (``cv_put_secret`` in
``routes/cred_vault.py``).

A DNS/provider credential always carries a non-secret ``provider`` marker. The
Edit form cannot prefill an encrypted password, so a re-save that leaves the
fields blank must be REJECTED — otherwise the stored secret is overwritten with
empty credentials (the exact way an HE.NET DNS-01 credential got stripped while
a Console login — which has no marker key — was correctly blocked).

The handler is a closure inside ``register``; we lift it with ``ast`` (stripping
its decorators) and exec it in a namespace wired with fakes.
"""
import ast
import asyncio
import os
import sys
import types

import pytest

_NS = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "cred_vault.py")


class _HTTPError(Exception):
    def __init__(self, status_code=400, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _load(put_calls, body_value):
    src = open(_NS).read()
    tree = ast.parse(src)

    async def _fake_body(request):
        return {"bucket": "__admin__", "name": "HE.NET", "mode": "hub",
                "type": "dns", "value": body_value, "psk": "pw"}

    async def _fake_put(hub, bucket, name, value, **kw):
        put_calls.append({"bucket": bucket, "name": name, "value": value})
        return {"bucket": bucket, "name": name, "mode": kw.get("mode")}

    ns = {
        "Request": object, "HTTPException": _HTTPError,
        "logger": types.SimpleNamespace(info=lambda *a, **k: None,
                                        warning=lambda *a, **k: None),
        "app": types.SimpleNamespace(post=lambda *a, **k: (lambda f: f)),
        "_guard": (lambda f: f),
        "hub": object(),
        "_sess": lambda request: {"user": {"name": "admin"}},
        "_body": _fake_body,
        "_require_reach": lambda sess, bucket: None,
        "_actor": lambda sess: "admin",
        "_cv": types.SimpleNamespace(put_secret=_fake_put),
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                node.name == "cv_put_secret":
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _NS, "exec"), ns)
    return ns["cv_put_secret"]


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_blank_he_login_is_rejected_not_stored():
    calls = []
    fn = _load(calls, {"provider": "he-login", "he_username": "", "he_password": ""})
    with pytest.raises(_HTTPError) as ei:
        _run(fn(object()))
    assert ei.value.status_code == 400
    assert "empty" in ei.value.detail
    assert calls == []  # never overwrote the stored credential


def test_provider_only_marker_is_rejected():
    calls = []
    fn = _load(calls, {"provider": "cloudflare"})
    with pytest.raises(_HTTPError):
        _run(fn(object()))
    assert calls == []


def test_filled_he_login_is_stored():
    calls = []
    fn = _load(calls, {"provider": "he-login",
                       "he_username": "acct@e.com", "he_password": "s3cret"})
    _run(fn(object()))
    assert len(calls) == 1
    assert calls[0]["value"]["he_password"] == "s3cret"


def test_non_provider_secret_unaffected():
    # A plain login secret (no provider marker) bypasses the provider guard and
    # is stored as-is (its own emptiness is enforced client-side).
    calls = []
    fn = _load(calls, {"username": "u", "password": "p"})
    _run(fn(object()))
    assert len(calls) == 1
