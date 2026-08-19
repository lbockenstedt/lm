"""Regression: GET ``/api/le/certs`` must tag each cert with its owner
``tenants`` at the depth the response actually carries them.

Bug ("I assign ``*.orange-tme.com`` to SHARED, save succeeds, but re-open shows
no tenant"): the assignment WAS stored + persisted correctly in
``global_config['le_cert_tenants']``, but the read-side tagger ``_tag_cert_tenants``
(and its siblings ``_tag_ab`` / ``_filter_le_certs``) read the cert list
from TOP-LEVEL ``data['certs']``. The real relay + warm-cache shape nests it a
level deeper — ``{"status":"SUCCESS","data":{"certs":[...]}}`` — and the WebUI
reads it via ``inner(d).certs`` (i.e. ``d['data']['certs']``). So the tag was
written to a nonexistent top-level list and never reached the certs the UI
renders → every cert looked tenant-less regardless of what was saved.

Fix: ``_le_certs_holder`` / ``_le_with_certs`` locate + replace the cert list at
whatever depth it lives, so the tag lands on the list the UI reads. These tests
lift the closures out of net_services with ``ast`` and assert the nested
(production) shape is tagged, while the flat shape keeps working.
"""
import ast
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import le_cert_access as lca  # noqa: E402

_NS = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "net_services.py")


class _State:
    def __init__(self):
        self.system_state = {
            "global_config": {lca.STORE_KEY: {"*.orange-tme.com": ["shared"]}}
        }
        self.tenant_state = {"tenants": {"shared": {"name": "SHARED"}}}


class _Hub:
    def __init__(self):
        self.state = _State()


@pytest.fixture(autouse=True)
def _access(monkeypatch):
    import access
    monkeypatch.setattr(access, "is_admin", lambda sess: True)
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared")


def _load(hub, names):
    """Lift the named closures out of net_services into one shared namespace so
    they can call each other (``_tag_cert_tenants`` → ``_le_certs_holder`` /
    ``_le_with_certs`` / ``_le_cert_tenant_store_keys``)."""
    src = open(_NS).read()
    tree = ast.parse(src)
    ns = {
        "Request": object,
        "logger": types.SimpleNamespace(
            warning=lambda *a, **k: None, info=lambda *a, **k: None,
            error=lambda *a, **k: None),
        "hub": hub,
        "_lca": lca,
        "_session_user": lambda request: {"user": {"tenants": [], "tenant_id": "default"}},
        "_le_cert_tenant_store_keys": lambda: sorted(
            (hub.state.system_state.get("global_config", {}) or {}).get(lca.STORE_KEY, {})),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in names:
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _NS, "exec"), ns)
    return ns


def _tagger(hub):
    ns = _load(hub, {"_le_certs_holder", "_le_with_certs", "_tag_cert_tenants"})
    return ns["_tag_cert_tenants"], ns["_le_certs_holder"]


def test_nested_envelope_shape_is_tagged():
    """The production shape: certs under ``data['data']['certs']``."""
    hub = _Hub()
    tag, _ = _tagger(hub)
    resp = {"status": "SUCCESS",
            "data": {"certs": [{"domain": "*.orange-tme.com"},
                               {"domain": "other.example.com"}]}}
    out = tag(object(), resp)
    certs = out["data"]["certs"]
    by = {c["domain"]: c for c in certs}
    assert by["*.orange-tme.com"]["tenants"] == ["shared"]
    assert by["*.orange-tme.com"]["shared"] is True
    assert by["other.example.com"]["tenants"] == []
    # The envelope is preserved, and no stray top-level certs list is injected.
    assert out["status"] == "SUCCESS"
    assert "certs" not in out


def test_flat_shape_still_tagged():
    """The unit-test / already-unwrapped shape keeps working."""
    hub = _Hub()
    tag, _ = _tagger(hub)
    out = tag(object(), {"certs": [{"domain": "*.orange-tme.com"}]})
    assert out["certs"][0]["tenants"] == ["shared"]


def test_holder_finds_list_at_both_depths():
    hub = _Hub()
    _, holder = _tagger(hub)
    assert holder({"certs": [1, 2]}) == [1, 2]
    assert holder({"data": {"certs": [3]}}) == [3]
    assert holder({"status": "SUCCESS"}) is None
    assert holder("nope") is None
