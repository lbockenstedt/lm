"""Unit tests for ``le_cert_access`` — the per-certificate tenant ownership +
shared-tenant deploy authorization used by the LE module. Pure helpers over a
fake hub with a ``state.system_state`` dict; ``access.is_admin`` /
``access.shared_tenant_id`` are monkeypatched per test.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import access  # noqa: E402
import le_cert_access as lca  # noqa: E402


SHARED = "shared-tenant"


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}


class _Hub:
    def __init__(self):
        self.state = _State()


def _sess(tenants, tenant_id=None):
    return {"user": {"tenants": list(tenants),
                     "tenant_id": tenant_id or (tenants[0] if tenants else None)}}


@pytest.fixture
def hub():
    return _Hub()


@pytest.fixture(autouse=True)
def _access(monkeypatch):
    # Default: nobody is admin; a fixed shared-tenant id.
    monkeypatch.setattr(access, "is_admin", lambda sess: False)
    monkeypatch.setattr(access, "shared_tenant_id", lambda: SHARED)


def _admin(monkeypatch):
    monkeypatch.setattr(access, "is_admin", lambda sess: True)


# ── get / set / add / forget ────────────────────────────────────────────────
def test_set_get_roundtrip(hub):
    lca.set_tenants(hub, "a.com", ["t1", "t2"])
    assert lca.get_tenants(hub, "a.com") == ["t1", "t2"]


def test_set_dedupes_and_strips(hub):
    lca.set_tenants(hub, "a.com", [" t1 ", "t1", "", "t2"])
    assert lca.get_tenants(hub, "a.com") == ["t1", "t2"]


def test_set_empty_removes_entry(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    lca.set_tenants(hub, "a.com", [])
    assert lca.get_tenants(hub, "a.com") == []
    assert "a.com" not in hub.state.system_state["global_config"][lca.STORE_KEY]


def test_add_tenant_idempotent(hub):
    lca.add_tenant(hub, "a.com", "t1")
    lca.add_tenant(hub, "a.com", "t1")
    lca.add_tenant(hub, "a.com", "t2")
    assert lca.get_tenants(hub, "a.com") == ["t1", "t2"]


def test_forget(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.forget(hub, "a.com") is True
    assert lca.forget(hub, "a.com") is False
    assert lca.has_owners(hub, "a.com") is False


# ── ownership / shared ──────────────────────────────────────────────────────
def test_is_owner_by_tenant(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.is_owner(hub, _sess(["t1"]), "a.com") is True
    assert lca.is_owner(hub, _sess(["t9"]), "a.com") is False


def test_is_owner_admin(hub, monkeypatch):
    _admin(monkeypatch)
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.is_owner(hub, _sess(["t9"]), "a.com") is True


def test_is_shared(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.is_shared(hub, "a.com") is False
    lca.add_tenant(hub, "a.com", SHARED)
    assert lca.is_shared(hub, "a.com") is True


# ── visibility ──────────────────────────────────────────────────────────────
def test_visible_legacy_returns_none(hub):
    assert lca.visible_to(hub, _sess(["t1"]), "a.com", ["t1"]) is None


def test_visible_owner_true_other_false(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.visible_to(hub, _sess(["t1"]), "a.com", ["t1"]) is True
    assert lca.visible_to(hub, _sess(["t9"]), "a.com", ["t9"]) is False


def test_visible_shared_to_anyone(hub):
    lca.set_tenants(hub, "a.com", ["t1", SHARED])
    assert lca.visible_to(hub, _sess(["t9"]), "a.com", ["t9"]) is True


def test_visible_admin_true(hub, monkeypatch):
    _admin(monkeypatch)
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.visible_to(hub, _sess(["t9"]), "a.com", ["t9"]) is True


# ── can_change ──────────────────────────────────────────────────────────────
def test_can_change_legacy_true(hub):
    assert lca.can_change(hub, _sess(["t9"]), "a.com") is True


def test_can_change_owner_true_other_false(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.can_change(hub, _sess(["t1"]), "a.com") is True
    assert lca.can_change(hub, _sess(["t9"]), "a.com") is False


def test_can_change_shared_non_owner_false(hub):
    # A shared cert is deploy-only for a non-owner — NOT changeable.
    lca.set_tenants(hub, "a.com", ["t1", SHARED])
    assert lca.can_change(hub, _sess(["t9"]), "a.com") is False


def test_can_change_admin_true(hub, monkeypatch):
    _admin(monkeypatch)
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.can_change(hub, _sess(["t9"]), "a.com") is True


# ── can_deploy ──────────────────────────────────────────────────────────────
def test_can_deploy_owner(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.can_deploy(hub, _sess(["t1"]), "a.com", "t1") is True


def test_can_deploy_shared_own_device(hub):
    lca.set_tenants(hub, "a.com", ["t1", SHARED])
    assert lca.can_deploy(hub, _sess(["t9"]), "a.com", "t9") is True


def test_can_deploy_shared_other_device_false(hub):
    lca.set_tenants(hub, "a.com", ["t1", SHARED])
    assert lca.can_deploy(hub, _sess(["t9"]), "a.com", "t8") is False


def test_can_deploy_not_shared_non_owner_false(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.can_deploy(hub, _sess(["t9"]), "a.com", "t9") is False


def test_can_deploy_admin(hub, monkeypatch):
    _admin(monkeypatch)
    lca.set_tenants(hub, "a.com", ["t1"])
    assert lca.can_deploy(hub, _sess(["t9"]), "a.com", "t8") is True


# ── meta ────────────────────────────────────────────────────────────────────
def test_meta(hub):
    lca.set_tenants(hub, "a.com", ["t1", SHARED])
    m = lca.meta(hub, _sess(["t1"]), "a.com")
    assert m == {"tenants": ["t1", SHARED], "shared": True,
                 "owned": True, "can_edit": True}


# ── validate_tenant_edit ────────────────────────────────────────────────────
def _exists(known):
    return lambda tid: tid in known


def test_validate_unknown_tenant_rejected(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    with pytest.raises(lca.TenantEditError):
        lca.validate_tenant_edit(hub, _sess(["t1"]), "a.com",
                                 ["t1", "ghost"], _exists({"t1"}))


def test_validate_drop_self_rejected(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    with pytest.raises(lca.TenantEditError):
        # non-admin owner t1 tries to remove itself
        lca.validate_tenant_edit(hub, _sess(["t1"]), "a.com",
                                 [SHARED], _exists({"t1", SHARED}))


def test_validate_add_other_ok(hub):
    lca.set_tenants(hub, "a.com", ["t1"])
    out = lca.validate_tenant_edit(hub, _sess(["t1"]), "a.com",
                                   ["t1", "t2", SHARED],
                                   _exists({"t1", "t2", SHARED}))
    assert out == ["t1", "t2", SHARED]


def test_validate_admin_can_drop_anyone(hub, monkeypatch):
    _admin(monkeypatch)
    lca.set_tenants(hub, "a.com", ["t1", "t2"])
    out = lca.validate_tenant_edit(hub, _sess(["zzz"]), "a.com",
                                   ["t2"], _exists({"t2"}))
    assert out == ["t2"]
