"""Regression guard for ``access.vm_in_tenant_scope`` — the toggle-independent
VM CONTROL/console ownership gate (VNC console, start/stop/snapshot/clone…).

THE bug: a tenant-admin assigned MULTIPLE tenants only carried a session
``tenant_id`` of ``tenants[0]``, and the gate checked ownership against that one
tenant only. A VM owned by any of the admin's OTHER tenants was denied with
"not authorized for this VM's tenant" — even though the VM list (which fails
open when the display filter is off) still showed it. The gate must authorize
across EVERY assigned tenant, matching ``spoke_visible_to_session`` /
``read_scope`` / ``write_scope`` / ``check_tenant_access``.
"""
import asyncio

import access
from _fakes import FakeHub, FakeState


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _hub():
    # Two tenants, each with a distinct Proxmox tag.
    return FakeHub(FakeState(tenants={
        "acme": {"name": "Acme", "proxmox_tag": "acme"},
        "globex": {"name": "Globex", "proxmox_tag": "globex"},
    }))


def _sess(tenants, tenant_id=None):
    return {"user": {"permissions": {"role": "tenant-admin"},
                     "tenants": tenants,
                     "tenant_id": tenant_id if tenant_id is not None
                     else (tenants[0] if tenants else None)}}


def _no_prefixes(monkeypatch):
    async def _empty(hub, tid):
        return []
    monkeypatch.setattr(access, "resolve_prefixes_for_tenant", _empty)


# ── Admin bypass ─────────────────────────────────────────────────────────────
def test_admin_always_allowed(monkeypatch):
    _no_prefixes(monkeypatch)
    sess = {"user": {"permissions": {"admin": True}}}
    assert _run(access.vm_in_tenant_scope(_hub(), sess, {"tags": ["nobody"]})) is True


# ── Single-tenant (unchanged behaviour) ──────────────────────────────────────
def test_single_tenant_tag_match(monkeypatch):
    _no_prefixes(monkeypatch)
    sess = _sess(["acme"])
    assert _run(access.vm_in_tenant_scope(_hub(), sess, {"tags": ["acme"]})) is True


def test_single_tenant_no_match_denied(monkeypatch):
    _no_prefixes(monkeypatch)
    sess = _sess(["acme"])
    assert _run(access.vm_in_tenant_scope(_hub(), sess, {"tags": ["globex"]})) is False


# ── Multi-tenant admin: THE fix ──────────────────────────────────────────────
def test_multi_tenant_matches_non_primary_tenant_tag(monkeypatch):
    _no_prefixes(monkeypatch)
    # Primary tenant is acme (tenants[0]); the VM belongs to globex.
    sess = _sess(["acme", "globex"])
    assert _run(access.vm_in_tenant_scope(_hub(), sess, {"tags": ["globex"]})) is True


def test_multi_tenant_still_denies_foreign_vm(monkeypatch):
    _no_prefixes(monkeypatch)
    sess = _sess(["acme", "globex"])
    assert _run(access.vm_in_tenant_scope(_hub(), sess, {"tags": ["initech"]})) is False


# ── Subnet attribution on a non-primary tenant ───────────────────────────────
def test_multi_tenant_subnet_match_non_primary(monkeypatch):
    async def _prefixes(hub, tid):
        return ["10.20.0.0/16"] if tid == "globex" else []
    monkeypatch.setattr(access, "resolve_prefixes_for_tenant", _prefixes)
    sess = _sess(["acme", "globex"])
    vm = {"tags": [], "ips": ["10.20.5.9"]}
    assert _run(access.vm_in_tenant_scope(_hub(), sess, vm)) is True


# ── Fail-closed: no assigned tenant ──────────────────────────────────────────
def test_no_tenants_denied(monkeypatch):
    _no_prefixes(monkeypatch)
    assert _run(access.vm_in_tenant_scope(_hub(), _sess([]), {"tags": ["acme"]})) is False


# ── Legacy session (tenant_id set, tenants list absent) ──────────────────────
def test_legacy_tenant_id_fallback(monkeypatch):
    _no_prefixes(monkeypatch)
    sess = {"user": {"permissions": {"role": "tenant-admin"}, "tenant_id": "acme"}}
    assert _run(access.vm_in_tenant_scope(_hub(), sess, {"tags": ["acme"]})) is True
