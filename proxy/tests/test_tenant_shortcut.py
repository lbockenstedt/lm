"""Unit tests for the Phase-2 console-shortcut tenant gate (_tenant_allows_shortcut).

The gate decides whether a tenant-local edge proxy may relay a console session
straight to the co-located spoke (hub out of the byte path) or must fall back to
the hub WS proxy. Rule: shortcut ONLY when the proxy owns a specific, non-shared
tenant AND the target descriptor's tenant matches it.
"""
import os
import sys
import types

import pytest

pytest.importorskip("aiohttp")  # proxy_app imports aiohttp at module load

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import proxy_app  # noqa: E402


def _spoke(tenant_id="", tenant_shared=False):
    """Minimal stand-in exposing just the attributes the gate reads."""
    return types.SimpleNamespace(tenant_id=tenant_id, tenant_shared=tenant_shared)


def test_same_tenant_shortcuts():
    assert proxy_app._tenant_allows_shortcut(
        _spoke("lrb"), {"tenant_id": "lrb"}) is True


def test_cross_tenant_falls_back():
    assert proxy_app._tenant_allows_shortcut(
        _spoke("lrb"), {"tenant_id": "acme"}) is False


def test_shared_proxy_never_shortcuts():
    # Even if the target tenant matches, a proxy assigned to a shared tenant
    # must never take the LAN shortcut.
    assert proxy_app._tenant_allows_shortcut(
        _spoke("shared", tenant_shared=True), {"tenant_id": "shared"}) is False


def test_unassigned_proxy_never_shortcuts():
    assert proxy_app._tenant_allows_shortcut(
        _spoke(""), {"tenant_id": "lrb"}) is False


def test_target_without_tenant_falls_back():
    assert proxy_app._tenant_allows_shortcut(
        _spoke("lrb"), {}) is False


def test_missing_attrs_fail_closed():
    # A spoke lacking the tenant attributes (older config) must not shortcut.
    assert proxy_app._tenant_allows_shortcut(
        types.SimpleNamespace(), {"tenant_id": "lrb"}) is False
