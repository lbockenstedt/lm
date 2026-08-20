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


# ── _resp_headers: preserve duplicate Set-Cookie (SSO fix) ────────────────────
# The hub emits MULTIPLE Set-Cookie headers in one response (e.g. the OIDC
# callback sets lm_session AND deletes lm_oidc_state). A plain-dict copy collapses
# them, dropping the session cookie and breaking SSO through the proxy. Since the
# proxy holds no cookie state (DummyCookieJar), every Set-Cookie MUST reach the
# browser verbatim.
def _upstream_resp(pairs):
    from multidict import CIMultiDict
    return types.SimpleNamespace(headers=CIMultiDict(pairs), status=302)


def test_resp_headers_preserves_multiple_set_cookie():
    up = _upstream_resp([
        ("Set-Cookie", "lm_session=tok; HttpOnly; Path=/"),
        ("Set-Cookie", 'lm_oidc_state=""; Max-Age=0; Path=/'),
        ("Location", "/"),
    ])
    out = proxy_app._resp_headers(up)
    cookies = out.getall("Set-Cookie")
    assert len(cookies) == 2
    assert any("lm_session=tok" in c for c in cookies)
    assert any("lm_oidc_state" in c for c in cookies)
    assert out["Location"] == "/"


def test_resp_headers_strips_hop_by_hop():
    up = _upstream_resp([
        ("Set-Cookie", "lm_session=tok"),
        ("Connection", "keep-alive"),
        ("Transfer-Encoding", "chunked"),
    ])
    out = proxy_app._resp_headers(up)
    assert "Connection" not in out
    assert "Transfer-Encoding" not in out
    assert out.getall("Set-Cookie") == ["lm_session=tok"]


def test_resp_headers_optionally_drops_content_length():
    up = _upstream_resp([("Content-Length", "123"), ("Set-Cookie", "a=b")])
    keep = proxy_app._resp_headers(up)
    assert keep["Content-Length"] == "123"
    drop = proxy_app._resp_headers(up, drop_content_length=True)
    assert "Content-Length" not in drop
    assert drop.getall("Set-Cookie") == ["a=b"]
