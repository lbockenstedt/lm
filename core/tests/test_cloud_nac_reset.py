"""cloud_nac.provision_user: rotate path patches the known oid and rides out
Graph replication lag (a just-created user can 404 for a few seconds)."""
import asyncio

import cloud_nac


class _Resp:
    def __init__(self, code, body=None):
        self.status_code, self._body, self.text = code, body or {}, ""

    def json(self):
        return self._body


def _patch(monkeypatch, codes):
    calls = []

    async def graph(method, path, token, json=None, params=None, http=None):
        calls.append((method, path))
        return _Resp(codes.pop(0))

    async def token(*a, **k):
        return "tok"

    async def no_sleep(_s):
        return None

    monkeypatch.setattr(cloud_nac, "_graph", graph)
    monkeypatch.setattr(cloud_nac, "fetch_app_token", token)
    monkeypatch.setattr(cloud_nac.asyncio, "sleep", no_sleep)
    return calls


def test_known_oid_skips_upn_lookup_and_retries_404(monkeypatch):
    calls = _patch(monkeypatch, [404, 404, 204])
    res = asyncio.run(cloud_nac.provision_user(None, "x.com", "bob", password="pw", oid="oid-1"))
    assert res["oid"] == "oid-1" and res["created"] is False
    assert calls == [("PATCH", "/users/oid-1")] * 3


def test_reset_gives_up_after_retries(monkeypatch):
    _patch(monkeypatch, [404] * 5)
    try:
        asyncio.run(cloud_nac.provision_user(None, "x.com", "bob", password="pw", oid="oid-1"))
    except cloud_nac.CloudNacError as e:
        assert "HTTP 404" in str(e)
    else:
        raise AssertionError("expected CloudNacError")
