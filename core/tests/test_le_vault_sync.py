"""Tests for the durable LE vault DNS-01 credential sync on the hub
(``LeCacheMixin._le_resolve_vault_map`` / ``_le_sync_vault_dns_creds`` in
``le_cache.py``).

The hub stores a secret-free {bucket,name} reference per cert domain in
``global_config['le_vault_dns_creds']`` at issue time, then re-resolves the
secret VALUE from the Credential Vault and pushes it to the le spoke on every
(re)connect (``LE_SYNC_VAULT_DNS``) — so certbot's DNS hook creds survive a
spoke reinstall that wiped ``/etc/lm-le/he-login.ini``.
"""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cred_vault  # noqa: E402
from le_cache import LeCacheMixin  # noqa: E402


class _Hub(LeCacheMixin):
    def __init__(self, refs):
        self.state = types.SimpleNamespace(
            system_state={"global_config": {"le_vault_dns_creds": refs}})
        self.sent = []

    async def request_response(self, spoke_id, command, data, timeout=None):
        self.sent.append({"spoke_id": spoke_id, "command": command, "data": data})
        return {"status": "SUCCESS"}


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _patch_vault(monkeypatch, mapping):
    async def _fake(hub, bucket, name):
        return mapping.get((bucket, name))
    monkeypatch.setattr(cred_vault, "automation_get", _fake)


def test_resolve_vault_map_he_login(monkeypatch):
    hub = _Hub({"lm-hub.orange-tme.com": {"bucket": "__admin__", "name": "he"}})
    _patch_vault(monkeypatch, {("__admin__", "he"): {
        "provider": "he-login", "he_username": "acct@e.com", "he_password": "pw"}})
    m = _run(hub._le_resolve_vault_map())
    assert m == {"lm-hub.orange-tme.com":
                 {"he_username": "acct@e.com", "he_password": "pw"}}


def test_resolve_skips_empty_and_unresolvable(monkeypatch):
    hub = _Hub({
        "a.example": {"bucket": "__admin__", "name": "he"},      # empty creds
        "b.example": {"bucket": "__admin__", "name": "gone"},    # unresolvable
        "c.example": "not-a-dict",                               # malformed ref
    })
    _patch_vault(monkeypatch, {("__admin__", "he"): {
        "provider": "he-login", "he_username": "", "he_password": ""}})
    m = _run(hub._le_resolve_vault_map())
    assert m == {}


def test_sync_pushes_he_creds_to_spoke(monkeypatch):
    hub = _Hub({"x.example": {"bucket": "__admin__", "name": "he"}})
    _patch_vault(monkeypatch, {("__admin__", "he"): {
        "provider": "he-login", "he_username": "u@e", "he_password": "pw"}})
    _run(hub._le_sync_vault_dns_creds("le-spoke-1"))
    assert len(hub.sent) == 1
    msg = hub.sent[0]
    assert msg["spoke_id"] == "le-spoke-1"
    assert msg["command"] == "LE_SYNC_VAULT_DNS"
    assert msg["data"] == {"he_username": "u@e", "he_password": "pw"}


def test_sync_noop_when_no_refs(monkeypatch):
    hub = _Hub({})
    _patch_vault(monkeypatch, {})
    _run(hub._le_sync_vault_dns_creds("le-spoke-1"))
    assert hub.sent == []


def test_sync_never_raises_on_vault_error(monkeypatch):
    hub = _Hub({"x.example": {"bucket": "__admin__", "name": "he"}})

    async def _boom(hub_, bucket, name):
        raise RuntimeError("vault unreachable")
    monkeypatch.setattr(cred_vault, "automation_get", _boom)
    _run(hub._le_sync_vault_dns_creds("le-spoke-1"))  # must not raise
    assert hub.sent == []
