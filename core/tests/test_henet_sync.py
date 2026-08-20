"""Tests for the scheduled HE.NET re-sync mixin (``henet_sync.HenetSyncMixin``).

Contract under test:
* managed records are grouped by ``tenant_id`` and each group is written with
  THAT scope's account login (its own assigned credential, else the global one);
* only A/AAAA records are re-applied (matching the manual "Sync all");
* accepted records are relayed to the spoke as ``HENET_WEB_RECORD`` (local-state
  refresh, no dyndns push);
* a scope with no assignable credential is skipped, not errored;
* the loop skips quietly when the henet spoke is offline.
"""
import asyncio

import pytest

import cred_vault
import henet_scrape
import henet_sync


# ── fakes ────────────────────────────────────────────────────────────────────
class _State:
    def __init__(self, gc):
        self.system_state = {"global_config": gc}


class _FakeHub(henet_sync.HenetSyncMixin):
    def __init__(self, gc, records, spoke="henet-sid"):
        self.state = _State(gc)
        self._spoke = spoke
        self._records = records
        self.relayed = []  # (cmd, payload)

    def get_spoke_by_type(self, mtype):
        return self._spoke if mtype == "henet" else None

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.relayed.append((cmd, payload))
        if cmd == "HENET_LIST":
            return {"payload": {"data": {"records": self._records}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


@pytest.fixture
def patch_write(monkeypatch):
    """Capture set_records calls and script their result. Records the
    (username, password, records) each web write was invoked with."""
    calls = []

    def _install(result_by_login=None):
        def _fake_set_records(self, username, password, records):
            calls.append({"username": username, "password": password,
                          "records": [dict(r) for r in records]})
            # Default: HE accepts every record.
            results = [{"name": r["name"], "type": r["type"], "ok": True, "detail": "ok"}
                       for r in records]
            if result_by_login and username in result_by_login:
                results = result_by_login[username](records)
            return {"status": "SUCCESS", "results": results, "applied": len(results)}
        monkeypatch.setattr(henet_scrape.HENetScraper, "set_records",
                            _fake_set_records, raising=True)
        return calls
    return _install


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── tests ────────────────────────────────────────────────────────────────────
def test_skips_when_spoke_offline(patch_write):
    calls = patch_write()
    hub = _FakeHub({}, [], spoke=None)
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "skipped"
    assert calls == []


def test_groups_by_tenant_and_uses_scope_login(patch_write, monkeypatch):
    # Global cred + a per-tenant cred for "lrb".
    gc = {"henet": {
        "vault_credential": {"bucket": "__admin__", "name": "he-global"},
        "tenant_credentials": {"lrb": {"bucket": "lrb", "name": "he-lrb"}},
    }}
    records = [
        {"name": "a.example.com", "type": "A", "value": "1.1.1.1", "ttl": 300, "tenant_id": ""},
        {"name": "b.lrb.com", "type": "A", "value": "2.2.2.2", "ttl": 300, "tenant_id": "lrb"},
        {"name": "c.example.com", "type": "TXT", "value": "x", "ttl": 300, "tenant_id": ""},
    ]
    calls = patch_write()

    async def _fake_get(hub, bucket, name):
        return {"he_username": f"{bucket}-user", "he_password": f"{bucket}-pass"}
    monkeypatch.setattr(cred_vault, "automation_get", _fake_get)

    hub = _FakeHub(gc, records)
    res = _run(hub.sync_henet_scheduled())

    assert res["status"] == "ok"
    assert res["scopes"] == 2          # global + lrb
    assert res["applied"] == 2         # 2 A records (TXT excluded)
    # Each scope wrote with ITS OWN account login.
    logins = {c["username"] for c in calls}
    assert logins == {"__admin__-user", "lrb-user"}
    # Accepted records were relayed to the spoke.
    web = [p for (cmd, p) in hub.relayed if cmd == "HENET_WEB_RECORD"]
    assert web and all(r["ok"] for pw in web for r in pw["records"])


def test_scope_without_credential_is_skipped(patch_write, monkeypatch):
    gc = {"henet": {}}  # no global, no tenant cred
    records = [{"name": "a.example.com", "type": "A", "value": "1.1.1.1",
                "ttl": 300, "tenant_id": ""}]
    calls = patch_write()

    async def _fake_get(hub, bucket, name):
        raise AssertionError("automation_get must not be called with no cred ref")
    monkeypatch.setattr(cred_vault, "automation_get", _fake_get)

    hub = _FakeHub(gc, records)
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "ok"
    assert res["applied"] == 0
    assert res["skipped"] == 1
    assert calls == []


def test_no_managed_records(patch_write):
    patch_write()
    hub = _FakeHub({"henet": {"vault_credential": {"bucket": "b", "name": "n"}}}, [])
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "ok"
    assert res["applied"] == 0
    assert res.get("scopes") == 0


def test_cfg_defaults_and_clamp():
    hub = _FakeHub({"henet_sync": {"enabled": True, "interval_seconds": 10}}, [])
    cfg = hub._henet_sync_cfg()
    assert cfg["enabled"] is True
    assert cfg["interval_seconds"] == henet_sync._MIN_INTERVAL  # clamped up from 10
    # Unset → opt-in default (disabled).
    assert _FakeHub({}, [])._henet_sync_cfg()["enabled"] is False
