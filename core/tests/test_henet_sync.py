"""Tests for the scheduled HE.NET re-sync mixin (``henet_sync.HenetSyncMixin``).

Contract under test:
* managed records are grouped by ``tenant_id`` and each group is written with
  THAT scope's account login (its own assigned credential, else the global one);
* only A/AAAA records are re-applied (matching the manual "Sync all");
* accepted records are relayed to the spoke as ``HENET_WEB_RECORD`` (local-state
  refresh, no dyndns push);
* a scope with no assignable credential is skipped, not errored;
* a tenant that several credential slots name is an error, not a skip, and
  nothing is written for it;
* a write that could not log in to or reach HE.NET is an error for every
  record of its scope, as is a record list the spoke did not return;
* a run with errors records a ``reason`` built from counts and failure kinds
  only, never a tenant, record, vault path, HE username or error text;
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


async def _login_get(hub, bucket, name):
    """Fake vault read: an account login named after the bucket."""
    return {"he_username": f"{bucket}-user", "he_password": f"{bucket}-pass"}


def _a_records(n, tenant=""):
    """``n`` managed A records for ``tenant``."""
    return [{"name": f"r{i}.example.com", "type": "A", "value": f"10.0.0.{i}",
             "ttl": 300, "tenant_id": tenant} for i in range(n)]


_GLOBAL_ONLY = {"henet": {"vault_credential": {"bucket": "__admin__", "name": "he-global"}}}


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
    assert "reason" not in res         # nothing to explain
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


@pytest.mark.parametrize("spellings", [["beta"], ["BETA"], ["BETA", "beta"], ["beta", "BETA"]])
def test_scope_with_several_slots_is_an_error(patch_write, monkeypatch, spellings):
    # "Beta" and "BETA" slots (saved before slots matched in any case) both
    # name tenant "beta": its records are written with neither, nor with the
    # global login, and the run reports an error rather than "ok". The same
    # when the records are tagged with the exact "BETA", and in either order
    # (the first record's spelling names the scope).
    gc = {"henet": {
        "vault_credential": {"bucket": "__admin__", "name": "he-global"},
        "tenant_credentials": {"Beta": {"bucket": "b", "name": "old"},
                               "BETA": {"bucket": "b", "name": "new"}},
    }}
    records = [{"name": f"b{i}.beta.com", "type": "A", "value": "2.2.2.2",
                "ttl": 300, "tenant_id": t} for i, t in enumerate(spellings)]
    calls = patch_write()
    # Recorded, not raised: the vault branch counts any exception as an error.
    reads = []

    async def _fake_get(hub, bucket, name):
        reads.append((bucket, name))
        return {"he_username": f"{bucket}-user", "he_password": f"{bucket}-pass"}
    monkeypatch.setattr(cred_vault, "automation_get", _fake_get)

    hub = _FakeHub(gc, records)
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "error"
    assert (res["applied"], res["errors"], res["skipped"]) == (0, len(spellings), 0)
    assert reads == [] and calls == []
    assert not [p for (cmd, p) in hub.relayed if cmd == "HENET_WEB_RECORD"]


@pytest.mark.parametrize("outcome", ["error_reply", "raises"])
def test_login_or_connection_failure_is_an_error(monkeypatch, outcome):
    # set_records answers ERROR with no per-record results when the login
    # fails, dns.he.net can't be reached or the account has no zones. That
    # counted 0 applied and 0 errors, so the run said "ok". A raise is the same.
    def _fake_set_records(self, username, password, records):
        if outcome == "raises":
            raise OSError("connection reset while logging in as __admin__-user")
        return {"status": "ERROR", "message": "HE.NET login failed for __admin__-user"}
    monkeypatch.setattr(henet_scrape.HENetScraper, "set_records", _fake_set_records)
    monkeypatch.setattr(cred_vault, "automation_get", _login_get)

    hub = _FakeHub(_GLOBAL_ONLY, _a_records(3))
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "error"
    assert (res["applied"], res["errors"], res["skipped"]) == (0, 3, 0)
    assert res["reason"] == "1 of 1 scope failed (1 HE.NET login or connection failure)"
    assert "__admin__" not in repr(res)
    assert not [p for (cmd, p) in hub.relayed if cmd == "HENET_WEB_RECORD"]


def test_reason_names_no_tenant_record_or_error_text(patch_write, monkeypatch):
    # GET /api/henet/sync-config returns the status to every user with HE.NET
    # or DNS access, tenant users included: the reason gives counts and kinds
    # only. Here the global scope writes, "beta" has two credential slots and
    # gamma's vault read fails.
    gc = {"henet": {
        "vault_credential": {"bucket": "__admin__", "name": "he-global"},
        "tenant_credentials": {"Beta": {"bucket": "beta-bkt", "name": "old"},
                               "BETA": {"bucket": "beta-bkt", "name": "new"},
                               "gamma": {"bucket": "gamma-bkt", "name": "he-gamma"}},
    }}
    records = _a_records(1) + _a_records(2, "beta") + _a_records(1, "gamma")
    calls = patch_write()

    async def _fake_get(hub, bucket, name):
        if bucket == "gamma-bkt":
            raise RuntimeError("vault gamma-bkt/he-gamma: permission denied")
        return await _login_get(hub, bucket, name)
    monkeypatch.setattr(cred_vault, "automation_get", _fake_get)

    hub = _FakeHub(gc, records)
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "error"
    assert (res["applied"], res["errors"], res["skipped"]) == (1, 3, 0)
    assert res["reason"] == "2 of 3 scopes failed (1 credential conflict, 1 vault read failure)"
    assert [c["username"] for c in calls] == ["__admin__-user"]
    shown = repr(res).lower()
    for leak in ("beta", "gamma", "example.com", "permission denied", "__admin__", "-user"):
        assert leak not in shown


@pytest.mark.parametrize("accepted", [1, 0])
def test_rejected_records_are_counted_in_the_reason(monkeypatch, accepted):
    # HE.NET refused records one by one: PARTIAL when some applied, ERROR with
    # per-record results when none did. Either way the scope did write, so the
    # reason counts records, not a failed scope.
    def _fake_set_records(self, username, password, records):
        results = [{"name": r["name"], "type": r["type"], "ok": i < accepted,
                    "detail": f"HE.NET did not accept {r['name']}"}
                   for i, r in enumerate(records)]
        return {"status": "PARTIAL" if accepted else "ERROR", "results": results}
    monkeypatch.setattr(henet_scrape.HENetScraper, "set_records", _fake_set_records)
    monkeypatch.setattr(cred_vault, "automation_get", _login_get)

    hub = _FakeHub(_GLOBAL_ONLY, _a_records(3))
    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "error"
    assert (res["applied"], res["errors"]) == (accepted, 3 - accepted)
    assert res["reason"] == f"{3 - accepted} records rejected by HE.NET"


@pytest.mark.parametrize("reply", [
    ConnectionError("spoke henet-sid at 10.1.2.3 closed the connection"),
    {"status": "ERROR", "message": "Timed out waiting for spoke response"},
], ids=["raises", "error_reply"])
def test_record_list_failure_is_a_neutral_error(patch_write, reply):
    # The hub answers a HENET_LIST timeout with an ERROR reply, which read as
    # "no managed records" and an "ok" run. A raise recorded its text as
    # "error". Both are now an error with a fixed reason.
    calls = patch_write()
    hub = _FakeHub(_GLOBAL_ONLY, _a_records(2))

    async def _list(sid, cmd, payload=None, timeout=None):
        if isinstance(reply, Exception):
            raise reply
        return reply
    hub.request_response = _list

    res = _run(hub.sync_henet_scheduled())
    assert res["status"] == "error"
    assert res["reason"] == "the HE.NET spoke did not return its record list"
    assert "error" not in res and "10.1.2.3" not in repr(res)
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
