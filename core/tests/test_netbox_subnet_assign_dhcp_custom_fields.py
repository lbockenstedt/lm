"""Pins the reported bug: checking "Enable DHCP scope" while creating a
prefix through the "Add Prefix" finder (POST /api/netbox/subnet-assign ->
NETBOX_CLAIM_PREFIX) silently never took effect, even though the same
checkbox on the "Allocate Subnet" modal (POST /api/netbox/prefixes ->
NETBOX_ALLOCATE_PREFIX) already worked -- exactly the "works on edit, not on
initial creation" symptom, since Edit goes through NETBOX_UPDATE_PREFIX,
which also already forwarded custom_fields correctly.

Two compounding bugs, both in this route:
1. ``custom_fields`` from the request body was never included in the
   NETBOX_CLAIM_PREFIX payload sent to the spoke.
2. A successful assign never triggered the DHCP sync, so even a spoke that
   DID persist custom_fields would not push the new scope to Kea until the
   periodic sync loop or an unrelated prefix edit ran.
"""
import api as api_mod

from test_auth_session_security import _build, _mint_session


def _capture_request_response(hub, status="SUCCESS", extra=None):
    calls = []

    async def _fake(spoke_id, cmd, data, timeout=30.0):
        calls.append((cmd, data))
        body = {"status": status, "prefix": data.get("prefix", "")}
        if extra:
            body.update(extra)
        return {"payload": {"data": body}}

    hub.request_response = _fake
    return calls


def test_subnet_assign_forwards_custom_fields_to_claim_prefix(tmp_path):
    c, hub = _build({}, tmp_path)
    calls = _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    r = c.post("/api/netbox/subnet-assign",
               json={"prefix": "10.0.0.0/24", "description": "Lab A",
                     "custom_fields": {"dhcp_enabled": True, "gateway": "10.0.0.1"}},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text
    cmds = [c for c, _ in calls]
    assert "NETBOX_CLAIM_PREFIX" in cmds
    data = dict(calls)["NETBOX_CLAIM_PREFIX"]
    assert data["custom_fields"] == {"dhcp_enabled": True, "gateway": "10.0.0.1"}


def test_subnet_assign_triggers_dhcp_sync_on_success(tmp_path, monkeypatch):
    c, hub = _build({}, tmp_path)
    _capture_request_response(hub)
    tok = _mint_session(hub, "admin")

    sync_calls = []

    async def _fake_sync_dhcp_from_netbox():
        sync_calls.append(True)
        return {"status": "ok"}

    hub.sync_dhcp_from_netbox = _fake_sync_dhcp_from_netbox

    r = c.post("/api/netbox/subnet-assign",
               json={"prefix": "10.0.0.0/24",
                     "custom_fields": {"dhcp_enabled": True}},
               cookies={"lm_session": tok})

    assert r.status_code == 200, r.text

    # The trigger is fire-and-forget (asyncio.create_task) -- give the loop a
    # turn to run it before asserting.
    import asyncio
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.sleep(0))
    loop.run_until_complete(asyncio.sleep(0))

    assert sync_calls, "subnet-assign must trigger a DHCP sync on success, same as allocate/update prefix"
