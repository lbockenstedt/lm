"""Hub routes for the per-client override Control Panel
(``/sim/api/{tenant}/clients/{hostname}/control`` + ``/clients/control-all``).

Model A: a per-client toggle is stored as a per-USER override in
``user-overrides.conf`` under a ``[username]`` section (hostname minus the
trailing ``-N``) — the same file the Config Editor shows and that is synced to
GitHub when a token is configured. The write is a read-modify-write of the
whole file, so other users' sections and this user's non-sim keys survive; the
edited text is then pushed to the spokes.

The legacy per-client registry RPC (``CS_SET_CLIENT_OVERRIDES``) is gone: every
write instead forwards ``CS_CLEAR_CLIENT_OVERRIDES`` so that old hidden layer
can never double-apply on top of the conf value. The GET route seeds from the
same conf (live from the spoke, falling back to the hub-owned copy when the
spoke is down) and degrades to empty overrides so the UI still renders.

``control-all`` is unchanged — it still forwards ``CS_SET_ALL_CLIENT_OVERRIDES``.
"""

import configparser

from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations.routes import register_simulations_routes


class _FakeSimStore:
    """The config-ownership gate the sim routes now consult before any write.

    register_simulations_routes' _require_config_writable asks the store who
    owns the tenant's simulation config: writes are allowed when the source is
    'hub', or 'github' with a token configured. These tests exercise a
    hub-owned tenant, which is the writable case. Previously this was an empty
    class, so every write 500'd on AttributeError.
    """

    def __init__(self, source="hub", github=None):
        self.source = source
        self.github = github or {}
        self.user_overrides = {}

    async def get_source_of_truth(self, tenant_id):
        return self.source

    async def get_github_config(self, tenant_id):
        return dict(self.github)

    # user-overrides.conf is a real read-modify-write in the routes (edit the
    # INI, persist, then push), so keep it a genuine in-memory round-trip
    # rather than a no-op -- otherwise the edit logic isn't actually covered.
    async def set_user_overrides_content(self, tenant_id, content):
        self.user_overrides[tenant_id] = content

    async def get_user_overrides_content(self, tenant_id):
        return self.user_overrides.get(tenant_id, "")


class FakeHub:
    """Minimal hub: records forwarded CS_* commands + returns canned replies."""

    def __init__(self, replies=None, connected=True):
        self.replies = replies or {}
        self.forwarded = []
        self._connected = connected
        self.simulations_cache = {}
        self.active_connections = {"cs-spoke-1"} if connected else set()
        self.simulations_store = _FakeSimStore()
        self.state = type("State", (),
                          {"get_spoke_tenant": lambda sid: "10"})()

    def get_client_sim_spoke(self, tenant_id):
        return "cs-spoke-1" if self._connected else None

    async def request_response(self, sid, cmd_type, payload, timeout=8.0):
        self.forwarded.append((cmd_type, payload))
        return {"payload": {"data": self.replies.get(cmd_type, {"status": "SUCCESS"})}}


def _build(replies=None, connected=True):
    app = FastAPI()
    hub = FakeHub(replies=replies, connected=connected)
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return TestClient(app), hub


def _overrides_written(hub, tenant_id="10"):
    """Parse the user-overrides.conf text the routes persisted to the store."""
    p = configparser.ConfigParser()
    p.optionxform = str
    p.read_string(hub.simulations_store.user_overrides.get(tenant_id, ""))
    return p


def _pushed_override_text(hub):
    """The user-overrides.conf text fanned out to the spokes via CS_PUSH_CONFIG."""
    for cmd, payload in reversed(hub.forwarded):
        if "user_conf_override" in (payload or {}):
            return payload["user_conf_override"]
    return None


def test_set_client_control_writes_a_per_user_override():
    """Model A: a per-client toggle is a per-USER override in
    user-overrides.conf (visible in the Config Editor, synced to GitHub when a
    token is configured) — NOT the legacy per-client registry RPC."""
    c, hub = _build()
    r = c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
               json={"overrides": {"dns_fail": "on", "kill_switch": "off"}})
    assert r.status_code == 200
    body = r.json()
    assert body["saved"] is True
    assert body["username"] == "host"          # hostname minus the trailing -N
    assert body["source"] == "hub"

    cfg = _overrides_written(hub)
    assert cfg.get("host", "dns_fail") == "on"
    assert cfg.get("host", "kill_switch") == "off"


def test_set_client_control_pushes_the_new_conf_to_spokes():
    c, hub = _build()
    c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    text = _pushed_override_text(hub)
    assert text is not None, "the edited user-overrides.conf must be pushed to spokes"
    assert "[host]" in text and "dns_fail" in text


def test_set_client_control_retires_the_legacy_per_client_override():
    """The old hidden per-client registry layer is cleared on every write so it
    can never double-apply on top of the user-overrides.conf value."""
    c, hub = _build()
    c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_CLEAR_CLIENT_OVERRIDES"
    assert payload["hostname"] == "host-a"
    # ...and the legacy SET RPC is gone entirely.
    assert "CS_SET_CLIENT_OVERRIDES" not in [c for c, _ in hub.forwarded]


def test_set_client_control_accepts_inline_flags():
    """Parity with the spoke's HTTP client_api: flags may be sent inline."""
    c, hub = _build()
    r = c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
               json={"dhcp_fail": "on"})
    assert r.status_code == 200
    assert _overrides_written(hub).get("host", "dhcp_fail") == "on"


def test_set_client_control_preserves_other_users_and_non_sim_keys():
    """The write is a read-modify-write of the whole file: another user's
    section, and this user's non-sim keys, must survive."""
    c, hub = _build()
    hub.simulations_store.user_overrides["10"] = (
        "[other]\ndns_fail = on\n\n[host]\nssid = corp-wifi\n"
    )
    c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    cfg = _overrides_written(hub)
    assert cfg.get("other", "dns_fail") == "on"
    assert cfg.get("host", "ssid") == "corp-wifi"
    assert cfg.get("host", "dns_fail") == "on"


def test_get_client_control_reads_from_user_overrides():
    """The control panel seeds from user-overrides.conf — the same place the
    toggles write — not from the legacy per-client registry."""
    c, hub = _build({"CS_GET_CONFIG":
                     {"status": "SUCCESS",
                      "user_overrides": "[host]\niperf = on\nssid = corp\n"}})
    r = c.get("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "host"
    # Only recognised sim flags are surfaced; ssid is not one.
    assert body["overrides"] == {"iperf": "on"}


def test_get_client_control_falls_back_to_hub_copy_when_spoke_offline():
    """An edit must never start from a blank file just because the spoke is
    down, so the hub-owned override content is the fallback."""
    c, hub = _build(connected=False)
    hub.simulations_store.user_overrides["10"] = "[host]\ndns_fail = on\n"
    r = c.get("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    assert r.json()["overrides"] == {"dns_fail": "on"}


def test_get_client_control_offline_returns_empty_overrides():
    c, hub = _build(connected=False)
    r = c.get("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    assert r.json()["overrides"] == {}
    assert hub.forwarded == []  # nothing forwarded when spoke is down


def test_clear_client_control_removes_only_the_sim_flags():
    c, hub = _build()
    hub.simulations_store.user_overrides["10"] = (
        "[host]\ndns_fail = on\nssid = corp-wifi\n"
    )
    r = c.delete("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    assert r.json()["saved"] is True
    cfg = _overrides_written(hub)
    assert not cfg.has_option("host", "dns_fail")   # sim flag cleared
    assert cfg.get("host", "ssid") == "corp-wifi"   # non-sim key preserved


def test_control_all_forwards_to_set_all():
    c, hub = _build({"CS_SET_ALL_CLIENT_OVERRIDES":
                     {"status": "SUCCESS", "applied": 3,
                      "overrides": {"dhcp_fail": "on"}}})
    r = c.post("/sim/api/10/clients/control-all?tenant_id=10",
               json={"overrides": {"dhcp_fail": "on"}})
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_SET_ALL_CLIENT_OVERRIDES"
    assert payload["overrides"] == {"dhcp_fail": "on"}
    assert r.json()["applied"] == 3


def test_control_all_does_not_collide_with_hostname_route():
    """``control-all`` is one segment; ``{hostname}/control`` is two — registered
    in that order so Starlette never captures 'control-all' as a hostname."""
    c, hub = _build()
    c.post("/sim/api/10/clients/control-all?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    assert hub.forwarded[-1][0] == "CS_SET_ALL_CLIENT_OVERRIDES"
    c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    # The per-hostname route goes through the user-overrides.conf write, whose
    # last spoke call is the legacy-layer clear — never the control-all RPC.
    assert hub.forwarded[-1][0] == "CS_CLEAR_CLIENT_OVERRIDES"