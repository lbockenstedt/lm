"""A tenant subscribes to data; they do not choose where their data goes.

The sensor content is no longer shipped as source, so this subscription is the
only supported way to get threat and simulation intelligence. That makes these
routes the place where two things must hold at once: a tenant can freely turn
participation on and off, and a tenant can NOT redirect an install's sensor
reports somewhere other than the exchange.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _State:
    def __init__(self, cfg=None):
        self.system_state = {"global_config": {}}
        if cfg is not None:
            self.system_state["global_config"]["subscription"] = cfg
        self.saves = 0

    def get_global_config(self):
        return self.system_state["global_config"]

    def update_global_config(self, patch):
        self.system_state["global_config"].update(patch)

    async def save_state_now(self):
        self.saves += 1


class _Hub:
    def __init__(self, state):
        self.state = state


class _Req:
    """Minimal stand-in for the pieces of Request these handlers touch."""

    def __init__(self, payload=None):
        self._payload = payload
        import json
        self._raw = b"" if payload is None else json.dumps(payload).encode()

    async def json(self):
        return self._payload

    async def body(self):
        return self._raw


def _handlers(hub):
    from fastapi import FastAPI
    import routes.security as security

    app = FastAPI()

    class _Ctx:
        @staticmethod
        def _session_user(request):
            return {"username": "admin"}

        @staticmethod
        def _is_admin(sess):
            return True

    security.register(app, hub, _Ctx())
    found = {}
    for route in app.routes:
        path = getattr(route, "path", "")
        if path.startswith("/api/security/subscription"):
            for m in (getattr(route, "methods", None) or {"GET"}):
                if m in ("GET", "PUT", "POST"):
                    found[(path, m)] = route.endpoint
    return found


def _h(hub, path, method):
    hs = _handlers(hub)
    key = ("/api/security/subscription" + path, method)
    assert key in hs, f"{key} was not registered (have {sorted(hs)})"
    return hs[key]


def _cfg(hub):
    return hub.state.get_global_config().get("subscription") or {}


# ── the tenant-facing contract ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_fresh_install_is_not_subscribed_and_makes_no_claim_to_be():
    """Absent config must read as "off", not as an error and not as enrolled.
    An install that has never opted in has to be inert."""
    hub = _Hub(_State())
    out = await _h(hub, "", "GET")(request=_Req())

    assert out["enabled"] is False
    assert out["status"] == "not_enrolled"
    assert out["credential_set"] is False
    assert out["channels"] == []


@pytest.mark.asyncio
async def test_the_tenant_picks_databases_by_name_not_by_url():
    """The choice on offer is *which* data, never *where from*."""
    hub = _Hub(_State())
    out = await _h(hub, "", "GET")(request=_Req())

    ids = {c["id"] for c in out["available_channels"]}
    assert ids == {"threat_monitor", "client_simulations"}
    assert all(c["label"] for c in out["available_channels"])


@pytest.mark.asyncio
async def test_saving_a_subscription_enables_it_and_records_the_channels():
    hub = _Hub(_State())
    out = await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"],
         "contact_email": "ops@example.com"}))

    assert out["enabled"] is True
    assert out["channels"] == ["threat_monitor"]
    assert out["contact_email"] == "ops@example.com"
    assert hub.state.saves == 1


@pytest.mark.asyncio
async def test_an_unknown_channel_is_refused_rather_than_stored():
    """The allow-list exists so a typo or a crafted request cannot enrol this
    install in a channel nobody reviewed."""
    from api import HTTPException

    hub = _Hub(_State())
    with pytest.raises(HTTPException) as e:
        await _h(hub, "", "PUT")(request=_Req(
            {"enabled": True, "channels": ["threat_monitor", "payroll"]}))
    assert e.value.status_code == 400
    assert "payroll" in str(e.value.detail)
    assert "subscription" not in hub.state.get_global_config()


@pytest.mark.asyncio
async def test_the_service_url_is_reported_but_not_settable():
    """An operator may see where the data comes from. They may not change it:
    a settable URL would let a tenant send their sensor reports elsewhere."""
    from security import tm_client

    hub = _Hub(_State())
    out = await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"],
         "service_url": "https://attacker.example",
         "base_url": "https://attacker.example"}))

    assert out["service_url"] == tm_client.SERVICE_URL
    stored = _cfg(hub)
    assert "service_url" not in stored and "base_url" not in stored


# ── identity ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identity_is_minted_once_and_then_kept():
    """LM has no pre-existing install identity, so one is generated. It must be
    stable: a fresh uuid on every save would look like a new participant each
    time and lose whatever standing the install had built up."""
    hub = _Hub(_State())
    first = await _h(hub, "", "PUT")(request=_Req({"enabled": True}))
    second = await _h(hub, "", "PUT")(request=_Req({"enabled": False}))

    assert first["install_uuid"]
    assert second["install_uuid"] == first["install_uuid"]
    assert second["tenant_id"] == first["tenant_id"]


@pytest.mark.asyncio
async def test_an_org_can_group_its_installs_under_a_shared_tenant_id():
    """The exchange counts independent reporters. An org running several hubs
    supplies one id so its installs are not miscounted as several separate
    confirmations of the same thing."""
    hub = _Hub(_State())
    out = await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "tenant_id": "acme-shared"}))
    assert out["tenant_id"] == "acme-shared"

    # A later unrelated save must not wipe it back to a minted value.
    out2 = await _h(hub, "", "PUT")(request=_Req({"contact_email": "a@b.c"}))
    assert out2["tenant_id"] == "acme-shared"


# ── enrolment ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrolment_refuses_before_the_tenant_has_chosen_anything():
    from api import HTTPException

    hub = _Hub(_State())
    with pytest.raises(HTTPException) as e:
        await _h(hub, "/enroll", "POST")(request=_Req({}))
    assert e.value.status_code == 400

    await _h(hub, "", "PUT")(request=_Req({"enabled": True, "channels": []}))
    with pytest.raises(HTTPException) as e2:
        await _h(hub, "/enroll", "POST")(request=_Req({}))
    assert "at least one" in str(e2.value.detail)


@pytest.mark.asyncio
async def test_an_approved_enrolment_persists_the_credential(monkeypatch):
    """TMClient owns no storage. If the route does not persist what enrolment
    returns, the credential is lost and re-enrolling burns a second one for the
    same install."""
    import security.tm_client as tm_client

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        self.credential = "cred-abc123"
        return {"status": "approved", "credential": "cred-abc123"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"]}))
    out = await _h(hub, "/enroll", "POST")(request=_Req({}))

    assert out["status"] == "approved"
    assert out["credential_set"] is True
    assert _cfg(hub)["credential"] == "cred-abc123"
    assert _cfg(hub)["enrolled_at"] > 0


@pytest.mark.asyncio
async def test_the_credential_is_never_returned_to_the_browser(monkeypatch):
    """It is bearer material for the exchange. The status may say one exists;
    it may not hand it out."""
    import json

    import security.tm_client as tm_client

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        self.credential = "cred-supersecret"
        return {"status": "approved", "credential": "cred-supersecret"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"],
         "enrollment_psk": "psk-alsosecret"}))
    enrolled = await _h(hub, "/enroll", "POST")(request=_Req({}))
    got = await _h(hub, "", "GET")(request=_Req())

    for body in (enrolled, got):
        blob = json.dumps(body)
        assert "cred-supersecret" not in blob
        assert "psk-alsosecret" not in blob
    assert got["credential_set"] is True
    assert got["psk_set"] is True


@pytest.mark.asyncio
async def test_a_pending_enrolment_is_reported_as_waiting_not_as_failure(monkeypatch):
    """Without a PSK the install waits for a human. That is an expected
    outcome, and showing it as an error would push an operator into retrying
    an enrolment that is already queued."""
    import security.tm_client as tm_client

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        return {"status": "pending"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["client_simulations"]}))
    out = await _h(hub, "/enroll", "POST")(request=_Req({}))

    assert out["status"] == "pending"
    assert out["last_error"] == ""
    assert out["credential_set"] is False


@pytest.mark.asyncio
async def test_an_unreachable_service_leaves_a_reason_an_operator_can_act_on(monkeypatch):
    import security.tm_client as tm_client

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        return {"status": "error", "reason": "service unreachable"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"]}))
    out = await _h(hub, "/enroll", "POST")(request=_Req({}))

    assert out["status"] == "error"
    assert "unreachable" in out["last_error"]
    assert out["credential_set"] is False


@pytest.mark.asyncio
async def test_enrolment_does_not_ask_for_databases_the_tenant_declined(monkeypatch):
    import security.tm_client as tm_client

    seen = {}

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        seen["subs"] = list(subscriptions or ())
        seen["email"] = contact_email
        seen["url"] = self.base_url
        return {"status": "pending"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"],
         "contact_email": "ops@example.com"}))
    await _h(hub, "/enroll", "POST")(request=_Req({}))

    assert "threat_monitor" in seen["subs"]
    assert "client_simulations" not in seen["subs"]
    assert seen["email"] == "ops@example.com"
    assert seen["url"] == tm_client.SERVICE_URL.rstrip("/")


# ── withdrawal ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unsubscribing_forgets_the_credential(monkeypatch):
    """Turning participation off while keeping the credential leaves valid
    bearer material in state for an install that believes it has withdrawn."""
    import security.tm_client as tm_client

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        self.credential = "cred-abc123"
        return {"status": "approved", "credential": "cred-abc123"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"],
         "enrollment_psk": "psk-1"}))
    await _h(hub, "/enroll", "POST")(request=_Req({}))
    assert _cfg(hub)["credential"]

    out = await _h(hub, "/unsubscribe", "POST")(request=_Req())

    assert out["enabled"] is False
    assert out["credential_set"] is False
    assert out["status"] == "not_enrolled"
    assert out["channels"] == []
    assert "credential" not in _cfg(hub)
    assert "enrollment_psk" not in _cfg(hub)


@pytest.mark.asyncio
async def test_unsubscribing_keeps_the_install_identity():
    """Re-subscribing with the same install_uuid is a rejoin. A fresh one would
    present as a brand new participant."""
    hub = _Hub(_State())
    before = await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"]}))
    after = await _h(hub, "/unsubscribe", "POST")(request=_Req())

    assert after["install_uuid"] == before["install_uuid"]
    assert after["tenant_id"] == before["tenant_id"]


@pytest.mark.asyncio
async def test_a_blank_psk_submit_preserves_the_stored_one():
    """Matching the PAT field above: an empty box means "leave it alone", and
    dropping the PSK silently would turn an auto-approving install into one
    that queues for a human with no explanation."""
    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"],
         "enrollment_psk": "psk-keepme"}))
    out = await _h(hub, "", "PUT")(request=_Req({"enrollment_psk": ""}))

    assert out["psk_set"] is True
    assert _cfg(hub)["enrollment_psk"] == "psk-keepme"

    cleared = await _h(hub, "", "PUT")(request=_Req({"clear_psk": True}))
    assert cleared["psk_set"] is False


@pytest.mark.asyncio
async def test_the_threat_database_pulls_in_the_decoys_it_needs(monkeypatch):
    """Subscribing to the threat database means running the tripwire, and a
    tripwire with no decoy routes observes nothing. Making it a second checkbox
    would only give an operator a way to half-enable the feature."""
    import security.tm_client as tm_client

    seen = {}

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        seen["subs"] = list(subscriptions or ())
        return {"status": "pending"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["threat_monitor"]}))
    await _h(hub, "/enroll", "POST")(request=_Req({}))

    assert "decoys" in seen["subs"]
    # The tenant's own choice is unchanged: implied channels are an enrolment
    # detail, not something that silently appears in what they picked.
    assert _cfg(hub)["channels"] == ["threat_monitor"]


@pytest.mark.asyncio
async def test_the_simulation_database_alone_pulls_in_no_decoys(monkeypatch):
    """Implied channels follow from a specific need, not from subscribing to
    anything at all."""
    import security.tm_client as tm_client

    seen = {}

    async def fake_enroll(self, subscriptions=None, contact_email="",
                          contact_message=""):
        seen["subs"] = list(subscriptions or ())
        return {"status": "pending"}

    monkeypatch.setattr(tm_client.TMClient, "enroll", fake_enroll)

    hub = _Hub(_State())
    await _h(hub, "", "PUT")(request=_Req(
        {"enabled": True, "channels": ["client_simulations"]}))
    await _h(hub, "/enroll", "POST")(request=_Req({}))

    assert seen["subs"] == ["client_simulations"]


@pytest.mark.asyncio
async def test_decoys_is_not_something_a_tenant_can_pick_on_its_own():
    """It is not a database anyone subscribes to in its own right — it is what
    makes the threat database work."""
    from api import HTTPException

    hub = _Hub(_State())
    out = await _h(hub, "", "GET")(request=_Req())
    assert "decoys" not in {c["id"] for c in out["available_channels"]}

    with pytest.raises(HTTPException):
        await _h(hub, "", "PUT")(request=_Req(
            {"enabled": True, "channels": ["decoys"]}))
