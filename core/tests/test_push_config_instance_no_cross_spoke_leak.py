"""Regression: push_config_to_spoke's NAC/IPAM/Directory instance resolution
must NEVER push a DIFFERENT spoke's instance config onto this spoke.

Two ClearPass appliances, each bound to its own spoke (e.g. two separate
tenants, each with their own dedicated CPPM — no sharing involved) used to
fall back to "the first instance in the list" whenever the direct spoke_id
match missed for any reason. That silently pushed tenant A's ClearPass
host/credentials onto tenant B's spoke, which then failed every query with
"no route to host" against an IP that was never meant for it — an
intermittent, self-resolving-looking bug that was actually a real
misconfiguration each time it happened.
"""
import asyncio

import pytest

from main import LabManagerHub
from messaging.protocol import Message, MessageHeader, MessagePayload


class _FakeHub:
    """Minimal hub stand-in for push_config_to_spoke, extending the pattern
    in test_hub_url_push.py with spoke_module_types + _primary_key so the
    NAC/_INSTANCE_CONFIG_SOURCES branch is actually reached.

    ``alias`` mirrors hub_identity.py's spoke_id_alias: maps a legacy
    operator-chosen spoke_id to its guid-primary identity once the
    guid-primary migration has armed for that spoke. Empty by default
    (pre-migration — _primary_key is a pass-through, matching production
    before any spoke migrates)."""

    def __init__(self, gc, module_type="nac", alias=None):
        self.key_manager = type("KM", (), {"hub_secrets": ["hubsecret"]})()
        self._gc = gc
        self.spoke_module_types = {}
        self._module_type = module_type
        self.sent = []
        self._nac_unconfigured_spokes = set()
        self._alias = alias or {}
        # The NAC push: per-spoke locks, the connect-time push tasks, and
        # the spoke's answer to UPDATE_CONFIG (CPPMSpoke answers SUCCESS).
        self.active_connections = {}
        self._nac_push_locks = {}
        self._nac_push_tasks = set()
        self.reply = {"status": "SUCCESS"}
        # The whole answer instead, when set: the hub's own timeout answer
        # has no payload envelope.
        self.frame = None
        # The nw/opn/... pushes now run each record through
        # instance_vault.overlay_many, which resolves a record's optional
        # ``vault_credential`` reference via cred_vault -> and that reads
        # ``state.system_state["global_config"]["cred_vault"]``. None of these
        # records carry a reference, so an empty system_state is enough to let
        # the overlay no-op instead of raising into push_config_to_spoke's
        # broad except (which swallowed it and pushed nothing at all).
        self.state = type("S", (), {
            "get_global_config": lambda self, _g=gc: _g,
            "system_state": {},
            "_mark_dirty": lambda self: None,
        })()

    def _primary_key(self, spoke_id):
        return self._alias.get(spoke_id, spoke_id)

    opn_config_for_spoke = LabManagerHub.opn_config_for_spoke
    push_nac_config = LabManagerHub.push_nac_config
    _push_nac_config_on_connect = LabManagerHub._push_nac_config_on_connect

    async def send_to_spoke(self, msg):
        self.sent.append(msg)

    async def request_response(self, spoke_id, cmd, payload, timeout=None):
        """Record the command like send_to_spoke, and answer with ``frame``,
        else ``reply`` in a COMMAND_RESULT envelope."""
        self.sent.append(Message(header=MessageHeader(sender_id="hub", destination_id=spoke_id),
                                 payload=MessagePayload(type=cmd, data=payload)))
        return self.frame or {"payload": {"type": "COMMAND_RESULT", "data": self.reply}}

    async def send_setup_to_spoke(self, msg):
        self.sent.append(msg)


def _make_hub(nac_instances, spoke_id, module_type="nac", alias=None):
    hub = _FakeHub({"nac_instances": nac_instances}, module_type, alias=alias)
    hub.spoke_module_types[spoke_id] = module_type
    return hub


def _config_pushed(hub):
    updates = [m for m in hub.sent if m.payload.type == "UPDATE_CONFIG"]
    return updates[-1].payload.data if updates else None


async def _push(hub, spoke_id):
    """push_config_to_spoke, then wait for the NAC push task it starts."""
    await LabManagerHub.push_config_to_spoke(hub, spoke_id)
    await asyncio.gather(*list(hub._nac_push_tasks))


@pytest.mark.asyncio
async def test_spoke_gets_its_own_bound_instance():
    hub = _make_hub([
        {"spoke_id": "cppm-a", "host": "172.16.1.16", "tenant_id": "tenantA"},
        {"spoke_id": "cppm-b", "host": "172.16.1.20", "tenant_id": "tenantB"},
    ], "cppm-a")
    await _push(hub, "cppm-a")
    assert _config_pushed(hub)["host"] == "172.16.1.16"


@pytest.mark.asyncio
async def test_other_spoke_gets_its_own_bound_instance_not_the_first_one():
    hub = _make_hub([
        {"spoke_id": "cppm-a", "host": "172.16.1.16", "tenant_id": "tenantA"},
        {"spoke_id": "cppm-b", "host": "172.16.1.20", "tenant_id": "tenantB"},
    ], "cppm-b")
    await _push(hub, "cppm-b")
    assert _config_pushed(hub)["host"] == "172.16.1.20"


@pytest.mark.asyncio
async def test_unbound_spoke_never_receives_another_spokes_instance():
    """The core regression: a spoke with NO matching (and no unbound) instance
    in the list must get pushed NOTHING for this module — never instances[0]
    (tenant A's host landing on a spoke that has no business with it)."""
    hub = _make_hub([
        {"spoke_id": "cppm-a", "host": "172.16.1.16", "tenant_id": "tenantA"},
        {"spoke_id": "cppm-b", "host": "172.16.1.20", "tenant_id": "tenantB"},
    ], "cppm-c")  # a third, unrelated nac spoke
    await _push(hub, "cppm-c")
    updates = [m for m in hub.sent if m.payload.type == "UPDATE_CONFIG"]
    assert updates == [], "must push nothing rather than another spoke's host/credentials"
    assert "cppm-c" in hub._nac_unconfigured_spokes


@pytest.mark.asyncio
async def test_unbound_instance_still_fills_single_product_deployment():
    """A single-product deployment (one instance, no spoke_id bound at all)
    still works — the unbound-instance fallback is preserved."""
    hub = _make_hub([{"host": "172.16.1.16"}], "cppm-a")
    await _push(hub, "cppm-a")
    assert _config_pushed(hub)["host"] == "172.16.1.16"


@pytest.mark.asyncio
async def test_empty_instances_list_falls_back_to_legacy_single_config():
    """Pre-multi-instance deployment (empty nac_instances) still pushes the
    legacy global_config['cppm'] single-config key."""
    hub = _FakeHub({"nac_instances": [], "cppm": {"host": "172.16.1.99"}})
    hub.spoke_module_types["cppm-legacy"] = "nac"
    await _push(hub, "cppm-legacy")
    assert _config_pushed(hub)["host"] == "172.16.1.99"


# ── guid-primary identity migration: matching must survive either generation ─
# hub_identity.py is mid-rollout on migrating spokes from name-primary to
# guid-primary (spoke_id_alias maps the legacy name -> guid once armed for a
# given spoke). An instance's spoke_id may have been saved under EITHER
# generation depending on when an admin bound it. Live incident this
# reproduces: both LRB's and RA's CPPM went "host not configured"
# simultaneously once their identity migration armed — raw string equality
# stopped matching in both directions at once.

@pytest.mark.asyncio
async def test_instance_saved_under_legacy_name_matches_spoke_connecting_as_guid():
    """The instance was bound back when this spoke connected under its legacy
    name; the migration has SINCE armed, so it now connects as its guid."""
    hub = _make_hub([
        {"spoke_id": "cppm-a", "host": "172.16.1.16", "tenant_id": "tenantA"},
    ], "guid-111", alias={"cppm-a": "guid-111"})
    await _push(hub, "guid-111")
    assert _config_pushed(hub)["host"] == "172.16.1.16"


@pytest.mark.asyncio
async def test_instance_saved_under_guid_matches_spoke_still_connecting_by_name():
    """The admin re-bound the instance AFTER migration (saved the guid), but
    this particular process/connection is still presenting the legacy name
    (e.g. mid-rollout) — _primary_key resolves it to the same guid either
    way."""
    hub = _make_hub([
        {"spoke_id": "guid-111", "host": "172.16.1.16", "tenant_id": "tenantA"},
    ], "cppm-a", alias={"cppm-a": "guid-111"})
    await _push(hub, "cppm-a")
    assert _config_pushed(hub)["host"] == "172.16.1.16"


@pytest.mark.asyncio
async def test_two_tenants_both_migrated_still_route_correctly():
    """The exact live incident: two tenants' CPPM spokes both arm guid-primary
    at once — neither must go 'not configured', and neither must get the
    OTHER's host."""
    hub_a = _make_hub([
        {"spoke_id": "lrb-agent-cppm", "host": "172.16.1.16", "tenant_id": "LRB"},
        {"spoke_id": "ra-agent-cppm", "host": "172.16.1.94", "tenant_id": "RA"},
    ], "guid-lrb", alias={"lrb-agent-cppm": "guid-lrb", "ra-agent-cppm": "guid-ra"})
    await _push(hub_a, "guid-lrb")
    assert _config_pushed(hub_a)["host"] == "172.16.1.16"

    hub_b = _make_hub([
        {"spoke_id": "lrb-agent-cppm", "host": "172.16.1.16", "tenant_id": "LRB"},
        {"spoke_id": "ra-agent-cppm", "host": "172.16.1.94", "tenant_id": "RA"},
    ], "guid-ra", alias={"lrb-agent-cppm": "guid-lrb", "ra-agent-cppm": "guid-ra"})
    await _push(hub_b, "guid-ra")
    assert _config_pushed(hub_b)["host"] == "172.16.1.94"


@pytest.mark.asyncio
async def test_migrated_spoke_still_never_receives_a_different_spokes_instance():
    """The no-cross-leak guarantee must hold across identity generations too:
    an unrelated spoke's guid must not resolve to someone else's instance."""
    hub = _make_hub([
        {"spoke_id": "lrb-agent-cppm", "host": "172.16.1.16", "tenant_id": "LRB"},
    ], "guid-unrelated", alias={"lrb-agent-cppm": "guid-lrb"})
    await _push(hub, "guid-unrelated")
    updates = [m for m in hub.sent if m.payload.type == "UPDATE_CONFIG"]
    assert updates == []


# ── nw (Network Devices) matching: same fix, same live symptom ──────────────

@pytest.mark.asyncio
async def test_nw_device_matches_across_identity_generations():
    hub = _FakeHub({"nw_devices": [
        {"spoke_id": "nw-agent", "name": "core-switch"},
    ]}, module_type="nw", alias={"nw-agent": "guid-nw"})
    hub.spoke_module_types["guid-nw"] = "nw"
    await LabManagerHub.push_config_to_spoke(hub, "guid-nw")
    data = _config_pushed(hub)
    assert [d["name"] for d in data["devices"]] == ["core-switch"]


@pytest.mark.asyncio
async def test_nw_unrelated_spoke_gets_no_devices_not_someone_elses():
    hub = _FakeHub({"nw_devices": [
        {"spoke_id": "nw-agent", "name": "core-switch"},
    ]}, module_type="nw", alias={"nw-agent": "guid-nw"})
    hub.spoke_module_types["guid-other"] = "nw"
    await LabManagerHub.push_config_to_spoke(hub, "guid-other")
    data = _config_pushed(hub)
    assert data["devices"] == []


# ── opn (firewalls): bound firewall must match across identity generations ──

@pytest.mark.asyncio
async def test_opn_firewall_matches_across_identity_generations():
    """A firewall bound under the legacy spoke name must still be pushed to
    the spoke connecting as its guid — not fall back to firewalls[0]."""
    hub = _FakeHub({"firewalls": [
        {"spoke_id": "other-fw", "model": "opnsense", "host": "10.0.0.1"},
        {"spoke_id": "lm-agent-opnsense", "model": "opnsense", "host": "10.0.0.2"},
    ]}, module_type="firewall", alias={"lm-agent-opnsense": "guid-fw"})
    hub.spoke_module_types["guid-fw"] = "firewall"
    await LabManagerHub.push_config_to_spoke(hub, "guid-fw")
    assert _config_pushed(hub)["host"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_opn_pushes_every_firewall_bound_to_the_spoke():
    """Both boxes of an HA pair on one spoke: the first stays the default, and
    the list carries both (connection fields only) so firewall_id can route."""
    hub = _FakeHub({"firewalls": [
        {"id": "fw-a", "name": "A", "spoke_id": "opn", "model": "opnsense", "host": "10.0.0.5",
         "port": 443, "api_key": "k1", "api_secret": "s1", "tenant_id": "t1"},
        {"id": "fw-x", "spoke_id": "other", "model": "opnsense", "host": "10.9.9.9"},
        {"id": "fw-b", "name": "B", "spoke_id": "opn", "model": "opnsense", "host": "10.0.0.6",
         "port": 443, "api_key": "k2", "api_secret": "s2"},
    ]}, module_type="firewall")
    hub.spoke_module_types["opn"] = "firewall"
    await LabManagerHub.push_config_to_spoke(hub, "opn")
    data = _config_pushed(hub)
    assert data["id"] == "fw-a" and data["host"] == "10.0.0.5"
    assert [f["id"] for f in data["firewalls"]] == ["fw-a", "fw-b"]
    assert data["firewalls"][1] == {"id": "fw-b", "name": "B", "host": "10.0.0.6", "port": 443,
                                    "api_key": "k2", "api_secret": "s2"}


@pytest.mark.asyncio
async def test_unbound_opn_spoke_never_gets_another_spokes_firewall():
    """A spoke with nothing bound is told to clear (empty list); it never gets
    a firewall bound to another spoke, or an unbound one."""
    hub = _FakeHub({"firewalls": [
        {"id": "fw-x", "spoke_id": "other", "model": "opnsense", "host": "10.9.9.9",
         "api_key": "k", "api_secret": "s"},
        {"id": "fw-t2", "model": "opnsense", "host": "10.8.8.8", "tenant_id": "t2",
         "api_key": "k", "api_secret": "s"},
    ]}, module_type="firewall")
    hub.spoke_module_types["opn"] = "firewall"
    await LabManagerHub.push_config_to_spoke(hub, "opn")
    assert _config_pushed(hub) == {"firewalls": []}


@pytest.mark.asyncio
async def test_unbound_firewall_is_never_pushed_even_to_its_own_tenant():
    """No fallback: an unbound firewall (legacy, or unbound on purpose) is not
    sent to a spoke with nothing bound, so an unbind clears the spoke."""
    hub = _FakeHub({"firewalls": [
        {"id": "fw-1", "model": "opnsense", "host": "10.0.0.5", "api_key": "k", "api_secret": "s"},
    ]}, module_type="firewall")
    hub.spoke_module_types["opn"] = "firewall"
    await LabManagerHub.push_config_to_spoke(hub, "opn")
    assert _config_pushed(hub) == {"firewalls": []}


@pytest.mark.asyncio
async def test_nac_push_remembers_what_the_spoke_was_sent():
    """The hub remembers the record and host each NAC spoke was sent, so it
    can tell when that record later moves or is deleted. The legacy single
    config is remembered as the hub's own record (nac_legacy_record)."""
    from hub_spoke_registry import LEGACY_NAC_RECORD_ID
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "h", "tenant_id": "tenantA"}],
                    "cppm-a")
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") == "rec-a"
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@h"}

    hub._gc["nac_instances"] = []
    hub._gc["cppm"] = {"host": "legacy"}
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") == LEGACY_NAC_RECORD_ID
    assert _config_pushed(hub)["host"] == "legacy"
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "legacy-cppm@legacy"}


@pytest.mark.asyncio
async def test_legacy_config_spoke_is_stale_until_it_confirms_after_a_reconnect_or_host_change():
    """With no NAC record every NAC spoke is sent the legacy single config.
    A spoke that reconnects holds only its .env config, and one that did not
    confirm a new host still holds the old ClearPass, so each is stale (no
    NAC read or write uses it) until it confirms the config. A spoke never
    sent one (the legacy config has no host) stays usable across reconnects."""
    from hub_spoke_registry import mark_nac_push_unknown, nac_spoke_stale
    hub = _FakeHub({"nac_instances": [], "cppm": {"host": "cp-1"}})
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") == "legacy-cppm"
    assert nac_spoke_stale(hub, "cppm-a") is False
    # Reconnect: stale until the connect push is confirmed.
    mark_nac_push_unknown(hub, "cppm-a")
    assert nac_spoke_stale(hub, "cppm-a") is True
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") == "legacy-cppm"
    assert nac_spoke_stale(hub, "cppm-a") is False
    # A host change: stale at once, and still stale when the spoke refuses it.
    hub._gc["cppm"] = {"host": "cp-2"}
    assert nac_spoke_stale(hub, "cppm-a") is True
    hub.reply = {"status": "ERROR", "message": "spoke command queue full"}
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") is None
    assert nac_spoke_stale(hub, "cppm-a") is True
    hub.reply = {"status": "SUCCESS"}
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") == "legacy-cppm"
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "legacy-cppm@cp-2"}
    # No legacy host: nothing is sent, and a reconnect leaves an .env spoke usable.
    hub = _FakeHub({"nac_instances": [], "cppm": {"host": " "}})
    assert await LabManagerHub.push_nac_config(hub, "cppm-b") is None
    mark_nac_push_unknown(hub, "cppm-b")
    assert nac_spoke_stale(hub, "cppm-b") is False


@pytest.mark.asyncio
async def test_nac_push_with_nothing_to_send_leaves_the_spoke_stale(caplog):
    """When a spoke's record moved to another spoke and nothing replaces it,
    there is no config to send. The spoke keeps the one it was sent, so it
    stays stale, and the hub warns once that it may still hold it."""
    import logging
    from hub_spoke_registry import nac_spoke_stale
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-b", "host": "h"}], "cppm-a")
    hub.state.system_state["nac_config_pushed"] = {"cppm-a": "rec-a@h"}
    with caplog.at_level(logging.WARNING):
        assert await LabManagerHub.push_nac_config(hub, "cppm-a") is None
    assert hub.sent == []
    assert "cppm-a" in hub._nac_unconfigured_spokes
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@h"}
    assert nac_spoke_stale(hub, "cppm-a") is True
    assert "may still hold" in caplog.text


@pytest.mark.asyncio
async def test_reconcile_drops_the_nac_caches_unless_told_not_to():
    """A NAC record change can change which ClearPass answers for a tenant,
    so reconcile drops every cached NAC read. Relocation keeps the record,
    its tenant and its ClearPass, and passes drop_caches=False."""
    from routes.cppm import NAC_CACHE_NAMESPACES
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "h"}], "cppm-a")
    hub.get_all_spokes_by_type = lambda module_type: ["cppm-a"]
    hub.approved_modules = {"cppm-a": True}
    hub.dropped = []
    hub.warm_drop = lambda namespace, key_prefixes: hub.dropped.append(namespace) or 0
    assert await LabManagerHub.reconcile_nac_spokes(hub, drop_caches=False) == {"cppm-a": "rec-a"}
    assert hub.dropped == []
    assert await LabManagerHub.reconcile_nac_spokes(hub) == {"cppm-a": "rec-a"}
    assert hub.dropped == list(NAC_CACHE_NAMESPACES)


# ── The NAC push is recorded only when the spoke confirms it ────────────────

def _updates(hub):
    """The UPDATE_CONFIG commands sent so far."""
    return [m for m in hub.sent if m.payload.type == "UPDATE_CONFIG"]


@pytest.mark.asyncio
@pytest.mark.parametrize("reply,frame", [
    ({"status": "ERROR", "message": "spoke command queue full"}, None),
    (None, {"status": "ERROR", "message": "Timed out waiting for spoke response"}),
])
async def test_nac_push_the_spoke_does_not_confirm_leaves_it_stale(reply, frame):
    """A spoke that refuses UPDATE_CONFIG (its command queue is full) or does
    not answer still holds its old ClearPass. The push is not recorded and
    the spoke stays stale, so no NAC read or write reaches it."""
    from hub_spoke_registry import nac_spoke_stale
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "h"}], "cppm-a")
    hub.state.system_state["nac_config_pushed"] = {"cppm-a": "rec-b@other"}
    hub.reply, hub.frame = reply, frame
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") is None
    assert _config_pushed(hub)["host"] == "h"
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": ""}
    assert nac_spoke_stale(hub, "cppm-a") is True


@pytest.mark.asyncio
async def test_failed_resend_of_the_confirmed_config_keeps_the_spoke_routable():
    """Re-sending a spoke the config it already confirmed leaves it routable
    even when it does not answer: either way it holds that config."""
    from hub_spoke_registry import nac_spoke_stale
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "h"}], "cppm-a")
    hub.state.system_state["nac_config_pushed"] = {"cppm-a": "rec-a@h"}
    hub.frame = {"status": "ERROR", "message": "Timed out waiting for spoke response"}
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") is None
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@h"}
    assert nac_spoke_stale(hub, "cppm-a") is False


def test_mark_nac_push_unknown():
    """A new connection makes the config a spoke confirmed unknown ("");
    a spoke never sent one keeps no entry. Before a push the entry is kept
    only when the spoke is re-sent exactly what it confirmed, so an
    unconfirmed push of A to a spoke that held B keeps it stale even after
    A is bound elsewhere again and B is what it should hold."""
    from hub_spoke_registry import mark_nac_push_unknown, nac_spoke_stale
    rec_b = {"id": "rec-b", "spoke_id": "cppm-a", "host": "hb"}
    hub = _make_hub([rec_b], "cppm-a")
    pushed = hub.state.system_state.setdefault("nac_config_pushed", {})
    # Connect: never sent a config, then sent one.
    mark_nac_push_unknown(hub, "cppm-a")
    assert pushed == {}
    pushed["cppm-a"] = "rec-b@hb"
    mark_nac_push_unknown(hub, "cppm-a")
    assert pushed == {"cppm-a": ""}
    # Before a push: the same config, then a different one.
    pushed["cppm-a"] = "rec-b@hb"
    mark_nac_push_unknown(hub, "cppm-a", sending=dict(rec_b))
    assert pushed == {"cppm-a": "rec-b@hb"}
    mark_nac_push_unknown(hub, "cppm-a", sending={"id": "rec-a", "host": "ha"})
    assert pushed == {"cppm-a": ""}
    assert nac_spoke_stale(hub, "cppm-a") is True


@pytest.mark.asyncio
async def test_nac_push_records_what_it_sent_when_the_record_is_edited_meanwhile():
    """The tenant NAC routes edit a stored record in place. An edit that
    lands while the spoke answers is not recorded as confirmed: the spoke
    holds the config it was sent."""
    stored = {"id": "rec-a", "spoke_id": "cppm-a", "host": "old"}
    hub = _make_hub([stored], "cppm-a")

    async def _answer(spoke_id, cmd, payload, timeout=None):
        """The record is edited while the spoke answers SUCCESS."""
        stored["host"] = "new"
        return {"payload": {"data": {"status": "SUCCESS"}}}

    hub.request_response = _answer
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") == "rec-a"
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@old"}


@pytest.mark.asyncio
async def test_nac_push_confirmed_by_a_replaced_connection_is_not_recorded():
    """A spoke that reconnects while the hub waits for its answer is a new
    process that holds only its .env. The old connection's SUCCESS is not
    recorded, so the spoke stays stale until the new connection confirms."""
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "h"}], "cppm-a")
    hub.active_connections["cppm-a"] = object()

    async def _answer(spoke_id, cmd, payload, timeout=None):
        """The spoke reconnects before the old connection's SUCCESS is read."""
        hub.active_connections["cppm-a"] = object()
        return {"payload": {"data": {"status": "SUCCESS"}}}

    hub.request_response = _answer
    assert await LabManagerHub.push_nac_config(hub, "cppm-a") is None
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": ""}


@pytest.mark.asyncio
async def test_concurrent_nac_pushes_send_the_newest_config_last():
    """Two pushes to one spoke run one at a time, and each reads the config
    once it runs: a save that lands while an older push waits for the
    spoke's answer is sent after it, so the spoke ends on the newest."""
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "old"}], "cppm-a")
    answer_first = asyncio.Event()
    hosts = []

    async def _answer(spoke_id, cmd, payload, timeout=None):
        """Hold the first push's answer until the test releases it."""
        hosts.append(payload["host"])
        if len(hosts) == 1:
            await answer_first.wait()
        return {"payload": {"data": {"status": "SUCCESS"}}}

    hub.request_response = _answer
    first = asyncio.create_task(LabManagerHub.push_nac_config(hub, "cppm-a"))
    for _ in range(5):
        await asyncio.sleep(0)
    # A save changes the host and pushes again while the first push waits.
    hub._gc["nac_instances"] = [{"id": "rec-a", "spoke_id": "cppm-a", "host": "new"}]
    second = asyncio.create_task(LabManagerHub.push_nac_config(hub, "cppm-a"))
    for _ in range(5):
        await asyncio.sleep(0)
    assert hosts == ["old"]
    answer_first.set()
    assert await asyncio.gather(first, second) == ["rec-a", "rec-a"]
    assert hosts == ["old", "new"]
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@new"}


# ── The connect-time NAC push ───────────────────────────────────────────────

def _connected_hub(monkeypatch, on_sleep):
    """A hub with spoke cppm-a connected, bound to rec-a and its NAC config
    unknown (as just after it connects). ``asyncio.sleep`` returns at once
    after calling ``on_sleep(hub, slept)``. Returns the hub and the list of
    delays slept."""
    hub = _make_hub([{"id": "rec-a", "spoke_id": "cppm-a", "host": "h"}], "cppm-a")
    hub.active_connections["cppm-a"] = object()
    hub.state.system_state["nac_config_pushed"] = {"cppm-a": ""}
    slept = []

    async def _sleep(delay):
        """Record the delay instead of waiting."""
        slept.append(delay)
        on_sleep(hub, slept)

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    return hub, slept


@pytest.mark.asyncio
async def test_connect_push_confirmed_at_once_does_not_wait(monkeypatch):
    """A connect-time push the spoke confirms ends the task at once."""
    hub, slept = _connected_hub(monkeypatch, lambda hub, slept: None)
    await LabManagerHub._push_nac_config_on_connect(hub, "cppm-a")
    assert slept == [] and len(_updates(hub)) == 1
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@h"}


@pytest.mark.asyncio
async def test_connect_push_is_tried_again_until_the_spoke_confirms(monkeypatch):
    """A connect-time push the spoke does not confirm is tried again after
    30 s and after 2 more minutes; the spoke here confirms the third."""
    def _confirm_third(hub, slept):
        """The spoke answers SUCCESS from the third push on."""
        if len(slept) == 2:
            hub.reply = {"status": "SUCCESS"}

    hub, slept = _connected_hub(monkeypatch, _confirm_third)
    hub.reply = {"status": "ERROR", "message": "spoke command queue full"}
    await LabManagerHub._push_nac_config_on_connect(hub, "cppm-a")
    assert slept == [30, 120] and len(_updates(hub)) == 3
    assert hub.state.system_state["nac_config_pushed"] == {"cppm-a": "rec-a@h"}


@pytest.mark.asyncio
async def test_connect_push_stops_on_a_new_connection_or_a_confirmed_save(monkeypatch):
    """Before trying again the task stops when the spoke reconnected (the
    new connection runs its own push) or the spoke confirmed its config
    meanwhile (a NAC save pushed it)."""
    def _reconnect(hub, slept):
        """The spoke reconnects while the task waits."""
        hub.active_connections["cppm-a"] = object()

    def _saved(hub, slept):
        """A NAC save gets the config confirmed while the task waits."""
        hub.state.system_state["nac_config_pushed"]["cppm-a"] = "rec-a@h"

    for on_sleep in (_reconnect, _saved):
        hub, slept = _connected_hub(monkeypatch, on_sleep)
        hub.reply = {"status": "ERROR", "message": "spoke command queue full"}
        await LabManagerHub._push_nac_config_on_connect(hub, "cppm-a")
        assert slept == [30] and len(_updates(hub)) == 1
