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
import pytest

from main import LabManagerHub


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
        self.state = type("S", (), {
            "get_global_config": lambda self, _g=gc: _g,
        })()

    def _primary_key(self, spoke_id):
        return self._alias.get(spoke_id, spoke_id)

    async def send_to_spoke(self, msg):
        self.sent.append(msg)


def _make_hub(nac_instances, spoke_id, module_type="nac", alias=None):
    hub = _FakeHub({"nac_instances": nac_instances}, module_type, alias=alias)
    hub.spoke_module_types[spoke_id] = module_type
    return hub


def _config_pushed(hub):
    updates = [m for m in hub.sent if m.payload.type == "UPDATE_CONFIG"]
    return updates[-1].payload.data if updates else None


@pytest.mark.asyncio
async def test_spoke_gets_its_own_bound_instance():
    hub = _make_hub([
        {"spoke_id": "cppm-a", "host": "172.16.1.16", "tenant_id": "tenantA"},
        {"spoke_id": "cppm-b", "host": "172.16.1.20", "tenant_id": "tenantB"},
    ], "cppm-a")
    await LabManagerHub.push_config_to_spoke(hub, "cppm-a")
    assert _config_pushed(hub)["host"] == "172.16.1.16"


@pytest.mark.asyncio
async def test_other_spoke_gets_its_own_bound_instance_not_the_first_one():
    hub = _make_hub([
        {"spoke_id": "cppm-a", "host": "172.16.1.16", "tenant_id": "tenantA"},
        {"spoke_id": "cppm-b", "host": "172.16.1.20", "tenant_id": "tenantB"},
    ], "cppm-b")
    await LabManagerHub.push_config_to_spoke(hub, "cppm-b")
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
    await LabManagerHub.push_config_to_spoke(hub, "cppm-c")
    updates = [m for m in hub.sent if m.payload.type == "UPDATE_CONFIG"]
    assert updates == [], "must push nothing rather than another spoke's host/credentials"
    assert "cppm-c" in hub._nac_unconfigured_spokes


@pytest.mark.asyncio
async def test_unbound_instance_still_fills_single_product_deployment():
    """A single-product deployment (one instance, no spoke_id bound at all)
    still works — the unbound-instance fallback is preserved."""
    hub = _make_hub([{"host": "172.16.1.16"}], "cppm-a")
    await LabManagerHub.push_config_to_spoke(hub, "cppm-a")
    assert _config_pushed(hub)["host"] == "172.16.1.16"


@pytest.mark.asyncio
async def test_empty_instances_list_falls_back_to_legacy_single_config():
    """Pre-multi-instance deployment (empty nac_instances) still pushes the
    legacy global_config['cppm'] single-config key."""
    hub = _FakeHub({"nac_instances": [], "cppm": {"host": "172.16.1.99"}})
    hub.spoke_module_types["cppm-legacy"] = "nac"
    await LabManagerHub.push_config_to_spoke(hub, "cppm-legacy")
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
    await LabManagerHub.push_config_to_spoke(hub, "guid-111")
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
    await LabManagerHub.push_config_to_spoke(hub, "cppm-a")
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
    await LabManagerHub.push_config_to_spoke(hub_a, "guid-lrb")
    assert _config_pushed(hub_a)["host"] == "172.16.1.16"

    hub_b = _make_hub([
        {"spoke_id": "lrb-agent-cppm", "host": "172.16.1.16", "tenant_id": "LRB"},
        {"spoke_id": "ra-agent-cppm", "host": "172.16.1.94", "tenant_id": "RA"},
    ], "guid-ra", alias={"lrb-agent-cppm": "guid-lrb", "ra-agent-cppm": "guid-ra"})
    await LabManagerHub.push_config_to_spoke(hub_b, "guid-ra")
    assert _config_pushed(hub_b)["host"] == "172.16.1.94"


@pytest.mark.asyncio
async def test_migrated_spoke_still_never_receives_a_different_spokes_instance():
    """The no-cross-leak guarantee must hold across identity generations too:
    an unrelated spoke's guid must not resolve to someone else's instance."""
    hub = _make_hub([
        {"spoke_id": "lrb-agent-cppm", "host": "172.16.1.16", "tenant_id": "LRB"},
    ], "guid-unrelated", alias={"lrb-agent-cppm": "guid-lrb"})
    await LabManagerHub.push_config_to_spoke(hub, "guid-unrelated")
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
