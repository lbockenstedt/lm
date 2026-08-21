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
    NAC/_INSTANCE_CONFIG_SOURCES branch is actually reached."""

    def __init__(self, gc, module_type="nac"):
        self.key_manager = type("KM", (), {"hub_secrets": ["hubsecret"]})()
        self._gc = gc
        self.spoke_module_types = {}
        self._module_type = module_type
        self.sent = []
        self._nac_unconfigured_spokes = set()
        self.state = type("S", (), {
            "get_global_config": lambda self, _g=gc: _g,
        })()

    def _primary_key(self, spoke_id):
        return spoke_id

    async def send_to_spoke(self, msg):
        self.sent.append(msg)


def _make_hub(nac_instances, spoke_id, module_type="nac"):
    hub = _FakeHub({"nac_instances": nac_instances}, module_type)
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
