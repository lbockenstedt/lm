"""Feature B4: ``/setup/pending_spokes`` emits an explicit ``parent_spoke_id``
+ ``role_name`` for role sub-spokes so the WebUI can match a sub-spoke to its
parent agent AFTER the B1 guid-primary migration re-keyed ``known_modules``
raw→guid (the pre-B1 ``{base}-{role}`` string-prefix match broke once both the
base + the sub-spoke became independent guid keys).

The hub stamps ``parent_name`` (the raw parent name the sub-spoke claimed at
connect) + ``role_name`` into the sub-spoke's ``module_metadata``; the emitter
resolves ``parent_name`` via ``_primary_key`` so it matches the parent row's
own ``spoke_id`` (guid once armed, raw until then). Persisted → the linkage
survives the sub-spoke going offline (the in-memory ``spoke_parent_map`` does
not). These pin the emit shape + the guid resolution + the blank-for-base case.
"""
import asyncio

from routes import setup


class _FakeState:
    def __init__(self, known, names=None, meta=None, tenants=None):
        self.system_state = {
            "known_modules": list(known),
            "module_names": names or {},
            "module_metadata": meta or {},
        }
        self._tenants = tenants or {}

    def get_spoke_tenant(self, sid):
        return self._tenants.get(sid)


class _FakeHub:
    """Hub whose ``_primary_key`` resolves raw→guid via ``spoke_id_alias``
    (mirrors the armed state post-B1)."""

    def __init__(self, known, names=None, meta=None, tenants=None,
                 approved=None, module_types=None, alias=None):
        self.state = _FakeState(known, names, meta, tenants)
        self.approved_modules = approved or {}
        self.spoke_module_types = module_types or {}
        self.spoke_id_alias = alias or {}

    def _primary_key(self, sid):
        return self.spoke_id_alias.get(sid, sid)

    def get_spoke_events(self, sid, limit=20):
        return []


def _reset_spokes_cache():
    setup._SPOKES_CACHE["data"] = None
    setup._SPOKES_CACHE["ts"] = 0.0
    setup._SPOKES_CACHE["refreshing"] = False


def test_subspoke_emits_parent_spoke_id_resolved_to_guid():
    """A role sub-spoke armed to its own guid, parent armed to its guid: the
    emitted ``parent_spoke_id`` is the PARENT's guid (matches the parent
    row's ``spoke_id``), NOT the raw name — so the WebUI's
    ``o.parent_spoke_id === baseId`` match holds."""
    _reset_spokes_cache()
    base_raw, base_guid = "agent-node-1", "GUID-BASE"
    sub_raw, sub_guid = "agent-node-1-firewall", "GUID-SUB-FW"
    hub = _FakeHub(
        known=[base_guid, sub_guid],
        names={base_guid: "Node 1", sub_guid: "Node 1 / firewall"},
        meta={
            base_guid: {"hostname": "n1", "install_uuid": base_guid,
                        "module_type": "agent"},
            sub_guid: {"hostname": "n1", "install_uuid": sub_guid,
                       "module_type": "firewall",
                       # stamped at connect (main.py handle_connection):
                       "parent_name": base_raw, "role_name": "firewall"},
        },
        approved={base_guid: True, sub_guid: True},
        module_types={base_guid: "agent", sub_guid: "firewall"},
        alias={base_raw: base_guid, sub_raw: sub_guid},
    )
    out = asyncio.run(setup._aggregate_spokes(hub))
    rows = {r["spoke_id"]: r for r in out["spokes"]}
    # Base row: no parent linkage.
    assert rows[base_guid]["parent_spoke_id"] == ""
    assert rows[base_guid]["role_name"] == ""
    # Sub-spoke row: parent resolved raw→guid; role name carried.
    assert rows[sub_guid]["parent_spoke_id"] == base_guid
    assert rows[sub_guid]["role_name"] == "firewall"


def test_subspoke_parent_resolves_to_raw_when_parent_not_yet_armed():
    """If the parent hasn't armed yet (alias empty — e.g. it never connected
    this boot), ``_primary_key(parent_raw)`` returns the raw name, which is
    still the parent's known_modules key → matches the parent row's
    ``spoke_id``. No mismatch across the arm boundary."""
    _reset_spokes_cache()
    sub_guid = "GUID-SUB-FW"
    hub = _FakeHub(
        known=[sub_guid],
        meta={sub_guid: {"hostname": "n1", "install_uuid": sub_guid,
                         "module_type": "firewall",
                         "parent_name": "agent-node-1", "role_name": "firewall"}},
        approved={sub_guid: True},
        module_types={sub_guid: "firewall"},
        alias={},  # parent not armed → _primary_key returns raw
    )
    out = asyncio.run(setup._aggregate_spokes(hub))
    rows = {r["spoke_id"]: r for r in out["spokes"]}
    assert rows[sub_guid]["parent_spoke_id"] == "agent-node-1"
    assert rows[sub_guid]["role_name"] == "firewall"


def test_base_spoke_and_legacy_entries_blank_parent():
    """A base spoke / any pre-B1 entry without ``parent_name`` emits blank
    parent_spoke_id + role_name (WebUI falls back to the prefix match)."""
    _reset_spokes_cache()
    hub = _FakeHub(
        known=["pxmx-1", "opn-1"],
        names={"pxmx-1": "PXMX One", "opn-1": "OPN One"},
        meta={"pxmx-1": {"hostname": "h1", "install_uuid": "g1", "module_type": "hypervisor"},
              "opn-1": {"hostname": "h2", "install_uuid": "g2", "module_type": "firewall"}},
        approved={"pxmx-1": True, "opn-1": False},
        module_types={"pxmx-1": "hypervisor", "opn-1": "firewall"},
    )
    out = asyncio.run(setup._aggregate_spokes(hub))
    for r in out["spokes"]:
        assert r["parent_spoke_id"] == ""
        assert r["role_name"] == ""