"""Registry diag: guid-migrated pxmx agents must not read as dead spokes.

Live signature (LM-HUB, mipbe-ssplm-pxmx01..03): the agents' real state is
keyed by install guid in ``agent_config`` (hostname/display_name = the raw
name), but the old approved_modules leak left RAW-NAME entries behind in
``module_metadata``/``module_names`` (tenant "default", no module_type). The
self-heal only un-approves leaks, so those rows survive. The in-memory
``agent_id_alias`` (name → guid) is empty after a hub restart until each agent
relays in again, so the diag found no relay evidence via the raw name and
rendered every row as "offline · no key · unapproved · never".

The fix resolves name → guid durably from ``agent_config`` / ``agent_info``
and treats the row as a relayed agent (liveness from the guid's relay
timestamp, no "no key"/"not approved" fault).
"""
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.setup as setup_routes
from routes.setup import _agent_last_seen_for, _agent_name_to_guid

GUID1 = "c3b11aff-5f63-4ed2-ac98-9bca95bf78d5"
GUID2 = "6a26953d-003a-4c43-b99d-5495b146a396"


# ── _agent_name_to_guid ─────────────────────────────────────────────────────

def test_name_map_from_agent_config_hostname_and_display_name():
    m = _agent_name_to_guid(
        {GUID1: {"hostname": "pxmx01", "display_name": "pxmx01"},
         GUID2: {"display_name": "Proxmox Two", "hostname": "pxmx02"}}, {})
    assert m == {"pxmx01": GUID1, "pxmx02": GUID2, "Proxmox Two": GUID2}


def test_name_map_includes_agent_info_raw_name():
    assert _agent_name_to_guid({}, {GUID1: {"agent_id": "pxmx01"}}) == {"pxmx01": GUID1}


def test_name_map_skips_unmigrated_agents_keyed_by_name():
    """A legacy name-keyed agent maps to itself — nothing to resolve."""
    assert _agent_name_to_guid({"pxmx01": {"hostname": "pxmx01"}}, {}) == {}


def test_name_map_drops_ambiguous_names():
    """Two guids claiming one hostname: never guess which is the row."""
    m = _agent_name_to_guid(
        {GUID1: {"hostname": "dup"}, GUID2: {"hostname": "dup"}}, {})
    assert "dup" not in m


def test_name_map_tolerates_malformed_entries():
    assert _agent_name_to_guid({GUID1: "x", GUID2: None}, {"g": 3}) == {}
    assert _agent_name_to_guid(None, None) == {}


# ── _agent_last_seen_for ────────────────────────────────────────────────────

def test_last_seen_picks_freshest_across_keys():
    assert _agent_last_seen_for({"a": 10.0, GUID1: 50.0}, "a", GUID1, "b") == 50.0


def test_last_seen_none_when_never_relayed():
    assert _agent_last_seen_for({}, "a", GUID1) is None
    assert _agent_last_seen_for({"a": 0, "b": "x"}, "a", "b", None) is None


# ── route ───────────────────────────────────────────────────────────────────

class _NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _hub(relayed_last, agent_config, alias=None, extra_md=None, approved=None,
         conns=None, keys=None):
    md = {
        "mipbe-ssplm-pxmx01": {"display_name": "mipbe-ssplm-pxmx01", "tenant_id": "default"},
        "mipbe-ssplm-pxmx02": {"display_name": "mipbe-ssplm-pxmx02", "tenant_id": "default"},
    }
    md.update(extra_md or {})
    alias = alias or {}
    state = _NS(system_state={"module_metadata": md, "agent_config": agent_config},
                get_spoke_tenant=lambda sid: (md.get(sid) or {}).get("tenant_id", ""))
    return _NS(
        state=state,
        approved_modules=approved or {},
        active_connections=conns or {},
        spoke_module_types={},
        key_manager=_NS(keys=keys or {}),
        heartbeat=_NS(last_seen={}),
        agent_info={},
        simulations_cache={},
        _relayed_agent_last_seen=lambda: dict(relayed_last),
        _relayed_agent_ids=lambda: set(agent_config),
        _primary_key=lambda sid: sid,
        _agent_primary_key=lambda aid: alias.get(aid, aid),
        get_client_sim_spoke=lambda t: None,
    )


def _rows(hub):
    app = FastAPI()
    app.state.hub = hub
    ctx = _NS(_session_user=lambda req: {"user": {"permissions": {"admin": True}}},
              _is_admin=lambda s: True)
    setup_routes.register(app, hub, ctx)
    body = TestClient(app).get("/setup/spoke-registry-diag").json()
    return {r["spoke_id"]: r for r in body["rows"]}, body


_CFG = {GUID1: {"hostname": "mipbe-ssplm-pxmx01", "display_name": "mipbe-ssplm-pxmx01"},
        GUID2: {"hostname": "mipbe-ssplm-pxmx02", "display_name": "mipbe-ssplm-pxmx02"}}


def test_raw_name_row_resolves_to_live_guid_agent_after_restart():
    """THE REGRESSION: empty alias (fresh restart), live relay under the guid."""
    now = time.time()
    rows, _ = _rows(_hub({GUID1: now - 20, GUID2: now - 40}, _CFG))
    for sid in ("mipbe-ssplm-pxmx01", "mipbe-ssplm-pxmx02"):
        r = rows[sid]
        assert r["is_relayed_agent"] is True
        assert r["connected"] is True
        assert r["last_seen"] is not None
        assert "no session key" not in r["ghost_reasons"]
        assert "not approved" not in r["ghost_reasons"]
        assert r["stuck_never_keyed"] is False


def test_in_memory_alias_still_used_when_armed():
    now = time.time()
    rows, _ = _rows(_hub({GUID1: now - 5}, {GUID1: {}},
                         alias={"mipbe-ssplm-pxmx01": GUID1}))
    assert rows["mipbe-ssplm-pxmx01"]["connected"] is True


def test_configured_agent_that_never_relayed_is_relayed_but_offline():
    """In agent_config but silent: labelled a relayed agent (not a ghost
    spoke with no key), honestly offline with no last_seen."""
    rows, _ = _rows(_hub({}, _CFG))
    r = rows["mipbe-ssplm-pxmx01"]
    assert r["is_relayed_agent"] is True
    assert r["connected"] is False
    assert r["last_seen"] is None
    assert "not connected" in r["ghost_reasons"]
    assert "no session key" not in r["ghost_reasons"]


def test_stale_relay_reads_offline_with_last_seen():
    old = time.time() - 3600
    rows, _ = _rows(_hub({GUID1: old}, _CFG))
    r = rows["mipbe-ssplm-pxmx01"]
    assert r["is_relayed_agent"] is True
    assert r["connected"] is False
    assert abs(r["last_seen"] - old) < 1


def test_unrelated_dead_spoke_still_flagged():
    """A real never-keyed spoke with no agent link keeps every fault."""
    rows, body = _rows(_hub({}, _CFG, extra_md={"cs-svr-09": {"tenant_id": "t"}},
                            approved={"cs-svr-09": True}))
    r = rows["cs-svr-09"]
    assert r["is_relayed_agent"] is False
    assert "no session key" in r["ghost_reasons"]
    assert r["stuck_never_keyed"] is True


def test_unapproved_plain_spoke_still_reports_not_approved():
    rows, _ = _rows(_hub({}, {}, extra_md={"fw-new": {"tenant_id": "t"}}))
    assert "not approved" in rows["fw-new"]["ghost_reasons"]
