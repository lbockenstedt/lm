"""nw scan agent scoping — routes/nw.py nw_scan_spoke_choices / resolve_nw_scan_spoke.

A tenant scans with ITS OWN nw agent, or an explicitly-offered SHARED one, and
nothing else. The previous resolver had an admin-only "any connected nw spoke"
fallback: with a single nw agent online (belonging to another tenant), an
Admin-tenant scan silently ran on that agent, so the aggregated targets and the
identified devices all came from that other tenant. These tests pin the
allowlist so that fallback cannot come back.
"""
from routes.nw import nw_scan_spoke_choices, resolve_nw_scan_spoke

SHARED = "tenant-shared"


class _FakeState:
    def __init__(self, metadata, names):
        self.system_state = {"module_metadata": metadata, "module_names": names}


class _Hub:
    """Minimal hub: nw spokes by type, approval flags, active connections and
    the module_metadata tenant bindings the resolver reads."""

    def __init__(self, spokes, metadata, active=None, approved=None, names=None):
        self._spokes = list(spokes)
        self.active_connections = set(spokes if active is None else active)
        self.approved_modules = (approved if approved is not None
                                 else {s: True for s in spokes})
        self.state = _FakeState(metadata, names or {})

    def get_all_spokes_by_type(self, module_type):
        return list(self._spokes) if module_type == "nw" else []

    def _primary_key(self, sid):
        return sid


def _hub():
    """Two nw agents: one bound to LRB (online), one to Admin (offline) — the
    exact live shape that produced the cross-tenant scan."""
    return _Hub(
        spokes=["nw-lrb", "nw-admin"],
        metadata={"nw-lrb": {"tenant_id": "tenant-lrb"},
                  "nw-admin": {"tenant_id": "tenant-admin"}},
        active=["nw-lrb"],
    )


# ── choices ────────────────────────────────────────────────────────────────
def test_choices_exclude_other_tenants_agent():
    got = nw_scan_spoke_choices(_hub(), "tenant-admin", SHARED)
    assert [c["spoke_id"] for c in got] == ["nw-admin"]
    assert got[0]["scope"] == "own"
    assert got[0]["connected"] is False


def test_choices_include_shared_agent_alongside_own():
    hub = _Hub(
        spokes=["nw-admin", "nw-shared"],
        metadata={"nw-admin": {"tenant_id": "tenant-admin"},
                  "nw-shared": {"tenant_id": SHARED}},
    )
    got = nw_scan_spoke_choices(hub, "tenant-admin", SHARED)
    # Own first, then shared — so the default pick is the tenant's own agent.
    assert [(c["spoke_id"], c["scope"]) for c in got] == [
        ("nw-admin", "own"), ("nw-shared", "shared")]


def test_choices_prefer_connected_within_a_scope():
    hub = _Hub(
        spokes=["nw-a", "nw-b"],
        metadata={"nw-a": {"tenant_id": "t1"}, "nw-b": {"tenant_id": "t1"}},
        active=["nw-b"],
        names={"nw-a": "aaa", "nw-b": "bbb"},
    )
    assert [c["spoke_id"] for c in nw_scan_spoke_choices(hub, "t1", SHARED)] == [
        "nw-b", "nw-a"]


def test_choices_skip_unapproved_spokes():
    hub = _Hub(spokes=["nw-x"], metadata={"nw-x": {"tenant_id": "t1"}},
               approved={"nw-x": False})
    assert nw_scan_spoke_choices(hub, "t1", SHARED) == []


def test_choices_skip_unassigned_spoke():
    """An unassigned nw spoke belongs to no tenant — it must not be offered."""
    hub = _Hub(spokes=["nw-free"], metadata={"nw-free": {}})
    assert nw_scan_spoke_choices(hub, "t1", SHARED) == []


# ── resolution ─────────────────────────────────────────────────────────────
def test_no_any_connected_fallback_to_another_tenant():
    """THE REGRESSION: Admin's own agent is offline and LRB's is the only one
    connected — resolve to nothing rather than silently scanning via LRB."""
    assert resolve_nw_scan_spoke(_hub(), "tenant-admin", "", SHARED) == ""


def test_resolves_own_connected_agent():
    hub = _Hub(spokes=["nw-admin"], metadata={"nw-admin": {"tenant_id": "tenant-admin"}})
    assert resolve_nw_scan_spoke(hub, "tenant-admin", "", SHARED) == "nw-admin"


def test_falls_back_to_shared_when_tenant_has_no_agent():
    hub = _Hub(spokes=["nw-shared"], metadata={"nw-shared": {"tenant_id": SHARED}})
    assert resolve_nw_scan_spoke(hub, "tenant-admin", "", SHARED) == "nw-shared"


def test_own_agent_wins_over_shared():
    hub = _Hub(
        spokes=["nw-shared", "nw-admin"],
        metadata={"nw-shared": {"tenant_id": SHARED},
                  "nw-admin": {"tenant_id": "tenant-admin"}},
    )
    assert resolve_nw_scan_spoke(hub, "tenant-admin", "", SHARED) == "nw-admin"


def test_explicit_shared_pick_is_honored():
    """The tenant may deliberately choose the shared agent over its own."""
    hub = _Hub(
        spokes=["nw-shared", "nw-admin"],
        metadata={"nw-shared": {"tenant_id": SHARED},
                  "nw-admin": {"tenant_id": "tenant-admin"}},
    )
    assert resolve_nw_scan_spoke(hub, "tenant-admin", "nw-shared", SHARED) == "nw-shared"


def test_requested_foreign_spoke_is_ignored_not_trusted():
    """A stale/hostile spoke_id naming another tenant's agent must not be used;
    it falls through to the tenant's own preference instead."""
    hub = _Hub(
        spokes=["nw-lrb", "nw-admin"],
        metadata={"nw-lrb": {"tenant_id": "tenant-lrb"},
                  "nw-admin": {"tenant_id": "tenant-admin"}},
    )
    assert resolve_nw_scan_spoke(hub, "tenant-admin", "nw-lrb", SHARED) == "nw-admin"


def test_requested_offline_own_spoke_falls_back_to_shared():
    hub = _Hub(
        spokes=["nw-admin", "nw-shared"],
        metadata={"nw-admin": {"tenant_id": "tenant-admin"},
                  "nw-shared": {"tenant_id": SHARED}},
        active=["nw-shared"],
    )
    assert resolve_nw_scan_spoke(hub, "tenant-admin", "nw-admin", SHARED) == "nw-shared"


def test_no_shared_tenant_configured_is_safe():
    """With no shared tenant, a tenant with no agent resolves to nothing rather
    than borrowing whatever is online."""
    assert resolve_nw_scan_spoke(_hub(), "tenant-admin", "", None) == ""
