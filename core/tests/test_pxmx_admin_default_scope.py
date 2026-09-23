"""ADMIN/Default must not accumulate every tenant's hypervisor agents.

Reported bug: with the Admin/Default tenant selected in the picker, the
Hypervisors page listed EVERY tenant's agents. ``default`` is the built-in
ADMIN tenant (routes/tenants_users.py renders it as "ADMIN"), not an
"All tenants" view, so its scope is UNASSIGNED + explicitly-default + shared
agents — never another tenant's dedicated ones. Same rule routes/nw.py names
"ADMIN(default) must not accumulate across tenants".

Guards ``pxmx_agents_payload``'s per-agent filter, including the precedence
that matters: an agent's OWN pin (``client_simulation.tenant_id``) wins over
its parent spoke's ``module_metadata`` binding.
"""
import time
import types

import pytest

import access
from routes import pxmx  # core/src on sys.path via conftest


def _agent(agent_id, spoke_id, pin=None):
    a = {"agent_id": agent_id, "spoke_id": spoke_id}
    if pin is not None:
        a["client_simulation"] = {"tenant_id": pin}
    return a


# Spokes: s_lrb bound to "lrb", s_shared to the shared tenant, s_none unbound.
_MD = {
    "s_lrb": {"tenant_id": "lrb"},
    "s_shared": {"tenant_id": "sharedtenant"},
    "s_none": {},
}

_AGENTS = [
    _agent("a_lrb", "s_lrb"),                        # dedicated to lrb
    _agent("a_pinned_acme", "s_shared", "acme"),     # pin wins over shared spoke
    _agent("a_pinned_default", "s_shared", "default"),  # pinned to ADMIN
    _agent("a_shared", "s_shared"),                  # shared infra
    _agent("a_unassigned", "s_none"),                # UNASSIGNED holding state
]


class _State:
    def __init__(self):
        self.system_state = {"module_metadata": _MD}


def _hub():
    return types.SimpleNamespace(
        state=_State(),
        get_all_spokes_by_type=lambda t: (["s_lrb", "s_shared", "s_none"]
                                          if t == "hypervisor" else []),
    )


@pytest.fixture(autouse=True)
def _seeded(monkeypatch):
    """Serve the full roster from the SWR cache so the real filter tail runs
    without needing a live spoke fan-out."""
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "sharedtenant", raising=False)
    monkeypatch.setattr(pxmx, "_offline_relay_agents", lambda hub, ids: [])
    monkeypatch.setitem(pxmx._AGENTS_CACHE, "data", {
        "agents": list(_AGENTS), "pending_agents": [], "spoke_connected": True,
    })
    monkeypatch.setitem(pxmx._AGENTS_CACHE, "ts", time.time())
    monkeypatch.setitem(pxmx._AGENTS_CACHE, "refreshing", False)


async def _ids(tid):
    out = await pxmx.pxmx_agents_payload(_hub(), tid)
    return {a["agent_id"] for a in out["agents"]}


@pytest.mark.asyncio
async def test_admin_default_excludes_other_tenants():
    ids = await _ids("default")
    assert "a_lrb" not in ids            # THE bug: another tenant's dedicated
    assert "a_pinned_acme" not in ids    # pinned elsewhere, on a shared spoke


@pytest.mark.asyncio
async def test_admin_default_includes_unassigned_default_and_shared():
    assert await _ids("default") == {"a_unassigned", "a_pinned_default", "a_shared"}


@pytest.mark.asyncio
async def test_specific_tenant_unchanged():
    # Its own dedicated agent + shared infra; no unassigned, no other tenant.
    assert await _ids("lrb") == {"a_lrb", "a_shared"}


@pytest.mark.asyncio
async def test_pin_wins_over_spoke_binding():
    # a_pinned_acme sits on the SHARED spoke but is pinned to acme, so it must
    # follow acme — and must NOT appear for lrb.
    assert "a_pinned_acme" in await _ids("acme")
    assert "a_pinned_acme" not in await _ids("lrb")


@pytest.mark.asyncio
async def test_unscoped_call_sees_everything():
    assert await _ids(None) == {a["agent_id"] for a in _AGENTS}


def test_route_source_uses_the_shared_helper():
    """The route must not re-introduce the ``tid != "default"`` skip."""
    import inspect
    src = inspect.getsource(pxmx.pxmx_agents_payload)
    assert 'tid != "default"' not in src
    assert "access.tenant_scope_ids(tid)" in src
    assert "access.in_tenant_scope(" in src


def test_drive_health_does_not_fall_back_to_global_spoke_on_default():
    import inspect
    src = inspect.getsource(pxmx)
    # The ADMIN/default branch must be explicit and flagged for the UI.
    assert 'if tid == "default":\n            spokes = []' in src
    assert "select_tenant" in src
