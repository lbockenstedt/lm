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


# The two source-text guards that used to live here -- grepping the route body
# for ``access.tenant_scope_ids(tid)`` and for
# ``'if tid == "default":\n            spokes = []'`` with exact indentation --
# were replaced by behavioural tests. They asserted the letter of the fix
# rather than its effect: reformatting the route broke them while an actual
# regression that kept the same text would have sailed through.
#
# Their coverage now lives in:
#   * the tests above, which exercise pxmx_agents_payload's filter directly
#     (test_admin_default_excludes_other_tenants and friends);
#   * test_pxmx_nodes_spoke_fallback.py, which drives /api/pxmx/drive-health
#     through a TestClient and asserts no spoke is queried for the ADMIN scope.


@pytest.mark.asyncio
async def test_admin_default_never_widens_when_helper_is_bypassed():
    """Behavioural stand-in for the old "route calls the shared helper" source
    grep: whatever the route does internally, an agent dedicated to another
    tenant must never appear in the ADMIN scope."""
    ids = await _ids("default")
    assert ids.isdisjoint({"a_lrb", "a_pinned_acme"})
    # ...and the ADMIN scope is genuinely narrower than the unscoped view.
    assert ids < await _ids(None)
