"""Parent-side ``VOUCH_SUBSPOKE`` handler (H3): the hub asks a base generic
agent to vouch that a ``sub_spoke_id`` is one of the role sub-spokes it
actually spawned and tracks. This is the parent-attestation half of H3 — the
hub's ``_parent_vouches`` round-trip resolves to this handler, and only a
``vouched=True`` reply (with a matching ``sub_spoke_id`` echo) lets the hub
auto-approve + tenant-bind the child without trusting the child's unsigned
``parent_spoke_id`` claim.

The handler reads only the in-memory role registry (``_roles`` →
``e["conn"].spoke_id``), so it's safe to answer the moment the session key is
pushed — before the agent is fully approved (signing uses whatever current key
the control plane holds). ``vouched=True`` only for a sub_spoke_id this agent
spawned; ``False`` otherwise. The reply shape (``status SUCCESS`` +
``data.vouched`` + ``data.sub_spoke_id`` echo) is what the hub verifies via
``unwrap_spoke`` + the echo match (prevents a generic/replayed "yes"
authorizing a different child).
"""

import asyncio
from types import SimpleNamespace

from agent_spoke import GenericAgent


def _agent():
    return GenericAgent("agent-1", {})


def _role_entry(sub_spoke_id, module_type="dns"):
    """A minimal _roles entry: the handler only reads conn.spoke_id."""
    return {"instance": SimpleNamespace(),
            "conn": SimpleNamespace(spoke_id=sub_spoke_id, module_type=module_type),
            "task": None}


# ── vouch lookup over the role registry ──────────────────────────────────────

def test_vouch_true_for_a_tracked_role_subspoke():
    agent = _agent()
    agent._roles["dns"] = _role_entry("agent-1-dns")
    res = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {"sub_spoke_id": "agent-1-dns"}))
    assert res == {"status": "SUCCESS",
                   "data": {"vouched": True, "sub_spoke_id": "agent-1-dns"}}


def test_vouch_false_for_an_unknown_subspoke():
    """An id the agent didn't spawn (e.g. an attacker's {base}-evil) → vouched
    False, so the hub leaves the child pending admin approval."""
    agent = _agent()
    agent._roles["dns"] = _role_entry("agent-1-dns")
    res = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {"sub_spoke_id": "agent-1-EVIL"}))
    assert res == {"status": "SUCCESS",
                   "data": {"vouched": False, "sub_spoke_id": "agent-1-EVIL"}}


def test_vouch_false_when_no_roles_loaded():
    """Safe before any role is spawned (boot race): _roles == {} → vouched False."""
    agent = _agent()  # _roles == {}
    res = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {"sub_spoke_id": "agent-1-dns"}))
    assert res["status"] == "SUCCESS"
    assert res["data"] == {"vouched": False, "sub_spoke_id": "agent-1-dns"}


def test_vouch_among_multiple_roles_matches_only_the_right_one():
    agent = _agent()
    agent._roles["dns"] = _role_entry("agent-1-dns")
    agent._roles["dhcp"] = _role_entry("agent-1-dhcp")
    res = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {"sub_spoke_id": "agent-1-dhcp"}))
    assert res["data"]["vouched"] is True
    assert res["data"]["sub_spoke_id"] == "agent-1-dhcp"
    # And the other role's id is still vouched True.
    res2 = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {"sub_spoke_id": "agent-1-dns"}))
    assert res2["data"]["vouched"] is True


def test_vouch_echoes_empty_subspoke_id_and_denies():
    """An empty/missing sub_spoke_id is echoed back and denied (bool("") is False)."""
    agent = _agent()
    agent._roles["dns"] = _role_entry("agent-1-dns")
    res = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {"sub_spoke_id": ""}))
    assert res == {"status": "SUCCESS", "data": {"vouched": False, "sub_spoke_id": ""}}


def test_vouch_command_is_case_insensitive():
    """The dispatcher upper-cases the command (consistent with LOAD_ROLE etc.)."""
    agent = _agent()
    agent._roles["dns"] = _role_entry("agent-1-dns")
    res = asyncio.run(agent.handle_command("vouch_subspoke", {"sub_spoke_id": "agent-1-dns"}))
    assert res["data"]["vouched"] is True


def test_vouch_missing_subspoke_id_field_denies():
    """No sub_spoke_id in the payload → echoed as "" and denied (defensive)."""
    agent = _agent()
    agent._roles["dns"] = _role_entry("agent-1-dns")
    res = asyncio.run(agent.handle_command("VOUCH_SUBSPOKE", {}))
    assert res == {"status": "SUCCESS", "data": {"vouched": False, "sub_spoke_id": ""}}