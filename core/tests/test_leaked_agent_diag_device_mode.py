"""/setup/alert-diagnostics must not accuse a working self-heal of failing.

A DEVICE-MODE agent dials the hub directly: it holds its own WebSocket, it is a
real module spoke and it MUST stay in ``approved_modules`` to remain
authorized. It also registers in ``agent_config``/``agent_info``, so
``_relayed_agent_ids()`` matches it — exactly like a relayed pxmx node-agent.

``_selfheal_leaked_agents`` distinguishes the two with ``direct_module_ids``
(own ``install_uuid``, no ``parent_name``) and correctly leaves device-mode
agents approved. The diagnostic's ``leaked_agent_approved`` finding computed
``approved & relay_ids`` with NO such exclusion, so it reported every healthy
device-mode agent as "the self-heal should have popped it" — forever, since the
self-heal is right and will never pop them.

Observed in production: five connected ``module_type=agent`` spokes (the DNS
resolvers among them) reported by the finding while the self-heal had never
logged a single removal.

These lock the two predicates together.
"""

from routes.setup import _is_relayed_agent, _leaked_approved_agent_ids
from spoke_alert_sync import direct_module_ids

from test_spoke_alert import _AlertHub


# ── direct_module_ids ───────────────────────────────────────────────────────

def test_direct_module_ids_picks_installed_unparented_modules():
    ids = direct_module_ids({"module_metadata": {
        "device-agent": {"install_uuid": "u1"},
        "relayed": {"install_uuid": "u2", "parent_name": "pxmx-host"},
        "no-uuid": {"module_type": "agent"},
    }})
    assert ids == {"device-agent"}


def test_direct_module_ids_tolerates_missing_and_malformed_state():
    assert direct_module_ids({}) == set()
    assert direct_module_ids(None) == set()
    assert direct_module_ids({"module_metadata": {"x": "not-a-dict"}}) == set()


# ── the finding predicate ───────────────────────────────────────────────────

def test_device_mode_agent_is_not_reported_as_leaked():
    """THE REGRESSION: approved + in relay_ids, but a direct module spoke."""
    assert _leaked_approved_agent_ids(
        approved={"device-agent"},
        relay_ids={"device-agent"},
        direct_ids={"device-agent"}) == set()


def test_a_genuinely_leaked_relayed_agent_is_still_reported():
    """The finding must keep working for the case it was written for."""
    assert _leaked_approved_agent_ids(
        approved={"pxmx-agent"},
        relay_ids={"pxmx-agent"},
        direct_ids=set()) == {"pxmx-agent"}


def test_only_the_leaked_id_is_reported_in_a_mixed_fleet():
    assert _leaked_approved_agent_ids(
        approved={"device-agent", "pxmx-agent", "plain-spoke"},
        relay_ids={"device-agent", "pxmx-agent"},
        direct_ids={"device-agent", "plain-spoke"}) == {"pxmx-agent"}


def test_an_unapproved_relayed_agent_is_not_reported():
    assert _leaked_approved_agent_ids(
        approved=set(), relay_ids={"pxmx-agent"}, direct_ids=set()) == set()


# ── the row flag / false-positive finding ───────────────────────────────────

def test_device_mode_agent_is_not_flagged_as_relayed():
    """Otherwise a REAL outage of a device-mode agent is dismissed by the
    'relayed_agent_false_positive' finding as 'Not a real outage.'"""
    assert _is_relayed_agent("device-agent", {"device-agent"},
                             {"device-agent"}) is False


def test_relayed_agent_is_still_flagged():
    assert _is_relayed_agent("pxmx-agent", {"pxmx-agent"}, set()) is True


def test_plain_spoke_is_not_flagged():
    assert _is_relayed_agent("plain-spoke", {"pxmx-agent"}, set()) is False


# ── the two predicates must agree ───────────────────────────────────────────

def _hub_with_device_mode_agent():
    """A device-mode agent: approved, heartbeats under a composite key, listed
    in agent_config/agent_info, AND a direct module spoke."""
    h = _AlertHub(approved={"device-agent": True},
                  last_seen={"pxmx:device-agent": 100.0})
    h.state.system_state["agent_config"] = {"device-agent": {}}
    h.state.system_state["module_metadata"] = {
        "device-agent": {"install_uuid": "direct-install-uuid"}}
    h.state.system_state["known_modules"] = ["device-agent"]
    h.known_modules = ["device-agent"]
    h.agent_info = {"device-agent": {"spoke_id": "pxmx"}}
    return h


def test_diagnostic_agrees_with_the_self_heal_for_a_device_mode_agent():
    h = _hub_with_device_mode_agent()

    removed = h._selfheal_leaked_agents()
    assert removed == set(), "self-heal must keep a live device-mode agent"

    approved = {s for s, a in h.approved_modules.items() if a}
    reported = _leaked_approved_agent_ids(
        approved, h._relayed_agent_ids(),
        direct_module_ids(h.state.system_state))
    assert reported == removed, (
        "the diagnostic must report exactly what the self-heal pops")


def test_diagnostic_agrees_with_the_self_heal_for_a_real_leak():
    """Same cross-check, opposite verdict — proves the agreement assertion
    above is not vacuously true of a predicate that returns nothing."""
    h = _AlertHub(approved={"pxmx-agent": True},
                  last_seen={"pxmx:pxmx-agent": 100.0})
    h.state.system_state["agent_config"] = {"pxmx-agent": {}}
    h.state.system_state["module_metadata"] = {}
    h.state.system_state["known_modules"] = ["pxmx-agent"]
    h.known_modules = ["pxmx-agent"]
    h.agent_info = {"pxmx-agent": {"spoke_id": "pxmx"}}

    approved_before = {s for s, a in h.approved_modules.items() if a}
    reported = _leaked_approved_agent_ids(
        approved_before, h._relayed_agent_ids(),
        direct_module_ids(h.state.system_state))

    removed = h._selfheal_leaked_agents()

    assert removed == {"pxmx-agent"}
    assert reported == removed
