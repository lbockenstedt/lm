"""Regression: SPOKE_UPDATE repo resolution must survive a disconnected spoke.

Root cause of the recurring ``lm-opnsense`` agent flap: the update fan-out read
the LIVE ``spoke_module_types`` map, which is popped when a spoke disconnects.
An approved-but-offline generic agent therefore resolved module_type ``""`` →
missed the ``_IN_LM_REPO_MODULE_TYPES`` guard → its spoke_id substring-mapped
``"lm-opnsense"`` → ``"opn"`` → the opnsense repo. That poison SPOKE_UPDATE,
queued into the agent's DURABLE mailbox, repointed the shared /opt/lm checkout
to opnsense.git and hard-reset it on reconnect — deleting control_plane.py and
crash-looping the agent.

``UpdatePipelineMixin._effective_module_type`` now falls back to the module_type
persisted in ``module_metadata`` (written on every registration), so an offline
agent still resolves as ``"agent"`` → the lm repo.
"""

import pytest
from update_pipeline import (
    UpdatePipelineMixin,
    _UPDATE_SOURCE_PREFIX_MAP,
    _IN_LM_REPO_MODULE_TYPES,
)


class _FakeState:
    def __init__(self, module_metadata):
        self.system_state = {"module_metadata": module_metadata}


class _StubHub(UpdatePipelineMixin):
    """Just the two attributes the resolution helpers touch."""

    def __init__(self, live_types, persisted_types):
        self.spoke_module_types = dict(live_types)
        self.state = _FakeState(
            {sid: {"module_type": mt} for sid, mt in persisted_types.items()}
        )


def test_offline_agent_resolves_to_lm_repo_not_role_repo():
    # Agent is approved but disconnected → NOT in the live map, only persisted.
    hub = _StubHub(live_types={}, persisted_types={"lm-opnsense": "agent"})
    mtype = hub._effective_module_type("lm-opnsense")
    assert mtype == "agent"
    assert mtype in _IN_LM_REPO_MODULE_TYPES
    # → the lm repo ("agent" source key), never the opnsense substring match.
    assert hub._resolve_module_key("lm-opnsense", mtype,
                                   _UPDATE_SOURCE_PREFIX_MAP) == "agent"


def test_offline_agent_without_fallback_would_substring_map_to_opnsense():
    """Documents the bug the fallback prevents: empty type → substring → opnsense."""
    hub = _StubHub(live_types={}, persisted_types={})
    # No live and no persisted type — the pre-fix behaviour.
    assert hub._effective_module_type("lm-opnsense") == ""
    assert hub._resolve_module_key("lm-opnsense", "",
                                   _UPDATE_SOURCE_PREFIX_MAP) == "opnsense"


def test_in_repo_role_subspoke_offline_resolves_to_lm_repo():
    # dns sub-spoke of the agent; dns code ships inside the lm repo.
    hub = _StubHub(live_types={},
                   persisted_types={"lm-opnsense-dns": "dns"})
    mtype = hub._effective_module_type("lm-opnsense-dns")
    assert mtype == "dns" and mtype in _IN_LM_REPO_MODULE_TYPES
    assert hub._resolve_module_key("lm-opnsense-dns", mtype,
                                   _UPDATE_SOURCE_PREFIX_MAP) == "agent"


def test_live_type_takes_precedence_over_persisted():
    hub = _StubHub(live_types={"lm-opnsense": "agent"},
                   persisted_types={"lm-opnsense": "stale"})
    assert hub._effective_module_type("lm-opnsense") == "agent"


def test_standalone_firewall_spoke_still_resolves_to_opnsense():
    # A dedicated OPNsense spoke (its cwd IS the opnsense checkout) must still
    # resolve to opnsense.git — the fix must not regress the correct case.
    hub = _StubHub(live_types={"lm-opnsense-1": "firewall"}, persisted_types={})
    mtype = hub._effective_module_type("lm-opnsense-1")
    assert mtype == "firewall"
    assert hub._resolve_module_key("lm-opnsense-1", mtype,
                                   _UPDATE_SOURCE_PREFIX_MAP) == "opnsense"
