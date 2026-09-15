"""Reconnect re-adoption must SKIP deploy roles (hub side).

Deploy roles (``dns-server``, ``dhcp-server``, ``netbox-server``,
``ldap-server``, ``ab``) are INSTALLS, not hosted sub-spokes: loading one runs
an external installer on the agent host, and the software it stands up runs as
a system service or dials the hub under its OWN spoke_id. The
``{agent}-{role}`` sub-spoke a hosted role creates NEVER appears.

``_readopt_agent_roles`` decided a role needed re-pushing when
``{agent}-{role}`` was not connected — permanently true for a deploy role. So
every agent reconnect (i.e. every reboot) re-pushed LOAD_ROLE and re-ran the
installer. Field report: SHARED-MIPBE-SVCS02 reinstalled Kea and Unbound on
every reboot and sat at "deploying…" forever.

Hosted roles must still be re-adopted — that self-healing is the whole point of
the loop, and regressing it re-opens the "console vanished" outage.
"""
import asyncio

from test_agent_role_registry_readopt import _ReadoptHub

from role_listeners import DEPLOY_ROLES, is_deploy_role


def _readopt(hub, agent):
    asyncio.run(hub._readopt_agent_roles(agent))


def test_deploy_roles_are_never_re_pushed():
    """The reboot-reinstall loop."""
    hub = _ReadoptHub()
    for role in ("dns-server", "dhcp-server", "netbox-server"):
        hub._record_agent_role("mipbe-svcs02", role)

    _readopt(hub, "mipbe-svcs02")

    assert hub.load_role_calls == [], \
        f"deploy roles were re-pushed on reconnect: {hub.load_role_calls}"


def test_every_known_deploy_role_is_skipped():
    hub = _ReadoptHub()
    for role in sorted(DEPLOY_ROLES):
        hub._record_agent_role("agent-x", role)

    _readopt(hub, "agent-x")

    assert hub.load_role_calls == [], hub.load_role_calls


def test_hosted_roles_are_still_re_adopted():
    """Not vacuous — the self-healing this loop exists for must survive."""
    hub = _ReadoptHub()
    hub._record_agent_role("agent-x", "console")
    hub._record_agent_role("agent-x", "dns")

    _readopt(hub, "agent-x")

    assert sorted(r for _, r in hub.load_role_calls) == ["console", "dns"], \
        hub.load_role_calls


def test_mixed_agent_re_adopts_only_the_hosted_roles():
    """The real MIPBE shape: a management role alongside its server install.
    'dns' (hosted module) heals; 'dns-server' (install) does not."""
    hub = _ReadoptHub()
    for role in ("dns", "dns-server", "dhcp", "dhcp-server", "netbox-server"):
        hub._record_agent_role("mipbe-svcs02", role)

    _readopt(hub, "mipbe-svcs02")

    assert sorted(r for _, r in hub.load_role_calls) == ["dhcp", "dns"], \
        hub.load_role_calls


def test_live_hosted_sub_spoke_is_still_skipped():
    """Pre-existing behaviour kept: a role already running is not re-pushed."""
    hub = _ReadoptHub()
    hub._record_agent_role("agent-x", "console")
    hub.active_connections["agent-x-console"] = object()

    _readopt(hub, "agent-x")

    assert hub.load_role_calls == [], hub.load_role_calls


def test_deploy_role_names_match_the_agent_side_table():
    """``role_listeners.DEPLOY_ROLES`` mirrors the agent's ``_DEPLOY_ROLES``;
    drift would silently re-open the reinstall loop for the missing role."""
    import os
    import sys
    agent_src = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "agent", "src"))
    if agent_src not in sys.path:
        sys.path.insert(0, agent_src)
    import agent_spoke

    assert set(agent_spoke._DEPLOY_ROLES) == set(DEPLOY_ROLES), (
        "role_listeners.DEPLOY_ROLES has drifted from agent_spoke._DEPLOY_ROLES: "
        f"{set(agent_spoke._DEPLOY_ROLES) ^ set(DEPLOY_ROLES)}")


def test_is_deploy_role_predicate():
    assert is_deploy_role("netbox-server")
    assert is_deploy_role("dhcp-server")
    assert not is_deploy_role("dhcp")
    assert not is_deploy_role("console")
    assert not is_deploy_role(None)
