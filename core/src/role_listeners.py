"""Roles that bind an inbound listener, and the host port each one claims.

Two of these CANNOT be stacked on one VM: whichever loads first wins the port
and the others fail to bind. The failure is silent — the loser just logs
EADDRINUSE and retries forever — so the box keeps answering on the wrong
service and looks healthy.

That is not hypothetical. On a live box the ``proxmox`` role's agent listener
bound ``wss://0.0.0.0:443`` two seconds before the ``proxy`` role loaded; the
edge proxy never got the port, and every browser request to the tenant WebUI
was answered by the agent listener with a bare ``OK``.

Who binds what:

* ``proxmox``    — the ``/ws/agent`` listener. ``AGENT_WSS_PORT`` defaults to
  443 (``messaging/agent_hosting.py``) and ``_agent_listener_enabled()``
  (``agent/src/control_plane.py``) is unconditionally true for proxmox.
* ``simulation`` — the same listener, with ``AGENT_WSS_PORT`` pointed at 443.
* ``proxy``      — the edge proxy's browser-facing :443 listener.
* ``statuspage`` — serves its own public HTTPS status page, ``web_port``
  defaulting to 443 (``statuspage/src/statuspage_spoke.py``).

Roles absent from this table (dns, dhcp, ldap, netbox, le, cppm, ...) bind
nothing and stack freely, including alongside one listener role.

Ports here are the DEFAULTS. Some roles can be pointed at another port
(``LM_STATUS_PORT``, ``AGENT_WSS_PORT``), but the table deliberately reflects
what a stock install actually does — an operator stacking two of these gets a
broken box unless they also went out of their way to re-port one of them.

Mirrored in the WebUI as ``ROLE_LISTENER_PORTS`` (``WebUI/main.js``) so the
broken combination is never offered; the checks here are the authoritative ones.
"""

LISTENER_PORT_ROLES = {
    "proxmox": 443,
    "simulation": 443,
    "proxy": 443,
    "statuspage": 443,
}


def listener_conflict(existing_roles, candidate):
    """The role in ``existing_roles`` that would fight ``candidate`` for a port.

    Returns the conflicting role name, or ``None`` when there is none. A role
    never conflicts with itself — re-loading an already-loaded role is an
    idempotent upgrade, not a collision."""
    port = LISTENER_PORT_ROLES.get(candidate)
    if port is None:
        return None
    for other in existing_roles or ():
        if other != candidate and LISTENER_PORT_ROLES.get(other) == port:
            return other
    return None


def listener_conflict_message(spoke_id, candidate, other):
    """Operator-facing explanation of why ``candidate`` was refused."""
    port = LISTENER_PORT_ROLES.get(candidate, 443)
    return (
        f"Cannot load role '{candidate}' on {spoke_id}: role '{other}' is already "
        f"loaded there and both bind port {port} on this host. Only one listener "
        f"can own a port, so whichever starts first wins and the other silently "
        f"fails to bind — leaving the box answering on the wrong service. Put "
        f"'{candidate}' on a separate VM, or unload '{other}' first."
    )
