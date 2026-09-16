"""Role sub-spokes must not be reported as "systemd did not revive".

A generic agent hosts each role as a ``RoleConnection`` sub-spoke named
``{base}-{role}``, all living INSIDE the base agent's single process. A role
therefore has no systemd unit of its own: when its connection drops, systemd
is not involved at all.

The WebUI nevertheless rendered every ``last_status == 'DISCONNECTED'`` spoke
as *"Disconnected (clean exit) — likely self-update restart that systemd did
not revive"*. On the production node ``mipbe-lmagent`` that text was shown for
``SHARED-MIPBE-LMAGENT-DNS`` and ``-DHCP`` while systemd had in fact revived
the agent every single time — ``systemctl show lm-agent`` reported
``Restart=always``, ``RestartUSec=10s``, ``NRestarts=9``, and the unit even
sets ``StartLimitIntervalSec=0`` specifically so it is ALWAYS brought back.
The message sent the operator to the one component that was working.

These pin the hub half: the diagnostics payload must carry the parent agent's
identity and live connection state so the UI can distinguish "the node's
service is dead" from "a role is reloading inside a healthy agent".
"""

import asyncio

from routes import setup_admin

from test_setup_diagnostics_cache import _FakeHub, _reset_diag_cache


class _FakeWS:
    """Stand-in for a live websocket; the payload reads ``.state`` off it."""
    state = "OPEN"


def _spokes_by_id(payload):
    return {s["spoke_id"]: s for s in payload["spokes"]}


def _compute(hub):
    _reset_diag_cache()
    return asyncio.run(setup_admin._maybe_refresh_diagnostics(hub, force=True))


def test_role_subspoke_reports_its_parent_and_that_parent_is_online():
    """The exact production shape: base agent connected, role sub-spoke not."""
    hub = _FakeHub(known=("mipbe-lmagent", "mipbe-lmagent-dns"))
    hub.spoke_parent_map = {"mipbe-lmagent-dns": "mipbe-lmagent"}
    hub.active_connections = {"mipbe-lmagent": _FakeWS()}  # parent up, role down

    rows = _spokes_by_id(_compute(hub))
    dns = rows["mipbe-lmagent-dns"]

    assert dns["authenticated"] is False, "role really is disconnected"
    assert dns["parent_spoke_id"] == "mipbe-lmagent"
    assert dns["parent_online"] is True, (
        "parent agent holds a live connection, so systemd demonstrably did "
        "NOT fail to revive anything")


def test_parent_offline_is_reported_as_such():
    """Whole node genuinely down — the systemd wording stays appropriate."""
    hub = _FakeHub(known=("mipbe-lmagent", "mipbe-lmagent-dns"))
    hub.spoke_parent_map = {"mipbe-lmagent-dns": "mipbe-lmagent"}
    hub.active_connections = {}  # nothing connected

    dns = _spokes_by_id(_compute(hub))["mipbe-lmagent-dns"]

    assert dns["parent_spoke_id"] == "mipbe-lmagent"
    assert dns["parent_online"] is False


def test_top_level_spoke_has_no_parent():
    """An ordinary spoke DOES own a unit, so it must not inherit the softer
    role wording — parent_online must stay False for it."""
    hub = _FakeHub(known=("dns-spoke-1",))
    hub.spoke_parent_map = {}
    hub.active_connections = {}

    row = _spokes_by_id(_compute(hub))["dns-spoke-1"]

    assert row["parent_spoke_id"] is None
    assert row["parent_online"] is False


def test_missing_parent_map_does_not_blank_diagnostics():
    """The diagnostics compute serves STALE on any exception, so a hub without
    spoke_parent_map must degrade to 'no parent', never raise."""
    hub = _FakeHub(known=("s1",))
    assert not hasattr(hub, "spoke_parent_map")

    row = _spokes_by_id(_compute(hub))["s1"]

    assert row["parent_online"] is False
    assert row["parent_spoke_id"] is None
