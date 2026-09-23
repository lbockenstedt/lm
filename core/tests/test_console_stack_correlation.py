"""Hub-side VSF stack correlation for ``/api/console/ports``.

A stack is one logical switch spread over several chassis, and those chassis are
frequently cabled to DIFFERENT console servers. A console spoke only ever sees
its own serial lines, so it can report "my conductor's MAC is X" but cannot say
which port reaches it. ``_correlate_stacks`` is the one place that holds every
port the caller may see, so the conductor lookup has to happen there.

These lock in:

* a standby member is pointed at the conductor's port, even on another spoke;
* correlation never leaks a port the requester couldn't already see;
* the shared warm-cache port dicts are not mutated in place;
* non-stacked and unidentified ports are left completely alone.
"""
from routes.console import _correlate_stacks


def _port(spoke, pid, mac="", stack=None, alias="", hostname=""):
    identity = {}
    if mac:
        identity["mac"] = mac
    if hostname:
        identity["hostname"] = hostname
    probe = {"identity": identity}
    if stack:
        probe["stack"] = stack
    return {"spoke_id": spoke, "port_id": pid, "alias": alias, "probe": probe}


_STANDBY_STACK = {
    "is_stack": True, "role": "standby", "member_id": 2, "topology": "",
    "stack_mac": "", "local_mac": "34:c5:15:9b:52:00",
    "conductor_mac": "8c:85:c1:4b:c7:80", "sw_version": "FL.10.13.1000",
    "members": [
        {"member_id": 1, "mac": "8c:85:c1:4b:c7:80", "model": "JL662A",
         "role": "conductor", "present": True},
        {"member_id": 2, "mac": "34:c5:15:9b:52:00", "model": "JL666A",
         "role": "standby", "present": True},
    ],
}

_CONDUCTOR_STACK = dict(_STANDBY_STACK, role="conductor", member_id=1,
                        topology="Ring", stack_mac="8c:85:c1:4b:c7:80",
                        local_mac="8c:85:c1:4b:c7:80")


def test_standby_is_pointed_at_the_conductor_on_another_spoke():
    """The whole point: the two chassis hang off different console agents, so
    only the hub can join "conductor_mac" to a console port."""
    standby = _port("spokeB", "ttyUSB9", stack=dict(_STANDBY_STACK))
    conductor = _port("spokeA", "ttyUSB0", mac="8c:85:c1:4b:c7:80",
                      stack=dict(_CONDUCTOR_STACK), hostname="BO-SYDm-ACSW01")
    ports = [standby, conductor]

    _correlate_stacks(ports)

    st = standby["probe"]["stack"]
    assert st["is_conductor"] is False
    assert st["conductor_port_id"] == "ttyUSB0"
    assert st["conductor_spoke_id"] == "spokeA"
    assert st["conductor_hostname"] == "BO-SYDm-ACSW01"


def test_conductor_marks_itself_and_does_not_link_to_itself():
    conductor = _port("spokeA", "ttyUSB0", mac="8c:85:c1:4b:c7:80",
                      stack=dict(_CONDUCTOR_STACK), hostname="BO-SYDm-ACSW01")
    _correlate_stacks([conductor])

    st = conductor["probe"]["stack"]
    assert st["is_conductor"] is True
    assert "conductor_port_id" not in st


def test_members_of_one_stack_share_a_stack_id():
    """Gives the UI a stable key to group a stack's chassis together."""
    standby = _port("spokeB", "ttyUSB9", stack=dict(_STANDBY_STACK))
    conductor = _port("spokeA", "ttyUSB0", mac="8c:85:c1:4b:c7:80",
                      stack=dict(_CONDUCTOR_STACK))
    _correlate_stacks([standby, conductor])

    assert standby["probe"]["stack"]["stack_id"] == "8c:85:c1:4b:c7:80"
    assert conductor["probe"]["stack"]["stack_id"] == "8c:85:c1:4b:c7:80"


def test_conductor_outside_the_callers_visibility_is_not_revealed():
    """``ports`` is already tenant-filtered, so a conductor the caller can't see
    simply isn't there — correlation must not invent a pointer to it."""
    standby = _port("spokeB", "ttyUSB9", stack=dict(_STANDBY_STACK))
    _correlate_stacks([standby])

    st = standby["probe"]["stack"]
    assert "conductor_port_id" not in st
    assert st["conductor_mac"] == "8c:85:c1:4b:c7:80"  # still reported as unknown-location


def test_the_shared_warm_cache_dicts_are_not_mutated():
    """Port dicts are shallow copies of warm-cache entries reused across
    requests; writing correlation results through would corrupt the cache."""
    cached_stack = dict(_STANDBY_STACK)
    cached_probe = {"identity": {}, "stack": cached_stack}
    standby = {"spoke_id": "spokeB", "port_id": "ttyUSB9", "probe": cached_probe}
    conductor = _port("spokeA", "ttyUSB0", mac="8c:85:c1:4b:c7:80",
                      stack=dict(_CONDUCTOR_STACK))

    _correlate_stacks([standby, conductor])

    assert "conductor_port_id" not in cached_stack
    assert "is_conductor" not in cached_stack
    assert cached_probe["stack"] is cached_stack
    assert standby["probe"]["stack"]["conductor_port_id"] == "ttyUSB0"


def test_ports_without_a_stack_are_untouched():
    plain = _port("spokeA", "ttyUSB1", mac="aa:bb:cc:dd:ee:ff", hostname="edge-sw")
    bare = {"spoke_id": "spokeA", "port_id": "ttyUSB2"}
    standalone = _port("spokeA", "ttyUSB3", stack={"is_stack": False, "role": "conductor"})

    _correlate_stacks([plain, bare, standalone])

    assert "stack" not in plain["probe"]
    assert bare == {"spoke_id": "spokeA", "port_id": "ttyUSB2"}
    assert standalone["probe"]["stack"] == {"is_stack": False, "role": "conductor"}


def test_alias_wins_over_hostname_for_the_conductor_label():
    """An operator-set alias is what they named the rack position; show that."""
    standby = _port("spokeB", "ttyUSB9", stack=dict(_STANDBY_STACK))
    conductor = _port("spokeA", "ttyUSB0", mac="8c:85:c1:4b:c7:80",
                      stack=dict(_CONDUCTOR_STACK), alias="Rack 4 top",
                      hostname="BO-SYDm-ACSW01")
    _correlate_stacks([standby, conductor])

    assert standby["probe"]["stack"]["conductor_hostname"] == "Rack 4 top"


def test_conductor_found_via_its_stack_local_mac():
    """A conductor whose `show system` was rejected still knows its own member
    MAC from `show vsf`, so the join must consider that too."""
    standby = _port("spokeB", "ttyUSB9", stack=dict(_STANDBY_STACK))
    conductor = _port("spokeA", "ttyUSB0", stack=dict(_CONDUCTOR_STACK))
    _correlate_stacks([standby, conductor])

    assert standby["probe"]["stack"]["conductor_port_id"] == "ttyUSB0"
