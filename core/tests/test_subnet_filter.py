"""Critical path 1/4 — tenant subnet filter (server-side tenant isolation gate).

The toggle ↔ backend ↔ filter read-path wiring is the security boundary that
stops one tenant seeing another's subnet-scoped data. These tests lock in the
resolution semantics of ``access.subnet_filter_config`` / ``subnet_filter_enabled``
— the single source of truth every server-side filter reads
(``subnet_filter_enabled`` → ``subnet_filter_config`` → ``system_state["subnet_filter_modules"]``
merged with the defaults). The actual prefix-matching lives in
``simulations/tenant_filter.py`` and is exercised by an integration test (TODO).
"""

from access import (
    subnet_filter_config,
    subnet_filter_enabled,
    _SUBNET_FILTER_MODULES,
    _SUBNET_FILTER_DEFAULTS,
)
from _fakes import FakeHub, FakeState


def test_defaults_when_no_stored_state():
    """No stored overrides → every module resolves to its documented default
    (nac/firewall/netbox/dhcp ON, cs OFF — cs is tenant-ID-scoped, not subnet)."""
    hub = FakeHub(FakeState(system_state={}))
    cfg = subnet_filter_config(hub)
    assert set(cfg) == set(_SUBNET_FILTER_MODULES)
    for m in _SUBNET_FILTER_MODULES:
        assert cfg[m] == _SUBNET_FILTER_DEFAULTS[m]


def test_stored_override_flips_a_module():
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"cs": True, "firewall": False}}))
    cfg = subnet_filter_config(hub)
    assert cfg["cs"] is True           # override ON (default OFF)
    assert cfg["firewall"] is False    # override OFF (default ON)
    # untouched modules keep their defaults
    assert cfg["nac"] is _SUBNET_FILTER_DEFAULTS["nac"]
    assert cfg["netbox"] is _SUBNET_FILTER_DEFAULTS["netbox"]
    assert cfg["dhcp"] is _SUBNET_FILTER_DEFAULTS["dhcp"]


def test_subnet_filter_enabled_per_module_and_unknown():
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"dhcp": False}}))
    assert subnet_filter_enabled(hub, "dhcp") is False   # overridden off
    assert subnet_filter_enabled(hub, "nac") is True      # default on
    assert subnet_filter_enabled(hub, "cs") is False      # default off
    assert subnet_filter_enabled(hub, "nonexistent") is False  # unknown module → False


def test_stored_values_are_coerced_to_bool():
    """``subnet_filter_config`` bool-coerces stored values (the PUT handler
    stores real bools, but the reader must tolerate any JSON-ish value)."""
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"nac": 0, "firewall": 1}}))
    cfg = subnet_filter_config(hub)
    assert cfg["nac"] is False
    assert cfg["firewall"] is True