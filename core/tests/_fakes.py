"""Lightweight test fakes for the hub — minimal stand-ins for ``hub.state`` and
``hub`` used by the unit tests in this directory.

These deliberately implement only the surface the unit tests exercise (the
pure/decision functions extracted from the critical paths). Integration tests
that need a real WebSocket hub + spokes are sketched in the test files as
TODOs and will want a fuller harness (see ``test_relay_contract.py``).
"""

from typing import Any, Dict, Optional


class FakeState:
    """Stand-in for ``hub.state``. Holds ``system_state`` + ``global_config``
    in memory; ``save_state`` is a no-op (tests assert on the in-memory dict)."""

    def __init__(self, system_state: Optional[dict] = None,
                 global_config: Optional[dict] = None,
                 tenants: Optional[Dict[str, dict]] = None):
        self.system_state = system_state or {}
        self._global_config = global_config or {}
        self._tenants = tenants or {}
        # The sync mixins read ``self.state.tenant_state["tenants"]``; reflect
        # the constructor tenants so tests that exercise tenant scoping work
        # without per-test patching.
        self.tenant_state = {"tenants": self._tenants}

    def get_global_config(self) -> dict:
        return self._global_config

    def update_global_config(self, patch: Dict[str, Any]) -> None:
        self._global_config.update(patch)

    def save_state(self) -> None:
        pass

    def get_tenant(self, tid: str) -> Optional[dict]:
        return self._tenants.get(tid)


class FakeHub:
    """Stand-in for the Hub. ``get_spoke_by_type`` returns None by default
    (no spokes connected) — tests override per-test as needed."""

    def __init__(self, state: Optional[FakeState] = None):
        self.state = state or FakeState()

    def get_spoke_by_type(self, module_type: str) -> Optional[str]:
        return None