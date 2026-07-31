"""A relayed CS_* event must land on the spoke the agent actually dials.

Field regression: four pxmx hosts, each dialing its OWN cs spoke, but every
agent's telemetry was delivered to get_client_sim_spoke(tenant_id) — a SINGLE
spoke per tenant. So one spoke held telemetry for all four hosts while the other
three held none.

That is not just misfiling. sim-tag dispatch needs a DIRECT agent connection, so
the receiving spoke had data for hosts it could not command, and their own spokes
could command them but had no data — only the one host whose agent dialed the
receiving spoke was ever tagged. It also cross-contaminated the VM lists (one
host's VMs appearing under another's entry).
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from hub_spoke_registry import SpokeRegistryMixin  # noqa: E402


class _Reg(SpokeRegistryMixin):
    """Minimal stand-in exercising only the spoke-type/approval lookups."""
    def __init__(self, by_type, approved):
        self._by_type = by_type
        self.approved_modules = approved

    def get_all_spokes_by_type(self, t):
        return list(self._by_type.get(t, []))

    def _primary_key(self, sid):
        return sid


def _reg():
    return _Reg({"Client-Sim": ["cs-01", "cs-02", "cs-03", "cs-04"]},
                {s: True for s in ("cs-01", "cs-02", "cs-03", "cs-04")})


def test_each_cs_spoke_is_recognised_as_its_agents_home():
    r = _reg()
    for sid in ("cs-01", "cs-02", "cs-03", "cs-04"):
        assert r._is_client_sim_spoke(sid), sid


def test_a_pxmx_spoke_is_not_a_cs_home():
    # A pxmx-dialed agent must still fall back to the tenant's cs spoke — a pxmx
    # spoke cannot ingest CS_* commands.
    r = _reg()
    assert not r._is_client_sim_spoke("pxmx-01")


def test_unapproved_cs_spoke_is_not_a_home():
    # Unapproved spokes drop telemetry frames, so routing there would black-hole
    # the event instead of falling back.
    r = _Reg({"Client-Sim": ["cs-09"]}, {"cs-09": False})
    assert not r._is_client_sim_spoke("cs-09")


def test_legacy_simulation_type_still_counts():
    r = _Reg({"simulation": ["cs-legacy"]}, {"cs-legacy": True})
    assert r._is_client_sim_spoke("cs-legacy")


def test_empty_spoke_id_is_not_a_home():
    assert not _reg()._is_client_sim_spoke("")
    assert not _reg()._is_client_sim_spoke(None)
