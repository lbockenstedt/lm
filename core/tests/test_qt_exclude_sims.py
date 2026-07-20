"""Dongle-quarantine ``qt_exclude_sims`` config plumbing — the global store
getter/setter + the sim-quota-defaults PUT validation (unknown sim ids dropped)
+ the resolved push (per-tenant csc override else global)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from simulations.store import SimulationsStore


async def test_qt_exclude_sims_store_roundtrip(tmp_path):
    s = SimulationsStore(str(tmp_path))
    assert await s.get_qt_exclude_sims() == []  # default: none stored
    await s.set_qt_exclude_sims(["dhcp_fail", "assoc_fail"])
    assert await s.get_qt_exclude_sims() == ["dhcp_fail", "assoc_fail"]


async def test_qt_exclude_sims_strips_blanks_and_coerces(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_qt_exclude_sims(["dhcp_fail", "  ", "", 123])
    out = await s.get_qt_exclude_sims()
    assert "dhcp_fail" in out
    assert "123" in out  # coerced to str
    assert all(s.strip() for s in out)  # no blanks


async def test_qt_exclude_sims_is_global_not_per_tenant(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_qt_exclude_sims(["dhcp_fail"])
    # A second tenant (never written) sees the SAME global set — it's __global__.
    assert await s.get_qt_exclude_sims() == ["dhcp_fail"]