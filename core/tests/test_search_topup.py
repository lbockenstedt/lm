"""topup_cold_legs: per-leg timeouts, error rows kept, degraded reporting."""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from search_index import topup_cold_legs  # noqa: E402

DASHBOARD_PY = Path(__file__).resolve().parents[1] / "src" / "routes" / "dashboard.py"
MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"

NB = ("nb-spoke", "NETBOX_SEARCH")
VM = ("vm-spoke", "SEARCH_VMS")
US = ("us-spoke", "SEARCH_USERS")


def _stub(table):
    async def call(spoke, cmd):
        v = table[cmd]
        if callable(v):
            return await v()
        return v
    return call


async def test_all_legs_answer():
    call = _stub({
        "NETBOX_SEARCH": [{"source": "netbox", "name": "a"}],
        "SEARCH_VMS": [{"source": "pxmx", "name": "b"}],
    })
    rows, degraded = await topup_cold_legs([NB, VM], call, timeout=1.0)
    assert {r["name"] for r in rows} == {"a", "b"}
    assert degraded == []


async def test_slow_leg_does_not_discard_others():
    async def slow():
        await asyncio.sleep(1.0)
        return [{"name": "slow"}]

    call = _stub({
        "NETBOX_SEARCH": slow,
        "SEARCH_VMS": [{"name": "vm"}],
        "SEARCH_USERS": [{"name": "user"}],
    })
    rows, degraded = await topup_cold_legs([NB, VM, US], call, timeout=0.05)
    names = {r["name"] for r in rows}
    assert "slow" not in names
    assert names == {"vm", "user"}
    assert degraded == ["NETBOX_SEARCH"]


async def test_raising_leg_is_degraded_others_returned():
    async def boom():
        raise RuntimeError("nope")

    call = _stub({"NETBOX_SEARCH": boom, "SEARCH_VMS": [{"name": "vm"}]})
    rows, degraded = await topup_cold_legs([NB, VM], call, timeout=1.0)
    assert [r["name"] for r in rows] == ["vm"]
    assert degraded == ["NETBOX_SEARCH"]


async def test_error_row_kept_and_leg_degraded():
    err = {"source": "NETBOX_SEARCH", "type": "error", "name": "boom"}
    call = _stub({"NETBOX_SEARCH": [err], "SEARCH_VMS": [{"name": "vm"}]})
    rows, degraded = await topup_cold_legs([NB, VM], call, timeout=1.0)
    assert err in rows
    assert {"name": "vm"} in rows
    assert degraded == ["NETBOX_SEARCH"]


async def test_empty_cold_and_non_list_result():
    assert await topup_cold_legs([], _stub({})) == ([], [])
    call = _stub({"NETBOX_SEARCH": None, "SEARCH_VMS": {"not": "a list"}})
    rows, degraded = await topup_cold_legs([NB, VM], call, timeout=1.0)
    assert rows == []
    assert degraded == []


async def test_legs_run_concurrently():
    async def nap():
        await asyncio.sleep(0.2)
        return [{"name": "x"}]

    call = _stub({"NETBOX_SEARCH": nap, "SEARCH_VMS": nap})
    t0 = time.monotonic()
    rows, degraded = await topup_cold_legs([NB, VM], call, timeout=1.0)
    assert time.monotonic() - t0 < 0.35
    assert len(rows) == 2 and degraded == []


def test_handle_search_reports_degraded_legs():
    src = MAIN_JS.read_text(encoding="utf-8")
    start = src.index("function handleSearch(")
    end = src.index("const more = d.total > 12", start)
    body = src[start:end + 400]
    assert "d.degraded" in body
    assert "NETBOX_SEARCH" in body


def test_dashboard_uses_topup_and_keeps_error_rows():
    src = DASHBOARD_PY.read_text(encoding="utf-8")
    assert "topup_cold_legs" in src
    start = src.index("NetBox is never warm")
    end = src.index("Nothing in memory", start)
    block = src[start:end]
    assert 'r.get("type") != "error"' not in block
    assert "topup_cold_legs(" in block
