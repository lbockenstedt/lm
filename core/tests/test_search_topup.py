"""topup_cold_legs: per-leg timeouts, error rows kept, degraded reporting."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from search_index import topup_cold_legs  # noqa: E402
from webui_src import main_js_source

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
    """Both legs are in flight at once. Each leg waits until the other has
    started, so the test has no sleep and no wall-clock pass bound (fleet
    rule 9.4). One leg after the other would peak at 1: the first leg would
    wait out its timeout and both would come back degraded."""
    legs = {"now": 0, "max": 0}
    both_started = asyncio.Event()

    async def leg():
        """Count this leg in flight and wait until the other leg has started."""
        legs["now"] += 1
        try:
            legs["max"] = max(legs["max"], legs["now"])
            if legs["now"] == 2:
                both_started.set()
            await both_started.wait()
        finally:
            legs["now"] -= 1
        return [{"name": "x"}]

    call = _stub({"NETBOX_SEARCH": leg, "SEARCH_VMS": leg})
    # The timeout only bounds a broken (serial) run; a passing run never
    # waits on the clock.
    rows, degraded = await topup_cold_legs([NB, VM], call, timeout=5.0)
    assert legs["max"] == 2
    assert len(rows) == 2 and degraded == []


def test_handle_search_reports_degraded_legs():
    src = main_js_source()
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
