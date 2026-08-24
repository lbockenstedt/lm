"""Per-client Sim Health cross-check adapter (Fleet Health metric 2 wiring)."""
import sys
import time
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "simulations"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sim_health_trend import SimHealthTrend  # noqa: E402
import sim_health_crosscheck as xc  # noqa: E402

T = "tenant-a"


def _trend(tmp_path):
    return SimHealthTrend(str(tmp_path), window_s=3600.0)


def test_norm_mac_strips_separators_and_case():
    assert xc.norm_mac("AA:BB:CC:11:22:33") == "aabbcc112233"
    assert xc.norm_mac("aa-bb-cc-11-22-33") == "aabbcc112233"
    assert xc.norm_mac("aabbcc112233") == "aabbcc112233"


def test_norm_mac_rejects_placeholders():
    assert xc.norm_mac("—") == ""
    assert xc.norm_mac("") == ""
    assert xc.norm_mac(None) == ""


def test_expects_failing_by_active_sims():
    assert xc.expects_failing({"active_simulations": ["auth_fail", "download"]}) is True
    assert xc.expects_failing({"active_simulations": ["download", "iperf"]}) is False


def test_expects_failing_by_pinned_sim():
    assert xc.expects_failing({"simulation_id": "port_flap"}) is True
    assert xc.expects_failing({"simulation_id": "www_traffic"}) is False


def _client(mac, sims, adapters=None):
    c = {"mac": mac, "active_simulations": sims}
    if adapters is not None:
        c["adapters"] = adapters
    return c


def test_traffic_client_present_is_working(tmp_path):
    tr = _trend(tmp_path)
    now = time.time()
    clients = [_client("aa:bb:cc:00:00:01", ["download"])]
    r = xc.observe_clients(tr, T, clients,
                           present_macs=["AABBCC000001"], failing_macs=[], now=now)
    assert r["total"] == 1 and r["working"] == 1


def test_traffic_client_absent_ages_out(tmp_path):
    tr = _trend(tmp_path)
    now = time.time()
    clients = [_client("aa:bb:cc:00:00:02", ["download"])]
    # first seen long ago, never present -> past grace -> not working
    xc.observe_clients(tr, T, clients, present_macs=[], failing_macs=[], now=now - 4000)
    r = xc.observe_clients(tr, T, clients, present_macs=[], failing_macs=[], now=now)
    assert r["working"] == 0 and r["status"] == "critical"


def test_failure_client_in_failed_list_is_working(tmp_path):
    tr = _trend(tmp_path)
    now = time.time()
    clients = [_client("aa:bb:cc:00:00:03", ["auth_fail"])]
    # A failure-sim client is WORKING when it's in the failed list — even though
    # it is NOT in the connected-client (present) list.
    r = xc.observe_clients(tr, T, clients,
                           present_macs=[], failing_macs=["aa-bb-cc-00-00-03"], now=now)
    assert r["total"] == 1 and r["working"] == 1


def test_failure_client_not_scored_against_present(tmp_path):
    # Being present as a healthy connected client does NOT count a failure sim as
    # working (that would be the old gateway-style false positive inverted).
    tr = _trend(tmp_path)
    now = time.time()
    clients = [_client("aa:bb:cc:00:00:04", ["assoc_fail"])]
    xc.observe_clients(tr, T, clients,
                       present_macs=["aa:bb:cc:00:00:04"], failing_macs=[], now=now - 4000)
    r = xc.observe_clients(tr, T, clients,
                           present_macs=["aa:bb:cc:00:00:04"], failing_macs=[], now=now)
    assert r["working"] == 0


def test_failure_client_intermittent_stays_working(tmp_path):
    # Central drops the failed entry most cycles; one hit inside the window keeps
    # it working (the whole reason for the trend).
    tr = _trend(tmp_path)
    now = time.time()
    clients = [_client("aa:bb:cc:00:00:05", ["dns_fail"])]
    xc.observe_clients(tr, T, clients, present_macs=[],
                       failing_macs=["aabbcc000005"], now=now - 3000)   # confirmed once
    for i in range(10):
        xc.observe_clients(tr, T, clients, present_macs=[],
                           failing_macs=[], now=now - 2400 + i * 60)    # then nothing
    r = xc.observe_clients(tr, T, clients, present_macs=[], failing_macs=[], now=now)
    assert r["working"] == 1


def test_matches_on_adapter_mac(tmp_path):
    tr = _trend(tmp_path)
    now = time.time()
    clients = [_client("—", ["download"],
                       adapters=[{"mac": "aa:bb:cc:00:00:06", "name": "wlan0"}])]
    r = xc.observe_clients(tr, T, clients,
                           present_macs=["aabbcc000006"], failing_macs=[], now=now)
    assert r["total"] == 1 and r["working"] == 1


def test_clients_without_sims_or_mac_are_skipped(tmp_path):
    tr = _trend(tmp_path)
    now = time.time()
    clients = [
        {"mac": "aa:bb:cc:00:00:07", "active_simulations": []},   # no sim
        {"mac": "—", "active_simulations": ["download"]},          # no usable mac
    ]
    r = xc.observe_clients(tr, T, clients, present_macs=[], failing_macs=[], now=now)
    assert r["status"] == "no_data" and r["total"] == 0


def test_mixed_fleet_rollup(tmp_path):
    tr = _trend(tmp_path)
    now = time.time()
    clients = [
        _client("aa:00:00:00:00:01", ["download"]),      # traffic, present -> working
        _client("aa:00:00:00:00:02", ["auth_fail"]),     # failure, in failed -> working
        _client("aa:00:00:00:00:03", ["port_flap"]),     # failure, NOT failing -> broken
    ]
    # age the broken one past grace
    xc.observe_clients(tr, T, clients,
                       present_macs=["aa:00:00:00:00:01"],
                       failing_macs=["aa:00:00:00:00:02"], now=now - 4000)
    r = xc.observe_clients(tr, T, clients,
                           present_macs=["aa:00:00:00:00:01"],
                           failing_macs=["aa:00:00:00:00:02"], now=now)
    assert r["total"] == 3 and r["working"] == 2
    assert r["pct"] == round(200 / 3, 1)
