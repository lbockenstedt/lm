"""Day/week/month retention window for per-destination query stats, query
logging enabled on every sync, structured query-logging results, and the
``query_logging`` diagnostics block — ported from the deprecated standalone
dns repo (6fdcba3, 852ae2a, b39fe16) into the live lm copy."""

import asyncio
import os
import time

import unbound_manager as um_mod
from dns_spoke import DNSSpoke
from dns_worker import DnsWorkerOps
from unbound_manager import UnboundManager

DAY = 86400
UNCHANGED = {"status": "unchanged", "changed": False, "restarted": False,
             "ok": True, "reason": "already-enabled"}


def _mgr(tmp_path):
    return UnboundManager(conf_path=str(tmp_path / "conf.d" / "lm-netbox.conf"))


def _today():
    return int(time.time() // DAY)


def test_range_days_sums_only_the_trailing_window(tmp_path):
    mgr = _mgr(tmp_path)
    today = _today()
    mgr._query_counts = {
        "a.example.com|A|10.0.0.1": {today: 2, today - 3: 5, today - 20: 7},
        "b.example.com|A|10.0.0.1": {today - 10: 4},
    }
    day = {r["name"]: r["count"] for r in mgr.get_query_names(range_days=1)}
    week = {r["name"]: r["count"] for r in mgr.get_query_names(range_days=7)}
    month = {r["name"]: r["count"] for r in mgr.get_query_names(range_days=30)}
    everything = {r["name"]: r["count"] for r in mgr.get_query_names()}
    assert day == {"a.example.com": 2}
    assert week == {"a.example.com": 7}
    assert month == {"a.example.com": 14, "b.example.com": 4}
    assert everything == month


def test_buckets_older_than_retention_are_pruned(tmp_path):
    mgr = _mgr(tmp_path)
    today = _today()
    old = today - um_mod.MAX_RETENTION_DAYS
    mgr._query_counts = {
        "a.example.com|A|10.0.0.1": {today: 1, old: 9},
        "gone.example.com|A|10.0.0.1": {old: 3},
    }
    mgr._prune_query_counts()
    assert mgr._query_counts == {"a.example.com|A|10.0.0.1": {today: 1}}


def test_legacy_int_counts_are_migrated_not_crashed(tmp_path):
    """Pre-bucketing state held a bare lifetime int per key; it must keep
    counting (folded into today's bucket) rather than raise."""
    mgr = _mgr(tmp_path)
    mgr._query_counts = {"legacy.example.com|A|10.0.0.1": 4}
    os.makedirs(os.path.dirname(um_mod.QUERY_LOG), exist_ok=True)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("info: 10.0.0.1 legacy.example.com. A IN\n")
    rows = mgr.get_query_names(range_days=1)
    assert rows[0]["name"] == "legacy.example.com"
    assert rows[0]["count"] == 5
    assert mgr._query_counts["legacy.example.com|A|10.0.0.1"] == {_today(): 5}


def test_tail_writes_into_todays_bucket(tmp_path):
    mgr = _mgr(tmp_path)
    os.makedirs(os.path.dirname(um_mod.QUERY_LOG), exist_ok=True)
    with open(um_mod.QUERY_LOG, "w") as f:
        f.write("info: 10.0.0.1 x.example.com. A IN\n" * 3)
    mgr._tail_query_log()
    assert mgr._query_counts == {"x.example.com|A|10.0.0.1": {_today(): 3}}


def test_get_stats_threads_range_days_to_query_names(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    seen = {}
    monkeypatch.setattr(mgr, "_ensure_query_logging", lambda: UNCHANGED)
    monkeypatch.setattr(mgr, "get_query_names",
                        lambda **kw: seen.update(kw) or [])
    monkeypatch.setattr(
        "unbound_manager.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    out = mgr.get_stats(range_days=7)
    assert out["status"] == "SUCCESS"
    assert seen["range_days"] == 7
    assert "warning" not in out


def test_worker_stats_passes_range_days_through():
    calls = []

    class Mgr:
        def get_stats(self, search=None, source_prefixes=None, range_days=None):
            calls.append((search, source_prefixes, range_days))
            return {"status": "SUCCESS"}

    ops = DnsWorkerOps.__new__(DnsWorkerOps)
    ops.mgr = Mgr()
    ops.stats({"search": "x", "source_prefixes": ["10.0.0.0/8"], "range_days": 30})
    assert calls == [("x", ["10.0.0.0/8"], 30)]


def test_cluster_stats_forwards_range_days_to_every_member():
    sent = []

    class Transport:
        async def fanout(self, op, payload, timeout=None):
            sent.append((op, payload))
            return {"results": {}}

    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke._transport = Transport()
    asyncio.run(spoke._cluster_stats(range_days=7))
    asyncio.run(spoke._cluster_stats())
    assert sent[0] == ("DNSW_STATS", {"range_days": 7})
    assert "range_days" not in sent[1][1]


def test_sync_ensures_query_logging_then_reloads(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    order = []
    monkeypatch.setattr(mgr, "_ensure_query_logging",
                        lambda: order.append("logging") or UNCHANGED)
    monkeypatch.setattr(mgr, "_reload",
                        lambda: order.append("reload") or {"ok": True, "error": ""})
    out = mgr.sync([{"name": "a.example.com", "type": "A", "value": "10.0.1.5"}])
    assert out["status"] == "SUCCESS"
    assert order == ["logging", "reload"]


def test_missing_logfile_forces_one_restart_per_process(tmp_path, monkeypatch):
    """lm-specific: a correct-but-inert logging conf (unbound never restarted
    since it was written) must still force a restart, but only once per
    process so a host whose logfile never appears is not restarted on every
    NetBox sync."""
    mgr = _mgr(tmp_path)
    want = (f'server:\n    log-queries: yes\n'
            f'    use-syslog: no\n    logfile: "{um_mod.QUERY_LOG}"\n')
    with open(um_mod.LOGGING_CONF, "w") as f:
        f.write(want)
    restarts = []
    monkeypatch.setattr(mgr, "_restart_unbound",
                        lambda reason: restarts.append(reason) or {"ok": True, "error": ""})
    first = mgr._ensure_query_logging()
    second = mgr._ensure_query_logging()
    assert first["restarted"] is True and first["reason"] == "logfile-missing"
    assert second == UNCHANGED
    assert len(restarts) == 1


def test_failed_restart_is_retried_on_the_next_call(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    results = iter([{"ok": False, "error": "busy"}, {"ok": True, "error": ""}])
    monkeypatch.setattr(mgr, "_restart_unbound", lambda reason: next(results))
    first = mgr._ensure_query_logging()
    second = mgr._ensure_query_logging()
    assert first["ok"] is False and first["reason"] == "restart-failed: busy"
    assert second["ok"] is True and second["restarted"] is True


def test_diagnostics_carry_query_logging_and_never_raise(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_run_diag",
                        lambda *a, **k: {"ok": False, "output": "", "error": "n/a"})
    monkeypatch.setattr(mgr, "_dns_probe",
                        lambda *a, **k: {"server": a[0], "responded": False})
    monkeypatch.setattr(mgr, "_local_ipv4s", lambda: [])
    diag = mgr.diagnostics()
    ql = diag["query_logging"]
    assert ql["query_log"] == um_mod.QUERY_LOG
    assert isinstance(ql["findings"], list)

    def boom():
        raise RuntimeError("kaput")

    monkeypatch.setattr(mgr, "query_log_diagnostics", boom)
    assert mgr.diagnostics()["query_logging"]["error"] == "kaput"
