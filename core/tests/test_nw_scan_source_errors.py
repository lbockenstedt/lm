"""Scan-source spoke errors are recognised and logged at most once an hour."""
import routes.nw as nw


def test_error_reply_is_recognised():
    """An ERROR/FAILED status returns the spoke's message; a normal reply returns None."""
    assert nw._scan_source_error({"status": "ERROR", "message": "403 Forbidden"}) == "403 Forbidden"
    assert nw._scan_source_error({"status": "failed", "error": "boom"}) == "boom"
    assert nw._scan_source_error({"status": "SUCCESS", "endpoints": []}) is None
    assert nw._scan_source_error([{"ip": "10.0.0.1"}]) is None


def test_warning_throttled_per_tenant_and_source():
    """The same (tenant, source) warns once per hour; other keys warn independently."""
    nw._SCAN_SOURCE_WARNED.clear()
    assert nw._should_warn_scan_source("ra", "nac", now=1000)
    assert not nw._should_warn_scan_source("ra", "nac", now=1000 + 3599)
    assert nw._should_warn_scan_source("ra", "dhcp", now=1001)
    assert nw._should_warn_scan_source("other", "nac", now=1002)
    assert nw._should_warn_scan_source("ra", "nac", now=1000 + 3600)


def test_snmp_silent_hosts_lists_only_hosts_that_ignored_every_community():
    """False (all communities tried, no answer) is listed; True (answered) and
    None (never tried or cut off) are not, so an untested host is not blamed."""
    results = [
        {"address": "10.0.0.9", "hostname": "SW-B", "snmp_ok": False},
        {"address": "10.0.0.2", "object_type": "cx_switch", "snmp_ok": False},
        {"address": "10.0.0.3", "hostname": "SW-OK", "snmp_ok": True},
        {"address": "10.0.0.4", "hostname": "SW-UNKNOWN", "snmp_ok": None},
        {"address": "10.0.0.5", "hostname": "SW-NOKEY"},
    ]
    assert nw._snmp_silent_hosts(results) == ["10.0.0.2 (cx_switch)", "10.0.0.9 (SW-B)"]
    assert nw._snmp_silent_hosts([]) == []
    # The spoke lists an identified host under both identified and reachable.
    twice = {"address": "10.0.0.7", "hostname": "SW-C", "snmp_ok": False}
    assert nw._snmp_silent_hosts([twice, dict(twice)]) == ["10.0.0.7 (SW-C)"]


def test_silent_snmp_log_includes_ping_only_hosts_but_not_foreign_ones():
    """The ping-only probe (hosts that answered ping but no management port)
    tries every community too. Its hosts are named in the silent log, and their
    addresses go through the same foreign-tenant check as the main scan hosts."""
    import inspect
    src = inspect.getsource(nw)
    pinged = src.index("pinged_hosts = (pinged.get(\"identified\") or []) + (pinged.get(\"reachable\") or [])")
    foreign_call = src.index("foreign = await access.foreign_tenant_ips(hub, tenant_id, {")
    silent = src.index("silent = _snmp_silent_hosts(identified + reachable + [")
    assert pinged < foreign_call < silent
    assert "identified + reachable + pinged_hosts}" in src[foreign_call:silent]
    assert "for d in pinged_hosts if str(d.get(\"address\") or \"\").strip() not in foreign" in src[silent:silent + 300]


def test_silent_snmp_log_names_only_hosts_left_after_the_foreign_tenant_filter():
    """LLDP crawling can reach another tenant's host (snmp_ok False); the scan
    drops those from identified/reachable first, so the log must be written after
    that filter or it would name a host the scanned tenant must never see."""
    import inspect
    src = inspect.getsource(nw)
    drop = src.index("reachable = [d for d in reachable if str(d.get(\"address\") or \"\").strip() not in foreign]")
    log = src.index("silent = _snmp_silent_hosts(identified + reachable + [")
    assert drop < log


def test_admin_scan_summary_lists_snmp_ok_only_when_the_entry_has_it():
    """An added/preview row (or an older spoke's result) carries no snmp_ok, so it
    is left out rather than shown as null, which would read as "SNMP never tried"."""
    from routes import admin_ops
    full = {"address": "10.0.0.9", "hostname": "SW-B", "snmp_ok": False, "extra": 1}
    assert admin_ops._scan_host_summary(full) == {
        "address": "10.0.0.9", "hostname": "SW-B", "object_type": None, "method": None, "snmp_ok": False}
    assert admin_ops._scan_host_summary({**full, "snmp_ok": None})["snmp_ok"] is None
    assert "snmp_ok" not in admin_ops._scan_host_summary({"address": "10.0.0.9", "hostname": "SW-B"})
