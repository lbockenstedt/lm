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
