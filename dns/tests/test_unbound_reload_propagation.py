"""``UnboundManager.sync`` must report a failed reload.

REGRESSION (review #9): ``_reload`` swallowed the failure with a WARNING and
``sync`` still returned SUCCESS, so a conf write that Unbound never picked up
looked identical to one it did. Every caller — the single-host spoke and the
clustered worker's applied-version bookkeeping — depends on the distinction.
"""

from unbound_manager import UnboundManager

RECORDS = [{"name": "a.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}]


def _mgr(tmp_path):
    mgr = UnboundManager(str(tmp_path / "conf.d" / "lm-netbox.conf"))
    # sync() now idempotently ensures query logging (which may restart
    # unbound); keep these reload-propagation tests off real systemctl.
    mgr._ensure_query_logging = lambda: {
        "status": "unchanged", "changed": False, "restarted": False,
        "ok": True, "reason": "already-enabled"}
    return mgr


def test_sync_reports_success_with_reloaded_true(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_reload", lambda: {"ok": True, "error": ""})
    out = mgr.sync(RECORDS)
    assert out["status"] == "SUCCESS"
    assert out["reloaded"] is True
    assert out["records_written"] == 1      # lm counts input records, not lines


def test_sync_reports_error_when_the_reload_fails(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": False, "error": "connection refused"})
    out = mgr.sync(RECORDS)
    assert out["status"] == "ERROR"
    assert out["reloaded"] is False
    assert "connection refused" in out["message"]
    # The write still happened — the message says so, rather than pretending
    # nothing changed.
    assert out["records_written"] == 1
    assert (tmp_path / "conf.d" / "lm-netbox.conf").exists()


def test_reload_returns_a_structured_result(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)

    def boom(*_a, **_kw):
        raise OSError("unbound-control: command not found")

    monkeypatch.setattr("unbound_manager.subprocess.run", boom)
    result = mgr._reload()
    assert result["ok"] is False
    assert "command not found" in result["error"]


def test_add_forwarder_persists_config_and_reloads(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)
    # lm verifies the zone took effect after reload, so Unbound's live view
    # must reflect LM's managed file (see test_unbound_forwarder_merge).
    monkeypatch.setattr(mgr, "list_forwarders",
                        lambda: {"status": "SUCCESS",
                                 "forwarders": mgr._managed_forwarders()})
    monkeypatch.setattr(mgr, "_reload",
                        lambda: {"ok": True, "error": ""})

    result = mgr.add_forwarder(".", ["1.1.1.1", "2606:4700:4700::1111"])

    assert result["status"] == "SUCCESS"
    text = (tmp_path / "conf.d" / "lm-forwarders.conf").read_text()
    assert 'name: "."' in text
    assert "forward-addr: 1.1.1.1" in text
    assert "forward-addr: 2606:4700:4700::1111" in text


def test_add_forwarder_rejects_invalid_or_duplicate_values(monkeypatch, tmp_path):
    mgr = _mgr(tmp_path)
    assert mgr.add_forwarder("bad zone", ["1.1.1.1"])["status"] == "ERROR"
    assert mgr.add_forwarder(".", ["not-an-ip"])["status"] == "ERROR"

    monkeypatch.setattr(mgr, "list_forwarders", lambda: {
        "status": "SUCCESS",
        "forwarders": [{"zone": ".", "upstreams": ["8.8.8.8"]}],
    })
    duplicate = mgr.add_forwarder(".", ["1.1.1.1"])
    assert duplicate["status"] == "ERROR"
    assert duplicate["changed"] is False
