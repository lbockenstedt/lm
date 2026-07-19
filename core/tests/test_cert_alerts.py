"""Cert-failure alert sources — ``cert_issue_failed`` / ``cert_renew_failed`` /
``cert_deploy_failed``.

These cover the two testable halves of the cert-failure alert feature:
  1. ``AlertEngine.evaluate`` edge-trigger + email routing (one email on a
     transition into bad, one on recovery, silent while held) — the shared core
     every cert source funnels through.
  2. ``_eval_tenant``'s cert pull-branch — scans the hub's ``le_cache`` mirror
     of the le spoke's ledger (LE_LIST_CERTS) for the three failure markers
     (``last_issue_error`` / ``last_error`` / per-target ``last_status == ERROR``),
     per-tenant. This is the restart re-fire + dedup-consistency path;
     ``cert_renew_failed`` is ALSO pushed realtime by the LE_CERT_RENEW_FAILED
     event (main.py dispatch → evaluate), whose le-side emit is covered by
     le/tests/test_le_spoke.py and whose dispatch wiring mirrors the tested
     LE_CERT_RENEWED block.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import alert_engine as ae  # noqa: E402
import notifications  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeStore:
    """simulations_store stand-in: only get_alert_rules is read by evaluate."""
    def __init__(self, rules):
        self._rules = rules

    async def get_alert_rules(self, tenant):
        return [r for r in self._rules if r.get("_tenant", tenant) == tenant]


class _FakeHub:
    def __init__(self, rules, certs_cache):
        self.simulations_store = _FakeStore(rules)
        self.alert_engine = ae.AlertEngine(self)
        self._certs_cache = certs_cache

    def le_cache_get(self, key):
        if key == "certs":
            return self._certs_cache
        return None


def _rule(source, recips=("noc@acme.com",), fmt="human", enabled=True):
    return {"id": "r1", "name": source, "source": source,
            "recipients": list(recips), "format": fmt, "enabled": enabled,
            "_tenant": "default"}


def _capture_send(monkeypatch):
    sent = []

    async def _send(hub, subject, body, to_emails=None, html=None, spoke_id=None):
        sent.append({"subject": subject, "body": body, "to": to_emails, "html": html})

    monkeypatch.setattr(notifications, "send_email", _send)
    return sent


# ── AlertEngine.evaluate: edge-trigger + routing ──────────────────────────────

def test_evaluate_fires_once_on_breach_then_recovery(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_deploy_failed")], None)
    eng = hub.alert_engine
    _run(eng.evaluate("default", "cert_deploy_failed", "a.com/firewall", True,
                      "INSTALL_CERT failed", severity="error"))
    assert len(sent) == 1
    assert "ALERT" in sent[0]["subject"]
    assert "Certificate deployment failed" in sent[0]["subject"]
    # Held bad → no re-fire (edge-triggered).
    _run(eng.evaluate("default", "cert_deploy_failed", "a.com/firewall", True, "x"))
    assert len(sent) == 1
    # Recovery → a second email.
    _run(eng.evaluate("default", "cert_deploy_failed", "a.com/firewall", False, "",
                      severity="ok"))
    assert len(sent) == 2
    assert "OK" in sent[1]["subject"]


def test_evaluate_no_rule_no_email(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_renew_failed")], None)  # rule for a DIFFERENT source
    _run(hub.alert_engine.evaluate("default", "cert_deploy_failed", "a.com/fw", True, "x"))
    assert sent == []


def test_evaluate_raw_format_emits_json(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_issue_failed", fmt="raw")], None)
    _run(hub.alert_engine.evaluate("default", "cert_issue_failed", "a.com", True,
                                   "certbot rc=1", severity="error"))
    assert len(sent) == 1
    assert sent[0]["body"].lstrip().startswith("{")  # JSON body
    assert '"source":"cert_issue_failed"' in sent[0]["body"]


def test_evaluate_sources_registered_and_labeled():
    assert "cert_issue_failed" in ae.SOURCES
    assert "cert_renew_failed" in ae.SOURCES
    assert "cert_deploy_failed" in ae.SOURCES
    assert ae._LABEL["cert_issue_failed"]
    assert ae._LABEL["cert_renew_failed"]
    assert ae._LABEL["cert_deploy_failed"]


# ── _eval_tenant cert pull-branch (scans le_cache) ─────────────────────────────

def _certs_cache(certs):
    return {"certs": certs, "count": len(certs), "certbot_present": True}


def _eval(hub, tenant, needed):
    _run(ae._eval_tenant(hub.alert_engine, None, tenant, needed))


def test_pull_branch_flags_issue_failure(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_issue_failed")],
                   _certs_cache([{"domain": "a.com", "tenant_id": "default",
                                  "last_issue_error": "certbot rc=1"}]))
    _eval(hub, "default", {"cert_issue_failed"})
    assert len(sent) == 1
    assert "a.com" in sent[0]["subject"]


def test_pull_branch_flags_renew_failure(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_renew_failed")],
                   _certs_cache([{"domain": "a.com", "tenant_id": "default",
                                  "last_error": "renew rc=1"}]))
    _eval(hub, "default", {"cert_renew_failed"})
    assert len(sent) == 1
    assert "a.com" in sent[0]["subject"]


def test_pull_branch_flags_deploy_failure_per_target(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_deploy_failed")], _certs_cache([{
        "domain": "a.com", "tenant_id": "default", "targets": [
            {"module_type": "firewall", "identifier": "edge-1",
             "last_status": "ERROR", "last_message": "missing CA key"},
            {"module_type": "ipam", "identifier": "",
             "last_status": "SUCCESS", "last_message": "installed"},
        ]}]))
    _eval(hub, "default", {"cert_deploy_failed"})
    assert len(sent) == 1  # only the ERROR target
    assert "a.com/firewall/edge-1" in sent[0]["subject"]


def test_pull_branch_recovery_clears_edge(monkeypatch):
    """A cert whose failure marker has cleared (last_issue_error None after a
    successful re-issue) → evaluate(is_bad=False) → recovery email, and a
    subsequent still-good tick is silent."""
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_issue_failed")], _certs_cache([{
        "domain": "a.com", "tenant_id": "default", "last_issue_error": None}]))
    # Pre-seed the edge as bad (as if a prior tick saw the failure).
    hub.alert_engine._state[("default", "cert_issue_failed", "a.com")] = True
    _eval(hub, "default", {"cert_issue_failed"})
    assert len(sent) == 1
    assert "OK" in sent[0]["subject"]  # recovery
    # Next tick still good → silent.
    _eval(hub, "default", {"cert_issue_failed"})
    assert len(sent) == 1


def test_pull_branch_tenant_filtered(monkeypatch):
    """A cert bound to a different tenant is NOT evaluated against this tenant's
    rules (no cross-tenant cert-failure leak)."""
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_issue_failed")], _certs_cache([{
        "domain": "other.com", "tenant_id": "acme",
        "last_issue_error": "x"}]))
    _eval(hub, "default", {"cert_issue_failed"})
    assert sent == []


def test_pull_branch_no_cache_no_fire(monkeypatch):
    """No le_cache yet (le spoke never reached) → no fire, no crash."""
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("cert_deploy_failed")], None)
    _eval(hub, "default", {"cert_deploy_failed"})
    assert sent == []