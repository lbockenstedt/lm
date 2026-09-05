"""Tests for provider-aware "Sync NSG now".

The Sync button used to run ONLY the Azure-only deny reconcile, so an operator
running OCI got "Azure NSG not configured — logged only" and nothing was
pushed — even though their trusted/allow list was perfectly syncable against
OCI. These tests pin the corrected split:

  * ALLOW / trusted list  → Azure AND OCI
  * DENY / blocked IPs    → Azure only (OCI NSGs have no deny construct)
"""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _State:
    def __init__(self, gc):
        self.system_state = {"global_config": gc}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, gc):
        self.state = _State(gc)


def _monitor(gc, auto_block=True):
    """A ThreatMonitor with its two reconcile halves stubbed, so these tests
    exercise the dispatch/merge logic rather than any cloud SDK."""
    from security.threat_monitor import ThreatMonitor
    tm = ThreatMonitor.__new__(ThreatMonitor)
    tm.hub = _Hub(gc)
    tm._cfg = {"auto_block": auto_block}
    tm._blocks = {}
    tm._nsg_dirty = True
    tm._nsg_live_rule_name = None
    return tm


AZURE_ON = {"azure_nsg": {"enabled": True, "subscription_id": "s",
                          "resource_group": "rg", "nsg_name": "n"}}
OCI_ON = {"oci_nsg": {"enabled": True, "region": "us-ashburn-1", "nsg_id": "ocid1.nsg"}}
NONE_ON = {}


# ── the reported bug ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oci_active_does_not_report_azure_not_configured():
    """The reported symptom: OCI selected, Sync says 'Azure NSG not configured'."""
    tm = _monitor(OCI_ON)
    res = await tm.reconcile_nsg()
    assert "Azure NSG not configured" not in res["message"]
    assert "OCI" in res["message"]
    assert "no deny rule" in res["message"]
    assert "allow list" in res["message"], "must point at how blocking IS done"


@pytest.mark.asyncio
async def test_oci_active_sync_still_pushes_allow_list():
    """The point of the fix: under OCI the button must still DO something."""
    tm = _monitor(OCI_ON)
    called = []

    async def fake_allow():
        called.append("allow")
        return {"status": "OK", "message": "3 prefixes applied to OCI"}

    tm.reconcile_allow = fake_allow
    res = await tm.sync_nsg_now()
    assert called == ["allow"], "allow half must run when OCI is active"
    assert res["status"] == "OK"
    assert "3 prefixes applied to OCI" in res["message"]


@pytest.mark.asyncio
async def test_no_provider_message_is_not_azure_specific():
    tm = _monitor(NONE_ON)
    res = await tm.reconcile_nsg()
    assert "Azure" not in res["message"]
    assert "no cloud NSG provider is configured" in res["message"]


# ── merge semantics ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_both_halves_reported():
    tm = _monitor(OCI_ON)

    async def fake_allow():
        return {"status": "OK", "message": "allow pushed"}

    tm.reconcile_allow = fake_allow
    res = await tm.sync_nsg_now()
    assert "allow list:" in res["message"]
    assert "blocked IPs:" in res["message"]
    assert res["allow"]["status"] == "OK"
    assert res["deny"]["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_error_in_either_half_dominates():
    tm = _monitor(OCI_ON)

    async def fake_allow():
        return {"status": "ERROR", "message": "OCI refused"}

    tm.reconcile_allow = fake_allow
    res = await tm.sync_nsg_now()
    assert res["status"] == "ERROR"


@pytest.mark.asyncio
async def test_all_skipped_is_skipped_not_ok():
    """Nothing pushed must not look like success."""
    tm = _monitor(NONE_ON, auto_block=False)

    async def fake_allow():
        return {"status": "SKIPPED", "message": "no provider"}

    tm.reconcile_allow = fake_allow
    res = await tm.sync_nsg_now()
    assert res["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_sync_sets_dirty_so_deny_half_is_not_short_circuited():
    """reconcile_nsg early-returns 'no change' unless _nsg_dirty is set;
    an operator pressing Sync explicitly wants a push regardless."""
    tm = _monitor(AZURE_ON, auto_block=False)
    tm._nsg_dirty = False

    async def fake_allow():
        return {"status": "SKIPPED", "message": "x"}

    tm.reconcile_allow = fake_allow
    res = await tm.sync_nsg_now()
    assert "no change" not in res["deny"]["message"]
    assert "auto-block off" in res["deny"]["message"]


@pytest.mark.asyncio
async def test_azure_active_reaches_azure_path_not_oci_message():
    tm = _monitor(AZURE_ON)
    res = await tm.reconcile_nsg()
    assert "no deny rule" not in res.get("message", "")
