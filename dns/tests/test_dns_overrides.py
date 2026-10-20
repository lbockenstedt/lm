"""Per-client DNS override profiles (Unbound views).

An admin defines named profiles (e.g. "PAVO-DEVICE") of custom answers and
blocked names; assigning a profile to a client IP/subnet renders an Unbound
``view:`` plus ``access-control-view`` so only that client sees the answers.
These tests drive the coordinator against REAL worker op tables (each with its
own temp UnboundManager), so the digest/marker contract between the two sides
is exercised end to end.
"""
import asyncio
import contextlib
import json
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from dns_overrides import (  # noqa: E402
    EMPTY_DIGEST, DnsOverrideCoordinator, DnsOverrideError, DnsOverrideState,
    assign, delete_profile, normalize_target, overrides_digest, render_unbound,
    unassign, upsert_profile, validate_overrides, validate_profile, view_name,
)
from dns_worker import DnsWorkerOps  # noqa: E402
from unbound_manager import UnboundManager  # noqa: E402

PAVO = {"name": "PAVO-DEVICE", "description": "lab device",
        "records": [{"name": "api.example.com", "type": "A", "value": "10.1.2.3"},
                    {"name": "*.cdn.example.com", "value": "10.1.2.4", "ttl": 60}],
        "block": ["telemetry.example.com"]}


# ── validation + rendering ──────────────────────────────────────────────────

def test_profile_is_normalized():
    p = validate_profile({**PAVO, "records": PAVO["records"] + [
        {"name": "API.Example.com.", "type": "a", "value": "10.1.2.3"}]})
    assert p["name"] == "PAVO-DEVICE"
    assert [r["name"] for r in p["records"]] == ["*.cdn.example.com", "api.example.com"]
    assert p["records"][1]["ttl"] == 300


@pytest.mark.parametrize("bad", [
    {"name": "has space"},
    {"name": "p", "records": [{"name": "a.com", "type": "MX", "value": "x"}]},
    {"name": "p", "records": [{"name": "a.com", "type": "A", "value": "::1"}]},
    {"name": "p", "records": [{"name": 'a.com" IN A 1.1.1.1', "value": "1.1.1.1"}]},
    {"name": "p", "records": [{"name": "a.com", "type": "CNAME", "value": "b.com"},
                              {"name": "a.com", "type": "A", "value": "1.1.1.1"}]},
    {"name": "p", "block": ["*"]},
    {"name": "p", "records": [{"name": "a.x.com", "value": "1.1.1.1"}], "block": ["x.com"]},
    {"name": "p", "records": [{"name": "a.x.com", "value": "1.1.1.1"},
                              {"name": "*.x.com", "value": "1.1.1.2"}]},
    {"name": "p", "records": [{"name": "*", "value": "1.1.1.1"},
                              {"name": "*.x.com", "value": "1.1.1.2"}]},
])
def test_invalid_profiles_are_rejected(bad):
    with pytest.raises(DnsOverrideError):
        validate_profile(bad)


def test_targets_are_canonical_cidrs_and_slash_zero_is_refused():
    assert normalize_target("10.1.2.3") == "10.1.2.3/32"
    assert normalize_target("10.1.2.9/24") == "10.1.2.0/24"
    assert normalize_target("2001:db8::5") == "2001:db8::5/128"
    with pytest.raises(DnsOverrideError):
        normalize_target("0.0.0.0/0")
    with pytest.raises(DnsOverrideError):
        normalize_target("not-an-ip")


def test_assignment_must_reference_a_known_profile():
    with pytest.raises(DnsOverrideError):
        validate_overrides({"profiles": [], "assignments": [
            {"target": "10.0.0.1", "profile": "NOPE"}]})


def test_render_one_view_per_profile_bound_to_assigned_clients():
    clean = validate_overrides({"profiles": [PAVO], "assignments": [
        {"target": "10.9.9.9", "profile": "PAVO-DEVICE"},
        {"target": "10.20.0.0/16", "profile": "PAVO-DEVICE"}]})
    text = render_unbound(clean)
    v = view_name("PAVO-DEVICE")
    assert v == "lm-ov-pavo-device"
    assert f"access-control-view: 10.9.9.9/32 {v}" in text
    assert f"access-control-view: 10.20.0.0/16 {v}" in text
    assert f'name: "{v}"' in text
    assert "view-first: yes" in text          # unmatched names resolve normally
    assert 'local-zone: "telemetry.example.com." always_nxdomain' in text
    assert 'local-zone: "cdn.example.com." redirect' in text
    assert 'local-data: "cdn.example.com. 60 IN A 10.1.2.4"' in text
    assert 'local-data: "api.example.com. 300 IN A 10.1.2.3"' in text


def test_digest_ignores_descriptions_and_labels():
    a = validate_overrides({"profiles": [PAVO], "assignments": [
        {"target": "10.0.0.1", "profile": "PAVO-DEVICE", "label": "x"}]})
    b = validate_overrides({"profiles": [{**PAVO, "description": "other"}], "assignments": [
        {"target": "10.0.0.1", "profile": "PAVO-DEVICE", "label": "y"}]})
    assert overrides_digest(a) == overrides_digest(b)


# ── harness: coordinator <-> real worker op tables ──────────────────────────

class _Cluster:
    """ClusterCoordinator stand-in that dispatches to real DnsWorkerOps."""

    def __init__(self, tmp_path, monkeypatch, n=2):
        self.ops, self.connected, self.broken = {}, {}, set()
        for i in range(n):
            mid = f"w{i}"
            mgr = UnboundManager(str(tmp_path / mid / "conf.d" / "lm-netbox.conf"))
            monkeypatch.setattr(mgr, "_reload", lambda: {"ok": True, "error": ""})
            monkeypatch.setattr(mgr, "_checkconf", lambda: {"ok": True, "error": ""})
            self.ops[mid] = DnsWorkerOps(mgr, str(tmp_path / mid / "state" / "applied.json"))
            self.connected[mid] = True

    def member_ids(self):
        return list(self.ops)

    def member_links(self):
        return [{"id": m, "connected": c} for m, c in self.connected.items()]

    async def fanout(self, cmd, data, timeout=None, member_ids=None):
        results, failed = {}, []
        for mid in (member_ids or self.member_ids()):
            if not self.connected[mid]:
                failed.append(mid)
                continue
            if mid in self.broken:
                reply = {"status": "ERROR", "message": "unsupported worker operation"}
            else:
                reply = self.ops[mid].op_table()[cmd](json.loads(json.dumps(data)))
            results[mid] = reply
            if reply.get("status") != "SUCCESS":
                failed.append(mid)
        return {"status": "SUCCESS" if not failed else "PARTIAL",
                "results": results, "failed": failed}

    def file(self, mid):
        return self.ops[mid].mgr.read_overrides()


@contextlib.asynccontextmanager
async def _no_lock():
    yield


def _coord(cluster, path):
    return DnsOverrideCoordinator(cluster, DnsOverrideState(str(path)), _no_lock)


def _run(coro):
    return asyncio.run(coro)


def _setup(coord):
    async def go():
        assert (await coord.mutate(upsert_profile(PAVO)))["status"] == "SUCCESS"
        return await coord.mutate(assign("10.0.0.7", "PAVO-DEVICE", "pavo-01"))
    return _run(go())


# ── coordinator ─────────────────────────────────────────────────────────────

def test_assign_reaches_every_worker_and_persists(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    out = _setup(coord)
    assert out["status"] == "SUCCESS" and out["version"] == 2
    for mid in cluster.ops:
        assert "access-control-view: 10.0.0.7/32 lm-ov-pavo-device" in cluster.file(mid)
    # Survives a coordinator restart.
    reloaded = DnsOverrideState(str(tmp_path / "ov.json"))
    assert reloaded.version == 2
    assert reloaded.data["assignments"][0]["label"] == "pavo-01"

    snap = _run(coord.snapshot())
    assert snap["converged"] is True
    assert {m["convergence"] for m in snap["members"]} == {"converged"}


def test_a_rejecting_worker_rolls_the_others_back(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _setup(coord)
    before = cluster.file("w0")
    cluster.broken.add("w1")
    out = _run(coord.mutate(assign("10.0.0.8", "PAVO-DEVICE")))
    assert out["status"] == "ERROR"
    assert "w1" in out["member_errors"]
    assert cluster.file("w0") == before        # w0 was put back
    assert coord.state.version == 2            # nothing persisted
    assert len(coord.state.data["assignments"]) == 1


def test_bad_unbound_config_is_restored_and_rolls_back(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _setup(coord)
    before = cluster.file("w1")
    monkeypatch.setattr(cluster.ops["w1"].mgr, "_checkconf",
                        lambda: {"ok": False, "error": "syntax error"})
    out = _run(coord.mutate(unassign("10.0.0.7")))
    assert out["status"] == "ERROR" and "checkconf" in out["message"]
    assert cluster.file("w1") == before and cluster.file("w0") == before


def test_offline_worker_is_partial_then_reconciled(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _run(coord.mutate(upsert_profile(PAVO)))
    cluster.connected["w1"] = False
    out = _run(coord.mutate(assign("10.0.0.7", "PAVO-DEVICE")))
    assert out["status"] == "PARTIAL" and out["members_offline"] == ["w1"]
    assert "10.0.0.7" not in cluster.file("w1")
    cluster.connected["w1"] = True
    rec = _run(coord.reconcile())
    assert rec["reconciled"] == ["w1"]
    assert "10.0.0.7/32" in cluster.file("w1")


def test_hand_edited_file_is_detected_as_drift_and_repaired(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _setup(coord)
    good = cluster.file("w0")
    with open(cluster.ops["w0"].mgr.overrides_path, "w") as fh:
        fh.write("# tampered\n")
    assert cluster.ops["w0"].overrides_state({})["digest"] is None
    assert _run(coord.reconcile())["reconciled"] == ["w0"]
    assert cluster.file("w0") == good


def test_fresh_worker_reports_the_empty_digest():
    class _Mgr:
        def read_overrides(self):
            return None
    ops = DnsWorkerOps.__new__(DnsWorkerOps)
    ops.mgr = _Mgr()
    ops.state_path = "/nonexistent/lm-dns-test/applied.json"
    assert ops.overrides_state({})["digest"] == EMPTY_DIGEST


def test_worker_refuses_a_payload_whose_digest_does_not_match(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch, n=1)
    clean = validate_overrides({"profiles": [PAVO], "assignments": []})
    out = cluster.ops["w0"].overrides_apply(
        {"version": 1, "digest": "0" * 64, "overrides": clean})
    assert out["status"] == "ERROR" and out["rejected"] is True
    assert cluster.file("w0") is None


def test_profile_delete_refuses_while_assigned_unless_forced(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _setup(coord)
    with pytest.raises(DnsOverrideError):
        _run(coord.mutate(delete_profile("PAVO-DEVICE")))
    out = _run(coord.mutate(delete_profile("pavo-device", force=True)))
    assert out["status"] == "SUCCESS"
    assert out["profiles"] == [] and out["assignments"] == []
    assert "access-control-view" not in cluster.file("w0")


def test_profile_rename_carries_its_assignments(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _setup(coord)
    out = _run(coord.mutate(upsert_profile({**PAVO, "name": "PAVO-V2"}, old_name="PAVO-DEVICE")))
    assert out["status"] == "SUCCESS"
    assert out["assignments"][0]["profile"] == "PAVO-V2"
    assert "lm-ov-pavo-v2" in cluster.file("w0")


def test_label_only_change_persists_without_a_push(tmp_path, monkeypatch):
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, tmp_path / "ov.json")
    _setup(coord)
    out = _run(coord.mutate(assign("10.0.0.7", "PAVO-DEVICE", "renamed")))
    assert out["changed"] is False
    assert DnsOverrideState(str(tmp_path / "ov.json")).data["assignments"][0]["label"] == "renamed"


def test_corrupt_state_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "ov.json"
    path.write_text(json.dumps({"version": 3, "digest": "bogus",
                                "overrides": {"profiles": [], "assignments": []}}))
    cluster = _Cluster(tmp_path, monkeypatch)
    coord = _coord(cluster, path)
    assert _run(coord.snapshot())["state_unavailable"] is True
    from dns_overrides import DnsOverrideStateUnavailable
    with pytest.raises(DnsOverrideStateUnavailable):
        _run(coord.mutate(upsert_profile(PAVO)))


# ── spoke command surface ───────────────────────────────────────────────────

def test_spoke_routes_override_commands(tmp_path, monkeypatch):
    from dns_spoke import DNSSpoke
    cluster = _Cluster(tmp_path, monkeypatch)
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke.overrides = _coord(cluster, tmp_path / "ov.json")

    async def go():
        r = await spoke._handle_override("DNS_OVERRIDE_PROFILE_SET", {"profile": PAVO})
        assert r["status"] == "SUCCESS"
        r = await spoke._handle_override("DNS_OVERRIDE_ASSIGN",
                                         {"target": "10.0.0.9", "profile": "PAVO-DEVICE"})
        assert r["status"] == "SUCCESS"
        r = await spoke._handle_override("DNS_OVERRIDE_ASSIGN",
                                         {"target": "10.0.0.9", "profile": "MISSING"})
        assert r["status"] == "ERROR" and "MISSING" in r["message"]
        snap = await spoke._handle_override("DNS_OVERRIDES", {})
        assert [a["target"] for a in snap["assignments"]] == ["10.0.0.9/32"]
        r = await spoke._handle_override("DNS_OVERRIDE_UNASSIGN", {"target": "10.0.0.9"})
        assert r["status"] == "SUCCESS" and r["assignments"] == []
        r = await spoke._handle_override("DNS_OVERRIDE_PROFILE_DELETE", {"name": "PAVO-DEVICE"})
        assert r["status"] == "SUCCESS"
    _run(go())
