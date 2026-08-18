"""Unit tests for access.last_known_vm_record — the pxmx_vms warm-cache lookup
that recovers a stopped / guest-agent-silent VM's last-known ips/tags so the
console/control gates can still attribute a subnet-owned VM the tenant sees."""
import access
from _fakes import FakeHub


def _hub_with_cache(cache):
    hub = FakeHub()
    hub.warm_cache = cache
    return hub


def test_no_warm_cache_attr_returns_empty():
    # A hub without a warm_cache attribute must not raise.
    assert access.last_known_vm_record(FakeHub(), unique_id="c/n/100") == {}


def test_empty_cache_returns_empty():
    hub = _hub_with_cache({})
    assert access.last_known_vm_record(hub, unique_id="c/n/100") == {}


def test_match_by_unique_id_recovers_ips_and_tags():
    hub = _hub_with_cache({"pxmx_vms": {
        "_all_|agent=": {"data": {"vms": [
            {"unique_id": "c/n/100", "vmid": "100", "node": "n",
             "ips": ["10.1.2.3"], "tags": ["tenantA"], "pool": "poolA"},
            {"unique_id": "c/n/101", "vmid": "101", "node": "n",
             "ips": ["10.9.9.9"], "tags": []},
        ]}},
    }})
    rec = access.last_known_vm_record(hub, unique_id="c/n/100")
    assert rec == {"ips": ["10.1.2.3"], "tags": ["tenantA"], "pool": "poolA"}


def test_no_match_returns_empty():
    hub = _hub_with_cache({"pxmx_vms": {
        "_all_|agent=": {"data": {"vms": [
            {"unique_id": "c/n/100", "ips": ["10.1.2.3"], "tags": ["t"]},
        ]}},
    }})
    assert access.last_known_vm_record(hub, unique_id="c/n/999") == {}


def test_match_by_vmid_and_node_when_no_unique_id():
    hub = _hub_with_cache({"pxmx_vms": {
        "_all_|agent=": {"data": {"vms": [
            {"unique_id": "c/n/100", "vmid": "100", "node": "n",
             "ips": ["10.1.2.3"], "tags": ["t"]},
        ]}},
    }})
    rec = access.last_known_vm_record(hub, vmid=100, node="n")
    assert rec.get("ips") == ["10.1.2.3"]
    # Wrong node → no match.
    assert access.last_known_vm_record(hub, vmid=100, node="other") == {}


def test_unions_across_multiple_cache_scopes():
    # Same VM may appear under several warm-key scopes; union its ips/tags.
    hub = _hub_with_cache({"pxmx_vms": {
        "_all_|agent=": {"data": {"vms": [
            {"unique_id": "c/n/100", "ips": ["10.1.2.3"], "tags": ["a"]},
        ]}},
        "tenantA|agent=": {"data": {"vms": [
            {"unique_id": "c/n/100", "ips": ["10.1.2.4"], "tags": ["b"]},
        ]}},
    }})
    rec = access.last_known_vm_record(hub, unique_id="c/n/100")
    assert set(rec["ips"]) == {"10.1.2.3", "10.1.2.4"}
    assert set(rec["tags"]) == {"a", "b"}


def test_handles_list_shaped_data():
    hub = _hub_with_cache({"pxmx_vms": {
        "_all_|agent=": {"data": [
            {"unique_id": "c/n/100", "ips": ["10.0.0.5"], "tags": ["x"]},
        ]},
    }})
    rec = access.last_known_vm_record(hub, unique_id="c/n/100")
    assert rec.get("ips") == ["10.0.0.5"]


def test_empty_identifiers_returns_empty():
    hub = _hub_with_cache({"pxmx_vms": {
        "_all_|agent=": {"data": {"vms": [
            {"unique_id": "c/n/100", "ips": ["10.1.2.3"]},
        ]}},
    }})
    # No unique_id and no vmid → nothing to match on.
    assert access.last_known_vm_record(hub) == {}
