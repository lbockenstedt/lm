"""The cluster coordinator must say WHY a forwarder add failed.

_cluster_add_forwarder collapsed every member's result into

    forwarder was not added to all resolvers (<uuid>, <uuid>)

and dropped the per-member payloads into a `members` dict nothing renders. In
production that hid a completely actionable message ("forwarder zone . already
exists") behind two opaque UUIDs, and recovering it meant reading each
resolver's own log by hand over the admin API.
"""
import asyncio

from test_dns_forwarder_cluster import _spoke

MEMBERS = ["res-a", "res-b"]


def _failed(results):
    return {"status": "ERROR", "results": results, "ok": [],
            "failed": list(results)}


def _add(spoke):
    return asyncio.run(spoke._cluster_add_forwarder(
        {"zone": ".", "upstreams": ["1.1.1.1"]}))


def test_the_members_own_reason_reaches_the_error_message():
    spoke = _spoke(_failed({
        m: {"status": "ERROR", "message": "forwarder zone . already exists"}
        for m in MEMBERS}))
    out = _add(spoke)
    assert out["status"] == "ERROR"
    assert "forwarder zone . already exists" in out["message"]
    # the resolver ids are still named, so an operator knows WHICH failed
    for member in MEMBERS:
        assert member in out["message"]


def test_identical_reasons_are_reported_once():
    spoke = _spoke(_failed({
        m: {"status": "ERROR", "message": "no more than 8 forwarder addresses"}
        for m in MEMBERS}))
    out = _add(spoke)
    assert out["message"].count("no more than 8 forwarder addresses") == 1


def test_differing_reasons_are_both_reported():
    spoke = _spoke(_failed({
        "res-a": {"status": "ERROR", "message": "already exists"},
        "res-b": {"status": "ERROR", "message": "unbound-control reload failed"},
    }))
    out = _add(spoke)
    assert "already exists" in out["message"]
    assert "unbound-control reload failed" in out["message"]


def test_a_member_with_no_message_does_not_add_empty_noise():
    spoke = _spoke(_failed({m: {"status": "ERROR"} for m in MEMBERS}))
    out = _add(spoke)
    assert out["status"] == "ERROR"
    assert out["message"].rstrip().endswith(")")


def test_the_per_member_payloads_are_still_returned():
    spoke = _spoke(_failed({
        m: {"status": "ERROR", "message": "already exists"} for m in MEMBERS}))
    out = _add(spoke)
    assert set(out["members"]) == set(MEMBERS)


def test_a_successful_add_is_unaffected():
    spoke = _spoke({"status": "SUCCESS", "ok": MEMBERS, "failed": [],
                    "results": {m: {"status": "SUCCESS"} for m in MEMBERS}})
    out = _add(spoke)
    assert out["status"] == "SUCCESS"
    assert "message" not in out
