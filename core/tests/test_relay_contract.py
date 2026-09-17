"""Critical path 3/4 — spoke relay error contract (DNS/DHCP + general).

The hub relay translates a spoke-side ERROR payload into HTTP 502 (Bad Gateway)
and passes SUCCESS bodies through unchanged. These tests lock in the pure
``_spoke_payload_or_raise`` decision extracted from the ``_relay_spoke`` closure
so the contract can't silently regress to the old 200+{status:ERROR} behaviour.

TODO (integration): spin up ``create_app(hub)`` with a ``FakeHub`` whose
``request_response`` returns a canned spoke payload and assert via
``fastapi.testclient.TestClient`` that GET /api/dns/records returns 502 +
``{"detail": ...}`` on a spoke ERROR and 200 + the records on SUCCESS.
"""

import pytest
from fastapi import HTTPException

from api import SPOKE_UPDATING_DETAIL, _spoke_payload_or_raise


def test_success_payload_returned_unchanged():
    data = {"status": "SUCCESS", "records": [{"name": "a.example", "type": "A"}]}
    assert _spoke_payload_or_raise(data) is data


def test_error_with_message_raises_502():
    with pytest.raises(HTTPException) as exc:
        _spoke_payload_or_raise({"status": "ERROR", "message": "name and value are required"})
    assert exc.value.status_code == 502
    assert exc.value.detail == "name and value are required"


def test_error_with_error_field_raises_502():
    # some spokes use "error" instead of "message"
    with pytest.raises(HTTPException) as exc:
        _spoke_payload_or_raise({"status": "ERROR", "error": "Unknown command: FOO"})
    assert exc.value.status_code == 502
    assert exc.value.detail == "Unknown command: FOO"


def test_error_with_no_message_field_uses_default():
    with pytest.raises(HTTPException) as exc:
        _spoke_payload_or_raise({"status": "ERROR"})
    assert exc.value.status_code == 502
    assert exc.value.detail == "Spoke returned an error"


def test_non_dict_passthrough():
    """A raw list / scalar (no status field) is returned as-is — the relay
    doesn't assume every spoke result is a dict."""
    lst = [{"ip": "10.0.0.1"}]
    assert _spoke_payload_or_raise(lst) is lst
    assert _spoke_payload_or_raise("raw") == "raw"


def test_dict_without_status_returned_as_is():
    d = {"records": []}
    assert _spoke_payload_or_raise(d) is d


def test_updating_spoke_raises_503_with_friendly_detail():
    """A target mid self-update (request_response short-circuits with
    ``updating: True`` instead of burning the full timeout) is NOT a failure:
    it must translate to 503 + the friendly 'update in progress' detail so the
    browser shows an update notice, not a false 'Timed out' error."""
    with pytest.raises(HTTPException) as exc:
        _spoke_payload_or_raise({
            "status": "ERROR",
            "message": "Timed out waiting for spoke response",
            "updating": True, "draining": True,
        })
    assert exc.value.status_code == 503
    assert exc.value.detail == SPOKE_UPDATING_DETAIL


def test_draining_flag_alone_also_raises_503():
    with pytest.raises(HTTPException) as exc:
        _spoke_payload_or_raise({"status": "ERROR", "draining": True,
                                 "message": "Timed out waiting for spoke response"})
    assert exc.value.status_code == 503
    assert exc.value.detail == SPOKE_UPDATING_DETAIL

# ── Null payload: the "null is not an object (evaluating 'd.status')" class ───
# A spoke replying {"payload": {"data": null}} unwrapped to None because
# ``.get("data", result)`` only falls back when the key is ABSENT. The route
# then returned HTTP 200 whose body was the literal JSON token ``null``, which
# the browser's r.json() PARSES successfully (so every `.catch()` guard was
# bypassed) before the first field access threw. Reported against
# DHCP → Overview on the shared tenant; the same shape reached DNS, LDAP,
# console and pxmx through their own copies of the idiom.

def test_none_payload_raises_502_not_200_null():
    """None must never be serialized as a 200 body of literal `null`."""
    with pytest.raises(HTTPException) as exc:
        _spoke_payload_or_raise(None)
    assert exc.value.status_code == 502
    assert exc.value.detail == "Spoke returned no data"


@pytest.mark.parametrize("empty", [{}, [], 0, False, ""])
def test_empty_but_real_payloads_still_pass_through(empty):
    """Fail on None only — an empty-but-real payload is legitimate data and
    must not be mistaken for 'no data' (this is why the guard tests `is None`
    rather than truthiness)."""
    assert _spoke_payload_or_raise(empty) is empty


def test_unwrap_spoke_treats_explicit_null_data_as_no_payload():
    from access import unwrap_spoke
    env = {"payload": {"data": None}, "status": "SUCCESS"}
    # Falls back to the ENVELOPE (not None) so status/message stay visible to
    # _spoke_payload_or_raise instead of collapsing to a null body.
    assert unwrap_spoke(env) is env


@pytest.mark.parametrize("payload", [{}, [], 0, False])
def test_unwrap_spoke_keeps_falsy_but_real_payloads(payload):
    from access import unwrap_spoke
    assert unwrap_spoke({"payload": {"data": payload}}) is payload


def test_unwrap_spoke_still_unwraps_real_data():
    from access import unwrap_spoke
    inner = {"status": "SUCCESS", "subnets": [{"subnet": "10.0.0.0/24"}]}
    assert unwrap_spoke({"payload": {"data": inner}}) is inner


def test_normalize_cached_null_data_falls_back_to_envelope():
    """The warm/tenant cache path must not hand a None back either."""
    from api import _normalize_cached
    env = {"payload": {"data": None}, "status": "SUCCESS"}
    assert _normalize_cached(env) is env
    bare = {"data": None, "status": "SUCCESS"}
    assert _normalize_cached(bare) is bare


def test_dhcp_stats_rescope_cannot_emit_none_for_shared_tenant():
    """End-to-end shape of the reported bug: DHCP → Overview on the shared
    tenant. filter_tenant returns the data UNCHANGED for a shared tenant with
    no prefixes, so a None relay result used to flow straight through
    _dhcp_rescope_stats and out as a 200 + `null`."""
    from routes.net_services import _dhcp_rescope_stats
    # _spoke_payload_or_raise now stops None before it ever reaches the filter.
    with pytest.raises(HTTPException):
        _spoke_payload_or_raise(_dhcp_rescope_stats(None, None))
