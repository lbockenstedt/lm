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

from api import _spoke_payload_or_raise


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