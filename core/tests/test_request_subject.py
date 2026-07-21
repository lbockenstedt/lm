"""``_request_subject`` — the Request Timeout log-line subject label.

Replaces the opaque per-request ``msg_id`` UUID in the ``Request Timeout:
[<CMD>] <subject> from <spoke> after Ns`` ERROR line with the *subject* the
request operates on (a hostname / appliance / device / vm / tenant …) so the
operator reads a name, not a random correlation id. Pure leaf helper — no
``main`` import (avoids the heavy app bootstrap the secret-hygiene suite pays
for)."""

from log_redaction import _request_subject


def test_cs_poll_agent_inbox_yields_hostname():
    # The exact case from the field: a CS_POLL_AGENT_INBOX poll timed out and
    # the log showed the msg_id UUID where the sim-client hostname belongs.
    assert _request_subject("CS_POLL_AGENT_INBOX", {"hostname": "linux-client-3"}) == "hostname=linux-client-3"


def test_truenas_get_pools_yields_appliance_id():
    assert _request_subject("TRUENAS_GET_POOLS", {"appliance_id": "nas1"}) == "appliance_id=nas1"


def test_nw_get_arp_yields_device_id():
    assert _request_subject("NW_GET_ARP", {"device_id": "core-sw-1"}) == "device_id=core-sw-1"


def test_prefers_hostname_over_id_when_both_present():
    # hostname is ordered before name/id-likes; a bare ``id`` (usually a UUID)
    # is never picked.
    assert _request_subject("CS_COMMAND",
                            {"id": "cf1766cb-a2b3-41a2-997c-733b18368474",
                             "hostname": "win-client-7"}) == "hostname=win-client-7"


def test_name_used_when_no_hostname():
    assert _request_subject("SOME_OP", {"name": "tank", "id": "abc-123"}) == "name=tank"


def test_bare_id_uuid_is_not_picked():
    # ``id`` is deliberately excluded from the allowlist (it's the UUID we're
    # replacing) → no subject derivable → empty (caller falls back to req=<8>).
    assert _request_subject("SOME_OP", {"id": "cf1766cb-a2b3-41a2-997c-733b18368474"}) == ""


def test_empty_or_missing_values_skipped():
    assert _request_subject("SOME_OP", {"hostname": "", "name": None, "ip": []}) == ""


def test_non_dict_data_returns_empty():
    assert _request_subject("SOME_OP", None) == ""
    assert _request_subject("SOME_OP", "not-a-dict") == ""
    assert _request_subject("SOME_OP", [{"hostname": "x"}]) == ""


def test_secret_fields_are_not_the_subject():
    # Secret-bearing fields aren't in the allowlist, so a payload carrying only
    # a secret yields no subject (never echoes a secret into the log line).
    assert _request_subject("SPOKE_UPDATE_SESSION_KEY", {"secret": "s", "token": "t"}) == ""


def test_tenant_id_is_a_valid_subject():
    assert _request_subject("SOME_OP", {"tenant_id": "acme"}) == "tenant_id=acme"


def test_never_raises_on_garbage():
    # Defensive: a bad payload must not break the timeout log path.
    class _Boom:
        def get(self, *a):
            raise RuntimeError("nope")
    assert _request_subject("SOME_OP", _Boom()) == ""