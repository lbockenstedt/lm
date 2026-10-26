"""fetch_tenant_prefixes: an empty-but-successful NetBox reply is a tenant with
no prefixes (normal) and logs at INFO; an error reply still WARNs. LM-HUB
logged ~380 warnings / 6h for 'shared' and 'stme-cordelia', which have none."""
import logging

import pytest

from access import fetch_tenant_prefixes
from _fakes import FakeState


class _Hub:
    def __init__(self, reply):
        self.state = FakeState(tenants={"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}})
        self._reply = reply

    def get_spoke_by_type(self, module_type):
        return "netbox-spoke-1" if module_type == "ipam" else None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        return {"payload": {"data": self._reply}}

    def warm_get(self, *a, **k):
        return None


def _levels(caplog):
    return {r.levelno for r in caplog.records if "fetch_tenant_prefixes" in r.getMessage()}


@pytest.mark.asyncio
async def test_empty_success_is_info(caplog):
    with caplog.at_level(logging.INFO):
        out = await fetch_tenant_prefixes(_Hub({"status": "SUCCESS", "prefixes": []}), "acme")
    assert out == []
    assert _levels(caplog) == {logging.INFO}


@pytest.mark.asyncio
async def test_error_reply_still_warns(caplog):
    with caplog.at_level(logging.INFO):
        out = await fetch_tenant_prefixes(_Hub({"status": "ERROR", "message": "boom"}), "acme")
    assert out == []
    assert logging.WARNING in _levels(caplog)
