"""Tests for reading what is ACTUALLY on the OCI NSG.

Reported: the OCI NSG setup screen showed nothing live even though the NSG had
rules. Cause: the live read filtered to rules carrying LM's managed marker, so
ingress rules the operator had created by hand in the OCI console were
invisible and the screen reported 0 prefixes — indistinguishable from a failed
read.

Reconcile must STILL only ever touch marked rules; the split here is for
visibility only.
"""
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import oci_nsg  # noqa: E402


OCCFG = {"nsg_id": "ocid1.nsg.oc1..aaa", "region": "us-ashburn-1", "dest_port": "443"}


def _cfg():
    return oci_nsg.OciConfig({
        "tenancy_ocid": "ocid1.tenancy.oc1..a", "user_ocid": "ocid1.user.oc1..b",
        "fingerprint": "fd:48:43:b1:9c:a6:7f:5f:e3:4e:f7:a4:a4:b2:1a:70",
        "key_path": "/tmp/k.pem", "region": "us-ashburn-1"})


def _rules():
    mk = lambda src, desc: {"direction": "INGRESS", "source": src, "description": desc}
    return [
        mk("10.0.0.1/32", f"Managed by LM hub ({oci_nsg._MANAGED_MARKER}) — do not edit"),
        mk("10.0.0.2/32", f"Managed by LM hub ({oci_nsg._MANAGED_MARKER}) — do not edit"),
        mk("203.0.113.0/24", "office range - created by hand"),
        mk("198.51.100.7/32", ""),                       # no description at all
        {"direction": "EGRESS", "source": "0.0.0.0/0", "description": "out"},
    ]


def _client(rules, status=200):
    def handler(request):
        if rules is None:
            return httpx.Response(404, json={"code": "NotFound"})
        return httpx.Response(status, json=rules)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_hand_made_rules_are_reported_not_hidden():
    """The reported bug: these used to be invisible."""
    out = await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client(_rules()))
    assert out["unmanaged"] == ["198.51.100.7/32", "203.0.113.0/24"]


@pytest.mark.asyncio
async def test_managed_rules_still_identified_separately():
    out = await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client(_rules()))
    assert out["managed"] == ["10.0.0.1/32", "10.0.0.2/32"]


@pytest.mark.asyncio
async def test_egress_rules_excluded():
    out = await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client(_rules()))
    assert "0.0.0.0/0" not in out["managed"] + out["unmanaged"]


@pytest.mark.asyncio
async def test_missing_nsg_returns_none():
    """Distinguish 'NSG absent' from 'NSG present but empty'."""
    assert await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client(None)) is None


@pytest.mark.asyncio
async def test_nsg_with_only_hand_made_rules_is_not_empty():
    """The exact reported shape: no LM rules yet, several manual ones."""
    manual = [r for r in _rules() if not oci_nsg._is_managed(r)]
    out = await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client(manual))
    assert out["managed"] == []
    assert len(out["unmanaged"]) == 2, "screen must not look like a failed read"


@pytest.mark.asyncio
async def test_get_allowlist_still_returns_only_managed():
    """Reconcile depends on this — it must not start seeing manual rules,
    or it would delete them."""
    assert await oci_nsg.get_allowlist(_cfg(), OCCFG, http=_client(_rules())) == \
        ["10.0.0.1/32", "10.0.0.2/32"]


@pytest.mark.asyncio
async def test_http_error_propagates():
    with pytest.raises(oci_nsg.OciNsgError):
        await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client([], status=401))


@pytest.mark.asyncio
async def test_duplicate_sources_deduped():
    dup = [{"direction": "INGRESS", "source": "203.0.113.0/24", "description": "a"},
           {"direction": "INGRESS", "source": "203.0.113.0/24", "description": "b"}]
    out = await oci_nsg.get_live_prefixes(_cfg(), OCCFG, http=_client(dup))
    assert out["unmanaged"] == ["203.0.113.0/24"]
