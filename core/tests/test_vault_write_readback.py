"""Cloud vaults are not read-your-writes — pin the guards that hide that.

Storing a credential and immediately using it is the normal flow (the operator
saves a token, then clicks "Fetch now"), but neither backend guarantees the
value is readable the instant the write returns:

* OCI ``CreateSecret`` returns 200 with the secret in ``CREATING``; the secret
  bundle 404s until it reaches ``ACTIVE`` — observed several seconds later.
* Azure can briefly 404 a freshly created or soft-delete-recovered secret while
  it propagates.

So the wait lives in the provider-agnostic layer (``cloud_vault.set_secret``)
rather than only in the OCI client: any backend added later inherits it. The
OCI client additionally waits on the precise ``ACTIVE`` signal so the generic
read-back confirmation normally succeeds on its first attempt.

Both guards are best-effort by design: on timeout they log and return rather
than raise, because the secret IS written — only its visibility lagged, and
failing the save would discard a credential the operator just typed.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cloud_vault  # noqa: E402


class _Hub:
    def __init__(self, gc):
        self.state = type("S", (), {"system_state": {"global_config": gc}})()


_OCI_GC = {"oci_vault": {"enabled": True, "compartment_id": "c", "vault_id": "v"}}


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Keep the retry loops instant so the tests don't pay the real backoff."""
    async def fake_sleep(_):
        return None
    monkeypatch.setattr(cloud_vault.asyncio, "sleep", fake_sleep)


# ── the write is not reported done until the value reads back ────────────────

@pytest.mark.asyncio
async def test_set_secret_retries_until_the_value_is_readable(monkeypatch):
    """The exact production failure: the read 404s at first, then succeeds."""
    reads = {"n": 0}

    async def fake_get(hub, name, http=None):
        reads["n"] += 1
        return "tok" if reads["n"] >= 3 else None

    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: "oci")
    monkeypatch.setattr(cloud_vault, "get_secret", fake_get)
    sys.modules["oci_vault"] = type("M", (), {
        "get_oci_config": staticmethod(lambda hub: None),
        "set_secret": staticmethod(_async_return("ocid1.secret")),
    })

    out = await cloud_vault.set_secret(_Hub(_OCI_GC), "n", "v", delay=0)
    assert out == "ocid1.secret"
    assert reads["n"] == 3, "must keep polling until the secret reads back"


@pytest.mark.asyncio
async def test_set_secret_does_not_raise_when_readback_times_out(monkeypatch, caplog):
    """The secret IS stored; a slow vault must not discard the operator's write."""
    async def never(hub, name, http=None):
        return None

    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: "oci")
    monkeypatch.setattr(cloud_vault, "get_secret", never)
    sys.modules["oci_vault"] = type("M", (), {
        "get_oci_config": staticmethod(lambda hub: None),
        "set_secret": staticmethod(_async_return("ocid1.secret")),
    })

    with caplog.at_level("WARNING"):
        out = await cloud_vault.set_secret(_Hub(_OCI_GC), "n", "v", attempts=2, delay=0)
    assert out == "ocid1.secret"
    assert "not readable" in caplog.text


@pytest.mark.asyncio
async def test_a_transient_read_error_is_retried_not_fatal(monkeypatch):
    """A backend hiccup mid-propagation is indistinguishable from 'not yet
    there' — it must be treated as a retry, not surfaced to the caller."""
    reads = {"n": 0}

    async def flaky(hub, name, http=None):
        reads["n"] += 1
        if reads["n"] == 1:
            raise RuntimeError("connection reset")
        return "tok"

    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: "oci")
    monkeypatch.setattr(cloud_vault, "get_secret", flaky)
    sys.modules["oci_vault"] = type("M", (), {
        "get_oci_config": staticmethod(lambda hub: None),
        "set_secret": staticmethod(_async_return("id")),
    })

    assert await cloud_vault.set_secret(_Hub(_OCI_GC), "n", "v", delay=0) == "id"
    assert reads["n"] == 2


# ── the guard is provider-agnostic, not OCI-only ─────────────────────────────

@pytest.mark.asyncio
async def test_azure_writes_are_confirmed_too(monkeypatch):
    """Regression guard: the wait must not be buried in the OCI client, or
    Azure deployments keep racing."""
    reads = {"n": 0}

    async def fake_get(hub, name, http=None):
        reads["n"] += 1
        return "tok" if reads["n"] >= 2 else None

    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: "azure")
    monkeypatch.setattr(cloud_vault, "get_secret", fake_get)
    sys.modules["key_vault"] = type("M", (), {
        "set_secret": staticmethod(_async_return({"id": "https://kv/secrets/n"})),
    })
    sys.modules["security.oidc"] = type("M", (), {
        "get_oidc_config": staticmethod(lambda hub: None),
    })

    gc = {"key_vault": {"enabled": True, "vault_url": "https://kv.vault.azure.net"}}
    await cloud_vault.set_secret(_Hub(gc), "n", "v", delay=0)
    assert reads["n"] == 2, "the Azure path must confirm read-back as well"


@pytest.mark.asyncio
async def test_confirmation_can_be_opted_out(monkeypatch):
    """Callers that only write (and never immediately read) shouldn't pay it."""
    reads = {"n": 0}

    async def fake_get(hub, name, http=None):
        reads["n"] += 1
        return "tok"

    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: "oci")
    monkeypatch.setattr(cloud_vault, "get_secret", fake_get)
    sys.modules["oci_vault"] = type("M", (), {
        "get_oci_config": staticmethod(lambda hub: None),
        "set_secret": staticmethod(_async_return("id")),
    })

    await cloud_vault.set_secret(_Hub(_OCI_GC), "n", "v", confirm=False)
    assert reads["n"] == 0


@pytest.mark.asyncio
async def test_no_vault_still_raises_before_any_waiting(monkeypatch):
    """The 'no vault enabled' contract must be unchanged by the retry work."""
    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: None)
    with pytest.raises(RuntimeError, match="no cloud vault"):
        await cloud_vault.set_secret(_Hub({}), "n", "v")


def _async_return(value):
    async def _f(*a, **k):
        return value
    return _f
