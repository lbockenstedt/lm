"""Tests for the Global-Admin last-resort pass-phrase reset
(``cred_vault.reset_bucket_psk``) and the bucket-metadata it relies on.

Background: ``set_bucket_psk`` can only ROTATE a pass-phrase — it verifies the
old one first. That left a lost/corrupted pass-phrase with no recovery at all:
the bucket became permanently unusable through the UI even when nothing in it
was actually encrypted under that pass-phrase.

The invariant under test: ``hub``-mode secrets are keyed on the hub Fernet key,
NOT the pass-phrase, so a reset must keep them intact; ``psk``-mode secrets are
already undecryptable once the pass-phrase is lost, so they may only be
discarded, and only when the caller explicitly confirms.
"""
import asyncio

import pytest

import cred_vault as cv
from _fakes import FakeHub, FakeState


@pytest.fixture()
def hub(monkeypatch):
    state = FakeState(system_state={"global_config": {
        "key_vault": {"vault_url": "https://vault.example/"}}})
    h = FakeHub(state=state)
    store: dict = {}

    async def _set(hub, name, value, http=None):
        store[name] = value
        return f"id/{name}"

    async def _get(hub, name, http=None):
        return store.get(name)

    async def _del(hub, name, http=None):
        store.pop(name, None)
        return True

    monkeypatch.setattr(cv._cv, "active_provider", lambda _h: "azure")
    monkeypatch.setattr(cv._cv, "set_secret", _set)
    monkeypatch.setattr(cv._cv, "get_secret", _get)
    monkeypatch.setattr(cv._cv, "delete_secret", _del)
    h._kv_store = store
    return h


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _seed(hub, bucket, psk="original-pass", *, hub_mode=(), psk_mode=()):
    run(cv.set_bucket_psk(hub, bucket, psk))
    for name in hub_mode:
        run(cv.put_secret(hub, bucket, name, {"password": f"v-{name}"},
                          mode="hub", psk=psk))
    for name in psk_mode:
        run(cv.put_secret(hub, bucket, name, {"password": f"v-{name}"},
                          mode="psk", psk=psk))


# ── count_psk_secrets ────────────────────────────────────────────────────────
def test_count_psk_secrets_ignores_hub_mode(hub):
    _seed(hub, "t1", hub_mode=("a", "b"), psk_mode=("c",))
    assert cv.count_psk_secrets(hub, "t1") == 1


def test_count_psk_secrets_empty_bucket(hub):
    assert cv.count_psk_secrets(hub, "nope") == 0


# ── the no-data-loss case (this is the real-world one) ───────────────────────
def test_reset_keeps_hub_mode_secrets_and_needs_no_confirmation(hub):
    # A bucket holding ONLY hub-mode secrets (e.g. the Global Admin slot with an
    # API key + a DNS credential) resets with zero data loss, so it must not
    # demand a destructive confirmation.
    _seed(hub, "__admin__", hub_mode=("HE.NET", "NetBox API"))
    res = run(cv.reset_bucket_psk(hub, "__admin__", "brand-new-pass", actor="lrb"))
    assert res["destroyed"] == []
    assert res["kept"] == 2
    names = {s["name"] for s in cv.list_secrets(hub, "__admin__")}
    assert names == {"HE.NET", "NetBox API"}


def test_reset_makes_the_new_passphrase_the_valid_one(hub):
    _seed(hub, "__admin__", psk="lost-forever", hub_mode=("NetBox API",))
    run(cv.reset_bucket_psk(hub, "__admin__", "brand-new-pass"))
    assert cv.verify_psk(hub, "__admin__", "brand-new-pass") is True
    assert cv.verify_psk(hub, "__admin__", "lost-forever") is False


def test_hub_mode_secret_still_decrypts_after_reset(hub):
    # The whole point: hub-mode values survive because they were never encrypted
    # with the pass-phrase. Automation keeps working across a reset.
    _seed(hub, "__admin__", psk="lost-forever", hub_mode=("NetBox API",))
    run(cv.reset_bucket_psk(hub, "__admin__", "brand-new-pass"))
    val = run(cv.automation_get(hub, "__admin__", "NetBox API"))
    assert val["password"] == "v-NetBox API"


# ── the destructive case ─────────────────────────────────────────────────────
def test_reset_refuses_psk_secrets_without_confirmation(hub):
    _seed(hub, "t1", hub_mode=("keep",), psk_mode=("doomed",))
    with pytest.raises(cv.CredVaultError) as e:
        run(cv.reset_bucket_psk(hub, "t1", "brand-new-pass"))
    assert "doomed" in str(e.value)
    # Nothing changed — the old pass-phrase is still the valid one.
    assert cv.verify_psk(hub, "t1", "original-pass") is True
    assert len(cv.list_secrets(hub, "t1")) == 2


def test_reset_with_confirmation_drops_only_psk_secrets(hub):
    _seed(hub, "t1", hub_mode=("keep",), psk_mode=("doomed",))
    res = run(cv.reset_bucket_psk(hub, "t1", "brand-new-pass",
                                  destroy_psk_secrets=True))
    assert res["destroyed"] == ["doomed"]
    assert res["kept"] == 1
    assert [s["name"] for s in cv.list_secrets(hub, "t1")] == ["keep"]
    assert cv.verify_psk(hub, "t1", "brand-new-pass") is True


def test_reset_rejects_short_passphrase(hub):
    _seed(hub, "t1", hub_mode=("keep",))
    with pytest.raises(cv.CredVaultError):
        run(cv.reset_bucket_psk(hub, "t1", "short"))
    # The original pass-phrase must survive a rejected reset.
    assert cv.verify_psk(hub, "t1", "original-pass") is True


def test_reset_works_on_bucket_with_no_passphrase_yet(hub):
    # Recovering a half-configured bucket must not blow up.
    res = run(cv.reset_bucket_psk(hub, "fresh", "brand-new-pass"))
    assert res == {"bucket": "fresh", "destroyed": [], "kept": 0}
    assert cv.bucket_has_psk(hub, "fresh") is True


def test_rotate_still_requires_the_old_passphrase(hub):
    # The reset path must not have weakened the normal rotation guard.
    _seed(hub, "t1", hub_mode=("keep",))
    with pytest.raises(cv.CredVaultError):
        run(cv.set_bucket_psk(hub, "t1", "brand-new-pass", old_psk="wrong"))
