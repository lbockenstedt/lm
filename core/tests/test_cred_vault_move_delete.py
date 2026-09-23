"""Tests for moving a secret between buckets and deleting a bucket outright.

Background: a bucket could be created by typing a free-text name but never
removed — ``list_buckets`` derives from the pass-phrase records UNION the secret
records — so a mistyped bucket lingered in every Global Admin's picker forever.
Worse, a bucket whose name matches no tenant is a dead end: tenant-scoped code
matches credential sets by tenant id, so nothing can ever reference what is
stored there.

The invariants under test:

* A move must be a metadata RE-POINT, not a copy-and-delete — the at-rest blob
  name is a random id, not derived from the bucket — so the value must still
  decrypt afterwards and must never exist in two buckets at once.
* ``hub``-mode secrets are keyed on the hub Fernet key, so a move needs no
  pass-phrase; ``psk``-mode secrets are keyed on the SOURCE bucket, so a move
  must re-encrypt under the destination's pass-phrase and requires both.
* Deleting must never silently destroy credentials, and must refuse the
  ``__admin__`` slot, which is load-bearing infrastructure.
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


def _seed(hub, bucket, psk="pass-phrase", *, hub_mode=(), psk_mode=()):
    run(cv.set_bucket_psk(hub, bucket, psk))
    for name in hub_mode:
        run(cv.put_secret(hub, bucket, name, {"password": f"v-{name}"},
                          mode="hub", psk=psk))
    for name in psk_mode:
        run(cv.put_secret(hub, bucket, name, {"password": f"v-{name}"},
                          mode="psk", psk=psk))


def _meta(hub):
    return hub.state.system_state["global_config"]["cred_vault"]


# ── move_secret: hub mode ────────────────────────────────────────────────────
def test_move_hub_secret_needs_no_passphrase(hub):
    _seed(hub, "orphan", hub_mode=("acct",))
    _seed(hub, "shared", psk="other-pass")

    run(cv.move_secret(hub, "orphan", "acct", "shared", actor="gadmin"))

    assert "acct" not in _meta(hub)["secrets"].get("orphan", {})
    assert "acct" in _meta(hub)["secrets"]["shared"]


def test_move_keeps_value_decryptable(hub):
    _seed(hub, "orphan", hub_mode=("acct",))
    _seed(hub, "shared", psk="other-pass")

    run(cv.move_secret(hub, "orphan", "acct", "shared"))
    got = run(cv.automation_get(hub, "shared", "acct"))

    assert got["password"] == "v-acct"


def test_move_reuses_the_same_blob(hub):
    """A move must re-point metadata, never copy — otherwise the credential
    briefly exists twice (or not at all) in the backing store."""
    _seed(hub, "orphan", hub_mode=("acct",))
    _seed(hub, "shared", psk="other-pass")
    kv_name = _meta(hub)["secrets"]["orphan"]["acct"]["kv_name"]

    run(cv.move_secret(hub, "orphan", "acct", "shared"))

    assert _meta(hub)["secrets"]["shared"]["acct"]["kv_name"] == kv_name
    assert list(hub._kv_store) == [kv_name]


# ── move_secret: psk mode ────────────────────────────────────────────────────
def test_move_psk_secret_re_encrypts_under_destination(hub):
    _seed(hub, "orphan", psk="src-pass", psk_mode=("acct",))
    _seed(hub, "shared", psk="dst-pass")

    run(cv.move_secret(hub, "orphan", "acct", "shared",
                       psk="src-pass", to_psk="dst-pass"))
    got = run(cv.reveal_secret(hub, "shared", "acct", psk="dst-pass"))

    assert got["password"] == "v-acct"


def test_move_psk_secret_rejects_wrong_source_passphrase(hub):
    _seed(hub, "orphan", psk="src-pass", psk_mode=("acct",))
    _seed(hub, "shared", psk="dst-pass")

    with pytest.raises(cv.CredVaultError):
        run(cv.move_secret(hub, "orphan", "acct", "shared",
                           psk="wrong", to_psk="dst-pass"))
    assert "acct" in _meta(hub)["secrets"]["orphan"]


def test_move_psk_secret_rejects_wrong_destination_passphrase(hub):
    _seed(hub, "orphan", psk="src-pass", psk_mode=("acct",))
    _seed(hub, "shared", psk="dst-pass")

    with pytest.raises(cv.CredVaultError):
        run(cv.move_secret(hub, "orphan", "acct", "shared",
                           psk="src-pass", to_psk="wrong"))
    assert "acct" in _meta(hub)["secrets"]["orphan"]


# ── move_secret: guards ──────────────────────────────────────────────────────
def test_move_refuses_to_overwrite_existing_name(hub):
    """Silently clobbering a same-named credential in the destination would
    destroy a secret the operator never asked to touch."""
    _seed(hub, "orphan", hub_mode=("acct",))
    _seed(hub, "shared", psk="other-pass", hub_mode=("acct",))

    with pytest.raises(cv.CredVaultError):
        run(cv.move_secret(hub, "orphan", "acct", "shared"))
    assert run(cv.automation_get(hub, "shared", "acct"))["password"] == "v-acct"
    assert "acct" in _meta(hub)["secrets"]["orphan"]


def test_move_refuses_unknown_secret(hub):
    _seed(hub, "orphan", hub_mode=("acct",))
    _seed(hub, "shared", psk="other-pass")
    with pytest.raises(cv.CredVaultError):
        run(cv.move_secret(hub, "orphan", "missing", "shared"))


def test_move_refuses_same_bucket(hub):
    _seed(hub, "orphan", hub_mode=("acct",))
    with pytest.raises(cv.CredVaultError):
        run(cv.move_secret(hub, "orphan", "acct", "orphan"))


def test_move_refuses_destination_without_passphrase(hub):
    """A bucket with no pass-phrase cannot be opened in the UI, so moving into
    one would strand the credential a second time."""
    _seed(hub, "orphan", hub_mode=("acct",))
    with pytest.raises(cv.CredVaultError):
        run(cv.move_secret(hub, "orphan", "acct", "nowhere"))


# ── delete_bucket ────────────────────────────────────────────────────────────
def test_delete_empty_bucket(hub):
    _seed(hub, "orphan")
    run(cv.delete_bucket(hub, "orphan", actor="gadmin"))

    assert "orphan" not in _meta(hub)["buckets"]
    assert not any(b["bucket"] == "orphan" for b in cv.list_buckets(hub))


def test_delete_refuses_non_empty_without_confirmation(hub):
    _seed(hub, "orphan", hub_mode=("acct",))
    with pytest.raises(cv.CredVaultError):
        run(cv.delete_bucket(hub, "orphan"))
    assert "acct" in _meta(hub)["secrets"]["orphan"]


def test_delete_with_confirmation_removes_blobs(hub):
    """Leaving blobs behind in Key Vault would keep the credential material
    alive after the operator was told it was destroyed."""
    _seed(hub, "orphan", hub_mode=("acct",), psk_mode=("other",))

    res = run(cv.delete_bucket(hub, "orphan", confirm_destroy=True))

    assert sorted(res["destroyed"]) == ["acct", "other"]
    assert hub._kv_store == {}
    assert "orphan" not in _meta(hub)["secrets"]
    assert "orphan" not in _meta(hub)["buckets"]


def test_delete_refuses_admin_slot(hub):
    _seed(hub, cv.ADMIN_BUCKET)
    with pytest.raises(cv.CredVaultError):
        run(cv.delete_bucket(hub, cv.ADMIN_BUCKET, confirm_destroy=True))
    assert cv.ADMIN_BUCKET in _meta(hub)["buckets"]


def test_delete_refuses_unknown_bucket(hub):
    with pytest.raises(cv.CredVaultError):
        run(cv.delete_bucket(hub, "never-existed"))


def test_delete_after_move_is_the_rescue_path(hub):
    """End-to-end: the stranded credential survives, the dead bucket does not."""
    _seed(hub, "orphan", hub_mode=("Lab Admin",))
    _seed(hub, "shared", psk="shared-pass")

    run(cv.move_secret(hub, "orphan", "Lab Admin", "shared"))
    run(cv.delete_bucket(hub, "orphan"))

    assert run(cv.automation_get(hub, "shared", "Lab Admin"))["password"] == "v-Lab Admin"
    assert not any(b["bucket"] == "orphan" for b in cv.list_buckets(hub))
