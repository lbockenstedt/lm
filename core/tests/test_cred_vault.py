"""Unit tests for the per-tenant + admin-slot credential vault (``cred_vault``).

The Key Vault broker is replaced by an in-memory dict so the crypto/metadata
logic is exercised without any Azure calls.
"""
import asyncio

import pytest

import cred_vault as cv
from _fakes import FakeHub, FakeState


@pytest.fixture()
def hub(monkeypatch):
    state = FakeState(system_state={"global_config": {"key_vault": {"vault_url": "https://vault.example/"}}})
    h = FakeHub(state=state)

    store: dict[str, str] = {}

    async def _set(cfg, url, name, value, http=None):
        store[name] = value
        return f"id/{name}"

    async def _get(cfg, url, name, http=None):
        return store.get(name)

    async def _del(cfg, url, name, http=None):
        store.pop(name, None)
        return True

    monkeypatch.setattr(cv._kv, "set_secret", _set)
    monkeypatch.setattr(cv._kv, "get_secret", _get)
    monkeypatch.setattr(cv._kv, "delete_secret", _del)
    monkeypatch.setattr(cv, "get_oidc_config", lambda _h: object())
    h._kv_store = store
    return h


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_psk_set_and_verify(hub):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))
    assert cv.bucket_has_psk(hub, "t1")
    assert cv.verify_psk(hub, "t1", "hunter2pass")
    assert not cv.verify_psk(hub, "t1", "wrongpass")


def test_psk_too_short_rejected(hub):
    with pytest.raises(cv.CredVaultError):
        run(cv.set_bucket_psk(hub, "t1", "short"))


def test_put_requires_psk(hub):
    with pytest.raises(cv.CredVaultError):
        run(cv.put_secret(hub, "t1", "he", {"user": "a"}, psk="nope"))


def test_psk_mode_roundtrip_and_wrong_psk(hub):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))
    run(cv.put_secret(hub, "t1", "he", {"username": "u", "password": "p"},
                      mode="psk", sec_type="login", psk="hunter2pass", actor="admin"))
    got = run(cv.reveal_secret(hub, "t1", "he", psk="hunter2pass"))
    assert got == {"username": "u", "password": "p"}
    # wrong PSK on reveal is rejected at the gate
    with pytest.raises(cv.CredVaultError):
        run(cv.reveal_secret(hub, "t1", "he", psk="wrongpass"))
    # psk-mode secrets are NOT unattended-readable
    with pytest.raises(cv.CredVaultError):
        run(cv.automation_get(hub, "t1", "he"))


def test_hub_mode_automation_readable(hub):
    run(cv.set_bucket_psk(hub, cv.ADMIN_BUCKET, "adminpass1"))
    run(cv.put_secret(hub, cv.ADMIN_BUCKET, "he-dns", {"username": "x", "password": "y"},
                      mode="hub", psk="adminpass1", actor="admin"))
    # tooling reads with no pass-phrase
    assert run(cv.automation_get(hub, cv.ADMIN_BUCKET, "he-dns")) == {"username": "x", "password": "y"}
    # interactive reveal still requires the PSK
    assert run(cv.reveal_secret(hub, cv.ADMIN_BUCKET, "he-dns", psk="adminpass1")) == {"username": "x", "password": "y"}
    with pytest.raises(cv.CredVaultError):
        run(cv.reveal_secret(hub, cv.ADMIN_BUCKET, "he-dns", psk="wrongpass"))


def test_automation_list_by_type_multi_type(hub):
    """The console resolver now passes a tuple of types so ordinary ``login``
    secrets work as device-console logins alongside the dedicated ``console``
    type. Verify a multi-type scan returns both (automation-readable only)."""
    run(cv.set_bucket_psk(hub, cv.ADMIN_BUCKET, "adminpass1"))
    run(cv.put_secret(hub, cv.ADMIN_BUCKET, "dev-console",
                      {"username": "c", "password": "p1"},
                      mode="hub", sec_type="console", psk="adminpass1"))
    run(cv.put_secret(hub, cv.ADMIN_BUCKET, "switch-login",
                      {"username": "l", "password": "p2"},
                      mode="hub", sec_type="login", psk="adminpass1"))
    # A pass-phrase-only login must NOT be swept (hub can't read it unattended).
    run(cv.put_secret(hub, cv.ADMIN_BUCKET, "psk-login",
                      {"username": "z", "password": "p3"},
                      mode="psk", sec_type="login", psk="adminpass1"))
    names = {r["name"] for r in
             run(cv.automation_list_by_type(hub, ("console", "login"), [cv.ADMIN_BUCKET]))}
    assert names == {"dev-console", "switch-login"}
    # A single-type string still works (back-compat with other callers).
    only_console = {r["name"] for r in
                    run(cv.automation_list_by_type(hub, "console", [cv.ADMIN_BUCKET]))}
    assert only_console == {"dev-console"}


def test_ciphertext_never_plaintext_in_vault(hub):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))
    run(cv.put_secret(hub, "t1", "he", {"password": "s3cr3t-value"},
                      mode="psk", psk="hunter2pass"))
    assert all("s3cr3t-value" not in blob for blob in hub._kv_store.values())


def test_list_hides_values(hub):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))
    run(cv.put_secret(hub, "t1", "he", {"password": "s3cr3t-secret-value"},
                      mode="psk", sec_type="login", description="HE acct", psk="hunter2pass"))
    listed = cv.list_secrets(hub, "t1")
    assert listed[0]["name"] == "he"
    # field NAMES are non-secret metadata; the VALUE must never appear
    assert "s3cr3t-secret-value" not in str(listed)
    assert listed[0]["fields"] == ["password"]


def test_psk_rotation_rekeys_secrets(hub):
    run(cv.set_bucket_psk(hub, "t1", "oldpassword"))
    run(cv.put_secret(hub, "t1", "he", {"password": "keepme"}, mode="psk", psk="oldpassword"))
    run(cv.set_bucket_psk(hub, "t1", "newpassword", old_psk="oldpassword"))
    # old PSK no longer decrypts; new one does
    with pytest.raises(cv.CredVaultError):
        run(cv.reveal_secret(hub, "t1", "he", psk="oldpassword"))
    assert run(cv.reveal_secret(hub, "t1", "he", psk="newpassword")) == {"password": "keepme"}


def test_rotation_wrong_old_psk_rejected(hub):
    run(cv.set_bucket_psk(hub, "t1", "oldpassword"))
    with pytest.raises(cv.CredVaultError):
        run(cv.set_bucket_psk(hub, "t1", "newpassword", old_psk="bogus"))


def test_delete_removes_metadata_and_vault(hub):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))
    run(cv.put_secret(hub, "t1", "he", {"password": "x"}, mode="psk", psk="hunter2pass"))
    run(cv.delete_secret(hub, "t1", "he", psk="hunter2pass"))
    assert cv.list_secrets(hub, "t1") == []
    assert hub._kv_store == {}


def test_no_vault_falls_back_to_local_store(monkeypatch):
    """A vault-less hub (plain local VM) stores ciphertext in hub state and still
    roundtrips — the vault is used when available, never required."""
    state = FakeState(system_state={"global_config": {}})
    h = FakeHub(state=state)
    monkeypatch.setattr(cv, "get_oidc_config", lambda _h: object())
    # No Key Vault URL configured.
    assert cv._vault_available(h) is False

    run(cv.set_bucket_psk(h, "t1", "hunter2pass"))
    res = run(cv.put_secret(h, "t1", "he", {"username": "u", "password": "s3cr3t-value"},
                            mode="psk", sec_type="login", psk="hunter2pass", actor="admin"))
    assert res["store"] == "local"

    # ciphertext lives in hub state (local blobs), never as plaintext
    blobs = h.state.system_state["global_config"]["cred_vault"]["blobs"]
    assert blobs and all("s3cr3t-value" not in b for b in blobs.values())

    # roundtrips: reveal (PSK) + list marks it local + delete purges the blob
    assert run(cv.reveal_secret(h, "t1", "he", psk="hunter2pass")) == {"username": "u", "password": "s3cr3t-value"}
    assert cv.list_secrets(h, "t1")[0]["store"] == "local"
    run(cv.delete_secret(h, "t1", "he", psk="hunter2pass"))
    assert cv.list_secrets(h, "t1") == []
    assert h.state.system_state["global_config"]["cred_vault"]["blobs"] == {}


def test_no_vault_hub_mode_automation_readable(monkeypatch):
    """hub-mode secrets stored locally are still unattended-readable."""
    state = FakeState(system_state={"global_config": {}})
    h = FakeHub(state=state)
    monkeypatch.setattr(cv, "get_oidc_config", lambda _h: object())
    run(cv.set_bucket_psk(h, cv.ADMIN_BUCKET, "adminpass1"))
    run(cv.put_secret(h, cv.ADMIN_BUCKET, "console-auto-credentials",
                      {"credentials": [{"username": "a", "password": "b"}]},
                      mode="hub", sec_type="console", psk="adminpass1"))
    got = run(cv.automation_get(h, cv.ADMIN_BUCKET, "console-auto-credentials"))
    assert got == {"credentials": [{"username": "a", "password": "b"}]}


# ── crypto-engine-failure handling (regression) ─────────────────────────────
# A runtime scrypt failure must NOT masquerade as a wrong pass-phrase. Before
# this guard, verify_psk swallowed every exception as False, so a transient
# crypto/resource error looked like "incorrect pass-phrase" for every bucket and
# tenant at once, with no trace in the logs.

def test_verify_psk_engine_failure_raises_not_false(hub, monkeypatch):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))

    def _boom(_pw, _salt):
        raise MemoryError("scrypt: cannot allocate")

    monkeypatch.setattr(cv, "_scrypt", _boom)
    with pytest.raises(cv.CredVaultEngineError):
        cv.verify_psk(hub, "t1", "hunter2pass")


def test_verify_psk_engine_failure_is_logged(hub, monkeypatch, caplog):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))

    def _boom(_pw, _salt):
        raise MemoryError("scrypt: cannot allocate")

    monkeypatch.setattr(cv, "_scrypt", _boom)
    with caplog.at_level("ERROR"):
        with pytest.raises(cv.CredVaultEngineError):
            cv.verify_psk(hub, "t1", "hunter2pass")
    assert any("ENGINE FAILURE" in r.getMessage() for r in caplog.records)


def test_require_psk_engine_failure_distinct_from_mismatch(hub, monkeypatch):
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))

    # A genuine mismatch stays a plain CredVaultError, not an engine error.
    with pytest.raises(cv.CredVaultError) as mismatch:
        cv._require_psk(hub, "t1", "wrongpass")
    assert not isinstance(mismatch.value, cv.CredVaultEngineError)
    assert "incorrect pass-phrase" in str(mismatch.value)

    # An engine failure surfaces as the distinct engine error, NOT a mismatch.
    def _boom(_pw, _salt):
        raise RuntimeError("openssl scrypt backend error")

    monkeypatch.setattr(cv, "_scrypt", _boom)
    with pytest.raises(cv.CredVaultEngineError) as engine:
        cv._require_psk(hub, "t1", "hunter2pass")
    assert "server crypto error" in str(engine.value)


def test_verify_psk_no_record_or_empty_still_false(hub):
    # Absent record / empty pass-phrase remain a plain False (not an engine error).
    assert cv.verify_psk(hub, "t1", "anything") is False
    run(cv.set_bucket_psk(hub, "t1", "hunter2pass"))
    assert cv.verify_psk(hub, "t1", "") is False
