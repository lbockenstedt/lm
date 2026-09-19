"""Tests for the LM_FERNET_KEY rotation script (security/rotate_fernet_key.py).

Covers: round-trip re-encryption under the new key, plain/empty files are
skipped (not clobbered), backups are written, .env is updated + backed up, and
--dry-run writes nothing.
"""

import json

import pytest
from cryptography.fernet import Fernet

# conftest puts core/src on sys.path so `security.*` imports flat (see other tests).
from security.rotate_fernet_key import rotate, _resolve_old_key  # noqa: E402


def _encrypt(key: str, data: dict) -> bytes:
    return Fernet(key.encode()).encrypt(json.dumps(data, sort_keys=True).encode())


def test_resolve_old_key_from_env(monkeypatch):
    k = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", k)
    assert _resolve_old_key(env_file=None) == k


def test_resolve_old_key_from_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("LM_FERNET_KEY", raising=False)
    k = Fernet.generate_key().decode()
    env = tmp_path / ".env"
    env.write_text(f"FOO=bar\nLM_FERNET_KEY={k}\nBAZ=qux\n")
    assert _resolve_old_key(env_file=str(env)) == k


def test_resolve_old_key_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("LM_FERNET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        _resolve_old_key(env_file=str(tmp_path / "nope.env"))


def test_rotate_reencrypts_under_new_key(tmp_path, monkeypatch):
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    state = tmp_path / "state"
    state.mkdir()
    env = tmp_path / ".env"
    env.write_text(f"LM_FERNET_KEY={old_key}\n")

    # Two encrypted state files.
    enc1 = {"tenant": "acme", "n": 1}
    enc2 = {"keys": ["a", "b"]}
    (state / "system.json").write_bytes(_encrypt(old_key, enc1))
    (state / "tenants.json").write_bytes(_encrypt(old_key, enc2))
    # A plain recovery file (update_recovery state) — must be left untouched.
    plain = {"pending": True, "from_commit": "abc"}
    (state / "pending_update.json").write_text(json.dumps(plain))
    # An empty marker file — must be skipped.
    (state / "healthy").write_text("")

    rotated, skipped, new_key = rotate(str(state), str(env), apply_env=True, dry_run=False)

    assert rotated == 2
    assert skipped == 2
    assert new_key != old_key
    Fernet(new_key.encode())  # valid key

    # Encrypted files now decrypt with the NEW key and content is unchanged.
    assert json.loads(Fernet(new_key.encode()).decrypt((state / "system.json").read_bytes())) == enc1
    assert json.loads(Fernet(new_key.encode()).decrypt((state / "tenants.json").read_bytes())) == enc2
    # They no longer decrypt with the OLD key.
    with pytest.raises(Exception):
        Fernet(old_key.encode()).decrypt((state / "system.json").read_bytes())

    # Plain file untouched (still plain JSON, identical bytes).
    assert json.loads((state / "pending_update.json").read_text()) == plain
    # Empty marker still empty.
    assert (state / "healthy").read_text() == ""

    # Backups exist for the two rotated files (not for the plain/empty ones).
    assert (state / "system.json.pre-rotate.bak").exists()
    assert (state / "tenants.json.pre-rotate.bak").exists()
    assert not (state / "pending_update.json.pre-rotate.bak").exists()

    # .env updated to the new key; backup retains the old.
    assert f"LM_FERNET_KEY={new_key}" in env.read_text().splitlines()
    assert f"LM_FERNET_KEY={old_key}" in (tmp_path / ".env.pre-rotate.bak").read_text()


def test_rotate_dry_run_writes_nothing(tmp_path, monkeypatch):
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    state = tmp_path / "state"
    state.mkdir()
    env = tmp_path / ".env"
    env.write_text(f"LM_FERNET_KEY={old_key}\n")

    blob = _encrypt(old_key, {"x": 1})
    (state / "system.json").write_bytes(blob)

    rotated, skipped, new_key = rotate(str(state), str(env), apply_env=False, dry_run=True)

    assert rotated == 1
    assert skipped == 0
    # Nothing written: file bytes unchanged, no backup, .env unchanged.
    assert (state / "system.json").read_bytes() == blob
    assert not (state / "system.json.pre-rotate.bak").exists()
    assert env.read_text() == f"LM_FERNET_KEY={old_key}\n"
    # A new key is still generated (reported) even in dry-run.
    Fernet(new_key.encode())


def test_rotate_invalid_old_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LM_FERNET_KEY", "not-a-fernet-key")
    state = tmp_path / "state"
    state.mkdir()
    with pytest.raises(RuntimeError):
        rotate(str(state), str(tmp_path / ".env"), apply_env=False, dry_run=False)


def test_rotate_reads_old_key_from_env_file_when_env_unset(tmp_path, monkeypatch):
    """Production path: the admin's shell has no LM_FERNET_KEY (it lives in
    .env). Rotation must parse the old key from --env-file and still work —
    _build_decryptor sets the env from the resolved key before importing
    security.encryption (which is fail-closed at import)."""
    monkeypatch.delenv("LM_FERNET_KEY", raising=False)
    old_key = Fernet.generate_key().decode()
    state = tmp_path / "state"
    state.mkdir()
    env = tmp_path / ".env"
    env.write_text(f"HUB_URL=ws://x:8765\nLM_FERNET_KEY={old_key}\n")
    enc = {"a": 1}
    (state / "system.json").write_bytes(_encrypt(old_key, enc))

    rotated, skipped, new_key = rotate(str(state), str(env), apply_env=True, dry_run=False)

    assert rotated == 1
    assert skipped == 0
    assert json.loads(Fernet(new_key.encode()).decrypt((state / "system.json").read_bytes())) == enc
    assert f"LM_FERNET_KEY={new_key}" in env.read_text().splitlines()

# ── Credential Vault inner-token re-wrap ─────────────────────────────────────
# Vault secrets are DOUBLE-encrypted: the payload is Fernet-encrypted with the
# hub key in its own right, and THAT ciphertext is then stored either in the
# cloud vault or in the `blobs` map inside system.json. Re-encrypting
# system.json only replaces the outer layer, so rotation used to leave every
# inner token under the OLD key — alive only via LM_FERNET_KEY_PREVIOUS. When
# that fallback was later cleared, the whole vault became undecryptable.

def _sysdoc(secrets, blobs):
    return {"global_config": {"cred_vault": {"buckets": {},
                                             "secrets": secrets,
                                             "blobs": blobs}}}


def _rotate_sysdoc(tmp_path, monkeypatch, doc):
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    state = tmp_path / "state"
    state.mkdir()
    env = tmp_path / ".env"
    env.write_text(f"LM_FERNET_KEY={old_key}\n")
    (state / "system.json").write_bytes(_encrypt(old_key, doc))
    _, _, new_key = rotate(str(state), str(env), apply_env=True, dry_run=False)
    out = json.loads(Fernet(new_key.encode()).decrypt((state / "system.json").read_bytes()))
    return old_key, new_key, out, env


def test_rotate_rewraps_local_cred_vault_secret(tmp_path, monkeypatch):
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    payload = {"username": "root", "password": "s3cret"}
    inner = Fernet(old_key.encode()).encrypt(json.dumps(payload).encode()).decode()
    doc = _sysdoc({"lrb": {"Console": {"mode": "hub", "store": "local",
                                       "kv_name": "kv1", "type": "login"}}},
                  {"kv1": inner})

    state = tmp_path / "state"
    state.mkdir()
    env = tmp_path / ".env"
    env.write_text(f"LM_FERNET_KEY={old_key}\n")
    (state / "system.json").write_bytes(_encrypt(old_key, doc))
    _, _, new_key = rotate(str(state), str(env), apply_env=True, dry_run=False)

    out = json.loads(Fernet(new_key.encode()).decrypt((state / "system.json").read_bytes()))
    tok = out["global_config"]["cred_vault"]["blobs"]["kv1"]
    # The INNER token now decrypts under the NEW key with the payload intact...
    assert json.loads(Fernet(new_key.encode()).decrypt(tok.encode())) == payload
    # ...and is genuinely re-wrapped, not merely carried over.
    with pytest.raises(Exception):
        Fernet(old_key.encode()).decrypt(tok.encode())


def test_rotate_leaves_psk_mode_secret_alone(tmp_path, monkeypatch):
    # psk-mode payloads are keyed by a pass-phrase, not the hub key — rotation
    # must not touch them (and must not report them as failures).
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    psk_token = Fernet(Fernet.generate_key()).encrypt(b'{"k":"v"}').decode()
    doc = _sysdoc({"dxp": {"Cluster Key": {"mode": "psk", "store": "local",
                                           "kv_name": "kvp"}}},
                  {"kvp": psk_token})

    state = tmp_path / "state"
    state.mkdir()
    env = tmp_path / ".env"
    env.write_text(f"LM_FERNET_KEY={old_key}\n")
    (state / "system.json").write_bytes(_encrypt(old_key, doc))
    _, _, new_key = rotate(str(state), str(env), apply_env=True, dry_run=False)

    out = json.loads(Fernet(new_key.encode()).decrypt((state / "system.json").read_bytes()))
    assert out["global_config"]["cred_vault"]["blobs"]["kvp"] == psk_token


def test_rotate_warns_about_cloud_vault_backed_secrets(tmp_path, monkeypatch, capsys):
    # These live outside this host, so the offline tool cannot re-wrap them.
    # It must say so loudly and keep LM_FERNET_KEY_PREVIOUS as the lifeline —
    # this is exactly the case that silently broke a production vault.
    doc = _sysdoc({"ra": {"default admin": {"mode": "hub", "store": "kv",
                                            "kv_name": "kvx"}},
                   "lrb": {"HE.NET": {"mode": "hub", "kv_name": "kvy"}}},  # no marker => kv
                  {})
    old_key, new_key, _out, env = _rotate_sysdoc(tmp_path, monkeypatch, doc)

    msg = capsys.readouterr().out
    assert "2 live in the cloud vault" in msg
    assert "DO NOT remove LM_FERNET_KEY_PREVIOUS" in msg
    assert f"LM_FERNET_KEY_PREVIOUS={old_key}" in env.read_text()
