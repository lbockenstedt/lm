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