"""POST /setup/key-vault/configure-tier1 and its _upsert_env_vars helper —
writes LM_FERNET_KEY_KV_SECRET/LM_KEYVAULT_URL into the hub's own .env and
restarts the hub. Security-sensitive: this writes to the file carrying every
other hub secret (including LM_FERNET_KEY), so the tests focus heavily on
"every other line is untouched" and "a crash mid-write can't corrupt it."
"""
import os
import tempfile
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.key_vault as kv_route
from routes.key_vault import _upsert_env_vars, register


# ── _upsert_env_vars (pure file-editing logic) ───────────────────────────────

@pytest.fixture
def env_file(tmp_path):
    p = tmp_path / ".env"
    p.write_text(
        "# a comment, must survive\n"
        "\n"
        "LM_FERNET_KEY=super-secret-do-not-touch\n"
        "LM_ALLOW_PLAINTEXT_FALLBACK=1\n"
    )
    return str(p)


def test_upsert_appends_new_keys(env_file):
    _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "lm-fernet-key",
                                "LM_KEYVAULT_URL": "https://v.vault.azure.net/"})
    content = open(env_file).read()
    assert "LM_FERNET_KEY_KV_SECRET=lm-fernet-key" in content
    assert "LM_KEYVAULT_URL=https://v.vault.azure.net/" in content


def test_upsert_never_touches_other_lines(env_file):
    _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "lm-fernet-key",
                                "LM_KEYVAULT_URL": "https://v.vault.azure.net/"})
    content = open(env_file).read()
    assert "LM_FERNET_KEY=super-secret-do-not-touch" in content
    assert "LM_ALLOW_PLAINTEXT_FALLBACK=1" in content
    assert "# a comment, must survive" in content


def test_upsert_replaces_an_existing_key_in_place(env_file):
    _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "first"})
    _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "second"})
    content = open(env_file).read()
    assert "LM_FERNET_KEY_KV_SECRET=second" in content
    assert "LM_FERNET_KEY_KV_SECRET=first" not in content
    # Only one line for this key — not appended a second time.
    assert content.count("LM_FERNET_KEY_KV_SECRET=") == 1


def test_upsert_sets_restrictive_permissions(env_file):
    os.chmod(env_file, 0o600)
    _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "x"})
    mode = os.stat(env_file).st_mode & 0o777
    assert mode == 0o600


def test_upsert_is_atomic_no_temp_file_left_behind(env_file):
    directory = os.path.dirname(env_file)
    before = set(os.listdir(directory))
    _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "x"})
    after = set(os.listdir(directory))
    assert after - before == set()  # the temp file was renamed away, not left sitting


def test_upsert_cleans_up_temp_file_on_write_failure(env_file, monkeypatch):
    """If the write itself fails partway, no stray temp file or corrupted
    .env should remain — original content must survive untouched."""
    original_content = open(env_file).read()

    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(kv_route.os, "fdopen", _boom)
    with pytest.raises(OSError):
        _upsert_env_vars(env_file, {"LM_FERNET_KEY_KV_SECRET": "x"})
    assert open(env_file).read() == original_content
    directory = os.path.dirname(env_file)
    assert not any(f.startswith(".env.tmp-") for f in os.listdir(directory))


# ── route ────────────────────────────────────────────────────────────────────

class _FakeHub:
    def __init__(self, restart_result="lm.service restarting", restart_raises=None,
                has_restart=True):
        self._restart_calls = 0
        self._restart_result = restart_result
        self._restart_raises = restart_raises
        if has_restart:
            self._hub_self_restart = self._do_restart

    async def _do_restart(self):
        self._restart_calls += 1
        if self._restart_raises:
            raise self._restart_raises
        return self._restart_result


def _build(hub):
    app = FastAPI()
    register(app, hub, SimpleNamespace())
    return TestClient(app)


def test_route_requires_both_fields():
    c = _build(_FakeHub())
    r = c.post("/setup/key-vault/configure-tier1", json={"secret_name": "x"})
    assert r.status_code == 400
    r = c.post("/setup/key-vault/configure-tier1", json={"vault_url": "https://x/"})
    assert r.status_code == 400


def test_route_rejects_newline_injection_attempt(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("LM_FERNET_KEY=real-key\n")
    monkeypatch.setattr(kv_route, "_env_candidates", lambda: [str(env_path)])
    c = _build(_FakeHub())
    r = c.post("/setup/key-vault/configure-tier1", json={
        "secret_name": "lm-fernet-key\nLM_ALLOW_PLAINTEXT_FALLBACK=0",
        "vault_url": "https://v.vault.azure.net/"})
    assert r.status_code == 400
    # Nothing was written — the file is untouched.
    assert env_path.read_text() == "LM_FERNET_KEY=real-key\n"


def test_route_503_when_no_env_file_found(monkeypatch):
    monkeypatch.setattr(kv_route, "_env_candidates", lambda: ["/nonexistent/.env"])
    c = _build(_FakeHub())
    r = c.post("/setup/key-vault/configure-tier1", json={
        "secret_name": "lm-fernet-key", "vault_url": "https://v.vault.azure.net/"})
    assert r.status_code == 503


def test_route_writes_env_and_restarts_on_success(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("LM_FERNET_KEY=real-key\n")
    monkeypatch.setattr(kv_route, "_env_candidates", lambda: [str(env_path)])
    hub = _FakeHub()
    c = _build(hub)
    r = c.post("/setup/key-vault/configure-tier1", json={
        "secret_name": "lm-fernet-key", "vault_url": "https://v.vault.azure.net/"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert hub._restart_calls == 1
    content = env_path.read_text()
    assert "LM_FERNET_KEY_KV_SECRET=lm-fernet-key" in content
    assert "LM_KEYVAULT_URL=https://v.vault.azure.net/" in content
    assert "LM_FERNET_KEY=real-key" in content  # untouched


def test_route_still_reports_ok_when_restart_unavailable(monkeypatch, tmp_path):
    """The write is the load-bearing part — a hub without self-restart
    support must not report failure for a successful .env write."""
    env_path = tmp_path / ".env"
    env_path.write_text("LM_FERNET_KEY=real-key\n")
    monkeypatch.setattr(kv_route, "_env_candidates", lambda: [str(env_path)])
    hub = _FakeHub(has_restart=False)
    c = _build(hub)
    r = c.post("/setup/key-vault/configure-tier1", json={
        "secret_name": "lm-fernet-key", "vault_url": "https://v.vault.azure.net/"})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "manually" in r.json()["message"]


def test_route_still_reports_ok_when_restart_raises(monkeypatch, tmp_path):
    """The write already succeeded by the time restart is attempted — a
    restart-scheduling failure must not roll that back or report an error."""
    env_path = tmp_path / ".env"
    env_path.write_text("LM_FERNET_KEY=real-key\n")
    monkeypatch.setattr(kv_route, "_env_candidates", lambda: [str(env_path)])
    hub = _FakeHub(restart_raises=RuntimeError("sudo unavailable"))
    c = _build(hub)
    r = c.post("/setup/key-vault/configure-tier1", json={
        "secret_name": "lm-fernet-key", "vault_url": "https://v.vault.azure.net/"})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "manually" in r.json()["message"]
    # The write must have happened regardless.
    assert "LM_FERNET_KEY_KV_SECRET=lm-fernet-key" in env_path.read_text()
