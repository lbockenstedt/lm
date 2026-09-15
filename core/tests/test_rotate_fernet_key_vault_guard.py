"""rotate_fernet_key must refuse to run on a Key-Vault-backed hub.

``HubEncryption._resolve_primary_key`` prefers Azure Key Vault and falls back to
``LM_FERNET_KEY`` **silently** when the vault is unreachable. This rotator is
env-only and cannot write the new key back to the vault, so on a vault-backed
hub a "successful" rotation is a time-bomb: state gets re-encrypted under the
new env key while the vault still holds the OLD one, and the moment the vault
becomes reachable the hub loads the old key and every rotated file is
undecryptable. That is the exact failure that previously stranded
system.json/tenants.json.

Observed on the live hub: LM_FERNET_KEY_KV_SECRET='lm-fernet-key' and
LM_KEYVAULT_URL were both set while the vault fetch failed, so the hub was
quietly running on the env key -- a rotation there would have looked fine.
"""

import os
import sys

import pytest
from cryptography.fernet import Fernet

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from security import rotate_fernet_key as R  # noqa: E402

KV_VARS = ("LM_FERNET_KEY_KV_SECRET", "LM_KEYVAULT_URL")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in KV_VARS:
        monkeypatch.delenv(var, raising=False)


def _env_file(tmp_path, *, kv=False, key=None):
    lines = ["LM_FERNET_KEY=%s" % (key or Fernet.generate_key().decode())]
    if kv:
        lines += ["LM_FERNET_KEY_KV_SECRET=lm-fernet-key",
                  "LM_KEYVAULT_URL=https://lm-vault.vault.azure.net"]
    p = tmp_path / ".env"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


# ── detection ────────────────────────────────────────────────────────────────

def test_detects_key_vault_from_the_env_file():
    """The rotator normally runs with the hub STOPPED, so the vars are only on
    disk -- detection must not rely on the live process environment."""
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as d:
        envf = _env_file(pathlib.Path(d), kv=True)
        assert R._key_vault_source(envf) == "lm-fernet-key"


def test_detects_key_vault_from_the_live_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    monkeypatch.setenv("LM_KEYVAULT_URL", "https://lm-vault.vault.azure.net")
    assert R._key_vault_source(_env_file(tmp_path)) == "lm-fernet-key"


def test_no_key_vault_on_a_plain_env_hub(tmp_path):
    assert R._key_vault_source(_env_file(tmp_path)) is None


def test_secret_without_a_url_is_not_treated_as_vault_backed(tmp_path):
    """Both are required for a fetch; a half-configured hub is env-only and
    must stay rotatable."""
    p = tmp_path / ".env"
    p.write_text("LM_FERNET_KEY=%s\nLM_FERNET_KEY_KV_SECRET=lm-fernet-key\n"
                 % Fernet.generate_key().decode())
    assert R._key_vault_source(str(p)) is None


def test_quoted_values_are_parsed(tmp_path):
    p = tmp_path / ".env"
    p.write_text("LM_FERNET_KEY=%s\nLM_FERNET_KEY_KV_SECRET='lm-fernet-key'\n"
                 'LM_KEYVAULT_URL="https://lm-vault.vault.azure.net"\n'
                 % Fernet.generate_key().decode())
    assert R._key_vault_source(str(p)) == "lm-fernet-key"


# ── refusal ──────────────────────────────────────────────────────────────────

def test_rotate_refuses_on_a_vault_backed_hub(tmp_path):
    envf = _env_file(tmp_path, kv=True)
    state = tmp_path / "state"
    state.mkdir()
    with pytest.raises(RuntimeError) as err:
        R.rotate(str(state), envf, apply_env=True, dry_run=False, keys_dir=None)
    msg = str(err.value)
    assert "Key Vault" in msg
    assert "--allow-key-vault" in msg


def test_refusal_happens_even_for_dry_run(tmp_path):
    """A dry run that "succeeds" would wrongly signal the real run is safe."""
    envf = _env_file(tmp_path, kv=True)
    state = tmp_path / "state"
    state.mkdir()
    with pytest.raises(RuntimeError):
        R.rotate(str(state), envf, apply_env=False, dry_run=True, keys_dir=None)


def test_refusal_leaves_the_env_file_untouched(tmp_path):
    envf = _env_file(tmp_path, kv=True)
    before = open(envf).read()
    state = tmp_path / "state"
    state.mkdir()
    with pytest.raises(RuntimeError):
        R.rotate(str(state), envf, apply_env=True, dry_run=False, keys_dir=None)
    assert open(envf).read() == before
    assert not os.path.exists(envf + ".pre-rotate.bak")


def test_override_allows_rotation(tmp_path):
    envf = _env_file(tmp_path, kv=True)
    state = tmp_path / "state"
    state.mkdir()
    rotated, skipped, new_key = R.rotate(
        str(state), envf, apply_env=False, dry_run=True, keys_dir=None,
        allow_key_vault=True)
    assert new_key and new_key != ""


def test_plain_env_hub_is_unaffected(tmp_path):
    """The guard must not break the normal on-prem rotation path."""
    envf = _env_file(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    rotated, skipped, new_key = R.rotate(
        str(state), envf, apply_env=False, dry_run=True, keys_dir=None)
    assert new_key


# ── CLI wiring ───────────────────────────────────────────────────────────────

def test_cli_exposes_the_override_and_exits_nonzero_when_refusing(tmp_path, capsys):
    envf = _env_file(tmp_path, kv=True)
    state = tmp_path / "state"
    state.mkdir()
    rc = R.main(["--state-dir", str(state), "--env-file", envf, "--keys-dir", ""])
    assert rc == 2
    assert "Key Vault" in capsys.readouterr().err


def test_cli_override_flag_is_plumbed_through(tmp_path, capsys):
    envf = _env_file(tmp_path, kv=True)
    state = tmp_path / "state"
    state.mkdir()
    rc = R.main(["--state-dir", str(state), "--env-file", envf, "--keys-dir", "",
                 "--dry-run", "--allow-key-vault"])
    assert rc == 0
