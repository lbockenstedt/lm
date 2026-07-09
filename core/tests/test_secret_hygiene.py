"""Secret hygiene / at-rest encryption regressions (item 11).

Covers the five fixes:
  1. ``simulations_store.json`` is Fernet-encrypted at rest (+ plaintext
     migration on first load).
  2. ``_redact`` covers ``SPOKE_UPDATE_SESSION_KEY`` / ``SPOKE_SET_HUB_SECRET``
     and the ``hub_secret``/``new_secret``/``psk``/``onboarding_psk`` fields so
     DEBUG-mode ``request_response`` logging can't write a session key / hub
     root secret to the hub log.
  3. ``rotate_fernet_key`` walks the KeyManager data dir (``keys.json`` +
     ``hub_secret.json``), not just the state dir, and records the old key as
     ``LM_FERNET_KEY_PREVIOUS``; ``KeyManager`` plaintext-fallback is gated
     behind ``LM_ALLOW_PLAINTEXT_FALLBACK`` (default allow / fail-closed on 0)
     and re-encrypts a plaintext ``keys.json`` on load.
  4. (connect-time secret log demoted to DEBUG — exercised indirectly by the
     log-level change, no assertion here.)
  5. (duplicate ``encode_frame`` removed — import + call still works, covered
     by the existing signature-rotation tests.)
"""
import json
import os

import pytest
from cryptography.fernet import Fernet

import main  # noqa: E402  (core/src on sys.path via conftest)
from main import _redact, _REDACT_COMMANDS, _REDACT_FIELDS  # noqa: E402
from simulations.store import SimulationsStore  # noqa: E402
from security.key_manager import KeyManager  # noqa: E402
from security.rotate_fernet_key import rotate  # noqa: E402


# ── 2. _redact covers the secret-carrying command types ─────────────────────

def test_session_key_command_is_redacted():
    assert "SPOKE_UPDATE_SESSION_KEY" in _REDACT_COMMANDS
    assert "SPOKE_SET_HUB_SECRET" in _REDACT_COMMANDS


def test_redact_drops_secret_from_session_key_payload():
    # The payload {"secret": <new session secret>} must not survive into the log.
    out = _redact("SPOKE_UPDATE_SESSION_KEY", {"secret": "new-session-secret", "spoke_id": "s1"})
    assert out == {"spoke_id": "s1"}
    assert "secret" not in out


def test_redact_drops_hub_secret_field():
    out = _redact("SPOKE_SET_HUB_SECRET", {"hub_secret": "hub-root", "n": 1})
    assert out == {"n": 1}
    assert "hub_secret" not in out


def test_redact_drops_psk_and_new_secret_fields():
    out = _redact("SPOKE_UPDATE_SESSION_KEY",
                  {"new_secret": "x", "psk": "p", "onboarding_psk": "o", "keep": 1})
    assert out == {"keep": 1}
    for k in ("new_secret", "psk", "onboarding_psk"):
        assert k not in out


def test_redact_non_allowlisted_type_drops_secret_fields():
    # Allow-list policy (default redact): a type NOT in _LOGSAFE_COMMANDS gets
    # its known secret fields dropped even though it isn't an enumerated secret
    # type — so a NEW secret-bearing command can't leak by absence from a
    # deny-list. Non-secret fields are preserved for the debug trail.
    d = {"secret": "s", "data": 1}
    out = _redact("SOME_TELEMETRY", d)
    assert out == {"data": 1}
    assert "secret" not in out


def test_redact_allowlisted_type_returned_unchanged():
    # A verifiably-secret-free type (telemetry/heartbeat/ack) keeps its full
    # debug trail — same object, no copy.
    from main import _LOGSAFE_COMMANDS
    assert "HEARTBEAT" in _LOGSAFE_COMMANDS
    d = {"spoke_id": "s1", "ts": 123}
    assert _redact("HEARTBEAT", d) is d


def test_redact_fully_redacts_password_and_console_config():
    # Types carrying inline secrets in a config blob / arbitrary field get the
    # whole payload replaced with a marker — field-name stripping can't reach a
    # secret buried in a ``config`` string.
    assert _redact("SET_PASSWORD", {"user_id": "u", "password": "x"}) == {"<redacted>": True}
    assert _redact("CONSOLE_PUSH_CONFIG", {"config": "enable password 0 hunter2"}) == {"<redacted>": True}
    # The arbitrary agent-command relay uses a user-supplied command type; the
    # PASSWORD/PUSH_CONFIG substring heuristic catches it without enumeration.
    assert _redact("NETBOX_RESET_ADMIN_PASSWORD", {"new": "pw"}) == {"<redacted>": True}


def test_redact_drops_secret_from_nested_result():
    out = _redact("CS_TOKEN_RESULT", {"result": {"token": "t", "secret": "s"}, "ok": True})
    assert out == {"result": {}, "ok": True}


def test_redact_drops_secret_from_response_payload_data():
    # The REAL response shape logged at request_response: response_cache stores
    # the full wire message, so ``data`` is {"header":…, "payload":{"type":
    # "COMMAND_RESULT","data":{…}}, "correlation_id":…}. The secret lives at
    # payload.data.<field>, NOT at top level — so the response side MUST reach
    # it (the b8f05e7 request-side fix missed this). CS_CREATE_PROXMOX_TOKEN
    # returns the minted Proxmox API token in payload.data.token.
    msg = {"header": {"sender_id": "spoke"},
           "payload": {"type": "COMMAND_RESULT",
                       "data": {"token": "proxmox-secret-token", "vmid": 90025}},
           "correlation_id": "abc"}
    out = _redact("CS_CREATE_PROXMOX_TOKEN", msg)
    assert out["payload"]["data"] == {"vmid": 90025}
    assert "token" not in out["payload"]["data"]
    # The original response forwarded to the caller is NOT mutated.
    assert msg["payload"]["data"]["token"] == "proxmox-secret-token"


def test_redact_drops_secret_from_response_payload_data_list():
    # A list-valued payload.data (a query result) has each item scrubbed.
    msg = {"payload": {"type": "COMMAND_RESULT",
                       "data": [{"id": 1, "api_key": "k1"}, {"id": 2, "name": "n"}]}}
    out = _redact("NETBOX_GET_DEVICES", msg)
    assert out["payload"]["data"] == [{"id": 1}, {"id": 2, "name": "n"}]


def test_redact_substring_catches_compound_secret_fields():
    # _REDACT_FIELDS is exact-key; the substring match catches compound names
    # the exact list misses: client_secret, userPassword, api_key, admin_pw,
    # access_token, private_key, credential.
    for ct, key in (("CPPM_PROBE", "client_secret"),
                    ("CREATE_USER", "userPassword"),
                    ("AGENT_COMMAND", "api_key"),
                    ("SET_LDAP_CONFIG", "LDAP_ADMIN_PW"),
                    ("OAUTH_EXCHANGE", "access_token"),
                    ("SIGN_KEY", "private_key"),
                    ("STORE_CREDS", "credential")):
        out = _redact(ct, {key: "secret-value", "keep": 1})
        assert key not in out, f"{ct}/{key} not redacted"
        assert out.get("keep") == 1


def test_redact_substring_does_not_overcorrect_benign_fields():
    # Benign field names must survive (no bare "key"/"auth"/"id" substring).
    out = _redact("NETBOX_GET_DEVICES",
                  {"id": 1, "name": "r1", "site": "dc1", "data": 42})
    assert out == {"id": 1, "name": "r1", "site": "dc1", "data": 42}


def test_redact_fields_set_covers_hub_secret():
    for k in ("token", "secret", "password", "api_token", "hub_secret",
              "new_secret", "psk", "onboarding_psk"):
        assert k in _REDACT_FIELDS


# ── 1. simulations_store.json is encrypted at rest ──────────────────────────

def _is_ciphertext(raw: bytes) -> bool:
    """A Fernet token is urlsafe-base64 (starts e.g. b'gAAAA...'), not JSON."""
    if raw.startswith(b"{") or raw.startswith(b"["):
        return False
    try:
        json.loads(raw)
        return False
    except Exception:
        return True


async def test_store_persists_encrypted_not_plaintext(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.add_psk("t1", "psk-secret-value")
    raw = (tmp_path / "simulations_store.json").read_bytes()
    assert _is_ciphertext(raw), "simulations_store.json must not be plaintext JSON on disk"
    # And it round-trips: a fresh store reloads the encrypted PSK.
    s2 = SimulationsStore(str(tmp_path))
    assert "psk-secret-value" in await s2.get_psks("t1")


async def test_store_migrates_pre_encryption_plaintext_file(tmp_path):
    """A plaintext file from before at-rest encryption is accepted once and
    re-encrypted on the next save (the one-time migration path)."""
    path = tmp_path / "simulations_store.json"
    path.write_text(json.dumps({"t1": {"onboarding_psks": ["legacy-psk"]}}))
    s = SimulationsStore(str(tmp_path))
    assert s._needs_rekey is True
    assert "legacy-psk" in await s.get_psks("t1")
    # A write flips it to ciphertext and clears the rekey flag.
    await s.add_psk("t1", "new-psk")
    assert _is_ciphertext(path.read_bytes())
    assert s._needs_rekey is False
    # Reload confirms both PSKs survived the migration.
    s2 = SimulationsStore(str(tmp_path))
    psks = await s2.get_psks("t1")
    assert "legacy-psk" in psks and "new-psk" in psks


# ── 3a. rotate_fernet_key walks keys-dir + records LM_FERNET_KEY_PREVIOUS ───

def _encrypt(key: str, data) -> bytes:
    return Fernet(key.encode()).encrypt(json.dumps(data, sort_keys=True).encode())


def test_rotate_walks_keys_dir_and_sets_previous(tmp_path, monkeypatch):
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    state = tmp_path / "state"; state.mkdir()
    keys = tmp_path / "data"; keys.mkdir()
    env = tmp_path / ".env"; env.write_text(f"LM_FERNET_KEY={old_key}\n")

    (state / "system.json").write_bytes(_encrypt(old_key, {"a": 1}))
    (keys / "keys.json").write_bytes(_encrypt(old_key, {"current": {}, "history": {}}))
    (keys / "hub_secret.json").write_bytes(_encrypt(old_key, ["hub-root-secret"]))

    rotated, skipped, new_key = rotate(str(state), str(env), apply_env=True,
                                       dry_run=False, keys_dir=str(keys))

    assert rotated == 3
    # keys.json + hub_secret.json now decrypt under the NEW key (the fix: they
    # were previously skipped because they live outside --state-dir).
    assert json.loads(Fernet(new_key.encode()).decrypt((keys / "keys.json").read_bytes()))["current"] == {}
    assert json.loads(Fernet(new_key.encode()).decrypt((keys / "hub_secret.json").read_bytes())) == ["hub-root-secret"]
    # They no longer decrypt under the OLD key.
    with pytest.raises(Exception):
        Fernet(old_key.encode()).decrypt((keys / "keys.json").read_bytes())

    # .env carries the new key AND the old key as LM_FERNET_KEY_PREVIOUS.
    lines = env.read_text().splitlines()
    assert f"LM_FERNET_KEY={new_key}" in lines
    assert f"LM_FERNET_KEY_PREVIOUS={old_key}" in lines
    # Backups for all three rotated files.
    assert (state / "system.json.pre-rotate.bak").exists()
    assert (keys / "keys.json.pre-rotate.bak").exists()
    assert (keys / "hub_secret.json.pre-rotate.bak").exists()


def test_rotate_without_keys_dir_only_walks_state(tmp_path, monkeypatch):
    """Back-compat: omitting keys_dir keeps the original state-dir-only walk."""
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", old_key)
    state = tmp_path / "state"; state.mkdir()
    env = tmp_path / ".env"; env.write_text(f"LM_FERNET_KEY={old_key}\n")
    (state / "system.json").write_bytes(_encrypt(old_key, {"a": 1}))

    rotated, skipped, new_key = rotate(str(state), str(env), apply_env=False,
                                       dry_run=False, keys_dir=None)
    assert rotated == 1
    assert json.loads(Fernet(new_key.encode()).decrypt((state / "system.json").read_bytes())) == {"a": 1}


# ── 3b. KeyManager plaintext-fallback gating + migration re-key ─────────────

def _km_at(tmp_path) -> KeyManager:
    """KeyManager with storage paths pointed at tmp_path. Cleans the default
    core/data files first so __init__'s load is empty (mirrors _make_km)."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("k_hygiene.json", "hs_hygiene.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    km = KeyManager("k_hygiene.json", "hs_hygiene.json")
    km.storage_path = str(tmp_path / "keys.json")
    km.hub_secret_path = str(tmp_path / "hub_secret.json")
    return km


def test_key_manager_migrates_plaintext_keys_json_on_load(tmp_path):
    """Default (LM_ALLOW_PLAINTEXT_FALLBACK unset): a plaintext keys.json is
    accepted and immediately re-encrypted under the primary key on load."""
    (tmp_path / "keys.json").write_text(json.dumps({"current": {}, "history": {}}))
    km = _km_at(tmp_path)
    km.load_keys()
    # File migrated to ciphertext (no longer plaintext JSON on disk).
    assert _is_ciphertext((tmp_path / "keys.json").read_bytes())


def test_key_manager_plaintext_fallback_fail_closed(tmp_path, monkeypatch):
    """LM_ALLOW_PLAINTEXT_FALLBACK=0 → a plaintext keys.json is REFUSED (no
    silent plaintext read of mis-decrypted secret material); keys stay empty
    and the file is left untouched (not migrated)."""
    monkeypatch.setenv("LM_ALLOW_PLAINTEXT_FALLBACK", "0")
    (tmp_path / "keys.json").write_text(json.dumps({"current": {}, "history": {}}))
    km = _km_at(tmp_path)
    km.load_keys()
    assert km.keys == {}
    raw = (tmp_path / "keys.json").read_bytes()
    assert raw.startswith(b"{")  # still plaintext — fail-closed did not migrate