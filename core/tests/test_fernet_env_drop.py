"""Tier-0 root/LPE hardening: LM_FERNET_KEY is dropped from os.environ after
load so a root reader can't slurp it from /proc/<pid>/environ.

Asserts:
  * default (no flag) leaves the env var in place (opt-in, non-breaking),
  * LM_DROP_FERNET_KEY_ENV=1 removes LM_FERNET_KEY + LM_FERNET_KEY_PREVIOUS from
    the environment, while the key material stays usable in-process,
  * primary_key()/primary_fernet_key() still return the raw key after the drop,
  * encrypt/decrypt still round-trips after the drop,
  * LM_KEEP_FERNET_KEY_ENV=1 force-disables the drop,
  * oidc._fernet_key_secret() (the state-cookie HMAC fallback) still resolves
    the key after the env var is gone.
"""
import os
import sys

from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import security.encryption as enc
from security import oidc


def _fresh_env(monkeypatch, drop=None, keep=None, previous=None):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", key)
    if previous is not None:
        monkeypatch.setenv("LM_FERNET_KEY_PREVIOUS", previous)
    else:
        monkeypatch.delenv("LM_FERNET_KEY_PREVIOUS", raising=False)
    if drop is None:
        monkeypatch.delenv("LM_DROP_FERNET_KEY_ENV", raising=False)
    else:
        monkeypatch.setenv("LM_DROP_FERNET_KEY_ENV", drop)
    if keep is None:
        monkeypatch.delenv("LM_KEEP_FERNET_KEY_ENV", raising=False)
    else:
        monkeypatch.setenv("LM_KEEP_FERNET_KEY_ENV", keep)
    return key


def test_default_keeps_env_var(monkeypatch):
    key = _fresh_env(monkeypatch)
    h = enc.HubEncryption()
    assert os.environ.get("LM_FERNET_KEY") == key
    assert h.primary_key() == key


def test_drop_flag_removes_env_but_keeps_key(monkeypatch):
    key = _fresh_env(monkeypatch, drop="1",
                     previous=Fernet.generate_key().decode())
    h = enc.HubEncryption()
    # Env var is gone from /proc/<pid>/environ...
    assert "LM_FERNET_KEY" not in os.environ
    assert "LM_FERNET_KEY_PREVIOUS" not in os.environ
    # ...but the in-process key still works.
    assert h.primary_key() == key
    token = h.encrypt("secret-payload")
    assert h.decrypt(token) == "secret-payload"


def test_module_accessor_resolves_after_drop(monkeypatch):
    key = _fresh_env(monkeypatch, drop="1")
    # Point the module singleton at the fresh instance so the accessor reads it.
    monkeypatch.setattr(enc, "hub_encryption", enc.HubEncryption())
    assert "LM_FERNET_KEY" not in os.environ
    assert enc.primary_fernet_key() == key


def test_keep_flag_overrides_drop(monkeypatch):
    key = _fresh_env(monkeypatch, drop="1", keep="1")
    enc.HubEncryption()
    assert os.environ.get("LM_FERNET_KEY") == key


def test_oidc_state_secret_fallback_after_drop(monkeypatch):
    key = _fresh_env(monkeypatch, drop="1")
    monkeypatch.setattr(enc, "hub_encryption", enc.HubEncryption())
    assert "LM_FERNET_KEY" not in os.environ
    # oidc's fallback must still resolve the key (no dedicated OIDC secret set).
    monkeypatch.delenv("LM_OIDC_STATE_SECRET", raising=False)
    assert oidc._fernet_key_secret() == key
