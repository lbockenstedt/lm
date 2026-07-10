"""LM_ALLOW_PLAINTEXT_FALLBACK gate is honored by the shared helper.

The operator's fail-closed promise (``LM_ALLOW_PLAINTEXT_FALLBACK=0``) must hold
across every encrypted store: KeyManager (secrets), StateManager (system/
tenants.json) and SimulationsStore. The shared ``plaintext_fallback_allowed``
helper is the single decision point the two state stores now gate on; these
tests pin its env-var resolution so a future change can't silently flip it.
"""

import os

from security.encryption import plaintext_fallback_allowed  # noqa: E402


def test_default_allows_fallback(monkeypatch):
    monkeypatch.delenv("LM_ALLOW_PLAINTEXT_FALLBACK", raising=False)
    assert plaintext_fallback_allowed() is True


def test_explicit_one_allows(monkeypatch):
    monkeypatch.setenv("LM_ALLOW_PLAINTEXT_FALLBACK", "1")
    assert plaintext_fallback_allowed() is True


def test_zero_fail_closed(monkeypatch):
    monkeypatch.setenv("LM_ALLOW_PLAINTEXT_FALLBACK", "0")
    assert plaintext_fallback_allowed() is False


def test_truthy_words_allowed(monkeypatch):
    for v in ("true", "yes"):
        monkeypatch.setenv("LM_ALLOW_PLAINTEXT_FALLBACK", v)
        assert plaintext_fallback_allowed() is True, v


def test_other_values_fail_closed(monkeypatch):
    for v in ("0", "no", "false", "off", "", "TRUE", "Yes"):
        monkeypatch.setenv("LM_ALLOW_PLAINTEXT_FALLBACK", v)
        assert plaintext_fallback_allowed() is False, v