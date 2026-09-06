"""Credential handling for the out-of-band extension source (``site_ext``).

Pins three properties that together keep the access token off disk in plaintext
and out of the logs:

1. The token is never written into ``.git/config``. ``git clone`` persists the
   credentialed remote URL, so provisioning MUST rewrite the remote to the bare
   URL afterwards; the update path must pass the credentialed URL as a one-shot
   fetch argument instead of ``remote set-url``.
2. Git failure output is redacted before it is logged — the hub log is surfaced
   in the WebUI error feed, so an unredacted failure would publish the PAT.
3. With no vault the literal still lands in ``global_config``, which the
   StateManager writes Fernet-encrypted; with a vault it is replaced by a
   ``kv:`` reference (asserted in the route tests below).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import site_ext  # noqa: E402


class _Hub:
    def __init__(self, cfg, data_dir):
        self.state = type("S", (), {
            "system_state": {"global_config": {"site_ext": cfg}},
            "data_dir": data_dir,
        })()


# ── _redact ──────────────────────────────────────────────────────────────────

def test_redact_removes_the_literal_token():
    out = site_ext._redact("fatal: could not read from https://x-access-token:ghp_SECRET@github.com/o/r",
                           "ghp_SECRET")
    assert "ghp_SECRET" not in out


def test_redact_strips_any_embedded_credential_even_without_the_token():
    """Defence in depth: redaction must not depend on knowing the token value —
    a resolve failure can leave ``token`` None while git still echoes a URL."""
    out = site_ext._redact("remote: https://x-access-token:abc123@github.com/o/r not found", None)
    assert "abc123" not in out
    assert "***@github.com" in out


def test_redact_leaves_clean_output_alone():
    msg = "fatal: Remote branch nope not found in upstream origin"
    assert site_ext._redact(msg, "tok") == msg


# ── provision: credential must not be persisted in .git/config ───────────────

@pytest.mark.asyncio
async def test_clone_rewrites_remote_to_bare_url(tmp_path, monkeypatch):
    calls = []

    async def fake_git(*args, cwd=None, timeout=90.0):
        calls.append(args)
        return 0, ""

    monkeypatch.setattr(site_ext, "_git", fake_git)
    hub = _Hub({"enabled": True, "repo": "https://github.com/o/r.git",
                "ref": "main", "token": "ghp_SECRET"}, str(tmp_path))
    await site_ext.provision(hub)

    clone = [c for c in calls if c and c[0] == "clone"]
    assert clone, "expected a clone on first provision"
    assert any("ghp_SECRET" in str(a) for a in clone[0]), "clone should authenticate"

    reset = [c for c in calls if c[:3] == ("-C",) + (str(site_ext.ext_dir(hub)),) + ("remote",)]
    assert reset, "clone must be followed by a remote set-url to the bare URL"
    assert reset[0][-1] == "https://github.com/o/r.git"
    assert "ghp_SECRET" not in reset[0][-1]


@pytest.mark.asyncio
async def test_update_path_never_sets_a_credentialed_remote(tmp_path, monkeypatch):
    """The pre-existing-checkout path must fetch from a one-shot URL, never
    write the credential into .git/config via ``remote set-url``."""
    dest = tmp_path / "site_ext"
    (dest / ".git").mkdir(parents=True)
    calls = []

    async def fake_git(*args, cwd=None, timeout=90.0):
        calls.append(args)
        return 0, ""

    monkeypatch.setattr(site_ext, "_git", fake_git)
    hub = _Hub({"enabled": True, "repo": "https://github.com/o/r.git",
                "ref": "main", "token": "ghp_SECRET"}, str(tmp_path))
    await site_ext.provision(hub)

    for c in calls:
        if "remote" in c and "set-url" in c:
            assert "ghp_SECRET" not in str(c), "credential must never be persisted to .git/config"
    fetches = [c for c in calls if "fetch" in c]
    assert fetches, "expected a fetch on the update path"
    assert any("ghp_SECRET" in str(a) for a in fetches[0])
    assert any("FETCH_HEAD" in str(c) for c in calls), "must reset to FETCH_HEAD, not origin/<ref>"


@pytest.mark.asyncio
async def test_failure_output_is_redacted_before_logging(tmp_path, monkeypatch, caplog):
    async def fake_git(*args, cwd=None, timeout=90.0):
        return 128, "fatal: https://x-access-token:ghp_SECRET@github.com/o/r not found"

    monkeypatch.setattr(site_ext, "_git", fake_git)
    hub = _Hub({"enabled": True, "repo": "https://github.com/o/r.git",
                "ref": "main", "token": "ghp_SECRET"}, str(tmp_path))
    with caplog.at_level("WARNING"):
        await site_ext.provision(hub)
    assert "ghp_SECRET" not in caplog.text
    assert "fetch failed" in caplog.text


@pytest.mark.asyncio
async def test_disabled_source_is_a_no_op(tmp_path, monkeypatch):
    calls = []

    async def fake_git(*args, cwd=None, timeout=90.0):
        calls.append(args)
        return 0, ""

    monkeypatch.setattr(site_ext, "_git", fake_git)
    hub = _Hub({"enabled": False, "repo": "https://github.com/o/r.git"}, str(tmp_path))
    await site_ext.provision(hub)
    assert calls == []
