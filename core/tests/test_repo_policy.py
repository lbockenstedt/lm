"""The sensor repository must not be reachable from any product code path.

The Threat Monitor's content used to arrive as a private git checkout, which
meant every participating install held the honeypot itself rather than the
benefit of it. It now arrives as a data subscription, and a subscription is
only a boundary if the old path is actually shut.

There were three independent ways in, and only one of them required an
operator to configure anything:

* ``site_ext`` takes an operator-supplied repo URL.
* ``update_pipeline._default_repo_for_key`` *derives* sibling repo URLs as
  ``github.com/<owner>/<key>.git``, so a module key of ``tm`` resolved to the
  sensor repo with nobody having configured it.
* ``repo_sync`` pulls every checkout under ``provisioning_repos/`` forever.

These tests exist because closing one of those and leaving the others is
indistinguishable, from the outside, from having closed all three.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import repo_policy  # noqa: E402


# ── identity, not string matching ────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://github.com/lbockenstedt/tm",
    "https://github.com/lbockenstedt/tm.git",
    "https://github.com/lbockenstedt/tm/",
    "https://github.com/LBockenstedt/TM.git",
    "git@github.com:lbockenstedt/tm.git",
    "ssh://git@github.com/lbockenstedt/tm.git",
    "https://x-access-token:ghp_secret@github.com/lbockenstedt/tm.git",
    "lbockenstedt/tm",
])
def test_every_spelling_of_the_sensor_repo_is_refused(url):
    """A denylist that compared literal URLs would be defeated by a suffix, an
    SSH remote, a trailing slash, capitalisation or an embedded token — none of
    which change which repository is being fetched."""
    assert repo_policy.is_forbidden(url), url
    assert repo_policy.refuse_reason(url)


@pytest.mark.parametrize("url", [
    "https://github.com/lbockenstedt/lm.git",
    "https://github.com/lbockenstedt/le.git",
    "https://github.com/lbockenstedt/ss.git",
    "https://github.com/someoneelse/tm.git",
    "https://github.com/lbockenstedt/tm-notes.git",
    "https://gitlab.com/lbockenstedt/tm.git",
    "",
])
def test_unrelated_repositories_are_untouched(url):
    """The owner is matched as well as the name: ``tm`` is a plausible name for
    an unrelated repository, and over-blocking would strand a real module."""
    assert not repo_policy.is_forbidden(url), url
    assert repo_policy.refuse_reason(url) == ""


def test_a_refusal_names_the_replacement():
    """An operator who configured this is trying to get threat content, not
    doing something unreasonable. A bare refusal would leave them with no idea
    that a supported path exists."""
    reason = repo_policy.refuse_reason("https://github.com/lbockenstedt/tm.git")
    assert "subscription" in reason.lower()


# ── the derived path nobody configures ───────────────────────────────────────

def test_the_sibling_fallback_cannot_derive_the_sensor_repo():
    """``_default_repo_for_key`` invents a URL from a module key. Without this
    guard a key of "tm" resolves to the sensor repo with nothing configured."""
    import update_pipeline

    sources = {"hub": "https://github.com/lbockenstedt/lm"}
    assert update_pipeline._default_repo_for_key("tm", sources) is None
    # The mechanism itself must still work, or this guard has broken updates
    # for every other module rather than closed one door.
    assert update_pipeline._default_repo_for_key("le", sources) == \
        "https://github.com/lbockenstedt/le.git"
    assert update_pipeline._default_repo_for_key("agent", sources) == \
        "https://github.com/lbockenstedt/lm"


# ── the configured path ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_site_ext_refuses_a_forbidden_source(monkeypatch):
    """Refused before the token is resolved, so a repo this install may not
    fetch never triggers a vault read or puts a credential on a command line."""
    import site_ext

    class _State:
        data_dir = "/tmp"
        system_state = {"global_config": {"site_ext": {
            "enabled": True,
            "repo": "https://github.com/lbockenstedt/tm.git",
            "token": "kv:should-never-be-read",
        }}}

    class _Hub:
        state = _State()

    async def _no_git(*a, **kw):
        raise AssertionError("git must not run for a refused repository")

    monkeypatch.setattr(site_ext, "_git", _no_git)

    result = await site_ext.provision(_Hub())
    assert result["ok"] is False
    assert result["reason"] == "forbidden_repo"
    assert "subscription" in result["detail"].lower()
