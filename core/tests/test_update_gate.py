"""Critical path 2/4 — hub self-update gate (commit-SHA detection).

The v.01 VERSION reset (2026-06-28) made string-VERSION detection dead, so the
gate now decides "update available" primarily by commit-SHA comparison. These
tests cover the pure ``_update_available`` decision (extracted from
``perform_update`` so it is testable without I/O) across git vs non-git
installs, the unknown-remote safe fallback, ``force``, and the legacy VERSION
fallback. The live ``get_local_commit`` / ``get_remote_commit`` (git rev-parse /
ls-remote) are exercised by a host integration test (TODO).
"""

import pytest
from update_pipeline import _update_available, _ver


def test_ver_parses_dotted_numeric_and_falls_back():
    assert _ver("1.2.3") == (1, 2, 3)
    assert _ver("v.01") == (0, 0, 0)      # non-numeric → fallback (the post-reset state)
    assert _ver(".01") == (0, 0, 0)       # current sentinel (no leading digit) → also fallback
    assert _ver("unknown") == (0, 0, 0)
    assert _ver("") == (0, 0, 0)
    assert _ver(None) == (0, 0, 0)


def test_git_install_up_to_date():
    g = _update_available(local_commit="aaa", remote_commit="aaa",
                          stored_commit=None, local_v="v.01", remote_v="v.01")
    assert g["update_available"] is False
    assert g["commit_ahead"] is False
    assert g["ver_ahead"] is False


def test_git_install_remote_ahead():
    g = _update_available(local_commit="aaa", remote_commit="bbb",
                          stored_commit=None, local_v="v.01", remote_v="v.01")
    assert g["update_available"] is True
    assert g["commit_ahead"] is True
    assert g["ver_ahead"] is False   # both v.01 → version can't see it


def test_non_git_install_ahead_via_stored_commit():
    # tarball install: local_commit unknown; remote tip differs from last applied
    g = _update_available(local_commit="unknown", remote_commit="bbb",
                          stored_commit="aaa", local_v="v.01", remote_v="v.01")
    assert g["update_available"] is True
    assert g["commit_ahead"] is True


def test_non_git_install_up_to_date():
    g = _update_available(local_commit="unknown", remote_commit="bbb",
                          stored_commit="bbb", local_v="v.01", remote_v="v.01")
    assert g["update_available"] is False
    assert g["commit_ahead"] is False


def test_unknown_remote_is_safe_no_update():
    """ls-remote failed → must NOT report an update (retry next cycle)."""
    g = _update_available(local_commit="aaa", remote_commit="unknown",
                          stored_commit=None, local_v="v.01", remote_v="v.01")
    assert g["update_available"] is False
    assert g["commit_ahead"] is False


def test_force_overrides_even_when_up_to_date():
    g = _update_available(local_commit="aaa", remote_commit="aaa",
                          stored_commit=None, local_v="v.01", remote_v="v.01",
                          force=True)
    assert g["update_available"] is True


def test_version_fallback_when_commits_equal_but_version_moved():
    """If a future deployment bumps VERSION again, the legacy compare still
    fires even when commit detection is unavailable."""
    g = _update_available(local_commit="unknown", remote_commit="unknown",
                          stored_commit=None, local_v="1.0.0", remote_v="1.0.1")
    assert g["ver_ahead"] is True
    assert g["update_available"] is True