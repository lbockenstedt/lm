"""Regression (lm#490): the tarball update path must refuse a git working tree.

``_download_update`` merges a downloaded tarball *over* ``hub_root`` with
``shutil.copytree(dirs_exist_ok=True)``. It exists for non-git installs. When it
was reached with ``hub_root`` pointing at a git checkout it silently overwrote
every tracked file with the tip of the branch, destroying uncommitted local
work and leaving no git trace (a plain file copy, not a ``git`` invocation).

That is exactly what a unit test did: ``perform_update(force=True)`` sets
``update_available``, ``_is_git_repo`` was stubbed False, and ``hub_root`` is
derived from ``__file__`` — so running the suite self-updated the developer's
checkout from GitHub.

``perform_update`` already branches on ``_is_git_repo``, so a checkout should
reach ``_git_update``. Arriving in ``_download_update`` with one means the
install type was mis-detected, and the safe response is to decline the update
rather than clobber the tree.
"""

import os

import pytest

from update_pipeline import UpdatePipelineMixin


class _Hub(UpdatePipelineMixin):
    """Only the pieces ``_download_update`` touches before it would download."""

    def __init__(self, is_git):
        self._is_git = is_git
        self.probed = []

    def _is_git_repo(self, path):
        self.probed.append(path)
        return self._is_git


@pytest.mark.asyncio
async def test_refuses_to_extract_a_tarball_over_a_git_working_tree(tmp_path):
    hub = _Hub(is_git=True)
    result = await hub._download_update(
        str(tmp_path), "https://github.com/lbockenstedt/lm.git", "main")
    assert result is False, (
        "a git working tree must never be overwritten by a tarball merge")
    assert hub.probed == [str(tmp_path)], (
        "the guard must probe the install root it is about to write to")


@pytest.mark.asyncio
async def test_guard_runs_before_any_network_or_filesystem_work(tmp_path, monkeypatch):
    """The refusal must short-circuit ahead of the download, not clean up after.

    Anything that reached the extract/merge stage would already have written to
    the tree, so the check has to happen first.
    """
    def _boom(*a, **k):
        raise AssertionError(
            "guard did not short-circuit: work started against a git tree")

    for name in ("copytree", "copy2", "rmtree", "move"):
        monkeypatch.setattr("update_pipeline.shutil." + name, _boom, raising=False)

    canary = tmp_path / "local-edit.txt"
    canary.write_text("uncommitted work")

    hub = _Hub(is_git=True)
    assert await hub._download_update(
        str(tmp_path), "https://github.com/lbockenstedt/lm.git", "main") is False
    assert canary.read_text() == "uncommitted work"
    assert os.listdir(tmp_path) == ["local-edit.txt"], (
        "the guard must not leave temp/extract artifacts behind")


@pytest.mark.asyncio
async def test_non_git_install_is_still_allowed_past_the_guard(tmp_path):
    """The guard must not disable the tarball path for its real use case.

    A non-git install proceeds; it fails later here only because the URL is
    unreachable in a test, which is enough to prove the guard let it through
    (the git-tree case never gets that far).
    """
    hub = _Hub(is_git=False)
    result = await hub._download_update(
        str(tmp_path), "not-a-github-url", "main")
    assert result is False
    assert hub.probed == [str(tmp_path)]
