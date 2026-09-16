"""Shared-core pull de-duplication across sibling control planes on one host.

A role-hosting generic agent runs N+1 control planes inside ONE process: the
base agent plus a ``RoleConnection`` per hosted role. They all share the same
``/opt/lm`` checkout. One hub-pushed update therefore made every one of them
try to pull that single checkout at the same moment.

Measured on the production 9-role node ``mipbe-lmagent`` (agent log
2026-09-16)::

    06:10:21  core-update lock busy >300s; skipping core pull this cycle
    06:10:20  Heartbeat send did not complete in 5s — WS send stuck   (x9)
    06:11:23  update failed: 'git fetch origin' timed out after 120 seconds
    06:48:35  core git pull --rebase failed (rc=128); resetting hard to origin/main

Role *loading* was never the cost — all 9 roles load in ~5s. The cost was the
pile-up on ``_core_update_lock`` plus concurrent ``git fetch`` on one repo.

``_core_already_converged`` collapses a wave: the first sibling pulls and
stamps the resulting HEAD, the rest skip the redundant fetch. It fails OPEN —
a missing / stale / HEAD-mismatched / corrupt stamp means "pull normally" — so
it can only skip a *redundant* fetch, never a genuine update.

Reuses the fake-git harness from ``test_spoke_update_core``.
"""

import json
import os
import time

import pytest

from test_spoke_update_core import (  # noqa: E402
    _Exited,
    _FakeGit,
    _patch_runner,
    cp,
    spoke,  # noqa: F401 — pytest fixture
)


def _stamp_path(core_root):
    return os.path.join(core_root, ".lm-core-converged.json")


def _write_stamp(core_root, head, age_s=0.0):
    with open(_stamp_path(core_root), "w") as fh:
        json.dump({"head": head, "ts": time.time() - age_s}, fh)


async def _run_update(spoke, core_root):
    """Drive one SPOKE_UPDATE; swallow the os._exit(3) the update ends with."""
    try:
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/spoke.git",
            "core_repo_url": "https://example/lm.git",
            "core_branch": "main",
        })
    except _Exited:
        pass


@pytest.fixture
def core_root(tmp_path):
    p = str(tmp_path / "opt-lm")
    os.makedirs(p, exist_ok=True)
    return p


# ── the fix: a wave collapses to one real pull ───────────────────────────────

@pytest.mark.asyncio
async def test_first_sibling_pulls_and_publishes_the_converged_head(
        spoke, core_root, monkeypatch):  # noqa: F811
    """The sibling that wins the lock does the real work and stamps the HEAD
    it landed on, so the rest of the wave can recognise convergence."""
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bbb"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)

    await _run_update(spoke, core_root)

    assert core_root in fake_git.fetch_called, "first sibling must really pull"
    with open(_stamp_path(core_root)) as fh:
        stamp = json.load(fh)
    assert stamp["head"] == "core_bbb", "stamp must carry the POST-pull HEAD"
    assert time.time() - stamp["ts"] < 30


@pytest.mark.asyncio
async def test_sibling_in_the_same_wave_skips_the_redundant_core_fetch(
        spoke, core_root, monkeypatch):  # noqa: F811
    """The production symptom. A fresh stamp whose HEAD matches the checkout
    means a sibling just converged it — this one must NOT fetch core again."""
    cwd = spoke._test_cwd
    # HEAD is already core_bbb and a sibling stamped core_bbb a second ago.
    fake_git = _FakeGit({
        core_root: {"before": "core_bbb", "after": "core_bbb"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    _write_stamp(core_root, "core_bbb", age_s=1.0)

    await _run_update(spoke, core_root)

    assert core_root not in fake_git.fetch_called, (
        "a converged core must not be re-fetched — this is the lock/fetch "
        "pile-up that cost ~8.5 min of recovery on a 9-role node")
    # The component's OWN repo still updates: de-duping core must not disarm
    # the actual update this spoke was told to perform.
    assert cwd in fake_git.fetch_called
    assert cwd in fake_git.pull_called


# ── fail-open: every doubt must still pull ───────────────────────────────────

@pytest.mark.asyncio
async def test_no_stamp_pulls_normally(spoke, core_root, monkeypatch):  # noqa: F811
    """First wave ever / fresh host — nothing to dedupe against."""
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bbb"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    assert not os.path.exists(_stamp_path(core_root))

    await _run_update(spoke, core_root)

    assert core_root in fake_git.fetch_called


@pytest.mark.asyncio
async def test_expired_stamp_pulls_normally(spoke, core_root, monkeypatch):  # noqa: F811
    """A stamp older than the TTL is a PREVIOUS wave, not this one. Skipping on
    it would defer real updates indefinitely on a quiet host."""
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_bbb", "after": "core_ccc"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    _write_stamp(core_root, "core_bbb",
                 age_s=spoke.CORE_CONVERGE_TTL_S + 30)

    await _run_update(spoke, core_root)

    assert core_root in fake_git.fetch_called


@pytest.mark.asyncio
async def test_stamp_for_a_different_head_pulls_normally(
        spoke, core_root, monkeypatch):  # noqa: F811
    """The checkout moved since the stamp (rollback, manual reset, another
    component). The stamp no longer describes reality → do the real work."""
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_zzz", "after": "core_ccc"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    _write_stamp(core_root, "core_bbb", age_s=1.0)  # != on-disk core_zzz

    await _run_update(spoke, core_root)

    assert core_root in fake_git.fetch_called


@pytest.mark.asyncio
async def test_corrupt_stamp_pulls_normally(spoke, core_root, monkeypatch):  # noqa: F811
    """A truncated/garbage stamp must never wedge the update channel."""
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bbb"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    with open(_stamp_path(core_root), "w") as fh:
        fh.write("{not json")

    await _run_update(spoke, core_root)

    assert core_root in fake_git.fetch_called


# ── unit-level guard on the predicate itself ─────────────────────────────────

def test_converged_predicate_is_false_without_a_readable_stamp(
        spoke, core_root, monkeypatch):  # noqa: F811
    """Directly pin the fail-open contract, independent of the update flow."""
    fake_git = _FakeGit({core_root: {"before": "core_bbb", "after": "core_bbb"}})
    monkeypatch.setattr(cp.subprocess, "run", fake_git.run)

    assert spoke._core_already_converged(core_root) is False  # no stamp

    _write_stamp(core_root, "core_bbb", age_s=1.0)
    assert spoke._core_already_converged(core_root) is True

    # An unwritable stamp path must not raise into the update worker.
    assert spoke._core_already_converged(os.path.join(core_root, "nope")) is False


def test_mark_core_converged_ignores_empty_head(spoke, core_root):  # noqa: F811
    """A blank HEAD (rev-parse failed) must not publish a bogus convergence
    claim that would make every sibling skip its pull."""
    spoke._mark_core_converged(core_root, "")
    assert not os.path.exists(_stamp_path(core_root))
