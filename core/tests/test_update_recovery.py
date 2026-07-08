"""First tests for ``update_recovery.py`` — the snapshot/rollback state machine.

Pins the parameterized contract: ``snapshot_code``/``restore_snapshot`` take a
``tree_list`` (basename-mapped: ``core/src``→``src``) and a ``state_dir``; the
pending manifest round-trips; bad-version AND bad-commit registries add/is;
``prune_backups`` keeps the newest N. The hub's default ``tree_list`` and
``STATE_DIR`` are preserved so existing hub call sites are unchanged.
"""

import json
import os

import pytest

from update_recovery import (
    DEFAULT_TREE_LIST,
    add_bad_commit,
    add_bad_version,
    clear_pending,
    is_bad_commit,
    is_version_bad,
    prune_backups,
    read_bad_commits,
    read_bad_versions,
    read_pending,
    restore_snapshot,
    snapshot_code,
    write_pending,
)


# ── fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def comp(tmp_path):
    """A fake component root with two code trees + an isolated state dir."""
    root = tmp_path / "comp"
    (root / "core" / "src").mkdir(parents=True)
    (root / "core" / "src" / "main.py").write_text("OLD_HUB\n")
    (root / "WebUI").mkdir(parents=True)
    (root / "WebUI" / "index.html").write_text("<old/>\n")
    # a spoke-style single src tree too, for the tree_list test
    (root / "src").mkdir(parents=True)
    (root / "src" / "spoke.py").write_text("OLD_SPOKE\n")
    state = tmp_path / "state"
    return {"root": str(root), "state": str(state)}


# ── snapshot / restore ─────────────────────────────────────────────────────

def test_default_tree_list_is_hub_core_src_plus_webui():
    assert DEFAULT_TREE_LIST == ["core/src", "WebUI"]


def test_snapshot_restore_round_trip_default_trees(comp):
    bdir = snapshot_code(comp["root"], "ts1", state_dir=comp["state"])
    # basename mapping: core/src → src, WebUI → WebUI
    assert os.path.isdir(os.path.join(bdir, "src"))
    assert os.path.isdir(os.path.join(bdir, "WebUI"))
    assert os.path.isfile(os.path.join(bdir, "src", "main.py"))

    # Simulate a broken swap: overwrite the live trees.
    with open(os.path.join(comp["root"], "core", "src", "main.py"), "w") as f:
        f.write("BROKEN_HUB\n")
    with open(os.path.join(comp["root"], "WebUI", "index.html"), "w") as f:
        f.write("<broken/>\n")

    # restore_snapshot uses the default tree_list (core/src + WebUI) and reads
    # the backup by absolute path, so no state_dir is needed on the restore side.
    ok = restore_snapshot(bdir, comp["root"])
    assert ok is True
    assert open(os.path.join(comp["root"], "core", "src", "main.py")).read() == "OLD_HUB\n"
    assert open(os.path.join(comp["root"], "WebUI", "index.html")).read() == "<old/>\n"


def test_snapshot_restore_custom_tree_list_spoke(comp):
    """A spoke passes tree_list=['src'] → snapshot captures src/, restore
    requires it (first tree)."""
    bdir = snapshot_code(comp["root"], "ts2", tree_list=["src"],
                        state_dir=comp["state"])
    assert os.path.isdir(os.path.join(bdir, "src"))
    assert not os.path.isdir(os.path.join(bdir, "WebUI"))  # not snapshotted

    with open(os.path.join(comp["root"], "src", "spoke.py"), "w") as f:
        f.write("BROKEN_SPOKE\n")

    ok = restore_snapshot(bdir, comp["root"], tree_list=["src"])
    assert ok is True
    assert open(os.path.join(comp["root"], "src", "spoke.py")).read() == "OLD_SPOKE\n"


def test_restore_returns_false_when_required_tree_missing(comp):
    bdir = snapshot_code(comp["root"], "ts3", tree_list=["src"],
                        state_dir=comp["state"])
    # Drop the required backup subdir → no usable snapshot.
    import shutil
    shutil.rmtree(os.path.join(bdir, "src"))
    assert restore_snapshot(bdir, comp["root"], tree_list=["src"]) is False


def test_restore_returns_false_when_backup_dir_empty():
    assert restore_snapshot("", "/nonexistent") is False
    assert restore_snapshot("/no/such/backup", "/nonexistent") is False


def test_snapshot_skips_missing_trees(tmp_path):
    root = str(tmp_path / "root")
    os.makedirs(root)
    # Neither core/src nor WebUI exists → snapshot is an empty backup dir, no raise.
    bdir = snapshot_code(root, "ts", state_dir=str(tmp_path / "state"))
    assert os.path.isdir(bdir)


# ── pending manifest ───────────────────────────────────────────────────────

def test_pending_write_read_clear(comp, tmp_path):
    state = str(tmp_path / "st2")
    write_pending("/backup/ts1", "1.0.0", "1.0.1", "ts1", state_dir=state,
                  extra={"from_commit": "aaa", "to_commit": "bbb",
                         "service_unit": "lm-cs", "deadline": 90})
    p = read_pending(state_dir=state)
    assert p is not None
    assert p["backup_dir"] == "/backup/ts1"
    assert p["from_version"] == "1.0.0"
    assert p["to_version"] == "1.0.1"
    assert p["from_commit"] == "aaa"
    assert p["service_unit"] == "lm-cs"

    clear_pending(state_dir=state)
    assert read_pending(state_dir=state) is None


def test_pending_state_dir_isolation(comp, tmp_path):
    """A spoke state dir must not collide with the hub's default state dir."""
    s1 = str(tmp_path / "hub_state")
    s2 = str(tmp_path / "spoke_state")
    write_pending("/b1", "1", "2", "ts", state_dir=s1)
    write_pending("/b2", "3", "4", "ts", state_dir=s2)
    assert read_pending(state_dir=s1)["backup_dir"] == "/b1"
    assert read_pending(state_dir=s2)["backup_dir"] == "/b2"
    # clearing one does not touch the other
    clear_pending(state_dir=s1)
    assert read_pending(state_dir=s1) is None
    assert read_pending(state_dir=s2)["backup_dir"] == "/b2"


# ── bad-version + bad-commit registries ────────────────────────────────────

def test_bad_version_add_is(tmp_path):
    state = str(tmp_path / "st")
    assert is_version_bad("1.0.9", state_dir=state) is False
    add_bad_version("1.0.9", state_dir=state)
    assert is_version_bad("1.0.9", state_dir=state) is True
    assert is_version_bad("1.0.10", state_dir=state) is False
    # idempotent + doesn't dupe
    add_bad_version("1.0.9", state_dir=state)
    assert len(read_bad_versions(state_dir=state)) == 1


def test_bad_commit_add_is(tmp_path):
    state = str(tmp_path / "st")
    assert is_bad_commit("abc123", state_dir=state) is False
    add_bad_commit("abc123", state_dir=state)
    assert is_bad_commit("abc123", state_dir=state) is True
    assert is_bad_commit("def456", state_dir=state) is False
    add_bad_commit("abc123", state_dir=state)  # idempotent
    assert len(read_bad_commits(state_dir=state)) == 1
    # lives in its own file, separate from the bad_versions registry
    assert os.path.isfile(os.path.join(state, "bad_commits.json"))


def test_bad_versions_and_commits_are_separate_registries(tmp_path):
    state = str(tmp_path / "st")
    add_bad_version("1.0.9", state_dir=state)
    add_bad_commit("abc123", state_dir=state)
    # a version is not a commit and vice versa
    assert is_bad_commit("1.0.9", state_dir=state) is False
    assert is_version_bad("abc123", state_dir=state) is False


# ── prune ──────────────────────────────────────────────────────────────────

def test_prune_keeps_newest_n(comp):
    # Create 4 snapshots with distinct mtimes.
    import time
    broot = os.path.join(comp["state"], "update-backup")
    os.makedirs(broot, exist_ok=True)
    for i in range(4):
        d = os.path.join(broot, f"ts{i}")
        os.makedirs(d)
        os.utime(d, (i + 100, i + 100))  # ts3 newest
    removed = prune_backups(keep=2, state_dir=comp["state"])
    assert removed == 2
    remaining = sorted(os.listdir(broot))
    assert remaining == ["ts2", "ts3"]  # newest two kept


# ── CLI ────────────────────────────────────────────────────────────────────

def test_cli_snapshot_and_rollback_with_state_dir_and_tree(comp):
    from update_recovery import main
    # snapshot via CLI with a custom tree + state dir
    rc = main(["snapshot", "--hub-root", comp["root"],
               "--from-version", "1", "--to-version", "2",
               "--tree", "src", "--state-dir", comp["state"]])
    assert rc == 0
    pending = read_pending(state_dir=comp["state"])
    assert pending is not None
    bdir = pending["backup_dir"]
    assert os.path.isdir(os.path.join(bdir, "src"))

    # break live tree
    with open(os.path.join(comp["root"], "src", "spoke.py"), "w") as f:
        f.write("BROKEN\n")
    rc2 = main(["rollback", "--hub-root", comp["root"],
                "--backup-dir", bdir, "--tree", "src",
                "--state-dir", comp["state"]])
    assert rc2 == 0
    assert open(os.path.join(comp["root"], "src", "spoke.py")).read() == "OLD_SPOKE\n"


def test_cli_markbadcommit_writes_file(tmp_path):
    from update_recovery import main
    state = str(tmp_path / "st")
    rc = main(["markbadcommit", "deadbee", "--state-dir", state])
    assert rc == 0
    assert is_bad_commit("deadbee", state_dir=state) is True


def test_cli_logging_emits_info_to_recovery_log(tmp_path, monkeypatch):
    """The recovery CLI MUST configure logging — without it every logger.info
    is dropped by the root lastResort handler (WARNING+ only), which is why
    "the recovery log never logged anything". _configure_cli_logging() sets
    root to INFO and attaches a best-effort FileHandler to recovery.log, so an
    INFO record reaches the file in the canonical dashed format.
    """
    import logging
    from update_recovery import _configure_cli_logging

    log_file = tmp_path / "recovery.log"
    monkeypatch.setattr("update_recovery._RECOVERY_LOG_FILE", str(log_file))
    _configure_cli_logging()

    # Root must be at INFO (or below) — the bug was root left at WARNING.
    assert logging.getLogger().level <= logging.INFO

    logging.getLogger("UpdateRecovery").info("RECOVERY_LOG_MARKER snapshot ok")
    for h in logging.getLogger().handlers:
        try:
            h.flush()
        except Exception:
            pass

    assert log_file.exists(), "recovery.log should be created on first INFO record"
    text = log_file.read_text()
    assert "RECOVERY_LOG_MARKER" in text
    # Canonical dashed format, NOT the old dropped/lastResort "WARNING"-only form.
    assert " - UpdateRecovery - INFO - " in text