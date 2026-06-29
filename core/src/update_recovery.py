"""Hub / WebUI update-recovery helpers.

Gives both update paths a pre-swap code snapshot, a post-restart health gate,
and a bad-version registry so a broken update can be rolled back instead of
leaving the hub dark:

- **Auto path** — ``Hub.perform_update`` (``main.py``) snapshots the code
  before a ``git pull``/tarball swap, writes a "pending update" manifest, then
  hands off to the root-run ``lm-update-restart`` helper (installed by
  ``install_all.sh``) which restarts the hub, polls ``/status``, and restores
  the snapshot if the new version won't boot.
- **Manual path** — ``install_all.sh`` snapshots before its destructive
  ``rm -rf core WebUI`` and, on the 60s ``/status`` poll failure, restores the
  snapshot inline (it already runs as root with the hub stopped).

All recovery state lives under the hub state dir (``/var/lib/lm/state`` in
prod) so it survives code swaps and is writable by the hub process (svc_lm)
and readable/writable by the root helper. The bash helper re-implements the
trivial JSON read/write with ``jq`` against these SAME paths and formats — keep
them in sync if you change anything here.

Python 3.9/3.11 note: prod runs 3.11, the dev machine runs 3.9, so this module
uses ``Optional[X]``/``Set``/``Dict`` (not ``X | None`` / ``set[X]``) — PEP 604
container syntax is 3.10+ and would break the dev ``py_compile`` check.
"""
import argparse
import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional, Set

logger = logging.getLogger("UpdateRecovery")

# ── Paths / tunables ───────────────────────────────────────────────────────
# Default to the prod state dir; allow an override for tests / non-standard
# installs (the hub StateManager falls back to ~/.local/share/lm/state in dev,
# but updates/recovery only run for real in prod where the systemd units exist).
STATE_DIR = os.environ.get("LM_STATE_DIR", "/var/lib/lm/state")
BACKUP_ROOT = os.path.join(STATE_DIR, "update-backup")
PENDING_PATH = os.path.join(STATE_DIR, "pending_update.json")
BAD_VERSIONS_PATH = os.path.join(STATE_DIR, "bad_versions.json")
FAILED_PATH = os.path.join(STATE_DIR, "update_failed.json")

# How long the root helper waits for the new version to reach /status 200, and
# how long it then waits for the rolled-back version to come back. Mirrors the
# 60s readiness poll install_all.sh already uses.
HEALTH_TIMEOUT = 60
ROLLBACK_TIMEOUT = 30
# Pre-swap snapshots retained on disk (newer ones win; oldest pruned).
KEEP_BACKUPS = 3


# ── Version comparison ─────────────────────────────────────────────────────
def _ver_tuple(v: str):
    """Parse a dotted version string into a tuple of ints for comparison.

    Matches perform_update's own ``_ver`` helper. Non-numeric versions fall
    back to (0, 0, 0) so a malformed VERSION file never crashes the registry.
    """
    try:
        return tuple(int(x) for x in (v or "").strip().split("."))
    except Exception:
        return (0, 0, 0)


# ── Pre-swap snapshot ─────────────────────────────────────────────────────
def snapshot_code(hub_root: str, ts: str) -> str:
    """Copy ``core/src`` + ``WebUI`` into ``update-backup/<ts>/``.

    These are the only trees a code update swaps and the only ones that can
    break the boot (venv/data/state are preserved separately by both paths).
    Returns the backup directory (absolute). The caller stamps ``ts`` (the
    hub process may use the wall clock; workflow scripts must pass one in).
    """
    os.makedirs(BACKUP_ROOT, exist_ok=True)
    backup_dir = os.path.join(BACKUP_ROOT, str(ts))
    # If a same-timestamp dir already exists (fast double-update), reuse it.
    os.makedirs(backup_dir, exist_ok=True)
    src = os.path.join(hub_root, "core", "src")
    webui = os.path.join(hub_root, "WebUI")
    if os.path.isdir(src):
        shutil.copytree(src, os.path.join(backup_dir, "src"), dirs_exist_ok=True)
    if os.path.isdir(webui):
        shutil.copytree(webui, os.path.join(backup_dir, "WebUI"), dirs_exist_ok=True)
    logger.info("update snapshot saved to %s", backup_dir)
    return backup_dir


def prune_backups(keep: int = KEEP_BACKUPS) -> int:
    """Delete oldest backups beyond ``keep`` (by directory mtime). Returns the
    number removed. Best-effort: never raises."""
    try:
        if not os.path.isdir(BACKUP_ROOT):
            return 0
        entries = [
            os.path.join(BACKUP_ROOT, d)
            for d in os.listdir(BACKUP_ROOT)
            if os.path.isdir(os.path.join(BACKUP_ROOT, d))
        ]
        entries.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        removed = 0
        for stale in entries[keep:]:
            shutil.rmtree(stale, ignore_errors=True)
            removed += 1
        return removed
    except Exception as e:  # pragma: no cover - disk/fs errors only
        logger.warning("prune_backups failed: %s", e)
        return 0


# ── Pending-update manifest ────────────────────────────────────────────────
def write_pending(backup_dir: str, from_version: str, to_version: str, ts: str) -> None:
    """Record the in-flight update so the root helper knows what to roll back.

    Present only between "snapshot taken" and "health verified / rolled back".
    The helper reads ``backup_dir`` + ``to_version`` + ``from_version`` here.
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    payload = {
        "backup_dir": backup_dir,
        "from_version": from_version,
        "to_version": to_version,
        "ts": ts,
    }
    with open(PENDING_PATH, "w") as f:
        json.dump(payload, f)
    logger.info("pending update manifest written: %s -> %s", from_version, to_version)


def read_pending() -> Optional[Dict[str, Any]]:
    """Return the pending-update manifest, or None if none/invalid."""
    try:
        with open(PENDING_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning("read_pending failed: %s", e)
        return None


def clear_pending() -> None:
    """Remove the pending manifest (success or rollback complete). Best-effort."""
    try:
        if os.path.exists(PENDING_PATH):
            os.remove(PENDING_PATH)
    except Exception as e:  # pragma: no cover
        logger.warning("clear_pending failed: %s", e)


# ── Bad-version registry ──────────────────────────────────────────────────
def read_bad_versions() -> Set[str]:
    """Versions that failed to boot and were rolled back. The auto loop skips
    re-pulling any version in this set (until a newer remote version clears it)."""
    try:
        with open(BAD_VERSIONS_PATH) as f:
            data = json.load(f)
        return set(data.get("versions", []))
    except FileNotFoundError:
        return set()
    except Exception as e:
        logger.warning("read_bad_versions failed: %s", e)
        return set()


def _write_bad_versions(versions: Set[str]) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(BAD_VERSIONS_PATH, "w") as f:
        json.dump({"versions": sorted(versions)}, f, indent=2)


def add_bad_version(version: str) -> None:
    """Mark a version bad (it was rolled back after failing to boot)."""
    versions = read_bad_versions()
    if version and version not in versions:
        versions.add(version)
        _write_bad_versions(versions)
        logger.warning("marked version %s bad (failed to boot, rolled back)", version)


def is_version_bad(version: str) -> bool:
    return version in read_bad_versions()


def clear_bad_versions_older_than(threshold: str) -> int:
    """Drop bad-version entries older than ``threshold`` — called when a newer
    remote version appears, so stale "don't pull 1.0.9" entries clear once the
    hub is moving forward to 1.0.10. Returns the number removed."""
    thresh = _ver_tuple(threshold)
    versions = read_bad_versions()
    keep = {v for v in versions if _ver_tuple(v) >= thresh}
    removed = len(versions) - len(keep)
    if removed:
        _write_bad_versions(keep)
        logger.info("cleared %d stale bad-version entries older than %s", removed, threshold)
    return removed


# ── Double-failure marker ─────────────────────────────────────────────────
def write_update_failed(to_version: str, backup_dir: str, reason: str) -> None:
    """Last-resort marker: the new version failed AND the rollback also failed
    to boot. Carries the bad version + backup location so an operator can
    recover manually (the backup is preserved on disk)."""
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(FAILED_PATH, "w") as f:
        json.dump(
            {"to_version": to_version, "backup_dir": backup_dir, "reason": reason},
            f,
            indent=2,
        )
    logger.error("update FAILED and rollback also failed: %s (backup at %s)", to_version, backup_dir)


# ── Snapshot restore (rollback) ────────────────────────────────────────────
def restore_snapshot(backup_dir: str, hub_root: str, chown_user: Optional[str] = None) -> bool:
    """Restore a pre-swap snapshot (``core/src`` + ``WebUI``) back into the hub
    root. Returns True if the snapshot was restored, False if no usable snapshot
    exists (missing backup_dir or missing src tree). Best-effort on the copy:
    a partial WebUI restore is ignored (matches the bash ``cp -a ... || true``
    leniency). ``chown_user`` recursively re-owns the restored trees to
    ``user:user`` (None = skip, used when already running as that user)."""
    if not backup_dir or not os.path.isdir(os.path.join(backup_dir, "src")):
        return False
    src_dst = os.path.join(hub_root, "core", "src")
    webui_dst = os.path.join(hub_root, "WebUI")
    # Wipe the failed-code trees before restoring (matches ``rm -rf`` in bash).
    shutil.rmtree(src_dst, ignore_errors=True)
    shutil.rmtree(webui_dst, ignore_errors=True)
    shutil.copytree(os.path.join(backup_dir, "src"), src_dst, dirs_exist_ok=True)
    if os.path.isdir(os.path.join(backup_dir, "WebUI")):
        try:
            shutil.copytree(os.path.join(backup_dir, "WebUI"), webui_dst, dirs_exist_ok=True)
        except Exception as e:  # best-effort: WebUI is optional for boot
            logger.warning("WebUI restore skipped: %s", e)
    if chown_user:
        _chown_tree(src_dst, chown_user)
        _chown_tree(webui_dst, chown_user)
    logger.info("snapshot restored from %s", backup_dir)
    return True


def _chown_tree(path: str, user: str) -> None:
    """Recursively ``chown -R user:user`` (best-effort, mirrors the bash
    ``2>/dev/null || true`` semantics)."""
    try:
        subprocess.run(
            ["chown", "-R", "{0}:{0}".format(user), path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    except Exception as e:  # pragma: no cover - chown missing / denied
        logger.warning("chown %s to %s failed: %s", path, user, e)


# ── CLI entrypoint ─────────────────────────────────────────────────────────
# Single source of truth for the on-disk recovery state machine. The bash
# blocks that previously re-implemented these JSON writes / cp / prune in jq
# (install_all.sh recovery_* helpers and the /usr/local/bin/lm-update-restart
# heredoc) now shell out here. State paths/formats are defined ABOVE in this
# module; the CLI only wires arguments to those functions. All subcommands are
# best-effort and exit 0 on success; ``rollback`` always exits 0 and reports
# success/failure in its JSON payload so callers under ``set -e`` can parse it.
#
# Usage:
#   python3 update_recovery.py snapshot   --hub-root R --from-version F --to-version T [--ts TS] [--chown-user U]
#   python3 update_recovery.py rollback   --hub-root R [--chown-user U]
#   python3 update_recovery.py markbad    VERSION [--chown-user U]
#   python3 update_recovery.py clearpending
#   python3 update_recovery.py writefailed --to-version V --backup-dir D --reason R [--chown-user U]
#   python3 update_recovery.py prune      [--keep N]
def _cli_snapshot(args) -> int:
    ts = args.ts or datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    try:
        bdir = snapshot_code(args.hub_root, ts)
    except Exception as e:
        logger.warning("snapshot_code failed: %s", e)
        print("", end="")
        return 1
    write_pending(bdir, args.from_version, args.to_version, ts)
    if args.chown_user:
        _chown_tree(STATE_DIR, args.chown_user)
    print(bdir)
    return 0


def _cli_rollback(args) -> int:
    # The caller (bash) reads the pending manifest itself — that preserves the
    # original log ordering (the "Rolling back..." line is printed BEFORE the
    # restore). This subcommand does ONLY the restore cp given an explicit
    # backup_dir, so bash keeps its exact flow and the cp is delegated here.
    bdir = args.backup_dir or ""
    ok = restore_snapshot(bdir, args.hub_root, chown_user=args.chown_user)
    payload = {"ok": ok, "backup_dir": bdir,
               "reason": "" if ok else "no snapshot; new version failed to boot"}
    json.dump(payload, sys.stdout)
    print("")
    return 0


def _cli_markbad(args) -> int:
    add_bad_version(args.version)
    if args.chown_user:
        try:
            subprocess.run(
                ["chown", "{0}:{0}".format(args.chown_user), BAD_VERSIONS_PATH],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        except Exception:
            pass
    return 0


def _cli_clearpending(args) -> int:
    clear_pending()
    return 0


def _cli_writefailed(args) -> int:
    write_update_failed(args.to_version, args.backup_dir, args.reason)
    if args.chown_user:
        try:
            subprocess.run(
                ["chown", "{0}:{0}".format(args.chown_user), FAILED_PATH],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        except Exception:
            pass
    return 0


def _cli_prune(args) -> int:
    removed = prune_backups(args.keep)
    print(removed)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="update_recovery", description="Hub update-recovery state machine CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("snapshot", help="snapshot core/src+WebUI and write pending manifest")
    p.add_argument("--hub-root", required=True)
    p.add_argument("--from-version", required=True)
    p.add_argument("--to-version", required=True)
    p.add_argument("--ts", default=None)
    p.add_argument("--chown-user", default=None)
    p.set_defaults(func=_cli_snapshot)

    p = sub.add_parser("rollback", help="restore a snapshot back into hub-root")
    p.add_argument("--hub-root", required=True)
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--chown-user", default=None)
    p.set_defaults(func=_cli_rollback)

    p = sub.add_parser("markbad", help="mark a version bad (skip re-pull)")
    p.add_argument("version")
    p.add_argument("--chown-user", default=None)
    p.set_defaults(func=_cli_markbad)

    p = sub.add_parser("clearpending", help="clear the pending-update manifest")
    p.set_defaults(func=_cli_clearpending)

    p = sub.add_parser("writefailed", help="write the double-failure marker")
    p.add_argument("--to-version", required=True)
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--chown-user", default=None)
    p.set_defaults(func=_cli_writefailed)

    p = sub.add_parser("prune", help="prune old snapshots (keep newest N)")
    p.add_argument("--keep", type=int, default=KEEP_BACKUPS)
    p.set_defaults(func=_cli_prune)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())