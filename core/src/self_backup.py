"""Hub self-backup subsystem.

A self-contained, named subsystem gathered here as a **mixin** (mirrors
``staleness_sweep.py``) so the Hub class body shrinks with zero call-site
change. ``api.py`` routes call ``hub.run_backup_now()`` /
``hub.run_self_backup_loop()`` / ``hub.get_self_backup_status()`` — all of
which resolve via inheritance once ``SelfBackupMixin`` is added to
``LabManagerHub`` bases. The method bodies take ``self`` and use the same
state helpers as the other syncs.

Captures a restorable snapshot of hub state into a timestamped, optionally
Fernet-encrypted ``.tar.gz`` under ``<state data_dir>/self-backup/``, prunes to
``keep_count``, and (optionally) pushes the latest backup to a remote host over
``scp`` using an **admin-placed key file** (no private-key/password storage in
config — honors the Fernet-at-rest discipline). All config lives in
``global_config["self_backup"]`` and is read fresh each loop cycle so a WebUI
change takes effect without a restart.

What gets backed up (so a restored hub can re-authenticate its spokes + decrypt
its state — without ALL of these a restore is useless):
  - ``<state data_dir>/*.json`` (+ ``.bak``) — ``system.json``, ``tenants.json``,
    ``simulations_store.json`` (the Fernet-encrypted hub state).
  - ``<key_manager data_dir>/*.json`` — ``keys.json`` (spoke session secrets)
    + ``hub_secret.json`` (the hub root secret). Resolved from
    ``self.key_manager.storage_path``'s directory so it tracks the real
    install location (``/opt/lm/core/data`` in prod).
  - optionally ``/opt/lm/.env`` when ``include_env`` is set — carries
    ``LM_FERNET_KEY``, which is REQUIRED to decrypt the rest of the backup;
    bundled only on explicit opt-in (it is a sensitive file).

Excludes the ``self-backup/`` and ``update-backup/`` subdirs (the backup itself
+ the update-recovery code snapshots) so the archive doesn't recurse or
balloon, and the transient ``running-version`` file.

This module is a **leaf**: it imports only stdlib and ``security.encryption``
(a leaf itself). It must NOT import ``main`` or ``api`` (no back-import — that
would create a cycle, since ``main`` imports this module to pull in the
mixin). Dependency direction is ``main → self_backup`` only.

Audience: Hub developers.
"""

from __future__ import annotations

# asyncio runs tar/scp off the event loop; datetime names archives.
import asyncio
import datetime as _dt
# logging for the hub log; os/re/tarfile build archives; time stamps runs.
import logging
import os
import re
import tarfile
import time
# Type hints only.
from typing import Any, Dict, List, Optional, Tuple

# Hub Fernet key, used to encrypt archives.
from security.encryption import hub_encryption

# Log to the hub's logger.
logger = logging.getLogger("Hub")

# Subdirectory of the state dir that holds the archives.
_SELF_BACKUP_DIR = "self-backup"
# Files we DO back up from a source dir (encrypted JSON state + their .bak
# rolling copies). Everything else in the dir (subdirs, the transient
# running-version file) is skipped.
_STATE_FILE_RE = re.compile(r"^[A-Za-z0-9_.\-]+\.(json|json\.bak)$")
# Where to look for .env when include_env is set. Prod: /opt/lm/.env. Allow an
# explicit override (LM_ENV_PATH) for non-standard installs / dev trees.
def _env_candidates() -> List[str]:
    """Return the .env paths to look for, in order: LM_ENV_PATH override, prod path, dev path."""
    # Explicit override first.
    cands: List[str] = []
    override = os.environ.get("LM_ENV_PATH", "").strip()
    if override:
        cands.append(override)
    # Then the prod path and the per-user dev path.
    cands.append("/opt/lm/.env")
    cands.append(os.path.expanduser("~/.local/share/lm/.env"))
    return cands

# Printable-ASCII gate for the scp argv fields. We pass them as real argv
# elements (create_subprocess_exec, no shell), so metacharacters are NOT
# interpreted — this gate is defense-in-depth against control chars / newline
# / unicode that would corrupt logging or the remote path.
_SSH_FIELD_RE = re.compile(r"^[A-Za-z0-9._~:/@%+\-= ]{1,1024}$")


class SelfBackupMixin:
    """Periodically backs up hub state to a rotated local archive and
    (optionally) pushes it to a remote host over scp.

    Config (``global_config["self_backup"]``): see ``seed_self_backup_defaults``
    for the full key set. Read fresh each cycle so a WebUI change takes effect
    without a restart. Disabled by default — opt-in via Setup → Self-Backup.
    """

    _SELF_BACKUP_CFG_KEY = "self_backup"

    # ── config readers ────────────────────────────────────────────────────
    def _self_backup_cfg(self) -> Dict[str, Any]:
        """Read the self-backup config fresh from global_config."""
        # The config block from global_config, or {}.
        return (self.state.system_state.get("global_config", {})
                .get(self._SELF_BACKUP_CFG_KEY, {})) or {}

    def _sb_int(self, key: str, default: int, minimum: int = 1) -> int:
        """Return an int config value (default on bad input), clamped to at least minimum."""
        # Bad values fall back to the default.
        try:
            v = int(self._self_backup_cfg().get(key, default))
        except (TypeError, ValueError):
            v = default
        return max(minimum, v)

    def _sb_bool(self, key: str, default: bool = False) -> bool:
        """Return a config value as a bool."""
        # Truthiness of the stored value.
        return bool(self._self_backup_cfg().get(key, default))

    def _sb_str(self, key: str, default: str = "") -> str:
        """Return a config value as a string (default when unset or None)."""
        # None falls back to the default.
        v = self._self_backup_cfg().get(key, default)
        return str(v) if v is not None else default

    def seed_self_backup_defaults(self) -> None:
        """Seed ``global_config["self_backup"]`` defaults ONCE at startup if
        the key is absent. Disabled by default — a self-backup is opt-in (the
        user configures the schedule + optional SSH destination in the WebUI).
        A hub that already has the key set — including an explicit
        ``enabled=True`` — is NEVER overwritten. Best-effort: a state/save
        failure is logged DEBUG and swallowed (a backup config must never
        block startup)."""
        # Add the default block only when the key is missing; failures are swallowed.
        try:
            gc = self.state.system_state.setdefault("global_config", {})
            if self._SELF_BACKUP_CFG_KEY not in gc:
                gc[self._SELF_BACKUP_CFG_KEY] = {
                    "enabled": False,
                    "backup_interval_hours": 24,
                    "keep_count": 7,
                    "include_env": False,
                    "encrypt_archive": True,
                    "copy_enabled": False,
                    "copy_mode": "after_each_backup",   # | "own_schedule"
                    "copy_interval_hours": 24,
                    "ssh_host": "",
                    "ssh_port": 22,
                    "ssh_user": "",
                    "ssh_path": "",
                    "ssh_keyfile": "",
                    "ssh_strict_hostkey": False,
                    "last_backup_at": 0.0,
                    "last_copy_at": 0.0,
                    "last_error": "",
                }
                # Save and tell the operator where to enable it.
                self.state._mark_dirty()
                logger.info("self-backup: seeded defaults (disabled by default) — "
                            "enable + schedule in Setup → Self-Backup")
        except Exception as e:  # noqa: BLE001
            logger.debug("self-backup: seed defaults skipped: %s", e)

    # ── paths / sources ──────────────────────────────────────────────────
    def _sb_backup_root(self) -> str:
        """Return the directory that holds backup archives."""
        # Under the state data dir.
        return os.path.join(self.state.data_dir, _SELF_BACKUP_DIR)

    def _sb_resolve_archive(self, name: str) -> Optional[str]:
        """Resolve a backup archive filename to a safe absolute path inside the
        backup root. Rejects path traversal and any non-archive name — returns
        None if it doesn't resolve to a real file directly under the root."""
        # Only the basename, and only archive extensions.
        base = os.path.basename(str(name or ""))
        if not base or not (base.endswith(".tar.gz") or base.endswith(".tgz.enc")):
            return None
        # Resolve symlinks; the file must sit directly in the backup root.
        root = os.path.realpath(self._sb_backup_root())
        p = os.path.realpath(os.path.join(root, base))
        if os.path.dirname(p) != root or not os.path.isfile(p):
            return None
        return p

    def sb_save_uploaded_archive(self, filename: str, data: bytes) -> Dict[str, Any]:
        """Store an operator-uploaded backup archive into the backup dir so it
        appears in the list and can be restored on-box (system-recovery). The
        name is sanitised to a basename and must be a real archive extension."""
        # Basename only (no NUL bytes) with an archive extension.
        base = os.path.basename(str(filename or "")).replace("\x00", "")
        if not (base.endswith(".tar.gz") or base.endswith(".tgz.enc")):
            raise ValueError("upload must be a .tar.gz or .tgz.enc backup archive")
        # Make sure the backup dir exists and write the file there.
        root = self._sb_backup_root()
        os.makedirs(root, exist_ok=True)
        dest = os.path.join(root, base)
        with open(dest, "wb") as f:
            f.write(data)
        logger.info("self-backup: uploaded archive stored (%s, %d bytes)", base, len(data))
        return {"name": base, "size": len(data)}

    def _sb_sources(self) -> List[Tuple[str, str]]:
        """(label, dir) pairs to archive. label becomes the top-level dir
        inside the tarball so a restore operator knows where each file came
        from."""
        # Always back up the state dir.
        srcs: List[Tuple[str, str]] = [("state", self.state.data_dir)]
        # Also the key manager's dir, when it exists.
        try:
            km_dir = os.path.dirname(os.path.abspath(self.key_manager.storage_path))
            if km_dir and os.path.isdir(km_dir):
                srcs.append(("keys", km_dir))
        except Exception:  # noqa: BLE001
            pass
        return srcs

    def _sb_latest_backup(self) -> Optional[str]:
        """Newest archive in the self-backup dir (by mtime), or None."""
        # No backup dir yet: nothing to return.
        root = self._sb_backup_root()
        if not os.path.isdir(root):
            return None
        # Archives in the dir that are real files.
        files = [os.path.join(root, f) for f in os.listdir(root)
                 if f.endswith(".tar.gz") or f.endswith(".tgz.enc")]
        files = [p for p in files if os.path.isfile(p)]
        if not files:
            return None
        # Newest by modification time.
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return files[0]

    # ── status persistence (last_backup_at / last_copy_at / last_error) ──
    def _sb_set_status(self, last_backup_at: Optional[float] = None,
                      last_copy_at: Optional[float] = None,
                      last_error: Optional[str] = None) -> None:
        """Persist run status back into global_config["self_backup"] so the
        WebUI status panel reflects it. Best-effort; never raises."""
        # Update only the fields given and save; failures are swallowed.
        try:
            gc = self.state.system_state.setdefault("global_config", {})
            sb = gc.setdefault(self._SELF_BACKUP_CFG_KEY, {})
            if last_backup_at is not None:
                sb["last_backup_at"] = float(last_backup_at)
            if last_copy_at is not None:
                sb["last_copy_at"] = float(last_copy_at)
            if last_error is not None:
                sb["last_error"] = last_error
            self.state._mark_dirty()
        except Exception as e:  # noqa: BLE001
            logger.debug("self-backup: status persist skipped: %s", e)

    # ── the archive build (runs in a worker thread) ──────────────────────
    def _sb_make_tarball(self, out_path: str, sources: List[Tuple[str, str]],
                        include_env: bool, encrypt: bool) -> str:
        """Build the gzip tarball at ``out_path`` (or a Fernet-encrypted
        ``.tgz.enc`` variant). Returns the final written path. Sync — call via
        ``asyncio.to_thread``."""
        # Write the plain tarball to a temp path first.
        tmp = out_path + ".tmp"
        with tarfile.open(tmp, "w:gz") as tar:
            # Add the matching state files from each source dir under its label.
            for label, dpath in sources:
                if not os.path.isdir(dpath):
                    continue
                for name in sorted(os.listdir(dpath)):
                    full = os.path.join(dpath, name)
                    # Skip subdirs, non-files, non-state names, and the running-version marker.
                    if os.path.isdir(full):
                        continue  # skip self-backup/ + update-backup/ subdirs
                    if not os.path.isfile(full):
                        continue
                    if not _STATE_FILE_RE.match(name):
                        continue
                    if name.startswith("running-version"):
                        continue
                    # Store under "<label>/<name>".
                    tar.add(full, arcname=os.path.join(label, name))
            # Optionally bundle the first .env found.
            if include_env:
                for cand in _env_candidates():
                    if os.path.isfile(cand):
                        tar.add(cand, arcname=os.path.join("env", os.path.basename(cand)))
                        break
        # Encrypted: Fernet-encrypt the tarball into the final path and drop the temp.
        if encrypt:
            with open(tmp, "rb") as f:
                blob = f.read()
            enc = hub_encryption.fernet.encrypt(blob)
            with open(out_path, "wb") as f:
                f.write(enc)
            try:
                os.remove(tmp)
            except OSError:
                pass
        # Plain: rename the temp into place.
        else:
            os.replace(tmp, out_path)
        # Owner-only permissions (best-effort).
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        return out_path

    def _sb_prune(self, keep: int) -> int:
        """Delete oldest archives beyond ``keep`` (by mtime). Best-effort."""
        # List archives newest first and delete everything past keep; errors yield 0.
        try:
            root = self._sb_backup_root()
            if not os.path.isdir(root):
                return 0
            # Archive files directly in the backup dir.
            files = [os.path.join(root, f) for f in os.listdir(root)
                     if (f.endswith(".tar.gz") or f.endswith(".tgz.enc"))
                     and os.path.isfile(os.path.join(root, f))]
            # Newest first.
            files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            removed = 0
            # Delete the excess (a failed delete still counts).
            for stale in files[keep:]:
                try:
                    os.remove(stale)
                except OSError:
                    pass
                removed += 1
            return removed
        except Exception:  # noqa: BLE001
            return 0

    # ── public ops ───────────────────────────────────────────────────────
    async def run_backup_now(self) -> Dict[str, Any]:
        """Take one backup now: flush state → tar+gzip the state + key stores
        (optionally encrypt + include .env) → prune → record status → (if
        copy_enabled + after_each_backup) push. Idempotent + best-effort:
        returns an ``{status, ...}`` dict; never raises (the loop + routes
        depend on this)."""
        # Read config and settings for this run.
        cfg = self._self_backup_cfg()
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        encrypt = self._sb_bool("encrypt_archive", True)
        include_env = self._sb_bool("include_env", False)
        keep = self._sb_int("keep_count", 7, 1)
        # Timestamped file name in the backup dir.
        ext = "tgz.enc" if encrypt else "tar.gz"
        root = self._sb_backup_root()
        out_path = os.path.join(root, f"{ts}.{ext}")
        # Directories to archive.
        sources = self._sb_sources()
        # Build, prune, and record; any failure becomes an error result.
        try:
            # Flush the in-memory state so the archive captures the latest
            # writes (not just the last 60s persistence-loop tick).
            try:
                await self.state.save_state_now()
            except Exception as e:  # noqa: BLE001
                logger.debug("self-backup: pre-flush state skipped: %s", e)
            # Create the backup dir and lock it to owner-only.
            os.makedirs(root, exist_ok=True)
            try:
                os.chmod(root, 0o700)
            except OSError:
                pass
            # Build the archive in a worker thread.
            await asyncio.to_thread(self._sb_make_tarball, out_path, sources,
                                    include_env, encrypt)
            # Size the archive, then prune old ones off-loop.
            size = os.path.getsize(out_path)
            removed = await asyncio.to_thread(self._sb_prune, keep)
            # Record success and log.
            self._sb_set_status(last_backup_at=time.time(), last_error="")
            logger.info("[self-backup] backup ok %s size=%d bytes pruned=%d",
                        os.path.basename(out_path), size, removed)
            # Result for the caller.
            result: Dict[str, Any] = {"status": "ok", "path": out_path,
                                     "name": os.path.basename(out_path),
                                     "size": size, "pruned": removed, "ts": ts,
                                     "encrypted": encrypt}
            # after_each_backup copy fires immediately on a fresh backup.
            if (self._sb_bool("copy_enabled", False)
                    and self._sb_str("copy_mode", "after_each_backup")
                    == "after_each_backup"):
                result["copy"] = await self._sb_run_copy(out_path)
            return result
        # Record and log the failure.
        except Exception as e:  # noqa: BLE001
            self._sb_set_status(last_error=f"backup: {e}")
            logger.warning("[sync-error] self-backup run failed: %s", e)
            return {"status": "error", "error": str(e), "ts": ts}

    async def _sb_run_copy(self, local_file: Optional[str] = None) -> Dict[str, Any]:
        """scp the latest (or given) backup to the configured remote. Returns
        ``{status, ...}``. Never raises."""
        # Read the SSH destination settings.
        cfg = self._self_backup_cfg()
        host = self._sb_str("ssh_host", "")
        user = self._sb_str("ssh_user", "")
        rpath = self._sb_str("ssh_path", "")
        keyfile = self._sb_str("ssh_keyfile", "")
        # Port, defaulting to 22 on bad input.
        try:
            port = int(cfg.get("ssh_port", 22) or 22)
        except (TypeError, ValueError):
            port = 22
        # Whether to verify the remote host key.
        strict = self._sb_bool("ssh_strict_hostkey", False)
        # defense-in-depth charset gate (we use exec, not shell)
        for label, v in (("host", host), ("user", user),
                         ("path", rpath), ("keyfile", keyfile)):
            if not v:
                msg = f"ssh_{label} not configured"
                self._sb_set_status(last_error=f"copy: {msg}")
                return {"status": "error", "error": msg}
            if not _SSH_FIELD_RE.match(v):
                msg = f"ssh_{label} has invalid characters"
                self._sb_set_status(last_error=f"copy: {msg}")
                return {"status": "error", "error": msg}
        # Default to the newest local archive; it must exist.
        if local_file is None:
            local_file = self._sb_latest_backup()
        if not local_file or not os.path.isfile(local_file):
            self._sb_set_status(last_error="copy: no local backup to copy")
            return {"status": "error", "error": "no local backup to copy"}
        # scp argv: key file, host-key mode, no prompts, custom port, source and destination.
        argv = ["scp", "-i", keyfile,
                "-o", f"StrictHostKeyChecking={'yes' if strict else 'no'}",
                "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no",
                "-P", str(port),
                local_file, f"{user}@{host}:{rpath}"]
        # Run scp with a 2-minute timeout.
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            # On timeout kill scp and record the error.
            try:
                _out, errb = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:  # noqa: BLE001
                    pass
                self._sb_set_status(last_error="copy: timeout")
                logger.warning("[sync-error] self-backup copy timeout to %s", host)
                return {"status": "error", "error": "timeout"}
            # Exit code 0: record success.
            rc = proc.returncode
            if rc == 0:
                self._sb_set_status(last_copy_at=time.time(), last_error="")
                logger.info("[self-backup] copy ok %s -> %s@%s:%s",
                            os.path.basename(local_file), user, host, rpath)
                return {"status": "ok", "file": os.path.basename(local_file)}
            # Otherwise record stderr as the error.
            msg = errb.decode(errors="replace").strip()[:300]
            self._sb_set_status(last_error=f"copy: rc={rc} {msg}")
            logger.warning("[sync-error] self-backup copy failed rc=%d: %s", rc, msg)
            return {"status": "error", "error": msg, "rc": rc}
        # scp missing, or any other launch failure.
        except FileNotFoundError:
            self._sb_set_status(last_error="copy: scp not installed")
            return {"status": "error", "error": "scp not installed on hub"}
        except Exception as e:  # noqa: BLE001
            self._sb_set_status(last_error=f"copy: {e}")
            logger.warning("[sync-error] self-backup copy failed: %s", e)
            return {"status": "error", "error": str(e)}

    async def test_self_backup_copy(self) -> Dict[str, Any]:
        """Manual 'Test copy' from the WebUI: push the latest backup once,
        regardless of the schedule. Returns the copy result dict."""
        # Copy the newest archive now.
        return await self._sb_run_copy()

    def get_self_backup_status(self) -> Dict[str, Any]:
        """Snapshot of config + on-disk archives for the WebUI status panel.
        Never exposes private-key material (ssh_keyfile is a path only)."""
        # Config, backup dir, and the archive listing to fill.
        cfg = self._self_backup_cfg()
        root = self._sb_backup_root()
        files: List[Dict[str, Any]] = []
        total = 0
        # List each archive with size and mtime, and total the sizes.
        if os.path.isdir(root):
            for f in os.listdir(root):
                p = os.path.join(root, f)
                if os.path.isfile(p) and (f.endswith(".tar.gz")
                                         or f.endswith(".tgz.enc")):
                    try:
                        sz = os.path.getsize(p)
                        files.append({"name": f, "size": sz,
                                      "mtime": os.path.getmtime(p)})
                        total += sz
                    except OSError:
                        pass
        # Newest first.
        files.sort(key=lambda x: x.get("mtime", 0), reverse=True)
        latest = self._sb_latest_backup()
        # Config values plus on-disk archive details.
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "backup_interval_hours": self._sb_int("backup_interval_hours", 24, 1),
            "keep_count": self._sb_int("keep_count", 7, 1),
            "include_env": self._sb_bool("include_env", False),
            "encrypt_archive": self._sb_bool("encrypt_archive", True),
            "copy_enabled": self._sb_bool("copy_enabled", False),
            "copy_mode": self._sb_str("copy_mode", "after_each_backup"),
            "copy_interval_hours": self._sb_int("copy_interval_hours", 24, 1),
            "ssh_host": self._sb_str("ssh_host", ""),
            "ssh_port": int(cfg.get("ssh_port", 22) or 22),
            "ssh_user": self._sb_str("ssh_user", ""),
            "ssh_path": self._sb_str("ssh_path", ""),
            "ssh_keyfile": self._sb_str("ssh_keyfile", ""),
            "ssh_strict_hostkey": self._sb_bool("ssh_strict_hostkey", False),
            "last_backup_at": float(cfg.get("last_backup_at", 0.0) or 0.0),
            "last_copy_at": float(cfg.get("last_copy_at", 0.0) or 0.0),
            "last_error": self._sb_str("last_error", ""),
            "backups": files,
            "backup_count": len(files),
            "total_bytes": total,
            "latest": os.path.basename(latest) if latest else None,
        }

    # ── the scheduled loop ───────────────────────────────────────────────
    async def run_self_backup_loop(self):
        """Periodically take a backup per ``backup_interval_hours`` and, in
        ``own_schedule`` copy mode, push on ``copy_interval_hours``. Reads the
        config fresh each cycle so a WebUI change takes effect without a
        restart. Disabled → 60s re-check. ``after_each_backup`` copy mode is
        handled inside ``run_backup_now`` (fires right after a successful
        backup), so this loop only drives the independent ``own_schedule``
        copy. Staggered ~120s after startup so it doesn't fire alongside the
        heavy syncs on boot."""
        # Initial stagger after startup.
        await asyncio.sleep(120)
        # Loop forever; a failed cycle only logs.
        while True:
            try:
                # Disabled: check again in a minute.
                cfg = self._self_backup_cfg()
                if not cfg.get("enabled", False):
                    await asyncio.sleep(60)
                    continue
                # Back up when the interval has elapsed since the last backup.
                now = time.time()
                last_b = float(cfg.get("last_backup_at", 0.0) or 0.0)
                interval_b = self._sb_int("backup_interval_hours", 24, 1) * 3600
                if now - last_b >= interval_b:
                    await self.run_backup_now()
                # Re-read config: run_backup_now may have updated last_*_at.
                cfg = self._self_backup_cfg()
                # own_schedule copy mode: copy when its own interval has elapsed.
                if (cfg.get("copy_enabled", False)
                        and self._sb_str("copy_mode", "after_each_backup")
                        == "own_schedule"):
                    last_c = float(cfg.get("last_copy_at", 0.0) or 0.0)
                    interval_c = self._sb_int("copy_interval_hours", 24, 1) * 3600
                    if now - last_c >= interval_c:
                        await self._sb_run_copy()
                # Re-check every 5 min so an interval change applies promptly
                # (the cadence itself is hourly-scale, so 5 min polling is fine).
                await asyncio.sleep(300)
            except Exception as e:  # noqa: BLE001
                logger.warning("[sync-error] self-backup loop cycle failed: %s", e)
                await asyncio.sleep(60)