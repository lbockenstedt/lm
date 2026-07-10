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

import asyncio
import datetime as _dt
import logging
import os
import re
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple

from security.encryption import hub_encryption

logger = logging.getLogger("Hub")

_SELF_BACKUP_DIR = "self-backup"
# Files we DO back up from a source dir (encrypted JSON state + their .bak
# rolling copies). Everything else in the dir (subdirs, the transient
# running-version file) is skipped.
_STATE_FILE_RE = re.compile(r"^[A-Za-z0-9_.\-]+\.(json|json\.bak)$")
# Where to look for .env when include_env is set. Prod: /opt/lm/.env. Allow an
# explicit override (LM_ENV_PATH) for non-standard installs / dev trees.
def _env_candidates() -> List[str]:
    cands: List[str] = []
    override = os.environ.get("LM_ENV_PATH", "").strip()
    if override:
        cands.append(override)
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
        return (self.state.system_state.get("global_config", {})
                .get(self._SELF_BACKUP_CFG_KEY, {})) or {}

    def _sb_int(self, key: str, default: int, minimum: int = 1) -> int:
        try:
            v = int(self._self_backup_cfg().get(key, default))
        except (TypeError, ValueError):
            v = default
        return max(minimum, v)

    def _sb_bool(self, key: str, default: bool = False) -> bool:
        return bool(self._self_backup_cfg().get(key, default))

    def _sb_str(self, key: str, default: str = "") -> str:
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
                self.state.save_state()
                logger.info("self-backup: seeded defaults (disabled by default) — "
                            "enable + schedule in Setup → Self-Backup")
        except Exception as e:  # noqa: BLE001
            logger.debug("self-backup: seed defaults skipped: %s", e)

    # ── paths / sources ──────────────────────────────────────────────────
    def _sb_backup_root(self) -> str:
        return os.path.join(self.state.data_dir, _SELF_BACKUP_DIR)

    def _sb_sources(self) -> List[Tuple[str, str]]:
        """(label, dir) pairs to archive. label becomes the top-level dir
        inside the tarball so a restore operator knows where each file came
        from."""
        srcs: List[Tuple[str, str]] = [("state", self.state.data_dir)]
        try:
            km_dir = os.path.dirname(os.path.abspath(self.key_manager.storage_path))
            if km_dir and os.path.isdir(km_dir):
                srcs.append(("keys", km_dir))
        except Exception:  # noqa: BLE001
            pass
        return srcs

    def _sb_latest_backup(self) -> Optional[str]:
        """Newest archive in the self-backup dir (by mtime), or None."""
        root = self._sb_backup_root()
        if not os.path.isdir(root):
            return None
        files = [os.path.join(root, f) for f in os.listdir(root)
                 if f.endswith(".tar.gz") or f.endswith(".tgz.enc")]
        files = [p for p in files if os.path.isfile(p)]
        if not files:
            return None
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return files[0]

    # ── status persistence (last_backup_at / last_copy_at / last_error) ──
    def _sb_set_status(self, last_backup_at: Optional[float] = None,
                      last_copy_at: Optional[float] = None,
                      last_error: Optional[str] = None) -> None:
        """Persist run status back into global_config["self_backup"] so the
        WebUI status panel reflects it. Best-effort; never raises."""
        try:
            gc = self.state.system_state.setdefault("global_config", {})
            sb = gc.setdefault(self._SELF_BACKUP_CFG_KEY, {})
            if last_backup_at is not None:
                sb["last_backup_at"] = float(last_backup_at)
            if last_copy_at is not None:
                sb["last_copy_at"] = float(last_copy_at)
            if last_error is not None:
                sb["last_error"] = last_error
            self.state.save_state()
        except Exception as e:  # noqa: BLE001
            logger.debug("self-backup: status persist skipped: %s", e)

    # ── the archive build (runs in a worker thread) ──────────────────────
    def _sb_make_tarball(self, out_path: str, sources: List[Tuple[str, str]],
                        include_env: bool, encrypt: bool) -> str:
        """Build the gzip tarball at ``out_path`` (or a Fernet-encrypted
        ``.tgz.enc`` variant). Returns the final written path. Sync — call via
        ``asyncio.to_thread``."""
        tmp = out_path + ".tmp"
        with tarfile.open(tmp, "w:gz") as tar:
            for label, dpath in sources:
                if not os.path.isdir(dpath):
                    continue
                for name in sorted(os.listdir(dpath)):
                    full = os.path.join(dpath, name)
                    if os.path.isdir(full):
                        continue  # skip self-backup/ + update-backup/ subdirs
                    if not os.path.isfile(full):
                        continue
                    if not _STATE_FILE_RE.match(name):
                        continue
                    if name.startswith("running-version"):
                        continue
                    tar.add(full, arcname=os.path.join(label, name))
            if include_env:
                for cand in _env_candidates():
                    if os.path.isfile(cand):
                        tar.add(cand, arcname=os.path.join("env", os.path.basename(cand)))
                        break
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
        else:
            os.replace(tmp, out_path)
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        return out_path

    def _sb_prune(self, keep: int) -> int:
        """Delete oldest archives beyond ``keep`` (by mtime). Best-effort."""
        try:
            root = self._sb_backup_root()
            if not os.path.isdir(root):
                return 0
            files = [os.path.join(root, f) for f in os.listdir(root)
                     if (f.endswith(".tar.gz") or f.endswith(".tgz.enc"))
                     and os.path.isfile(os.path.join(root, f))]
            files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            removed = 0
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
        cfg = self._self_backup_cfg()
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        encrypt = self._sb_bool("encrypt_archive", True)
        include_env = self._sb_bool("include_env", False)
        keep = self._sb_int("keep_count", 7, 1)
        ext = "tgz.enc" if encrypt else "tar.gz"
        root = self._sb_backup_root()
        out_path = os.path.join(root, f"{ts}.{ext}")
        sources = self._sb_sources()
        try:
            # Flush the in-memory state so the archive captures the latest
            # writes (not just the last 60s persistence-loop tick).
            try:
                self.state.save_state()
            except Exception as e:  # noqa: BLE001
                logger.debug("self-backup: pre-flush state skipped: %s", e)
            os.makedirs(root, exist_ok=True)
            try:
                os.chmod(root, 0o700)
            except OSError:
                pass
            await asyncio.to_thread(self._sb_make_tarball, out_path, sources,
                                    include_env, encrypt)
            size = os.path.getsize(out_path)
            removed = await asyncio.to_thread(self._sb_prune, keep)
            self._sb_set_status(last_backup_at=time.time(), last_error="")
            logger.info("[self-backup] backup ok %s size=%d bytes pruned=%d",
                        os.path.basename(out_path), size, removed)
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
        except Exception as e:  # noqa: BLE001
            self._sb_set_status(last_error=f"backup: {e}")
            logger.warning("[sync-error] self-backup run failed: %s", e)
            return {"status": "error", "error": str(e), "ts": ts}

    async def _sb_run_copy(self, local_file: Optional[str] = None) -> Dict[str, Any]:
        """scp the latest (or given) backup to the configured remote. Returns
        ``{status, ...}``. Never raises."""
        cfg = self._self_backup_cfg()
        host = self._sb_str("ssh_host", "")
        user = self._sb_str("ssh_user", "")
        rpath = self._sb_str("ssh_path", "")
        keyfile = self._sb_str("ssh_keyfile", "")
        try:
            port = int(cfg.get("ssh_port", 22) or 22)
        except (TypeError, ValueError):
            port = 22
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
        if local_file is None:
            local_file = self._sb_latest_backup()
        if not local_file or not os.path.isfile(local_file):
            self._sb_set_status(last_error="copy: no local backup to copy")
            return {"status": "error", "error": "no local backup to copy"}
        argv = ["scp", "-i", keyfile,
                "-o", f"StrictHostKeyChecking={'yes' if strict else 'no'}",
                "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no",
                "-P", str(port),
                local_file, f"{user}@{host}:{rpath}"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
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
            rc = proc.returncode
            if rc == 0:
                self._sb_set_status(last_copy_at=time.time(), last_error="")
                logger.info("[self-backup] copy ok %s -> %s@%s:%s",
                            os.path.basename(local_file), user, host, rpath)
                return {"status": "ok", "file": os.path.basename(local_file)}
            msg = errb.decode(errors="replace").strip()[:300]
            self._sb_set_status(last_error=f"copy: rc={rc} {msg}")
            logger.warning("[sync-error] self-backup copy failed rc=%d: %s", rc, msg)
            return {"status": "error", "error": msg, "rc": rc}
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
        return await self._sb_run_copy()

    def get_self_backup_status(self) -> Dict[str, Any]:
        """Snapshot of config + on-disk archives for the WebUI status panel.
        Never exposes private-key material (ssh_keyfile is a path only)."""
        cfg = self._self_backup_cfg()
        root = self._sb_backup_root()
        files: List[Dict[str, Any]] = []
        total = 0
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
        files.sort(key=lambda x: x.get("mtime", 0), reverse=True)
        latest = self._sb_latest_backup()
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
        await asyncio.sleep(120)
        while True:
            try:
                cfg = self._self_backup_cfg()
                if not cfg.get("enabled", False):
                    await asyncio.sleep(60)
                    continue
                now = time.time()
                last_b = float(cfg.get("last_backup_at", 0.0) or 0.0)
                interval_b = self._sb_int("backup_interval_hours", 24, 1) * 3600
                if now - last_b >= interval_b:
                    await self.run_backup_now()
                # Re-read config: run_backup_now may have updated last_*_at.
                cfg = self._self_backup_cfg()
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