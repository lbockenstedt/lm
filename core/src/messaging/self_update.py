"""Self-update mixin — shared by ``BaseControlPlane`` (every spoke + the
hub-hosting generic agent) and the device-mode ``SpokeClient`` (the dumb
agent, NOT a ``BaseControlPlane`` subclass).

This is the git pull + snapshot + rollback-watchdog + restart machinery that
backs ``SPOKE_UPDATE`` (hub→spoke) and ``AGENT_UPDATE`` (spoke→device-mode
agent). Both legs run the SAME mechanical sequence — fetch/pull the component's
own repo (+ the shared ``/opt/lm`` core checkout when the caller threads a
``core_repo_url``), snapshot the prior HEAD, write a pending-update manifest,
schedule the external health-gate watchdog, flush queued logs, and
``os._exit(3)`` so systemd ``Restart=on-failure`` reloads the new code. A bad
update (new code crashes at boot / crash-loops) is rolled back by the external
watchdog (``git reset --hard <from_commit>``); known-bad commits are skipped
rather than re-pulled into a crash-loop.

Extracted here (was on ``BaseControlPlane`` only) so the device-mode agent
inherits the identical self-update + rollback guarantees a spoke has — closing
the "device-mode agent can't be updated via the Update button / auto-update"
gap, with a ONE-command wire contract symmetric to ``SPOKE_UPDATE``. This is
the sibling of ``CodeDriftWatchdogMixin`` (feature (c)): shared operational
code → mixin both inherit, single source of truth, BaseControlPlane behavior
unchanged via MRO.

The mixin calls overridable hooks each consumer keeps anchored to its own
layout: ``_repo_root()`` (CWD-anchored on a spoke, ``__file__``-anchored on the
device-mode agent) and ``_resolve_core_root()`` (the shared ``/opt/lm`` core
checkout). It also calls ``get_service_name()`` (the systemd unit the
watchdog restarts) and ``_flush_log_relay_sync()`` (a best-effort pre-exit log
flush) — each consumer provides those. ``_spoke_state_dir()`` keys the
per-component recovery state dir off ``self.spoke_id`` (spoke) or
``self.agent_id`` (device-mode agent) — whichever the consumer exposes.

State lives in a per-component dir (``/var/lib/lm/<id>/``) separate from the
hub's ``/var/lib/lm/state`` so a co-located box never collides. The watchdog
script + sudoers land only on a full installer re-run (bootstrap caveat:
auto-update pulls code but not install-script/systemd changes); until then
the watchdog Popen fails silently and we degrade to the pre-rollback
behavior (restart, no rollback) — never fatal.
"""
import asyncio
import contextlib
import fcntl
import logging
import os
import queue
import subprocess
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("lm.self_update")


class SelfUpdateMixin:
    """Git self-update + rollback machinery shared by spokes and the
    device-mode agent. Consumers provide hooks: ``_repo_root()``,
    ``_resolve_core_root()``, ``get_service_name()``, ``_flush_log_relay_sync()``,
    and expose either ``spoke_id`` or ``agent_id`` (for the recovery state dir).
    Also reads the ``_draining`` / ``_spoke_update_in_progress`` drain flags
    (shared with ``CodeDriftWatchdogMixin``)."""

    # ------------------------------------------------------------------
    # git primitives
    # ------------------------------------------------------------------

    def _ensure_git_pull_strategy(self, cwd: str) -> None:
        subprocess.run(["git", "config", "pull.rebase", "true"], cwd=cwd, check=False, timeout=15)
        subprocess.run(["git", "config", "rebase.autoStash", "true"], cwd=cwd, check=False, timeout=15)

    def _run_git(self, args, cwd: str) -> subprocess.CompletedProcess:
        # All git sub-commands (rev-parse/rev-list/pull/rebase/reset) run via
        # this helper in the update path, awaited through to_thread — a
        # stalled remote could hang any of them forever without a deadline.
        # Pull/fetch get 120s; lightweight config/rev-parse gets 60s.
        timeout = 120 if args and args[0] in ("pull", "fetch", "rebase") else 60
        try:
            return subprocess.run(["git"] + args, cwd=cwd, text=True,
                                  capture_output=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            logger.warning("git %s timed out after %ss in %s", args[0] if args else "?",
                           timeout, cwd)
            return subprocess.CompletedProcess(args, 124, "", str(e))

    def _prepare_service_restart(self, reason: str = "update") -> bool:
        """Signal that this component should restart to load new code.

        Returns True; the caller MUST then flush queued log entries and
        ``os._exit(3)``. We deliberately do NOT ``systemctl restart`` ourselves
        anymore. That client ran inside this component's own systemd cgroup, so
        systemd's restart stop-phase (``KillMode=control-group``, the default)
        SIGTERMed the whole cgroup and killed the ``systemctl`` child
        mid-transaction — before its start-phase committed. The unit then
        deactivated with ``code=killed, signal=TERM``, which
        ``Restart=on-failure`` treats as a clean stop and does NOT revive,
        stranding the component "offline / never connected" — the recurring
        outage this fixes. (``start_new_session=True`` would not have helped:
        it changes session/pgid, not cgroup membership, so the cgroup kill
        still reached the child.)

        Instead the caller exits with a non-zero status (3). systemd sees a
        *failure* exit, so ``Restart=on-failure`` — which every spoke + agent
        unit is configured with — reliably relaunches us after ``RestartSec``.
        No subprocess is left in the cgroup, so there is no race and no sudo
        dependency. The cost is a ``RestartSec`` delay (acceptable for an
        update); the benefit is the component always comes back.
        """
        svc = self.get_service_name()
        logger.info(
            "Reloading %s to apply new code (reason: %s); exiting so systemd "
            "Restart=on-failure relaunches it.", svc, reason,
        )
        return True

    # ------------------------------------------------------------------
    # per-component recovery state dir + health marker
    # ------------------------------------------------------------------

    def _spoke_state_dir(self) -> str:
        """Per-component recovery state dir (``/var/lib/lm/<id>/``).

        ``id`` is ``self.spoke_id`` (a spoke) or ``self.agent_id`` (a
        device-mode agent) — whichever the consumer exposes.

        Falls back to a repo-local ``.lm-state/<id>`` when ``/var/lib/lm``
        isn't writable by this (non-root ``svc_lm``) process — otherwise the
        pre-update snapshot + rollback silently disable with "Permission denied:
        '/var/lib/lm'" (the installer didn't create/chown the dir). The chosen
        path is passed to the external watchdog via ``--state-dir`` so both
        agree. Cached so the choice is stable across a run."""
        cached = getattr(self, "_state_dir_cached", None)
        if cached:
            return cached
        sid = getattr(self, "spoke_id", None) or getattr(self, "agent_id", None) or "component"
        primary = os.path.join("/var/lib/lm", sid)
        chosen = primary
        try:
            os.makedirs(primary, exist_ok=True)
            # Confirm we can actually write here (makedirs can succeed on an
            # existing dir we still can't write to).
            probe = os.path.join(primary, ".wtest")
            with open(probe, "w"):
                pass
            os.remove(probe)
        except OSError:
            fallback = os.path.join(self._repo_root(), ".lm-state", sid)
            try:
                os.makedirs(fallback, exist_ok=True)
                chosen = fallback
                logger.warning("State dir %s not writable — using repo-local "
                               "fallback %s (pre-update snapshot/rollback still "
                               "work; run the installer to fix /var/lib/lm perms)",
                               primary, fallback)
            except OSError as e:
                logger.warning("No writable state dir (%s); rollback disabled: %s",
                               primary, e)
        self._state_dir_cached = chosen
        return chosen

    def _clear_healthy_marker(self) -> None:
        """Drop a stale ``healthy`` marker on boot so a fresh start must re-prove
        health (the watchdog treats the marker as the positive health signal)."""
        try:
            m = os.path.join(self._spoke_state_dir(), "healthy")
            if os.path.exists(m):
                os.remove(m)
        except Exception:  # pragma: no cover - state dir not writable / missing
            pass

    def _touch_healthy_marker(self) -> None:
        """Mark the component healthy after the hub mutual-auth succeeds — the
        watchdog's positive health signal (presence => new code booted + authed)."""
        try:
            d = self._spoke_state_dir()
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "healthy"), "w").close()
        except Exception as e:  # pragma: no cover - state dir not writable
            logger.debug("could not write healthy marker: %s", e)

    def _snapshot_for_update(self, head_before: str, repo_root: str):
        """Pre-swap code snapshot (belt-and-suspenders — ``git reset --hard`` is
        the primary rollback for a git repo). Returns the backup dir or None."""
        try:
            from update_recovery import snapshot_code
            ts = time.strftime("%Y%m%d-%H%M%S")
            return snapshot_code(repo_root, ts, tree_list=["src"],
                                 state_dir=self._spoke_state_dir())
        except Exception as e:
            logger.warning("Pre-update snapshot failed (rollback disabled): %s", e)
            return None

    def _is_known_bad_commit(self, commit: str) -> bool:
        """True if ``commit`` was rolled back before (skip re-pulling it)."""
        if not commit:
            return False
        try:
            from update_recovery import is_bad_commit
            return bool(is_bad_commit(commit, state_dir=self._spoke_state_dir()))
        except Exception:  # pragma: no cover - update_recovery unavailable
            return False

    def _clear_pending_update(self) -> None:
        try:
            from update_recovery import clear_pending
            clear_pending(state_dir=self._spoke_state_dir())
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # Shared lm/core propagation (/opt/lm) — host-wide locked so concurrent
    # components on one box don't race the shared .git index.
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def _core_update_lock(self, timeout: float = 300.0):
        """Host-wide exclusive lock for pulls of the shared ``/opt/lm`` core
        checkout. Every component on a host that shares /opt/lm serializes here
        so two concurrent updates don't race the same .git index. Polls with
        ``LOCK_NB`` so we can give up after ``timeout`` (warn + skip core this
        cycle) instead of blocking the loop indefinitely. Never held across
        ``os._exit(3)`` — the ``finally`` releases before the caller exits.
        Falls back to a repo-local lock file when /var/lib/lm isn't writable."""
        lock_path = "/var/lib/lm/.lm-core-update.lock"
        try:
            os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        except OSError:
            lock_path = os.path.join(self._repo_root(), ".lm-state",
                                     "core-update.lock")
            try:
                os.makedirs(os.path.dirname(lock_path), exist_ok=True)
            except OSError:
                lock_path = os.path.join(self._repo_root(), ".lm-core-update.lock")
        fd = None
        acquired = False
        deadline_ts = time.monotonic() + timeout
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    remaining = deadline_ts - time.monotonic()
                    if remaining <= 0:
                        logger.warning("core-update lock busy >%ss; skipping core "
                                       "pull this cycle", int(timeout))
                        yield False
                        return
                    time.sleep(min(1.0, remaining))
            yield True
        finally:
            if acquired:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # external rollback watchdog arming
    # ------------------------------------------------------------------

    def _prepare_restart_with_watchdog(self, head_before: str, head_after: str,
                                       backup_dir, repo_root: str,
                                       reason: str = "update",
                                       deadline: int = 90,
                                       core_repo: Optional[Dict[str, str]] = None) -> bool:
        """Write the pending-update manifest, schedule the external health-gate
        watchdog, and signal a service restart. Returns True; the caller MUST
        then flush queued logs (sync or async per its context) and
        ``os._exit(3)``. Best-effort watchdog: a missing script / no sudoers
        (pre-reinstall box) fails silently — we still restart via os._exit(3)
        with no rollback, exactly the pre-rollback behavior.

        ``core_repo`` (optional) records a SECOND repo — the shared ``/opt/lm``
        core checkout — so the watchdog can roll *both* back on boot failure
        (component first, then core). ``core_repo`` carries ``root`` /
        ``from_commit`` / ``to_commit``. When omitted the manifest + watchdog
        behave exactly as before (single-repo). v1 is non-atomic across the two
        repos: a watchdog crash between the two ``git reset --hard``s leaves the
        component rolled back but core forward — recoverable via the on-disk
        manifest + ``writefailed`` marker. Atomic two-repo rollback is deferred."""
        state_dir = self._spoke_state_dir()
        service_unit = self.get_service_name()
        recovery_py = None
        try:
            from update_recovery import write_pending
            import update_recovery as _ur
            recovery_py = getattr(_ur, "__file__", None)
            ts = time.strftime("%Y%m%d-%H%M%S")
            extra = {"from_commit": head_before, "to_commit": head_after,
                     "service_unit": service_unit, "deadline": deadline}
            if core_repo and core_repo.get("root"):
                extra["core_root"] = core_repo["root"]
                extra["core_from_commit"] = core_repo.get("from_commit", "")
                extra["core_to_commit"] = core_repo.get("to_commit", "")
            write_pending(backup_dir or "", from_version=(head_before or "")[:12],
                          to_version=(head_after or "")[:12], ts=ts,
                          state_dir=state_dir, extra=extra)
        except Exception as e:
            logger.warning("write_pending failed (rollback disabled): %s", e)
        try:
            cmd = ["sudo", "-n", "/usr/local/bin/lm-component-update-restart",
                   "--unit", service_unit, "--state-dir", state_dir,
                   "--repo-root", repo_root, "--deadline", str(deadline)]
            if recovery_py:
                cmd += ["--recovery-py", recovery_py]
            if core_repo and core_repo.get("root"):
                cmd += ["--core-repo-root", core_repo["root"]]
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as e:  # pragma: no cover - sudo missing / not permitted
            logger.debug("could not schedule update watchdog: %s", e)
        return self._prepare_service_restart(reason=reason)

    # ------------------------------------------------------------------
    # the update worker — shared by SPOKE_UPDATE (spoke) + AGENT_UPDATE (agent)
    # ------------------------------------------------------------------

    def _perform_self_update_sync(self, repo_url: str,
                                  core_repo_url: Optional[str] = None,
                                  core_branch: Optional[str] = None,
                                  reason: str = "update") -> Dict[str, Any]:
        """Blocking git-update body for ``SPOKE_UPDATE`` / ``AGENT_UPDATE``.
        Runs on a worker thread via ``asyncio.to_thread`` (see each consumer's
        command handler) so the event loop — and every other in-flight command —
        stays responsive while ``git fetch``/``pull`` run.

        Two repos are pulled: the component's OWN repo (``_repo_root()``) and,
        when the caller sends ``core_repo_url``, the shared ``/opt/lm`` core
        checkout it imports at runtime. The core pull is host-wide locked
        (``_core_update_lock``) so concurrent components on one box don't race
        the shared ``.git`` index. A restart fires if EITHER repo advanced —
        so a core-only change reaches remote components with zero CLI. The
        watchdog rolls BOTH repos back on boot failure (component first, then
        core); the core ``to_commit`` is marked bad so a crash-looping core
        isn't re-pulled."""
        try:
            cwd = self._repo_root()
            logger.info("Performing update in %s from %s...", cwd, repo_url)

            # 0. Pull the shared lm/core checkout (/opt/lm) BEFORE the
            # component's own repo, so a boot-crashing core is caught by the
            # watchdog along with the component update. Skipped when: no
            # core_repo_url (air-gapped), no git root at /opt/lm (old non-git
            # layout — graceful: log once and continue, the component's own
            # repo still updates), or core_root == cwd (all-in-one: the
            # component's own repo IS /opt/lm, so the pull below already covers
            # core — avoid a duplicate fetch).
            core_changed = False
            core_root = None
            core_from_commit = ""
            core_to_commit = ""
            if core_repo_url:
                core_root = self._resolve_core_root()
                if core_root is None:
                    logger.warning(
                        "update: no git root at /opt/lm or /opt/lm/core — "
                        "lm/core will NOT auto-update on this component. Re-run "
                        "the installer to convert /opt/lm to a real lm checkout. "
                        "The component's own repo still updates.")
                elif core_root == cwd:
                    logger.debug("update: core root == component root (%s); "
                                  "own-repo pull covers core — skipping duplicate.",
                                  core_root)
                    core_root = None  # don't double-record in the manifest
                else:
                    with self._core_update_lock() as got_lock:
                        if not got_lock:
                            logger.warning("update: could not acquire core "
                                           "lock; skipping core pull this cycle.")
                        else:
                            try:
                                self._run_git(["remote", "set-url", "origin",
                                               core_repo_url], cwd=core_root)
                                self._run_git(["config", "pull.rebase", "true"],
                                              cwd=core_root)
                                self._run_git(["config", "rebase.autoStash", "true"],
                                              cwd=core_root)
                                self._run_git(["rebase", "--abort"], cwd=core_root)
                                core_from_commit = self._run_git(
                                    ["rev-parse", "HEAD"], cwd=core_root).stdout.strip()
                                fetch_core = self._run_git(["fetch", "origin"],
                                                           cwd=core_root)
                                if fetch_core.returncode == 0:
                                    cbranch = core_branch or self._run_git(
                                        ["rev-parse", "--abbrev-ref", "HEAD"],
                                        cwd=core_root).stdout.strip() or "main"
                                    pull_core = self._run_git(
                                        ["pull", "--rebase", "--autostash", "origin",
                                         cbranch], cwd=core_root)
                                    if pull_core.returncode != 0:
                                        logger.warning(
                                            "core git pull --rebase failed (rc=%s); "
                                            "resetting hard to origin/%s",
                                            pull_core.returncode, cbranch)
                                        self._run_git(["rebase", "--abort"], cwd=core_root)
                                        self._run_git(["reset", "--hard",
                                                       f"origin/{cbranch}"], cwd=core_root)
                                    core_to_commit = self._run_git(
                                        ["rev-parse", "HEAD"], cwd=core_root).stdout.strip()
                                    if self._is_known_bad_commit(core_to_commit):
                                        logger.warning(
                                            "update: core HEAD %s is a "
                                            "known-bad commit; resetting core to "
                                            "%s and skipping core.",
                                            core_to_commit[:8], core_from_commit[:8])
                                        self._run_git(["reset", "--hard",
                                                       core_from_commit], cwd=core_root)
                                        core_to_commit = core_from_commit
                                    else:
                                        core_changed = (core_to_commit != core_from_commit)
                                else:
                                    logger.warning("update: core fetch failed: %s",
                                                   (fetch_core.stderr or "").strip())
                            except Exception as e:
                                logger.warning("update: core pull failed (%s); "
                                               "continuing with own-repo update only.", e)
                                core_root = None
            else:
                core_root = None

            # 1. Update remote origin
            subprocess.run(["git", "remote", "set-url", "origin", repo_url], cwd=cwd, check=True, timeout=15)

            # 2. Configure pull strategy
            subprocess.run(["git", "config", "pull.rebase", "true"], cwd=cwd, check=True, timeout=15)
            subprocess.run(["git", "config", "rebase.autoStash", "true"], cwd=cwd, check=True, timeout=15)

            # 3. Abort any interrupted rebase before pulling
            self._run_git(["rebase", "--abort"], cwd=cwd)

            # 4. Snapshot HEAD + the code tree before pull so the external
            # watchdog can roll back (git reset --hard head_before) if the new
            # code crashes at boot. The src/ file snapshot is belt-and-suspenders.
            head_before = self._run_git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()
            backup_dir = self._snapshot_for_update(head_before, cwd)

            # 5. Fetch + pull; on rebase conflict reset hard to origin.
            # capture_output so a failure's stderr (e.g. git's "Could not resolve
            # host") reaches the CalledProcessError handler and the log — otherwise
            # a DNS outage just logged an opaque "exit code 128".
            subprocess.run(["git", "fetch", "origin"], cwd=cwd, check=True, timeout=120,
                           capture_output=True, text=True)
            pull = self._run_git(["pull", "--rebase", "--autostash", "origin"], cwd=cwd)
            if pull.returncode != 0:
                logger.warning(f"git pull --rebase failed (rc={pull.returncode}); resetting hard to origin")
                branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd).stdout.strip() or "main"
                subprocess.run(["git", "rebase", "--abort"], cwd=cwd, check=False, timeout=60)
                subprocess.run(["git", "reset", "--hard", f"origin/{branch}"], cwd=cwd, check=True,
                               timeout=60, capture_output=True, text=True)

            head_after = self._run_git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()

            own_changed = (head_after != head_before)
            # 6. Restart if EITHER the own repo or the shared core advanced.
            if own_changed or core_changed:
                # Skip a known-bad commit (rolled back before): reset to
                # head_before and stay put rather than crash-looping into the
                # same broken code. (Core known-bad is handled in its own block
                # above — a bad core alone doesn't trip this branch.)
                if own_changed and self._is_known_bad_commit(head_after):
                    logger.warning(
                        "update: new HEAD %s is a known-bad commit "
                        "(rolled back before); resetting to %s and skipping.",
                        head_after[:8], head_before[:8])
                    self._run_git(["reset", "--hard", head_before], cwd=cwd)
                    self._clear_pending_update()
                    return {"status": "SUCCESS",
                            "message": f"Update {head_after[:8]} is marked bad; stayed on {head_before[:8]}"}
                # Reload to run the new code. _prepare_restart_with_watchdog
                # writes the pending manifest + schedules the external
                # health-gate watchdog (lm-component-update-restart) so a bad
                # update is rolled back instead of crash-looping forever. We
                # then flush logs and exit NON-ZERO (3); systemd sees a
                # failure exit and Restart=on-failure reliably relaunches us.
                # (The old `systemctl restart` child died in our own cgroup
                # mid-restart, stranding the component offline — see
                # _prepare_service_restart's docstring.) When core advanced we
                # also record it so the watchdog resets /opt/lm too.
                core_repo = None
                if core_changed and core_root:
                    core_repo = {"root": core_root,
                                 "from_commit": core_from_commit,
                                 "to_commit": core_to_commit}
                if self._prepare_restart_with_watchdog(
                        head_before, head_after, backup_dir, cwd,
                        reason=reason, core_repo=core_repo):
                    self._flush_log_relay_sync()
                    os._exit(3)
                return {"status": "SUCCESS",
                        "message": f"Updated from {repo_url}; restart skipped"}
            else:
                logger.debug("update: already up to date; no restart needed.")
                return {"status": "SUCCESS", "message": "Already up to date; no restart needed"}
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else (e.stderr or '')
            stdout = e.stdout.decode('utf-8', errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or '')
            detail = (stderr or stdout or str(e)).strip()
            _dl = detail.lower()
            if any(k in _dl for k in ("could not resolve host", "temporary failure in name resolution",
                                      "name or service not known", "could not resolve hostname")):
                logger.error(
                    "update failed: DNS — git could not RESOLVE the remote host. This is a "
                    "name-resolution problem on this box, NOT a git/repo error. Check "
                    "/etc/resolv.conf + that the DNS server is reachable. git said: %s", detail)
            else:
                logger.error("update failed (git command exit code %s): %s", e.returncode, detail or e)
            return {"status": "ERROR", "message": f"git operation failed: {detail}"}
        except Exception as e:
            logger.error(f"update failed: {e}")
            return {"status": "ERROR", "message": str(e)}