"""Code-drift watchdog mixin — shared by ``BaseControlPlane`` (every spoke +
the generic agent) and the device-mode ``SpokeClient`` (the dumb agent, NOT a
``BaseControlPlane`` subclass).

The watchdog restarts (``os._exit(3)`` → systemd ``Restart=on-failure``) when a
watched repo's on-disk HEAD advances AHEAD of the running process — the
"pulled-but-not-restarted" trap (a SPOKE_UPDATE / manual pull / spoke-driven
self-update advanced the repo on disk while the process kept serving the old
class, so the next update sees "already up to date" and never reloads).

Extracted here (was verbatim-duplicated in ``control_plane.py`` and
``agent/src/spoke_client.py``) so both consumers share ONE source of truth. The
mixin calls two overridable hooks — ``_repo_root()`` and
``_resolve_core_root()`` — that each consumer keeps anchored to its own layout
(a spoke derives its repo root from CWD; the device-mode agent derives it from
``__file__``). ``_drift_watched_dirs()`` composes them the same way for both.

Loop guard: ``while not getattr(self, "_stop", False)`` — the device-mode agent
sets ``self._stop`` on shutdown; ``BaseControlPlane`` has no ``_stop`` attribute
so ``getattr`` returns ``False`` and the loop runs forever (identical to the
prior ``while True:``). The skip-while-draining guard
(``self._draining or self._spoke_update_in_progress``) is shared by both.

Blast radius (role-hosting agent)
---------------------------------
A role-hosting agent runs ONE process containing the base agent plus a
``RoleConnection`` per loaded role — commonly 10 control planes sharing one
event loop, one ``/opt/lm`` core checkout, and one PID. ``BaseControlPlane.run``
arms this watchdog on EVERY one of them, so that process historically held ~10
independent watchdogs, each able to ``os._exit(3)`` all of them. Three process-
wide corrections live here:

* **Update coordination.** ``_draining`` / ``_spoke_update_in_progress`` are
  per-INSTANCE flags. When one role pulled ``/opt/lm``, its 9 peers each saw
  their own flag ``False``, observed the HEAD move that the pull itself caused,
  and exited the process mid-``git pull`` — leaving a half-finished rebase that
  the next boot had to ``reset --hard`` out of, which is what turned a single
  update into a restart loop. The guard is now process-wide: nobody exits while
  ANY control plane in this process is updating.
* **One checker per directory.** All ~10 watchdogs polled the same two repos
  every cycle (~10x the ``git rev-parse`` subprocesses) and then raced to exit.
  Each directory is now owned by the first watchdog to claim it; ownership is
  released when that watchdog stops so an unloaded role hands the repo back.
* **Role-scoped drift.** Drift in a single role's sibling repo only requires
  that ROLE to reload, not the whole process. Consumers that can do targeted
  reloads override ``_drift_role_for_dir`` / ``_reload_role_for_drift``; the
  default keeps the historical whole-process restart.
"""
import asyncio
import logging
import os
import weakref

logger = logging.getLogger("lm.watchdog.code_drift")

# Every control plane with an armed watchdog in THIS process. Weak so a stopped
# RoleConnection drops out without a teardown hook. Single event loop → no lock.
_DRIFT_PEERS: "weakref.WeakSet" = weakref.WeakSet()

# abspath -> weakref(owning watchdog). Exactly one watchdog per directory per
# process polls + acts; the rest skip it.
_DRIFT_DIR_OWNERS: dict = {}


def _update_in_flight_anywhere() -> bool:
    """True if ANY control plane in this process is mid-update.

    The per-instance flags are not sufficient in a role-hosting agent: the peer
    doing the pull is a DIFFERENT object from the peers watching the repo it is
    pulling. Exiting on a HEAD move that an in-process peer is actively creating
    truncates that peer's ``git pull``."""
    for peer in list(_DRIFT_PEERS):
        try:
            if getattr(peer, "_draining", False) or getattr(
                    peer, "_spoke_update_in_progress", False):
                return True
        except Exception:  # noqa: BLE001 — a peer mid-teardown must not break the guard
            continue
    return False


class CodeDriftWatchdogMixin:
    """Restart on on-disk code drift. Consumers provide ``_repo_root()`` and
    ``_resolve_core_root()`` (overridable hooks) + the ``_draining`` /
    ``_spoke_update_in_progress`` flags + ``_flush_log_relay_async()``."""

    def _drift_watched_dirs(self) -> list:
        """Git checkouts whose on-disk HEAD advancing past the running process
        should trigger a restart. Base set: the consumer's OWN repo
        (``_repo_root()``) plus the shared ``/opt/lm`` core checkout it imports
        at runtime (``_resolve_core_root()``) — exactly the two repos an update
        pulls. The generic agent overrides this to also watch each loaded role's
        sibling repo. Only real git roots are returned."""
        dirs = set()
        try:
            dirs.add(os.path.abspath(self._repo_root()))
        except Exception:  # noqa: BLE001
            pass
        try:
            core = self._resolve_core_root()
            if core:
                dirs.add(os.path.abspath(core))
        except Exception:  # noqa: BLE001
            pass
        return [d for d in dirs if os.path.isdir(os.path.join(str(d), ".git"))]

    # ── Role-scoped drift hooks (overridden by the role-hosting agent) ────────
    def _drift_role_for_dir(self, d: str):
        """Return the role name whose sibling repo is ``d``, or ``None`` when a
        drift in ``d`` must restart the whole process.

        ``None`` for every directory here (the consumer's own repo and the
        shared core checkout are imported by the running process, so only a
        restart can reload them). The role-hosting agent overrides this to
        classify a loaded role's sibling repo as reloadable-in-place."""
        return None

    async def _reload_role_for_drift(self, role: str, d: str) -> bool:
        """Reload just ``role`` after its repo drifted. Return ``True`` when the
        drift was fully absorbed; ``False`` falls back to the process restart.

        Default: no targeted reload available."""
        return False

    # ── Process-wide directory ownership ─────────────────────────────────────
    def _drift_owns_dir(self, key: str) -> bool:
        """Claim ``key`` for this watchdog, or report whether we already hold it.

        One checker per directory per process: the first watchdog to reach a
        directory owns it, the other ~9 in a role-hosting agent skip it. Removes
        both the duplicated ``git rev-parse`` load and the race where several
        watchdogs exit on the same event."""
        ref = _DRIFT_DIR_OWNERS.get(key)
        current = ref() if ref is not None else None
        if current is None:  # unclaimed, or the previous owner has gone away
            _DRIFT_DIR_OWNERS[key] = weakref.ref(self)
            return True
        return current is self

    def _drift_release_dirs(self) -> None:
        """Release every directory this watchdog owns so a surviving peer can
        take over — an unloaded role must not strand ``/opt/lm`` unwatched."""
        for key, ref in list(_DRIFT_DIR_OWNERS.items()):
            try:
                if ref() is self or ref() is None:
                    _DRIFT_DIR_OWNERS.pop(key, None)
            except Exception:  # noqa: BLE001
                _DRIFT_DIR_OWNERS.pop(key, None)

    async def _code_drift_watchdog(self, interval_s: float = 300.0):
        """Restart when code on disk drifts AHEAD of the running process.

        Baselines each watched repo's HEAD at startup and re-reads it every
        ``interval_s``; any advance -> ``os._exit(3)`` so systemd
        ``Restart=on-failure`` reloads the current code. Closes the
        "pulled-but-not-restarted" trap. Skips the exit while a self-update is
        mid-flight (that path restarts itself); a repo that first appears after
        boot (a role loaded at runtime) is baselined, not treated as drift.
        Never crashes the consumer — every failure is swallowed."""
        async def _head(d):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "git", "-C", str(d), "rev-parse", "HEAD",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                return out.decode().strip() if proc.returncode == 0 else ""
            except Exception:  # noqa: BLE001 — never let the watchdog crash the consumer
                return ""

        baseline = {}
        for d in self._drift_watched_dirs():
            baseline[str(d)] = await _head(d)
        # Publish the boot-time HEAD map so the self-update path can also detect
        # a process running BEHIND on-disk HEAD (operator did a manual `git pull`
        # before clicking Update — that pull is a no-op to the updater, which
        # would otherwise take the "already up to date; no restart" branch and
        # leave the stale process running until the next watchdog cycle). Same
        # dict object so runtime-baselined repos stay in sync.
        self._drift_baseline = baseline
        # Join the process-wide peer set BEFORE the first sleep so a peer that
        # starts updating immediately is visible to everyone else's guard.
        _DRIFT_PEERS.add(self)
        logger.info("code-drift watchdog armed (every %ss): %s", int(interval_s),
                    {k: v[:8] for k, v in baseline.items() if v})
        # _stop exists on the device-mode SpokeClient (shutdown flag); absent on
        # BaseControlPlane → getattr default False → loop runs forever (== while True).
        try:
            while not getattr(self, "_stop", False):
                try:
                    await asyncio.sleep(interval_s)
                    # A self-update in flight advances HEAD on purpose and restarts
                    # itself; don't race it with a second exit. Checked across EVERY
                    # control plane in this process, not just our own flags — in a
                    # role-hosting agent the peer doing the pull is a different
                    # object, and exiting on the HEAD move it is actively creating
                    # truncates its `git pull` mid-rebase.
                    if (self._draining or self._spoke_update_in_progress
                            or _update_in_flight_anywhere()):
                        continue
                    for d in self._drift_watched_dirs():
                        key = str(d)
                        # One checker per directory per process.
                        if not self._drift_owns_dir(key):
                            continue
                        now = await _head(d)
                        if not now:
                            continue
                        if key not in baseline:  # newly-watched repo -> baseline it
                            baseline[key] = now
                            continue
                        was = baseline.get(key)
                        if not (was and now != was):
                            continue
                        # Re-check the drain guard: `_head` awaited, so a peer may
                        # have STARTED updating while we were reading git. Without
                        # this the window we just closed above reopens here.
                        if _update_in_flight_anywhere():
                            continue
                        # A single role's sibling repo only needs that role to
                        # reload; the process (and its other roles) can stay up.
                        role = self._drift_role_for_dir(key)
                        if role:
                            try:
                                absorbed = await self._reload_role_for_drift(role, key)
                            except Exception as e:  # noqa: BLE001
                                logger.warning(
                                    "code-drift: reloading role '%s' after %s "
                                    "advanced %s->%s failed (%s); falling back to a "
                                    "process restart.", role, d, was[:8], now[:8], e)
                                absorbed = False
                            if absorbed:
                                baseline[key] = now
                                logger.info(
                                    "code-drift: %s advanced %s->%s; reloaded role "
                                    "'%s' in place (other roles left running).",
                                    d, was[:8], now[:8], role)
                                continue
                        logger.warning(
                            "code-drift: %s advanced %s->%s on disk but the process "
                            "never restarted -- exiting so systemd reloads current "
                            "code.", d, was[:8], now[:8])
                        try:
                            await self._flush_log_relay_async()
                        except Exception:  # noqa: BLE001
                            pass
                        os._exit(3)
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa: BLE001 — never fatal
                    logger.debug("code-drift watchdog cycle failed: %s", e)
        finally:
            # Hand our directories back so a surviving peer keeps watching them.
            self._drift_release_dirs()