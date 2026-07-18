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
"""
import asyncio
import logging
import os

logger = logging.getLogger("lm.watchdog.code_drift")


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
        logger.info("code-drift watchdog armed (every %ss): %s", int(interval_s),
                    {k: v[:8] for k, v in baseline.items() if v})
        # _stop exists on the device-mode SpokeClient (shutdown flag); absent on
        # BaseControlPlane → getattr default False → loop runs forever (== while True).
        while not getattr(self, "_stop", False):
            try:
                await asyncio.sleep(interval_s)
                # A self-update in flight advances HEAD on purpose and restarts
                # itself; don't race it with a second exit.
                if self._draining or self._spoke_update_in_progress:
                    continue
                for d in self._drift_watched_dirs():
                    key, now = str(d), await _head(d)
                    if not now:
                        continue
                    if key not in baseline:  # newly-watched repo -> baseline it
                        baseline[key] = now
                        continue
                    was = baseline.get(key)
                    if was and now != was:
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