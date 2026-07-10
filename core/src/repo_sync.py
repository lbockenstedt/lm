"""GitHub repo-sync subsystem for the Hub.

Mirrors ``staleness_sweep.py``: a self-contained, named subsystem gathered here
as a **mixin** so the Hub class body shrinks with zero call-site change.
``api.py`` routes call ``hub.run_repo_sync_all()`` / ``hub.run_repo_sync_loop()``
— all of which resolve via inheritance once ``RepoSyncMixin`` is added to
``LabManagerHub`` bases.

The repo sync is the **single scheduled "sync all repos" mechanism** (it
replaced the old 1-hour ``run_autoupdate_loop``). Every cycle, on the configured
interval (default 15 minutes):

1. Pulls each hub-local ``provisioning_repos/*`` subdirectory that is a git repo
   (best-effort ``git pull --ff-only``; non-git subdirs are skipped). These are
   the auxiliary service install sources the hub host keeps on disk.
2. Calls ``self.perform_update()`` — the existing version-gated path that pulls
   the **hub tree** (only when the remote tip differs, with snapshot/rollback),
   fans a ``SPOKE_UPDATE`` out to **every approved spoke** (pxmx / opnsense / cs /
   cppm / netbox / ldap / nw), restarts the in-repo lm-dns / lm-dhcp spokes when
   the hub updated, and self-restarts the hub *only when its own code changed*.
   Reusing it keeps one git/update code path instead of duplicating it.

So "all repos" = hub tree + ``provisioning_repos/*`` (pulled locally) + every
approved spoke (pushed to, each spoke self-pulls). The schedule lives on the
System → Sync page; config rides on the shared ``global_config["repo_sync"]``
key (like staleness_sweep), and the last-run status is persisted by
``simulations_store.set_repo_sync_status`` for the WebUI card.

This module is a **leaf**: it imports only stdlib and must NOT import ``main``
or ``api`` (no back-import — that would create a cycle, since ``main`` imports
this module to pull in the mixin). It reuses ``self.perform_update`` /
``self._is_git_repo`` (from ``update_pipeline.UpdatePipelineMixin``) and
``self.state`` / ``self.simulations_store`` via inheritance.

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger("Hub")


class RepoSyncMixin:
    """Periodically syncs every GitHub repo (hub tree + provisioning_repos +
    approved spokes) and records the last-run status for the WebUI.

    Config (``global_config["repo_sync"]``): ``enabled`` (bool, default True),
    ``interval_seconds`` (default 900 — 15 minutes). Read fresh each cycle so a
    WebUI change takes effect without a restart.
    """

    _REPO_SYNC_CFG_KEY = "repo_sync"

    def _repo_sync_cfg(self) -> Dict[str, Any]:
        """Read the repo-sync config fresh (enabled / interval_seconds)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._REPO_SYNC_CFG_KEY, {})) or {}

    def _repo_sync_interval(self) -> float:
        """Seconds between scheduled syncs. Clamp >= 60 so a bad config can't
        hot-loop the hub. Default 900 (15 minutes)."""
        try:
            n = int(self._repo_sync_cfg().get("interval_seconds", 900))
        except (TypeError, ValueError):
            n = 900
        return max(60.0, float(n))

    async def _git_head(self, repo_dir: str) -> str:
        """Best-effort `git rev-parse HEAD` for a repo dir; '' on any failure."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_dir, "rev-parse", "HEAD",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            if proc.returncode == 0:
                return out.decode("utf-8", "replace").strip()
        except Exception as e:  # noqa: BLE001 — best-effort, never fatal
            logger.debug("repo_sync rev-parse %s failed: %s", repo_dir, e)
        return ""

    async def _git_pull_repo(self, repo_dir: str) -> Dict[str, Any]:
        """Best-effort ``git pull --ff-only`` on one repo dir.

        Respects each repo's configured upstream (no hard-coded origin/branch)
        so provisioning_repos cloned by different install scripts all work.
        Records ``commit_before`` / ``commit_after`` so the WebUI can show
        whether anything actually moved. Never raises — a failure is recorded
        as ``status: "error"`` and the sync continues with the next repo.
        """
        name = os.path.basename(repo_dir.rstrip("/"))
        before = await self._git_head(repo_dir)
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_dir, "pull", "--ff-only",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), timeout=120.0)
            after = await self._git_head(repo_dir)
            ok = proc.returncode == 0
            tail = (out.decode("utf-8", "replace").strip()
                    or err.decode("utf-8", "replace").strip())
            # A clean pull that's already up to date is still "ok" (nothing
            # moved) — git prints "Already up to date." in that case.
            return {
                "name": name,
                "status": "ok" if ok else "error",
                "message": (tail[:300] if tail else
                            ("up to date" if ok else "pull failed")),
                "commit_before": before,
                "commit_after": after,
                "changed": bool(before) and bool(after) and before != after,
            }
        except Exception as e:  # noqa: BLE001 — best-effort
            return {"name": name, "status": "error", "message": str(e)[:300],
                    "commit_before": before, "commit_after": "",
                    "changed": False}

    async def run_repo_sync_all(self, force_spokes: bool = False) -> Dict[str, Any]:
        """Run one GitHub repo-sync cycle and record its status.

        Pulls ``provisioning_repos/*`` (hub-local) then delegates to
        ``perform_update`` (hub tree + spoke fan-out). Returns the combined
        status ``{last_sync_ts, hub, provisioning_repos, message}``. Idempotent
        + best-effort: any failure yields a per-entry error, never an unhandled
        exception (the background loop depends on this).

        ``force_spokes`` is threaded through to ``perform_update`` so a MANUAL
        "Update" click (footer button / Update All → /setup/update) bypasses the
        per-spoke re-push cooldown and gate, while the scheduled background loop
        calls with the default ``False`` (gated/cooldown-respecting). This is the
        single shared code path for BOTH the scheduled sync and the manual
        button — "update now" is just "run the scheduled cycle immediately".

        NOTE: when ``perform_update`` pulls a hub change it schedules a hub
        self-restart (via the transient unit) and returns a "restarting"
        message — the status below is persisted before that restart wins the
        race (the restart is a non-blocking ``systemd-run``), so the WebUI
        still shows the cycle that triggered it.
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # ── provisioning_repos/* (hub-local auxiliary service sources) ──────
        repo_results: List[Dict[str, Any]] = []
        try:
            hub_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../"))
            prov_dir = os.path.join(hub_root, "provisioning_repos")
            if os.path.isdir(prov_dir):
                for entry in sorted(os.listdir(prov_dir)):
                    sub = os.path.join(prov_dir, entry)
                    if not os.path.isdir(sub):
                        continue
                    if not self._is_git_repo(sub):
                        repo_results.append({"name": entry, "status": "skipped",
                                             "message": "not a git repo",
                                             "changed": False})
                        continue
                    repo_results.append(await self._git_pull_repo(sub))
        except Exception as e:  # noqa: BLE001 — best-effort, never fatal
            logger.warning("[sync-error] repo_sync provisioning_repos scan failed: %s", e)

        # ── Sibling-repo latest-version cache refresh ──────────────────────
        # Primary refresh of the per-repo latest-.NN used by the diagnostics
        # "behind latest" chip for spokes whose repo isn't checked out locally
        # (opnsense/netbox/cs/pxmx/…). Rides THIS cycle so it runs on the same
        # schedule as replication and is gated by the same repo_sync.enabled
        # toggle (checked inside). Off-loop, concurrent, best-effort — never
        # blocks /setup/diagnostics and never raises.
        try:
            await self._refresh_all_module_versions()
        except Exception as e:  # noqa: BLE001 — best-effort, never fatal
            logger.debug("repo_sync module-version refresh failed: %s", e)

        # ── hub tree + spoke fan-out (version-gated, snapshot/rollback) ─────
        try:
            hub_result = await self.perform_update(force_spokes=force_spokes)
            if not isinstance(hub_result, dict):
                hub_result = {"status": "checked",
                              "message": str(hub_result)}
        except Exception as e:  # noqa: BLE001 — best-effort
            logger.warning("[sync-error] repo_sync perform_update failed: %s", e)
            hub_result = {"status": "error", "message": str(e)[:300]}

        # ── Update-path self-diagnosis ─────────────────────────────────────
        # Verify the hub's OWN git/update machinery is functional so a broken
        # updater is LOUD, not silent (the failure mode behind a hub quietly
        # serving stale code). Each warning → [sync-error] so it lands in the
        # hub error log + GET_ERROR_LOGS (bugfixer) and the repo-sync status.
        try:
            update_health = await self.check_update_health()
        except Exception as e:  # noqa: BLE001 — never fatal to the loop
            update_health = {"ok": False, "checks": {}, "warnings": [f"health check crashed: {e}"]}
        for e in update_health.get("errors", []):
            # BROKEN update/self-heal infrastructure -> ERROR so it lands in the
            # hub error view (GET_ERROR_LOGS / bugfixer), not just a warning.
            logger.error("[sync-error] update-health CRITICAL: %s", e)
        # Dedup update-health warnings across cycles. A persistent mis-config
        # (e.g. update_sources.hub empty) would otherwise log a WARNING every
        # 15-min cycle (~96/day) of the SAME advisory, drowning the hub error
        # log and teaching operators to ignore [sync-error]. Log each DISTINCT
        # warning at WARNING only on its first occurrence or when it RE-appears
        # after clearing (state change = signal); while it persists unchanged,
        # emit a single condensed INFO line so the condition stays observable
        # without flooding. Errors above are never deduped (always loud).
        cur_warnings = set(update_health.get("warnings", []))
        prev_warnings = getattr(self, "_prev_update_warnings", set())
        for w in sorted(cur_warnings - prev_warnings):
            logger.warning("[sync-error] update-health: %s", w)
        for w in sorted(prev_warnings - cur_warnings):
            logger.info("[sync-error] update-health: CLEARED — %s", w)
        if cur_warnings and not (cur_warnings - prev_warnings):
            logger.info("[sync-error] update-health: %d warning(s) unchanged since last cycle",
                        len(cur_warnings))
        self._prev_update_warnings = cur_warnings

        ok_count = sum(1 for r in repo_results if r.get("status") == "ok")
        err_count = sum(1 for r in repo_results if r.get("status") == "error")
        skip_count = sum(1 for r in repo_results if r.get("status") == "skipped")
        changed = [r["name"] for r in repo_results if r.get("changed")]
        hub_status = str(hub_result.get("status") or "")
        message = (f"hub={hub_status}; provisioning_repos: {ok_count} ok, "
                   f"{err_count} error, {skip_count} skipped"
                   + (f"; changed: {', '.join(changed)}" if changed else "")
                   + ("" if update_health.get("ok") else
                      f"; update-health: {len(update_health.get('errors', []))} error(s), "
                      f"{len(update_health.get('warnings', []))} warning(s)"))

        # Hub-authoritative sync log: errors → [sync-error] WARNING so the
        # cause lands in the hub log + GET_ERROR_LOGS (bugfixer).
        if err_count or hub_status == "error" or not update_health.get("ok"):
            logger.warning("[sync-error] repo_sync — %s", message)
        else:
            logger.info("repo_sync: %s", message)

        status = {"last_sync_ts": now, "hub": hub_result,
                  "provisioning_repos": repo_results, "message": message,
                  "update_health": update_health}
        try:
            await self.simulations_store.set_repo_sync_status(status)
        except Exception as e:  # noqa: BLE001 — store failure must not kill the loop
            logger.warning("[sync-error] repo_sync status persist failed: %s", e)
        return status

    async def run_repo_sync_loop(self):
        """Periodically sync all repos per the configured interval (default 15m).

        Reads the config fresh each cycle (enabled / interval_seconds) so a
        WebUI change takes effect without a restart. Disabled → short sleep +
        re-check. Staggered ~30s after startup (shorter than staleness's 90s so
        a freshly-booted hub reconciles its repos sooner) and away from the
        other heavy syncs that stagger at 90s+.
        """
        await asyncio.sleep(30)  # let spokes connect; stagger off the 90s syncs
        _last_disabled_audit = 0.0
        while True:
            try:
                cfg = self._repo_sync_cfg()
                if cfg.get("enabled", True):
                    # run_repo_sync_all runs check_update_health every cycle.
                    # Backstop: bound the cycle to 10m so a slow/hung op (serial
                    # provisioning pulls, a wedged spoke send in the fan-out)
                    # can't strand updates — abandon and retry next interval
                    # instead of stalling the loop indefinitely.
                    try:
                        await asyncio.wait_for(self.run_repo_sync_all(), timeout=600)
                    except asyncio.TimeoutError:
                        # ERROR (not WARNING) so it lands in the hub error view
                        # (GET_ERROR_LOGS / bugfixer keys off [sync-error] ERROR),
                        # and persist a timeout status so the WebUI Sync card
                        # shows the stall (the abandoned run_repo_sync_all was
                        # cancelled BEFORE it could set_repo_sync_status, so
                        # without this the card kept the last green cycle while
                        # the loop sat wedged on a hung spoke send / slow pull).
                        logger.error("[sync-error] repo_sync cycle exceeded 600s "
                                      "— abandoned; will retry next interval")
                        try:
                            _ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            await self.simulations_store.set_repo_sync_status({
                                "last_sync_ts": _ts,
                                "hub": {"status": "error",
                                        "message": "repo_sync cycle exceeded 600s — abandoned"},
                                "provisioning_repos": [],
                                "message": "hub=error; cycle exceeded 600s timeout — abandoned",
                                "update_health": {"ok": False, "checks": {},
                                                  "warnings": ["cycle timeout"],
                                                  "errors": ["repo_sync cycle exceeded 600s"]},
                            })
                        except Exception as _e:  # noqa: BLE001 — store failure must not kill the loop
                            logger.warning("[sync-error] repo_sync timeout status persist failed: %s", _e)
                else:
                    # Scheduled sync OFF - still audit the update/self-heal
                    # infrastructure (systemd Type=exec / MainPID / Restart=,
                    # watchdog timer, restart helper, git checkout) so drift is
                    # LOUD in the hub log regardless of the sync toggle. Throttled
                    # to ~5m to avoid a per-minute git ls-remote.
                    _now = _dt.datetime.now(_dt.timezone.utc).timestamp()
                    if (_now - _last_disabled_audit) >= 300:
                        _last_disabled_audit = _now
                        try:
                            health = await self.check_update_health()
                            for e in health.get("errors", []):
                                logger.error("[sync-error] update-health CRITICAL "
                                             "(sync disabled): %s", e)
                            for w in health.get("warnings", []):
                                logger.warning("[sync-error] update-health "
                                               "(sync disabled): %s", w)
                        except Exception as e:  # noqa: BLE001 - never fatal
                            logger.warning("[sync-error] update-health audit failed: %s", e)
                delay = self._repo_sync_interval() if cfg.get("enabled", True) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.warning("[sync-error] repo_sync loop cycle failed: %s", e)
                await asyncio.sleep(60)