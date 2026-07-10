"""Hub self-update + spoke/agent update pipeline (extracted from main.py).

These were methods of ``LabManagerHub`` (``get_local_version``,
``get_remote_version``, ``_is_git_repo``, ``_download_update``, ``_git_update``,
``perform_update``, ``update_spokes_only``, ``update_agents_only``) — ~500 lines
of git/version/tarball update logic plus the spoke/agent SPOKE_UPDATE fan-out.
They are gathered here as a **mixin** (``UpdatePipelineMixin``) that
``LabManagerHub`` inherits, so the methods keep operating on ``self`` (the Hub
instance) with **zero call-site changes** — ``hub.perform_update()`` /
``self.get_local_version()`` resolve exactly as before via inheritance.

The mixin must NOT import ``main`` (that would create a cycle, since ``main``
imports this module). It imports only stdlib, ``httpx``, the
``messaging.protocol`` / ``update_recovery`` leaves, and its own logger (same
``"Hub"`` name as main, so log config is unified). ``_save_sessions`` is
lazy-imported from ``api`` at the one call site that needs it, to avoid a
module-level ``api`` dependency.

Audience: Hub developers. See ``docs/user_manual.md`` for the update flow;
``update_recovery.py`` for the snapshot/rollback companion; [[webui-update-recovery-gap]].
"""

import os
import io
import time
import uuid
import shutil
import tarfile
import tempfile
import asyncio
import subprocess
import datetime as _dt
import logging
from typing import Any, Dict, List, Optional

import httpx

from messaging.protocol import Message, MessageHeader, MessagePayload
from update_recovery import (
    is_version_bad,
    clear_bad_versions_older_than,
    snapshot_code,
    write_pending,
    clear_pending,
)

logger = logging.getLogger("Hub")  # same name as main.py — shared log config

# module_type → update_sources config key (key space #2). NOTE "firewall" →
# "opnsense" here, NOT "opn". Used to look up global_config["update_sources"][k].
_UPDATE_SOURCE_MODULE_KEY = {
    "hypervisor": "pxmx", "firewall": "opnsense", "nac": "cppm",
    "directory": "ldap", "ipam": "netbox", "simulation": "cs", "nw": "nw",
    "certificates": "le",
}

# spoke_id substring → update_sources config key. "opn" → "opnsense" (the
# config key), the opposite of _PUSH_CONFIG_PREFIX_MAP — because this feeds an
# update_sources lookup, not a push_config branch.
_UPDATE_SOURCE_PREFIX_MAP = {
    'pxmx': 'pxmx', 'opn': 'opnsense', 'cs': 'cs',
    'cppm': 'cppm', 'netbox': 'netbox', 'ldap': 'ldap', 'nw': 'nw',
    'le': 'le',
}

# module_types whose code lives INSIDE the lm/hub clone at /opt/lm — the generic
# agent itself ("agent") and the in-repo roles (dns/dhcp/console, which are
# repo_url=None in agent_spoke._ROLE_MAP). Their update source is the lm repo
# (the "agent" update_sources key), NEVER a spoke_id substring. Without this a
# sub-spoke id like "lm-opnsense-dns" substring-matches "opn" → the opnsense repo,
# and the resulting SPOKE_UPDATE repoints the checkout + hard-resets, wiping the
# tree (the class of bug that broke lm-opnsense). Role sub-spokes that DO have
# their own repo (firewall→opnsense, ipam→netbox, …) resolve via
# _UPDATE_SOURCE_MODULE_KEY above and are unaffected.
_IN_LM_REPO_MODULE_TYPES = {"agent", "dns", "dhcp", "console"}

# Canonical default for the hub's own repo. Used to fall back when
# ``global_config["update_sources"]["hub"]`` is absent OR an empty string. An
# empty-string value MUST behave like absent, not like a real URL: ``git
# ls-remote "" refs/heads/main`` fails → ``get_remote_commit`` returns
# ``"unknown"`` → ``_update_available`` reports "no update" → ``perform_update``
# returns ``"checked"`` every cycle, SILENTLY — and ``check_update_health``'s
# old ``if hub_repo:`` guard skipped the remote probe entirely so the box
# reported ``ok`` with no warning. That is the exact failure mode that stranded
# the repo_sync backstop fix on origin while the hub sat un-updated at an old
# SHA reporting "hub=checked" with a clean health suffix. Treat empty as
# absent everywhere (perform_update, get_remote_commit, check_update_health)
# and WARN on the mis-config so it is LOUD, not silent.
_DEFAULT_HUB_REPO = "https://github.com/lbockenstedt/lm"


def _resolve_hub_repo(sources: Dict[str, Any]) -> str:
    """Resolve the hub repo URL from ``update_sources``, treating an empty
    string like an absent key (fall back to the default). Shared by every
    reader so the empty-vs-absent asymmetry can never strand the hub again."""
    return (sources or {}).get("hub") or _DEFAULT_HUB_REPO


# module_type (as reported by a spoke) → the repo directory basename that ships
# that module's code. Mirrors agent_spoke._ROLE_MAP: each role's spoke code lives
# in the sibling repo named here. Both the canonical module_type (left column of
# _ROLE_MAP, e.g. "firewall") and the raw repo/role alias (e.g. "opnsense") are
# keyed so a spoke that reports either resolves. Used to find the LOCAL VERSION
# file backing a spoke so the hub can tell "this spoke is BEHIND its repo's
# latest .NN". module_types NOT here (and not in _IN_LM_REPO_MODULE_TYPES) resolve
# to no repo → latest unknown → NEVER flagged behind (no false positive).
_MODULE_REPO_DIR = {
    "hypervisor": "pxmx", "proxmox": "pxmx", "pxmx": "pxmx",
    "firewall": "opnsense", "opnsense": "opnsense", "opn": "opnsense",
    "nac": "cppm", "cppm": "cppm",
    "directory": "ldap", "ldap": "ldap",
    "ipam": "netbox", "netbox": "netbox",
    "simulation": "cs", "cs": "cs",
    "nw": "nw", "network": "nw",
    "certificates": "le", "le": "le",
}


def _parse_nn(v) -> Optional[int]:
    """Parse a per-repo ``.NN`` version string into its integer ``N`` (e.g.
    ``".486" -> 486``), or ``None`` for anything that is NOT on the ``.NN``
    numbering (``"unknown"``, ``"v.01"``, an ``X.Y.Z`` tag, ``None``, ``""``).
    Pure + module-level so the diagnostics handler and its test share one parser."""
    import re as _re
    m = _re.match(r"^\.(\d+)$", str(v if v is not None else "").strip())
    return int(m.group(1)) if m else None


def _version_behind(running, latest) -> bool:
    """True iff BOTH ``running`` and ``latest`` are valid ``.NN`` versions and
    ``running`` is strictly older (smaller ``N``) than ``latest``.

    NEVER true when either side is unknown / non-``.NN`` — so a spoke is only
    flagged "behind" when the hub genuinely knows a newer version exists for that
    repo. Strictly-less (not ``!=``) so a spoke that is somehow AHEAD of a stale
    local checkout is not mislabeled behind. Pure → unit-testable."""
    r = _parse_nn(running)
    l = _parse_nn(latest)
    if r is None or l is None:
        return False
    return r < l


# ── GitHub-backed "latest .NN" for sibling repos ────────────────────────────
# A normal hub keeps only its OWN repo locally (/opt/lm); sibling spokes
# (opnsense/netbox/cs/pxmx/…) have no local VERSION checkout, so their latest
# .NN can't be resolved from disk and they were NEVER flagged behind. These repos
# autobump a `.NN` VERSION on every push (see .github/workflows/version-bump.yml)
# and the CI bot COMMITS the VERSION file to the default branch — it does NOT tag
# — so the latest .NN is read from the raw VERSION file on the default branch, not
# from `git ls-remote --tags`. Fetched over HTTPS (stdlib urllib, no deps) with a
# short timeout, HOURLY-cached (lazy stale-while-revalidate), and refreshed OFF
# the event loop. On any failure the last-good value (or None) is kept — the
# never-false-positive rule holds.
_GITHUB_OWNER = "lbockenstedt"
# Hourly is plenty — these .NN counters move on human-paced pushes, and the chip
# only needs to be roughly current. Serving a value up to an hour stale never
# false-positives (a stale-but-real latest is still <= the true latest).
_VERSION_CHECK_TTL_S = 3600
# Short, so an air-gapped / offline hub never stalls the background refresh long.
# The diagnostics request itself NEVER waits on this — it reads the cache only.
_VERSION_FETCH_TIMEOUT_S = 8.0


def _github_version_url(repo: str, owner: str = _GITHUB_OWNER, branch: str = "main") -> str:
    """Raw-content URL for a repo's ``VERSION`` file on its default branch. The
    version-bump bot commits ``VERSION`` (no tag), so this raw file IS the latest
    ``.NN``. ``repo`` is a bare repo name from ``_MODULE_REPO_DIR`` (or ``lm``)."""
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/VERSION"


def _fetch_github_version(repo: str, owner: str = _GITHUB_OWNER,
                          branch: str = "main",
                          timeout: float = _VERSION_FETCH_TIMEOUT_S) -> Optional[str]:
    """Fetch a repo's raw ``VERSION`` over HTTPS and return its stripped contents
    (e.g. ``".486"``), or ``None`` on any failure (network down, non-200, bad
    content). Pure stdlib ``urllib`` (no extra deps). Blocking — callers run it via
    ``asyncio.to_thread``; NEVER on the event loop. Reads only a small prefix (a
    VERSION file is a few bytes). Failures are DEBUG-logged and non-fatal so an
    offline hub never errors or false-positives — it just serves the last good
    value (or None)."""
    import urllib.request
    url = _github_version_url(repo, owner, branch)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "lm-hub-version-check"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) not in (200, None):
                return None
            raw = resp.read(64).decode("utf-8", "replace").strip()
            return raw or None
    except Exception as e:  # noqa: BLE001 — offline is normal; never fatal
        logger.debug("github version fetch failed for %s: %s", repo, e)
        return None


def _ver(v: str):
    """Parse a dotted-numeric VERSION string into a comparable tuple, or
    ``(0, 0, 0)`` on any parse failure (non-numeric like ``"v.01"``, ``"unknown"``).
    Module-level so the gate helper and callers share one parser."""
    try:
        return tuple(int(x) for x in (v or "").strip().split("."))
    except Exception:
        return (0, 0, 0)


def _update_available(local_commit, remote_commit, stored_commit,
                      local_v, remote_v, force=False) -> dict:
    """Decide whether a hub update is available. Pure (no I/O) → unit-testable,
    and the gate logic lives in one place instead of inline in ``perform_update``.

    Primary signal is commit-SHA comparison: the v.01 VERSION reset (2026-06-28)
    made a string VERSION compare always say "up to date" (both ends perpetually
    ``v.01``), so it can no longer detect an ahead remote. For a **git** install
    ``local_commit`` is HEAD → compare to ``remote_commit``. For a **non-git**
    (tarball) install ``local_commit`` is ``"unknown"`` → compare ``remote_commit``
    to ``stored_commit`` (``global_config["last_update_commit"]``, the last commit
    recorded as applied). VERSION comparison (``ver_ahead``) is kept as a final
    fallback for any future deployment that bumps VERSION again.

    Returns ``{"update_available", "commit_ahead", "ver_ahead"}``.
    """
    if local_commit != "unknown":
        commit_ahead = remote_commit != "unknown" and remote_commit != local_commit
    else:
        # Non-git install: compare remote tip to the last commit we applied.
        commit_ahead = remote_commit != "unknown" and remote_commit != stored_commit
    ver_ahead = _ver(remote_v) > _ver(local_v)
    return {
        "update_available": bool(force or commit_ahead or ver_ahead),
        "commit_ahead": bool(commit_ahead),
        "ver_ahead": bool(ver_ahead),
    }


def _detect_legacy_leaf() -> List[str]:
    """Names of any leftover legacy Generic Leaf Agent units (the crash-looping
    lm-bootstrap / lm-generic-agent zombie that a hub VM can inherit from an old
    image). Read-only — the hub process (svc_lm) can't purge units, but it CAN
    surface them so install_all.sh's retire_legacy_leaf (or a manual purge) is
    prompted. Matches the well-known names + any unit whose ExecStart references
    the removed /opt/lm/generic-agent path."""
    found: List[str] = []
    try:
        for name in ("lm-bootstrap", "lm-generic-agent"):
            if os.path.exists(f"/etc/systemd/system/{name}.service"):
                found.append(name)
        if os.path.isdir("/opt/lm/generic-agent") and "legacy-dir:/opt/lm/generic-agent" not in found:
            found.append("legacy-dir:/opt/lm/generic-agent")
    except Exception:  # noqa: BLE001
        pass
    return found


class UpdatePipelineMixin:
    """Hub self-update + spoke/agent update methods, extracted from
    ``LabManagerHub``. All methods operate on ``self`` (a fully-initialised Hub
    instance at runtime) so they read ``self.state`` / ``self.mailbox`` /
    ``self.approved_modules`` / etc. exactly as when they lived on the Hub."""

    async def get_local_version(self) -> str:
        """Return the locally-installed Hub version from the VERSION file, or ``"unknown"`` on error."""
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")
            with open(version_path, "r") as f:
                return f.read().strip()
        except Exception as e:
            logger.error(f"Failed to read local version: {e}")
            return "unknown"

    def _read_version_cached(self, path: str) -> Optional[str]:
        """Read a ``VERSION`` file's contents, cached by (path, mtime).

        The diagnostics handler resolves a latest-version per spoke and many
        spokes share a repo, so a naive read would stat+open the same file once
        per spoke per /setup/diagnostics call. Cache keyed on mtime: re-read only
        when the file actually changes (a repo pull rewrites VERSION → new mtime).
        Missing/unreadable file → ``None`` (never raises). Lazy cache dict, so no
        Hub ``__init__`` change is needed for this mixin."""
        cache = self.__dict__.setdefault("_version_read_cache", {})
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            cache.pop(path, None)
            return None
        hit = cache.get(path)
        if hit is not None and hit[0] == mtime:
            return hit[1]
        try:
            with open(path, "r") as f:
                val = f.read().strip()
        except OSError:
            cache.pop(path, None)
            return None
        cache[path] = (mtime, val)
        return val

    def _sibling_version_candidates(self, repo: str) -> List[str]:
        """Candidate on-disk paths for a sibling repo's ``VERSION`` file.

        The hub only reliably keeps its OWN repo locally (``/opt/lm``); a given
        deployment MAY also keep sibling checkouts (agent-morph clones, a
        provisioning_repos entry, or a dev sibling tree). Probe the known layouts;
        the first that holds a valid ``.NN`` wins. None found → latest unknown →
        the spoke is never flagged behind."""
        here = os.path.dirname(__file__)                      # core/src
        hub_root = os.path.abspath(os.path.join(here, "../../"))  # lm/ (== /opt/lm)
        parent = os.path.abspath(os.path.join(hub_root, ".."))    # dev sibling parent
        return [
            os.path.join(hub_root, repo, "VERSION"),
            os.path.join(hub_root, "provisioning_repos", repo, "VERSION"),
            os.path.join(parent, repo, "VERSION"),
            os.path.join("/opt/lm", repo, "VERSION"),
        ]

    def latest_version_for_module(self, module_type: Optional[str]) -> Optional[str]:
        """Latest known ``.NN`` version for the repo that backs ``module_type``.

        - Module code that ships INSIDE the lm/hub clone (dns/dhcp/console/agent)
          → the hub's own ``/opt/lm/VERSION`` (always local, always authoritative).
        - A sibling-repo module (firewall→opnsense, ipam→netbox, …) → the first
          local sibling ``VERSION`` checkout that holds a valid ``.NN`` (see
          ``_sibling_version_candidates``).
        - Unknown module_type, or no local checkout found → ``None``.

        ``None`` means "hub can't determine latest" and the caller MUST NOT flag
        the spoke as behind (never false-positive). Cheap (mtime-cached reads)."""
        mt = (module_type or "").strip().lower()
        if mt in _IN_LM_REPO_MODULE_TYPES:
            hub_version = os.path.join(os.path.dirname(__file__), "../../VERSION")
            v = self._read_version_cached(hub_version)
            if v is None:
                v = self._read_version_cached(
                    os.path.join(os.path.dirname(__file__), "../VERSION"))
            return v
        repo = _MODULE_REPO_DIR.get(mt)
        if not repo:
            return None
        for path in self._sibling_version_candidates(repo):
            v = self._read_version_cached(path)
            if _parse_nn(v) is not None:
                return v
        # No local authoritative VERSION for this sibling repo → fall back to the
        # hourly GitHub-cached latest .NN (served synchronously; refreshed in the
        # background). None when unresolvable → caller never flags behind.
        gh = self._github_latest_cached(repo)
        return gh if _parse_nn(gh) is not None else None

    # ── GitHub latest-version cache (repo_sync-driven + stale-while-revalidate) ─
    def _github_check_enabled(self) -> bool:
        """Whether to fetch the latest ``.NN`` from GitHub. Tied to the EXISTING
        hub "sync all repos" replication toggle
        (``global_config["repo_sync"]["enabled"]``, default True) — no separate
        env flag: when GitHub replication is OFF (e.g. an air-gapped hub), the
        per-repo latest-version check is OFF too, and sibling latest then resolves
        only from local checkouts (unresolved siblings are simply never flagged
        behind). Defaults True; never raises (a stub/early hub with no state → ON)."""
        try:
            return bool(self.state.get_global_config()
                        .get("repo_sync", {}).get("enabled", True))
        except Exception:  # noqa: BLE001 — no state yet / stub → default enabled
            return True

    def _github_latest_cached(self, repo: str) -> Optional[str]:
        """Latest ``.NN`` for a sibling ``repo`` from the HOURLY GitHub cache.

        Synchronous + fast — reads the in-memory cache ONLY, NEVER a live network
        call, so ``/setup/diagnostics`` stays fast. When the cached entry is stale
        (or absent) a background refresh is scheduled and the last-good value is
        returned in the meantime (stale-while-revalidate). First-ever call returns
        ``None`` (nothing cached yet) and warms the cache for the next call — so a
        spoke is never false-positived on a cold cache. Returns ``None`` when the
        check is disabled or nothing good has been fetched yet."""
        if not self._github_check_enabled():
            return None
        cache = self.__dict__.setdefault("_github_version_cache", {})
        entry = cache.get(repo)  # (fetched_ts, value_or_None) | None
        fresh = entry is not None and (time.time() - entry[0]) < _VERSION_CHECK_TTL_S
        if not fresh:
            self._schedule_github_version_refresh(repo)
        return entry[1] if entry is not None else None

    def _schedule_github_version_refresh(self, repo: str) -> None:
        """Fire-and-forget a background refresh of ``repo``'s latest .NN, if a
        running event loop is available (it is, inside the async diagnostics
        handler). De-duplicated by ``_refresh_github_version`` so overlapping
        diagnostics calls don't launch parallel fetches. Best-effort: no running
        loop (e.g. a unit test with no loop) → silently skip; the cache simply
        stays as-is and the caller returns the last-good value (or None)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._refresh_github_version(repo))

    async def _refresh_github_version(self, repo: str) -> None:
        """Refresh ``repo``'s latest .NN in the GitHub cache. Runs the blocking
        HTTPS fetch OFF the event loop (``asyncio.to_thread``). De-duplicated via
        an in-flight set so concurrent diagnostics calls fetch each repo at most
        once at a time. On a good ``.NN`` the cache is updated; on failure the
        LAST-GOOD value is kept (its TTL reset so we don't hammer an offline
        remote every request) — NEVER dropped and NEVER turned into a
        false-positive. Never raises."""
        if not self._github_check_enabled():
            return
        inflight = self.__dict__.setdefault("_github_version_inflight", set())
        if repo in inflight:
            return
        inflight.add(repo)
        try:
            text = await asyncio.to_thread(_fetch_github_version, repo)
            cache = self.__dict__.setdefault("_github_version_cache", {})
            now = time.time()
            if _parse_nn(text) is not None:
                cache[repo] = (now, text)
            else:
                # Fetch failed / non-.NN: keep the last-good value if we have one
                # (reset its TTL so we retry ~hourly, not every request); otherwise
                # remember the miss as None so the cold cache doesn't spin.
                prev = cache.get(repo)
                cache[repo] = (now, prev[1] if prev is not None else None)
        except Exception as e:  # noqa: BLE001 — background refresh is best-effort
            logger.debug("github version refresh errored for %s: %s", repo, e)
        finally:
            inflight.discard(repo)

    async def _refresh_all_module_versions(self) -> None:
        """Refresh the GitHub latest-``.NN`` cache for EVERY sibling repo. This is
        the PRIMARY refresh path — the repo-sync cycle (``run_repo_sync_all``,
        which already does GitHub network work on the configured interval, default
        15m) calls it, so the cache stays warm on the same schedule as replication
        and is OFF whenever replication is off. The lazy stale-while-revalidate in
        ``_github_latest_cached`` (hourly TTL) is only a fallback. Refreshes run
        concurrently (each is a ~8s off-loop fetch) and are individually
        best-effort; never raises."""
        if not self._github_check_enabled():
            return
        repos = sorted(set(_MODULE_REPO_DIR.values()))
        await asyncio.gather(
            *(self._refresh_github_version(r) for r in repos),
            return_exceptions=True,
        )

    async def get_remote_version(self) -> str:
        try:
            config = self.state.get_global_config()
            sources = config.get("update_sources", {})
            repo_url = _resolve_hub_repo(sources)

            if "github.com" in repo_url:
                parts = repo_url.rstrip("/").split("github.com/")
                if len(parts) == 2:
                    path = parts[1].removesuffix(".git")
                    version_url = f"https://raw.githubusercontent.com/{path}/main/VERSION"
                else:
                    logger.warning(f"Malformed GitHub URL: {repo_url}. Falling back to default.")
                    version_url = "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION"
            else:
                logger.warning(f"Non-GitHub repository URL configured ({repo_url}). Version check requires GitHub Raw format. Falling back to default.")
                version_url = "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION"

            logger.info(f"Fetching remote version from: {version_url}")

            async with httpx.AsyncClient() as client:
                resp = await client.get(version_url)
                if resp.status_code == 200:
                    return resp.text.strip()
                else:
                    logger.error(f"Failed to fetch remote version: HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Error fetching remote version: {e}")
        return "unknown"

    async def get_local_commit(self) -> str:
        """Return the SHA of the local ``HEAD`` commit, or ``"unknown"`` if the
        hub install isn't a git repo (tarball install) or git isn't available.

        Primary update-detection signal for git installs since the VERSION
        reset to ``v.01``: a string VERSION comparison can no longer tell
        ahead-of-remote from up-to-date, but a commit-SHA comparison can. See
        ``perform_update`` for how this composes with the remote SHA and the
        non-git fallback.
        """
        try:
            hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", hub_root, "rev-parse", "HEAD",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            if proc.returncode == 0:
                return out.decode().strip() or "unknown"
        except Exception as e:
            logger.debug(f"get_local_commit: {e}")
        return "unknown"

    async def get_remote_commit(self, hub_repo: Optional[str] = None, branch: Optional[str] = None) -> str:
        """Return the SHA of the remote ``refs/heads/<branch>`` tip via
        ``git ls-remote`` (no object download — lighter than a fetch), or
        ``"unknown"`` on failure. Works for any git remote (GitHub or not),
        so it does not depend on the GitHub Raw VERSION URL. ``hub_repo`` /
        ``branch`` default to the configured ``update_sources.hub`` and
        ``global_branch``.
        """
        try:
            config = self.state.get_global_config()
            sources = config.get("update_sources", {})
            repo = hub_repo or _resolve_hub_repo(sources)
            ref = branch or config.get("global_branch", "main")
            proc = await asyncio.create_subprocess_exec(
                "git", "ls-remote", repo, f"refs/heads/{ref}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            if proc.returncode == 0:
                # `ls-remote` prints "<sha>\trefs/heads/main"; take the first token.
                line = out.decode().strip().splitlines()
                if line and line[0].split():
                    return line[0].split()[0]
            else:
                logger.debug(f"get_remote_commit ls-remote rc={proc.returncode}: {err.decode().strip()}")
        except Exception as e:
            logger.debug(f"get_remote_commit: {e}")
        return "unknown"

    _STALE_RESTART_SENTINEL = "/var/lib/lm/state/stale-restart-requested"

    def _request_watchdog_restart(self, reason: str, force: bool = False) -> None:
        """Signal the external lm-watchdog to cleanly restart the hub by dropping
        a sentinel file it polls — the RELIABLE restart path (the in-process
        self-restart can't be trusted to fire). The watchdog restarts + clears
        it; the fresh process boots current so the sentinel is not re-written.

        ``force`` marks a user-initiated restart (the footer Update button): the
        watchdog restarts IMMEDIATELY, bypassing the logged-in-users idle guard.
        A non-force (auto-update / stale-recovery) sentinel is deferred by the
        watchdog while users are actively logged in (up to its max-defer).
        Best-effort; never raises. Overridable via LM_STALE_RESTART_SENTINEL."""
        try:
            path = os.environ.get("LM_STALE_RESTART_SENTINEL",
                                  self._STALE_RESTART_SENTINEL)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(f"{'force ' if force else ''}{reason}\n")
        except Exception as e:  # noqa: BLE001 — signalling is best-effort
            logger.debug("watchdog-restart sentinel write failed: %s", e)

    def _clear_watchdog_restart_sentinel(self) -> None:
        """Remove the watchdog restart sentinel — called at hub startup. The
        fresh process is by definition current, so any pending restart request
        is satisfied; clearing it prevents a double-restart when the direct
        self-restart worked (a genuinely-still-stale process is re-detected by
        check_update_health, which re-drops it). Best-effort."""
        try:
            path = os.environ.get("LM_STALE_RESTART_SENTINEL",
                                  self._STALE_RESTART_SENTINEL)
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:  # noqa: BLE001
            logger.debug("watchdog sentinel clear failed: %s", e)

    def _is_git_repo(self, path: str) -> bool:
        """Check if the given path is a git repository (contains a .git directory or is git rev-parse valid)."""
        git_dir = os.path.join(path, ".git")
        if os.path.isdir(git_dir) or os.path.isfile(git_dir):
            return True
        # Fallback: ask git itself (handles worktrees / bare configs)
        try:
            result = subprocess.run(
                ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except Exception:
            return False

    async def check_update_health(self) -> Dict[str, Any]:
        """Self-diagnose the hub's OWN update/git path so a broken updater is LOUD
        instead of silent — the failure mode behind a hub that quietly serves
        stale code (no .git → fragile tarball; unresolved HEAD → button git pull
        fails; running-version ≠ on-disk → updated-but-not-restarted; missing
        restart helper → pulls but never restarts; leftover legacy leaf zombie).
        Returns ``{ok, checks, warnings, errors}``; never raises (best-effort).

        ``errors`` = the update/self-heal path is BROKEN (would serve stale code
        or fail to restart: bad unit type, MainPID=0, no Restart=, unresolved
        HEAD, unwritable .git, missing restart helper, stale process). The
        caller logs these at ERROR so they surface in the hub error view.
        ``warnings`` = advisory (behind by N commits, watchdog absent, remote
        unreachable, legacy leaf) - logged at WARNING."""
        warnings: List[str] = []
        errors: List[str] = []
        checks: Dict[str, Any] = {}
        try:
            hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

            is_git = self._is_git_repo(hub_root)
            checks["git_checkout"] = is_git
            if not is_git:
                warnings.append(
                    f"{hub_root} is NOT a git checkout — updates use the fragile "
                    f"tarball path; re-run install_all.sh to restore .git.")
            else:
                # Permission-drift SELF-HEAL. A person or faulty install can leave
                # .git/objects root-owned; the svc_lm-run git pull then fails with
                # "insufficient permission for adding an object". Detect it (can
                # this process write .git/objects?) and auto-repair via the root
                # helper (sudo -n lm-fix-perms) so the drift never sits silently.
                git_objects = os.path.join(hub_root, ".git", "objects")
                if os.path.isdir(git_objects) and not os.access(git_objects, os.W_OK):
                    repaired = await self._repair_update_perms()
                    if repaired and os.access(git_objects, os.W_OK):
                        checks["git_writable"] = "repaired"
                        logger.warning("[sync-error] update-health: .git ownership had "
                                       "drifted (root-owned objects) — auto-repaired via lm-fix-perms.")
                    else:
                        checks["git_writable"] = False
                        errors.append(
                            f"{git_objects} not writable by the hub user — git pull will "
                            f"fail ('insufficient permission for adding an object'). "
                            f"Auto-repair {'unavailable (lm-fix-perms/sudoers missing)' if not repaired else 'did not resolve it'}; "
                            f"run: chown -R svc_lm:svc_lm {hub_root} /var/log/lm")
                else:
                    checks["git_writable"] = True
                local = await self.get_local_commit()
                checks["local_commit"] = local
                if local == "unknown":
                    errors.append(
                        f"git HEAD unresolved in {hub_root} (dubious ownership / .git "
                        f"unreadable by the service user?) — the Update button's git pull will fail.")
                config = self.state.get_global_config()
                sources = config.get("update_sources", {}) or {}
                configured = sources.get("hub")
                branch = config.get("global_branch", "main")
                # Empty/missing update_sources.hub is a SILENT stale-hub bug, not
                # a skip: the old `if hub_repo:` guard skipped this probe entirely
                # so the box reported `ok` with no warning while perform_update's
                # ls-remote on "" returned "unknown" → "checked" forever. Resolve
                # to the default and probe regardless; WARN on the mis-config so
                # it is LOUD (the fallback keeps updates working, but the operator
                # should set the source explicitly, not accidentally inherit the
                # default).
                if not configured:
                    warnings.append(
                        "update_sources.hub is empty/missing — falling back to the "
                        "default repo URL for update checks. Set it explicitly so the "
                        "hub's own update source is intentional, not accidental.")
                hub_repo = _resolve_hub_repo(sources)
                remote = await self.get_remote_commit(hub_repo, branch)
                checks["remote_commit"] = remote
                if remote == "unknown":
                    warnings.append(
                        f"cannot reach {hub_repo}@{branch} (git ls-remote failed) — "
                        f"update checks can't see new versions.")
                elif local != "unknown" and remote != local:
                    warnings.append(
                        f"hub code is BEHIND {branch} (local {local[:10]} vs "
                        f"remote {remote[:10]}) — an update is pending.")

            # Process-vs-disk drift: running version != on-disk VERSION → the code
            # was updated on disk but this process never restarted (THE stale-hub bug).
            disk_v = await self.get_local_version()
            run_v = getattr(self, "_startup_version", None)
            checks["running_version"] = run_v
            checks["disk_version"] = disk_v
            if run_v and disk_v and run_v not in ("unknown",) and run_v != disk_v:
                errors.append(
                    f"process is STALE: running v{run_v} but on-disk is v{disk_v} — "
                    f"code updated without a restart (systemctl restart lm.service).")
                # The in-process self-restart (lm-update-restart) can silently
                # fail to fire from the daemon, leaving a stale process serving
                # old code. Drop a sentinel for the ROOT lm-watchdog, which does a
                # PROVEN `systemctl restart lm` and clears it. New process boots
                # current → not stale → no sentinel → no restart loop.
                self._request_watchdog_restart(f"stale v{run_v}->v{disk_v}")

            helper = "/usr/local/bin/lm-update-restart"
            checks["restart_helper"] = os.path.isfile(helper) and os.access(helper, os.X_OK)
            if not checks["restart_helper"]:
                errors.append(
                    f"{helper} missing/not executable — the Update button can pull but "
                    f"never RESTART (would leave a stale process).")

            # systemd unit audit. The self-restart-on-update path is
            # os._exit(3) + systemd Restart=. If the live unit is not Type=exec
            # with a real MainPID and a Restart= policy, an update pulls new code
            # but the process is never cleanly cycled - THE stale-hub failure
            # this whole subsystem exists to prevent. Audit the RUNNING unit
            # (not the install script) so drift from a hand-edit / old install is
            # LOUD. Skipped where systemd is absent (dev / macOS).
            if shutil.which("systemctl"):
                unit = os.environ.get("LM_HUB_UNIT", "lm.service")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "systemctl", "show", unit,
                        "-p", "Type", "-p", "Restart", "-p", "MainPID", "-p", "ActiveState",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    out, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                    props: Dict[str, str] = {}
                    for line in out.decode(errors="replace").splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            props[k.strip()] = v.strip()
                    checks["systemd_unit"] = props
                    if not props:
                        errors.append(
                            f"{unit}: systemctl show returned nothing - the hub unit "
                            f"is missing/misnamed; self-restart + watchdog cannot work. "
                            f"Set LM_HUB_UNIT or re-run install_all.sh.")
                    else:
                        utype = props.get("Type", "")
                        urestart = props.get("Restart", "")
                        active = props.get("ActiveState", "")
                        try:
                            mainpid = int(props.get("MainPID", "0") or "0")
                        except ValueError:
                            mainpid = 0
                        if utype and utype != "exec":
                            errors.append(
                                f"{unit} Type={utype} (expected 'exec') - the old "
                                f"oneshot/start_all.sh mode detaches main.py (MainPID=0) "
                                f"so an update os._exit(3) leaves a STALE process serving "
                                f"old code; re-run install_all.sh to rebuild as Type=exec.")
                        if urestart in ("", "no"):
                            errors.append(
                                f"{unit} Restart={urestart or 'no'} - the self-update "
                                f"os._exit(3) will NOT be revived by systemd, so the hub "
                                f"stays DOWN after every update; expected on-failure/always.")
                        if active == "active" and mainpid == 0:
                            errors.append(
                                f"{unit} is active but MainPID=0 - systemd is not tracking "
                                f"the hub process (detached mode); systemctl restart and "
                                f"the self-update cannot cleanly cycle it (stale-hub signature).")
                except Exception as e:  # noqa: BLE001 - audit must never raise
                    checks["systemd_unit"] = {"error": str(e)[:120]}
                    warnings.append(f"could not audit {unit} via systemctl: {str(e)[:120]}")

                # Watchdog timer - the EXTERNAL auto-heal (root, outside
                # lm.service cgroup) that force-restarts a wedged hub (active but
                # :443 dead, or MainPID=0). Advisory: the primary Type=exec +
                # Restart= self-restart still works without it.
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "systemctl", "is-active", "lm-watchdog.timer",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    out, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                    wd = out.decode(errors="replace").strip() or "unknown"
                    checks["watchdog_timer"] = wd
                    if wd != "active":
                        warnings.append(
                            f"lm-watchdog.timer is '{wd}' (expected active) - the external "
                            f"auto-heal that force-restarts a wedged hub is NOT running; "
                            f"run scripts/install-lm-watchdog.sh (or re-run install_all.sh).")
                except Exception as e:  # noqa: BLE001
                    checks["watchdog_timer"] = f"error: {str(e)[:80]}"
            else:
                checks["systemd_unit"] = "n/a (no systemctl)"

            legacy = _detect_legacy_leaf()
            if legacy:
                checks["legacy_leaf"] = legacy
                warnings.append(
                    f"legacy generic-agent unit(s) present: {', '.join(legacy)} — "
                    f"crash-looping zombie; retire it (install_all.sh now purges it, "
                    f"or: systemctl disable --now <unit> && rm the unit file).")
        except Exception as e:  # noqa: BLE001 — health check must never raise
            warnings.append(f"update health check error: {e}")
        return {"ok": not warnings and not errors, "checks": checks,
                "warnings": warnings, "errors": errors}

    async def _repair_update_perms(self) -> bool:
        """Best-effort self-heal for update-path permission drift (root-owned
        .git/objects or /var/log/lm — what a person or faulty install
        re-introduces). Runs `git config safe.directory` (doable as the hub user)
        + the root `lm-fix-perms` helper via `sudo -n` (installed by
        install_all.sh with a sudoers grant, like lm-update-restart). Returns True
        if the helper ran successfully; never raises."""
        hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
        try:
            p = await asyncio.create_subprocess_shell(
                f"git config --global --add safe.directory {hub_root}",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await p.communicate()
        except Exception:
            pass
        helper = "/usr/local/bin/lm-fix-perms"
        if not (os.path.isfile(helper) and os.access(helper, os.X_OK)):
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", "-n", helper,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _out, err = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            if proc.returncode == 0:
                return True
            logger.warning("update-health: lm-fix-perms failed rc=%s: %s",
                           proc.returncode, err.decode(errors="replace")[:200])
        except Exception as e:  # noqa: BLE001
            logger.warning("update-health: perm repair invocation failed: %s", e)
        return False

    async def _download_update(self, hub_root: str, repo_url: str, branch: str) -> bool:
        """
        Alternative update mechanism for non-git installations.
        Downloads a tarball from GitHub and extracts it over the existing install.
        Returns True only if the local VERSION actually changes to match the remote.
        """
        tmp_dir = None
        try:
            if "github.com" in repo_url:
                parts = repo_url.rstrip("/").split("github.com/")
                if len(parts) != 2 or not parts[1]:
                    logger.error(f"Malformed GitHub URL for tarball update: {repo_url}")
                    return False
                repo_path = parts[1].rstrip("/")
                if repo_path.endswith(".git"):
                    repo_path = repo_path[:-4]
                tarball_url = f"https://github.com/{repo_path}/archive/refs/heads/{branch}.tar.gz"
            else:
                logger.error(f"Non-GitHub repository URL configured ({repo_url}). Cannot perform download-based update.")
                return False

            logger.info(f"Downloading update tarball from: {tarball_url}")
            async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
                resp = await client.get(tarball_url)
                if resp.status_code != 200:
                    logger.error(f"Failed to download update tarball: HTTP {resp.status_code}")
                    return False

                tar_bytes = io.BytesIO(resp.content)

            tmp_dir = tempfile.mkdtemp(prefix="lm_update_")
            with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tar:
                # Prevent path traversal (zip-slip) attacks
                safe_members = []
                for m in tar.getmembers():
                    member_path = os.path.normpath(m.name)
                    if member_path.startswith("..") or os.path.isabs(member_path):
                        logger.warning(f"Skipping unsafe member in tarball: {m.name}")
                        continue
                    safe_members.append(m)
                tar.extractall(path=tmp_dir, members=safe_members)

            # Locate the extracted top-level directory
            entries = os.listdir(tmp_dir)
            if not entries:
                logger.error("Update tarball is empty.")
                return False
            extracted_root = os.path.join(tmp_dir, entries[0])
            if not os.path.isdir(extracted_root):
                logger.error(f"Update tarball top-level entry is not a directory: {entries[0]}")
                return False

            # Merge extracted contents into hub root. Never delete existing dirs —
            # rmtree would kill the running venv (breaking httpx/SSL mid-update).
            # Skip runtime-only dirs that must not be overwritten.
            top_preserve = {"data", "state", "cache", ".git", "__pycache__"}
            sub_ignore = shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.pyo")
            for item in os.listdir(extracted_root):
                if item in top_preserve:
                    continue
                src = os.path.join(extracted_root, item)
                dst = os.path.join(hub_root, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=sub_ignore)
                else:
                    shutil.copy2(src, dst)

            # Verify update actually took effect. A tarball install has no local
            # git HEAD to compare, and post the v.01 reset a VERSION-equality
            # check is always true (both ends v.01), so the success signal is
            # the exception-free merge of a 200 tarball above. Resolve the remote
            # tip via ls-remote for logging; perform_update() records
            # ``last_update_commit = remote_commit`` on success, which is how the
            # *next* advance is detected for a non-git install.
            remote_commit = await self.get_remote_commit(repo_url, branch)
            if remote_commit != "unknown":
                logger.info(
                    f"Hub tarball update applied from {branch} tip {remote_commit[:10]} "
                    f"(repo {repo_url})."
                )
            else:
                logger.warning(
                    f"Tarball merge completed but ls-remote failed; recording "
                    f"last_update_commit will be skipped this cycle."
                )
            return True
        except Exception as e:
            logger.error(f"Error during download-based update: {e}", exc_info=True)
            return False
        finally:
            if tmp_dir and os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

    async def _git_checkout_is_conflicted(self, root: str) -> bool:
        """True if the checkout has unmerged files or an in-progress rebase/merge
        — a wedged pull-only deploy checkout that blocks every future pull."""
        try:
            gd = os.path.join(root, ".git")
            if (os.path.isdir(os.path.join(gd, "rebase-merge"))
                    or os.path.isdir(os.path.join(gd, "rebase-apply"))
                    or os.path.isfile(os.path.join(gd, "MERGE_HEAD"))):
                return True
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", root, "diff", "--name-only", "--diff-filter=U",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            return proc.returncode == 0 and bool(out.decode().strip())
        except Exception as e:  # noqa: BLE001
            logger.debug("conflict check failed: %s", e)
            return False

    async def _git_reset_hard_to_remote(self, root: str, branch: str) -> bool:
        """Abandon any half-rebase/merge + local changes and hard-align the
        pull-only deploy checkout to origin/<branch>. Returns True on success."""
        cmd = (f"cd {root} && "
               f"(git rebase --abort 2>/dev/null; git merge --abort 2>/dev/null; true) && "
               f"git fetch origin {branch} && git reset --hard origin/{branch}")
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _out, err = await asyncio.wait_for(proc.communicate(), timeout=120.0)
            if proc.returncode == 0:
                return True
            logger.warning("reset --hard recovery failed (rc=%d): %s",
                           proc.returncode, err.decode().strip()[:300])
        except Exception as e:  # noqa: BLE001
            logger.warning("reset --hard recovery errored: %s", e)
        return False

    async def _git_update(self, hub_root: str, hub_repo: str, branch: str) -> bool:
        """
        Performs a git-based update. Returns True only if the update actually
        changed the local version (verified post-update).
        """
        try:
            await asyncio.create_subprocess_shell(f"git config --global --add safe.directory {hub_root}")

            update_cmd = (
                f"cd {hub_root} && "
                f"git remote set-url origin {hub_repo} && "
                f"git pull --rebase --autostash origin {branch}"
            )

            process = await asyncio.create_subprocess_shell(
                update_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300.0)

            err_msg = stderr.decode().strip()
            out_msg = stdout.decode().strip()

            if process.returncode != 0:
                logger.error(f"Hub git pull failed (rc={process.returncode}): {err_msg}")
                # SELF-HEAL: a pull-only deploy checkout can wedge in a conflicted
                # / half-rebased state (unmerged files — classically the CI VERSION
                # bump colliding with a racing pull), which then blocks EVERY future
                # pull. /opt/lm carries no intentional local commits, so recover by
                # abandoning local state and hard-aligning to the remote tip — the
                # same recovery a human runs (rebase --abort + reset --hard).
                el = err_msg.lower()
                if ("unmerged" in el or "conflict" in el or "unresolved" in el
                        or "would be overwritten" in el
                        or await self._git_checkout_is_conflicted(hub_root)):
                    logger.warning("Hub checkout is conflicted — self-healing via "
                                   "reset --hard origin/%s", branch)
                    if await self._git_reset_hard_to_remote(hub_root, branch):
                        nlc = await self.get_local_commit()
                        rc2 = await self.get_remote_commit(hub_repo, branch)
                        if nlc != "unknown" and nlc == rc2:
                            logger.info("Hub self-healed to %s via reset --hard.", nlc[:10])
                            return True
                        logger.warning("Hub reset --hard ran but HEAD still != remote.")
                return False

            # CRITICAL: verify the pull actually advanced HEAD to the remote tip.
            # Post the v.01 VERSION reset a VERSION-equality check is always true
            # (both ends v.01), so it can no longer confirm a real update —
            # compare commit SHAs instead, falling back to VERSION only if git
            # is somehow unavailable on a git install.
            new_local_commit = await self.get_local_commit()
            remote_commit = await self.get_remote_commit(hub_repo, branch)
            if new_local_commit != "unknown" and remote_commit != "unknown":
                if new_local_commit == remote_commit:
                    logger.info(f"Hub successfully updated via git to {new_local_commit[:10]}.")
                    return True
                logger.warning(
                    f"Git pull returned success but HEAD {new_local_commit[:10]} "
                    f"!= remote tip {remote_commit[:10]}. Update verification failed."
                )
                return False
            # Fallback (git unavailable): legacy VERSION equality.
            new_local_v = await self.get_local_version()
            remote_v = await self.get_remote_version()
            if new_local_v == remote_v and new_local_v != "unknown":
                logger.info(f"Hub updated via git to {new_local_v} (VERSION fallback).")
                return True
            logger.warning(
                f"Git update verification failed: local={new_local_v} remote={remote_v}."
            )
            return False
        except Exception as e:
            logger.error(f"Unexpected error during git-based Hub update: {e}", exc_info=True)
            return False

    # ── Spoke-update fan-out helpers ────────────────────────────────────────
    # perform_update / update_spokes_only / update_agents_only all fan out
    # SPOKE_UPDATE messages to approved spokes. The module_key resolve (from
    # spoke_id via a prefix map), the Message construction, and the mailbox.push
    # are identical in shape; the log markers, the triggered/skipped result
    # formatting, the 'qa' prefix, the opnsense→opn legacy fallback, and the
    # agent-only filter differ and stay inline at each call site. Two small
    # helpers share the identical core so the three fan-out loops become short
    # inline tails (better a clean shared core + 3 small inline tails than 3
    # forced-fit bugs).

    def _effective_module_type(self, spoke_id: str) -> str:
        """module_type for update-source resolution, resilient to disconnects.

        ``self.spoke_module_types`` is the LIVE map and is POPPED when a spoke
        disconnects (see main.py handle_connection cleanup). An approved-but-
        offline agent — or any spoke whose type has not re-registered yet after a
        hub restart — therefore resolves to ``""`` here. That empty type MISSES
        the ``_IN_LM_REPO_MODULE_TYPES`` guard in ``_resolve_module_key`` and
        falls through to the spoke_id substring map, so an id like
        ``"lm-opnsense"`` substring-matches ``"opn"`` → the opnsense repo. The
        resulting SPOKE_UPDATE is queued into the agent's DURABLE mailbox and, on
        the next reconnect, repoints the shared ``/opt/lm`` checkout's git origin
        to the role repo + hard-resets it — deleting ``agent/src/control_plane.py``
        and crash-looping/flapping the agent. Falling back to the module_type
        persisted in ``module_metadata`` (written on every registration) keeps
        ``agent`` → the lm repo across disconnects and hub restarts."""
        live = self.spoke_module_types.get(spoke_id)
        if live:
            return live
        return (self.state.system_state.get("module_metadata", {})
                .get(spoke_id, {}).get("module_type", "")) or ""

    def _resolve_module_key(
        self, spoke_id: str, mtype: str, prefix_map: Dict[str, str]
    ) -> Optional[str]:
        """Resolve the ``update_sources`` config key for a spoke: try the
        module-type registry (``_UPDATE_SOURCE_MODULE_KEY``) first, then fall
        back to the first substring match against ``prefix_map``. Returns the
        key string (e.g. ``"pxmx"``, ``"opnsense"``) or ``None``.

        Used by perform_update (with ``_UPDATE_SOURCE_PREFIX_MAP``) and
        update_spokes_only (with that map plus ``'qa': 'qa'``). update_agents_only
        does not resolve — it draws its repo_url directly from
        ``update_sources["agent"]``, so it does not call this helper.
        """
        # The generic agent AND the in-repo roles (dns/dhcp/console) live in the
        # lm/hub clone at /opt/lm; their update source is the "agent" key (the lm
        # repo) — NEVER a spoke_id substring match. Without this a name like
        # "lm-opnsense" (or a sub-spoke "lm-opnsense-dns") substring-matches "opn"
        # → the opnsense repo, and the resulting SPOKE_UPDATE repoints the
        # checkout's git origin + hard-resets, wiping the tree (the recurring
        # "can't open control_plane.py" crash-loop). See _IN_LM_REPO_MODULE_TYPES.
        # (If "agent" isn't in update_sources the caller's `if repo_url:` guard
        # simply skips the push — these self-update from the lm repo anyway.)
        if mtype in _IN_LM_REPO_MODULE_TYPES:
            return "agent"
        module_key = _UPDATE_SOURCE_MODULE_KEY.get(mtype)
        if not module_key:
            for prefix, key in prefix_map.items():
                if prefix in spoke_id:
                    module_key = key
                    break
        return module_key

    async def _push_spoke_update(
        self,
        spoke_id: str,
        repo_url: str,
        branch: str,
        msg_type: str = "SPOKE_UPDATE",
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Exception]:
        """Build a SPOKE_UPDATE ``Message`` and push it to the spoke's mailbox.

        Shared core of the three update fan-out paths — the Message construction
        and ``mailbox.push`` are identical across all three; the log markers and
        triggered/skipped result formatting differ and stay inline at each call
        site. Returns ``None`` on success or the caught ``Exception`` on mailbox
        failure, so the caller can emit its own error log marker and append its
        own skipped/error entry with the exact format each path uses.
        """
        data: Dict[str, Any] = {"repo_url": repo_url, "branch": branch}
        if extra_data:
            data.update(extra_data)
        msg = Message(
            header=MessageHeader(
                message_id=str(uuid.uuid4()),
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id,
            ),
            payload=MessagePayload(type=msg_type, data=data),
        )
        try:
            await self.mailbox.push(msg, self.send_to_spoke)
            return None
        except Exception as e:
            return e

    async def perform_update(self, force=False, force_spokes=False):
        """
        Checks for updates and performs either a git pull (for git installs) or a
        tarball-based download (for non-git installs) if a new version is available.
        Also triggers updates for all approved modules (connected or offline).
        """
        # Anti-lockout: ensure the first admin account always retains its
        # privileges and reconcile the two admin-flag forms (role + boolean)
        # across all admin users. Runs on every update so manual edits to state
        # files cannot permanently lock out the initial admin or leave an
        # admin's "System Admin" checkbox unset in the WebUI.
        if self.state.ensure_admin_lockout():
            self.state.save_state()

        logger.info(f"Running update check (force={force})...")
        local_v = await self.get_local_version()
        remote_v = await self.get_remote_version()

        # ── Update detection ─────────────────────────────────────────────────
        # Since the VERSION reset to ``v.01`` (2026-06-28) a string VERSION
        # comparison can no longer distinguish ahead-of-remote from up-to-date
        # — both ends are perpetually ``v.01``. Commit-SHA comparison is now the
        # primary signal: the hub is "behind" when the remote tip SHA differs
        # from what it has. For git installs that's local HEAD vs the remote
        # tip; for non-git (tarball) installs there is no local HEAD, so we
        # compare the remote tip to the last commit we recorded as applied
        # (``global_config["last_update_commit"]``, written on a successful
        # update). The legacy ``_ver`` comparison is kept as a final fallback
        # for any future deployment that bumps VERSION again.
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        hub_repo = _resolve_hub_repo(sources)
        branch = config.get("global_branch", "main")
        stored_commit = config.get("last_update_commit")
        # Thread the lm/core source so each spoke also pulls its shared /opt/lm
        # checkout on SPOKE_UPDATE (no CLI for lm/core deploys). RAW sources.get
        # (no default) so an air-gapped deploy with update_sources.hub blank
        # sends core_repo_url=None and the spoke skips core gracefully instead of
        # pointing at the public repo.
        core_extra = {"core_repo_url": sources.get("hub"), "core_branch": branch}

        local_commit = await self.get_local_commit()
        remote_commit = await self.get_remote_commit(hub_repo, branch)

        gate = _update_available(local_commit, remote_commit, stored_commit,
                                 local_v, remote_v, force)
        update_available = gate["update_available"]

        logger.info(
            f"Update check: local={local_v}@{local_commit[:10] if local_commit != 'unknown' else 'n/a'} "
            f"remote={remote_v}@{remote_commit[:10] if remote_commit != 'unknown' else 'n/a'} "
            f"commit_ahead={gate['commit_ahead']} ver_ahead={gate['ver_ahead']} force={force}"
        )

        self.state.update_global_config({"last_update_ts": time.time()})
        self.state.save_state()

        hub_updated = False
        stale_reload = False  # git current but the running process is older than on-disk
        update_failed = False  # update was available + attempted, but did NOT apply
        if update_available:
            try:
                hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

                # ── Recovery prelude ──────────────────────────────────────────
                # Skip a version that was rolled back after failing to boot. force
                # bypasses it (operator explicitly re-trying a known-bad version).
                # Stale bad entries older than this newer remote are cleared so a
                # "don't pull 1.0.9" marker doesn't block a forward move to 1.0.10.
                if not force and is_version_bad(remote_v):
                    logger.warning(
                        f"Remote v{remote_v} is marked bad after a failed boot; "
                        f"skipping auto-update (use ?force=true to retry)."
                    )
                else:
                    if not force and remote_v:
                        clear_bad_versions_older_than(remote_v)

                    # Snapshot core/src + WebUI *before* the swap so the root
                    # helper (lm-update-restart) can roll back if the new version
                    # fails to reach /status. The pending manifest tells it where
                    # the backup lives and which version to mark bad on rollback.
                    # dns/+dhcp/ are the in-repo spokes the hub restarts itself
                    # (update_pipeline.py:596 systemctl restart lm-dns/lm-dhcp) —
                    # include them in the snapshot so a broken spoke code swap is
                    # captured for recovery too (the automated hub rollback
                    # restores core/src+WebUI; dns/dhcp are preserved on disk for
                    # operator/manual restore since their restart path bypasses
                    # the spoke's own BaseControlPlane rollback).
                    try:
                        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                        # snapshot_code does recursive shutil.copytree of core/src
                        # + WebUI + dns + dhcp (synchronous I/O) — run it on a
                        # thread so the hub loop keeps serving heartbeats /
                        # request_response during the snapshot (this is the hourly
                        # repo_sync path; a stall here times out every spoke).
                        backup_dir = await asyncio.to_thread(
                            snapshot_code, hub_root, ts,
                            ["core/src", "WebUI", "dns", "dhcp"])
                        await asyncio.to_thread(write_pending, backup_dir, local_v, remote_v, ts)
                    except Exception as _e:
                        logger.warning(
                            f"Pre-update snapshot failed (rollback disabled): {_e}"
                        )

                    # Check whether the installation directory is a git repository
                    is_git_repo = self._is_git_repo(hub_root)

                    if is_git_repo:
                        logger.info(f"Hub installation is a git repo. Attempting git-based update...")
                        hub_updated = await self._git_update(hub_root, hub_repo, branch)
                    else:
                        logger.info(
                            f"Hub installation directory {hub_root} is NOT a git repo. "
                            f"Using download-based (tarball) update mechanism."
                        )
                        hub_updated = await self._download_update(hub_root, hub_repo, branch)

                    if hub_updated:
                        # Record the commit we just applied so a non-git install
                        # can detect the *next* remote advance. For a git install
                        # local HEAD now equals the remote tip; storing it is
                        # harmless and keeps one code path for both install types.
                        applied = await self.get_local_commit()
                        if applied == "unknown":
                            applied = remote_commit
                        if applied != "unknown":
                            self.state.update_global_config({"last_update_commit": applied})
                            self.state.save_state()
                    else:
                        # Pull failed — local code is unchanged, so there is
                        # nothing to roll back to. Drop the pending manifest.
                        clear_pending()
                        update_failed = True
                        logger.warning(
                            f"Hub update did NOT succeed. Local version remains {local_v} "
                            f"(target: {remote_v}). Will retry on next cycle."
                        )
            except Exception as e:
                logger.error(f"Unexpected error during Hub update: {e}", exc_info=True)
                hub_updated = False
                update_failed = True
                clear_pending()
        else:
            logger.info("Hub is already up to date. Skipping Hub pull.")
            # The on-disk code can still be NEWER than the RUNNING process — e.g.
            # repo-sync or the dev watcher pulled /opt/lm/core without cycling the
            # process, so git reads "up to date" while the process serves STALE
            # code and the Update button reports success without ever reloading.
            # Detect it (startup VERSION != on-disk VERSION) and flag a self-
            # restart so the reload happens after the spoke fan-out below.
            try:
                _disk_v = await self.get_local_version()
                _run_v = getattr(self, "_startup_version", None)
                if _run_v and _disk_v and _run_v not in ("unknown",) and _run_v != _disk_v:
                    logger.warning(
                        "Hub git is current but the PROCESS is STALE (running %s, "
                        "on-disk %s) — will self-restart to load the on-disk code.",
                        _run_v, _disk_v)
                    stale_reload = True
            except Exception as _e:
                logger.debug("stale-process check skipped: %s", _e)

        update_results = []
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        branch = config.get("global_branch", "main")

        # Gate the spoke fan-out PER REPO: only push SPOKE_UPDATE to spokes whose
        # repo's remote tip actually advanced since we last pushed it. This loop
        # used to run UNCONDITIONALLY every repo-sync cycle — pinging every spoke
        # every interval regardless of whether anything changed. For a generic
        # agent's role sub-spokes (which pin their update to the lm repo), a
        # cs/opnsense/... bump then kept nudging them, forcing a pointless lm
        # re-pull + "SPOKE_UPDATE carried non-lm repo_url" churn / reconnect flap.
        # Group spokes by resolved repo, check each repo's tip once, push on change.
        last_pushed = dict(config.get("spoke_update_commits", {}) or {})
        repo_spokes: Dict[str, list] = {}
        for spoke_id, approved in self.approved_modules.items():
            if not approved:
                continue
            # Persisted-fallback type (not the raw live map) so an offline /
            # not-yet-re-registered agent still resolves as "agent" → the lm repo
            # and never substring-maps to a role repo. See _effective_module_type
            # for the poison-mailbox flap this prevents. update-source config-key
            # space — see _UPDATE_SOURCE_MODULE_KEY / _UPDATE_SOURCE_PREFIX_MAP
            # (firewall → "opnsense", NOT "opn").
            mtype = self._effective_module_type(spoke_id)
            module_key = self._resolve_module_key(spoke_id, mtype, _UPDATE_SOURCE_PREFIX_MAP)
            if not module_key:
                update_results.append(f"{spoke_id}: unknown module type")
                continue
            repo_url = sources.get(module_key)
            if not repo_url:
                update_results.append(f"{spoke_id}: no repo configured")
                continue
            repo_spokes.setdefault(repo_url, []).append(spoke_id)

        commits_changed = False
        # A manual "Update All" click forces the spoke fan-out (force_spokes) so a
        # spoke the gate believes is already current still gets re-pushed. The hub
        # self-update above stays gated on `force` alone, so an up-to-date hub is
        # NOT needlessly re-pulled/restarted just to nudge the spokes.
        spoke_force = bool(force or force_spokes)
        # Per-spoke re-push COOLDOWN. The marker (last_pushed[sid]) only advances
        # when the spoke was CONNECTED at push time, so a spoke that drops
        # mid-update (a slow git pull can stall its WS → 1011 keepalive timeout)
        # never records the tip and gets re-pushed EVERY repo-sync cycle — a
        # SPOKE_UPDATE storm that keeps it flapping. Suppress re-pushing the same
        # spoke within SPOKE_UPDATE_COOLDOWN_S so a legit update has time to land
        # + restart + reconnect on the new tip. `force_spokes` (Update button)
        # bypasses it. Stamped on every push attempt (connected or not).
        SPOKE_UPDATE_COOLDOWN_S = 600
        _now = time.time()
        pushed_ts = dict(config.get("spoke_update_pushed_ts", {}) or {})
        _approved_ids = {sid for ss in repo_spokes.values() for sid in ss}
        for _stale in [sid for sid in last_pushed if sid not in _approved_ids]:
            last_pushed.pop(_stale, None)
            commits_changed = True
        for _stale in [sid for sid in pushed_ts if sid not in _approved_ids]:
            pushed_ts.pop(_stale, None)
            commits_changed = True
        for repo_url, spoke_ids in repo_spokes.items():
            tip = await self.get_remote_commit(repo_url, branch)
            for sid in spoke_ids:
                if not spoke_force and tip != "unknown" and last_pushed.get(sid) == tip:
                    update_results.append(f"{sid}: up-to-date ({repo_url})")
                    continue
                if not spoke_force and (_now - float(pushed_ts.get(sid, 0) or 0)) < SPOKE_UPDATE_COOLDOWN_S:
                    _left = int(SPOKE_UPDATE_COOLDOWN_S - (_now - float(pushed_ts.get(sid, 0) or 0)))
                    update_results.append(f"{sid}: recently pushed - cooldown {_left}s ({repo_url})")
                    continue
                connected = sid in getattr(self, "active_connections", {})
                if not connected and not spoke_force:
                    update_results.append(f"{sid}: offline - deferred ({repo_url})")
                    continue
                logger.info(f"Triggering update for spoke {sid} from {repo_url}@{branch}"
                            + (f" (tip {tip[:10]})" if tip != "unknown" else "") + "...")
                err = await self._push_spoke_update(sid, repo_url, branch,
                                                    extra_data=core_extra)
                if err is None:
                    update_results.append(f"{sid}: triggered")
                    pushed_ts[sid] = _now
                    commits_changed = True
                    if connected and tip != "unknown":
                        last_pushed[sid] = tip
                else:
                    logger.error(f"Failed to push update for {sid}: {err}")
                    update_results.append(f"{sid}: failed")

        if commits_changed:
            self.state.update_global_config({"spoke_update_commits": last_pushed,
                                             "spoke_update_pushed_ts": pushed_ts})
            self.state.save_state()

        logger.info(f"Spoke update results: {update_results}")

        if hub_updated or stale_reload:
            # Restart local in-repo spokes (dns/dhcp live inside the lm repo; they
            # are already updated by the hub git pull above and just need a
            # restart). Only on a real git update — a stale-process reload didn't
            # change their code.
            if hub_updated:
                for local_svc in ("lm-dns", "lm-dhcp"):
                    try:
                        subprocess.Popen(["sudo", "systemctl", "restart", local_svc])
                        logger.info(f"Restarting local spoke service {local_svc}")
                    except Exception as _e:
                        logger.warning(f"Could not restart {local_svc}: {_e}")
            # Restart the hub from OUTSIDE its own cgroup so the restart
            # command survives lm.service being stopped. Calling
            # `systemctl restart lm` directly from here races the stop/start
            # against this process's cgroup and can strand the hub inactive
            # for ~16 min. /usr/local/bin/lm-update-restart uses
            # `systemd-run --no-block` to schedule the restart from a
            # transient unit owned by PID 1 (independent of lm.service), then
            # polls /status and rolls back the pre-swap snapshot if the new
            # version fails to boot (see core/src/update_recovery.py).
            logger.info("Hub was updated. Scheduling self-restart via transient unit...")
            # Flush the in-memory session store to disk so any login/logout since the
            # last save survives the restart (best-effort; save-on-mutation already
            # covers the common path, this closes the last-few-seconds window).
            try:
                from api import _save_sessions  # lazy: avoid a module-level api dep
                _save_sessions(self)
            except Exception as _e:
                logger.warning(f"Pre-restart session flush failed: {_e}")
            try:
                # DETACH the restart helper into its own session with std streams
                # sent to /dev/null. Launched un-detached from inside the asyncio
                # hub daemon, the child sudo lives in the hub's process group and
                # is killed before it can `systemd-run` the restart — which is why
                # the hub logged "Scheduling self-restart…" every cycle but never
                # actually restarted (no sudo in the journal, process stayed STALE).
                # start_new_session=True lets it survive to escape the cgroup and
                # fire the restart, exactly like a manual invocation from a tty.
                subprocess.Popen(
                    ["sudo", "-n", "/usr/local/bin/lm-update-restart"],
                    start_new_session=True, close_fds=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info("Self-restart helper (lm-update-restart) launched (detached).")
            except Exception as _e:
                logger.warning(f"Could not schedule hub self-restart: {_e}")
            # Also request the restart via the RELIABLE external watchdog path —
            # the in-process helper above can silently fail to fire from the
            # daemon. force=<manual Update button> → the watchdog restarts
            # immediately; an auto-update / stale-reload sentinel is deferred by
            # the watchdog while users are logged in (up to its max-defer). The
            # fresh process clears the sentinel on boot, so a successful direct
            # restart above does NOT cause a double-restart.
            self._request_watchdog_restart(
                "update->restart" if hub_updated else "stale-reload->restart",
                force=bool(force))
            if hub_updated:
                _rmsg = f"Updated Hub to {remote_v} and triggered spoke updates. Server is restarting (rolled back automatically if it fails to boot)..."
            else:
                _rmsg = "Hub code on disk was newer than the running process (stale process) — restarting to load it. Spoke updates triggered."
            return {"status": "success", "message": _rmsg}

        if update_failed:
            # An update WAS available and we tried to apply it, but the code did
            # not change (git/download failed, or the merge couldn't be verified).
            # Do NOT report success — return "error" so the route maps it to HTTP
            # 500 and the button surfaces the failure, instead of the old
            # "Hub is current" message that made every failed update look like a
            # no-op success (the reason a stale hub could sit un-updated silently).
            return {"status": "error",
                    "message": (f"Hub update FAILED — still at {local_v}, target was {remote_v}. "
                                f"Check hub logs (update_pipeline). "
                                f"{len(update_results)} spoke update(s) attempted.")}
        return {"status": "checked", "message": f"Update successful. Hub is current at {local_v}. {len(update_results)} spoke(s) updating to latest."}

    async def update_spokes_only(self):
        """Send SPOKE_UPDATE to every approved spoke without touching the Hub itself.

        Called by POST /setup/update/spokes — typically triggered by BugFixer after
        pushing a fix to GitHub so deployed services pick up the change before QA runs.
        """
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        branch = config.get("global_branch", "main")
        # Thread lm/core source alongside each spoke's own repo (see perform_update).
        core_extra = {"core_repo_url": sources.get("hub"), "core_branch": branch}

        # update-source config-key space, same as perform_update. The prefix map
        # adds "qa" → "qa" so a QA harness spoke can be pointed at a "qa" repo via
        # update_sources (perform_update intentionally omits qa — it doesn't
        # auto-update the test harness during a full hub update). See
        # _UPDATE_SOURCE_MODULE_KEY / _UPDATE_SOURCE_PREFIX_MAP.
        _upd_prefix_map = {**_UPDATE_SOURCE_PREFIX_MAP, 'qa': 'qa'}

        triggered = []
        skipped = []
        for spoke_id, approved in self.approved_modules.items():
            if not approved:
                continue
            mtype = self._effective_module_type(spoke_id)
            module_key = self._resolve_module_key(spoke_id, mtype, _upd_prefix_map)
            if not module_key:
                skipped.append(f"{spoke_id}: unknown module type")
                continue
            repo_url = sources.get(module_key)
            # Backward-compat: the Setup UI used to store the OPNsense repo URL
            # under the key "opn" while the hub looks it up as "opnsense". Honor
            # the legacy key so deployments that saved it before the fix still
            # self-update without a forced re-save of the Setup page.
            if not repo_url and module_key == "opnsense":
                repo_url = sources.get("opn")
            if not repo_url:
                skipped.append(f"{spoke_id}: no repo_url in update_sources.{module_key}")
                continue
            err = await self._push_spoke_update(spoke_id, repo_url, branch,
                                                extra_data=core_extra)
            if err is None:
                triggered.append(spoke_id)
                logger.info(f"SPOKE_UPDATE queued for {spoke_id} ({repo_url}@{branch})")
            else:
                logger.error(f"Failed to queue SPOKE_UPDATE for {spoke_id}: {err}")
                skipped.append(f"{spoke_id}: mailbox error — {err}")

        # Restart local in-repo spokes (dns/dhcp share the lm repo; they need a
        # service restart so they pick up the code the hub already pulled).
        for local_svc in ("lm-dns", "lm-dhcp"):
            try:
                subprocess.Popen(["sudo", "systemctl", "restart", local_svc])
                triggered.append(local_svc)
                logger.info(f"Restarting local spoke service {local_svc}")
            except Exception as _e:
                logger.warning(f"Could not restart {local_svc}: {_e}")
                skipped.append(f"{local_svc}: {_e}")

        summary = f"Triggered {len(triggered)} spoke(s): {', '.join(triggered) or 'none'}"
        if skipped:
            summary += f". Skipped: {'; '.join(skipped)}"
        logger.info(f"update_spokes_only complete — {summary}")
        return {"status": "ok", "triggered": triggered, "skipped": skipped, "message": summary}

    async def update_agents_only(self):
        """Send SPOKE_UPDATE to every approved *agent* (module_type == "agent").

        Mirrors update_spokes_only but filters to agent modules. Agents are
        generic (no per-type registry), so they all draw their repo_url from
        update_sources["agent"]; an agent is skipped if that source is unset.
        Triggered by BugFixer (via HUB_REQUEST TRIGGER_AGENT_UPDATES) after it
        pushes a fix, so deployed agents pick up the change before QA runs.
        """
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        branch = config.get("global_branch", "main")
        repo_url = sources.get("agent")
        # Thread lm/core source. For agents the spoke's own repo is typically the
        # lm repo itself (all-in-one /opt/lm layout), so core_repo_url == repo_url
        # and the spoke's _resolve_core_root sees core_root == cwd → skips the
        # duplicate core fetch (the spoke-repo pull already covers /opt/lm). RAW
        # sources.get("hub") so air-gapped blank → None → graceful skip.
        core_extra = {"core_repo_url": sources.get("hub"), "core_branch": branch}

        triggered = []
        skipped = []
        if not repo_url:
            # No agent update source configured — skip every agent with a clear reason.
            for spoke_id, approved in self.approved_modules.items():
                if not approved:
                    continue
                if self._effective_module_type(spoke_id) == "agent":
                    skipped.append(f"{spoke_id}: no update_sources.agent repo_url")
            msg = "Skipped all agents: update_sources.agent not configured" if skipped else "No approved agents"
            logger.info(f"update_agents_only complete — {msg}")
            return {"status": "ok", "triggered": [], "skipped": skipped, "message": msg}

        for spoke_id, approved in self.approved_modules.items():
            if not approved:
                continue
            if self._effective_module_type(spoke_id) != "agent":
                continue
            err = await self._push_spoke_update(spoke_id, repo_url, branch,
                                                extra_data=core_extra)
            if err is None:
                triggered.append(spoke_id)
                logger.info(f"SPOKE_UPDATE queued for agent {spoke_id} ({repo_url}@{branch})")
            else:
                logger.error(f"Failed to queue SPOKE_UPDATE for agent {spoke_id}: {err}")
                skipped.append(f"{spoke_id}: mailbox error — {err}")

        summary = f"Triggered {len(triggered)} agent(s): {', '.join(triggered) or 'none'}"
        if skipped:
            summary += f". Skipped: {'; '.join(skipped)}"
        logger.info(f"update_agents_only complete — {summary}")
        return {"status": "ok", "triggered": triggered, "skipped": skipped, "message": summary}