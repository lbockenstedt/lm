"""Operator site extensions — optional, out-of-band plugin loader.

Some operators run private, deployment-specific modules alongside the hub that
should NOT live in this (public) application repo — bespoke integrations,
per-site automation, detection tripwires, and so on. This module is the small,
generic mechanism that lets the hub load such modules at startup:

  * ``provision(hub)`` — best-effort fetch of a private source repo into a hub-
    local directory (outside the git checkout so a self-update ``git reset
    --hard`` can't wipe it). Runs BEFORE the app is built.
  * ``load(app, hub, ctx)`` — imports every ``*.py`` in that directory that
    exposes ``register(app, hub, ctx)`` (the same convention the built-in route
    registrars use) and calls it while the app is being built.

Everything here is optional and fail-safe:

  * No source configured (or ``enabled`` false) → provisioning is skipped.
  * No token, or a Key-Vault token reference but no vault configured → the fetch
    is skipped and whatever is already present in the ext dir is still loaded.
  * A stock checkout with an empty ext dir → ``load`` is a no-op.

Nothing here assumes Azure; a self-hosted deployment with no vault and no
private source simply runs with zero extensions.

Config (``global_config['site_ext']``, operator-set, never committed):

    enabled  bool  master switch                                (default False)
    repo     str   https git URL of the private source repo
    ref      str   branch/tag to check out                      (default main)
    token    str   inline token, or ``kv:<secret-name>`` to read
                   it from Azure Key Vault (optional)
    dir      str   override the local ext dir                   (optional)
"""
from __future__ import annotations

import asyncio
import glob
import importlib.util
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")


def _cfg(hub) -> Dict[str, Any]:
    gc = hub.state.system_state.get("global_config", {}) or {}
    c = gc.get("site_ext", {}) or {}
    return c if isinstance(c, dict) else {}


def ext_dir(hub) -> str:
    """Local directory the extension modules live in. ``LM_EXT_DIR`` wins, then
    an explicit ``dir`` override, else ``<data_dir>/site_ext``."""
    return (os.environ.get("LM_EXT_DIR")
            or _cfg(hub).get("dir")
            or os.path.join(hub.state.data_dir, "site_ext"))


def _repo_url_with_token(repo: str, token: Optional[str]) -> str:
    """Inject a token into an https git URL as an ``x-access-token`` basic-auth
    credential. No token → the URL is returned unchanged (public/anon clone)."""
    if not token or not repo.startswith("https://"):
        return repo
    rest = repo[len("https://"):]
    # Drop any credentials already embedded in the URL.
    if "@" in rest.split("/", 1)[0]:
        rest = rest.split("@", 1)[1]
    return f"https://x-access-token:{token}@{rest}"


async def _git(*args: str, cwd: Optional[str] = None, timeout: float = 90.0) -> tuple[int, str]:
    """Run git with prompts disabled; return (rc, combined-output-tail)."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        return 124, "git timed out"
    return proc.returncode or 0, (out or b"").decode(errors="replace")[-500:]


async def provision(hub) -> None:
    """Fetch the configured private extension repo into the ext dir. Best-effort:
    logs and returns on any problem; NEVER raises into startup."""
    cfg = _cfg(hub)
    if not cfg.get("enabled") or not cfg.get("repo"):
        return
    repo = str(cfg["repo"]).strip()
    ref = str(cfg.get("ref") or "main").strip()
    dest = ext_dir(hub)

    token = None
    token_ref = cfg.get("token")
    if token_ref:
        try:
            import key_vault
            token = await key_vault.resolve_ref(hub, str(token_ref))
        except Exception as e:  # noqa: BLE001
            logger.debug("site extensions: token resolve failed: %s", e)
        if str(token_ref).startswith("kv:") and not token:
            # A vault reference that couldn't be resolved (no vault here / not
            # found). Don't fetch with a broken/anon credential for a private
            # source — just load whatever is already on disk.
            logger.info("site extensions: token unavailable — skipping fetch, "
                        "loading any modules already present")
            return

    url = _repo_url_with_token(repo, token)
    try:
        if os.path.isdir(os.path.join(dest, ".git")):
            rc, out = await _git("-C", dest, "remote", "set-url", "origin", url)
            rc, out = await _git("-C", dest, "fetch", "--depth", "1", "origin", ref)
            if rc == 0:
                rc, out = await _git("-C", dest, "reset", "--hard", f"origin/{ref}")
        else:
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            rc, out = await _git("clone", "--depth", "1", "--branch", ref, url, dest)
        if rc == 0:
            logger.info("site extensions: provisioned into %s", dest)
        else:
            logger.warning("site extensions: fetch failed (rc=%s): %s", rc, out)
    except Exception as e:  # noqa: BLE001
        logger.warning("site extensions: provisioning error: %s", e)


def load(app, hub, ctx) -> None:
    """Import every ``register(app, hub, ctx)`` module in the ext dir. Best-effort;
    a bad module is logged and skipped, never fatal."""
    d = ext_dir(hub)
    if not os.path.isdir(d):
        return
    n = 0
    for path in sorted(glob.glob(os.path.join(d, "*.py"))):
        base = os.path.splitext(os.path.basename(path))[0]
        if base.startswith("_"):
            continue
        name = "siteext_" + base
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            reg = getattr(mod, "register", None)
            if callable(reg):
                reg(app, hub, ctx)
                n += 1
        except Exception:  # noqa: BLE001
            logger.warning("site extension %s failed to load", os.path.basename(path),
                           exc_info=True)
    if n:
        logger.info("loaded %d site extension(s) from %s", n, d)
