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

# asyncio runs git; glob/importlib find and import extension modules.
import asyncio
import glob
import importlib.util
# logging for the hub log; os for paths/env; re redacts credentials; type hints only.
import logging
import os
import re
from typing import Any, Dict, Optional

# Log to the hub's logger.
logger = logging.getLogger("Hub")


def _cfg(hub) -> Dict[str, Any]:
    """Return the site_ext config block from global_config ({} if missing or not a dict)."""
    # global_config, then the site_ext block.
    gc = hub.state.system_state.get("global_config", {}) or {}
    c = gc.get("site_ext", {}) or {}
    # Only a dict is a usable config.
    return c if isinstance(c, dict) else {}


def ext_dir(hub) -> str:
    """Local directory the extension modules live in. ``LM_EXT_DIR`` wins, then
    an explicit ``dir`` override, else ``<data_dir>/site_ext``."""
    # Env var, then config override, then the default under data_dir.
    return (os.environ.get("LM_EXT_DIR")
            or _cfg(hub).get("dir")
            or os.path.join(hub.state.data_dir, "site_ext"))


def _repo_url_with_token(repo: str, token: Optional[str]) -> str:
    """Inject a token into an https git URL as an ``x-access-token`` basic-auth
    credential. No token → the URL is returned unchanged (public/anon clone)."""
    # No token or non-https URL: use it as is.
    if not token or not repo.startswith("https://"):
        return repo
    # Strip the scheme so the credential can be inserted.
    rest = repo[len("https://"):]
    # Drop any credentials already embedded in the URL.
    if "@" in rest.split("/", 1)[0]:
        rest = rest.split("@", 1)[1]
    # Rebuild with the token as basic-auth credentials.
    return f"https://x-access-token:{token}@{rest}"


async def _git(*args: str, cwd: Optional[str] = None, timeout: float = 90.0) -> tuple[int, str]:
    """Run git with prompts disabled; return (rc, combined-output-tail)."""
    # Copy the environment and stop git from prompting for credentials.
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    # Start git with stderr merged into stdout.
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    # Wait with a timeout; kill git and report rc 124 on timeout.
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        return 124, "git timed out"
    # Exit code and the last 500 characters of output.
    return proc.returncode or 0, (out or b"").decode(errors="replace")[-500:]


def _redact(text: str, token: Optional[str]) -> str:
    """Strip a credential out of git output before it is logged. Git echoes the
    remote URL in most failure messages, and the hub log is surfaced in the
    WebUI error feed — so an unredacted failure would publish the PAT."""
    # Replace the literal token, then any credentials embedded in https URLs.
    out = text or ""
    if token:
        out = out.replace(token, "***")
    return re.sub(r"(https://)[^/@\s]+@", r"\1***@", out)


async def provision(hub) -> Dict[str, Any]:
    """Fetch the configured private extension repo into the ext dir. Best-effort:
    logs and returns on any problem; NEVER raises into startup.

    Returns a ``{"ok", "reason", "detail"}`` result so an interactive caller can
    tell the operator WHAT went wrong. Startup ignores it, as before."""
    # Not enabled or no repo: nothing to fetch.
    cfg = _cfg(hub)
    if not cfg.get("enabled") or not cfg.get("repo"):
        return {"ok": False, "reason": "disabled",
                "detail": "extension source is disabled or has no repo configured"}
    # Repo URL, ref (default main), and local destination.
    repo = str(cfg["repo"]).strip()
    ref = str(cfg.get("ref") or "main").strip()
    dest = ext_dir(hub)

    # Checked before the token is resolved, so a refused source never causes a
    # vault read and never puts a credential on a command line for a repo this
    # install may not fetch in the first place.
    # Refuse repositories that may not be fetched.
    import repo_policy
    if repo_policy.is_forbidden(repo):
        logger.warning("site extensions: refusing configured source %s — %s",
                       repo, repo_policy.refuse_reason(repo))
        return {"ok": False, "reason": "forbidden_repo",
                "detail": repo_policy.refuse_reason(repo)}

    # Resolve the token (inline or a vault reference); failures only log.
    token = None
    token_ref = cfg.get("token")
    if token_ref:
        try:
            import cloud_vault
            token = await cloud_vault.resolve_ref(hub, str(token_ref))
        except Exception as e:  # noqa: BLE001
            logger.debug("site extensions: token resolve failed: %s", e)
        # A vault reference that did not resolve: skip the fetch.
        if str(token_ref).startswith("kv:") and not token:
            # A vault reference that couldn't be resolved (no vault here / not
            # found). Don't fetch with a broken/anon credential for a private
            # source — just load whatever is already on disk.
            logger.info("site extensions: token unavailable — skipping fetch, "
                        "loading any modules already present")
            return {"ok": False, "reason": "token_unavailable",
                    "detail": f"the vault secret {str(token_ref)[3:]!r} could not be read. "
                              "A newly saved secret can take a few seconds to become "
                              "readable — retry shortly. If it persists, check that a "
                              "cloud vault is enabled and the secret exists."}

    # Build the URL with the token, if any.
    url = _repo_url_with_token(repo, token)
    # Update an existing checkout or clone a new one; errors become a result.
    try:
        if os.path.isdir(os.path.join(dest, ".git")):
            # Pass the credentialed URL as a ONE-SHOT argument and reset to
            # FETCH_HEAD; never `remote set-url` it, so the token is not written
            # into .git/config.
            rc, out = await _git("-C", dest, "fetch", "--depth", "1", url, ref)
            if rc == 0:
                rc, out = await _git("-C", dest, "reset", "--hard", "FETCH_HEAD")
        # No checkout yet: make the parent dir and do a shallow clone of the ref.
        else:
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            rc, out = await _git("clone", "--depth", "1", "--branch", ref, url, dest)
        # Success: scrub the token from the stored remote and report ok.
        if rc == 0:
            # git clone persists the credentialed URL in .git/config — rewrite it
            # to the bare form immediately so the PAT is not left in plaintext on
            # disk. (The fetch path above never wrote it.)
            if token:
                await _git("-C", dest, "remote", "set-url", "origin", repo)
            logger.info("site extensions: provisioned into %s", dest)
            return {"ok": True, "reason": "", "detail": ""}
        # Failure: log redacted output and explain it.
        safe = _redact(out, token)
        logger.warning("site extensions: fetch failed (rc=%s): %s", rc, safe)
        return {"ok": False, "reason": "git_failed",
                "detail": _explain_git_failure(safe, ref)}
    # Unexpected error: log and report it redacted.
    except Exception as e:  # noqa: BLE001
        safe = _redact(str(e), token)
        logger.warning("site extensions: provisioning error: %s", safe)
        return {"ok": False, "reason": "error", "detail": safe}


def _explain_git_failure(output: str, ref: str) -> str:
    """Turn git's stderr into something an operator can act on. ``output`` is
    ALREADY redacted — never pass raw git output here."""
    # Match common failure texts (case-insensitive).
    low = (output or "").lower()
    if "authentication failed" in low or "could not read username" in low or "403" in low:
        return ("git rejected the credential — check the token is valid, not expired, "
                "and grants Contents: Read to this repository. " + output)
    # Not found (also what an unauthorised token looks like).
    if "repository not found" in low or "404" in low:
        return ("repository not found — with a private repo this is also what an "
                "unauthorised token looks like, so verify both the name and the "
                "token's repository access. " + output)
    # Missing branch or ref.
    if "remote branch" in low or "not found in upstream" in low or "couldn't find remote ref" in low:
        return f"branch/ref {ref!r} does not exist in the repository. {output}"
    # Network or DNS failure.
    if "could not resolve host" in low or "connection refused" in low or "timed out" in low:
        return "could not reach github.com — check egress/DNS from this host. " + output
    # Anything else: return git's output.
    return output or "git failed with no output"


def load(app, hub, ctx) -> None:
    """Import every ``register(app, hub, ctx)`` module in the ext dir. Best-effort;
    a bad module is logged and skipped, never fatal."""
    # No ext dir: nothing to load.
    d = ext_dir(hub)
    if not os.path.isdir(d):
        return
    # Count of modules registered.
    n = 0
    # Each top-level .py file, skipping names starting with "_".
    for path in sorted(glob.glob(os.path.join(d, "*.py"))):
        base = os.path.splitext(os.path.basename(path))[0]
        if base.startswith("_"):
            continue
        # Unique module name so extensions cannot shadow real modules.
        name = "siteext_" + base
        # Import the file and call its register(); a bad module is logged and skipped.
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
    # Log how many loaded.
    if n:
        logger.info("loaded %d site extension(s) from %s", n, d)
