"""Prepare owner-approved CPU candidates in the isolated test runtime."""

import asyncio
import http.client
import json
import logging
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

from agent.src.llm_install import PUBLIC_RUNTIME_VERSION, stage_public_runtime
from agent.src.llm_qualification import _run_with_service
from core.src.llm_candidates import CANDIDATES

logger = logging.getLogger("LLMSpoke")
CANDIDATE_RUNTIME = Path("/opt/lm-llm-candidate")
STATE = Path("/var/lib/lm-llm-agent/preparation.json")


def _check_state_directory(create=False):
    """Keep preparation journals in an owner-managed private directory."""
    parent = STATE.parent
    if parent.is_symlink():
        raise ValueError("LLM preparation directory cannot be a symlink")
    if create:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.exists() and (parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o077):
        raise ValueError("LLM preparation directory must be private and owner-managed")


def load_state():
    """Load one bounded, root-managed preparation journal."""
    _check_state_directory()
    try:
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        raw = source.read(16385)
    if len(raw) > 16384:
        raise ValueError("LLM preparation journal is too large")
    data = json.loads(raw)
    if (not isinstance(data, dict) or not isinstance(data.get("request_id"), str)
            or not re.fullmatch(r"[a-f0-9]{32}", data["request_id"])
            or type(data.get("revision")) is not int or not 1 <= data["revision"] < 2**53
            or not isinstance(data.get("candidate"), str) or data["candidate"] not in CANDIDATES
            or data.get("state") not in ("running", "passed", "failed")
            or (data["state"] != "running" and not isinstance(data.get("result"), dict))):
        raise ValueError("Invalid LLM preparation journal")
    return data


def save_state(data):
    """Persist one journal revision before acknowledging a preparation."""
    parent = STATE.parent
    _check_state_directory(create=True)
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    if len(payload) > 16384:
        raise ValueError("LLM preparation journal is too large")
    with tempfile.NamedTemporaryFile(dir=parent, delete=False) as output:
        path = Path(output.name)
        try:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    try:
        os.replace(path, STATE)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        path.unlink(missing_ok=True)


async def prepare(key, version, request, progress=None):
    """Stage the pinned runtime and smoke-test one pinned candidate on this CPU."""
    candidate = CANDIDATES.get(key) if isinstance(key, str) else None
    if candidate is None:
        return {"status": "ERROR", "code": "candidate_not_provisioned"}
    if version != PUBLIC_RUNTIME_VERSION:
        return {"status": "ERROR", "code": "runtime_version_mismatch"}
    try:
        if progress:
            progress("runtime")
        await asyncio.to_thread(stage_public_runtime, CANDIDATE_RUNTIME)
        artifact = (candidate["model"], candidate["digest"], version)
        spec = (artifact, None, candidate["options"], True)
        return await asyncio.to_thread(_run_with_service, key, request, {}, spec, progress)
    except (OSError, ValueError, tarfile.TarError, http.client.HTTPException, subprocess.TimeoutExpired) as exc:
        logger.warning("LLM candidate runtime provisioning failed: %s", exc)
        return {"status": "ERROR", "code": "candidate_runtime_install_failed"}
