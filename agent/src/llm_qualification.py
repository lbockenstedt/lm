"""Run synthetic CPU tests using an isolated, operator-staged Ollama service."""

import ast
import asyncio
import http.client
import json
import re
import subprocess
import time
from pathlib import Path


MANIFEST = Path("/etc/lm/llm-qualification.json")
# Loopback ports set by OLLAMA_HOST in lm-llm-candidate.service and lm-llm-ollama.service
# (llm_spoke.SERVING_PORT); private to the VM, so fixed rather than configured.
PORT = 11439
BASELINE_PORT = 11438
CANDIDATE_SERVICE = "lm-llm-candidate.service"
JSON_EXPECTED = {"items": [{"label": "CPU", "count": 2}]}
PYTHON_EXPECTED = "def classify(value):\n    if value > 0:\n        return 1\n    return 0\n"


def _candidate(key):
    """Resolve only local, operator-approved public model tags and exact pins."""
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key):
        return None
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    spec = manifest.get(key) if isinstance(manifest, dict) else None
    if not isinstance(spec, dict):
        return None
    candidate, baseline = _artifact(spec), _artifact(spec.get("baseline"))
    return (candidate, baseline) if candidate and baseline else None


def _artifact(spec):
    """Read an exact artifact identity without accepting registry URLs."""
    if not isinstance(spec, dict):
        return None
    model, digest, version = (spec.get(name) for name in ("model", "digest", "version"))
    if (not isinstance(model, str) or not re.fullmatch(r"[\w-]+(?:/[\w-]+)?:[\w.-]+", model, re.ASCII)
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version)):
        return None
    return model, digest, version


def _run_case(request, port, model, fixture, prompt):
    """Score exact semantics and capture timing without retaining generated text."""
    body = {"model": model, "prompt": prompt, "stream": False, "think": False,
            "keep_alive": 0, "options": {"num_gpu": 0, "num_predict": 256, "temperature": 0}}
    if fixture == "json":
        body["format"] = "json"
    started = time.monotonic()
    reply = request("/api/generate", body, 240, port=port)
    elapsed = time.monotonic() - started
    valid = reply.get("done") is True and reply.get("done_reason") == "stop" and reply.get("model") == model
    try:
        text = reply.get("response")
        passed = valid and isinstance(text, str) and (
            json.loads(text) == JSON_EXPECTED if fixture == "json"
            else ast.dump(ast.parse(text)) == ast.dump(ast.parse(PYTHON_EXPECTED))
        )
    except (SyntaxError, ValueError, RecursionError):
        passed = False
    return {"fixture": fixture, "passed": passed, "elapsed_s": round(elapsed, 3),
            **{key: reply[key] for key in ("load_duration", "eval_duration", "eval_count")
               if type(reply.get(key)) is int and 0 <= reply[key] < 2**53}}


def _installed(request, port, model, digest):
    """Verify the selected local artifact, rejecting remote-model redirects."""
    inventory = request("/api/tags", port=port).get("models")
    return isinstance(inventory, list) and any(
        isinstance(row, dict) and row.get("name") == model and row.get("digest") == digest
        and not row.get("remote_host") and not row.get("remote_model") for row in inventory)


def _suite(request, port, artifact):
    """Run the same cold-start fixtures on each CPU runtime."""
    model, digest, version = artifact
    fixtures = [
        _run_case(request, port, model, "json", "Return only this exact JSON object:\n" + json.dumps(JSON_EXPECTED)),
        _run_case(request, port, model, "indentation", "Return this exact Python text, without fences:\n" + PYTHON_EXPECTED),
    ]
    return {"model": model, "digest": digest, "version": version, "fixtures": fixtures}


def _run(key, request, approved_baseline, *, spec=None):
    """Use only the pre-provisioned candidate service and its separate store."""
    spec = spec or _candidate(key)
    if spec is None:
        return {"status": "ERROR", "code": "candidate_not_provisioned"}
    candidate, baseline = spec
    model, digest, version = candidate
    if (approved_baseline.get(baseline[0]) != baseline[1]
            or request("/api/version", port=BASELINE_PORT).get("version") != baseline[2]
            or not _installed(request, BASELINE_PORT, baseline[0], baseline[1])):
        return {"status": "ERROR", "code": "baseline_unavailable"}
    if request("/api/version", port=PORT).get("version") != version:
        return {"status": "ERROR", "code": "runtime_version_mismatch"}
    # Validate the artifact after download and before running any fixture.
    try:
        pulled = request("/api/pull", {"model": model, "stream": False}, 420, port=PORT)
    except (OSError, ValueError, http.client.HTTPException):
        return {"status": "ERROR", "code": "candidate_pull_failed"}
    if pulled.get("status") != "success":
        return {"status": "ERROR", "code": "candidate_pull_failed"}
    if not _installed(request, PORT, model, digest):
        return {"status": "ERROR", "code": "candidate_digest_mismatch"}
    # Nothing from a real job is provided to the candidate runtime.
    reference = _suite(request, BASELINE_PORT, baseline)
    result = _suite(request, PORT, candidate)
    code = ("baseline_fixture_mismatch" if not all(row["passed"] for row in reference["fixtures"])
            else "qualified" if all(row["passed"] for row in result["fixtures"])
            else "fixture_mismatch")
    return {**result, "baseline": reference,
            "status": "SUCCESS" if code == "qualified" else "ERROR", "code": code}


def _service(action):
    """Operate only the isolated qualification unit."""
    return subprocess.run(["systemctl", action, CANDIDATE_SERVICE], check=False, timeout=20,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _run_with_service(key, request, approved_baseline):
    """Start and stop the candidate service within the exclusive qualification job."""
    spec = _candidate(key)
    if spec is None:
        return {"status": "ERROR", "code": "candidate_not_provisioned"}
    try:
        if not _service("start") or not _service("is-active"):
            result = {"status": "ERROR", "code": "candidate_not_provisioned"}
        else:
            # Type=exec does not imply the HTTP listener is ready.
            for _ in range(10):
                try:
                    request("/api/version", timeout=1, port=PORT)
                    break
                except (OSError, ValueError, http.client.HTTPException):
                    time.sleep(0.5)
            else:
                return {"status": "ERROR", "code": "qualification_runtime_failed"}
            result = _run(key, request, approved_baseline, spec=spec)
    finally:
        stopped = _service("stop")
    return result if stopped else {"status": "ERROR", "code": "qualification_runtime_failed"}


async def qualify(key, request, available_models):
    """Run the comparison under the spoke's exclusive job slot."""
    try:
        return await asyncio.to_thread(_run_with_service, key, request, await available_models())
    except FileNotFoundError:
        return {"status": "ERROR", "code": "candidate_not_provisioned"}
    except (OSError, ValueError, http.client.HTTPException, subprocess.TimeoutExpired):
        return {"status": "ERROR", "code": "qualification_runtime_failed"}
