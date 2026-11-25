"""Run synthetic CPU tests using an isolated, operator-staged Ollama service."""

import ast
import asyncio
import http.client
import json
import re
import subprocess
import time
from pathlib import Path

from agent.src.llm_options import valid_sampling


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
    options = spec.get("options")
    bootstrap = spec.get("bootstrap", False)
    if (type(bootstrap) is not bool or not candidate
            or (bootstrap and ("baseline" in spec or not isinstance(options, dict) or "num_ctx" not in options))
            or (not bootstrap and not baseline)
            or (options is not None and not valid_sampling(options))):
        return None
    return candidate, baseline, options, bootstrap


def _artifact(spec):
    """Read an exact artifact identity without accepting registry URLs."""
    if not isinstance(spec, dict):
        return None
    model, digest, version = (spec.get(name) for name in ("model", "digest", "version"))
    if (not isinstance(model, str) or len(model) > 200
            or not re.fullmatch(r"(?:[\w-]+/)?[\w-][\w.-]*:[\w.-]+", model, re.ASCII)
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version)):
        return None
    return model, digest, version


_THINK = re.compile(r"\A\s*<think>.*?</think>\s*", re.DOTALL)
_FENCE = re.compile(r"\A\s*```[\w+-]*\n(.*?)\n?```\s*\Z", re.DOTALL)


def _unwrap(text):
    """Drop a leading reasoning block and one surrounding code fence; the answer itself is untouched."""
    if not isinstance(text, str):
        return text
    text = _THINK.sub("", text, count=1)
    fenced = _FENCE.match(text)
    return fenced.group(1) if fenced else text


def _shape(text):
    """Name the wrapper around a reply (never its content) so a failed fixture can be diagnosed."""
    if not isinstance(text, str):
        return "no_text"
    if not text.strip():
        return "empty"
    if text.lstrip().startswith("<think>"):
        return "think_block"
    if "```" in text:
        return "code_fence"
    return "plain"


def _run_case(request, port, model, fixture, prompt, options=None):
    """Score exact semantics and capture timing without retaining generated text."""
    profile = {"num_predict": 1024, **options} if options is not None else {
        "num_predict": 256, "temperature": 0}
    body = {"model": model, "prompt": prompt, "stream": False, "think": False,
            "keep_alive": 0, "options": {**profile, "num_gpu": 0}}
    if fixture == "json":
        body["format"] = "json"
    started = time.monotonic()
    reply = request("/api/generate", body, 3600 if options is not None else 240, port=port)
    elapsed = time.monotonic() - started
    valid = reply.get("done") is True and reply.get("done_reason") == "stop" and reply.get("model") == model
    raw = reply.get("response")
    shape = _shape(raw)
    text = _unwrap(raw)
    try:
        passed = valid and isinstance(text, str) and (
            json.loads(text) == JSON_EXPECTED if fixture == "json"
            else ast.dump(ast.parse(text)) == ast.dump(ast.parse(PYTHON_EXPECTED))
        )
    except (SyntaxError, ValueError, RecursionError):
        passed = False
    # done_reason ("length" means the model ran out of tokens, e.g. while reasoning) explains a fail.
    reason = reply.get("done_reason")
    return {"fixture": fixture, "passed": passed, "elapsed_s": round(elapsed, 3),
            **({"done_reason": reason} if reason in ("stop", "length", "load", "unload") else {}),
            **({"shape": shape} if not passed else {}),
            **{key: reply[key] for key in ("load_duration", "eval_duration", "eval_count")
               if type(reply.get(key)) is int and 0 <= reply[key] < 2**53}}


def _installed(request, port, model, digest):
    """Verify the selected local artifact, rejecting remote-model redirects."""
    # A freshly pulled multi-GB model can keep Ollama busy well past the default 3 s.
    inventory = request("/api/tags", timeout=120, port=port).get("models")
    return isinstance(inventory, list) and any(
        isinstance(row, dict) and row.get("name") == model and row.get("digest") == digest
        and not row.get("remote_host") and not row.get("remote_model") for row in inventory)


def _suite(request, port, artifact, options=None):
    """Run the same cold-start fixtures on each CPU runtime."""
    model, digest, version = artifact
    fixtures = [
        _run_case(request, port, model, "json", "Return only this exact JSON object:\n" + json.dumps(JSON_EXPECTED), options),
        _run_case(request, port, model, "indentation", "Return this exact Python text, without fences:\n" + PYTHON_EXPECTED, options),
    ]
    return {"model": model, "digest": digest, "version": version, "fixtures": fixtures}


def _run(key, request, approved_baseline, *, spec=None, progress=None):
    """Use only the pre-provisioned candidate service and its separate store."""
    spec = spec or _candidate(key)
    if spec is None:
        return {"status": "ERROR", "code": "candidate_not_provisioned"}
    candidate, baseline, options, bootstrap = spec
    model, digest, version = candidate
    if not bootstrap and (approved_baseline.get(baseline[0]) != baseline[1]
            or request("/api/version", port=BASELINE_PORT).get("version") != baseline[2]
            or not _installed(request, BASELINE_PORT, baseline[0], baseline[1])):
        return {"status": "ERROR", "code": "baseline_unavailable"}
    if request("/api/version", port=PORT).get("version") != version:
        return {"status": "ERROR", "code": "runtime_version_mismatch"}
    # Validate the artifact after download and before running any fixture.
    if progress:
        progress("pull")
    try:
        pulled = request("/api/pull", {"model": model, "stream": False}, 7200, port=PORT)
    except (OSError, ValueError, http.client.HTTPException):
        return {"status": "ERROR", "code": "candidate_pull_failed"}
    if pulled.get("status") != "success":
        return {"status": "ERROR", "code": "candidate_pull_failed"}
    if not _installed(request, PORT, model, digest):
        return {"status": "ERROR", "code": "candidate_digest_mismatch"}
    # Nothing from a real job is provided to the candidate runtime.
    if progress:
        progress("fixtures")
    reference = None if bootstrap else _suite(request, BASELINE_PORT, baseline, options)
    result = _suite(request, PORT, candidate, options)
    if bootstrap:
        passed = all(row["passed"] for row in result["fixtures"])
        return {**result, "mode": "bootstrap", "options": options,
                "status": "SUCCESS" if passed else "ERROR",
                "code": "bootstrap_smoke_passed" if passed else "fixture_mismatch"}
    code = ("baseline_fixture_mismatch" if not all(row["passed"] for row in reference["fixtures"])
            else "qualified" if all(row["passed"] for row in result["fixtures"])
            else "fixture_mismatch")
    return {**result, "baseline": reference, **({"options": options} if options is not None else {}),
            "status": "SUCCESS" if code == "qualified" else "ERROR", "code": code}


def _service(action):
    """Operate only the isolated qualification unit."""
    return subprocess.run(["systemctl", action, CANDIDATE_SERVICE], check=False, timeout=20,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _run_with_service(key, request, approved_baseline, spec, progress=None):
    """Start and stop the candidate service within the exclusive qualification job."""
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
            result = _run(key, request, approved_baseline, spec=spec, progress=progress)
    finally:
        stopped = _service("stop")
    return result if stopped else {"status": "ERROR", "code": "qualification_runtime_failed"}


async def qualify(key, request, available_models, runtime_started):
    """Run the comparison under the spoke's exclusive job slot."""
    try:
        spec = await asyncio.to_thread(_candidate, key)
        if spec is None:
            return {"status": "ERROR", "code": "candidate_not_provisioned"}
        if not spec[3] and not runtime_started:
            return {"status": "ERROR", "code": "baseline_unavailable"}
        approved = {} if spec[3] else await available_models()
        return await asyncio.to_thread(_run_with_service, key, request, approved, spec)
    except FileNotFoundError:
        return {"status": "ERROR", "code": "candidate_not_provisioned"}
    except (OSError, ValueError, http.client.HTTPException, subprocess.TimeoutExpired):
        return {"status": "ERROR", "code": "qualification_runtime_failed"}
