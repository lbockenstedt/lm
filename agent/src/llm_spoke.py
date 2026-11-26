"""CPU inference role backed by a dedicated, loopback-only Ollama service."""

import asyncio
import ast
import http.client
import json
import logging
import os
import platform
import re
import subprocess
import time
from pathlib import Path

from core.src.base_spoke import BaseSpoke
from agent.src.llm_install import PUBLIC_RUNTIME_VERSION
from agent.src.llm_options import SAMPLING_LIMITS, valid_sampling

# A fixed name: the agent loads this file as module lm_role_llm, and only a
# name under the llm role's "LLM" stem (_ROLE_LOG_PREFIXES) reaches the
# role's own log bucket on the hub.
logger = logging.getLogger("LLMSpoke")

MAX_PROMPT_BYTES = 192 * 1024  # keep equal to the hub limit in core/src/llm_pool.py
MAX_RESPONSE_BYTES = 256 * 1024
INFERENCE_TIMEOUT = 7200  # slow CPU models may take hours; speed does not matter
# Start from the owner's CLI pin; Linux CPU artifacts still need qualification.
DEFAULT_OLLAMA_VERSION = PUBLIC_RUNTIME_VERSION
SERVICE = "lm-llm-ollama.service"
SERVICE_UNIT_PATH = Path("/etc/systemd/system") / SERVICE
RUNTIME_BINARY_PATH = Path("/opt/lm-llm/bin/ollama")
# Loopback-only port of SERVICE (its OLLAMA_HOST). Fixed, not a setting: it never leaves
# the VM, and staying off Ollama's 11434 means a system Ollama can't be mistaken for ours.
SERVING_PORT = 11438
ACTIVATION_READY_S = 120
CATALOG = Path("/etc/lm/llm-models.json")
BUNDLE_CATALOG = Path("/opt/lm-llm/llm-models.json")


class RuntimeVersionMismatch(ValueError):
    """The loopback runtime is not the qualified release."""


def cpu_capabilities():
    """Measure guest hardware, not host hardware or model memory usage."""
    result = {"mode": "cpu", "arch": platform.machine()}
    count = os.cpu_count()
    if count:
        result["vcpus"] = count
    try:
        pages, page_size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            result["ram_bytes"] = pages * page_size
        with Path("/proc/cpuinfo").open(encoding="utf-8", errors="replace") as cpuinfo:
            for line in cpuinfo:
                name, _, value = line.partition(":")
                if name.strip() in ("model name", "Hardware") and value.strip():
                    result["cpu_model"] = value.strip()[:160]
                    break
    except (OSError, ValueError):
        # An unavailable metric is unknown, never zero or assumed capacity.
        pass
    return result


def runtime_service(action):
    """Operate only the dedicated service, never the system's generic Ollama."""
    return subprocess.run(
        ["systemctl", action, SERVICE], check=False, timeout=20,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def runtime_failure_code():
    """Classify a failed start without returning raw systemd output.

    The missing codes mean nothing exists at the path, which unit staging or
    the offline bundle repairs. A path that exists but is unusable (a
    directory in place of the unit, a binary without execute permission) is
    ``runtime_start_failed``: staging never overwrites an existing entry, so
    "stage the unit" or "install the bundle" would be the wrong remediation.
    """
    if SERVICE_UNIT_PATH.is_symlink() and not SERVICE_UNIT_PATH.is_file():
        return "runtime_unit_symlink"
    if not SERVICE_UNIT_PATH.exists():
        return "runtime_unit_missing"
    if not RUNTIME_BINARY_PATH.exists():
        return "runtime_binary_missing"
    return "runtime_start_failed"


def ollama_request(path, body=None, timeout=3, *, port=SERVING_PORT):
    """Read one bounded JSON reply without using HTTP proxies or redirects."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(
            "GET" if body is None else "POST", path,
            body=None if body is None else json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        reply = conn.getresponse()
        if reply.status != 200:
            # Ollama explains a 5xx in a small JSON body; keep a bounded, single-line copy for the log.
            detail = reply.read(300).decode("utf-8", "replace").replace("\n", " ").strip()
            raise ValueError(f"Ollama returned an error status: {reply.status} for {path}: {detail}")
        content = reply.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("Ollama response exceeds the size limit")
        if reply.length:
            raise http.client.IncompleteRead(content, reply.length)
        data = json.loads(content.decode("utf-8"))
        if not isinstance(data, dict) or "error" in data:
            raise ValueError("Ollama returned an invalid response")
        return data
    finally:
        conn.close()


class LlmSpoke(BaseSpoke):
    """Serve only pinned local models, with one active inference per VM."""

    def __init__(self, spoke_id, config):
        """Initialize the approved catalog and the local inference slot."""
        super().__init__(spoke_id, config)
        # A local operator changes this pin after qualification, never a hub job.
        self._runtime_version = os.environ.get("LM_LLM_OLLAMA_VERSION", DEFAULT_OLLAMA_VERSION)
        self._job = None
        self._preparation_job = None
        self._provision_phase = None
        self._preparation = None
        self._preparation_load = None
        self._stopping = False
        self.control_plane = None
        self._reporter = None
        self._service_started = False
        self._runtime_issue = None
        self._startup = None
        self._health_failures = 0
        self._last_recovery = float("-inf")

    def start_background_loops(self):
        """Start a reconnect-safe inventory reporter for this role."""
        if self._reporter is None:
            self._reporter = asyncio.create_task(self._report_status())
        if self._preparation_load is None:
            self._preparation_load = asyncio.create_task(self._load_preparation())

    async def _load_preparation(self):
        """Restore an interrupted preparation for an authorized hub retry."""
        from agent.src.llm_provisioning import load_state
        try:
            self._preparation = await asyncio.to_thread(load_state)
        except (OSError, ValueError) as exc:
            logger.error("LLM preparation journal cannot be read: %s", exc)
            return False
        return True

    def _start_preparation(self):
        """Reserve the worker slot before a preparation can start."""
        job = self._preparation_job = self._job = asyncio.create_task(self._run_preparation())
        job.add_done_callback(self._release)
        return job

    async def _run_preparation(self):
        """Persist the request and its terminal result around the synthetic job."""
        from agent.src.llm_provisioning import prepare, save_state
        state = self._preparation
        loop = asyncio.get_running_loop()
        job = asyncio.current_task()

        def progress(phase):
            """Publish phase changes only for the current preparation."""
            def apply():
                """Ignore delayed updates from an already finished job."""
                if self._job is job:
                    self._provision_phase = phase
            loop.call_soon_threadsafe(apply)

        try:
            await asyncio.to_thread(save_state, state)
            result = await prepare(state["candidate"], self._runtime_version, ollama_request, progress)
            final = {**state, "state": "passed" if result.get("status") == "SUCCESS" else "failed",
                     "result": result}
            await asyncio.to_thread(save_state, final)
            self._preparation = final
            return result
        except (OSError, ValueError) as exc:
            logger.error("LLM preparation journal could not be saved: %s", exc)
            return {"status": "ERROR", "code": "preparation_state_failed"}

    async def _activate_candidate(self, candidate):
        """Publish a smoke-tested candidate and verify the serving inventory."""
        from agent.src.llm_activation import finalize, prune_candidate, publish, rollback
        from agent.src.llm_install import PUBLIC_RUNTIME
        from agent.src.llm_qualification import _installed
        release = PUBLIC_RUNTIME.get(platform.machine())
        if release is None or self._runtime_version != PUBLIC_RUNTIME_VERSION:
            return {"status": "ERROR", "code": "runtime_version_mismatch"}
        if self.config.get("models") is not None:
            return {"status": "ERROR", "code": "operator_catalog_override"}
        record, start_attempted = None, False
        try:
            record = await asyncio.to_thread(publish, candidate, release["sha256"])
            if record["created"] and self._service_started:
                raise ValueError("Serving service is running without a managed runtime")
            if not self._service_started:
                start_attempted = True
                if not await asyncio.to_thread(runtime_service, "start"):
                    raise ValueError("Serving service failed to start")
                self._service_started = True
            # systemd Type=exec can report started before the API listens.
            # A freshly started Ollama can answer 5xx or stall while it scans a large store,
            # so allow it ACTIVATION_READY_S before giving up and rolling back.
            deadline = time.monotonic() + ACTIVATION_READY_S
            while True:
                try:
                    version = await asyncio.to_thread(ollama_request, "/api/version")
                    if version.get("version") != self._runtime_version:
                        raise RuntimeVersionMismatch
                    if await asyncio.to_thread(_installed, ollama_request, SERVING_PORT,
                                               candidate["model"], candidate["digest"]):
                        break
                except (OSError, ValueError, http.client.HTTPException) as exc:
                    if time.monotonic() >= deadline:
                        raise
                    logger.info("LLM serving runtime not ready yet: %s", exc)
                else:
                    if time.monotonic() >= deadline:
                        raise ValueError("Published model is not present in the serving inventory")
                await asyncio.sleep(1)
            await asyncio.to_thread(finalize, record)
            models = await self._available_models()
            if models.get(candidate["model"]) != candidate["digest"]:
                raise ValueError("Published model is not approved by the serving catalog")
            # Approved: the serving store has its own copy, so free the candidate's.
            # Best effort and outside the failure path, so it can never trigger rollback.
            try:
                await asyncio.to_thread(prune_candidate, candidate)
            except Exception as exc:  # best effort: activation is already committed
                logger.warning("LLM candidate prune failed: %s", exc)
            return {"status": "SUCCESS", "code": "activated",
                    "model": candidate["model"], "digest": candidate["digest"]}
        except (OSError, ValueError, http.client.HTTPException, subprocess.TimeoutExpired) as exc:
            logger.warning("LLM candidate activation failed: %s", exc)
            try:
                if start_attempted:
                    if not await asyncio.to_thread(runtime_service, "stop"):
                        raise ValueError("Serving service could not be stopped")
                    self._service_started = False
                if record is not None:
                    await asyncio.to_thread(rollback, record)
            except (OSError, ValueError, subprocess.TimeoutExpired) as rollback_exc:
                logger.error("LLM candidate activation rollback failed: %s", rollback_exc)
                return {"status": "ERROR", "code": "activation_rollback_failed"}
            return {"status": "ERROR", "code": "activation_failed"}

    async def _report_status(self):
        """Publish inventory periodically; workers remain unready before approval."""
        while not self._stopping:
            if self.control_plane is not None and self.control_plane.secret:
                await self._recover_idle_runtime()
                await self.control_plane.send_to_hub("LLM_WORKER_STATUS", await self.get_status())
            await asyncio.sleep(30)

    async def _start_runtime(self):
        """Start the pre-provisioned service on an approved hub command."""
        if self._stopping or self._job is not None:
            return {"status": "ERROR", "code": "busy"}
        if self._startup is None or self._startup.done():
            self._startup = asyncio.create_task(self._run_service_start("start"))
        return await asyncio.shield(self._startup)

    async def _run_service_start(self, action):
        """Record the result even if the connection goes away during startup."""
        try:
            self._service_started = await asyncio.to_thread(runtime_service, action)
        except (OSError, subprocess.TimeoutExpired):
            self._service_started = False
        if not self._service_started:
            self._runtime_issue = await asyncio.to_thread(runtime_failure_code)
            logger.warning("LLM runtime %s failed: %s", action, self._runtime_issue)
            return {"status": "ERROR", "code": self._runtime_issue}
        self._runtime_issue = None
        logger.info("LLM runtime %s succeeded", action)
        return {"status": "SUCCESS"}

    async def _recover_idle_runtime(self):
        """Restart only an idle, previously started runtime after repeated API failures."""
        if (not self._service_started or self._stopping or self._job is not None
                or (self._startup is not None and not self._startup.done())):
            self._health_failures = 0
            return
        try:
            await asyncio.to_thread(ollama_request, "/api/version")
        except (OSError, ValueError, http.client.HTTPException):
            self._health_failures += 1
        else:
            self._health_failures = 0
        # Recheck after the probe: a completion may have taken the slot.
        if (self._health_failures >= 3 and self._job is None and not self._stopping
                and (self._startup is None or self._startup.done())
                and time.monotonic() - self._last_recovery >= 300):
            self._last_recovery = time.monotonic()
            self._health_failures = 0
            self._startup = asyncio.create_task(self._run_service_start("restart"))
            await asyncio.shield(self._startup)

    async def _available_models(self):
        """Intersect operator approvals with the runtime's installed digests."""
        version = await asyncio.to_thread(ollama_request, "/api/version")
        if (not re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,5}){2}", self._runtime_version)
                or version.get("version") != self._runtime_version):
            raise RuntimeVersionMismatch

        # Read the approved digest catalog before querying installed artifacts.
        catalog = self.config.get("models")
        if catalog is None:
            try:
                catalog = json.loads(await asyncio.to_thread(CATALOG.read_text, encoding="utf-8"))
            except FileNotFoundError:
                try:
                    catalog = json.loads(await asyncio.to_thread(BUNDLE_CATALOG.read_text, encoding="utf-8"))
                except FileNotFoundError:
                    catalog = {}
        if not isinstance(catalog, dict) or not catalog:
            return {}
        inventory = await asyncio.to_thread(ollama_request, "/api/tags", timeout=120)
        rows = inventory.get("models")
        if not isinstance(rows, list):
            raise ValueError("Invalid Ollama inventory")
        return {
            name: digest
            for row in rows
            if isinstance(row, dict)
            and isinstance(name := row.get("name"), str)
            and not row.get("remote_host")
            and not row.get("remote_model")
            and isinstance(digest := row.get("digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", digest)
            and catalog.get(name) == digest
        }

    async def get_status(self):
        """Report matching local models and capacity without returning any content."""
        hardware = {"capabilities": await asyncio.to_thread(cpu_capabilities),
                    **({"provision_phase": self._provision_phase} if self._provision_phase else {}),
                    **({"preparation": self._preparation} if self._preparation else {})}
        if not self._service_started:
            if self._runtime_issue is not None:
                self._runtime_issue = await asyncio.to_thread(runtime_failure_code)
            return {"status": "ERROR",
                    "code": "runtime_not_started",
                    **({"detail_code": self._runtime_issue} if self._runtime_issue else {}),
                    **hardware}
        try:
            models = await self._available_models()
        except RuntimeVersionMismatch:
            return {"status": "ERROR", "code": "runtime_version_mismatch", **hardware}
        except (OSError, ValueError, http.client.HTTPException):
            return {"status": "ERROR", "code": "runtime_unavailable", **hardware}
        return {
            "status": "SUCCESS", "models": models, "version": self._runtime_version,
            "available": bool(models) and self._job is None and not self._stopping,
            "supported_options": sorted(SAMPLING_LIMITS),
            **hardware,
        }

    def stop_background_loops(self):
        """Reject new work and let the role shutdown hook drain the current job."""
        self._stopping = True
        return asyncio.create_task(self._drain())

    async def _drain(self):
        """Stop reporting and wait for the in-flight completion."""
        if self._reporter is not None:
            self._reporter.cancel()
            await asyncio.gather(self._reporter, return_exceptions=True)
        if self._preparation_load is not None:
            await asyncio.shield(self._preparation_load)
        if self._job is not None:
            await asyncio.shield(self._job)
        if self._startup is not None:
            await asyncio.shield(self._startup)
        if self._service_started:
            await asyncio.to_thread(runtime_service, "stop")

    async def handle_command(self, command_type, data):
        """Run a completion or return an explicit refusal before accepting it."""
        if command_type == "LLM_GET_STATUS":
            return await self.get_status()
        if command_type == "LLM_START_RUNTIME":
            return await self._start_runtime()
        if command_type in ("LLM_COMPLETE", "LLM_QUALIFY", "LLM_PREPARE", "LLM_ACTIVATE") and self._startup and not self._startup.done():
            return {"status": "ERROR", "code": "busy"}
        if command_type == "LLM_PREPARE":
            from core.src.llm_candidates import CANDIDATES
            key, request_id, revision = (data.get(name) for name in ("candidate", "request_id", "revision"))
            if (not isinstance(key, str) or key not in CANDIDATES
                    or not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id)
                    or type(revision) is not int or not 1 <= revision < 2**53):
                return {"status": "ERROR", "code": "invalid_request"}
            if self._preparation_load is None:
                self._preparation_load = asyncio.create_task(self._load_preparation())
            if not await asyncio.shield(self._preparation_load):
                return {"status": "ERROR", "code": "preparation_state_failed"}
            current = self._preparation
            if current and (revision < current["revision"]
                            or (revision == current["revision"] and request_id != current["request_id"])):
                return {"status": "ERROR", "code": "preparation_superseded"}
            if current and current["request_id"] == request_id:
                if current["candidate"] != key or current["revision"] != revision:
                    return {"status": "ERROR", "code": "invalid_request"}
                if current["state"] != "running":
                    return current["result"]
                if self._preparation_job is not None:
                    return await asyncio.shield(self._preparation_job)
            if self._stopping or self._job is not None:
                return {"status": "ERROR", "code": "busy"}
            self._preparation = {"request_id": request_id, "candidate": key, "revision": revision, "state": "running"}
            job = self._start_preparation()
            return await asyncio.shield(job)
        if command_type == "LLM_ACTIVATE":
            from core.src.llm_candidates import CANDIDATES
            key = data.get("candidate")
            if not isinstance(key, str) or key not in CANDIDATES:
                return {"status": "ERROR", "code": "invalid_request"}
            if self._preparation_load is None:
                self._preparation_load = asyncio.create_task(self._load_preparation())
            if not await asyncio.shield(self._preparation_load):
                return {"status": "ERROR", "code": "preparation_state_failed"}
            state = self._preparation
            result = state.get("result") if isinstance(state, dict) else None
            candidate = CANDIDATES[key]
            if (not state or state.get("candidate") != key or state.get("state") != "passed"
                    or not isinstance(result, dict) or result.get("code") != "bootstrap_smoke_passed"
                    or result.get("model") != candidate["model"] or result.get("digest") != candidate["digest"]
                    or result.get("options") != candidate["options"]):
                return {"status": "ERROR", "code": "candidate_not_smoke_tested"}
            if (self._stopping or self._job is not None
                    or (self._startup is not None and not self._startup.done())):
                return {"status": "ERROR", "code": "busy"}
            job = self._job = asyncio.create_task(self._activate_candidate(candidate))
            job.add_done_callback(self._release)
            return await asyncio.shield(job)
        if command_type == "LLM_QUALIFY":
            from agent.src.llm_qualification import qualify
            if self._stopping or self._job is not None:
                return {"status": "ERROR", "code": "busy"}
            job = self._job = asyncio.create_task(
                qualify(data.get("candidate"), ollama_request, self._available_models, self._service_started))
            job.add_done_callback(self._release)
            return await asyncio.shield(job)
        if command_type == "GET_VERSION":
            return {"status": "SUCCESS", "version": await asyncio.to_thread(
                lambda: (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip())}
        if command_type != "LLM_COMPLETE":
            return {"status": "ERROR", "code": "unsupported_command"}
        if self._stopping or self._job is not None:
            return {"status": "ERROR", "code": "busy"}
        if not self._service_started:
            return {"status": "ERROR", "code": "runtime_unavailable"}
        prompt, model, digest = (data.get(key) for key in ("prompt", "model", "digest"))
        output_format = data.get("format", "text")
        sampling = data.get("options", {})
        if (not isinstance(prompt, str) or not prompt.strip()
                or len(prompt.encode("utf-8", errors="replace")) > MAX_PROMPT_BYTES
                or not isinstance(model, str) or not isinstance(digest, str)
                or output_format not in ("text", "json", "python")
                or not valid_sampling(sampling)):
            return {"status": "ERROR", "code": "invalid_request"}
        # Assign before the first await; a stale hub snapshot cannot overbook the VM.
        job = self._job = asyncio.create_task(
            self._complete(prompt, model, digest, output_format, sampling))
        job.add_done_callback(self._release)
        return await asyncio.shield(job)

    def _release(self, job):
        """Release the slot only when the actual inference task has finished."""
        if self._job is job:
            self._job = None
            if self._preparation_job is job:
                self._preparation_job = None
            self._provision_phase = None

    async def _complete(self, prompt, model, digest, output_format, sampling=None):
        """Recheck the pinned model immediately before calling local inference."""
        try:
            # An inventory failure is retryable: no prompt was dispatched.
            installed = await self._available_models()
        except RuntimeVersionMismatch:
            return {"status": "ERROR", "code": "runtime_version_mismatch"}
        except (OSError, ValueError, http.client.HTTPException):
            return {"status": "ERROR", "code": "runtime_unavailable"}
        if installed.get(model) != digest:
            return {"status": "ERROR", "code": "model_unavailable"}
        try:
            # CPU only, no tools, one bounded response, then normal idle eviction.
            # Sampling comes only from the hub task profile, never from the model name.
            body = {"model": model, "prompt": prompt, "stream": False, "think": False,
                    "options": {**(sampling or {}), "num_gpu": 0, "num_predict": 1024}}
            if output_format == "json":
                body["format"] = "json"
            result = await asyncio.to_thread(ollama_request, "/api/generate", body, INFERENCE_TIMEOUT)
        except TimeoutError:
            return {"status": "ERROR", "code": "inference_timeout"}
        except (UnicodeError, json.JSONDecodeError, http.client.IncompleteRead):
            return {"status": "ERROR", "code": "invalid_response"}
        except (OSError, ValueError, http.client.HTTPException):
            return {"status": "ERROR", "code": "inference_failed"}
        if result.get("done_reason") == "length":
            return {"status": "ERROR", "code": "truncated_response"}
        text = result.get("response")
        if (result.get("done") is not True or result.get("done_reason") != "stop"
                or result.get("model") != model or not isinstance(text, str)
                or not text.strip() or "\ufffd" in text
                or any(0xD800 <= ord(char) <= 0xDFFF for char in text)):
            return {"status": "ERROR", "code": "invalid_response"}
        if output_format == "json":
            try:
                structured = json.loads(text)
            except (ValueError, RecursionError):
                return {"status": "ERROR", "code": "invalid_response"}
            if not isinstance(structured, (list, dict)):
                return {"status": "ERROR", "code": "invalid_response"}
        elif output_format == "python":
            try:
                # Validate complete Python drafts without executing generated code.
                ast.parse(text)
            except (SyntaxError, ValueError, RecursionError):
                return {"status": "ERROR", "code": "invalid_python"}
        metrics = {key: result[key] for key in (
            "load_duration", "prompt_eval_duration", "eval_duration", "eval_count",
        ) if type(result.get(key)) is int and 0 <= result[key] < 2**53}
        return {"status": "SUCCESS", "text": text, "metrics": metrics}
