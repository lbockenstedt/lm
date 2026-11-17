"""CPU inference role backed by a dedicated, loopback-only Ollama service."""

import asyncio
import ast
import http.client
import json
import re
import subprocess
from pathlib import Path

from core.src.base_spoke import BaseSpoke


MAX_PROMPT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
INFERENCE_TIMEOUT = 900
# Previously qualified release. New versions require explicit side-by-side qualification.
QUALIFIED_OLLAMA_VERSION = "0.40.16"
SERVICE = "lm-llm-ollama.service"
CATALOG = Path("/etc/lm/llm-models.json")


class RuntimeVersionMismatch(ValueError):
    """The loopback runtime is not the qualified release."""


def runtime_service(action):
    """Operate only the dedicated service, never the system's generic Ollama."""
    return subprocess.run(
        ["systemctl", action, SERVICE], check=False, timeout=20,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def ollama_request(path, body=None, timeout=3):
    """Read one bounded JSON reply without using HTTP proxies or redirects."""
    conn = http.client.HTTPConnection("127.0.0.1", 11438, timeout=timeout)
    try:
        conn.request(
            "GET" if body is None else "POST", path,
            body=None if body is None else json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        reply = conn.getresponse()
        if reply.status != 200:
            raise ValueError("Ollama returned an error status")
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
        self._job = None
        self._stopping = False
        self.control_plane = None
        self._reporter = None
        self._service_started = False
        self._startup = None

    def start_background_loops(self):
        """Start a reconnect-safe inventory reporter for this role."""
        if self._reporter is None:
            self._reporter = asyncio.create_task(self._report_status())

    async def _report_status(self):
        """Publish inventory periodically; workers remain unready before approval."""
        while not self._stopping:
            if self.control_plane is not None and self.control_plane.secret:
                await self.control_plane.send_to_hub("LLM_WORKER_STATUS", await self.get_status())
            await asyncio.sleep(30)

    async def _start_runtime(self):
        """Start the pre-provisioned service on an approved hub command."""
        if self._stopping:
            return {"status": "ERROR", "code": "busy"}
        if self._startup is None or self._startup.done():
            self._startup = asyncio.create_task(self._run_service_start())
        return await asyncio.shield(self._startup)

    async def _run_service_start(self):
        """Record the result even if the connection goes away during startup."""
        try:
            self._service_started = await asyncio.to_thread(runtime_service, "start")
        except (OSError, subprocess.TimeoutExpired):
            self._service_started = False
        return {"status": "SUCCESS"} if self._service_started else {
            "status": "ERROR", "code": "runtime_unavailable",
        }

    async def _available_models(self):
        """Intersect operator approvals with the runtime's installed digests."""
        catalog = self.config.get("models")
        if catalog is None:
            try:
                catalog = json.loads(await asyncio.to_thread(CATALOG.read_text, encoding="utf-8"))
            except FileNotFoundError:
                catalog = {}
        if not isinstance(catalog, dict) or not catalog:
            return {}
        version = await asyncio.to_thread(ollama_request, "/api/version")
        if version.get("version") != QUALIFIED_OLLAMA_VERSION:
            raise RuntimeVersionMismatch
        inventory = await asyncio.to_thread(ollama_request, "/api/tags")
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
        if not self._service_started:
            return {"status": "ERROR", "code": "runtime_not_started"}
        try:
            models = await self._available_models()
        except RuntimeVersionMismatch:
            return {"status": "ERROR", "code": "runtime_version_mismatch"}
        except (OSError, ValueError, http.client.HTTPException):
            return {"status": "ERROR", "code": "runtime_unavailable"}
        return {
            "status": "SUCCESS", "models": models,
            "available": bool(models) and self._job is None and not self._stopping,
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
        if (not isinstance(prompt, str) or not prompt.strip()
                or len(prompt.encode("utf-8", errors="replace")) > MAX_PROMPT_BYTES
                or not isinstance(model, str) or not isinstance(digest, str)
                or output_format not in ("text", "json", "python")):
            return {"status": "ERROR", "code": "invalid_request"}
        # Assign before the first await; a stale hub snapshot cannot overbook the VM.
        job = self._job = asyncio.create_task(self._complete(prompt, model, digest, output_format))
        job.add_done_callback(self._release)
        return await asyncio.shield(job)

    def _release(self, job):
        """Release the slot only when the actual inference task has finished."""
        if self._job is job:
            self._job = None

    async def _complete(self, prompt, model, digest, output_format):
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
            body = {"model": model, "prompt": prompt, "stream": False, "think": False,
                    "options": {"num_gpu": 0, "num_predict": 1024}}
            if model.split("/")[-1].casefold().startswith("gemma"):
                # Match the sampling caps that stopped unstable Gemma drafts in CLI trials.
                body["options"].update(temperature=0.7, top_p=0.8)
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
