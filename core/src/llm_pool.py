"""Tenant-scoped, live-only routing to approved inference workers."""

import asyncio
import re
import time
from collections.abc import Mapping

from access import same_tenant, tenant_is_shared
import instance_vault
import llm_cloud


REMEDIATION = {
    "runtime_unavailable": "Check the local-only Ollama service and its loopback listener.",
    "runtime_not_started": "Provision the dedicated Ollama service on the worker VM.",
    "runtime_version_mismatch": (
        "Use the pinned release, or check open regressions and qualify a candidate "
        "side by side on a spare port before changing the pin."
    ),
    "inference_timeout": (
        "Check cold-load, prompt and generation time on the CPU VM. Keep thinking "
        "disabled, send a smaller prompt, or qualify a smaller approved model."
    ),
    "slow_cpu_inference": (
        "The reply passed validation. Compare load, prompt and generation timings; "
        "if throughput matters, shorten the prompt or qualify a smaller CPU model."
    ),
    "truncated_response": "Split the work into smaller requests with shorter expected outputs.",
    "invalid_response": (
        "Replay a synthetic JSON or indentation fixture via the native non-streaming "
        "API with thinking disabled. If reproducible, compare a known-good runtime "
        "and check open regressions before upgrading."
    ),
    "invalid_python": (
        "Ask for one complete Python file without Markdown fences. Replay an "
        "indentation fixture; if it still fails, compare the known-good Ollama release."
    ),
    "fixture_mismatch": (
        "The model returned valid syntax but changed the expected content. "
        "Confirm the request format and compare a known-good model and runtime on a spare port."
    ),
    "inference_failed": "Check Ollama service health and VM memory pressure.",
    "no_matching_models": "Verify the approved model name and digest match the local inventory.",
    "no_capacity": "Retry locally when an eligible worker frees up; do not silently use cloud.",
    "cloud_invalid_endpoint": "Check the configured cloud HTTPS endpoint.",
    "cloud_rate_limit": "Retry later or check the provider's rate limit.",
    "cloud_provider_failed": "Check the provider status and the configured Vault credential.",
    "cloud_timeout": "Check the provider status; do not automatically resubmit an ambiguous request.",
}


def diagnostic(code):
    """Return a stable issue code and operator guidance, never raw runtime output."""
    return {"code": code, "resolution": REMEDIATION[code]}


def valid_model(model, digest):
    """Check the wire representation of an exact model artifact."""
    return (isinstance(model, str) and 0 < len(model) <= 200
            and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest))


class LlmPool:
    """Keep only volatile worker metadata and in-flight reservations."""

    def __init__(self, hub):
        """Bind the pool to the authoritative spoke and approval registry."""
        self.hub = hub
        self.inventory = {}
        self.worker_issues = {}
        self.start_attempts = {}
        self.cloud_busy = set()
        self.cloud_cooldown = {}
        self.reserved = set()
        self.sequence = 0

    def report(self, key, websocket, data):
        """Accept bounded catalog metadata only from the current approved socket."""
        hub = self.hub
        if (hub.spoke_module_types.get(key) != "llm"
                or not hub.approved_modules.get(key)
                or hub.active_connections.get(key) is not websocket
                or not isinstance(data, dict)):
            return
        models = data.get("models")
        if (data.get("status") != "SUCCESS" or not isinstance(models, dict)
                or len(models) > 64):
            self.inventory.pop(key, None)
            code = data.get("code")
            if code not in ("runtime_version_mismatch", "runtime_unavailable", "runtime_not_started"):
                code = "runtime_unavailable"
            self.worker_issues[key] = diagnostic(code)
            # Report frames arrive only after approval and session authentication.
            # Defer the command so its acknowledgement can be read by this socket.
            now = time.monotonic()
            if (code == "runtime_not_started" and self._bound(key)
                    and now - self.start_attempts.get(key, float("-inf")) >= 120):
                self.start_attempts[key] = now
                asyncio.create_task(self._start_runtime(key, websocket))
            return
        self.worker_issues.pop(key, None)
        self.start_attempts.pop(key, None)
        approved = {name: digest for name, digest in models.items() if valid_model(name, digest)}
        self.inventory[key] = (time.monotonic(), websocket, approved, data.get("available") is True)
        if not approved:
            self.worker_issues[key] = diagnostic("no_matching_models")

    def _bound(self, key):
        """Do not issue lifecycle commands to unassigned worker hosts."""
        return bool(self.hub.state.system_state.get("module_metadata", {})
                    .get(key, {}).get("tenant_id"))

    async def _start_runtime(self, key, websocket):
        """Start only a current, approved, tenant-bound worker."""
        if (self.hub.active_connections.get(key) is not websocket
                or not self.hub.approved_modules.get(key) or not self._bound(key)):
            return
        try:
            await self.hub.request_response(key, "LLM_START_RUNTIME", {}, timeout=25)
        except (TimeoutError, ConnectionError):
            # The next authenticated status report is authoritative.
            return

    def forget(self, key):
        """Forget status belonging to a disconnected worker."""
        self.inventory.pop(key, None)
        self.worker_issues.pop(key, None)
        self.start_attempts.pop(key, None)

    def diagnostics_for(self, tenant):
        """Return only issues for workers in scope; no prompt or output retention."""
        return [self.worker_issues[key] for key in self._tenant_workers(tenant)
                if key in self.worker_issues and key in self.hub.active_connections]

    def models_for(self, tenant):
        """Expose only names and digests, with no identity or job metadata."""
        models = {}
        for key in self._tenant_workers(tenant):
            report = self.inventory.get(key)
            if (report and time.monotonic() - report[0] < 75
                    and self.hub.active_connections.get(key) is report[1]):
                for name, digest in report[2].items():
                    models.setdefault(name, set()).add(digest)
        return {name: sorted(digests) for name, digests in models.items()}

    async def ab_pr_summary(self, request, certificate_names):
        """Route only explicit repository opt-ins, using the presented certificate."""
        repo = request.get("repository")
        configured = self.hub.state.get_global_config().get("llm_ab_pr_repos")
        if not isinstance(repo, str) or not isinstance(configured, dict):
            return {"status": "ERROR", "code": "not_configured"}
        rule = configured.get(repo)
        if not isinstance(rule, dict) or rule.get("certificate") not in (certificate_names or ()):
            return {"status": "ERROR", "code": "not_configured"}
        tenant = rule.get("tenant")
        if (not isinstance(tenant, str) or not tenant or tenant_is_shared(tenant)
                or not self.hub.state.get_tenant(tenant)):
            return {"status": "ERROR", "code": "not_configured"}
        result = await self.complete(tenant, {
            "task": "pr_summary", "prompt": request.get("prompt"),
        })
        # The certificate-authenticated AB client supplies the GitHub visibility
        # result. The server-side repo allowlist is independently required.
        if (result.get("code") == "no_capacity" and request.get("public") is True
                and rule.get("allow_public_cloud") is True):
            return await self._public_cloud_summary(tenant, request["prompt"], result)
        return result

    async def _public_cloud_summary(self, tenant, prompt, unavailable):
        """Try eligible cloud capacity only for a trusted public PR summary."""
        profiles = self.hub.state.get_global_config().get("llm_cloud_profiles")
        if not isinstance(profiles, list):
            return unavailable
        # Own cloud profile hides Shared, even when rate-limited or busy.
        own, shared = [], []
        for profile in profiles:
            if not isinstance(profile, dict) or profile.get("task") != "pr_summary":
                continue
            owner = profile.get("tenant")
            if owner and same_tenant(owner, tenant):
                own.append(profile)
            elif tenant_is_shared(owner):
                shared.append(profile)
        for profile in own or shared:
            result = await self._try_cloud(profile, prompt)
            if result is not None:
                return result
        return unavailable

    async def _try_cloud(self, profile, prompt):
        """Apply endpoint capacity and resolve a Vault key only for dispatch."""
        endpoint, model = profile.get("url"), profile.get("model")
        ref = profile.get("vault_credential")
        if (not llm_cloud.valid_endpoint(endpoint) or not isinstance(model, str) or not model
                or not instance_vault.has_vault_ref(profile)
                or not same_tenant(ref.get("bucket"), profile.get("tenant"))):
            return None
        if (endpoint in self.cloud_busy
                or self.cloud_cooldown.get(endpoint, 0) > time.monotonic()):
            return None
        self.cloud_busy.add(endpoint)
        try:
            # Whitelist the overlay input: a stored inline key must never be used.
            resolved = await instance_vault.overlay(
                self.hub, {"vault_credential": profile["vault_credential"]}, "llm_cloud_profiles")
            key = resolved.get("api_key")
            if not isinstance(key, str) or not key:
                return None
            result = await asyncio.to_thread(llm_cloud.complete_public, endpoint, model, key, prompt)
            if result.get("code") == "cloud_rate_limit":
                self.cloud_cooldown[endpoint] = time.monotonic() + 60
                return None
            if result.get("status") != "SUCCESS":
                result.update(diagnostic(result["code"]))
            return result
        finally:
            self.cloud_busy.discard(endpoint)

    def _tenant_workers(self, tenant):
        """Select the tenant's own pool even if it is entirely disconnected."""
        metadata = self.hub.state.system_state.get("module_metadata", {})
        own, shared = [], []
        for key, record in metadata.items():
            if (not isinstance(record, dict)
                    or record.get("module_type") != "llm"
                    or not self.hub.approved_modules.get(key)):
                continue
            owner = record.get("tenant_id")
            if owner and same_tenant(tenant, owner):
                own.append(key)
            elif tenant_is_shared(owner):
                shared.append(key)
        return sorted(own or shared)

    async def complete(self, tenant, data):
        """Route a validated job without touching the durable message mailbox."""
        prompt = data.get("prompt")
        output_format = data.get("format", "text")
        if (not isinstance(tenant, str) or not tenant.strip()
                or not isinstance(prompt, str) or not prompt.strip()
                or len(prompt.encode("utf-8", errors="replace")) > 65536
                or output_format not in ("text", "json", "python")):
            return {"status": "ERROR", "code": "invalid_request"}

        # Try task-approved artifacts in order. Never substitute an approximate
        # tag, or replay after an ambiguous dispatch or any completed inference.
        artifacts = self._job_models(data)
        if not artifacts:
            return {"status": "ERROR", "code": "invalid_request"}
        for model, digest in artifacts:
            result = await self._dispatch(tenant, prompt, model, digest, output_format)
            if result is not None:
                return result
        return {"status": "ERROR", **diagnostic("no_capacity"), "retryable": True}

    def _job_models(self, data):
        """Resolve an exact request or the operator's ordered local task profile."""
        if "task" not in data:
            model, digest = data.get("model"), data.get("digest")
            return [(model, digest)] if valid_model(model, digest) else []
        task = data["task"]
        if not isinstance(task, str) or "model" in data or "digest" in data:
            return []
        profiles = self.hub.state.get_global_config().get("llm_task_models")
        approved = profiles.get(task) if isinstance(profiles, dict) else None
        if not isinstance(approved, list):
            return []
        return list(dict.fromkeys((row["model"], row["digest"]) for row in approved[:8]
                                  if isinstance(row, dict)
                                  and valid_model(row.get("model"), row.get("digest"))))

    async def _dispatch(self, tenant, prompt, model, digest, output_format):
        """Try one artifact across its eligible workers, or return no capacity."""
        # Rotate the starting point, but recheck all claims before each dispatch.
        workers = self._tenant_workers(tenant)
        offset = self.sequence % len(workers) if workers else 0
        self.sequence += 1
        for key in workers[offset:] + workers[:offset]:
            if not self._eligible(key, tenant, model, digest):
                continue
            self.reserved.add(key)
            started = time.monotonic()
            try:
                # A lost response is ambiguous. Do not replay on another worker.
                reply = await asyncio.wait_for(self.hub.request_response(
                    key, "LLM_COMPLETE",
                    {"prompt": prompt, "model": model, "digest": digest, "format": output_format},
                    timeout=930), timeout=935)
            except (TimeoutError, ConnectionError):
                return {"status": "ERROR", "code": "dispatch_outcome_unknown"}
            finally:
                self.reserved.discard(key)

            envelope = reply.get("payload", {})
            payload = envelope.get("data", reply) if isinstance(envelope, Mapping) else None
            if not isinstance(payload, Mapping):
                return {"status": "ERROR", "code": "invalid_response"}
            if payload.get("code") in (
                    "busy", "runtime_unavailable", "model_unavailable", "runtime_version_mismatch"):
                continue
            if (payload.get("status") == "SUCCESS" and isinstance(payload.get("text"), str)
                    and 0 < len(payload["text"].encode("utf-8", errors="replace")) <= 262144):
                metrics = payload.get("metrics")
                safe_metrics = {name: metrics[name] for name in (
                    "load_duration", "prompt_eval_duration", "eval_duration", "eval_count",
                ) if isinstance(metrics, dict) and type(metrics.get(name)) is int
                    and 0 <= metrics[name] < 2**53}
                elapsed = round(time.monotonic() - started, 3)
                # Near-deadline CPU jobs are advisory only: latency is not corruption.
                notes = [diagnostic("slow_cpu_inference")] if elapsed >= 600 else []
                return {"status": "SUCCESS", "text": payload["text"], "model": model,
                        "metrics": safe_metrics, "elapsed_s": elapsed, "issues": notes}
            code = payload.get("code")
            if not isinstance(code, str) or code not in REMEDIATION:
                code = "inference_failed"
            return {"status": "ERROR", **diagnostic(code)}
        return None

    def _eligible(self, key, tenant, model, digest):
        """Use fresh live status only; a stale snapshot cannot authorize routing."""
        status = self.inventory.get(key)
        if not status or key in self.reserved or key not in self._tenant_workers(tenant):
            return False
        seen, websocket, models, available = status
        return (available and time.monotonic() - seen < 75
                and self.hub.active_connections.get(key) is websocket
                and self.hub.spoke_module_types.get(key) == "llm"
                and not self.hub.is_draining(key)
                and models.get(model) == digest)
