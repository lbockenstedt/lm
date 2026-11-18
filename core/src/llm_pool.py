"""Tenant-scoped, live-only routing to approved inference workers."""

import asyncio
import logging
import re
import time
from collections import deque
from collections.abc import Mapping

from access import same_tenant, tenant_is_shared
import instance_vault
import llm_cloud

logger = logging.getLogger(__name__)


REMEDIATION = {
    "runtime_unavailable": "Check the local-only Ollama service and its loopback listener.",
    "runtime_not_started": "Provision the dedicated Ollama service on the worker VM.",
    "runtime_unit_missing": "Stage the approved lm-llm-ollama.service unit on the worker.",
    "runtime_unit_symlink": (
        "Inspect the existing service-unit symlink; remove an intentional mask or "
        "repair a dangling target before retrying."
    ),
    "runtime_binary_missing": (
        "Install the approved offline Ollama bundle on the worker. The installer "
        "never replaces an existing /opt/lm-llm, so remove a partial runtime first."
    ),
    "runtime_start_failed": "Check the worker's systemd journal for lm-llm-ollama.service.",
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


HARDWARE_LIMITS = {"vcpus": 65536, "ram_bytes": 2**52}
# hub.request_response returns this, rather than raising, when a reply times
# out, and also without sending anything while the spoke is draining.
SPOKE_TIMEOUT = "Timed out waiting for spoke response"
# The causes a stopped worker re-evaluates and sends as detail_code; mirrors
# runtime_failure_code in the agent's llm_spoke.py.
RUNTIME_STOP_CAUSES = {
    "runtime_unit_missing", "runtime_unit_symlink", "runtime_binary_missing",
    "runtime_start_failed",
}
WORKER_ISSUE_CODES = {
    "runtime_version_mismatch", "runtime_unavailable", "runtime_not_started",
} | RUNTIME_STOP_CAUSES


def worker_issue_code(value):
    """Return ``value`` when it is a known worker issue code, else None.

    Status and reply fields are untrusted JSON. A list or object is unhashable,
    so it is type-checked before the set lookup rather than raising TypeError,
    which would end the worker's status handling."""
    return value if isinstance(value, str) and value in WORKER_ISSUE_CODES else None


def model_minimums(row):
    """Reject malformed hardware minima rather than treating them as zero."""
    values = tuple(row.get(f"min_{field}", 0) for field in HARDWARE_LIMITS)
    if any(type(value) is not int or not 0 <= value <= limit
           for value, limit in zip(values, HARDWARE_LIMITS.values())):
        return None
    return values


# Per-artifact sampling caps replace any model-name rule in the worker.
SAMPLING_LIMITS = {"temperature": 2.0, "top_p": 1.0}
# Worker worst case (agent/src/llm_qualification.py): two 20 s systemctl calls,
# a 15 s listener wait, a 420 s pull, four 240 s fixtures, a 20 s stop and
# short probes, about 1470 s. Keep headroom so a slow but live job is not
# reported as an unknown outcome while the worker still holds its slot.
QUALIFY_TIMEOUT = 1800


def model_sampling(row):
    """Return a profile's optional sampling caps as sorted pairs, or None if malformed."""
    pairs = []
    for field, limit in SAMPLING_LIMITS.items():
        if field in row:
            value = row[field]
            # bool is an int subclass, and NaN fails both comparisons.
            if type(value) not in (int, float) or not 0 <= value <= limit:
                return None
            pairs.append((field, float(value)))
    return tuple(pairs)


def qualification_result(data):
    """Keep only exact artifact identity and fixed, complete fixture results."""
    if not isinstance(data, Mapping) or not valid_model(data.get("model"), data.get("digest")):
        return None
    version, fixtures = data.get("version"), data.get("fixtures")
    if (not isinstance(version, str) or not re.fullmatch(r"\d{1,5}\.\d{1,5}\.\d{1,5}", version)
            or not isinstance(fixtures, list) or len(fixtures) != 2):
        return None
    results = []
    for expected, row in zip(("json", "indentation"), fixtures):
        if (not isinstance(row, dict) or row.get("fixture") != expected
                or not isinstance(row.get("passed"), bool)):
            return None
        results.append({"fixture": expected, "passed": row["passed"], **{
            name: row[name] for name in ("elapsed_s", "eval_count", "eval_duration", "load_duration")
            if type(row.get(name)) in (int, float) and 0 <= row[name] < 2**53
        }})
    return {"model": data["model"], "digest": data["digest"], "version": version, "fixtures": results}


QUALIFICATION_GUIDANCE = {
    "unsupported_or_invalid_reply": "Update the test agent and rerun qualification.",
    "baseline_unavailable": "Start the pinned baseline and install its approved model on the test worker.",
    "baseline_fixture_mismatch": "Repair the pinned baseline before drawing conclusions from this comparison.",
    "runtime_version_mismatch": "Check the staged candidate version and manifest before rerunning.",
    "candidate_not_provisioned": "Stage the candidate and its local qualification manifest.",
    "candidate_pull_failed": "Check registry access and disk space on the test worker.",
    "candidate_digest_mismatch": "Check the approved digest and registry tag; do not promote this artifact.",
    "qualification_runtime_failed": "Check CPU, memory and the candidate service logs; consider a smaller model.",
    "fixture_mismatch": "Check the response format and thinking settings, then qualify a different artifact or runtime.",
}


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
        self.jobs = deque(maxlen=200)
        self.qualification_jobs = {}
        self.active_jobs = {}
        self.runtime_versions = {}
        self.hardware = {}

    def qualification_candidates(self):
        """Resolve configured candidates to approved Shared test workers only."""
        manifest = self.hub.state.get_global_config().get("llm_qualification_candidates")
        metadata = self.hub.state.system_state.get("module_metadata", {})
        candidates = {}
        for key, row in (manifest.items() if isinstance(manifest, dict) else ()):
            if (not isinstance(row, dict) or not isinstance(key, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key)):
                continue
            worker, label = row.get("worker"), row.get("label")
            if not isinstance(worker, str) or not isinstance(label, str):
                continue
            pk = self.hub._primary_key(worker)
            record = metadata.get(pk, {})
            if (isinstance(record, dict) and record.get("module_type") == "llm"
                    and self.hub.approved_modules.get(pk)
                    and tenant_is_shared(record.get("tenant_id"))):
                candidates[key] = (pk, label[:100])
        return candidates

    def dashboard(self):
        """Return bounded operational metadata, with no prompts, output or credentials."""
        candidates = self.qualification_candidates()
        test_workers = {pk for pk, _ in candidates.values()}
        metadata = self.hub.state.system_state.get("module_metadata", {})
        workers = []
        for pk, row in metadata.items():
            if not isinstance(row, dict) or row.get("module_type") != "llm":
                continue
            socket = self.hub.active_connections.get(pk)
            report = self.inventory.get(pk)
            fresh = socket is not None and report and report[1] is socket and time.monotonic() - report[0] < 75
            hardware = self.hardware.get(pk)
            capabilities = (hardware[2] if hardware and hardware[1] is socket
                            and time.monotonic() - hardware[0] < 75 else {})
            state = ("pending" if not self.hub.approved_modules.get(pk) else
                     "disconnected" if socket is None else
                     "draining" if self.hub.is_draining(pk) else
                     "unavailable" if pk in self.worker_issues else
                     "no_fresh_report" if not fresh else
                     "busy" if pk in self.reserved or not report[3] else "ready")
            workers.append({"name": self.hub.state.get_module_name(pk), "state": state,
                            "issues": [self.worker_issues[pk]] if pk in self.worker_issues else [],
                            "version": self.runtime_versions.get(pk) if fresh else None,
                            "capabilities": capabilities,
                            "qualification": pk in test_workers,
                            "models": [{"name": name, "digest": digest}
                                       for name, digest in (report[2].items() if fresh else ())]})
        jobs = (list(self.qualification_jobs.values()) + list(self.active_jobs.values())
                + list(reversed(self.jobs)))
        metrics = {}
        for job in self.jobs:
            if job.get("model") is None:
                continue
            key = (job["model"], job["tier"], job.get("digest"), job.get("version"), job["kind"])
            row = metrics.setdefault(key, {"model": key[0], "tier": key[1], "completed": 0,
                                           "digest": key[2], "version": key[3], "kind": key[4],
                                           "failed": 0, "no_capacity": 0, "mean_elapsed_s": 0.0})
            if job["state"] == "no_capacity":
                row["no_capacity"] += 1
                continue
            count = row["completed"] + row["failed"]
            counter = "completed" if job["state"] == "passed" else "failed"
            row[counter] += 1
            row["mean_elapsed_s"] += (job["elapsed_s"] - row["mean_elapsed_s"]) / (count + 1)
        return {"workers": workers, "jobs": jobs, "metrics": list(metrics.values()),
                "candidates": [{"key": key, "label": label,
                                "worker": self.hub.state.get_module_name(pk)}
                               for key, (pk, label) in candidates.items()]}

    def start_qualification(self, key):
        """Schedule a synthetic job only on its configured Shared worker."""
        candidate = self.qualification_candidates().get(key)
        if not candidate:
            return False
        worker, label = candidate
        socket = self.hub.active_connections.get(worker)
        report = self.inventory.get(worker)
        if (socket is None or self.hub.is_draining(worker) or worker in self.reserved
                or not report or report[1] is not socket or not report[3]
                or time.monotonic() - report[0] >= 75):
            return False
        job = {"kind": "qualification", "state": "running", "candidate": label, "tier": "local",
               "worker": self.hub.state.get_module_name(worker)}
        self.qualification_jobs[worker] = job
        self.reserved.add(worker)
        asyncio.create_task(self._qualify(worker, socket, key, job))
        return True

    async def _qualify(self, worker, socket, key, job):
        """Store only validated qualification results from the reserved socket."""
        start = time.monotonic()
        try:
            candidate = self.qualification_candidates().get(key)
            if not candidate or candidate[0] != worker or self.hub.active_connections.get(worker) is not socket:
                job.update(state="failed", code="worker_changed")
                return
            reply = await asyncio.wait_for(self.hub.request_response(
                worker, "LLM_QUALIFY", {"candidate": key}, timeout=QUALIFY_TIMEOUT), QUALIFY_TIMEOUT + 5)
            envelope = reply.get("payload", {}) if isinstance(reply, Mapping) else None
            data = envelope.get("data", reply) if isinstance(envelope, Mapping) else None
            if not isinstance(data, Mapping):
                data = {}
            if self.hub.active_connections.get(worker) is not socket:
                job.update(state="failed", code="worker_changed")
                return
            code = data.get("code")
            if data.get("message") == SPOKE_TIMEOUT:
                code = "dispatch_outcome_unknown"
            elif code not in ("qualified", "fixture_mismatch", "baseline_fixture_mismatch", "candidate_not_provisioned",
                            "runtime_version_mismatch", "candidate_pull_failed",
                            "candidate_digest_mismatch", "qualification_runtime_failed",
                            "baseline_unavailable", "busy"):
                code = "unsupported_or_invalid_reply"
            result, baseline = qualification_result(data), qualification_result(data.get("baseline"))
            if result and baseline:
                job.update(result, baseline=baseline)
                job["fixture_deltas"] = [
                    {"fixture": after["fixture"], "pass_delta": int(after["passed"]) - int(before["passed"]),
                     **({"elapsed_s_delta": round(after["elapsed_s"] - before["elapsed_s"], 3)}
                        if "elapsed_s" in after and "elapsed_s" in before else {})}
                    for after, before in zip(result["fixtures"], baseline["fixtures"])
                ]
            passed = (result and baseline and code == "qualified" and data.get("status") == "SUCCESS"
                      and all(row["passed"] for row in result["fixtures"] + baseline["fixtures"]))
            if code == "qualified" and not passed:
                code = "unsupported_or_invalid_reply"
            job.update(state="passed" if passed else "failed", code=code)
        except asyncio.CancelledError:
            job.update(state="failed", code="dispatch_outcome_unknown")
            raise
        except (TimeoutError, ConnectionError):
            job.update(state="failed", code="dispatch_outcome_unknown")
        finally:
            if job.get("code") in QUALIFICATION_GUIDANCE:
                job["resolution"] = QUALIFICATION_GUIDANCE[job["code"]]
            self.reserved.discard(worker)
            self.qualification_jobs.pop(worker, None)
            job["elapsed_s"] = round(time.monotonic() - start, 3)
            self.jobs.append(job)


    def report(self, key, websocket, data):
        """Accept bounded catalog metadata only from the current approved socket."""
        hub = self.hub
        if (hub.spoke_module_types.get(key) != "llm"
                or not hub.approved_modules.get(key)
                or hub.active_connections.get(key) is not websocket
                or not isinstance(data, dict)):
            return
        models = data.get("models")
        raw = data.get("capabilities")
        if isinstance(raw, dict) and raw.get("mode") == "cpu":
            capabilities = {"mode": "cpu"}
            capabilities.update({field: raw[field] for field, limit in HARDWARE_LIMITS.items()
                                 if type(raw.get(field)) is int and 0 < raw[field] <= limit})
            capabilities.update({field: raw[field] for field, limit in (("cpu_model", 160), ("arch", 32))
                                 if isinstance(raw.get(field), str) and 0 < len(raw[field]) <= limit})
            self.hardware[key] = (time.monotonic(), websocket, capabilities)
        else:
            self.hardware.pop(key, None)
        if (data.get("status") != "SUCCESS" or not isinstance(models, dict)
                or len(models) > 64):
            self.inventory.pop(key, None)
            self.runtime_versions.pop(key, None)
            code = worker_issue_code(data.get("code")) or "runtime_unavailable"
            detail_code = worker_issue_code(data.get("detail_code"))
            # Stopped workers keep runtime_not_started for older hubs and send
            # the re-evaluated cause in detail_code. Only a stop cause may
            # refine it; any other code would end the start retry below.
            if code == "runtime_not_started" and detail_code in RUNTIME_STOP_CAUSES:
                code = detail_code
            self._set_worker_issue(key, code)
            # Report frames arrive only after approval and session authentication.
            # Defer the command so its acknowledgement can be read by this socket.
            now = time.monotonic()
            if (code in ("runtime_not_started", "runtime_start_failed")
                    and self._bound(key)
                    and now - self.start_attempts.get(key, float("-inf")) >= 120):
                self.start_attempts[key] = now
                asyncio.create_task(self._start_runtime(key, websocket))
            return
        self.start_attempts.pop(key, None)
        approved = {name: digest for name, digest in models.items() if valid_model(name, digest)}
        self.inventory[key] = (time.monotonic(), websocket, approved, data.get("available") is True)
        version = data.get("version")
        if isinstance(version, str) and re.fullmatch(r"\d{1,5}\.\d{1,5}\.\d{1,5}", version):
            self.runtime_versions[key] = version
        else:
            self.runtime_versions.pop(key, None)
        if not approved:
            self._set_worker_issue(key, "no_matching_models")
        else:
            self._clear_worker_issue(key)

    def _set_worker_issue(self, key, code):
        """Log an unavailable transition once and store bounded guidance."""
        issue = diagnostic(code)
        previous = self.worker_issues.get(key)
        self.worker_issues[key] = issue
        if previous != issue:
            logger.warning("LLM worker %s unavailable: %s", self._label(key), code)

    def _clear_worker_issue(self, key):
        """Log recovery once when a worker returns to a usable inventory."""
        issue = self.worker_issues.pop(key, None)
        if issue:
            logger.info("LLM worker %s recovered from %s", self._label(key), issue["code"])

    def _label(self, key):
        """Name a worker in hub logs; its key alone can be an opaque GUID."""
        name = self.hub.state.get_module_name(key)
        return f"{name} ({key})" if name and name != key else key

    def _bound(self, key):
        """Do not issue lifecycle commands to unassigned worker hosts."""
        return bool(self.hub.state.system_state.get("module_metadata", {})
                    .get(key, {}).get("tenant_id"))

    async def _start_runtime(self, key, websocket):
        """Start only a current, approved, tenant-bound worker.

        The checks are repeated here, right before the send, because the
        worker can be unbound or unapproved after its report scheduled this."""
        if (self.hub.active_connections.get(key) is not websocket
                or not self.hub.approved_modules.get(key) or not self._bound(key)):
            return
        label = self._label(key)
        try:
            reply = await self.hub.request_response(
                key, "LLM_START_RUNTIME", {}, timeout=25)
        except (TimeoutError, ConnectionError):
            # The next authenticated status report is authoritative.
            logger.warning("LLM worker %s runtime start request failed", label)
            return
        # Unwrap the reply envelope; anything but an object is malformed.
        envelope = reply.get("payload") if isinstance(reply, Mapping) else None
        data = (envelope.get("data", reply) if isinstance(envelope, Mapping) else reply)
        if not isinstance(data, Mapping):
            data = {}
        if data.get("status") == "SUCCESS":
            logger.info("LLM worker %s runtime start request accepted", label)
            return
        # Only a stable issue code shows that the worker tried and failed.
        code = worker_issue_code(data.get("code"))
        if code:
            logger.warning("LLM worker %s runtime start rejected: %s", label, code)
            return
        # A timeout (or an unsent request to a draining spoke), a stopping
        # worker's busy reply or a malformed reply says nothing about the
        # runtime, so do not point the operator at its journal. Log fixed text,
        # never the raw reply; the next status report decides any retry.
        outcome = (SPOKE_TIMEOUT if data.get("message") == SPOKE_TIMEOUT
                   else "busy" if data.get("code") == "busy" else "unrecognised reply")
        logger.warning("LLM worker %s runtime start outcome unknown: %s", label, outcome)

    def forget(self, key):
        """Forget status belonging to a disconnected worker."""
        self.inventory.pop(key, None)
        self.runtime_versions.pop(key, None)
        self.hardware.pop(key, None)
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
        job = {"kind": "inference", "tier": "cloud", "model": model, "state": "running"}
        self.active_jobs[id(job)] = job
        started = time.monotonic()
        try:
            # Whitelist the overlay input: a stored inline key must never be used.
            resolved = await instance_vault.overlay(
                self.hub, {"vault_credential": profile["vault_credential"]}, "llm_cloud_profiles")
            key = resolved.get("api_key")
            if not isinstance(key, str) or not key:
                job.update(state="failed", code="credential_unavailable")
                return None
            limit_field = profile.get("token_limit_field", "max_tokens")
            if limit_field not in llm_cloud.TOKEN_LIMIT_FIELDS:
                job.update(state="failed", code="cloud_invalid_profile")
                return None
            result = await asyncio.to_thread(llm_cloud.complete_public, endpoint, model, key, prompt, limit_field)
            job.update(state="passed" if result.get("status") == "SUCCESS" else "failed",
                       code=result.get("code"))
            if result.get("code") == "cloud_rate_limit":
                self.cloud_cooldown[endpoint] = time.monotonic() + 60
                return None
            if result.get("status") != "SUCCESS":
                result.update(diagnostic(result["code"]))
            return result
        finally:
            self.cloud_busy.discard(endpoint)
            self.active_jobs.pop(id(job), None)
            if job["state"] == "running":
                job.update(state="failed", code="dispatch_outcome_unknown")
            job["elapsed_s"] = round(time.monotonic() - started, 3)
            self.jobs.append(job)

    def _tenant_workers(self, tenant):
        """Select the tenant's own pool even if it is entirely disconnected."""
        metadata = self.hub.state.system_state.get("module_metadata", {})
        own, shared = [], []
        test_workers = {pk for pk, _ in self.qualification_candidates().values()}
        for key, record in metadata.items():
            if (not isinstance(record, dict)
                    or key in test_workers
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
        for model, digest, minimums, sampling in artifacts:
            started = time.monotonic()
            job = {"kind": "inference", "state": "running", "model": model,
                   "digest": digest, "tier": "local"}
            self.active_jobs[id(job)] = job
            try:
                result = await self._dispatch(
                    tenant, prompt, model, digest, output_format, job, minimums, sampling)
                if result is not None:
                    job.update(state="passed" if result["status"] == "SUCCESS" else "failed",
                               code=result.get("code"), metrics=result.get("metrics", {}),
                               issues=result.get("issues", []))
                    return result
                job.update(state="no_capacity", code="no_capacity")
            finally:
                self.active_jobs.pop(id(job), None)
                if job["state"] == "running":
                    job.update(state="failed", code="dispatch_outcome_unknown")
                job["elapsed_s"] = round(time.monotonic() - started, 3)
                self.jobs.append(job)
        return {"status": "ERROR", **diagnostic("no_capacity"), "retryable": True}

    def _job_models(self, data):
        """Resolve an exact request or the operator's ordered local task profile."""
        if "task" not in data:
            model, digest = data.get("model"), data.get("digest")
            return [(model, digest, (0, 0), ())] if valid_model(model, digest) else []
        task = data["task"]
        if not isinstance(task, str) or "model" in data or "digest" in data:
            return []
        profiles = self.hub.state.get_global_config().get("llm_task_models")
        approved = profiles.get(task) if isinstance(profiles, dict) else None
        if not isinstance(approved, list):
            return []
        return list(dict.fromkeys((row["model"], row["digest"], minimums, sampling)
                                  for row in approved[:8]
                                  if isinstance(row, dict)
                                  and valid_model(row.get("model"), row.get("digest"))
                                  and (minimums := model_minimums(row)) is not None
                                  and (sampling := model_sampling(row)) is not None))

    async def _dispatch(self, tenant, prompt, model, digest, output_format, job, minimums, sampling=()):
        """Try one artifact across its eligible workers, or return no capacity."""
        request = {"prompt": prompt, "model": model, "digest": digest, "format": output_format}
        if sampling:
            # Older workers ignore this key and keep Ollama's default sampling.
            request["options"] = dict(sampling)
        # Rotate the starting point, but recheck all claims before each dispatch.
        workers = self._tenant_workers(tenant)
        offset = self.sequence % len(workers) if workers else 0
        self.sequence += 1
        for key in workers[offset:] + workers[:offset]:
            if not self._eligible(key, tenant, model, digest, minimums):
                continue
            job["version"] = self.runtime_versions.get(key)
            self.reserved.add(key)
            started = time.monotonic()
            try:
                # A lost response is ambiguous. Do not replay on another worker.
                reply = await asyncio.wait_for(self.hub.request_response(
                    key, "LLM_COMPLETE", request, timeout=930), timeout=935)
            except (TimeoutError, ConnectionError):
                return {"status": "ERROR", "code": "dispatch_outcome_unknown"}
            finally:
                self.reserved.discard(key)

            envelope = reply.get("payload", {}) if isinstance(reply, Mapping) else None
            payload = envelope.get("data", reply) if isinstance(envelope, Mapping) else None
            if not isinstance(payload, Mapping):
                return {"status": "ERROR", "code": "invalid_response"}
            if payload.get("message") == SPOKE_TIMEOUT:
                return {"status": "ERROR", "code": "dispatch_outcome_unknown"}
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

    def _eligible(self, key, tenant, model, digest, minimums=(0, 0)):
        """Use fresh live status only; a stale snapshot cannot authorize routing."""
        status = self.inventory.get(key)
        if not status or key in self.reserved or key not in self._tenant_workers(tenant):
            return False
        seen, websocket, models, available = status
        if any(minimums):
            hardware = self.hardware.get(key)
            if (not hardware or hardware[1] is not websocket or time.monotonic() - hardware[0] >= 75
                    or any(hardware[2].get(field, 0) < minimum
                           for field, minimum in zip(HARDWARE_LIMITS, minimums))):
                return False
        return (available and time.monotonic() - seen < 75
                and self.hub.active_connections.get(key) is websocket
                and self.hub.spoke_module_types.get(key) == "llm"
                and not self.hub.is_draining(key)
                and models.get(model) == digest)
