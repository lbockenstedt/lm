"""Tenant-scoped, live-only routing to approved inference workers."""

import asyncio
import logging
import re
import time
import uuid
from collections import deque
from collections.abc import Mapping

from access import same_tenant, tenant_is_shared
import instance_vault
import llm_cloud
from llm_candidates import CANDIDATES, default_task_models

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
# A worker reporting one of these has no runtime installed, so it sends no
# inventory; the provisioner treats it as serving nothing and installs it.
NO_RUNTIME_CODES = {"runtime_not_started", "runtime_unit_missing", "runtime_unit_symlink",
                    "runtime_binary_missing"}
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
SAMPLING_LIMITS = {
    "temperature": 2.0, "top_p": 1.0, "top_k": 256,
    "repeat_penalty": 2.0, "num_ctx": 131072,
}
LEGACY_OPTIONS = {"temperature", "top_p"}
INTEGER_OPTIONS = {"top_k", "num_ctx"}
# A runtime download, model pull and CPU fixtures can take several hours.
QUALIFY_TIMEOUT = 15000


def model_sampling(row):
    """Return a profile's optional sampling caps as sorted pairs, or None if malformed."""
    pairs = []
    for field, limit in SAMPLING_LIMITS.items():
        if field in row:
            value = row[field]
            # bool is an int subclass, and NaN fails both comparisons.
            if (type(value) not in (int, float) or not 0 <= value <= limit
                    or (field in INTEGER_OPTIONS and type(value) is not int)
                    or (field in ("num_ctx", "repeat_penalty") and value == 0)):
                return None
            pairs.append((field, value if field in INTEGER_OPTIONS else float(value)))
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
    "bootstrap_smoke_passed": "The synthetic smoke test passed; this is not model certification.",
    "unsupported_or_invalid_reply": "Update the test agent and rerun qualification.",
    "baseline_unavailable": "Start the pinned baseline and install its approved model on the test worker.",
    "baseline_fixture_mismatch": "Repair the pinned baseline before drawing conclusions from this comparison.",
    "runtime_version_mismatch": "Check the staged candidate version and manifest before rerunning.",
    "candidate_not_provisioned": "Stage the candidate and its local qualification manifest.",
    "candidate_runtime_install_failed": "Check the worker's download, disk space and LLM agent logs.",
    "preparation_state_failed": "Check the worker's preparation journal and disk; the hub will retry.",
    "preparation_superseded": "Inspect the hub and worker preparation journals before retrying.",
    "candidate_not_smoke_tested": "Prepare the selected candidate on this worker before activating it.",
    "operator_catalog_override": "Remove the role catalog override only after reviewing the operator-managed catalog.",
    "activation_failed": "Check the worker's LLM logs and serving runtime before retrying.",
    "activation_rollback_failed": "Inspect the worker immediately; automatic activation rollback failed.",
    "candidate_pull_failed": "Check registry access and disk space on the test worker.",
    "candidate_digest_mismatch": "Check the approved digest and registry tag; do not promote this artifact.",
    "qualification_runtime_failed": "Check CPU, memory and the candidate service logs; consider a smaller model.",
    "fixture_mismatch": "Check the response format and thinking settings, then qualify a different artifact or runtime.",
}


MAX_METRIC_ROWS = 500
# A job waits for a busy pool instead of failing: poll this often, hold at most
# MAX_QUEUED waiters, and give up after llm_queue_wait_s (default and clamp below).
QUEUE_POLL_S = 2
MAX_QUEUED = 64
QUEUE_WAIT_DEFAULT = 600
QUEUE_WAIT_MAX = 3600
# Auto-provisioning: at most this many workers pull models at once hub-wide, a failed
# model waits 15 min, doubling per failure up to 6 h, and a step is polled this often.
PROVISION_MAX_WORKERS = 2
PROVISION_BACKOFF_BASE = 900
PROVISION_BACKOFF_MAX = 21600
PROVISION_POLL_S = 2
ACTIVATION_IDLE_WAIT_S = 90


def queue_wait(config):
    """Return the operator's llm_queue_wait_s clamped to 0..3600; bad values use the default."""
    value = config.get("llm_queue_wait_s", QUEUE_WAIT_DEFAULT)
    if type(value) is not int:
        return QUEUE_WAIT_DEFAULT
    return max(0, min(QUEUE_WAIT_MAX, value))


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
        self.waiters = []  # queued-job tickets, oldest first; fairness is enforced per worker claim
        self.last_dispatch = {}
        self.queued = 0
        self.jobs = deque(maxlen=200)
        # Per-model performance totals outlive the job rows, so clearing rows keeps them.
        self.metric_rows = {}
        self.qualification_jobs = {}
        self.active_jobs = {}
        self.runtime_versions = {}
        self.hardware = {}
        self.worker_options = {}
        self.bootstrap_done = {}
        self.bootstrap_retry_at = {}
        # Auto-provisioning state (volatile; the live inventory is re-checked each pass).
        self.provision_retry_at = {}
        self.provision_fail_count = {}
        self.provision_skipped = {}
        self.provision_failures = {}
        self.provisioning = set()
        self.provision_tasks = set()

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
            job = self.qualification_jobs.get(pk)
            provisioning = job is not None and job.get("kind") in ("bootstrap", "activation")
            failures = self.provision_failures.get(pk)
            failure = ({"model": next(iter(failures)), "code": next(iter(failures.values()))}
                       if failures else None)
            detail = ""
            # A model that fails its fixtures is not worker trouble while the worker serves others.
            unfit_only = bool(failure and fresh and report[2]
                              and all(code == "fixture_mismatch" for code in failures.values()))
            state = ("pending" if not self.hub.approved_modules.get(pk) else
                     "disconnected" if socket is None else
                     "draining" if self.hub.is_draining(pk) else
                     # Provisioning comes before unavailable and busy: a new worker with no
                     # models reports "no_matching_models" and is reserved while it runs.
                     "provisioning" if provisioning else
                     "attention" if failure and not unfit_only and (fresh or pk in self.worker_issues) else
                     "unavailable" if pk in self.worker_issues else
                     "no_fresh_report" if not fresh else
                     "busy" if pk in self.reserved or not report[3] else "ready")
            if state == "provisioning":
                detail = ("Preparing " if job["kind"] == "bootstrap" else "Activating ") + job["candidate"]
            elif state == "attention":
                detail = f"{failure['code']}: {failure['model']}"
            elif unfit_only:
                detail = "; ".join(f"{label}: fixture_mismatch" for label in failures)
            elif self.provision_skipped.get(pk):
                detail = "; ".join(f"Too small for {label}" for label in self.provision_skipped[pk])
            workers.append({"name": self.hub.state.get_module_name(pk), "state": state,
                            "issues": [self.worker_issues[pk]] if pk in self.worker_issues else [],
                            "version": self.runtime_versions.get(pk) if fresh else None,
                            "capabilities": capabilities,
                            "qualification": pk in test_workers,
                            "detail": detail,
                            "skipped": list(self.provision_skipped.get(pk, ())),
                            "models": [{"name": name, "digest": digest}
                                       for name, digest in (report[2].items() if fresh else ())]})
        jobs = (list(self.qualification_jobs.values()) + list(self.active_jobs.values())
                + list(reversed(self.jobs)))
        return {"workers": workers, "jobs": jobs, "metrics": [dict(row) for row in self.metric_rows.values()],
                "candidates": [{"key": key, "label": label,
                                "worker": self.hub.state.get_module_name(pk)}
                               for key, (pk, label) in candidates.items()]}

    def _provision_plan(self, pk):
        """Return the catalog keys to pull now on a worker, smallest first.

        Needs a fresh inventory and hardware report; otherwise returns nothing so a
        worker we cannot yet size is never loaded. Also refreshes the 'too small'
        list and clears a stale failure once nothing is left to pull."""
        socket = self.hub.active_connections.get(pk)
        now = time.monotonic()
        report, hardware = self.inventory.get(pk), self.hardware.get(pk)
        if (socket is None or not hardware or hardware[1] is not socket or now - hardware[0] >= 75):
            return []
        fresh_report = bool(report and report[1] is socket and now - report[0] < 75)
        no_runtime = (self.worker_issues.get(pk) or {}).get("code") in NO_RUNTIME_CODES
        if not fresh_report and not no_runtime:
            return []
        ram = hardware[2].get("ram_bytes")
        if type(ram) is not int:
            return []
        served = set(report[2].items()) if fresh_report else set()
        # Every catalog model, smallest first so a worker serves something useful soonest;
        # a model added to the catalog is provisioned without touching this code.
        missing = [key for key in sorted(CANDIDATES, key=lambda k: CANDIDATES[k]["min_ram_bytes"])
                   if (CANDIDATES[key]["model"], CANDIDATES[key]["digest"]) not in served]
        small = [key for key in missing if ram < CANDIDATES[key]["min_ram_bytes"]]
        if small:
            self.provision_skipped[pk] = [CANDIDATES[key]["label"] for key in small]
        else:
            self.provision_skipped.pop(pk, None)
        wanted = [key for key in missing if key not in small]
        if not wanted:
            self.provision_failures.pop(pk, None)
        return [key for key in wanted if self.provision_retry_at.get((pk, key), 0) <= now]

    async def provision_once(self):
        """Start provisioning on workers that lack catalog models; never blocks on a pull.

        Each worker gets its own task (one model at a time), and at most
        PROVISION_MAX_WORKERS run at once hub-wide, so a multi-hour pull never
        delays the next 60 s pass or blocks the hub."""
        if self.hub.state.get_global_config().get("llm_auto_provision", True) is False:
            return
        metadata = self.hub.state.system_state.get("module_metadata", {})
        for pk, record in list(metadata.items()):
            if len(self.provisioning) >= PROVISION_MAX_WORKERS:
                break
            if (not isinstance(record, dict) or record.get("module_type") != "llm"
                    or not self.hub.approved_modules.get(pk) or pk in self.provisioning
                    or pk in self.reserved):
                continue
            keys = self._provision_plan(pk)
            if keys:
                self.provisioning.add(pk)
                task = asyncio.create_task(self._provision_worker(pk, keys))
                self.provision_tasks.add(task)
                task.add_done_callback(self.provision_tasks.discard)

    async def _provision_worker(self, pk, keys):
        """Provision a worker's missing models one after another, stopping at a failure."""
        try:
            for key in keys:
                if not await self._provision_model(pk, key):
                    break
        except Exception:  # noqa: BLE001 - one worker must never kill the reconciler
            logger.exception("LLM provisioning of %s failed", self._label(pk))
        finally:
            self.provisioning.discard(pk)

    async def _wait_job(self, job):
        """Wait for a bootstrap or activation job to leave the running state."""
        while job["state"] == "running":
            await asyncio.sleep(PROVISION_POLL_S)
        return job

    def _provision_failed(self, pk, key, code):
        """Record a failed step: exponential backoff for this model and the code for the dashboard."""
        count = self.provision_fail_count.get((pk, key), 0)
        delay = min(PROVISION_BACKOFF_MAX, PROVISION_BACKOFF_BASE * 2 ** count)
        if code == "fixture_mismatch":
            # The model is deterministically unfit for this hardware; retrying only burns CPU.
            delay = PROVISION_BACKOFF_MAX
        self.provision_fail_count[(pk, key)] = count + 1
        self.provision_retry_at[(pk, key)] = time.monotonic() + delay
        self.provision_failures.setdefault(pk, {})[CANDIDATES[key]["label"]] = code
        logger.warning("LLM worker %s: provisioning %s failed (%s); retry in %ds",
                       self._label(pk), key, code, delay)
        return False

    async def _provision_model(self, pk, key):
        """Prepare then activate one catalog model; return True when it is now served.

        A worker that is merely busy or not ready returns False without a backoff
        (the next pass retries); only a failed step starts the backoff."""
        try:
            job = await self.start_bootstrap(pk, key, auto=True)
        except Exception as exc:  # noqa: BLE001 - a failed config save is a failed step
            logger.warning("LLM worker %s: cannot save preparation: %s", self._label(pk), exc)
            return self._provision_failed(pk, key, "preparation_state_failed")
        if not job:
            return False
        job = await self._wait_job(job)
        if job["state"] != "passed":
            return self._provision_failed(pk, key, job.get("code", "unsupported_or_invalid_reply"))
        # The worker's last status report may still say "busy" from the bootstrap that just
        # ended; a worker already serving models stays non-idle until its next report.
        job = self.start_activation(pk, key, auto=True)
        for _ in range(ACTIVATION_IDLE_WAIT_S // 2):
            if job:
                break
            await asyncio.sleep(PROVISION_POLL_S)
            job = self.start_activation(pk, key, auto=True)
        if not job:
            return self._provision_failed(pk, key, "worker_changed")
        job = await self._wait_job(job)
        if job["state"] != "passed":
            return self._provision_failed(pk, key, job.get("code", "unsupported_or_invalid_reply"))
        # Success: drop the saved preparation so a reconnect replay cannot re-pull a
        # candidate copy the agent has already pruned after activation.
        configured = self.hub.state.get_global_config().get("llm_worker_preparations")
        if isinstance(configured, dict) and pk in configured:
            row = configured[pk]
            floors = self.hub.state.get_global_config().get("llm_worker_prep_revisions")
            floors = dict(floors) if isinstance(floors, dict) else {}
            if isinstance(row, dict) and type(row.get("revision")) is int:
                floors[pk] = max(floors.get(pk, 0), row["revision"])
            self.hub.state.update_global_config(
                {"llm_worker_preparations": {k: v for k, v in configured.items() if k != pk},
                 "llm_worker_prep_revisions": floors})
            await self.hub.state.save_state_now()
        self.provision_fail_count.pop((pk, key), None)
        self.provision_retry_at.pop((pk, key), None)
        # A later model's success must not hide an earlier, still-backed-off failure.
        failed = self.provision_failures.get(pk)
        if failed:
            failed.pop(CANDIDATES[key]["label"], None)
            if not failed:
                self.provision_failures.pop(pk, None)
        return True

    def _finish(self, job):
        """Record a terminal job row and fold it into the per-model metrics."""
        if job["state"] == "queued":
            # A cancelled or expired wait never ran; history rows are always terminal.
            job.update(state="no_capacity", code="no_capacity")
        if job["state"] == "cancelled":
            # The caller went away while queued; that is not a capacity shortage.
            self.jobs.append(job)
            return
        if job["state"] == "running":
            # An unexpected exception left it unresolved; history rows are always terminal.
            job.update(state="failed", code="dispatch_outcome_unknown")
        self.jobs.append(job)
        if job.get("model") is None:
            return
        key = (job["model"], job["tier"], job.get("digest"), job.get("version"), job["kind"])
        if key not in self.metric_rows and len(self.metric_rows) >= MAX_METRIC_ROWS:
            return  # caller-chosen model/digest values must not grow memory without bound
        row = self.metric_rows.setdefault(key, {
            "model": key[0], "tier": key[1], "completed": 0, "digest": key[2],
            "version": key[3], "kind": key[4], "failed": 0, "no_capacity": 0,
            "mean_elapsed_s": 0.0})
        if job["state"] == "no_capacity":
            row["no_capacity"] += 1
            return
        count = row["completed"] + row["failed"]
        row["completed" if job["state"] == "passed" else "failed"] += 1
        row["mean_elapsed_s"] += (job["elapsed_s"] - row["mean_elapsed_s"]) / (count + 1)

    def clear_finished_jobs(self):
        """Empty the finished-job history and return how many rows were removed.

        Only `self.jobs` (terminal attempts) is cleared. Running qualification and
        active jobs live in their own dicts, so they are never touched, and the
        per-model metrics are kept in `metric_rows`, so they survive the clear.
        """
        removed = len(self.jobs)
        self.jobs.clear()
        return removed

    def start_qualification(self, key):
        """Schedule a synthetic job only on its configured Shared test worker; return its job."""
        candidate = self.qualification_candidates().get(key)
        if not candidate:
            return False
        worker, label = candidate
        socket = self._available_worker(worker)
        if socket is None:
            return False
        job = {"kind": "qualification", "state": "running", "candidate": label, "tier": "local",
               "worker": self.hub.state.get_module_name(worker)}
        self.qualification_jobs[worker] = job
        self.reserved.add(worker)
        asyncio.create_task(self._qualify(worker, socket, key, job))
        return job

    def _available_worker(self, worker, auto=False):
        """Return the socket of an approved, connected, fresh, idle, unreserved LLM worker.

        Admin-triggered work (auto=False) only reaches Shared-tenant workers: a
        superadmin never remote-controls a tenant's spoke (fleet rule 5.5). The
        hub's own reconciler and reconnect replay (auto=True) manage every
        approved LLM worker, since that is a fleet-wide hub policy."""
        metadata = self.hub.state.system_state.get("module_metadata", {})
        record = metadata.get(worker, {})
        if (not isinstance(record, dict) or record.get("module_type") != "llm"
                or not self.hub.approved_modules.get(worker)
                or not (auto or tenant_is_shared(record.get("tenant_id")))):
            return None
        socket = self.hub.active_connections.get(worker)
        report = self.inventory.get(worker)
        hardware = self.hardware.get(worker)
        fresh_report = bool(report and report[1] is socket and time.monotonic() - report[0] < 75)
        fresh_status = (fresh_report or bool(
            hardware and hardware[1] is socket and time.monotonic() - hardware[0] < 75))
        idle = not report or (fresh_report and (report[3] or not report[2]))
        if (socket is None or self.hub.is_draining(worker) or worker in self.reserved
                or not fresh_status or not idle):
            return None
        return socket

    async def start_bootstrap(self, worker, key, auto=False):
        """Reserve an approved LLM worker for one pinned candidate; return its job."""
        if (not isinstance(worker, str) or not 0 < len(worker) <= 255
                or not isinstance(key, str) or key not in CANDIDATES):
            return False
        worker = self.hub._primary_key(worker)
        socket = self._available_worker(worker, auto)
        if socket is None:
            return False
        configured = self.hub.state.get_global_config().get("llm_worker_preparations")
        if configured is not None and not isinstance(configured, dict):
            return False
        desired = dict(configured or {})
        request_id = uuid.uuid4().hex
        prior = desired.get(worker)
        prior_revision = prior.get("revision", 0) if isinstance(prior, dict) else 0
        # The worker's journal keeps its last revision after the replay row is removed,
        # so the next request must start above the highest revision ever used.
        floors = self.hub.state.get_global_config().get("llm_worker_prep_revisions")
        floor = floors.get(worker, 0) if isinstance(floors, dict) else 0
        if type(floor) is int and type(prior_revision) is int:
            prior_revision = max(prior_revision, floor)
        if type(prior_revision) is not int or not 0 <= prior_revision < 2**53 - 1:
            return False
        revision = prior_revision + 1
        desired[worker] = {"candidate": key, "request_id": request_id, "revision": revision}
        if auto:
            # Provenance: only a reconciler-made row may be replayed on a tenant worker.
            desired[worker]["auto"] = True
        self.reserved.add(worker)
        try:
            self.hub.state.update_global_config({"llm_worker_preparations": desired})
            await self.hub.state.save_state_now()
        except BaseException:
            current = self.hub.state.get_global_config().get("llm_worker_preparations")
            if isinstance(current, dict) and current.get(worker) == desired[worker]:
                restored = dict(current)
                if prior is None:
                    restored.pop(worker, None)
                else:
                    restored[worker] = prior
                self.hub.state.update_global_config({"llm_worker_preparations": restored})
            self.reserved.discard(worker)
            raise
        return self._schedule_bootstrap(worker, socket, key, request_id, revision, auto)

    def _schedule_bootstrap(self, worker, socket, key, request_id, revision, auto=False):
        """Track and dispatch a persisted, idempotent preparation request; return its job."""
        job = {"kind": "bootstrap", "state": "running", "candidate": CANDIDATES[key]["label"], "tier": "local",
               "worker": self.hub.state.get_module_name(worker)}
        self.qualification_jobs[worker] = job
        self.reserved.add(worker)
        asyncio.create_task(self._qualify(
            worker, socket, key, job, bootstrap=True, request_id=request_id, revision=revision, auto=auto))
        return job

    def reconcile_bootstrap(self, worker):
        """Replay a saved preparation on reconnect or after an ambiguous reply."""
        configured = self.hub.state.get_global_config().get("llm_worker_preparations")
        row = configured.get(worker) if isinstance(configured, dict) else None
        if not isinstance(row, dict):
            return
        key, request_id, revision = (row.get(name) for name in ("candidate", "request_id", "revision"))
        if (not isinstance(key, str) or key not in CANDIDATES or not isinstance(request_id, str)
                or not re.fullmatch(r"[a-f0-9]{32}", request_id)
                or type(revision) is not int or not 1 <= revision < 2**53
                or self.bootstrap_done.get(worker) == request_id
                or self.bootstrap_retry_at.get(worker, 0) > time.monotonic()):
            return
        auto = row.get("auto") is True
        socket = self._available_worker(worker, auto)
        if socket is not None:
            self._schedule_bootstrap(worker, socket, key, request_id, revision, auto)

    def start_activation(self, worker, key, auto=False):
        """Schedule activation of a prepared model on an approved LLM worker; return its job."""
        if (not isinstance(worker, str) or not 0 < len(worker) <= 255
                or not isinstance(key, str) or key not in CANDIDATES):
            return False
        worker = self.hub._primary_key(worker)
        desired = self.hub.state.get_global_config().get("llm_worker_preparations")
        row = desired.get(worker) if isinstance(desired, dict) else None
        if not isinstance(row, dict) or row.get("candidate") != key:
            return False
        socket = self._available_worker(worker, auto)
        if socket is None:
            return False
        job = {"kind": "activation", "state": "running", "candidate": CANDIDATES[key]["label"],
               "tier": "local", "worker": self.hub.state.get_module_name(worker)}
        self.qualification_jobs[worker] = job
        self.reserved.add(worker)
        asyncio.create_task(self._activate(worker, socket, key, job, auto))
        return job

    async def _activate(self, worker, socket, key, job, auto=False):
        """Validate the activation reply without replaying an ambiguous result."""
        started = time.monotonic()
        try:
            row = self.hub.state.system_state.get("module_metadata", {}).get(worker, {})
            desired = self.hub.state.get_global_config().get("llm_worker_preparations")
            selection = desired.get(worker) if isinstance(desired, dict) else None
            if (not isinstance(row, dict) or row.get("module_type") != "llm"
                    or not self.hub.approved_modules.get(worker)
                    or not (auto or tenant_is_shared(row.get("tenant_id")))
                    or not isinstance(selection, dict) or selection.get("candidate") != key
                    or self.hub.active_connections.get(worker) is not socket):
                job.update(state="failed", code="worker_changed")
                return
            reply = await asyncio.wait_for(self.hub.request_response(
                worker, "LLM_ACTIVATE", {"candidate": key}, timeout=QUALIFY_TIMEOUT), QUALIFY_TIMEOUT + 5)
            envelope = reply.get("payload", {}) if isinstance(reply, Mapping) else None
            data = envelope.get("data", reply) if isinstance(envelope, Mapping) else None
            if not isinstance(data, Mapping):
                data = {}
            if self.hub.active_connections.get(worker) is not socket or data.get("message") == SPOKE_TIMEOUT:
                job.update(state="failed", code="dispatch_outcome_unknown")
                return
            expected = CANDIDATES[key]
            passed = (data.get("status") == "SUCCESS" and data.get("code") == "activated"
                      and data.get("model") == expected["model"] and data.get("digest") == expected["digest"])
            code = data.get("code") if data.get("code") in (
                "candidate_not_smoke_tested", "operator_catalog_override", "activation_failed",
                "activation_rollback_failed", "runtime_version_mismatch", "preparation_state_failed", "busy") else (
                "activated" if passed else "unsupported_or_invalid_reply")
            job.update(state="passed" if passed else "failed", code=code)
            if passed:
                job.update(model=expected["model"], digest=expected["digest"])
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
            job["elapsed_s"] = round(time.monotonic() - started, 3)
            self._finish(job)

    async def _qualify(self, worker, socket, key, job, bootstrap=False, request_id=None, revision=None,
                       auto=False):
        """Store only validated qualification results from the reserved socket."""
        start = time.monotonic()
        try:
            candidate = self.qualification_candidates().get(key) if not bootstrap else None
            metadata = self.hub.state.system_state.get("module_metadata", {}).get(worker, {})
            valid = (isinstance(metadata, dict) and metadata.get("module_type") == "llm"
                     and self.hub.approved_modules.get(worker)
                     and (auto or tenant_is_shared(metadata.get("tenant_id"))))
            if (not valid or (not bootstrap and (not candidate or candidate[0] != worker))
                    or self.hub.active_connections.get(worker) is not socket):
                job.update(state="failed", code="worker_changed")
                return
            reply = await asyncio.wait_for(self.hub.request_response(
                worker, "LLM_PREPARE" if bootstrap else "LLM_QUALIFY",
                {"candidate": key, **({"request_id": request_id, "revision": revision} if bootstrap else {})},
                timeout=QUALIFY_TIMEOUT), QUALIFY_TIMEOUT + 5)
            envelope = reply.get("payload", {}) if isinstance(reply, Mapping) else None
            data = envelope.get("data", reply) if isinstance(envelope, Mapping) else None
            if not isinstance(data, Mapping):
                data = {}
            if self.hub.active_connections.get(worker) is not socket:
                job.update(state="failed", code="worker_changed")
                return
            if bootstrap and data.get("status") == "SUCCESS":
                expected = CANDIDATES[key]
                if (data.get("mode") != "bootstrap" or data.get("model") != expected["model"]
                        or data.get("digest") != expected["digest"]
                        or data.get("options") != expected["options"]):
                    job.update(state="failed", code="unsupported_or_invalid_reply")
                    return
            code = data.get("code")
            if data.get("message") == SPOKE_TIMEOUT:
                code = "dispatch_outcome_unknown"
            elif code not in ("qualified", "bootstrap_smoke_passed", "fixture_mismatch", "baseline_fixture_mismatch", "candidate_not_provisioned",
                            "runtime_version_mismatch", "candidate_pull_failed",
                            "candidate_digest_mismatch", "candidate_runtime_install_failed", "preparation_state_failed",
                            "preparation_superseded",
                            "qualification_runtime_failed",
                            "baseline_unavailable", "busy"):
                code = "unsupported_or_invalid_reply"
            result, baseline = qualification_result(data), qualification_result(data.get("baseline"))
            bootstrap = data.get("mode") == "bootstrap"
            options = data.get("options")
            sampling = model_sampling(options) if isinstance(options, dict) else None
            valid_options = sampling is not None and options.keys() <= SAMPLING_LIMITS.keys()
            if bootstrap and result and valid_options and "num_ctx" in options:
                job.update(result, mode="bootstrap", options=dict(sampling))
            if result and baseline:
                job.update(result, baseline=baseline)
                if valid_options:
                    job["options"] = dict(sampling)
                job["fixture_deltas"] = [
                    {"fixture": after["fixture"], "pass_delta": int(after["passed"]) - int(before["passed"]),
                     **({"elapsed_s_delta": round(after["elapsed_s"] - before["elapsed_s"], 3)}
                        if "elapsed_s" in after and "elapsed_s" in before else {})}
                    for after, before in zip(result["fixtures"], baseline["fixtures"])
                ]
            passed = (result and data.get("status") == "SUCCESS" and (
                bootstrap and not baseline and valid_options and "num_ctx" in options and code == "bootstrap_smoke_passed"
                and all(row["passed"] for row in result["fixtures"])
                or not bootstrap and baseline and (options is None or valid_options) and code == "qualified"
                and all(row["passed"] for row in result["fixtures"] + baseline["fixtures"])))
            if code in ("qualified", "bootstrap_smoke_passed") and not passed:
                code = "unsupported_or_invalid_reply"
            job.update(state="passed" if passed else "failed", code=code)
        except asyncio.CancelledError:
            job.update(state="failed", code="dispatch_outcome_unknown")
            raise
        except (TimeoutError, ConnectionError):
            job.update(state="failed", code="dispatch_outcome_unknown")
        finally:
            if request_id:
                if job.get("code") in ("dispatch_outcome_unknown", "worker_changed", "busy",
                                       "preparation_state_failed"):
                    self.bootstrap_retry_at[worker] = time.monotonic() + 120
                else:
                    self.bootstrap_done[worker] = request_id
                    self.bootstrap_retry_at.pop(worker, None)
            if job.get("code") in QUALIFICATION_GUIDANCE:
                job["resolution"] = QUALIFICATION_GUIDANCE[job["code"]]
            self.reserved.discard(worker)
            self.qualification_jobs.pop(worker, None)
            job["elapsed_s"] = round(time.monotonic() - start, 3)
            self._finish(job)


    def report(self, key, websocket, data):
        """Accept bounded catalog metadata only from the current approved socket."""
        hub = self.hub
        if (hub.spoke_module_types.get(key) != "llm"
                or not hub.approved_modules.get(key)
                or hub.active_connections.get(key) is not websocket
                or not isinstance(data, dict)):
            return
        job = self.qualification_jobs.get(key)
        phase = data.get("provision_phase")
        if job and job.get("kind") == "bootstrap" and phase in ("runtime", "pull", "fixtures"):
            job["phase"] = phase
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
            self.reconcile_bootstrap(key)
            return
        self.start_attempts.pop(key, None)
        approved = {name: digest for name, digest in models.items() if valid_model(name, digest)}
        self.inventory[key] = (time.monotonic(), websocket, approved, data.get("available") is True)
        options = data.get("supported_options")
        self.worker_options[key] = (
            {name for name in options if isinstance(name, str) and name in SAMPLING_LIMITS}
            if isinstance(options, list) and len(options) <= len(SAMPLING_LIMITS)
            else LEGACY_OPTIONS.copy() if "supported_options" not in data else set()
        )
        version = data.get("version")
        if isinstance(version, str) and re.fullmatch(r"\d{1,5}\.\d{1,5}\.\d{1,5}", version):
            self.runtime_versions[key] = version
        else:
            self.runtime_versions.pop(key, None)
        if not approved:
            self._set_worker_issue(key, "no_matching_models")
        else:
            self._clear_worker_issue(key)
        self.reconcile_bootstrap(key)

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
        self.worker_options.pop(key, None)
        self.worker_issues.pop(key, None)
        self.start_attempts.pop(key, None)
        self.provision_skipped.pop(key, None)

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
            self._finish(job)

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
        # Decide before dispatching, without recording anything, which artifacts
        # could be served by a connected worker that is merely busy. Only then is
        # a miss worth waiting for; otherwise no_capacity is recorded as usual.
        wait = queue_wait(self.hub.state.get_global_config())
        capable = ([a for a in artifacts if self._could_serve_soon(tenant, [a])]
                   if wait and self.queued < MAX_QUEUED else [])
        result = await self._try_artifacts(
            tenant, prompt, artifacts, output_format, quiet=bool(capable))
        if result is not None:
            return result
        if capable:
            result = await self._queue(tenant, prompt, artifacts, capable[0], output_format, wait)
            if result is not None:
                return result
        return {"status": "ERROR", **diagnostic("no_capacity"), "retryable": True}

    async def _try_artifacts(self, tenant, prompt, artifacts, output_format,
                             quiet=False, queued_job=None, ticket=None):
        """Try each artifact once in order; return the first result or None for no capacity.

        quiet leaves a no-capacity miss unrecorded, because the caller will queue
        the request and record one row for it later. queued_job is that row: it
        becomes the first attempt's running row instead of a new one.
        """
        for index, (model, digest, minimums, sampling) in enumerate(artifacts):
            started = time.monotonic()
            reused = queued_job is not None  # a missed attempt hands the row back, so any artifact may own it
            job = queued_job if reused else {"kind": "inference", "tier": "local"}
            queued_identity = (job.get("model"), job.get("digest"))
            job.update(state="running", model=model, digest=digest)
            self.active_jobs[id(job)] = job
            try:
                result = await self._dispatch(
                    tenant, prompt, model, digest, output_format, job, minimums, sampling, ticket)
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
                if job["state"] == "no_capacity" and quiet:
                    if reused:  # hand the waiting row back untouched
                        job.update(state="queued", model=queued_identity[0], digest=queued_identity[1])
                        job.pop("code", None)
                else:
                    job["elapsed_s"] = round(time.monotonic() - started, 3)
                    self._finish(job)
        return None

    async def _queue(self, tenant, prompt, artifacts, first, output_format, wait):
        """Hold one "queued" row for the first queue-capable artifact; None when the wait expires.

        The row becomes "running" when a worker frees up and is finished once,
        by the dispatch, with its real outcome; an expired wait is finished here once as
        no_capacity, a cancelled one as cancelled (not counted as a capacity shortage).
        """
        job = {"kind": "inference", "state": "queued", "model": first[0],
               "digest": first[1], "tier": "local"}
        if self.queued >= MAX_QUEUED:
            # Admission is re-checked here, with no await before the increment below,
            # because complete()'s earlier check can be stale after its dispatch awaited.
            job.update(state="no_capacity", code="no_capacity", elapsed_s=0)
            self._finish(job)
            return None
        started = time.monotonic()
        deadline = started + wait
        self.active_jobs[id(job)] = job
        self.queued += 1
        ticket = {"tenant": tenant, "artifacts": artifacts, "deadline": deadline, "waiting": True}
        self.waiters.append(ticket)
        step = min(QUEUE_POLL_S, wait / 4)  # a short wait still gets several polls before its deadline
        waiting = True  # False once a dispatch attempt owns the row's final record
        try:
            while time.monotonic() < deadline:
                # asyncio.sleep keeps the event loop free; cancellation propagates.
                await asyncio.sleep(max(0, min(step, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break  # the wait expired while sleeping; never dispatch after the deadline
                if not self._could_serve_soon(tenant, artifacts):
                    break  # the pool lost its last capable worker; waiting is pointless
                idle = [a for a in artifacts if self._has_idle_worker(tenant, a)]
                if not idle:
                    continue
                waiting = ticket["waiting"] = False
                result = await self._try_artifacts(
                    tenant, prompt, idle, output_format, quiet=True, queued_job=job, ticket=ticket)
                if result is not None:
                    return result  # never replay after a dispatched or ambiguous result
                waiting = ticket["waiting"] = True
                self.active_jobs[id(job)] = job  # lost a race; keep waiting
            return None
        except asyncio.CancelledError:
            if waiting:  # once a dispatch owns the row, its outcome is ambiguous and recorded there
                job.update(state="cancelled", code="cancelled")
            raise
        finally:
            self.queued -= 1
            self.waiters.remove(ticket)
            self.active_jobs.pop(id(job), None)
            if waiting:
                job["elapsed_s"] = round(time.monotonic() - started, 3)
                self._finish(job)  # records an expired wait as no_capacity and a cancelled one as cancelled

    def _older_waiter_wants(self, key, ticket):
        """True when a queued job older than ``ticket`` (any, for a new request) could use worker ``key``.

        Checked at each worker claim so waiters are served oldest first, while a
        younger job may still use a worker no older waiter can use. A ticket whose
        dispatch is in flight is not waiting and blocks nobody.
        """
        if not self.waiters:
            return False
        now = time.monotonic()
        for other in self.waiters:
            if other is ticket:
                break
            if (other["waiting"] and other["deadline"] > now
                    and any(self._eligible(key, other["tenant"], model, digest, minimums, sampling)
                            for model, digest, minimums, sampling in other["artifacts"])):
                return True
        return False

    def _has_idle_worker(self, tenant, artifact):
        """True when some tenant worker can take this artifact right now."""
        model, digest, minimums, sampling = artifact
        return any(self._eligible(key, tenant, model, digest, minimums, sampling)
                   for key in self._tenant_workers(tenant))

    def _could_serve_soon(self, tenant, artifacts):
        """True when a connected approved worker holds an artifact but is busy or provisioning.

        A role being unloaded closes its hub socket before it drains (agent_spoke._stop_role),
        and eligibility requires the live socket, so a stopping worker never counts here.
        """
        return any(self._eligible(key, tenant, model, digest, minimums, sampling, busy_ok=True)
                   for model, digest, minimums, sampling in artifacts
                   for key in self._tenant_workers(tenant))

    def _job_models(self, data):
        """Resolve an exact request or the operator's ordered local task profile."""
        if "task" not in data:
            model, digest = data.get("model"), data.get("digest")
            return [(model, digest, (0, 0), ())] if valid_model(model, digest) else []
        task = data["task"]
        if not isinstance(task, str) or "model" in data or "digest" in data:
            return []
        profiles = self.hub.state.get_global_config().get("llm_task_models")
        # The operator's entry, when present, wins; otherwise use the built-in default map.
        if isinstance(profiles, dict) and task in profiles:
            approved = profiles[task]
        else:
            approved = default_task_models(task)
        if not isinstance(approved, list):
            return []
        return list(dict.fromkeys((row["model"], row["digest"], minimums, sampling)
                                  for row in approved[:8]
                                  if isinstance(row, dict)
                                  and valid_model(row.get("model"), row.get("digest"))
                                  and (minimums := model_minimums(row)) is not None
                                  and (sampling := model_sampling(row)) is not None))

    async def _dispatch(self, tenant, prompt, model, digest, output_format, job, minimums,
                        sampling=(), ticket=None):
        """Try one artifact across its eligible workers, or return no capacity."""
        request = {"prompt": prompt, "model": model, "digest": digest, "format": output_format}
        if sampling:
            request["options"] = dict(sampling)
        # Least-recently-dispatched first (never-used = 0), so idle workers win and
        # load spreads; recheck all claims before each dispatch.
        workers = sorted(self._tenant_workers(tenant),
                         key=lambda key: (self.last_dispatch.get(key, 0), key))
        for key in workers:
            if (not self._eligible(key, tenant, model, digest, minimums, sampling)
                    or self._older_waiter_wants(key, ticket)):
                continue  # no await between this check and the reservation below
            job["version"] = self.runtime_versions.get(key)
            self.reserved.add(key)
            started = self.last_dispatch[key] = time.monotonic()
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

    def _eligible(self, key, tenant, model, digest, minimums=(0, 0), sampling=(), busy_ok=False):
        """Use fresh live status only; a stale snapshot cannot authorize routing.

        busy_ok ignores only the busy/reserved/provisioning state, to ask whether
        the worker could serve the job once it frees up.
        """
        status = self.inventory.get(key)
        if not status or (key in self.reserved and not busy_ok) or key not in self._tenant_workers(tenant):
            return False
        # Older workers may ignore options; never silently lose context or sampling.
        required = {name for name, _ in sampling}
        if not required <= self.worker_options.get(key, set()):
            return False
        seen, websocket, models, available = status
        if any(minimums):
            hardware = self.hardware.get(key)
            if (not hardware or hardware[1] is not websocket or time.monotonic() - hardware[0] >= 75
                    or any(hardware[2].get(field, 0) < minimum
                           for field, minimum in zip(HARDWARE_LIMITS, minimums))):
                return False
        return ((available or busy_ok) and time.monotonic() - seen < 75
                and self.hub.active_connections.get(key) is websocket
                and self.hub.spoke_module_types.get(key) == "llm"
                and not self.hub.is_draining(key)
                and models.get(model) == digest)
