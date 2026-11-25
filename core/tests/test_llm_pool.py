"""Verify scoped placement and CPU inference diagnostics."""

import asyncio
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import llm_pool
from llm_pool import LlmPool
from llm_candidates import CANDIDATES
import llm_cloud
from llm_cloud import PublicHTTPSConnection, valid_endpoint
from log_redaction import _redact
from routes import llm


DIGEST = "a" * 64
JOB = {"model": "test:latest", "digest": DIGEST, "prompt": "synthetic fixture"}


@pytest.mark.parametrize("field", ["max_tokens", "max_completion_tokens"])
def test_cloud_profiles_send_only_the_configured_output_limit(monkeypatch, field):
    """Never retry a paid request merely to negotiate its token-limit field."""
    from unittest.mock import Mock
    connection = Mock()
    connection.getresponse.return_value = SimpleNamespace(status=429)
    monkeypatch.setattr(llm_cloud, "PublicHTTPSConnection", lambda *args, **kwargs: connection)
    result = llm_cloud.complete_public(
        "https://provider.example.com/v1/chat/completions", "test", "synthetic", "fixture", field)
    assert result["code"] == "cloud_rate_limit"
    connection.request.assert_called_once()
    body = json.loads(connection.request.call_args.args[2])
    assert {name: body[name] for name in llm_cloud.TOKEN_LIMIT_FIELDS if name in body} == {field: 1024}


def make_pool():
    """Build live own, shared and foreign workers with matching catalogs."""
    owners = {"a": "tenant-a", "b": "tenant-a", "c": "shared", "d": "tenant-b"}
    hub = SimpleNamespace(
        active_connections={key: object() for key in owners},
        approved_modules=dict.fromkeys(owners, True),
        spoke_module_types=dict.fromkeys(owners, "llm"),
        is_draining=lambda key: False,
        _primary_key=lambda key: key,
        request_response=AsyncMock(),
        state=SimpleNamespace(
            get_global_config=dict,
            get_tenant=lambda name: name in owners.values(),
            get_module_name=lambda key: f"Worker {key}",
            system_state={"module_metadata": {
                key: {"tenant_id": tenant, "module_type": "llm"}
                for key, tenant in owners.items()
            }},
        ),
    )
    pool = LlmPool(hub)
    hub.state.system_state["global_config"] = {}
    hub.state.get_global_config = lambda: hub.state.system_state["global_config"]
    hub.state.update_global_config = lambda value: hub.state.system_state["global_config"].update(value)
    hub.state.save_state_now = AsyncMock()
    for key, socket in hub.active_connections.items():
        pool.report(key, socket, {
            "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
        })
    return pool


def test_clear_finished_jobs_keeps_running_jobs_and_returns_count():
    """Clearing removes only terminal history rows, and reports how many went."""
    pool = make_pool()
    pool.jobs.extend([{"state": "passed"}, {"state": "failed"}])
    pool.active_jobs["run"] = {"state": "running"}
    pool.qualification_jobs["qual"] = {"state": "running"}
    assert pool.clear_finished_jobs() == 2
    assert len(pool.jobs) == 0
    assert set(pool.active_jobs) == {"run"}
    assert set(pool.qualification_jobs) == {"qual"}


def test_metrics_accumulate_per_model_and_survive_clearing_job_rows():
    """Performance totals are kept for evaluation when the finished rows are cleared."""
    pool = make_pool()
    base = {"model": "m", "tier": "local", "digest": "d", "version": "1", "kind": "inference"}
    pool._finish({**base, "state": "passed", "elapsed_s": 10.0})
    pool._finish({**base, "state": "failed", "elapsed_s": 30.0})
    pool._finish({**base, "state": "no_capacity"})
    assert pool.clear_finished_jobs() == 3
    (row,) = pool.metric_rows.values()
    assert (row["completed"], row["failed"], row["no_capacity"]) == (1, 1, 1)
    assert row["mean_elapsed_s"] == 20.0


def test_finish_never_leaves_a_running_row_in_history():
    """A job that ends unresolved is recorded as failed so Clear can remove it."""
    pool = make_pool()
    job = {"state": "running", "model": "m", "tier": "local", "kind": "qualification", "elapsed_s": 1.0}
    pool._finish(job)
    assert pool.jobs[0]["state"] == "failed"


def test_metric_rows_are_bounded():
    """Unique model/digest values cannot grow the metrics table past its cap."""
    pool = make_pool()
    for i in range(llm_pool.MAX_METRIC_ROWS + 20):
        pool._finish({"state": "passed", "model": f"m{i}", "tier": "local", "kind": "inference", "elapsed_s": 1.0})
    assert len(pool.metric_rows) == llm_pool.MAX_METRIC_ROWS


def test_clear_jobs_route_requires_admin_and_returns_removed_count():
    """The clear route is admin-only and reports the pool's removed count."""
    app = FastAPI()
    pool = SimpleNamespace(clear_finished_jobs=lambda: 3)
    session = {"role": "tenant_admin"}
    ctx = SimpleNamespace(_session_user=lambda request: session,
                          _is_admin=lambda user: user["role"] == "global_admin")
    llm.register(app, SimpleNamespace(llm_pool=pool), ctx)
    with TestClient(app) as client:
        assert client.post("/api/llm/admin/jobs/clear").status_code == 403
        session["role"] = "global_admin"
        response = client.post("/api/llm/admin/jobs/clear")
        assert response.status_code == 200
        assert response.json() == {"status": "cleared", "removed": 3}


def test_admin_llm_routes_reject_non_admin_before_using_pool():
    """Fleet diagnostics and qualification are not tenant-admin operations."""
    app = FastAPI()
    pool = SimpleNamespace(dashboard=lambda: pytest.fail("unauthorized read"),
                           start_qualification=lambda key: pytest.fail("unauthorized dispatch"))
    ctx = SimpleNamespace(_session_user=lambda request: {"role": "tenant_admin"},
                          _is_admin=lambda session: False)
    llm.register(app, SimpleNamespace(llm_pool=pool), ctx)
    with TestClient(app) as client:
        assert client.get("/api/llm/admin/dashboard").status_code == 403
        assert client.post("/api/llm/admin/qualify", json={"candidate": "cpu"}).status_code == 403
        assert client.post("/api/llm/admin/prepare", json={"worker": "c", "candidate": "gemma4-12b"}).status_code == 403
        assert client.post("/api/llm/admin/activate", json={"worker": "c", "candidate": "gemma4-12b"}).status_code == 403
        assert client.get("/api/llm/admin/settings").status_code == 403
        assert client.post("/api/llm/admin/settings", json={"llm_cloud_profiles": []}).status_code == 403


def test_admin_settings_supply_exact_candidate_options():
    """Task forms can prefill settings only for the pinned model artifact."""
    pool = make_pool()
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(
        _session_user=lambda request: {"role": "admin"}, _is_admin=lambda session: True))
    with TestClient(app) as client:
        candidates = client.get("/api/llm/admin/settings").json()["public_candidates"]
    for candidate in candidates:
        expected = CANDIDATES[candidate["key"]]
        assert candidate["model"] == expected["model"]
        assert candidate["digest"] == expected["digest"]
        assert candidate["options"] == expected["options"]


def test_admin_cloud_settings_persist_and_return_only_vault_reference(monkeypatch):
    """Reject mismatched ownership and strip any inline key from accepted records."""
    pool = make_pool()
    state = pool.hub.state
    state._mark_dirty = lambda: None
    state.get_global_config = lambda: state.system_state.get("global_config", {})
    validate = AsyncMock()
    monkeypatch.setattr(llm.instance_vault, "validate_ref", validate)
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(
        _session_user=lambda request: {"role": "admin"}, _is_admin=lambda session: True))
    profile = {"url": "https://provider.example.com/v1/chat/completions", "model": "test",
               "tenant": "tenant-a", "task": "pr_summary", "api_key": "synthetic",
               "vault_credential": {"bucket": "tenant-b", "name": "summary"}}
    with TestClient(app) as client:
        path = "/api/llm/admin/settings"
        assert client.post(path, json={"llm_cloud_profiles": [profile]}).status_code == 400
        validate.assert_not_called()
        profile["vault_credential"]["bucket"] = "tenant-a"
        assert client.post(path, json={"llm_cloud_profiles": [profile]}).status_code == 200
        stored = state.get_global_config()["llm_cloud_profiles"][0]
        assert "api_key" not in stored
        stored["api_key"] = "synthetic legacy value"
        response = client.get(path)
        assert response.status_code == 200 and "synthetic" not in response.text
    validate.assert_awaited_once()


def test_qualification_reserves_only_shared_test_worker_and_handles_old_reply():
    """Qualification cannot touch a tenant-owned worker or use it for serving."""
    pool = make_pool()
    pool.hub.state.get_global_config = lambda: {"llm_qualification_candidates": {
        "cpu": {"worker": "c", "label": "CPU trial"},
        "owned": {"worker": "a", "label": "Not a test worker"},
    }}
    entered = asyncio.Event()
    release = asyncio.Event()

    async def old_peer(*args, **kwargs):
        """Hold the slot until the older spoke's error arrives."""
        entered.set()
        await release.wait()
        return {"payload": {"data": {"status": "ERROR", "message": "Unknown command"}}}

    async def exercise():
        """Verify reservation and the resulting terminal state."""
        assert not pool.start_qualification("owned")
        assert pool.start_qualification("cpu")
        assert not pool.start_qualification("cpu")
        await entered.wait()
        assert pool.dashboard()["jobs"][0]["state"] == "running"
        assert (await pool.complete("tenant-without-workers", JOB))["code"] == "no_capacity"
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_qualify")
        release.set()
        await task

    pool.hub.request_response.side_effect = old_peer
    asyncio.run(exercise())
    assert pool.hub.request_response.call_args.args[:2] == ("c", "LLM_QUALIFY")
    assert pool.dashboard()["jobs"][0]["code"] == "unsupported_or_invalid_reply"
    assert not pool.reserved


def test_bootstrap_smoke_can_run_on_shared_worker_without_serving_runtime():
    """A first-worker smoke pass is distinct from comparative qualification."""
    pool = make_pool()
    pool.hub.state.get_global_config = lambda: {"llm_qualification_candidates": {
        "cpu": {"worker": "c", "label": "CPU trial"},
        "owned": {"worker": "a", "label": "Not shared"},
    }}
    pool.report("c", pool.hub.active_connections["c"], {
        "status": "ERROR", "code": "runtime_not_started", "detail_code": "runtime_binary_missing",
        "capabilities": {"mode": "cpu"},
    })
    pool.hub.request_response.return_value = {
        "status": "SUCCESS", "code": "bootstrap_smoke_passed", "mode": "bootstrap",
        "model": JOB["model"], "digest": DIGEST, "version": "0.40.16",
        "options": {"num_ctx": 65536, "temperature": 0.7},
        "fixtures": [{"fixture": "json", "passed": True, "elapsed_s": 1},
                     {"fixture": "indentation", "passed": True, "elapsed_s": 2}],
    }

    async def exercise():
        """Only the configured shared worker can be reserved."""
        assert not pool.start_qualification("owned")
        assert pool.start_qualification("cpu")
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_qualify")
        await task

    asyncio.run(exercise())
    job = pool.dashboard()["jobs"][0]
    assert job["code"] == "bootstrap_smoke_passed" and job["mode"] == "bootstrap"
    assert job["options"]["num_ctx"] == 65536
    assert job["resolution"] == "The synthetic smoke test passed; this is not model certification."
    assert "baseline" not in job


def test_public_candidate_prepares_on_any_approved_llm_worker_but_not_other_modules():
    """Preparation is no longer Shared-only, but still needs an approved LLM module."""
    pool = make_pool()
    pool.report("c", pool.hub.active_connections["c"], {
        "status": "ERROR", "code": "runtime_not_started", "detail_code": "runtime_binary_missing",
        "capabilities": {"mode": "cpu"},
    })
    candidate = CANDIDATES["gemma4-12b"]
    pool.hub.request_response.return_value = {
        "status": "SUCCESS", "code": "bootstrap_smoke_passed", "mode": "bootstrap",
        "model": candidate["model"], "digest": candidate["digest"], "version": "0.40.16",
        "options": candidate["options"],
        "fixtures": [{"fixture": "json", "passed": True}, {"fixture": "indentation", "passed": True}],
    }

    async def exercise():
        """Check reservation, valid identity and the final diagnostic."""
        pool.hub.state.system_state["module_metadata"]["d"]["module_type"] = "nw"
        assert not await pool.start_bootstrap("d", "gemma4-12b")
        assert not await pool.start_bootstrap("c", "unapproved")
        assert await pool.start_bootstrap("c", "gemma4-12b")
        assert not await pool.start_bootstrap("c", "gemma4-12b")
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_qualify")
        await task

    asyncio.run(exercise())
    assert pool.hub.request_response.call_args.args[:2] == ("c", "LLM_PREPARE")
    sent = pool.hub.request_response.call_args.args[2]
    saved = pool.hub.state.get_global_config()["llm_worker_preparations"]["c"]
    assert sent == saved and sent["candidate"] == "gemma4-12b" and len(sent["request_id"]) == 32
    pool.hub.state.save_state_now.assert_awaited_once()
    assert pool.dashboard()["jobs"][0]["code"] == "bootstrap_smoke_passed"


def test_public_candidate_reconnect_replays_same_persisted_request():
    """A lost reply is resumed with the same id rather than starting a new download."""
    pool = make_pool()
    pool.hub.request_response.side_effect = [
        ConnectionError("disconnected"),
        {"status": "ERROR", "code": "candidate_digest_mismatch"},
    ]

    async def exercise():
        """A new authenticated report reconnects the existing assignment."""
        assert await pool.start_bootstrap("c", "gemma4-12b")
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_qualify")
        await task
        assert pool.dashboard()["jobs"][0]["code"] == "dispatch_outcome_unknown"
        pool.bootstrap_retry_at["c"] = 0
        pool.report("c", pool.hub.active_connections["c"], {
            "status": "SUCCESS", "models": {}, "available": False,
            "capabilities": {"mode": "cpu"},
        })
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_qualify")
        await task

    asyncio.run(exercise())
    assert pool.hub.request_response.call_args_list[0].args[2] == pool.hub.request_response.call_args_list[1].args[2]
    assert pool.dashboard()["jobs"][0]["code"] == "candidate_digest_mismatch"
    pool.hub.state.save_state_now.assert_awaited_once()


def test_failed_preparation_save_does_not_dispatch_new_request():
    """A failed save cannot be dispatched later by a status report."""
    pool = make_pool()
    pool.hub.state.save_state_now.side_effect = OSError("disk failure")

    async def exercise():
        """A failed durable write removes the pending in-memory selection."""
        with pytest.raises(OSError):
            await pool.start_bootstrap("c", "gemma4-12b")
        pool.reconcile_bootstrap("c")
        await asyncio.sleep(0)
        assert not pool.hub.state.get_global_config()["llm_worker_preparations"]
        assert not pool.reserved
        pool.hub.request_response.assert_not_awaited()

    asyncio.run(exercise())


def test_activation_is_scoped_to_selected_llm_worker():
    """Only a worker with a matching saved preparation may be activated, and only LLM modules."""
    pool = make_pool()
    pool.hub.state.update_global_config({"llm_worker_preparations": {
        "c": {"candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1},
        "a": {"candidate": "gemma4-12b", "request_id": "b" * 32, "revision": 1},
        "d": {"candidate": "gemma4-12b", "request_id": "c" * 32, "revision": 1},
    }})
    pool.hub.state.system_state["module_metadata"]["d"]["module_type"] = "nw"
    candidate = CANDIDATES["gemma4-12b"]
    pool.hub.request_response.return_value = {"status": "SUCCESS", "code": "activated",
                                              "model": candidate["model"], "digest": candidate["digest"]}

    async def exercise():
        """A non-LLM module or a mismatched key is rejected; a tenant-owned worker is not."""
        assert not pool.start_activation("d", "gemma4-12b")
        assert not pool.start_activation("a", "qwen38-scout")
        assert not pool.start_activation("c", "qwen38-scout")
        assert pool.start_activation("c", "gemma4-12b")
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_activate")
        await task

    asyncio.run(exercise())
    assert pool.hub.request_response.call_args.args[:3] == ("c", "LLM_ACTIVATE", {"candidate": "gemma4-12b"})
    assert pool.dashboard()["jobs"][0]["code"] == "activated"


@pytest.mark.parametrize("options", [{}, {"num_ctx": True}, {"num_ctx": 65536, "num_gpu": 1}])
def test_bootstrap_rejects_success_with_missing_or_invalid_options(options):
    """A malformed worker reply cannot claim a configured-settings smoke pass."""
    pool = make_pool()
    pool.hub.state.get_global_config = lambda: {"llm_qualification_candidates": {
        "cpu": {"worker": "c", "label": "CPU trial"},
    }}
    pool.hub.request_response.return_value = {
        "status": "SUCCESS", "code": "bootstrap_smoke_passed", "mode": "bootstrap",
        "model": JOB["model"], "digest": DIGEST, "version": "0.40.16", "options": options,
        "fixtures": [{"fixture": "json", "passed": True},
                     {"fixture": "indentation", "passed": True}],
    }

    async def exercise():
        """Wait for the malformed reply to be processed."""
        assert pool.start_qualification("cpu")
        task = next(t for t in asyncio.all_tasks() if t.get_coro().__name__ == "_qualify")
        await task

    asyncio.run(exercise())
    job = pool.dashboard()["jobs"][0]
    assert job["state"] == "failed" and job["code"] == "unsupported_or_invalid_reply"


def test_pool_tries_second_own_worker_and_never_spills_to_shared():
    """A busy refusal can be retried; an offline own pool still hides Shared."""
    pool = make_pool()
    pool.hub.request_response.side_effect = [
        {"payload": {"data": {"status": "ERROR", "code": "busy"}}},
        {"status": "SUCCESS", "text": "valid slow result",
         "metrics": {"eval_duration": 120_000_000_000}},
    ]
    result = asyncio.run(pool.complete("Tenant-A", JOB))
    assert result["metrics"]["eval_duration"] == 120_000_000_000
    assert [call.args[0] for call in pool.hub.request_response.call_args_list] == ["a", "b"]
    for key in ("a", "b"):
        pool.hub.active_connections.pop(key)
        pool.hub.spoke_module_types.pop(key)
    result = asyncio.run(pool.complete("tenant-a", JOB))
    assert result["code"] == "no_capacity"
    assert pool.hub.request_response.call_count == 2


def test_task_routes_only_to_workers_meeting_reported_guest_capacity():
    """Skip old peers and undersized workers without spilling into Shared."""
    pool = make_pool()
    gib = 1024**3
    pool.hub.state.get_global_config = lambda: {"llm_task_models": {"coding": [
        {"model": JOB["model"], "digest": DIGEST, "min_vcpus": 8, "min_ram_bytes": 16 * gib},
    ]}}
    for key, ram in (("b", 8 * gib), ("c", 32 * gib)):
        pool.report(key, pool.hub.active_connections[key], {
            "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
            "capabilities": {"mode": "cpu", "vcpus": 8, "ram_bytes": ram},
        })
    job = {"task": "coding", "prompt": JOB["prompt"]}
    assert asyncio.run(pool.complete("tenant-a", job))["code"] == "no_capacity"
    pool.hub.request_response.assert_not_called()
    pool.report("b", pool.hub.active_connections["b"], {
        "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
        "capabilities": {"mode": "cpu", "vcpus": 8, "ram_bytes": 16 * gib,
                         "arch": "x86_64", "cpu_model": "Test CPU", "extra": "ignored"},
    })
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "valid"}
    assert asyncio.run(pool.complete("tenant-a", job))["status"] == "SUCCESS"
    assert pool.hub.request_response.call_args.args[0] == "b"
    worker = next(row for row in pool.dashboard()["workers"] if row["name"] == "Worker b")
    assert worker["capabilities"] == {"mode": "cpu", "vcpus": 8, "ram_bytes": 16 * gib,
                                      "arch": "x86_64", "cpu_model": "Test CPU"}


def test_unavailable_runtime_still_reports_guest_capacity():
    """An Ollama error must not erase independent hardware observations."""
    pool = make_pool()
    capabilities = {"mode": "cpu", "vcpus": 8, "ram_bytes": 16 * 1024**3}
    pool.report("a", pool.hub.active_connections["a"], {
        "status": "ERROR", "code": "runtime_version_mismatch", "capabilities": capabilities,
    })
    worker = next(row for row in pool.dashboard()["workers"] if row["name"] == "Worker a")
    assert worker["state"] == "unavailable"
    assert worker["capabilities"] == capabilities
    pool.forget("a")
    assert not next(row for row in pool.dashboard()["workers"] if row["name"] == "Worker a")["capabilities"]


@pytest.mark.parametrize("code", ["runtime_unit_missing", "runtime_unit_symlink"])
def test_worker_issue_logs_only_transitions(caplog, code):
    """Repeated failure reports do not flood logs; recovery is visible."""
    pool = make_pool()
    socket = pool.hub.active_connections["a"]
    failure = {"status": "ERROR", "code": code}
    recovery = {"status": "SUCCESS", "models": {JOB["model"]: DIGEST},
                "available": True}

    with caplog.at_level(logging.INFO, logger="llm_pool"):
        pool.report("a", socket, failure)
        pool.report("a", socket, failure)
        pool.report("a", socket, recovery)

    assert caplog.text.count(f"LLM worker Worker a (a) unavailable: {code}") == 1
    assert f"LLM worker Worker a (a) recovered from {code}" in caplog.text
    assert pool.worker_issues.get("a") is None


def test_runtime_start_reply_is_logged_with_stable_code(caplog):
    """The hub records start failures without logging the raw reply."""
    pool = make_pool()
    pool.hub.request_response.return_value = {
        "payload": {"data": {"status": "ERROR", "code": "runtime_binary_missing"}}
    }

    with caplog.at_level(logging.WARNING, logger="llm_pool"):
        asyncio.run(pool._start_runtime("a", pool.hub.active_connections["a"]))

    assert "LLM worker Worker a (a) runtime start rejected: runtime_binary_missing" in caplog.text


@pytest.mark.parametrize(("report", "expected"), [
    ({"status": "ERROR", "code": []}, "runtime_unavailable"),
    ({"status": "ERROR", "code": {"x": 1}}, "runtime_unavailable"),
    ({"status": "ERROR", "code": "runtime_not_started", "detail_code": []},
     "runtime_not_started"),
    ({"status": "ERROR", "code": "runtime_not_started", "detail_code": {}},
     "runtime_not_started"),
])
def test_malformed_status_codes_fall_back_without_raising(report, expected):
    """Unhashable JSON codes map to a stable issue instead of raising TypeError."""
    pool = make_pool()
    pool.hub.state.system_state["module_metadata"]["a"]["tenant_id"] = ""

    pool.report("a", pool.hub.active_connections["a"], report)

    assert pool.worker_issues["a"]["code"] == expected


@pytest.mark.parametrize(("reply", "outcome"), [
    ({"status": "ERROR", "message": "Timed out waiting for spoke response"},
     "Timed out waiting for spoke response"),
    ({"status": "ERROR", "message": "Timed out waiting for spoke response",
      "updating": True, "draining": True}, "Timed out waiting for spoke response"),
    ({"payload": {"data": {"status": "ERROR", "code": "busy"}}}, "busy"),
    ({"payload": {"data": {"status": "ERROR", "code": ["runtime_binary_missing"]}}},
     "unrecognised reply"),
    ({"payload": {"data": ["not", "an", "object"]}}, "unrecognised reply"),
])
def test_unconfirmed_runtime_start_is_logged_as_unknown_outcome(caplog, reply, outcome):
    """A timeout, busy or malformed start reply never claims the runtime failed."""
    pool = make_pool()
    pool.hub.request_response.return_value = reply

    with caplog.at_level(logging.WARNING, logger="llm_pool"):
        asyncio.run(pool._start_runtime("a", pool.hub.active_connections["a"]))

    assert f"LLM worker Worker a (a) runtime start outcome unknown: {outcome}" in caplog.text
    assert "rejected" not in caplog.text
    # Only the next status report changes the issue or the retry schedule.
    assert not pool.worker_issues and not pool.start_attempts


@pytest.mark.parametrize("revoke", ["unbind", "unapprove"])
def test_runtime_start_never_reaches_unbound_or_unapproved_worker(revoke):
    """Revoking the tenant or approval also stops a start that is already scheduled."""
    pool = make_pool()
    socket = pool.hub.active_connections["b"]
    report = {"status": "ERROR", "code": "runtime_not_started"}

    def revoke_worker():
        """Unassign the worker's tenant or withdraw its approval."""
        if revoke == "unbind":
            pool.hub.state.system_state["module_metadata"]["b"]["tenant_id"] = ""
        else:
            pool.hub.approved_modules["b"] = False

    async def exercise():
        """Revoke between scheduling and sending, then report again."""
        pool.report("b", socket, report)
        assert "b" in pool.start_attempts
        revoke_worker()
        await asyncio.sleep(0)
        pool.start_attempts.clear()
        pool.report("b", socket, report)
        await asyncio.sleep(0)

    asyncio.run(exercise())
    pool.hub.request_response.assert_not_called()


def test_pool_uses_shared_only_for_tenant_without_its_own_pool():
    """Only Shared can supply work when the tenant owns no workers."""
    pool = make_pool()
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    assert asyncio.run(pool.complete("tenant-c", JOB))["status"] == "SUCCESS"
    assert pool.hub.request_response.call_args.args[0] == "c"


def test_task_uses_next_operator_approved_artifact_when_first_cannot_accept():
    """A named task can use another qualified artifact, never an arbitrary model."""
    pool = make_pool()
    pool.hub.state.get_global_config = lambda: {
        "llm_task_models": {"summary": [
            {"model": "preferred:latest", "digest": "b" * 64},
            {"model": JOB["model"], "digest": DIGEST},
        ]},
    }
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "summary"}
    result = asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "summary"}))
    assert result["model"] == JOB["model"]
    assert pool.hub.request_response.call_count == 1
    assert asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "unknown"}))[
        "code"] == "invalid_request"
    assert pool.hub.request_response.call_count == 1


def test_task_profile_sampling_is_validated_forwarded_and_applied(monkeypatch):
    """Sampling comes from the operator's profile row, never from the model's name."""
    pool = make_pool()
    state = pool.hub.state
    state._mark_dirty = lambda: None
    state.get_global_config = lambda: state.system_state.get("global_config", {})
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(
        _session_user=lambda request: {"role": "admin"}, _is_admin=lambda session: True))
    row = {"model": JOB["model"], "digest": DIGEST}
    with TestClient(app) as client:
        path = "/api/llm/admin/settings"
        for bad in ({"temperature": True}, {"temperature": 2.5}, {"top_p": -0.1}, {"top_p": "0.8"}):
            assert client.post(path, json={"llm_task_models": {"summary": [
                {**row, **bad}]}}).status_code == 400
        assert client.post(path, json={"llm_task_models": {"summary": [
            {**row, "temperature": 0.7, "top_p": 0.8}]}}).status_code == 200

    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "summary"}
    assert asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "summary"}))["status"] == "SUCCESS"
    assert pool.hub.request_response.call_args.args[2]["options"] == {"temperature": 0.7, "top_p": 0.8}
    pool.report("a", pool.hub.active_connections["a"], {
        "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
        "supported_options": ["temperature", "top_p"],
    })
    asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "summary"}))
    assert pool.hub.request_response.call_args.args[2]["options"] == {"temperature": 0.7, "top_p": 0.8}
    asyncio.run(pool.complete("tenant-a", JOB))
    assert "options" not in pool.hub.request_response.call_args.args[2]

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from agent.src import llm_spoke

    sent = []

    def fake_request(path, body=None, timeout=3):
        """Record the generate options a Gemma-named artifact receives."""
        if path == "/api/version":
            return {"version": "0.40.16"}
        if path == "/api/tags":
            return {"models": [{"name": "gemma-test:cpu", "digest": DIGEST}]}
        sent.append(body["options"])
        return {"done": True, "done_reason": "stop", "model": "gemma-test:cpu", "response": "ok"}

    monkeypatch.setattr(llm_spoke, "ollama_request", fake_request)
    worker = llm_spoke.LlmSpoke("test", {"models": {"gemma-test:cpu": DIGEST}})
    worker._service_started = True
    job = {"prompt": "fixture", "model": "gemma-test:cpu", "digest": DIGEST}
    assert asyncio.run(worker.handle_command("LLM_COMPLETE", job))["status"] == "SUCCESS"
    assert "temperature" not in sent[-1] and "top_p" not in sent[-1]
    asyncio.run(worker.handle_command("LLM_COMPLETE", {**job, "options": {"temperature": 0.7}}))
    assert sent[-1] == {"temperature": 0.7, "num_gpu": 0, "num_predict": 1024}
    for bad in ({"num_gpu": 1}, {"temperature": 3}, {"top_p": False}, ["temperature"]):
        assert asyncio.run(worker.handle_command(
            "LLM_COMPLETE", {**job, "options": bad}))["code"] == "invalid_request"
    assert len(sent) == 2


def test_context_and_sampling_require_support_and_reach_the_worker(monkeypatch):
    """Keep the selected model settings intact, and do not send them to old peers."""
    pool = make_pool()
    options = {"num_ctx": 65536, "temperature": 0.6, "top_p": 0.95,
               "top_k": 20, "repeat_penalty": 1.0}
    row = {"model": JOB["model"], "digest": DIGEST, **options}
    pool.hub.state.get_global_config = lambda: {"llm_task_models": {"coding": [row]}}
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "draft"}
    job = {"task": "coding", "prompt": "fixture"}

    assert asyncio.run(pool.complete("tenant-a", job))["code"] == "no_capacity"
    pool.hub.request_response.assert_not_awaited()
    pool.report("a", pool.hub.active_connections["a"], {
        "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
        "supported_options": list(options),
    })
    assert asyncio.run(pool.complete("tenant-a", job))["status"] == "SUCCESS"
    assert pool.hub.request_response.call_args.args[2]["options"] == options

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from agent.src import llm_spoke
    sent = []

    def request(path, body=None, timeout=None):
        """Return synthetic runtime status and record the completion options."""
        if path == "/api/version":
            return {"version": "0.40.16"}
        if path == "/api/tags":
            return {"models": [{"name": JOB["model"], "digest": DIGEST}]}
        sent.append(body)
        return {"done": True, "done_reason": "stop", "model": JOB["model"], "response": "draft"}

    monkeypatch.setattr(llm_spoke, "ollama_request", request)
    worker = llm_spoke.LlmSpoke("test", {"models": {JOB["model"]: DIGEST}})
    worker._service_started = True
    assert asyncio.run(worker.handle_command("LLM_COMPLETE", {**JOB, "options": options}))["status"] == "SUCCESS"
    assert sent[0]["think"] is False
    assert sent[0]["options"] == {**options, "num_gpu": 0, "num_predict": 1024}
    for bad in ({"num_ctx": 0}, {"num_ctx": 65536.5}, {"top_k": True},
                {"repeat_penalty": 0}, {"top_k": 257}):
        assert not llm_spoke.valid_sampling(bad)
        assert llm.model_sampling({**row, **bad}) is None


def test_certificate_bound_summary_only_falls_back_for_public_opt_in(monkeypatch):
    """Private or wrong-identity AB jobs cannot invoke cloud inference."""
    pool = make_pool()
    pool.hub.state.get_global_config = lambda: {
        "llm_ab_pr_repos": {"owner/repo": {
            "tenant": "tenant-a", "certificate": "ab.example.org", "allow_public_cloud": True,
        }},
    }
    monkeypatch.setattr(pool, "complete", AsyncMock(return_value={"code": "no_capacity"}))
    cloud = AsyncMock(return_value={"status": "SUCCESS", "tier": "cloud"})
    monkeypatch.setattr(pool, "_public_cloud_summary", cloud)
    job = {"repository": "owner/repo", "prompt": "synthetic", "tenant": "tenant-b"}
    assert asyncio.run(pool.ab_pr_summary(job, ("wrong.example.org",)))["code"] == "not_configured"
    assert asyncio.run(pool.ab_pr_summary(job, ("ab.example.org",)))["code"] == "no_capacity"
    cloud.assert_not_awaited()
    assert asyncio.run(pool.ab_pr_summary(
        {**job, "public": True}, ("ab.example.org",)))["tier"] == "cloud"
    assert cloud.call_args.args[:2] == ("tenant-a", "synthetic")


def test_cloud_rejects_internal_resolution_before_connect(monkeypatch):
    """A syntactically public name cannot resolve to an internal address."""
    import llm_cloud

    assert valid_endpoint("https://provider.example.org/v1/chat/completions")
    assert not valid_endpoint("https://user@provider.example.org/v1/chat/completions")
    monkeypatch.setattr(llm_cloud.socket, "getaddrinfo", lambda *args, **kwargs: [
        (None, None, None, None, ("127.0.0.1", 443)),
    ])
    monkeypatch.setattr(llm_cloud.socket, "create_connection",
                        lambda *args: pytest.fail("must not connect"))
    with pytest.raises(OSError):
        PublicHTTPSConnection("provider.example.org").connect()


def test_cloud_capacity_uses_only_same_tenant_vault_reference(monkeypatch):
    """Use the tenant's endpoint, never an inline key or Shared overflow."""
    pool = make_pool()
    endpoint = "https://provider.example.org/v1/chat/completions"
    own = {"url": endpoint, "tenant": "tenant-a", "task": "pr_summary", "model": "approved",
           "api_key": "must not be used", "vault_credential": {"bucket": "tenant-a", "name": "llm"}}
    shared = {**own, "tenant": "shared", "url": "https://shared.example.org/chat/completions",
              "vault_credential": {"bucket": "shared", "name": "llm"}}
    pool.hub.state.get_global_config = lambda: {"llm_cloud_profiles": [shared, own]}
    resolver = AsyncMock(return_value={"api_key": "synthetic-vault-key"})
    monkeypatch.setattr("llm_pool.instance_vault.overlay", resolver)
    from unittest.mock import Mock
    invoke = Mock(return_value={"status": "ERROR", "code": "cloud_rate_limit"})
    monkeypatch.setattr("llm_pool.llm_cloud.complete_public", invoke)
    unavailable = {"code": "no_capacity"}
    assert asyncio.run(pool._public_cloud_summary("tenant-a", "fixture", unavailable)) == unavailable
    assert asyncio.run(pool._public_cloud_summary("tenant-a", "fixture", unavailable)) == unavailable
    resolver.assert_awaited_once_with(pool.hub, {"vault_credential": own["vault_credential"]},
                                      "llm_cloud_profiles")
    invoke.assert_called_once_with(endpoint, "approved", "synthetic-vault-key", "fixture", "max_tokens")


def test_pool_does_not_replay_at_ambiguous_disconnect():
    """A job might already be running and must not be duplicated."""
    pool = make_pool()
    pool.hub.request_response.side_effect = ConnectionError()
    assert asyncio.run(pool.complete("tenant-a", JOB))["code"] == "dispatch_outcome_unknown"
    assert pool.hub.request_response.call_count == 1


def test_slow_cpu_reply_is_advisory_not_failure(monkeypatch):
    """A result near the wall deadline remains successful if valid."""
    pool = make_pool()
    import llm_pool

    start = pool.inventory["a"][0]
    # The first value serves the pre-dispatch queue-capability probe.
    clock = iter((start, start, start, start, start + 700, start + 700))
    monkeypatch.setattr(llm_pool, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "preserved"}
    result = asyncio.run(pool.complete("tenant-a", JOB))
    assert result["text"] == "preserved"
    assert result["status"] == "SUCCESS"
    assert result["issues"][0]["code"] == "slow_cpu_inference"


@pytest.mark.parametrize("code", ["inference_timeout", "invalid_python", "truncated_response"])
def test_pool_returns_actionable_safe_diagnostics(code):
    """Distinct failures surface guidance without echoing raw model content."""
    pool = make_pool()
    pool.hub.request_response.return_value = {
        "status": "ERROR", "code": code, "text": "private output",
    }
    result = asyncio.run(pool.complete("tenant-a", JOB))
    assert result["code"] == code and result["resolution"]
    assert "private output" not in str(result)


def test_api_rejects_forged_tenant_before_dispatch():
    """Tenant override cannot move work onto a different tenant's machines."""
    pool = make_pool()
    pool.hub.llm_pool = pool
    session = {"user": {"tenant_id": "tenant-a", "tenants": ["tenant-a"]}}
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(_session_user=lambda request: session))
    with TestClient(app) as client:
        response = client.post("/api/llm/complete?tenant=tenant-b", json=JOB)
        assert response.status_code == 403
        assert pool.hub.request_response.call_count == 0
        response = client.get("/api/llm/models")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("permissions", [{}, {"edit": True}])
def test_view_only_member_lists_models_but_cannot_run_jobs(permissions):
    """Inference holds a shared CPU slot, so it needs the write tier, not tenant membership."""
    pool = make_pool()
    pool.hub.llm_pool = pool
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    session = {"user": {"tenant_id": "tenant-a", "tenants": ["tenant-a"], "permissions": permissions}}
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(_session_user=lambda request: session))
    with TestClient(app) as client:
        assert client.get("/api/llm/models").status_code == 200
        ran = client.post("/api/llm/complete", json=JOB).status_code
        checked = client.post("/api/llm/check", json={**JOB, "fixture": "json"}).status_code
    if permissions:
        assert ran == checked == 200
    else:
        assert ran == checked == 403
        assert pool.hub.request_response.call_count == 0


def test_prompts_and_completions_are_not_debug_logged():
    """Both sides of the relay use the full-redaction command policy."""
    assert _redact("LLM_COMPLETE", JOB) == {"<redacted>": True}
    assert _redact("LLM_COMPLETE", {"text": "private reply"}) == {"<redacted>": True}


def test_fixture_reports_semantic_indentation_corruption():
    """A syntactically valid but changed branch fails without echoing output."""
    pool = make_pool()
    pool.hub.llm_pool = pool
    pool.hub.request_response.side_effect = [
        {"status": "SUCCESS", "text": "def classify(value):\n    if value > 0:\n        return 1\n    return 0\n"},
        {"status": "SUCCESS", "text": "def classify(value):\n    if value > 0:\n        return 1\n        return 0\n"},
    ]
    session = {"user": {"tenant_id": "tenant-a", "tenants": ["tenant-a"], "permissions": {"edit": True}}}
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(_session_user=lambda request: session))
    body = {**JOB, "fixture": "indentation", "prompt": "must not be forwarded"}
    with TestClient(app) as client:
        assert client.post("/api/llm/check", json=body).json()["status"] == "SUCCESS"
        result = client.post("/api/llm/check", json=body).json()
        assert result["code"] == "fixture_mismatch" and result["resolution"]
        assert "text" not in result
    assert "must not be forwarded" not in pool.hub.request_response.call_args.args[2]["prompt"]


def test_fixture_uses_selected_task_profile_options():
    """A synthetic task check measures the same options as a task job."""
    pool = make_pool()
    pool.hub.llm_pool = pool
    options = {"num_ctx": 65536, "temperature": 0.6, "top_k": 20}
    pool.hub.state.get_global_config = lambda: {
        "llm_task_models": {"coding": [{"model": JOB["model"], "digest": DIGEST, **options}]}
    }
    pool.report("a", pool.hub.active_connections["a"], {
        "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
        "supported_options": list(options),
    })
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": '{"items":[{"label":"CPU","count":2}]}'}
    session = {"user": {"tenant_id": "tenant-a", "tenants": ["tenant-a"], "permissions": {"edit": True}}}
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(_session_user=lambda request: session))
    with TestClient(app) as client:
        result = client.post("/api/llm/check", json={"task": "coding", "fixture": "json"}).json()
        assert result["status"] == "SUCCESS"
        assert client.post("/api/llm/check", json={
            "task": "coding", "model": JOB["model"], "fixture": "json",
        }).status_code == 400
    assert pool.hub.request_response.call_args.args[2]["options"] == options


@pytest.mark.parametrize(("response", "code"), [
    ({"done_reason": "length"}, "truncated_response"),
    ({"response": '{"items": ['}, "invalid_response"),
    ({"response": '{"items": ["\ufffd"]}'}, "invalid_response"),
    ({"model": "wrong-model"}, "invalid_response"),
    ({}, None),
])
def test_worker_validates_cpu_output(monkeypatch, response, code):
    """An unhurried valid reply passes; partial and corrupt output does not."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from agent.src import llm_spoke

    def fake_request(path, body=None, timeout=3):
        """Provide synthetic native Ollama replies and inspect its options."""
        if path == "/api/version":
            return {"version": "0.40.16"}
        if path == "/api/tags":
            return {"models": [{"name": JOB["model"], "digest": DIGEST}]}
        assert path == "/api/generate"
        assert body["options"]["num_gpu"] == 0
        assert body["think"] is False and body["stream"] is False
        assert body["format"] == "json" and timeout >= 600
        return {"done": True, "done_reason": "stop", "model": JOB["model"],
                "response": '{"items": ["valid"]}', "eval_duration": 120_000_000_000,
                **response}

    monkeypatch.setattr(llm_spoke, "ollama_request", fake_request)
    worker = llm_spoke.LlmSpoke("test", {"models": {JOB["model"]: DIGEST}})
    worker._service_started = True
    reply = asyncio.run(worker.handle_command("LLM_COMPLETE", {**JOB, "format": "json"}))
    assert reply.get("code") == code
    assert reply["status"] == ("ERROR" if code else "SUCCESS")


def test_worker_detects_corrupted_indentation_and_version_drift(monkeypatch):
    """Reject a corrupt draft and do not send prompts to an unqualified runtime."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from agent.src import llm_spoke

    version = "0.40.16"
    text = "def f():\nreturn 1\n"
    calls = []

    def fake_request(path, body=None, timeout=3):
        """Record requests and model the older corruption regression."""
        calls.append(path)
        if path == "/api/version":
            return {"version": version}
        if path == "/api/tags":
            return {"models": [{"name": JOB["model"], "digest": DIGEST}]}
        return {"done": True, "done_reason": "stop", "model": JOB["model"], "response": text}

    monkeypatch.setattr(llm_spoke, "ollama_request", fake_request)
    worker = llm_spoke.LlmSpoke("test", {"models": {JOB["model"]: DIGEST}})
    worker._service_started = True
    job = {**JOB, "format": "python"}
    assert asyncio.run(worker.handle_command("LLM_COMPLETE", job))["code"] == "invalid_python"
    text = "def f():\n    return 1\n"
    assert asyncio.run(worker.handle_command("LLM_COMPLETE", job))["text"] == text
    version = "0.34.2"
    calls.clear()
    assert asyncio.run(worker.handle_command("LLM_COMPLETE", job))["code"] == "runtime_version_mismatch"
    assert calls == ["/api/version"]


@pytest.mark.parametrize(("detail_code", "expected", "should_start"), [
    (None, "runtime_not_started", True),
    ("runtime_start_failed", "runtime_start_failed", True),
    ("runtime_unit_missing", "runtime_unit_missing", False),
    ("runtime_unit_symlink", "runtime_unit_symlink", False),
    ("runtime_binary_missing", "runtime_binary_missing", False),
    # Known codes that are not stop causes cannot end the start retry.
    ("runtime_version_mismatch", "runtime_not_started", True),
    ("runtime_unavailable", "runtime_not_started", True),
])
def test_runtime_start_retries_only_recoverable_failures(detail_code, expected, should_start):
    """Only an approved, bound role can cause its runtime to start."""
    pool = make_pool()
    report = {"status": "ERROR", "code": "runtime_not_started"}
    if detail_code:
        report["detail_code"] = detail_code

    async def exercise():
        """Send authenticated, stale, and repeated reports."""
        pool.report("a", object(), report)
        pool.report("b", pool.hub.active_connections["b"], report)
        pool.report("b", pool.hub.active_connections["b"], report)
        await asyncio.sleep(0)

    asyncio.run(exercise())
    assert pool.worker_issues["b"]["code"] == expected
    if should_start:
        pool.hub.request_response.assert_awaited_once_with(
            "b", "LLM_START_RUNTIME", {}, timeout=25)
    else:
        pool.hub.request_response.assert_not_awaited()


def report_all(pool, model, digest, keys="abcd"):
    """Report every listed worker as idle with the model and all sampling options."""
    for key in keys:
        pool.report(key, pool.hub.active_connections[key], {
            "status": "SUCCESS", "models": {model: digest}, "available": True,
            "supported_options": list(llm_pool.SAMPLING_LIMITS),
        })


def test_default_task_map_is_used_and_operator_entry_overrides_it():
    """A task works with no configuration; an operator entry still wins."""
    from llm_candidates import default_task_models
    gemma = CANDIDATES["gemma4-12b"]
    pool = make_pool()
    report_all(pool, gemma["model"], gemma["digest"])
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    result = asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "docs"}))
    assert result["model"] == gemma["model"]
    assert pool.hub.request_response.call_args.args[2]["options"] == {
        "num_ctx": 65536, "temperature": 0.7, "top_p": 0.8, "top_k": 64}
    assert [row["model"] for row in default_task_models("coding")] == [
        CANDIDATES["qwen36-coding"]["model"], CANDIDATES["qwen38-scout"]["model"]]
    assert default_task_models("nope") == []
    pool.hub.state.system_state["global_config"]["llm_task_models"] = {
        "docs": [{"model": JOB["model"], "digest": DIGEST}]}
    report_all(pool, JOB["model"], DIGEST)
    assert asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "docs"}))[
        "model"] == JOB["model"]
    assert asyncio.run(pool.complete("tenant-a", {"prompt": "fixture", "task": "nope"}))[
        "code"] == "invalid_request"


def test_least_recently_dispatched_idle_worker_goes_first():
    """Never-used workers win, then the one idle longest; ties break by key."""
    pool = make_pool()
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    pool.last_dispatch["a"] = 5.0
    for _ in range(3):
        asyncio.run(pool.complete("tenant-a", JOB))
    assert [call.args[0] for call in pool.hub.request_response.call_args_list] == ["b", "a", "b"]


def run_queued(pool, release_after, monkeypatch, wait=60):
    """Run one job while both tenant workers are busy; free them after a short delay."""
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.01)
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: wait)
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    pool.reserved.update("ab")
    states = []

    async def scenario():
        """Start the job, record its dashboard state while waiting, then free a worker."""
        task = asyncio.create_task(pool.complete("tenant-a", JOB))
        await asyncio.sleep(release_after)
        states.extend(job["state"] for job in pool.dashboard()["jobs"])
        pool.reserved.discard("b")
        return await task

    return asyncio.run(scenario()), states


def test_queued_job_completes_when_a_worker_frees_up(monkeypatch):
    """A busy pool queues the job, shows it as queued, then runs it once."""
    pool = make_pool()
    result, states = run_queued(pool, 0.05, monkeypatch)
    assert result["status"] == "SUCCESS" and states == ["queued"]
    assert pool.hub.request_response.call_args.args[0] == "b"
    assert pool.queued == 0 and not pool.active_jobs
    # One attempt, one terminal row: no no_capacity row or metric from the first pass.
    assert [row["state"] for row in pool.jobs] == ["passed"]
    assert all(row["no_capacity"] == 0 for row in pool.metric_rows.values())
    assert pool.hub.request_response.call_count == 1


def test_queue_times_out_to_no_capacity(monkeypatch):
    """When no worker frees up before the deadline, the existing error returns."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.01)
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 0.1)
    pool.reserved.update("ab")
    result = asyncio.run(pool.complete("tenant-a", JOB))
    assert result["code"] == "no_capacity" and result["retryable"] is True
    assert pool.queued == 0 and not pool.active_jobs
    assert [row["state"] for row in pool.jobs] == ["no_capacity"]
    assert [row["no_capacity"] for row in pool.metric_rows.values()] == [1]
    pool.hub.request_response.assert_not_called()


def test_cancelled_queued_job_cleans_up(monkeypatch):
    """Cancelling a waiting job releases its slot and records it once."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.01)
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 60)
    pool.reserved.update("ab")

    async def scenario():
        """Cancel the job while it is waiting."""
        task = asyncio.create_task(pool.complete("tenant-a", JOB))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert pool.queued == 0 and not pool.active_jobs
    # A caller going away is not a capacity shortage: its row says so and no metric moves.
    assert pool.jobs[-1]["state"] == "cancelled"
    assert all(row["no_capacity"] == 0 for row in pool.metric_rows.values())


def test_cancel_during_a_queued_dispatch_keeps_the_ambiguous_outcome(monkeypatch):
    """A cancel after the request went out is not "never ran": history and metrics agree."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.01)
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 60)
    pool.reserved.update("ab")

    async def hang(*args, **kwargs):
        """Never answer, so the dispatch is in flight when the caller cancels."""
        await asyncio.sleep(60)

    pool.hub.request_response.side_effect = hang

    async def scenario():
        """Free a worker, let the dispatch start, then cancel the caller."""
        task = asyncio.create_task(pool.complete("tenant-a", JOB))
        await asyncio.sleep(0.03)
        pool.reserved.discard("b")
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert pool.jobs[-1]["state"] == "failed" and pool.jobs[-1]["code"] == "dispatch_outcome_unknown"
    assert [row["failed"] for row in pool.metric_rows.values()] == [1]


def test_a_new_request_cannot_take_a_worker_an_older_waiter_could_use(monkeypatch):
    """Waiters are served oldest first: a late arrival does not jump a freed worker."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.2)
    waits = iter([60, 0.05])
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: next(waits))
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    pool.reserved.update("ab")

    async def scenario():
        """Queue an older job, free a worker between its polls, then submit a newer job."""
        older = asyncio.create_task(pool.complete("tenant-a", JOB))
        await asyncio.sleep(0.05)
        pool.reserved.discard("b")
        newer = await pool.complete("tenant-a", JOB)
        assert pool.hub.request_response.call_count == 0  # the newer job did not take it
        return newer, await older

    newer, older = asyncio.run(scenario())
    assert newer["code"] == "no_capacity" and older["status"] == "SUCCESS"
    assert pool.hub.request_response.call_count == 1 and not pool.waiters


def test_queued_row_is_finished_by_a_fallback_artifact_after_the_first_misses():
    """The one queued row records the outcome whichever artifact finally dispatches."""
    pool = make_pool()
    calls = []

    async def dispatch(tenant, prompt, model, *args):
        """Miss on the first artifact, serve the second."""
        calls.append(model)
        return None if len(calls) == 1 else {"status": "SUCCESS", "text": "ok", "metrics": {}, "issues": []}

    pool._dispatch = dispatch
    row = {"kind": "inference", "state": "queued", "model": "first:m", "digest": "1" * 64, "tier": "local"}
    artifacts = [("first:m", "1" * 64, (0, 0), ()), ("second:m", "2" * 64, (0, 0), ())]
    result = asyncio.run(pool._try_artifacts("tenant-a", "x", artifacts, "text", quiet=True, queued_job=row))
    assert result["status"] == "SUCCESS" and calls == ["first:m", "second:m"]
    assert [(r["state"], r["model"]) for r in pool.jobs] == [("passed", "second:m")] and pool.jobs[0] is row


def test_a_one_second_wait_still_polls_before_its_deadline(monkeypatch):
    """With the default 2 s poll, a 1 s wait must still dispatch to a worker freed within it."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 1)
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    pool.reserved.update("ab")

    async def scenario():
        """Free a worker 0.1 s into the wait."""
        task = asyncio.create_task(pool.complete("tenant-a", JOB))
        await asyncio.sleep(0.1)
        pool.reserved.discard("b")
        return await task

    assert asyncio.run(scenario())["status"] == "SUCCESS"


def test_queue_never_dispatches_after_the_deadline(monkeypatch):
    """A worker that frees up while the wait sleeps through its deadline is not used."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.1)
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 0.4)
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    pool.reserved.update("ab")

    async def scenario():
        """Free a worker just before the deadline; the last poll then lands on it."""
        task = asyncio.create_task(pool.complete("tenant-a", JOB))
        await asyncio.sleep(0.36)
        pool.reserved.discard("b")
        return await task

    result = asyncio.run(scenario())
    assert result["code"] == "no_capacity"
    pool.hub.request_response.assert_not_called()
    assert [row["state"] for row in pool.jobs] == ["no_capacity"]


def test_no_queueing_when_no_worker_holds_the_model(monkeypatch):
    """A busy pool without the model, or no connected worker, fails at once."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 60)
    pool.reserved.update("ab")
    other = {"model": "other:latest", "digest": "c" * 64, "prompt": "x"}
    assert asyncio.run(pool.complete("tenant-a", other))["code"] == "no_capacity"
    for key in "ab":
        pool.hub.active_connections.pop(key)
    assert asyncio.run(pool.complete("tenant-a", JOB))["code"] == "no_capacity"
    assert pool.queued == 0


def test_queue_is_capped_and_wait_setting_is_clamped(monkeypatch):
    """The 65th waiter fails immediately; llm_queue_wait_s is clamped with a safe default."""
    pool = make_pool()
    pool.reserved.update("ab")
    pool.queued = llm_pool.MAX_QUEUED
    assert asyncio.run(pool.complete("tenant-a", JOB))["code"] == "no_capacity"
    assert pool.jobs[-1]["state"] == "no_capacity"
    for value, expected in ((None, 600), ("5", 600), (True, 600), (-5, 0), (99999, 3600), (30, 30)):
        config = {} if value is None else {"llm_queue_wait_s": value}
        assert llm_pool.queue_wait(config) == expected


def test_queue_admission_is_rechecked_when_the_cap_fills_after_the_first_check(monkeypatch):
    """complete()'s cap check can be stale after its dispatch awaited; _queue must not exceed 64."""
    pool = make_pool()
    pool.reserved.update("ab")
    pool.queued = llm_pool.MAX_QUEUED
    first = (JOB["model"], JOB["digest"], None, None)
    result = asyncio.run(pool._queue("tenant-a", "x", [first], first, None, 60))
    assert result is None and pool.queued == llm_pool.MAX_QUEUED
    assert pool.jobs[-1]["state"] == "no_capacity" and not pool.active_jobs


def test_ab_pr_summary_routes_to_default_model_with_no_operator_map():
    """The pr_summary task the hub submits itself needs no llm_task_models entry."""
    gemma = CANDIDATES["gemma4-12b"]
    pool = make_pool()
    report_all(pool, gemma["model"], gemma["digest"])
    pool.hub.state.system_state["global_config"]["llm_ab_pr_repos"] = {
        "owner/repo": {"tenant": "tenant-a", "certificate": "ab-client"}}
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "summary"}
    result = asyncio.run(pool.ab_pr_summary(
        {"repository": "owner/repo", "prompt": "diff"}, ("ab-client",)))
    assert result["status"] == "SUCCESS" and result["model"] == gemma["model"]
    assert pool.hub.request_response.call_args.args[0] in ("a", "b")


def test_queue_wait_setting_validates_and_round_trips():
    """llm_queue_wait_s saves only as an integer 0..3600 and is returned with its default."""
    pool = make_pool()
    state = pool.hub.state
    state._mark_dirty = lambda: None
    app = FastAPI()
    llm.register(app, pool.hub, SimpleNamespace(
        _session_user=lambda request: {"role": "admin"}, _is_admin=lambda session: True))
    with TestClient(app) as client:
        path = "/api/llm/admin/settings"
        assert client.get(path).json()["llm_queue_wait_s"] == 600
        for bad in (-1, 3601, "30", 1.5, True, None):
            assert client.post(path, json={"llm_queue_wait_s": bad}).status_code == 400
        assert client.post(path, json={"llm_queue_wait_s": 45}).status_code == 200
        assert client.get(path).json()["llm_queue_wait_s"] == 45
        assert client.post(path, json={"llm_queue_wait_s": 0}).status_code == 200
        assert client.get(path).json()["llm_queue_wait_s"] == 0


def test_queue_attributes_its_row_to_the_fallback_artifact_that_can_serve():
    """Only the fallback's model is held by a busy worker, so the one row is its."""
    pool = make_pool()
    pool.hub.state.system_state["global_config"]["llm_task_models"] = {"summary": [
        {"model": "preferred:latest", "digest": "b" * 64},
        {"model": JOB["model"], "digest": DIGEST}]}
    pool.hub.request_response.return_value = {"status": "SUCCESS", "text": "ok"}
    pool.reserved.update("ab")
    seen = []

    async def scenario():
        """Record the queued row, then free a worker."""
        task = asyncio.create_task(pool.complete("tenant-a", {"prompt": "x", "task": "summary"}))
        await asyncio.sleep(0.05)
        seen.extend((j["state"], j["model"], j["digest"]) for j in pool.dashboard()["jobs"])
        pool.reserved.discard("a")
        return await task

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(llm_pool, "QUEUE_POLL_S", 0.01)
        result = asyncio.run(scenario())
    assert seen == [("queued", JOB["model"], DIGEST)]
    assert result["model"] == JOB["model"]
    assert [(row["state"], row["model"]) for row in pool.jobs] == [("passed", JOB["model"])]
    assert all(row["no_capacity"] == 0 for row in pool.metric_rows.values())


def test_queue_timeout_row_belongs_to_the_queue_capable_fallback(monkeypatch):
    """An expired wait leaves one no_capacity row and metric, for the fallback artifact."""
    pool = make_pool()
    pool.hub.state.system_state["global_config"]["llm_task_models"] = {"summary": [
        {"model": "preferred:latest", "digest": "b" * 64},
        {"model": JOB["model"], "digest": DIGEST}]}
    monkeypatch.setattr(llm_pool, "QUEUE_POLL_S", 0.01)
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 0.1)
    pool.reserved.update("ab")
    result = asyncio.run(pool.complete("tenant-a", {"prompt": "x", "task": "summary"}))
    assert result["code"] == "no_capacity"
    assert [(row["state"], row["model"], row["digest"]) for row in pool.jobs] == [
        ("no_capacity", JOB["model"], DIGEST)]
    assert [(key[0], row["no_capacity"]) for key, row in pool.metric_rows.items()] == [
        (JOB["model"], 1)]


def test_no_capable_worker_still_records_no_capacity_per_artifact(monkeypatch):
    """With nothing to wait for, each artifact's miss is recorded as before."""
    pool = make_pool()
    pool.hub.state.system_state["global_config"]["llm_task_models"] = {"summary": [
        {"model": "preferred:latest", "digest": "b" * 64},
        {"model": "other:latest", "digest": "c" * 64}]}
    monkeypatch.setattr(llm_pool, "queue_wait", lambda config: 60)
    pool.reserved.update("ab")
    result = asyncio.run(pool.complete("tenant-a", {"prompt": "x", "task": "summary"}))
    assert result["code"] == "no_capacity"
    assert [(row["state"], row["model"]) for row in pool.jobs] == [
        ("no_capacity", "preferred:latest"), ("no_capacity", "other:latest")]


# --- automatic provisioning ---------------------------------------------------

GIB = 2**30
ORDER = ["gemma4-12b", "qwen38-scout", "qwen36-coding", "deepseek-r1-70b"]


def prov_pool(monkeypatch, ram=128 * GIB, served=(), workers="a"):
    """Build a pool whose listed workers report the given RAM and served catalog keys."""
    pool = make_pool()
    monkeypatch.setattr(llm_pool, "PROVISION_POLL_S", 0)
    for worker in workers:
        pool.report(worker, pool.hub.active_connections[worker], {
            "status": "SUCCESS", "available": True,
            "models": {CANDIDATES[k]["model"]: CANDIDATES[k]["digest"] for k in served},
            "capabilities": {"mode": "cpu", "ram_bytes": ram, "vcpus": 8},
        })
    return pool


def fake_agent(pool, order, fail=None):
    """Answer PREPARE/ACTIVATE like a healthy worker, recording the model order."""
    journal = {}

    async def reply(worker, command, data, timeout=None):
        """Return the success reply for one command, or a failure for `fail`."""
        key = data["candidate"]
        if command == "LLM_PREPARE":
            # Mirror the agent's persisted journal: a reused revision with a new id is rejected.
            last = journal.get(worker)
            if last and (data["revision"] < last[0] or (
                    data["revision"] == last[0] and data["request_id"] != last[1])):
                return {"status": "ERROR", "code": "preparation_superseded"}
            journal[worker] = (data["revision"], data["request_id"])
            order.append(key)
            if key == fail:
                return {"status": "ERROR", "code": "candidate_pull_failed"}
            return {"status": "SUCCESS", "code": "bootstrap_smoke_passed", "mode": "bootstrap",
                    "model": CANDIDATES[key]["model"], "digest": CANDIDATES[key]["digest"],
                    "options": CANDIDATES[key]["options"], "version": "0.40.16",
                    "fixtures": [{"fixture": "json", "passed": True},
                                 {"fixture": "indentation", "passed": True}]}
        return {"status": "SUCCESS", "code": "activated",
                "model": CANDIDATES[key]["model"], "digest": CANDIDATES[key]["digest"]}
    pool.hub.request_response.side_effect = reply


def run_provision(pool):
    """Run one reconciler pass and wait for the tasks it started."""
    async def go():
        """Start the pass, then await every per-worker task."""
        await pool.provision_once()
        await asyncio.gather(*list(pool.provision_tasks))
    asyncio.run(go())


def test_catalog_has_ram_minimums_in_gib():
    """Each catalog entry carries the owner-chosen minimum RAM."""
    assert {k: v["min_ram_bytes"] // GIB for k, v in CANDIDATES.items()} == {
        "gemma4-12b": 16, "qwen36-coding": 40, "qwen38-scout": 32, "deepseek-r1-70b": 64}


def test_provisioner_installs_missing_models_smallest_first_on_a_non_shared_worker(monkeypatch):
    """A tenant-owned worker gets all four models in order and the preparation row is removed."""
    pool = prov_pool(monkeypatch)
    order = []
    fake_agent(pool, order)
    run_provision(pool)
    assert order == ORDER
    assert not pool.hub.state.get_global_config()["llm_worker_preparations"]
    assert not pool.provision_failures and not pool.reserved and not pool.provisioning
    activations = [c.args[2]["candidate"] for c in pool.hub.request_response.call_args_list
                   if c.args[1] == "LLM_ACTIVATE"]
    assert activations == ORDER


def test_provisioner_skips_models_already_served(monkeypatch):
    """A model the worker reports with the pinned digest is never pulled again."""
    pool = prov_pool(monkeypatch, served=("gemma4-12b", "qwen36-coding"))
    order = []
    fake_agent(pool, order)
    run_provision(pool)
    assert order == ["qwen38-scout", "deepseek-r1-70b"]


def test_provisioner_skips_models_too_big_for_the_worker(monkeypatch):
    """A 36 GiB worker gets Gemma and Qwen 3.8 only, and the dashboard says why."""
    pool = prov_pool(monkeypatch, ram=36 * GIB)
    order = []
    fake_agent(pool, order)
    run_provision(pool)
    assert order == ["gemma4-12b", "qwen38-scout"]
    row = next(w for w in pool.dashboard()["workers"] if w["name"] == "Worker a")
    assert len(row["skipped"]) == 2 and "Too small for" in row["detail"]


def test_provisioner_skips_workers_without_hardware_report(monkeypatch):
    """A worker with no hardware report cannot be sized, so nothing is pulled."""
    pool = prov_pool(monkeypatch, workers="")
    pool.report("a", pool.hub.active_connections["a"], {"status": "SUCCESS", "models": {}, "available": True})
    order = []
    fake_agent(pool, order)
    run_provision(pool)
    assert order == []


def test_failure_sets_backoff_and_attention_and_is_not_retried_early(monkeypatch):
    """A failed pull stops the worker's pass, shows attention, and waits out the backoff."""
    pool = prov_pool(monkeypatch)
    order = []
    fake_agent(pool, order, fail="qwen38-scout")
    run_provision(pool)
    assert order == ["gemma4-12b", "qwen38-scout"]
    assert list(pool.provision_failures["a"].values()) == ["candidate_pull_failed"]
    row = next(w for w in pool.dashboard()["workers"] if w["name"] == "Worker a")
    assert row["state"] == "attention" and "candidate_pull_failed" in row["detail"]
    # Within the backoff nothing is retried (the worker reports again, still idle).
    prov_pool_report = pool.hub.active_connections["a"]
    pool.report("a", prov_pool_report, {
        "status": "SUCCESS", "available": True,
        "models": {CANDIDATES["gemma4-12b"]["model"]: CANDIDATES["gemma4-12b"]["digest"]},
        "capabilities": {"mode": "cpu", "ram_bytes": 128 * GIB}})
    order.clear()
    pool.hub.state.get_global_config()["llm_worker_preparations"] = {}
    run_provision(pool)
    assert order == ["qwen36-coding", "deepseek-r1-70b"] or order == []
    assert "qwen38-scout" not in order
    # Once the backoff elapses the failed model is retried first.
    pool.provision_retry_at[("a", "qwen38-scout")] = 0
    order.clear()
    run_provision(pool)
    assert order[0] == "qwen38-scout"


def test_backoff_doubles_and_is_capped(monkeypatch):
    """Failures back off 15 min, 30, 60 ... never past 6 hours."""
    pool = prov_pool(monkeypatch)
    now = 1000.0
    monkeypatch.setattr(llm_pool.time, "monotonic", lambda: now)
    delays = []
    for _ in range(8):
        pool._provision_failed("a", "gemma4-12b", "x")
        delays.append(pool.provision_retry_at[("a", "gemma4-12b")] - now)
    assert delays[:3] == [900, 1800, 3600] and max(delays) == 21600


def test_provisioner_runs_at_most_two_workers_at_once(monkeypatch):
    """A third worker waits for the next pass while two are busy."""
    pool = prov_pool(monkeypatch, workers="abc")
    gate = asyncio.Event()
    seen = set()

    async def slow(worker, command, data, timeout=None):
        """Hold every PREPARE until released, noting which workers are in flight."""
        seen.add(worker)
        await gate.wait()
        return {"status": "ERROR", "code": "candidate_pull_failed"}

    pool.hub.request_response.side_effect = slow

    async def go():
        """Start a pass, let the pulls begin, then release them."""
        await pool.provision_once()
        await asyncio.sleep(0.05)
        assert len(pool.provisioning) == 2 and len(seen) == 2
        await pool.provision_once()
        assert len(pool.provisioning) == 2
        gate.set()
        await asyncio.gather(*list(pool.provision_tasks))

    asyncio.run(go())


def test_provisioner_knob_off_does_nothing(monkeypatch):
    """llm_auto_provision=false stops the reconciler."""
    pool = prov_pool(monkeypatch)
    pool.hub.state.get_global_config()["llm_auto_provision"] = False
    order = []
    fake_agent(pool, order)
    run_provision(pool)
    assert order == [] and not pool.provision_tasks


def test_dashboard_shows_provisioning_with_model_label(monkeypatch):
    """While a model is being prepared the worker is 'provisioning', not 'busy'."""
    pool = prov_pool(monkeypatch)
    gate = asyncio.Event()

    async def slow(*args, **kwargs):
        """Hold the pull open so the dashboard can be sampled."""
        await gate.wait()
        return {"status": "ERROR", "code": "candidate_pull_failed"}

    pool.hub.request_response.side_effect = slow

    async def go():
        """Sample the dashboard mid-pull."""
        await pool.provision_once()
        await asyncio.sleep(0.05)
        row = next(w for w in pool.dashboard()["workers"] if w["name"] == "Worker a")
        assert row["state"] == "provisioning"
        assert row["detail"] == "Preparing " + CANDIDATES["gemma4-12b"]["label"]
        gate.set()
        await asyncio.gather(*list(pool.provision_tasks))

    asyncio.run(go())


def test_non_shared_worker_in_qualification_manifest_still_serves_inference():
    """Workers listed as qualification candidates are no longer excluded from tenant pools."""
    pool = make_pool()
    pool.hub.state.get_global_config()["llm_qualification_candidates"] = {
        "cpu": {"worker": "c", "label": "CPU trial"}}
    assert pool._tenant_workers("tenant-without-workers") == ["c"]


def test_admin_prepare_stays_shared_only_but_reconciler_reaches_tenant_workers(monkeypatch):
    """Admin Prepare/Activate never reach a tenant spoke; the hub's own reconciler does."""
    pool = prov_pool(monkeypatch)
    key = next(iter(CANDIDATES))
    assert asyncio.run(pool.start_bootstrap("a", key)) is False
    assert pool._available_worker("a") is None
    assert pool._available_worker("a", True) is not None
    assert pool._available_worker("c") is not None


def test_manual_activation_rechecks_shared_tenancy_at_dispatch(monkeypatch):
    """A Shared worker reassigned to a tenant before dispatch is not sent a manual command."""
    pool = prov_pool(monkeypatch, workers="c")
    key = next(iter(CANDIDATES))
    pool.hub.state.get_global_config()["llm_worker_preparations"] = {"c": {"candidate": key}}
    pool.hub.state.system_state["module_metadata"]["c"]["tenant_id"] = "tenant-a"
    job = {"kind": "activation", "state": "running", "candidate": "x", "tier": "local", "worker": "w"}
    asyncio.run(pool._activate("c", pool.hub.active_connections["c"], key, job))
    assert job["code"] == "worker_changed"
    pool.hub.request_response.assert_not_called()


def test_later_success_keeps_earlier_model_failure_visible(monkeypatch):
    """Needs attention stays until the failed model itself succeeds."""
    pool = prov_pool(monkeypatch)
    keys = list(CANDIDATES)
    pool.provision_failures["a"] = {CANDIDATES[keys[0]]["label"]: "candidate_pull_failed",
                                    CANDIDATES[keys[2]]["label"]: "activation_failed"}
    fake_agent(pool, [])
    assert asyncio.run(pool._provision_model("a", keys[1])) is True
    assert "a" in pool.provision_failures
    assert asyncio.run(pool._provision_model("a", keys[0])) is True
    assert list(pool.provision_failures["a"].values()) == ["activation_failed"]
    assert asyncio.run(pool._provision_model("a", keys[2])) is True
    assert "a" not in pool.provision_failures


def test_replay_of_manual_preparation_does_not_reach_a_reassigned_tenant_worker(monkeypatch):
    """A row saved by a manual Prepare is replayed only while the worker is Shared."""
    pool = prov_pool(monkeypatch, workers="c")
    key = next(iter(CANDIDATES))
    row = {"candidate": key, "request_id": "a" * 32, "revision": 1}
    pool.hub.state.get_global_config()["llm_worker_preparations"] = {"c": row}
    pool.hub.state.system_state["module_metadata"]["c"]["tenant_id"] = "tenant-a"

    async def go():
        """Replay on reconnect and let any scheduled task run."""
        pool.reconcile_bootstrap("c")
        await asyncio.sleep(0.05)
    asyncio.run(go())
    pool.hub.request_response.assert_not_called()
    row["auto"] = True
    asyncio.run(go())
    pool.hub.request_response.assert_called()


def test_worker_without_a_runtime_is_provisioned_from_hardware_alone(monkeypatch):
    """A fresh worker reports an error (no inventory); the provisioner still installs it."""
    pool = prov_pool(monkeypatch)
    sock = pool.hub.active_connections["a"]
    pool.report("a", sock, {"status": "ERROR", "code": "runtime_not_started",
                            "detail_code": "runtime_binary_missing",
                            "capabilities": {"mode": "cpu", "ram_bytes": 128 * GIB, "vcpus": 8}})
    assert "a" not in pool.inventory
    order = []
    fake_agent(pool, order)
    run_provision(pool)
    assert order == ORDER
