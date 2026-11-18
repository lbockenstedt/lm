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

from llm_pool import LlmPool
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
    for key, socket in hub.active_connections.items():
        pool.report(key, socket, {
            "status": "SUCCESS", "models": {JOB["model"]: DIGEST}, "available": True,
        })
    return pool


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
        assert client.get("/api/llm/admin/settings").status_code == 403
        assert client.post("/api/llm/admin/settings", json={"llm_cloud_profiles": []}).status_code == 403


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
    clock = iter((start, start, start, start + 700, start + 700))
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
