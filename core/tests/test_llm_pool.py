"""Verify scoped placement and CPU inference diagnostics."""

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from llm_pool import LlmPool
from llm_cloud import PublicHTTPSConnection, valid_endpoint
from log_redaction import _redact
from routes import llm


DIGEST = "a" * 64
JOB = {"model": "test:latest", "digest": DIGEST, "prompt": "synthetic fixture"}


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
    invoke.assert_called_once_with(endpoint, "approved", "synthetic-vault-key", "fixture")


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
    session = {"user": {"tenant_id": "tenant-a", "tenants": ["tenant-a"]}}
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


def test_runtime_start_requires_current_approved_tenant_socket():
    """Only an approved, bound role can cause its runtime to start."""
    pool = make_pool()
    report = {"status": "ERROR", "code": "runtime_not_started"}

    async def exercise():
        """Send authenticated, stale, and repeated reports."""
        pool.report("a", object(), report)
        pool.report("b", pool.hub.active_connections["b"], report)
        pool.report("b", pool.hub.active_connections["b"], report)
        await asyncio.sleep(0)

    asyncio.run(exercise())
    pool.hub.request_response.assert_awaited_once_with("b", "LLM_START_RUNTIME", {}, timeout=25)
