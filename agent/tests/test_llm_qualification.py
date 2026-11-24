"""Exercise side-by-side qualification without downloading a real model."""

import asyncio
from pathlib import Path
import json

import pytest

from agent.src import llm_qualification as qualification
from agent.src import llm_activation
from agent.src import llm_provisioning
from agent.src import llm_spoke
from core.src.llm_candidates import CANDIDATES


@pytest.mark.parametrize(("pin", "running", "expected"), [
    (None, "0.40.16", "SUCCESS"),
    ("0.41.0", "0.41.0", "SUCCESS"),
    ("0.41.0", "0.40.16", "ERROR"),
    ("", "0.40.16", "ERROR"),
])
@pytest.mark.parametrize("with_models", [True, False])
def test_worker_checks_local_runtime_pin_before_advertising_models(
        monkeypatch, pin, running, expected, with_models):
    """A stale or invalid local pin cannot advertise usable capacity."""
    setting = "LM_LLM_OLLAMA_VERSION"
    monkeypatch.delenv(setting, raising=False)
    if pin is not None:
        monkeypatch.setenv(setting, pin)
    digest = "a" * 64
    models = {"test:cpu": digest} if with_models else {}
    probes = []

    def request(path):
        """Return the running version and one approved model."""
        probes.append(path)
        if path == "/api/version":
            return {"version": running}
        return {"models": [{"name": "test:cpu", "digest": digest}]}

    monkeypatch.setattr(llm_spoke, "ollama_request", request)
    worker = llm_spoke.LlmSpoke("test-worker", {"models": models})
    worker._service_started = True
    status = asyncio.run(worker.get_status())
    assert status["status"] == expected
    if expected == "SUCCESS":
        assert status["version"] == running
        assert status["models"] == models
        assert status["available"] is with_models
    else:
        assert status["code"] == "runtime_version_mismatch"
        assert probes == ["/api/version"]


def test_runtime_start_failure_codes_are_actionable(tmp_path, monkeypatch):
    """Identify a missing unit or binary without exposing systemd output."""
    unit = tmp_path / "lm-llm-ollama.service"
    binary = tmp_path / "ollama"
    monkeypatch.setattr(llm_spoke, "SERVICE_UNIT_PATH", unit)
    monkeypatch.setattr(llm_spoke, "RUNTIME_BINARY_PATH", binary)

    assert llm_spoke.runtime_failure_code() == "runtime_unit_missing"
    unit.symlink_to("/dev/null")
    assert llm_spoke.runtime_failure_code() == "runtime_unit_symlink"
    unit.unlink()
    unit.symlink_to(tmp_path / "missing-unit")
    assert llm_spoke.runtime_failure_code() == "runtime_unit_symlink"
    unit.unlink()
    unit.write_text("[Service]\n", encoding="utf-8")
    assert llm_spoke.runtime_failure_code() == "runtime_binary_missing"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    assert llm_spoke.runtime_failure_code() == "runtime_start_failed"


def test_unusable_runtime_paths_are_not_reported_missing(tmp_path, monkeypatch):
    """A unit or binary that exists but cannot be used is not "missing"."""
    unit = tmp_path / "lm-llm-ollama.service"
    binary = tmp_path / "ollama"
    monkeypatch.setattr(llm_spoke, "SERVICE_UNIT_PATH", unit)
    monkeypatch.setattr(llm_spoke, "RUNTIME_BINARY_PATH", binary)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o644)

    # Staging skips an existing directory, so "stage the unit" cannot fix it.
    unit.mkdir()
    assert llm_spoke.runtime_failure_code() == "runtime_start_failed"
    # A present binary without execute permission needs no bundle install.
    unit.rmdir()
    unit.write_text("[Service]\n", encoding="utf-8")
    assert llm_spoke.runtime_failure_code() == "runtime_start_failed"


def test_failed_runtime_start_is_reported_in_worker_status(monkeypatch):
    """The periodic status frame exposes the stable start failure code."""
    monkeypatch.setattr(llm_spoke, "runtime_service", lambda _action: False)
    monkeypatch.setattr(llm_spoke, "runtime_failure_code", lambda: "runtime_unit_missing")
    worker = llm_spoke.LlmSpoke("test-worker", {})

    result = asyncio.run(worker._run_service_start("start"))

    assert result == {"status": "ERROR", "code": "runtime_unit_missing"}
    status = asyncio.run(worker.get_status())
    assert status["code"] == "runtime_not_started"
    assert status["detail_code"] == "runtime_unit_missing"


def test_worker_status_reclassifies_repaired_runtime_preconditions(monkeypatch):
    """A fixed unit or binary changes the detail code and lets the hub retry."""
    current_code = ["runtime_unit_missing"]
    monkeypatch.setattr(llm_spoke, "runtime_failure_code", lambda: current_code[0])
    monkeypatch.setattr(llm_spoke, "cpu_capabilities", lambda: {"mode": "cpu"})
    worker = llm_spoke.LlmSpoke("test-worker", {})
    worker._runtime_issue = "runtime_unit_missing"

    first = asyncio.run(worker.get_status())
    current_code[0] = "runtime_start_failed"
    repaired = asyncio.run(worker.get_status())

    assert first["code"] == repaired["code"] == "runtime_not_started"
    assert first["detail_code"] == "runtime_unit_missing"
    assert repaired["detail_code"] == "runtime_start_failed"


@pytest.mark.parametrize(("fault", "expected"), [
    (None, "qualified"),
    ("indentation", "fixture_mismatch"),
    ("baseline_indentation", "baseline_fixture_mismatch"),
    ("digest", "candidate_digest_mismatch"),
    ("version", "runtime_version_mismatch"),
    ("pull", "candidate_pull_failed"),
])
def test_cpu_candidate_uses_separate_store_and_fixed_fixtures(tmp_path, monkeypatch, fault, expected):
    """Collect baseline and candidate evidence and never pull on the serving port."""
    baseline = {"model": "test:base", "digest": "a" * 64, "version": "0.40.16"}
    candidate = {"model": "test:new", "digest": "b" * 64, "version": "0.41.0"}
    manifest = tmp_path / "qualification.json"
    manifest.write_text(json.dumps({"cpu": {**candidate, "baseline": baseline}}))
    monkeypatch.setattr(qualification, "MANIFEST", manifest)
    generations = []

    def request(path, body=None, timeout=3, *, port):
        """Simulate candidate and baseline Ollama on two ports."""
        active = candidate if port == qualification.PORT else baseline
        new = active is candidate
        if path == "/api/version":
            return {"version": "0.40.0" if new and fault == "version" else active["version"]}
        if path == "/api/pull":
            assert new and body["model"] == candidate["model"]
            return {"status": "error" if fault == "pull" else "success"}
        if path == "/api/tags":
            return {"models": [{"name": active["model"],
                                "digest": "c" * 64 if new and fault == "digest" else active["digest"]}]}
        assert path == "/api/generate"
        generations.append((port, body["options"]))
        assert body["think"] is False and body["options"]["num_gpu"] == 0
        text = (json.dumps(qualification.JSON_EXPECTED) if body.get("format") == "json"
                else qualification.PYTHON_EXPECTED)
        if (new and fault == "indentation" or not new and fault == "baseline_indentation") and not body.get("format"):
            text = text.replace("        return 1", "    return 1")
        return {"done": True, "done_reason": "stop", "model": active["model"],
                "response": text, "eval_duration": 180_000_000_000}

    result = qualification._run("cpu", request, {baseline["model"]: baseline["digest"]})
    assert result["code"] == expected
    if fault in (None, "indentation", "baseline_indentation"):
        assert len(generations) == 4 and generations[0][1] == generations[2][1]
        assert all(fixture["passed"] for fixture in result["baseline"]["fixtures"]) is (fault != "baseline_indentation")
        assert result["fixtures"][1]["passed"] is (fault != "indentation")
        assert result["fixtures"][0]["eval_duration"] == 180_000_000_000
    else:
        assert not generations


def test_watchdog_restarts_only_idle_runtime_after_repeated_failures(monkeypatch):
    """CPU work owns its slot even when the health endpoint cannot respond."""
    actions = []

    def offline(*args):
        """Stand in for an unresponsive daemon."""
        raise TimeoutError

    monkeypatch.setattr(llm_spoke, "ollama_request", offline)
    monkeypatch.setattr(llm_spoke, "runtime_service", lambda action: actions.append(action) or True)

    async def exercise():
        """Report three failures only after the current job has ended."""
        worker = llm_spoke.LlmSpoke("test-worker", {})
        worker._service_started = True
        worker._job = object()
        for _ in range(3):
            await worker._recover_idle_runtime()
        assert not actions
        worker._job = None
        for _ in range(3):
            await worker._recover_idle_runtime()
        assert actions == ["restart"]
        for _ in range(3):
            await worker._recover_idle_runtime()
        assert actions == ["restart"]

    asyncio.run(exercise())


def test_unavailable_candidate_stops_only_its_isolated_service(monkeypatch):
    """A skipped systemd condition must not use some other process on the test port."""
    artifact = ("test:tag", "a" * 64, "0.40.16")
    actions = []
    monkeypatch.setattr(qualification, "_service",
                        lambda action: actions.append(action) or action != "is-active")
    result = qualification._run_with_service(
        "cpu", lambda *a, **kw: pytest.fail("unexpected probe"), {}, (artifact, artifact, None, False))
    assert result["code"] == "candidate_not_provisioned"
    assert actions == ["start", "is-active", "stop"]


@pytest.mark.parametrize("bad_digest", [False, True])
def test_bootstrap_smoke_uses_pinned_model_and_configured_options_without_baseline(tmp_path, monkeypatch, bad_digest):
    """A first-worker smoke test never contacts a missing baseline or activates the candidate."""
    digest = "b" * 64
    options = {"num_ctx": 65536, "temperature": 0.7, "top_p": 0.8, "top_k": 64}
    manifest = tmp_path / "qualification.json"
    manifest.write_text(json.dumps({"cpu": {
        "model": "test:new", "digest": digest, "version": "0.40.16",
        "bootstrap": True, "options": options,
    }}))
    monkeypatch.setattr(qualification, "MANIFEST", manifest)
    generated = []

    def request(path, body=None, timeout=3, *, port):
        """Only the isolated candidate runtime may be reached."""
        assert port == qualification.PORT
        if path == "/api/version":
            return {"version": "0.40.16"}
        if path == "/api/pull":
            assert timeout == 7200
            return {"status": "success"}
        if path == "/api/tags":
            return {"models": [{"name": "test:new", "digest": "c" * 64 if bad_digest else digest}]}
        generated.append(body)
        assert timeout == 900
        return {"done": True, "done_reason": "stop", "model": "test:new",
                "response": json.dumps(qualification.JSON_EXPECTED) if body.get("format")
                else qualification.PYTHON_EXPECTED}

    result = qualification._run("cpu", request, {})
    if bad_digest:
        assert result["code"] == "candidate_digest_mismatch"
        assert not generated
    else:
        assert result["code"] == "bootstrap_smoke_passed"
        assert result["options"] == options and "baseline" not in result
        assert len(generated) == 2
        assert all(body["think"] is False and body["options"] == {
            **options, "num_gpu": 0, "num_predict": 1024} for body in generated)

    for invalid in ({"num_ctx": 0}, {"num_ctx": 65536, "num_gpu": 1}, {}):
        manifest.write_text(json.dumps({"cpu": {
            "model": "test:new", "digest": digest, "version": "0.40.16",
            "bootstrap": True, "options": invalid,
        }}))
        assert qualification._candidate("cpu") is None


def test_bootstrap_job_does_not_require_serving_runtime(monkeypatch):
    """A missing serving runtime cannot prevent the isolated bootstrap job."""
    spec = (("test:new", "a" * 64, "0.40.16"), None, {"num_ctx": 65536}, True)
    monkeypatch.setattr(qualification, "_candidate", lambda _key: spec)
    monkeypatch.setattr(qualification, "_run_with_service",
                        lambda _key, _request, approved, supplied, *_rest: {
                            "status": "SUCCESS", "code": "bootstrap_smoke_passed"
                        } if approved == {} and supplied == spec else pytest.fail("unexpected baseline"))

    async def unavailable():
        """A missing baseline must not be probed in bootstrap mode."""
        pytest.fail("unexpected baseline probe")

    result = asyncio.run(qualification.qualify("cpu", None, unavailable, False))
    assert result["code"] == "bootstrap_smoke_passed"


def test_candidate_accepts_dotted_public_model_names_without_registry_urls():
    """Public Qwen tags are valid; arbitrary URLs and path traversal are not."""
    spec = {"digest": "a" * 64, "version": "0.40.16"}
    assert qualification._artifact({**spec, "model": "qwen3.6:35b-a3b-coding"})
    assert qualification._artifact({**spec, "model": "qwen3.8:27b"})
    for model in ("https://example.com/model:tag", "example.com/model:tag",
                  "../model:tag", "host:80/model:tag"):
        assert qualification._artifact({**spec, "model": model}) is None


def test_comparison_uses_same_tuned_options_for_both_runtimes(monkeypatch):
    """A timing comparison must not use a different context or sampling profile."""
    candidate = ("test:new", "a" * 64, "0.40.16")
    baseline = ("test:base", "b" * 64, "0.40.16")
    options = {"num_ctx": 65536, "temperature": 0.6}
    calls = []

    def suite(_request, port, artifact, supplied):
        """Return synthetic passing results while recording the effective profile."""
        calls.append((port, supplied))
        return {"model": artifact[0], "digest": artifact[1], "version": artifact[2],
                "fixtures": [{"fixture": "json", "passed": True},
                             {"fixture": "indentation", "passed": True}]}

    def request(path, body=None, timeout=3, *, port):
        """Respond to version and pull probes."""
        return {"version": "0.40.16"} if path == "/api/version" else {"status": "success"}

    monkeypatch.setattr(qualification, "_installed", lambda *_args: True)
    monkeypatch.setattr(qualification, "_suite", suite)
    result = qualification._run("cpu", request, {baseline[0]: baseline[1]},
                                spec=(candidate, baseline, options, False))
    assert result["code"] == "qualified"
    assert calls == [(qualification.BASELINE_PORT, options), (qualification.PORT, options)]


def test_prepare_uses_only_pinned_cpu_candidate_and_reports_install_failure(monkeypatch):
    """The hub selects a catalog key, never a URL, digest or inference options."""
    staged = []
    specs = []
    monkeypatch.setattr(llm_provisioning, "stage_public_runtime", lambda path: staged.append(path))
    monkeypatch.setattr(llm_provisioning, "_run_with_service",
                        lambda key, request, approved, spec, progress: specs.append(spec) or {"status": "SUCCESS"})
    assert asyncio.run(llm_provisioning.prepare("missing", "0.40.16", None))["status"] == "ERROR"
    assert asyncio.run(llm_provisioning.prepare("gemma4-12b", "0.41.0", None))["code"] == "runtime_version_mismatch"
    assert not staged
    assert asyncio.run(llm_provisioning.prepare("gemma4-12b", "0.40.16", None))["status"] == "SUCCESS"
    candidate = CANDIDATES["gemma4-12b"]
    assert specs == [((candidate["model"], candidate["digest"], "0.40.16"), None, candidate["options"], True)]

    def failed(_path):
        """Model an unavailable or untrusted release."""
        raise ValueError("download failed")

    monkeypatch.setattr(llm_provisioning, "stage_public_runtime", failed)
    assert asyncio.run(llm_provisioning.prepare("gemma4-12b", "0.40.16", None))["code"] == "candidate_runtime_install_failed"


def test_preparation_is_durable_and_duplicate_requests_join_the_same_job(tmp_path, monkeypatch):
    """Reconnects and duplicate deliveries must not repeat a model download."""
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    started, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def prepare(key, version, request, progress):
        """Hold the synthetic job until a duplicate request has attached."""
        calls.append(key)
        progress("pull")
        started.set()
        await release.wait()
        return {"status": "SUCCESS", "code": "bootstrap_smoke_passed"}

    monkeypatch.setattr(llm_provisioning, "prepare", prepare)
    request = {"candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1}

    async def exercise():
        """A different request cannot overbook the same CPU slot."""
        worker = llm_spoke.LlmSpoke("test-worker", {})
        first = asyncio.create_task(worker.handle_command("LLM_PREPARE", request))
        await started.wait()
        assert llm_provisioning.load_state()["state"] == "running"
        second = asyncio.create_task(worker.handle_command("LLM_PREPARE", request))
        assert (await worker.handle_command(
            "LLM_PREPARE", {**request, "request_id": "b" * 32, "revision": 2}))["code"] == "busy"
        assert (await worker.handle_command(
            "LLM_PREPARE", {**request, "request_id": "b" * 32}))["code"] == "preparation_superseded"
        release.set()
        assert (await first)["status"] == (await second)["status"] == "SUCCESS"
        worker2 = llm_spoke.LlmSpoke("restarted", {})
        assert (await worker2.handle_command("LLM_PREPARE", request))["status"] == "SUCCESS"
        assert llm_provisioning.load_state()["state"] == "passed"

    asyncio.run(exercise())
    assert calls == ["gemma4-12b"]


def test_preparation_journal_failure_does_not_start_download(tmp_path, monkeypatch):
    """An unpersisted assignment cannot start a side effect."""
    def failed(_data):
        """Model a failing journal write."""
        raise OSError("disk full")

    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    monkeypatch.setattr(llm_provisioning, "save_state", failed)
    monkeypatch.setattr(llm_provisioning, "prepare", lambda *_args: pytest.fail("unpersisted job ran"))
    worker = llm_spoke.LlmSpoke("test-worker", {})
    result = asyncio.run(worker.handle_command("LLM_PREPARE", {
        "candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1,
    }))
    assert result["code"] == "preparation_state_failed"


def test_interrupted_preparation_waits_for_authorized_retry(tmp_path, monkeypatch):
    """Restart keeps the request, but cannot start it without a fresh hub command."""
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    request = {"candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1}
    llm_provisioning.save_state({**request, "state": "running"})
    calls = []

    async def prepare(key, *_args):
        """Return a synthetic result only after the hub retries."""
        calls.append(key)
        return {"status": "ERROR", "code": "candidate_digest_mismatch"}

    monkeypatch.setattr(llm_provisioning, "prepare", prepare)

    async def exercise():
        """Loading the journal alone does not run the old job."""
        worker = llm_spoke.LlmSpoke("test-worker", {})
        assert await worker._load_preparation()
        assert not calls and worker._job is None
        assert (await worker.handle_command("LLM_PREPARE", request))["code"] == "candidate_digest_mismatch"
        assert llm_provisioning.load_state()["state"] == "failed"

    asyncio.run(exercise())
    assert calls == ["gemma4-12b"]


@pytest.mark.parametrize("fail_verify", [False, True])
def test_activation_requires_worker_smoke_pass_and_rolls_back_on_failure(tmp_path, monkeypatch, fail_verify):
    """Only the exact prepared artifact is published, and failed verification is undone."""
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    candidate = CANDIDATES["gemma4-12b"]
    state = {"candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1, "state": "passed",
             "result": {"status": "SUCCESS", "code": "bootstrap_smoke_passed", **candidate}}
    llm_provisioning.save_state(state)
    calls = []
    monkeypatch.setattr(llm_activation, "publish",
                        lambda model, digest: calls.append("publish") or {"created": True})
    monkeypatch.setattr(llm_activation, "finalize", lambda record: calls.append("finalize"))
    monkeypatch.setattr(llm_activation, "rollback", lambda record: calls.append("rollback"))
    monkeypatch.setattr(llm_spoke.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(llm_spoke, "runtime_service", lambda action: calls.append(action) or True)
    monkeypatch.setattr(llm_spoke, "ollama_request", lambda *_args, **_kw: {"version": "0.40.16"})
    monkeypatch.setattr(qualification, "_installed", lambda *_args: True)
    worker = llm_spoke.LlmSpoke("test-worker", {})

    async def inventory():
        """Return the approved artifact or simulate a catalog verification failure."""
        if fail_verify:
            raise ValueError("invalid catalog")
        return {candidate["model"]: candidate["digest"]}

    worker._available_models = inventory
    result = asyncio.run(worker.handle_command("LLM_ACTIVATE", {"candidate": "gemma4-12b"}))
    if fail_verify:
        assert result["code"] == "activation_failed"
        assert calls == ["publish", "start", "finalize", "stop", "rollback"]
    else:
        assert result["code"] == "activated"
        assert calls == ["publish", "start", "finalize"]


def test_activation_refuses_a_model_without_a_matching_smoke_pass(tmp_path, monkeypatch):
    """A download or a different candidate is not an approval."""
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    worker = llm_spoke.LlmSpoke("test-worker", {})
    result = asyncio.run(worker.handle_command("LLM_ACTIVATE", {"candidate": "gemma4-12b"}))
    assert result["code"] == "candidate_not_smoke_tested"


def test_activation_waits_for_an_inflight_runtime_start(tmp_path, monkeypatch):
    """Activation must not race a separate service start or stop its runtime."""
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    candidate = CANDIDATES["gemma4-12b"]
    llm_provisioning.save_state({
        "candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1, "state": "passed",
        "result": {"status": "SUCCESS", "code": "bootstrap_smoke_passed", **candidate},
    })
    worker = llm_spoke.LlmSpoke("test-worker", {})

    async def exercise():
        """A pending start keeps the candidate unmodified."""
        worker._startup = asyncio.create_task(asyncio.sleep(60))
        try:
            result = await worker.handle_command("LLM_ACTIVATE", {"candidate": "gemma4-12b"})
            assert result["code"] == "busy"
        finally:
            worker._startup.cancel()
            await asyncio.gather(worker._startup, return_exceptions=True)

    asyncio.run(exercise())


def test_post_pull_inventory_check_allows_a_busy_runtime_to_answer(monkeypatch):
    """The inventory check after a large pull must outlast a briefly busy runtime."""
    candidate = ("test:new", "a" * 64, "0.40.16")
    timeouts = {}

    def request(path, body=None, timeout=3, *, port):
        """Record each probe's timeout and answer as a healthy runtime."""
        timeouts[path] = timeout
        if path == "/api/version":
            return {"version": "0.40.16"}
        if path == "/api/tags":
            return {"models": [{"name": candidate[0], "digest": candidate[1]}]}
        return {"status": "success"}

    monkeypatch.setattr(qualification, "_suite", lambda *_a: {
        "model": candidate[0], "digest": candidate[1], "version": candidate[2],
        "fixtures": [{"fixture": "json", "passed": True}, {"fixture": "indentation", "passed": True}]})
    qualification._run("cpu", request, {}, spec=(candidate, None, {"num_ctx": 4096}, True))
    assert timeouts["/api/tags"] >= 120


@pytest.mark.parametrize("scenario", ["ok", "prune_raises", "prune_type_error", "verify_fails"])
def test_activation_prunes_the_candidate_only_after_success(tmp_path, monkeypatch, scenario):
    """Pruning follows approval, never breaks the reply and never runs on failure."""
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    candidate = CANDIDATES["gemma4-12b"]
    llm_provisioning.save_state({
        "candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1, "state": "passed",
        "result": {"status": "SUCCESS", "code": "bootstrap_smoke_passed", **candidate},
    })
    calls = []

    def prune(model):
        """Record the call, optionally failing like a read-only disk."""
        calls.append("prune")
        if scenario == "prune_raises":
            raise OSError("read-only")
        if scenario == "prune_type_error":
            raise TypeError("malformed")

    monkeypatch.setattr(llm_activation, "publish", lambda model, digest: {"created": True})
    monkeypatch.setattr(llm_activation, "finalize", lambda record: None)
    monkeypatch.setattr(llm_activation, "rollback", lambda record: None)
    monkeypatch.setattr(llm_activation, "prune_candidate", prune)
    monkeypatch.setattr(llm_spoke.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(llm_spoke, "runtime_service", lambda action: True)
    monkeypatch.setattr(llm_spoke, "ollama_request", lambda *_a, **_kw: {"version": "0.40.16"})
    monkeypatch.setattr(qualification, "_installed", lambda *_a: True)
    worker = llm_spoke.LlmSpoke("test-worker", {})

    async def inventory():
        """Approve the artifact, or fail the catalog check."""
        return {} if scenario == "verify_fails" else {candidate["model"]: candidate["digest"]}

    worker._available_models = inventory
    result = asyncio.run(worker.handle_command("LLM_ACTIVATE", {"candidate": "gemma4-12b"}))
    if scenario == "verify_fails":
        assert result["code"] == "activation_failed" and calls == []
    else:
        assert result["code"] == "activated" and calls == ["prune"]


def test_activation_reply_survives_a_malformed_candidate_store(tmp_path, monkeypatch):
    """The real prune on a store with a malformed manifest deletes nothing and the reply stays activated."""
    from agent.tests.test_llm_install import _add_model
    monkeypatch.setattr(llm_provisioning, "STATE", tmp_path / "private" / "preparation.json")
    candidate = CANDIDATES["gemma4-12b"]
    llm_provisioning.save_state({
        "candidate": "gemma4-12b", "request_id": "a" * 32, "revision": 1, "state": "passed",
        "result": {"status": "SUCCESS", "code": "bootstrap_smoke_passed", **candidate},
    })
    store = tmp_path / "store"
    (store / "blobs").mkdir(parents=True)
    entry, blobs = _add_model(store, "gemma4:12b", [b"cfg", b"layer"])
    # The pinned registry digest is not reproducible here; let the real prune get past verification.
    parts = ("manifests", "registry.ollama.ai", "library", "gemma4", "12b")
    monkeypatch.setattr(llm_activation, "_manifest", lambda _c: (parts, b"", blobs))
    bad = store / "manifests" / "registry.ollama.ai" / "library" / "bad" / "cpu"
    bad.parent.mkdir(parents=True)
    bad.write_text('{"layers": 1}')
    monkeypatch.setattr(llm_activation, "CANDIDATE_STORE", store)
    monkeypatch.setattr(llm_activation, "publish", lambda model, digest: {"created": True})
    monkeypatch.setattr(llm_activation, "finalize", lambda record: None)
    monkeypatch.setattr(llm_spoke.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(llm_spoke, "runtime_service", lambda action: True)
    monkeypatch.setattr(llm_spoke, "ollama_request", lambda *_a, **_kw: {"version": "0.40.16"})
    monkeypatch.setattr(qualification, "_installed", lambda *_a: True)
    worker = llm_spoke.LlmSpoke("test-worker", {})

    async def inventory():
        """Approve the artifact."""
        return {candidate["model"]: candidate["digest"]}

    worker._available_models = inventory
    before = sorted(p.name for p in (store / "blobs").iterdir())
    result = asyncio.run(worker.handle_command("LLM_ACTIVATE", {"candidate": "gemma4-12b"}))
    assert result["code"] == "activated"
    assert sorted(p.name for p in (store / "blobs").iterdir()) == before
    assert (store / Path(*parts)).exists()
