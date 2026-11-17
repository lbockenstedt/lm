"""Exercise side-by-side qualification without downloading a real model."""

import json

import pytest

from agent.src import llm_qualification as qualification


@pytest.mark.parametrize(("fault", "expected"), [
    (None, "qualified"),
    ("indentation", "fixture_mismatch"),
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
        if new and fault == "indentation" and not body.get("format"):
            text = text.replace("        return 1", "    return 1")
        return {"done": True, "done_reason": "stop", "model": active["model"],
                "response": text, "eval_duration": 180_000_000_000}

    result = qualification._run("cpu", request, {baseline["model"]: baseline["digest"]})
    assert result["code"] == expected
    if fault in (None, "indentation"):
        assert len(generations) == 4 and generations[0][1] == generations[2][1]
        assert all(fixture["passed"] for fixture in result["baseline"]["fixtures"])
        assert result["fixtures"][1]["passed"] is (fault is None)
        assert result["fixtures"][0]["eval_duration"] == 180_000_000_000
    else:
        assert not generations
