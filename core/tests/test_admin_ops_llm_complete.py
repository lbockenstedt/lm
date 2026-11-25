"""``/admin/ops/llm-complete`` replays a prompt through the LM pool for one non-shared tenant."""
import asyncio
import os
import tempfile

import pytest
from fastapi import HTTPException

from routes import admin_ops

from test_admin_ops_guard import _FakeApp, _FakeRequest, _State


class _PoolHub:
    """Hub double whose pool records what it is asked to run."""

    def __init__(self, data_dir):
        self.state = _State(data_dir)
        self.state.get_tenant = lambda tenant: {"id": tenant} if tenant == "tenant-a" else None
        self.calls = []
        self.llm_pool = type("P", (), {"complete": self._complete})()

    async def _complete(self, tenant, data):
        """Record the call and answer."""
        self.calls.append((tenant, data))
        return {"status": "SUCCESS", "text": "ok"}


def _call(body):
    with tempfile.TemporaryDirectory() as tmp:
        app, hub = _FakeApp(), _PoolHub(tmp)
        admin_ops.register(app, hub, ctx=None)
        tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
        req = _FakeRequest("127.0.0.1", tok)
        req.url = type("U", (), {"path": "/admin/ops/llm-complete"})()

        async def _json():
            return body
        req.json = _json
        fn = app.routes[("POST", "/admin/ops/llm-complete")]
        try:
            return asyncio.run(fn(req)), hub
        except HTTPException as exc:
            return exc.status_code, hub


def test_runs_the_prompt_for_a_known_tenant_without_forwarding_the_tenant_key():
    result, hub = _call({"tenant": "tenant-a", "task": "review", "prompt": "diff"})
    assert result["status"] == "SUCCESS"
    assert hub.calls == [("tenant-a", {"task": "review", "prompt": "diff"})]


@pytest.mark.parametrize("tenant", [None, "unknown", "shared"])
def test_rejects_a_missing_unknown_or_shared_tenant(tenant):
    status, hub = _call({"tenant": tenant, "task": "review", "prompt": "diff"})
    assert status == 400 and hub.calls == []


def test_llm_jobs_lists_only_inference_jobs_without_prompt_data():
    """The jobs lever shows model, worker and timing for inference rows, and drops other fields and kinds."""
    with tempfile.TemporaryDirectory() as tmp:
        app, hub = _FakeApp(), _PoolHub(tmp)
        rows = [{"kind": "inference", "model": "m", "worker": "W1", "state": "passed", "elapsed_s": 2.0,
                 "prompt": "secret diff"}, {"kind": "bootstrap", "worker": "W2"}]
        hub.llm_pool = type("P", (), {"dashboard": lambda self: {"jobs": rows}})()
        admin_ops.register(app, hub, ctx=None)
        tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
        req = _FakeRequest("127.0.0.1", tok)
        req.url = type("U", (), {"path": "/admin/ops/llm-jobs"})()
        out = asyncio.run(app.routes[("GET", "/admin/ops/llm-jobs")](req))
        assert out == {"jobs": [{"model": "m", "worker": "W1", "state": "passed", "code": None,
                                 "elapsed_s": 2.0, "finished_at": None}]}
