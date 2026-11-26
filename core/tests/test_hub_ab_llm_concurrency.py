"""AppBuilder's LLM_COMPLETE jobs run concurrently on the hub instead of one at a time."""
import asyncio
import types

import main


class _Hub:
    """Stub with only what _spoke_msg_hub_request touches."""

    def __init__(self, authorized=True):
        self._ab_llm_jobs = set()
        self.authorized = authorized
        self.started, self.release, self.inline = [], asyncio.Event(), []

    def _hub_request_authorized(self, spoke_id, identity):
        """Answer the canned authorization."""
        return self.authorized

    async def _handle_hub_request(self, spoke_id, msg_data, payload, identity, **kw):
        """Record the start; background jobs wait for release, inline ones finish at once."""
        self.started.append(payload["data"]["task"])
        if kw.get("reply_socket") is not None:
            await self.release.wait()
        else:
            self.inline.append(kw.get("allow_llm", True))


def _conn():
    """A connection stub carrying an mTLS identity."""
    return types.SimpleNamespace(spoke_id="ab", websocket=types.SimpleNamespace(peer_cert_identity=("ab",)))


def _send(hub, kind, task):
    """Deliver one HUB_REQUEST through the real dispatcher."""
    return main.LabManagerHub._spoke_msg_hub_request(
        hub, _conn(), {}, {"data": {"type": kind, "task": task}}, None)


def test_llm_complete_jobs_overlap_and_the_cap_falls_back_to_a_refusal():
    async def run():
        hub = _Hub()
        for i in range(main.AB_LLM_MAX_JOBS):
            await _send(hub, "LLM_COMPLETE", f"t{i}")
        await asyncio.sleep(0)
        # Every job started without the first one finishing.
        assert len(hub.started) == main.AB_LLM_MAX_JOBS and len(hub._ab_llm_jobs) == main.AB_LLM_MAX_JOBS
        # Past the cap the request is answered inline with allow_llm off (a retryable no_capacity).
        await _send(hub, "LLM_COMPLETE", "over")
        assert hub.inline == [False]
        hub.release.set()
        await asyncio.gather(*hub._ab_llm_jobs)
    asyncio.run(run())


def test_unauthorized_caller_never_gets_a_background_job():
    async def run():
        hub = _Hub(authorized=False)
        await _send(hub, "LLM_COMPLETE", "x")
        assert not hub._ab_llm_jobs and hub.inline == [False]
    asyncio.run(run())
