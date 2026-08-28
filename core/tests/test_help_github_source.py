"""GitHub-backed source corpus for the Help assistant.

``search_source`` used to walk the local filesystem for sibling checkouts named
``cs``/``pxmx``. On a real hub (installed to ``/opt/lm``) those don't exist, so
the tool silently returned nothing for every question about a client simulation
and the model concluded the feature wasn't there. ``github_source`` reads that
code from GitHub instead.

These tests are OFFLINE: the selection rules, the cache/TTL contract and the
fail-soft behaviour are what regress, and all three are testable with a stub
HTTP client. Live fetching is covered manually (and by the module's own logging)
rather than by making the suite depend on network + GitHub rate limits.
"""

import asyncio

import pytest

from routes import github_source as gs


# ── path selection ───────────────────────────────────────────────────────────

def _spec():
    return gs.SourceSpec(owner="o", repo="cs", branch="main",
                         path_prefixes=("clients/linux/", "clients/windows/",
                                        "clients/lib/"),
                         exts=(".sh", ".ps1"))


@pytest.mark.parametrize("path", [
    "clients/linux/dns_fail.sh",
    "clients/windows/dns_fail.ps1",
    "clients/lib/common.sh",
])
def test_wants_the_simulation_scripts(path):
    assert _spec().wants(path) is True


@pytest.mark.parametrize("path", [
    "clients/linux/collab.py",      # right dir, wrong extension
    "server/app.sh",                # right extension, wrong dir
    "clients/t3/emulator.sh",       # t3 is a WiFi/IoT emulator, not a sim client
    "README.md",
])
def test_rejects_everything_outside_the_scope(path):
    assert _spec().wants(path) is False


def test_extension_match_is_case_insensitive():
    assert _spec().wants("clients/windows/Dns_Fail.PS1") is True


def test_default_spec_covers_both_platforms():
    """The linux and windows scripts are functional twins — a question about a
    simulation is as likely to be about either, so both must be searchable."""
    spec = gs.default_specs()[0]
    assert "clients/linux/" in spec.path_prefixes
    assert "clients/windows/" in spec.path_prefixes
    assert set(spec.exts) == {".sh", ".ps1"}


def test_repo_is_overridable_by_env(monkeypatch):
    monkeypatch.setenv("LM_HELP_SOURCE_REPO", "someone/fork")
    monkeypatch.setenv("LM_HELP_SOURCE_BRANCH", "dev")
    spec = gs.default_specs()[0]
    assert (spec.owner, spec.repo, spec.branch) == ("someone", "fork", "dev")


def test_malformed_repo_env_falls_back_to_the_default(monkeypatch):
    """A typo'd override must not blank out the corpus."""
    monkeypatch.setenv("LM_HELP_SOURCE_REPO", "no-slash-here")
    spec = gs.default_specs()[0]
    assert spec.owner and spec.repo


# ── cache behaviour ──────────────────────────────────────────────────────────

class _StubCache(gs.GitHubSourceCache):
    """Counts fetches so we can assert the TTL and the stampede lock."""

    def __init__(self, payload, ttl=3600, fail=False):
        super().__init__(specs=[_spec()], ttl=ttl)
        self._payload = payload
        self._fail = fail
        self.calls = 0

    async def _fetch_all(self):
        self.calls += 1
        if self._fail:
            raise RuntimeError("github unreachable")
        return dict(self._payload)


def test_fetches_once_then_serves_from_cache():
    c = _StubCache({"cs/clients/linux/dns_fail.sh": "#!/bin/bash"})
    async def go():
        assert len(await c.files()) == 1
        await c.files()
        await c.files()
    asyncio.run(go())
    assert c.calls == 1


def test_expired_cache_refetches():
    c = _StubCache({"a.sh": "x"}, ttl=-1)
    async def go():
        await c.files()
        await c.files()
    asyncio.run(go())
    assert c.calls == 2


def test_concurrent_callers_collapse_to_one_fetch():
    """N simultaneous questions must not become N GitHub tree calls — that
    endpoint is rate limited to 60/hr unauthenticated."""
    c = _StubCache({"a.sh": "x"})
    async def go():
        await asyncio.gather(*(c.files() for _ in range(10)))
    asyncio.run(go())
    assert c.calls == 1


def test_fetch_failure_is_fail_soft_not_raising():
    """search_source feeds an LLM answer; a GitHub outage should degrade the
    answer, never raise into the user's question."""
    c = _StubCache({}, fail=True)
    assert asyncio.run(c.files()) == {}
    assert c.stats()["error"]


def test_stale_corpus_is_kept_when_a_refresh_fails():
    """An expired corpus is far more useful than an empty one."""
    c = _StubCache({"a.sh": "keep me"}, ttl=-1)
    asyncio.run(c.files())
    c._fail = True
    assert asyncio.run(c.files()) == {"a.sh": "keep me"}


def test_stats_reports_the_configured_repos():
    c = _StubCache({"a.sh": "x"})
    asyncio.run(c.files())
    st = c.stats()
    assert st["files"] == 1 and st["error"] is None
    assert st["repos"] == ["o/cs@main"]
