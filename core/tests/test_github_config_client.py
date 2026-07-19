"""Unit tests for the hub-side GitHub config client.

Pure stdlib (no create_app / httpx import): the module's pull/push accept an
injected ``client=`` so we drive them with a fake async client and assert the
REST Contents API calls (base64 decode/encode, sha handling, 404 missing file,
422 stale-sha retry). Async funcs are driven via ``asyncio.run`` so no
pytest-asyncio is needed.
"""
import asyncio
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "simulations"))
import github_config_client as gcc  # noqa: E402


class FakeResp:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeClient:
    def __init__(self, get_responses=None, put_responses=None):
        self.get_calls = []
        self.put_calls = []
        self._get = list(get_responses or [])
        self._put = list(put_responses or [])

    async def get(self, url, params=None, headers=None):
        self.get_calls.append({"url": url, "params": params, "headers": headers})
        return self._get.pop(0)

    async def put(self, url, json=None, headers=None):
        self.put_calls.append({"url": url, "json": json, "headers": headers})
        return self._put.pop(0)

    async def aclose(self):
        pass


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _gh():
    return {"repo_url": "https://github.com/owner/repo",
            "repo_branch": "main", "github_token": "tok123"}


# ── parse_owner_repo ────────────────────────────────────────────────────────
def test_parse_owner_repo_forms():
    assert gcc.parse_owner_repo("https://github.com/owner/repo") == ("owner", "repo")
    assert gcc.parse_owner_repo("https://github.com/owner/repo.git") == ("owner", "repo")
    assert gcc.parse_owner_repo("git@github.com:owner/repo.git") == ("owner", "repo")
    assert gcc.parse_owner_repo("owner/repo") == ("owner", "repo")
    assert gcc.parse_owner_repo("") is None
    assert gcc.parse_owner_repo("nope") is None


def test_is_configured():
    assert gcc.is_configured(_gh()) is True
    assert gcc.is_configured({"repo_url": "owner/repo"}) is False  # no token
    assert gcc.is_configured({"github_token": "t"}) is False       # no repo
    assert gcc.is_configured({}) is False
    assert gcc.is_configured(None) is False


# ── pull ────────────────────────────────────────────────────────────────────
def test_pull_decodes_content_and_sha():
    client = FakeClient(get_responses=[
        FakeResp(200, {"content": _b64("SIM=1\n"), "sha": "sha_sim"}),
        FakeResp(200, {"content": _b64("USER=2\n"), "sha": "sha_user"}),
    ])
    out = asyncio.run(gcc.pull(_gh(), client=client))
    assert out["sim_conf"] == "SIM=1\n"
    assert out["sim_sha"] == "sha_sim"
    assert out["user_overrides"] == "USER=2\n"
    assert out["user_sha"] == "sha_user"
    assert out["branch"] == "main"
    # ref=branch passed; auth header carries the token
    assert client.get_calls[0]["params"] == {"ref": "main"}
    assert client.get_calls[0]["headers"]["Authorization"] == "Bearer tok123"


def test_pull_missing_file_is_none_not_error():
    client = FakeClient(get_responses=[
        FakeResp(404),
        FakeResp(200, {"content": _b64("USER=2\n"), "sha": "sha_user"}),
    ])
    out = asyncio.run(gcc.pull(_gh(), client=client))
    assert out["sim_conf"] is None
    assert out["sim_sha"] is None
    assert out["user_overrides"] == "USER=2\n"


def test_pull_unconfigured_returns_none():
    assert asyncio.run(gcc.pull({"repo_url": "owner/repo"})) is None  # no token


# ── push ────────────────────────────────────────────────────────────────────
def test_push_create_no_sha():
    client = FakeClient(put_responses=[
        FakeResp(201, {"content": {"sha": "new_sha"}}),
    ])
    new = asyncio.run(gcc.push(_gh(), "configs/simulation.conf", "X=1\n",
                               "msg", sha=None, client=client))
    assert new == "new_sha"
    body = client.put_calls[0]["json"]
    assert "sha" not in body                       # create → no sha
    assert body["branch"] == "main"
    assert body["message"] == "msg"
    assert base64.b64decode(body["content"]).decode() == "X=1\n"


def test_push_stale_sha_retries_with_current():
    # First PUT rejected as stale (422); client re-GETs the current sha, retries.
    client = FakeClient(
        get_responses=[FakeResp(200, {"content": _b64("cur"), "sha": "cur_sha"})],
        put_responses=[
            FakeResp(422, {"message": "sha wasn't supplied"}),
            FakeResp(200, {"content": {"sha": "final_sha"}}),
        ],
    )
    new = asyncio.run(gcc.push(_gh(), "configs/simulation.conf", "X=2\n",
                               "msg", sha="stale", client=client))
    assert new == "final_sha"
    assert len(client.put_calls) == 2
    assert client.put_calls[0]["json"].get("sha") == "stale"     # first: stale
    assert client.put_calls[1]["json"].get("sha") == "cur_sha"   # retry: current
    assert len(client.get_calls) == 1                            # one re-GET


def test_push_unconfigured_raises():
    try:
        asyncio.run(gcc.push({"repo_url": "owner/repo"}, "configs/x", "y", "m"))
    except ValueError:
        return
    raise AssertionError("expected ValueError for unconfigured github_config")
