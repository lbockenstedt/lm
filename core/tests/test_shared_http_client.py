"""Regression: a borrowed ``httpx.AsyncClient`` must never be re-entered/closed.

Helpers that accept an optional ``http`` client used to do::

    async with (http or httpx.AsyncClient(timeout=20.0)) as c:

``httpx.AsyncClient`` may only be entered once, so passing an already-entered
client raised ``RuntimeError: Cannot open a client instance more than once``.
In :func:`cred_vault.automation_list_by_type` those failures were absorbed by
``asyncio.gather(..., return_exceptions=True)``, so EVERY vault secret silently
failed to decrypt and the console reported "no credentials exist" on a fleet
whose vault was full.
"""

import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from http_client import shared_client  # noqa: E402


@pytest.mark.asyncio
async def test_borrowed_client_is_reusable_concurrently():
    """The old pattern raised here; shared_client must not."""
    async with httpx.AsyncClient() as shared:
        async def use():
            async with shared_client(shared) as c:
                assert c is shared
                return True

        results = await asyncio.gather(*(use() for _ in range(5)),
                                       return_exceptions=True)
        assert results == [True] * 5, results
        assert not shared.is_closed


@pytest.mark.asyncio
async def test_borrowed_client_is_not_closed_by_callee():
    async with httpx.AsyncClient() as shared:
        async with shared_client(shared) as c:
            assert c is shared
        assert not shared.is_closed, "callee closed a client it does not own"


@pytest.mark.asyncio
async def test_owned_client_is_created_and_closed():
    async with shared_client(None, 5.0) as c:
        assert isinstance(c, httpx.AsyncClient)
        assert not c.is_closed
        created = c
    assert created.is_closed


@pytest.mark.asyncio
async def test_old_pattern_really_did_fail():
    """Pins the underlying httpx behaviour this fix works around."""
    async with httpx.AsyncClient() as shared:
        with pytest.raises(RuntimeError):
            async with (shared or httpx.AsyncClient()):
                pass


def test_no_module_reintroduces_the_anti_pattern():
    """Guard the whole hub source tree against the pattern coming back."""
    src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    offenders = []
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if not fn.endswith(".py") or fn == "http_client.py":
                continue
            path = os.path.join(root, fn)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    stripped = line.strip()
                    if stripped.startswith("async with (") and \
                            "httpx.AsyncClient(" in stripped and " or " in stripped:
                        offenders.append(f"{os.path.relpath(path, src)}:{i}")
    assert not offenders, (
        "use shared_client(http, timeout) instead of "
        "'async with (http or httpx.AsyncClient(...))' at: " + ", ".join(offenders))
