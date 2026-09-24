"""Shared-``httpx.AsyncClient`` borrowing helper.

Many hub helpers accept an optional ``http`` client so a caller that makes
several calls in a row (or concurrently, via :func:`asyncio.gather`) can reuse
one connection pool. The obvious implementation is wrong::

    async with (http or httpx.AsyncClient(timeout=20.0)) as c:   # BUG
        ...

``httpx.AsyncClient.__aenter__`` may only be entered once per instance. When a
caller passes an already-entered client, that line raises
``RuntimeError: Cannot open a client instance more than once`` — and on the exit
path it would *close* a client the callee does not own, breaking every other
in-flight user of the pool. Under ``asyncio.gather(..., return_exceptions=True)``
the failure is silent: every task raises and the caller sees an empty result.

:func:`shared_client` fixes both halves: a borrowed client is yielded as-is
(never entered, never closed), and only a client created here is managed here.
Always prefer it over ``async with (http or httpx.AsyncClient(...))``.
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx

__all__ = ["shared_client"]


@asynccontextmanager
async def shared_client(http: Optional[httpx.AsyncClient],
                        timeout: float = 20.0) -> AsyncIterator[httpx.AsyncClient]:
    """Yield ``http`` when the caller supplied one, else a new client.

    The borrowed client is neither entered nor closed — its owner keeps that
    responsibility. A client created here is closed on exit as usual.
    """
    if http is not None:
        yield http
        return
    async with httpx.AsyncClient(timeout=timeout) as client:
        yield client
