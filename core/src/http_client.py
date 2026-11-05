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

# asynccontextmanager turns the generator below into an "async with" context manager.
from contextlib import asynccontextmanager
# Type hints only; they document what the context manager yields.
from typing import AsyncIterator, Optional

# httpx is the async HTTP library whose client objects we lend out or create.
import httpx

# Public API of this module: only shared_client should be imported by other code.
__all__ = ["shared_client"]


# Decorator that makes shared_client usable as "async with shared_client(http) as c:".
@asynccontextmanager
async def shared_client(http: Optional[httpx.AsyncClient],
                        timeout: float = 20.0) -> AsyncIterator[httpx.AsyncClient]:
    """Yield ``http`` when the caller supplied one, else a new client.

    The borrowed client is neither entered nor closed — its owner keeps that
    responsibility. A client created here is closed on exit as usual.
    """
    # Caller supplied its own client: hand it back untouched and do not close it.
    if http is not None:
        yield http
        return
    # No client supplied: create one, and let "async with" close it when the caller is done.
    async with httpx.AsyncClient(timeout=timeout) as client:
        yield client
