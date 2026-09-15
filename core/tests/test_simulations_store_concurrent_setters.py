"""``SimulationsStore._lock`` must be an ``asyncio.Lock``, never a ``threading.Lock``.

Every setter in the store holds ``_lock`` across ``await self._asave()``, and
``_asave`` yields to the event loop via ``asyncio.to_thread``. With a
``threading.Lock`` that combination is not merely slow — it is an unrecoverable
whole-hub deadlock:

  1. Setter A acquires ``_lock`` and awaits ``to_thread(_save)`` → yields.
  2. Setter B is scheduled on the SAME event-loop thread, hits
     ``with self._lock`` and blocks the THREAD in ``acquire()``.
  3. The loop is now frozen, so A's ``to_thread`` future can never be resumed
     to release the lock. B waits on A, A waits on the loop B is blocking.

This was hit in production: the endpoint-sync loop fans tenants out with
``asyncio.gather`` (default concurrency 8), and when the CPPM spoke was not
resolvable every tenant took the fast "spoke not connected" branch, so several
``set_endpoint_sync_status`` calls overlapped. The hub wedged ~40s after every
start — ``/status`` stopped answering, the supervising watchdog SIGKILLed it,
and the restart stampede reproduced the race immediately.

The deadlock is reproduced in a dedicated thread with its own event loop: a
blocked loop cannot service ``asyncio.wait_for``, so an in-loop timeout would
hang the whole suite instead of failing. Joining the worker thread with a
timeout lets this fail cleanly on the regressed code.
"""

import asyncio
import threading

from simulations.store import SimulationsStore


def _run_in_isolated_loop(coro_factory, timeout):
    """Run ``coro_factory()`` on a private loop in a daemon thread.

    Returns ``(finished, error)``. ``finished`` is False when the thread was
    still running after ``timeout`` — i.e. the event loop deadlocked. The
    thread is a daemon so a wedged loop cannot block interpreter exit.
    """
    done = threading.Event()
    box = {}

    def _target():
        try:
            asyncio.run(coro_factory())
        except BaseException as e:  # noqa: BLE001 — surfaced to the assertion
            box["error"] = e
        finally:
            done.set()

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return done.wait(timeout), box.get("error")


def test_lock_is_asyncio_lock_not_threading_lock(tmp_path):
    """Pin the type: a threading.Lock here deadlocks the hub (see module docstring)."""
    s = SimulationsStore(str(tmp_path))
    assert isinstance(s._lock, asyncio.Lock), (
        "SimulationsStore._lock must be an asyncio.Lock — it is held across "
        "`await self._asave()`, so a threading.Lock blocks the event-loop "
        "thread and deadlocks the whole hub."
    )


def test_concurrent_setters_do_not_deadlock(tmp_path):
    """Overlapping setters must all complete — the exact production trigger.

    Mirrors the endpoint-sync gather: several tenants writing their sync status
    at once. On a threading.Lock this never returns.
    """
    tenants = [f"tenant-{i}" for i in range(8)]

    async def _exercise():
        s = SimulationsStore(str(tmp_path))
        await asyncio.gather(*(
            s.set_endpoint_sync_status(
                tid,
                {"tenant_id": tid, "status": "error", "pushed": 0, "errors": 0,
                 "message": "NetBox or CPPM spoke not connected",
                 "last_sync_ts": "2026-09-15T20:45:48Z", "endpoints_total": 0},
            )
            for tid in tenants
        ))
        # Every write must survive, not just not-hang.
        for tid in tenants:
            assert (await s.get_endpoint_sync_status(tid))["tenant_id"] == tid

    finished, error = _run_in_isolated_loop(_exercise, timeout=30)
    assert finished, (
        "SimulationsStore deadlocked on concurrent setters: the event loop "
        "never completed 8 overlapping set_endpoint_sync_status() calls. "
        "_lock must be an asyncio.Lock so a contending setter yields instead "
        "of blocking the event-loop thread."
    )
    assert error is None, f"concurrent setters raised: {error!r}"


def test_concurrent_mixed_setters_do_not_deadlock(tmp_path):
    """The deadlock is not specific to one setter — any two overlapping ones hang."""

    async def _exercise():
        s = SimulationsStore(str(tmp_path))
        await asyncio.gather(
            s.set_endpoint_sync_status("t1", {"status": "error"}),
            s.set_user_overrides("t2", {"k": "v"}),
            s.set_security_config("t3", {"auth": "local"}),
            s.set_source_of_truth("t4", "hub"),
        )
        assert (await s.get_user_overrides("t2")) == {"k": "v"}
        assert (await s.get_security_config("t3")) == {"auth": "local"}

    finished, error = _run_in_isolated_loop(_exercise, timeout=30)
    assert finished, (
        "SimulationsStore deadlocked on mixed concurrent setters — every setter "
        "holds _lock across `await self._asave()`."
    )
    assert error is None, f"mixed concurrent setters raised: {error!r}"


def test_no_setter_holds_a_synchronous_lock(tmp_path):
    """Source guard: no ``with self._lock:`` may return to the store.

    The async form (``async with self._lock:``) is required; the synchronous
    form only type-checks if ``_lock`` is a threading.Lock, which is the
    regression this module exists to prevent.
    """
    import inspect

    src = inspect.getsource(SimulationsStore)
    offenders = [
        ln.strip() for ln in src.splitlines()
        if ln.strip().startswith("with self._lock")
    ]
    assert not offenders, (
        f"found {len(offenders)} synchronous `with self._lock:` block(s) — use "
        "`async with self._lock:` so contention yields to the event loop."
    )
