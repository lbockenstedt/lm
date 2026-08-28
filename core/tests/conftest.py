"""pytest bootstrap: make ``core/src`` importable the same way the hub runs it
(scripts add ``core/src`` to ``sys.path`` and import modules as top-level:
``import access``, ``import update_pipeline``, ``import api``, …)."""

import asyncio
import os
import sys

import pytest

# At-rest encryption (security.encryption) builds its Fernet at import time and
# requires LM_FERNET_KEY. Generate a fresh throwaway key per test run so the
# state/manager import (and any test that round-trips encrypted state files)
# works without a real .env — and so NO literal Fernet key is committed to the
# repo (secret scanners flag any structurally-valid key). Tests only round-trip
# (encrypt then decrypt within one run), so a random key is fine. A pre-set
# LM_FERNET_KEY in the env is still honored via setdefault.
if "LM_FERNET_KEY" not in os.environ:
    from cryptography.fernet import Fernet as _Fernet
    os.environ["LM_FERNET_KEY"] = _Fernet.generate_key().decode()
    del _Fernet

# dep_guard.ensure_requirements runs at main.py import time. A dev test box may
# be missing optional deps (e.g. zeroconf) — never attempt a real `pip install`
# into the test interpreter. Production never sets this.
os.environ.setdefault("LM_DEP_GUARD_DISABLE", "1")

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Make the test fakes importable as ``from _fakes import FakeHub, FakeState``.
TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

@pytest.fixture(autouse=True)
def _current_event_loop():
    """Guarantee the main thread has a usable current event loop.

    Dozens of tests here drive async code synchronously via
    ``asyncio.get_event_loop().run_until_complete(...)``. On Python 3.10+ that
    raises ``RuntimeError: There is no current event loop in thread
    'MainThread'`` as soon as anything in the session has consumed and closed
    the default loop (``asyncio.run``, pytest-asyncio, or a test that closes it
    deliberately). The result is order-dependent: the tests pass alone and fail
    in a full run.

    Rather than rewrite every call site, restore the invariant they were
    written against. ``asyncio.run`` is NOT a drop-in substitute for all of
    them: on 3.9 ``asyncio.Queue()`` binds to the current loop at construction,
    so several tests build objects and then run coroutines that must share that
    same loop.

    A *closed* loop is also replaced — ``get_event_loop()`` returns closed
    loops without raising, and ``run_until_complete`` on one fails with "Event
    loop is closed".
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    yield
