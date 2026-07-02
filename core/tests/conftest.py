"""pytest bootstrap: make ``core/src`` importable the same way the hub runs it
(scripts add ``core/src`` to ``sys.path`` and import modules as top-level:
``import access``, ``import update_pipeline``, ``import api``, …)."""

import os
import sys

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