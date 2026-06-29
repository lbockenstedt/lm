"""pytest bootstrap: make ``core/src`` importable the same way the hub runs it
(scripts add ``core/src`` to ``sys.path`` and import modules as top-level:
``import access``, ``import update_pipeline``, ``import api``, …)."""

import os
import sys

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Make the test fakes importable as ``from _fakes import FakeHub, FakeState``.
TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)