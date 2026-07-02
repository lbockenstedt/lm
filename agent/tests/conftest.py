"""pytest bootstrap: make ``agent/src`` and ``core/src`` importable the way the
agent runs (PYTHONPATH=/opt/lm/core/src:/opt/lm/agent/src, modules imported as
top-level: ``import agent_spoke``, ``import base_spoke``)."""

import os
import sys

os.environ.setdefault("LM_FERNET_KEY", "REDACTED_TEST_FERNET_KEY=")

_AGENT_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
_CORE_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "core", "src"))
for _p in (_AGENT_SRC, _CORE_SRC):
    if _p not in sys.path:
        sys.path.insert(0, _p)