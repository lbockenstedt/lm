"""pytest bootstrap: make ``agent/src`` and ``core/src`` importable the way the
agent runs (PYTHONPATH=/opt/lm/core/src:/opt/lm/agent/src, modules imported as
top-level: ``import agent_spoke``, ``import base_spoke``)."""

import os
import sys

os.environ.setdefault("LM_FERNET_KEY", "REDACTED_TEST_FERNET_KEY=")

_AGENT_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
_CORE_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "core", "src"))
# lm repo root — needed so `core.src.messaging.control_plane` (PEP-420 namespace
# package chain) resolves for the SPOKE_UPDATE override tests.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_AGENT_SRC, _CORE_SRC, _LM_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)