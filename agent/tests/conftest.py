"""pytest bootstrap: make ``agent/src`` and ``core/src`` importable the way the
agent runs (PYTHONPATH=/opt/lm/core/src:/opt/lm/agent/src, modules imported as
top-level: ``import agent_spoke``, ``import base_spoke``)."""

import os
import sys

# At-rest encryption (security.encryption) builds its Fernet at import time and
# requires LM_FERNET_KEY. Generate a fresh throwaway key per test run (no literal
# key committed — secret scanners flag any structurally-valid Fernet key). Tests
# only round-trip within one run, so a random key is fine; a pre-set env value is
# still honored.
if "LM_FERNET_KEY" not in os.environ:
    from cryptography.fernet import Fernet as _Fernet
    os.environ["LM_FERNET_KEY"] = _Fernet.generate_key().decode()
    del _Fernet

_AGENT_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
_CORE_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "core", "src"))
# lm repo root — needed so `core.src.messaging.control_plane` (PEP-420 namespace
# package chain) resolves for the SPOKE_UPDATE override tests.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_AGENT_SRC, _CORE_SRC, _LM_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)