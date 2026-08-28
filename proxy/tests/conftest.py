"""pytest bootstrap for the proxy component.

``proxy_app``/``proxy_spoke`` import shared hub code — ``security.*`` and
``core.src.base_spoke`` — so the tests need both the repo ROOT (which makes
``core.src.*`` importable) and ``core/src`` (which makes ``security`` importable
as a top-level package, the way the hub runs it) on ``sys.path``.

This used to come for free: CI ran every component in ONE pytest process, so
``core/tests/conftest.py`` had already put those on the path by the time the
proxy modules were collected. That also meant the components fought over shared
top-level module names (agent and henet both define ``control_plane``), so the
components now run as separate processes — and proxy has to bootstrap its own
path instead of relying on another component's conftest side effects.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
CORE_SRC = os.path.join(ROOT, "core", "src")

for _p in (CORE_SRC, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# security.encryption builds its Fernet at import time and requires
# LM_FERNET_KEY. Use a throwaway key so no real .env is needed and no literal
# key is committed (secret scanners flag structurally-valid keys). Mirrors
# core/tests/conftest.py.
if "LM_FERNET_KEY" not in os.environ:
    from cryptography.fernet import Fernet as _Fernet

    os.environ["LM_FERNET_KEY"] = _Fernet.generate_key().decode()
    del _Fernet

os.environ.setdefault("LM_DEP_GUARD_DISABLE", "1")
