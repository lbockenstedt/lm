"""pytest bootstrap for the dns component.

``unbound_manager`` is imported as a TOP-LEVEL module the way the DNS cluster
worker runs it on the node (``/opt/lm/dns/src/unbound_manager.py``), so the
component's own ``src`` has to be on ``sys.path``.

Each component gets its own pytest process (see ci.yml) because components
share top-level module names, so this cannot rely on another component's
conftest having already set the path up.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
DNS_SRC = os.path.abspath(os.path.join(_HERE, "..", "src"))

if DNS_SRC not in sys.path:
    sys.path.insert(0, DNS_SRC)
