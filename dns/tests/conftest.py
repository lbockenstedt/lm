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

import pytest


@pytest.fixture(autouse=True)
def _isolate_unbound_query_log_paths(tmp_path, monkeypatch):
    """``UnboundManager.sync()``/``get_stats()`` idempotently enable query
    logging, which writes LOGGING_CONF and creates QUERY_LOG's directory.
    Point both at the test's tmp dir so no test can touch the real
    /etc/unbound or /var/log/unbound (tests may still override them)."""
    try:
        import unbound_manager
    except Exception:  # noqa: BLE001 — not every test imports the manager
        return
    monkeypatch.setattr(unbound_manager, "LOGGING_CONF",
                        str(tmp_path / "_lm-logging.conf"))
    monkeypatch.setattr(unbound_manager, "QUERY_LOG",
                        str(tmp_path / "_unbound-log" / "lm-queries.log"))
