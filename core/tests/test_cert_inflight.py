"""Hub-side in-flight cert-distribution tracking (yellow target badge + timer).

While the hub awaits an INSTALL_CERT confirmation, the target is "in flight" —
the WebUI surfaces it as a yellow badge with an elapsed timer (fetched from
``GET /api/le/inflight``) because we can't predict how fast a cert will transfer
or install (the hypervisor path's pveproxy restart can take many minutes).

``_inflight_rr`` wraps ``request_response`` so the pure helpers'
``rr(spoke_id, "INSTALL_CERT", {domain, module_type, identifier, ...})`` records
the target before the await and clears it in a ``finally`` (SUCCESS or ERROR).
Non-INSTALL_CERT rr calls (LE_GET_CERT / LE_MARK_DISTRIBUTED) pass through
untouched. Exercised via a bare ``HubCertDistributionMixin`` (no Hub
construction), mirroring test_cert_retry_interval.py.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_cert_distribution import HubCertDistributionMixin  # noqa: E402


class _FakeState:
    def __init__(self, gc=None):
        self._gc = gc or {}
    def get_global_config(self):
        return self._gc


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _hub(gc=None):
    m = HubCertDistributionMixin()
    m.state = _FakeState(gc)
    return m


def test_inflight_rr_records_during_and_clears_after():
    h = _hub()
    seen = {}

    async def fake_rr(spoke_id, command, data=None, timeout=None):
        # While inside the INSTALL_CERT await, the in-flight entry exists.
        seen["during"] = dict(h._cert_inflight())
        return {"payload": {"data": {"status": "SUCCESS", "message": "installed"}}}

    wrapped = h._inflight_rr(fake_rr)
    _run(wrapped("pxmx-1", "INSTALL_CERT",
                {"domain": "a.example.com", "module_type": "hypervisor",
                 "identifier": "node1"}))
    assert "a.example.com|hypervisor|node1" in seen["during"]
    entry = seen["during"]["a.example.com|hypervisor|node1"]
    assert entry["domain"] == "a.example.com"
    assert entry["module_type"] == "hypervisor"
    assert entry["identifier"] == "node1"
    assert isinstance(entry["since"], float)
    # Cleared once the push returned.
    assert h._cert_inflight() == {}


def test_inflight_rr_clears_on_error_too():
    h = _hub()

    async def fake_rr(spoke_id, command, data=None, timeout=None):
        return {"payload": {"data": {"status": "ERROR", "message": "boom"}}}

    wrapped = h._inflight_rr(fake_rr)
    _run(wrapped("fw-1", "INSTALL_CERT",
                {"domain": "a.example.com", "module_type": "firewall",
                 "identifier": "edge-1"}))
    # The finally runs on the ERROR path too → no stale in-flight entry.
    assert h._cert_inflight() == {}


def test_inflight_rr_clears_on_exception():
    h = _hub()

    async def fake_rr(spoke_id, command, data=None, timeout=None):
        raise RuntimeError("relay exploded")

    wrapped = h._inflight_rr(fake_rr)
    try:
        _run(wrapped("fw-1", "INSTALL_CERT",
                    {"domain": "a.example.com", "module_type": "firewall", "identifier": ""}))
    except RuntimeError:
        pass
    assert h._cert_inflight() == {}


def test_inflight_rr_ignores_non_install_cert():
    h = _hub()

    async def fake_rr(spoke_id, command, data=None, timeout=None):
        return {"payload": {"data": {"status": "SUCCESS", "certs": []}}}

    wrapped = h._inflight_rr(fake_rr)
    # LE_GET_CERT and LE_MARK_DISTRIBUTED must pass through WITHOUT recording.
    _run(wrapped("le-1", "LE_GET_CERT", {"domain": "a.example.com"}))
    _run(wrapped("le-1", "LE_MARK_DISTRIBUTED",
                {"domain": "a.example.com", "module_type": "firewall",
                 "identifier": "edge-1", "status": "SUCCESS", "hash": "h"}))
    assert h._cert_inflight() == {}


def test_cert_inflight_lazy_init_returns_same_dict():
    h = _hub()
    assert not hasattr(h, "cert_dist_inflight") or h.cert_dist_inflight == h._cert_inflight()
    d = h._cert_inflight()
    d["x|y|z"] = {"since": 1.0}
    assert h._cert_inflight() is d  # same object (lazy init is stable)