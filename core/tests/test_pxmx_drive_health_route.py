"""Tests for the Proxmox drive diagnostics backend API (/api/pxmx/drive-health)
and WebUI main.js subMenus / renderPxmxDiagnostics integration.
"""
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cache_core import StalenessPolicy
from routes import pxmx

MAIN_JS_PATH = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


@pytest.fixture(autouse=True)
def _reset_nodes_cache():
    pxmx._NODES_CACHE.clear()
    yield
    pxmx._NODES_CACHE.clear()


class _MockState:
    def __init__(self):
        self.system_state = {}

    def _mark_dirty(self):
        pass

    def is_agent_decommissioned(self, apk):
        return False


class _MockHub:
    """Mock hub for testing /api/pxmx/drive-health route."""

    def __init__(self, bound_spoke=None, global_spoke="pxmx-spoke-1",
                 drive_response=None, node_stats=None):
        self.state = _MockState()
        self._bound = bound_spoke
        self._global = global_spoke
        self.drive_response = drive_response
        self.node_stats = node_stats if node_stats is not None else [
            {"node": "pve1", "status": "online", "cluster": "lab-cluster"}
        ]
        self.calls = []
        self.warm_cache = {}
        self.warm_ts = {}

    def get_hypervisor_spoke_for_tenant(self, tid=None):
        return self._bound

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        return [self._bound] if self._bound else []

    def get_hypervisor_spoke(self):
        return self._global

    def get_all_spokes_by_type(self, module_type):
        if module_type == "hypervisor":
            return [self._global] if self._global else []
        return []

    def warm_get(self, ns, key):
        return (self.warm_cache.get(ns) or {}).get(key)

    async def warm_set(self, ns, key, data):
        self.warm_cache.setdefault(ns, {})[key] = data
        self.warm_ts[(ns, key)] = time.time()

    def seed_warm(self, ns, key, data, age_s=0.0):
        """Pre-populate the cache as if it had been written ``age_s`` ago —
        the real mixin records a timestamp alongside every entry, and the
        staleness ladder is meaningless without one."""
        self.warm_cache.setdefault(ns, {})[key] = data
        self.warm_ts[(ns, key)] = time.time() - age_s

    def warm_fetched_at(self, ns, key="_"):
        return self.warm_ts.get((ns, key))

    def warm_state(self, ns, key="_", policy=None):
        return (policy or StalenessPolicy()).classify(self.warm_fetched_at(ns, key))

    async def request_response(self, sid, cmd, payload, timeout=30.0, signing_secret=None):
        self.calls.append({"sid": sid, "cmd": cmd, "payload": payload, "timeout": timeout})
        if cmd == "GET_NODE_STATS":
            return {"payload": {"data": {"nodes": self.node_stats}}}
        if cmd == "PXMX_DRIVE_HEALTH":
            if self.drive_response is not None:
                return {"payload": {"data": self.drive_response}}
            req_node = payload.get("node") or "pve1"
            return {
                "payload": {
                    "data": {
                        "status": "SUCCESS",
                        "node": req_node,
                        "cluster": "lab-cluster",
                        "drives": [
                            {
                                "physical_index": 0,
                                "block_device": "/dev/sda",
                                "vendor": "HPE",
                                "model": "VO001920KWZQR",
                                "serial": "2F40A001ABCD",
                                "wear_level": 12,
                                "health_status": "healthy",
                                "success": True,
                            }
                        ],
                        "summary": {
                            "total_drives": 1,
                            "healthy": 1,
                            "warning": 0,
                            "critical": 0,
                            "unknown": 0,
                        },
                    }
                }
            }
        return {"payload": {"data": {}}}


def _create_ctx(authenticated=True, admin=True, tenant=None):
    async def _filter_tenant(request, data, module, ip_fields, explicit=None):
        return data

    return SimpleNamespace(
        _session_user=lambda request: {"user": {"username": "testuser"}} if authenticated else None,
        _is_admin=lambda sess: admin,
        _resolve_tenant=lambda request, explicit=None: tenant or explicit,
        _filter_tenant=_filter_tenant,
    )


def _build_client(hub, authenticated=True, admin=True, tenant=None):
    app = FastAPI()
    app.state.hub = hub
    pxmx.register(app, hub, _create_ctx(authenticated=authenticated, admin=admin, tenant=tenant))
    return TestClient(app)


def test_drive_health_unauthenticated_returns_401():
    """Unauthenticated requests must be rejected with HTTP 401."""
    hub = _MockHub()
    client = _build_client(hub, authenticated=False)
    response = client.get("/api/pxmx/drive-health")
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_drive_health_no_spoke_connected():
    """When no hypervisor spokes are connected, returns clean empty structure."""
    hub = _MockHub(bound_spoke=None, global_spoke=None)
    client = _build_client(hub, authenticated=True)
    response = client.get("/api/pxmx/drive-health")
    assert response.status_code == 200
    data = response.json()
    assert data["spoke_connected"] is False
    assert data["nodes"] == []
    assert data["summary"] == {
        "total_drives": 0,
        "healthy": 0,
        "warning": 0,
        "critical": 0,
        "unknown": 0,
    }


def test_drive_health_authenticated_success_schema():
    """Authenticated request returns drive health schema with drives and summaries."""
    hub = _MockHub(global_spoke="pxmx-global")
    client = _build_client(hub, authenticated=True)
    response = client.get("/api/pxmx/drive-health")
    assert response.status_code == 200
    data = response.json()
    assert data["spoke_connected"] is True
    assert len(data["nodes"]) >= 1

    node_entry = data["nodes"][0]
    assert node_entry["node"] == "pve1"
    assert node_entry["cluster"] == "lab-cluster"
    assert len(node_entry["drives"]) == 1

    drive = node_entry["drives"][0]
    assert drive["physical_index"] == 0
    assert drive["block_device"] == "/dev/sda"
    assert drive["vendor"] == "HPE"
    assert drive["model"] == "VO001920KWZQR"
    assert drive["serial"] == "2F40A001ABCD"
    assert drive["wear_level"] == 12
    assert drive["health_status"] == "healthy"
    assert drive["success"] is True

    assert data["summary"]["total_drives"] == 1
    assert data["summary"]["healthy"] == 1
    assert data["summary"]["warning"] == 0
    assert data["summary"]["critical"] == 0
    assert data["summary"]["unknown"] == 0


def test_drive_health_specific_node_parameter():
    """When ?node=pve2 is specified, payload sent to spoke contains {'node': 'pve2'}."""
    hub = _MockHub(global_spoke="pxmx-global")
    client = _build_client(hub, authenticated=True)
    response = client.get("/api/pxmx/drive-health?node=pve2")
    assert response.status_code == 200

    dh_calls = [c for c in hub.calls if c["cmd"] == "PXMX_DRIVE_HEALTH"]
    assert len(dh_calls) == 1
    assert dh_calls[0]["payload"] == {"node": "pve2"}
    assert dh_calls[0]["timeout"] == 30.0

    data = response.json()
    assert data["nodes"][0]["node"] == "pve2"


def test_drive_health_multi_drive_warning_critical_summary():
    """Verifies that wear levels and health statuses are properly summarized across drives."""
    drives_payload = {
        "status": "SUCCESS",
        "node": "pve-storage",
        "cluster": "datacenter",
        "drives": [
            {
                "physical_index": 0,
                "block_device": "/dev/sda",
                "vendor": "HPE",
                "model": "VO001920KWZQR",
                "serial": "SN001",
                "wear_level": 15,
                "health_status": "healthy",
                "success": True,
            },
            {
                "physical_index": 1,
                "block_device": "/dev/sdb",
                "vendor": "Samsung",
                "model": "PM883",
                "serial": "SN002",
                "wear_level": 84,
                "health_status": "warning",
                "success": True,
            },
            {
                "physical_index": 2,
                "block_device": "/dev/sdc",
                "vendor": "Micron",
                "model": "5300PRO",
                "serial": "SN003",
                "wear_level": 93,
                "health_status": "critical",
                "success": True,
            },
            {
                "physical_index": 3,
                "block_device": "/dev/sdd",
                "vendor": "Generic",
                "model": "Disk",
                "serial": "SN004",
                "wear_level": None,
                "health_status": "unknown",
                "success": False,
            },
        ],
    }
    hub = _MockHub(global_spoke="pxmx-global", drive_response=drives_payload)
    client = _build_client(hub, authenticated=True)
    response = client.get("/api/pxmx/drive-health?node=pve-storage")
    assert response.status_code == 200
    data = response.json()
    assert data["summary"] == {
        "total_drives": 4,
        "healthy": 1,
        "warning": 1,
        "critical": 1,
        "unknown": 1,
    }


def test_drive_health_tenant_spoke_resolution():
    """When tenant is provided, uses get_hypervisor_spokes_for_tenant."""
    hub = _MockHub(bound_spoke="pxmx-acme", global_spoke="pxmx-global")
    client = _build_client(hub, authenticated=True, tenant="acme")
    response = client.get("/api/pxmx/drive-health?tenant=acme")
    assert response.status_code == 200

    dh_calls = [c for c in hub.calls if c["cmd"] == "PXMX_DRIVE_HEALTH"]
    assert len(dh_calls) >= 1
    # Ensure call was dispatched to the tenant's bound spoke
    assert dh_calls[0]["sid"] == "pxmx-acme"


def test_webui_main_js_submenus_and_diagnostics_renderer():
    """Verify WebUI/main.js has 'Diagnostics' in subMenus.pxmx and renderPxmxDiagnostics."""
    assert MAIN_JS_PATH.exists(), f"WebUI/main.js not found at {MAIN_JS_PATH}"
    content = MAIN_JS_PATH.read_text(encoding="utf-8")

    # Verify 'Diagnostics' is present in pxmx submenu
    assert "pxmx: ['Overview', 'Virtual Machines', 'Diagnostics', 'Settings']" in content or (
        "'Diagnostics'" in content and "pxmx:" in content
    )
    # Check specifically in VIEW_SUBMENUS
    assert "pxmx: ['Overview', 'Virtual Machines', 'Diagnostics', 'Settings']" in content

    # Verify renderPxmxDiagnostics is defined and called
    assert "async function renderPxmxDiagnostics(container)" in content
    assert "if (subMenu === 'Diagnostics')" in content
    assert "await renderPxmxDiagnostics(container)" in content

    # Verify required UI elements are present in renderPxmxDiagnostics
    assert "Drive Health & Diagnostics" in content
    assert "All drives healthy" in content
    assert "Attention needed" in content
    assert "Total Drives" in content
    assert "Healthy" in content
    assert "Warning (wear >= 80%)" in content
    assert "Critical (wear >= 90%)" in content
    assert "↻ Run Diagnostics / Refresh" in content
    assert "Device Path" in content
    assert "Vendor & Model" in content
    assert "Serial Number" in content
    assert "Wear Level" in content
    assert "Health Status" in content
