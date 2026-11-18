"""Tests for operator-owned display-name provenance in Setup routes."""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import setup


class _State:
    """Minimal persisted state used by the spoke metadata route."""

    def __init__(self):
        self.system_state = {
            "known_modules": ["agent-node"],
            "module_names": {"agent-node": "node"},
            "module_metadata": {
                "agent-node": {"display_name": "node", "display_name_source": "auto"},
            },
        }

    def update_module_metadata(self, spoke_id, metadata):
        """Merge route metadata the way StateManager does."""
        row = self.system_state["module_metadata"].setdefault(
            spoke_id, {"display_name": spoke_id, "description": ""})
        row.update(metadata)
        if "display_name" in metadata:
            self.system_state["module_names"][spoke_id] = metadata["display_name"]

    def _mark_dirty(self):
        """Match the StateManager save hook."""


class _Hub:
    """Resolve spoke aliases the same way the running hub does."""

    def __init__(self, state, aliases=None):
        self.state = state
        self.aliases = aliases or {}

    def _primary_key(self, spoke_id):
        """Return the persisted key for a connected spoke."""
        return self.aliases.get(spoke_id, spoke_id)


def test_setup_spoke_metadata_preserves_auto_name_until_explicitly_edited():
    """Unchanged names stay auto-derived; explicit edits become operator-owned."""
    state = _State()
    hub = _Hub(state)
    app = FastAPI()
    app.state.hub = hub
    ctx = SimpleNamespace(
        _session_user=lambda _request: {"permissions": {"admin": True}},
        _is_admin=lambda _session: True,
    )
    setup.register(app, hub, ctx)

    response = TestClient(app).post("/setup/spoke-metadata", json={
        "spoke_id": "agent-node",
        "metadata": {
            "display_name": "node",
            "description": "Updated description",
            "display_name_source": "auto",
        },
    })

    assert response.status_code == 200
    metadata = state.system_state["module_metadata"]["agent-node"]
    assert metadata["display_name"] == "node"
    assert metadata["description"] == "Updated description"
    assert metadata["display_name_source"] == "auto"

    response = TestClient(app).post("/setup/spoke-metadata", json={
        "spoke_id": "agent-node",
        "metadata": {
            "display_name": "node",
            "display_name_edited": True,
            "display_name_source": "auto",
        },
    })

    assert response.status_code == 200
    assert metadata["display_name_source"] == "operator"


def test_setup_spoke_metadata_uses_primary_key_for_auto_name():
    """A guid-primary spoke keeps its auto name on a description-only edit."""
    state = _State()
    state.system_state["known_modules"] = ["connect-id"]
    state.system_state["module_metadata"] = {
        "guid-1": {
            "display_name": "node",
            "display_name_source": "auto",
            "description": "Existing description",
        },
    }
    state.system_state["module_names"] = {"guid-1": "node"}
    hub = _Hub(state, {"connect-id": "guid-1"})
    app = FastAPI()
    app.state.hub = hub
    ctx = SimpleNamespace(
        _session_user=lambda _request: {"permissions": {"admin": True}},
        _is_admin=lambda _session: True,
    )
    setup.register(app, hub, ctx)

    client = TestClient(app)
    opened = client.get("/setup/spoke-metadata/connect-id")
    assert opened.status_code == 200
    metadata = opened.json()["metadata"]
    assert metadata["description"] == "Existing description"

    response = client.post("/setup/spoke-metadata", json={
        "spoke_id": "connect-id",
        "metadata": {
            "display_name": metadata["display_name"],
            "description": metadata["description"],
        },
    })

    assert response.status_code == 200
    assert state.system_state["module_metadata"] == {
        "guid-1": {
            "display_name": "node",
            "display_name_source": "auto",
            "description": "Existing description",
        },
    }
