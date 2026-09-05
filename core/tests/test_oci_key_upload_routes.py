"""POST /setup/oci-nsg/upload-key and /setup/oci-vault/upload-key.

Lets an admin upload the OCI API signing private key (PEM) via the WebUI
instead of hand-copying it onto the hub / typing a filesystem path into
``key_path``. Both routes share ``oci_auth.write_uploaded_private_key`` (see
``test_oci_auth.py`` for the validation/write-path unit tests); this module
pins the ROUTE-level contract: multipart upload -> config's ``key_path`` is
persisted immediately (independent of the rest of the form), a bad upload is
rejected with 400 and never touches the stored config, and each integration
writes to its OWN file (oci_nsg vs oci_vault use separate keys).
"""
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

import importlib.util
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
_ROUTES_DIR = os.path.join(_SRC, "routes")
if _ROUTES_DIR not in sys.path:
    sys.path.append(_ROUTES_DIR)


def _load_from_path(modname, path):
    """Load a routes/*.py module by explicit file path, under a UNIQUE module
    name -- ``core/src/oci_nsg.py`` (business logic) and
    ``core/src/routes/oci_nsg.py`` (this route file) share the bare name
    ``oci_nsg``, so a plain ``import oci_nsg`` would resolve to whichever one
    sys.path favors first (core/src, per the ordering above) and silently
    load the WRONG module here."""
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


oci_nsg_routes = _load_from_path("oci_nsg_routes", os.path.join(_ROUTES_DIR, "oci_nsg.py"))
oci_vault_routes = _load_from_path("oci_vault_routes", os.path.join(_ROUTES_DIR, "oci_vault.py"))


def _gen_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())


class _FakeCtx:
    def _session_user(self, request):
        return {"user": "admin"}

    def _is_admin(self, sess):
        return True


class _FakeState:
    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": global_config or {}}

    def _mark_dirty(self):
        pass


class _FakeRouteHub:
    def __init__(self, data_dir, global_config=None):
        self.state = _FakeState(data_dir, global_config)


def _build_nsg(tmp_path, global_config=None):
    app = FastAPI()
    hub = _FakeRouteHub(str(tmp_path), global_config)
    app.state.hub = hub
    oci_nsg_routes.register(app, hub, _FakeCtx())
    return TestClient(app), hub


def _build_vault(tmp_path, global_config=None):
    app = FastAPI()
    hub = _FakeRouteHub(str(tmp_path), global_config)
    app.state.hub = hub
    oci_vault_routes.register(app, hub, _FakeCtx())
    return TestClient(app), hub


def test_oci_nsg_upload_key_persists_path_into_config(tmp_path):
    c, hub = _build_nsg(tmp_path, {"oci_nsg": {"tenancy_ocid": "ocid1.tenancy.oc1..t"}})
    pem = _gen_pem()
    r = c.post("/setup/oci-nsg/upload-key", files={"file": ("key.pem", pem)})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert os.path.isfile(body["key_path"])
    with open(body["key_path"], "rb") as f:
        assert f.read() == pem
    # Persisted into config AND other fields untouched.
    cfg = hub.state.system_state["global_config"]["oci_nsg"]
    assert cfg["key_path"] == body["key_path"]
    assert cfg["tenancy_ocid"] == "ocid1.tenancy.oc1..t"


def test_oci_nsg_upload_key_rejects_garbage(tmp_path):
    c, hub = _build_nsg(tmp_path, {"oci_nsg": {"key_path": "old-path"}})
    r = c.post("/setup/oci-nsg/upload-key", files={"file": ("key.pem", b"not a key")})
    assert r.status_code == 400
    # Config's key_path must be untouched on rejection.
    assert hub.state.system_state["global_config"]["oci_nsg"]["key_path"] == "old-path"


def test_oci_vault_upload_key_persists_path_into_config(tmp_path):
    c, hub = _build_vault(tmp_path, {"oci_vault": {"region": "us-ashburn-1"}})
    pem = _gen_pem()
    r = c.post("/setup/oci-vault/upload-key", files={"file": ("key.pem", pem)})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert os.path.isfile(body["key_path"])
    cfg = hub.state.system_state["global_config"]["oci_vault"]
    assert cfg["key_path"] == body["key_path"]
    assert cfg["region"] == "us-ashburn-1"


def test_oci_nsg_and_oci_vault_uploads_write_to_different_files(tmp_path):
    """Each integration owns its own auth block/key -- a customer may want a
    narrower-scoped OCI user/key per integration (see module docstrings)."""
    c_nsg, hub_nsg = _build_nsg(tmp_path)
    c_vault, hub_vault = _build_vault(tmp_path)
    r1 = c_nsg.post("/setup/oci-nsg/upload-key", files={"file": ("a.pem", _gen_pem())})
    r2 = c_vault.post("/setup/oci-vault/upload-key", files={"file": ("b.pem", _gen_pem())})
    assert r1.json()["key_path"] != r2.json()["key_path"]


def test_oci_vault_upload_key_rejects_empty_upload(tmp_path):
    c, hub = _build_vault(tmp_path)
    r = c.post("/setup/oci-vault/upload-key", files={"file": ("k.pem", b"")})
    assert r.status_code == 400
    assert "oci_vault" not in hub.state.system_state["global_config"]
