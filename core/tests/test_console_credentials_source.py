"""Tests for where the console auto-login credential list is sourced from:
the Fernet-encrypted hub-state blob (default) vs a read-only Azure Key Vault
reference (``console_credentials_ref`` / ``LM_CONSOLE_CREDENTIALS_REF``).

The route helpers are closures inside ``routes/console.py``'s registration
function, so — like ``test_console_tenant_scoping`` — we lift the relevant
FunctionDef nodes out with ``ast`` and exec them in a namespace, exercising the
real logic without standing up the whole hub app. Vault resolution is driven
through the env credential provider (a bare secret name → ``os.environ``), so no
Azure SDK is needed.
"""
import ast
import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import security.credential_store as cs  # noqa: E402

_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "console.py")
_WANTED = {"_console_credentials_ref", "_console_creds_keyvault_backed",
           "_console_creds_from_vault", "_console_load_credentials"}


def _load_helpers():
    src = open(_CONSOLE).read()
    tree = ast.parse(src)
    ns = {"os": os, "json": json,
          "logger": types.SimpleNamespace(warning=lambda *a, **k: None,
                                          info=lambda *a, **k: None)}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in _WANTED:
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CONSOLE, "exec"), ns)
    return ns


class _Hub:
    def __init__(self, gc=None):
        self.state = types.SimpleNamespace(system_state={"global_config": gc or {}})


@pytest.fixture(autouse=True)
def _clean_env():
    cs.reset_credential_provider()
    saved = {k: os.environ.pop(k, None) for k in
             ("LM_CONSOLE_CREDENTIALS_REF", "LM_KEYVAULT_URL", "LM_TEST_CONSOLE_CREDS")}
    yield
    cs.reset_credential_provider()
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v


def test_no_ref_is_not_keyvault_backed():
    ns = _load_helpers()
    hub = _Hub(gc={})
    assert ns["_console_creds_keyvault_backed"](hub) is False
    assert ns["_console_credentials_ref"](hub) == ""


def test_config_ref_is_keyvault_backed():
    ns = _load_helpers()
    hub = _Hub(gc={"console_credentials_ref": "kv:console-creds"})
    assert ns["_console_creds_keyvault_backed"](hub) is True


def test_env_ref_overrides_config():
    ns = _load_helpers()
    os.environ["LM_CONSOLE_CREDENTIALS_REF"] = "ENVREF"
    hub = _Hub(gc={"console_credentials_ref": "cfgref"})
    assert ns["_console_credentials_ref"](hub) == "ENVREF"


def test_load_credentials_resolved_from_ref():
    ns = _load_helpers()
    os.environ["LM_TEST_CONSOLE_CREDS"] = json.dumps(
        [{"username": "admin", "password": "pw"}, {"username": "backup", "password": "x"}])
    hub = _Hub(gc={"console_credentials_ref": "LM_TEST_CONSOLE_CREDS"})  # bare name → env provider
    creds = ns["_console_load_credentials"](hub)
    assert creds == [{"username": "admin", "password": "pw"},
                     {"username": "backup", "password": "x"}]


def test_load_credentials_ref_unresolvable_fails_closed():
    ns = _load_helpers()
    hub = _Hub(gc={"console_credentials_ref": "LM_NO_SUCH_SECRET"})
    assert ns["_console_load_credentials"](hub) == []  # can't resolve → empty, never the blob


def test_load_credentials_ref_malformed_json_fails_closed():
    ns = _load_helpers()
    os.environ["LM_TEST_CONSOLE_CREDS"] = "not json {["
    hub = _Hub(gc={"console_credentials_ref": "LM_TEST_CONSOLE_CREDS"})
    assert ns["_console_load_credentials"](hub) == []
