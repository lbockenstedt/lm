"""Tests for the 'migrate local passwords to the vault' warning signal.

When the Credential Vault is enabled but legacy LOCAL console passwords still
linger on the hub (the Fernet blob ``console_credentials_enc``), the console
credentials endpoint surfaces a ``migrate_warning`` so the operator can move
them by hand — we NEVER auto-migrate or auto-delete. The detection helper
``_console_local_passwords_present`` is the presence signal that gates it.

Like ``test_console_credentials_source``, the helper is a closure inside
``routes/console.py``'s registration function, so we lift the FunctionDef out
with ``ast`` and exec it in a bare namespace.
"""
import ast
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "console.py")
_WANTED = {"_console_local_passwords_present", "_cv_admin_bucket"}


def _load_helpers():
    src = open(_CONSOLE).read()
    tree = ast.parse(src)
    ns = {"os": os,
          "logger": types.SimpleNamespace(warning=lambda *a, **k: None,
                                          info=lambda *a, **k: None)}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in _WANTED:
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CONSOLE, "exec"), ns)
    return ns


class _Hub:
    def __init__(self, system_state=None):
        self.state = types.SimpleNamespace(system_state=system_state or {})


def test_no_local_blob_means_no_local_passwords():
    ns = _load_helpers()
    assert ns["_console_local_passwords_present"](_Hub({})) is False


def test_present_local_blob_is_detected():
    ns = _load_helpers()
    hub = _Hub({"console_credentials_enc": "gAAAAAB_fake_fernet_blob=="})
    assert ns["_console_local_passwords_present"](hub) is True


def test_empty_local_blob_is_not_present():
    ns = _load_helpers()
    hub = _Hub({"console_credentials_enc": ""})
    assert ns["_console_local_passwords_present"](hub) is False


def test_admin_bucket_default():
    ns = _load_helpers()
    # Resolves via cred_vault.ADMIN_BUCKET when importable, else the "__admin__"
    # literal — either way the console vault slot is the Global Admin bucket.
    assert ns["_cv_admin_bucket"]() == "__admin__"
