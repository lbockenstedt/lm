"""The retired hub-local console password store is removed, not tolerated.

Console logins live in the Credential Vault, which works on every deployment
(it falls back to its own encrypted ``blobs`` map when no cloud vault is
configured). The second, module-private store — the Fernet blob
``console_credentials_enc`` in hub state — is therefore redundant, and on any
hub whose Fernet key was replaced (re-install, restore, rotation without
``LM_FERNET_KEY_PREVIOUS``) it is an unreadable ORPHAN that made every resolve
log "could not decrypt stored credentials" and return [] — which looked like
the reason the credential list was empty while hiding the real one.

``_console_purge_legacy_credentials`` drops it on sight. Like
``test_console_credentials_source``, the helper is a closure inside
``routes/console.py``'s registration function, so we lift the FunctionDef out
with ``ast`` and exec it in a bare namespace.
"""
import ast
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "console.py")
_WANTED = {"_console_purge_legacy_credentials", "_cv_admin_bucket",
           "_console_warn_no_credentials", "_console_clear_no_credentials"}


def _load_helpers(logs=None):
    src = open(_CONSOLE).read()
    tree = ast.parse(src)

    def _rec(*a, **k):
        if logs is not None:
            logs.append(a[0] % a[1:] if len(a) > 1 else a[0])

    ns = {"os": os,
          "logger": types.SimpleNamespace(warning=_rec, info=_rec)}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in _WANTED:
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CONSOLE, "exec"), ns)
    return ns


class _Hub:
    def __init__(self, system_state=None):
        self.dirty = 0
        self.state = types.SimpleNamespace(system_state=system_state or {},
                                           _mark_dirty=self._mark)

    def _mark(self):
        self.dirty += 1


# ── the purge ───────────────────────────────────────────────────────────────
def test_purge_is_a_noop_when_there_is_no_legacy_blob():
    ns = _load_helpers()
    hub = _Hub({})
    assert ns["_console_purge_legacy_credentials"](hub) is False
    assert hub.dirty == 0  # nothing changed -> no needless state write


def test_purge_removes_an_unreadable_orphan_blob():
    ns = _load_helpers()
    hub = _Hub({"console_credentials_enc": "gAAAAAB_unreadable_orphan==",
                "keep_me": 1})
    assert ns["_console_purge_legacy_credentials"](hub) is True
    assert "console_credentials_enc" not in hub.state.system_state
    assert hub.state.system_state["keep_me"] == 1   # surgical
    assert hub.dirty == 1                            # persisted


def test_purge_removes_an_empty_blob_too():
    """An empty string still occupied the key and kept the dead code path
    reachable — the key goes, not just its value."""
    ns = _load_helpers()
    hub = _Hub({"console_credentials_enc": ""})
    assert ns["_console_purge_legacy_credentials"](hub) is True
    assert "console_credentials_enc" not in hub.state.system_state


def test_purge_is_idempotent():
    ns = _load_helpers()
    hub = _Hub({"console_credentials_enc": "x"})
    assert ns["_console_purge_legacy_credentials"](hub) is True
    assert ns["_console_purge_legacy_credentials"](hub) is False
    assert hub.dirty == 1


def test_purge_survives_a_failing_state_writer():
    """A persistence failure must not 500 the request that triggered the purge."""
    ns = _load_helpers()
    hub = _Hub({"console_credentials_enc": "x"})

    def _boom():
        raise RuntimeError("disk full")

    hub.state._mark_dirty = _boom
    assert ns["_console_purge_legacy_credentials"](hub) is True
    assert "console_credentials_enc" not in hub.state.system_state


# ── the replacement diagnostic ──────────────────────────────────────────────
def test_no_credentials_warning_names_spoke_tenant_and_where_to_look():
    logs = []
    ns = _load_helpers(logs)
    hub = _Hub({})
    ns["_console_warn_no_credentials"](hub, "spoke-1", "dxp",
                                       {"buckets": ["__admin__", "dxp"],
                                        "candidates": 0, "unusable": 0})
    assert len(logs) == 1
    msg = logs[0]
    assert "spoke-1" in msg and "dxp" in msg
    assert "__admin__" in msg
    assert "Credential Library" in msg


def test_no_credentials_warning_distinguishes_wrong_shaped_secrets():
    """The operator-visible difference between 'you never added a console
    login' and 'the secret you added has no username/password' — e.g. an
    API-key secret typed `login` holding client_id/client_secret."""
    logs = []
    ns = _load_helpers(logs)
    ns["_console_warn_no_credentials"](_Hub({}), "s1", "ra",
                                       {"buckets": ["__admin__", "ra"],
                                        "candidates": 2, "unusable": 2})
    assert "username/password" in logs[0]
    assert "check their fields" in logs[0]


def test_no_credentials_warning_is_logged_once_per_spoke():
    """The seed retries on every trigger; without throttling this warning was
    the log-spam it replaced."""
    logs = []
    ns = _load_helpers(logs)
    hub = _Hub({})
    stats = {"buckets": ["__admin__"], "candidates": 0, "unusable": 0}
    for _ in range(25):
        ns["_console_warn_no_credentials"](hub, "s1", "t", stats)
    assert len(logs) == 1


def test_distinct_spokes_each_get_their_own_warning():
    logs = []
    ns = _load_helpers(logs)
    hub = _Hub({})
    stats = {"buckets": ["__admin__"], "candidates": 0, "unusable": 0}
    ns["_console_warn_no_credentials"](hub, "s1", "t", stats)
    ns["_console_warn_no_credentials"](hub, "s2", "t", stats)
    assert len(logs) == 2


def test_a_seeded_spoke_is_reported_again_if_it_regresses():
    """Clearing on success means a LATER loss of credentials is not silently
    suppressed by the once-per-spoke throttle."""
    logs = []
    ns = _load_helpers(logs)
    hub = _Hub({})
    stats = {"buckets": ["__admin__"], "candidates": 0, "unusable": 0}
    ns["_console_warn_no_credentials"](hub, "s1", "t", stats)
    ns["_console_clear_no_credentials"](hub, "s1")
    ns["_console_warn_no_credentials"](hub, "s1", "t", stats)
    assert len(logs) == 2


def test_clear_is_safe_before_any_warning():
    ns = _load_helpers()
    ns["_console_clear_no_credentials"](_Hub({}), "never-seen")
