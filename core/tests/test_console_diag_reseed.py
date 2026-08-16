"""The console diagnostics view re-seeds operator credentials.

A console spoke holds its auto-login credential list in memory only, so a
restart (manual or self-update) wipes it and auto-identify falls back to the
factory-default set alone — "auth rejected" for devices whose real creds were
saved. Diagnostics is the page an operator opens first when login is failing,
so it must re-seed any (re)connected spoke, exactly like the ports list does.

The route helpers are closures inside ``routes/console.py``'s registration
function, so — like ``test_console_credentials_source`` — we lift the relevant
FunctionDef nodes with ``ast`` and exec them in a namespace, injecting a fake
``_console_load_credentials`` so no Fernet/Key Vault is needed.
"""
import ast
import os
import types

import pytest

_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "console.py")
_WANTED = {"_console_seed_credentials", "_console_mark_seeded"}


def _load_seed_helpers(creds):
    """Lift the seed helpers and inject a stub credential loader returning
    ``creds`` so we exercise the real push/skip/mark logic in isolation."""
    src = open(_CONSOLE).read()
    tree = ast.parse(src)
    ns = {"getattr": getattr,
          "_console_load_credentials": lambda hub: creds,
          "logger": types.SimpleNamespace(warning=lambda *a, **k: None,
                                           info=lambda *a, **k: None)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _WANTED:
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CONSOLE, "exec"), ns)
    return ns


class _Hub:
    def __init__(self, seeded=None):
        self._console_creds_seeded = set(seeded or [])
        self.pushed = []  # (sid, cmd, data)

    async def send_to_spoke_command(self, sid, cmd, data):
        self.pushed.append((sid, cmd, data))


@pytest.mark.asyncio
async def test_reseeds_a_forgotten_spoke():
    creds = [{"username": "admin", "password": "s3cret"}]
    ns = _load_seed_helpers(creds)
    hub = _Hub(seeded=set())  # restart forgot the marker
    await ns["_console_seed_credentials"](hub, ["lm-agent-console"])
    assert hub.pushed == [("lm-agent-console", "CONSOLE_SET_CREDENTIALS",
                           {"credentials": creds})]
    assert "lm-agent-console" in hub._console_creds_seeded  # now marked


@pytest.mark.asyncio
async def test_skips_an_already_seeded_spoke():
    ns = _load_seed_helpers([{"username": "admin", "password": "x"}])
    hub = _Hub(seeded={"lm-agent-console"})
    await ns["_console_seed_credentials"](hub, ["lm-agent-console"])
    assert hub.pushed == []  # no duplicate push


@pytest.mark.asyncio
async def test_no_push_when_no_operator_creds_saved():
    ns = _load_seed_helpers([])  # nothing saved in hub state / vault
    hub = _Hub(seeded=set())
    await ns["_console_seed_credentials"](hub, ["lm-agent-console"])
    assert hub.pushed == []  # only factory defaults will be tried on the agent


def test_diagnostics_endpoint_seeds_credentials():
    """Guard: the diagnostics route must call the seed helper (the ports list
    already does; diagnostics is what operators open when login fails)."""
    src = open(_CONSOLE).read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "console_diagnostics")
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_console_seed_credentials" in calls


def test_diagnostics_endpoint_returns_debug_block():
    """Guard: the diagnostics route must include a hub-side ``debug`` block so the
    credential/seed state is visible even when a console agent's own summary is
    missing (stale hub / agent not reporting)."""
    src = open(_CONSOLE).read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "console_diagnostics")
    # The final return is a dict literal; assert it carries a "debug" key.
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    keys = set()
    for r in returns:
        if isinstance(r.value, ast.Dict):
            keys |= {k.value for k in r.value.keys if isinstance(k, ast.Constant)}
    assert "debug" in keys
    # And the git-head helper the debug block awaits must exist.
    names = {n.name for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "_console_hub_git_head" in names
