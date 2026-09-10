"""Fresh-install startup: the standalone units must actually run.

REGRESSION (round 3, #1): the systemd units never passed ``--secret`` — and must
not, because argv is world-readable via ``ps`` — while argparse declared it
``required=True``. Every FRESH install therefore crash-looped under
``Restart=always`` before it ever reached the hub.

These tests execute the real ``ExecStart`` argv against the real entrypoint with
only the unit's ``EnvironmentFile`` in the environment, and assert argparse
accepts it. ``LM_CLUSTER_ENTRYPOINT_DRYRUN`` is not used: the modules are parsed
and their ``__main__`` argparse block is replayed, so no daemon is started.
"""

import ast
import os
import re
import shlex
import subprocess
import sys
import textwrap

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

UNITS = {
    "dns": (os.path.join(ROOT, "dns", "install_dns.sh"),
            os.path.join(ROOT, "dns", "src", "control_plane.py"),
            "Lab Manager DNS Spoke"),
    "dhcp": (os.path.join(ROOT, "dhcp", "install_dhcp.sh"),
             os.path.join(ROOT, "dhcp", "src", "control_plane.py"),
             "Lab Manager DHCP Spoke"),
}


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _spoke_execstart(installer_src, description):
    """The ExecStart line of the SPOKE unit (not the worker unit)."""
    block = installer_src[installer_src.index(description):]
    line = next(l for l in block.splitlines() if l.startswith("ExecStart="))
    return line[len("ExecStart="):]


def _argv_from_execstart(execstart, env):
    """Expand systemd's ``$VAR`` the way systemd does: unset/empty expands to
    NOTHING (the argument disappears entirely), which is exactly why passing a
    possibly-empty secret on the command line cannot work."""
    argv = []
    for token in shlex.split(execstart.replace("\\$", "$")):
        if token.startswith("$"):
            value = env.get(token[1:], "")
            if value:
                argv.append(value)
        else:
            argv.append(token)
    # Drop the interpreter + script tokens; what we replay is the ARGUMENTS.
    while argv and not argv[0].startswith("--"):
        argv.pop(0)
    return argv


def _main_block(entrypoint):
    """The module's ``if __name__ == '__main__':`` body, as source."""
    tree = ast.parse(_read(entrypoint))
    for node in tree.body:
        if (isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and getattr(node.test.left, "id", "") == "__name__"):
            return textwrap.dedent(
                "".join(ast.unparse(stmt) + "\n" for stmt in node.body))
    raise AssertionError(f"no __main__ block in {entrypoint}")


def _run_arg_parsing(entrypoint, argv, env):
    """Replay the entrypoint's argparse block in a subprocess.

    Only the parser is exercised (the control-plane construction and
    ``asyncio.run`` are stripped), so this asserts the FRESH-INSTALL command
    line parses without starting a daemon."""
    body = _main_block(entrypoint)
    body = re.sub(r"^\s*cp = .*$", "", body, flags=re.M)
    body = re.sub(r"^\s*asyncio\.run\(.*$", "", body, flags=re.M)
    script = (
        "import argparse, os, sys, json\n"
        + body
        + "\nprint(json.dumps({'id': args.id, 'secret': args.secret,"
          " 'hub': args.hub, 'hub_secret': args.hub_secret}))\n"
    )
    proc = subprocess.run([sys.executable, "-c", script, *argv],
                          capture_output=True, text=True,
                          env={**os.environ, **env})
    return proc


# ── The unit line itself ───────────────────────────────────────────────────

def test_the_unit_never_puts_the_secret_on_the_command_line():
    """argv is world-readable via `ps`; the secret must come from the env."""
    for module, (installer, _entry, description) in UNITS.items():
        execstart = _spoke_execstart(_read(installer), description)
        assert "--secret" not in execstart, module
        assert "SPOKE_SECRET" not in execstart, module


def test_the_unit_supplies_the_environment_file():
    for module, (installer, _entry, _d) in UNITS.items():
        src = _read(installer)
        assert "EnvironmentFile=$ENV_FILE" in src, module
        assert "SPOKE_SECRET=$SPOKE_SECRET" in src, module
        assert "SPOKE_ID=$SPOKE_ID" in src, module


# ── The command actually starts ────────────────────────────────────────────

def test_a_fresh_install_command_parses_with_a_zero_touch_env():
    """Fresh install, no pre-shared secret: SPOKE_SECRET is EMPTY in .env and
    the spoke must still start (it connects unauthenticated and waits for
    approval)."""
    for module, (installer, entry, description) in UNITS.items():
        env = {"SPOKE_ID": f"lm-{module}-node1", "SPOKE_SECRET": "",
               "HUB_URL": "wss://hub.example.com:443"}
        argv = _argv_from_execstart(
            _spoke_execstart(_read(installer), description), env)
        proc = _run_arg_parsing(entry, argv, env)
        assert proc.returncode == 0, f"{module}: {proc.stderr}"
        assert f'"id": "lm-{module}-node1"' in proc.stdout.replace("'", '"')
        assert '"secret": ""' in proc.stdout.replace("'", '"')


def test_a_fresh_install_command_picks_up_a_preseeded_secret():
    for module, (installer, entry, description) in UNITS.items():
        env = {"SPOKE_ID": f"lm-{module}-node1", "SPOKE_SECRET": "s3cr3t",
               "HUB_URL": "wss://hub.example.com:443"}
        argv = _argv_from_execstart(
            _spoke_execstart(_read(installer), description), env)
        proc = _run_arg_parsing(entry, argv, env)
        assert proc.returncode == 0, f"{module}: {proc.stderr}"
        assert "s3cr3t" in proc.stdout


def test_the_entrypoint_still_refuses_a_missing_id():
    for module, (_installer, entry, _d) in UNITS.items():
        proc = _run_arg_parsing(entry, [], {"SPOKE_ID": "", "SPOKE_SECRET": ""})
        assert proc.returncode != 0, module
        assert "--id is required" in proc.stderr, module


def test_the_worker_units_start_from_their_environment_file():
    for module, member_env in (("dns", "LM_DNS_MEMBER_ID"),
                               ("dhcp", "LM_DHCP_MEMBER_ID")):
        src = _read(os.path.join(ROOT, module, f"install_{module}.sh"))
        assert f"{member_env}=$MEMBER_ID" in src
        assert f"--id \\${member_env}" in src
        worker = os.path.join(ROOT, module, "src", f"{module}_worker.py")
        body = _read(worker)
        assert f'default=os.getenv("{member_env}", "")' in body
        # The secret and coordinator URL come from the EnvironmentFile too.
        assert 'os.getenv("LM_' in body
