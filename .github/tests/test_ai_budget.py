"""The daily AI spend gate (.github/hooks/ai_budget.py, fleet rule 1.10).

Copilot runs the script as a preToolUse hook. These tests run it the same
way, as a subprocess fed the hook's JSON on stdin, against a scratch
COPILOT_HOME whose usage log holds a chosen amount of spend.
"""
import datetime
import importlib.util
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

GITHUB_DIR = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = GITHUB_DIR / "hooks" / "ai_budget.py"
POLICY = json.loads((GITHUB_DIR / "ai-budget.json").read_text())
GATE = POLICY["gate_usd"]

_spec = importlib.util.spec_from_file_location("ai_budget", SCRIPT)
ai_budget = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai_budget)


class GateTest(unittest.TestCase):
    """Each test gets its own COPILOT_HOME and usage log."""

    def setUp(self):
        """Create an empty usage log in a scratch COPILOT_HOME."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = pathlib.Path(tmp.name)
        self.db = self.home / "session-store.db"
        with sqlite3.connect(self.db) as con:
            con.execute("CREATE TABLE assistant_usage_events (session_id TEXT, created_at TEXT, total_nano_aiu INTEGER)")

    def spend(self, usd, days_ago=0, session="cloud"):
        """Log one model call costing ``usd`` (None: a free local model), ``days_ago`` days back."""
        when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
        with sqlite3.connect(self.db) as con:
            con.execute("INSERT INTO assistant_usage_events VALUES (?, ?, ?)",
                        (session, when.strftime("%Y-%m-%dT%H:%M:%S.000Z"), None if usd is None else int(usd * 1e11)))

    def run_script(self, *args, stdin="", session_env=None):
        """Run the script as Copilot does; return (exit code, stdout)."""
        env = dict(os.environ, COPILOT_HOME=str(self.home))
        env.pop("COPILOT_AGENT_SESSION_ID", None)
        if session_env:
            env["COPILOT_AGENT_SESSION_ID"] = session_env
        p = subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, env=env,
                           capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout

    def check(self, tool, args, session=None):
        """The preToolUse answer for one call: the deny reason, or None when allowed."""
        payload = {"toolName": tool, "toolArgs": args}
        if session:
            payload["sessionId"] = session
        code, out = self.run_script("check", stdin=json.dumps(payload))
        self.assertEqual(code, 0)
        return json.loads(out)["permissionDecisionReason"] if out.strip() else None

    def test_closed_gate_refuses_work_but_lets_the_agent_stop(self):
        """Past the gate every call is refused, except stopping and checking status."""
        self.spend(GATE * 1.5)
        reason = self.check("bash", {"command": "ls"})
        self.assertIn("gate closed", reason)
        self.assertIn("continue", reason)
        self.assertIsNotNone(self.check("view", {"path": "/tmp/x"}))
        self.assertIsNone(self.check("task_complete", {"summary": "stopped"}))
        self.assertIsNone(self.check("bash", {"command": "python3 %s status" % SCRIPT}))
        self.assertIsNotNone(self.check("bash", {"command": "python3 %s status; ls" % SCRIPT}))
        _, out = self.run_script("context", stdin="{}")
        self.assertIn("CLOSED", json.loads(out)["additionalContext"])

    def test_local_session_keeps_working_past_the_gate(self):
        """Past the gate a session whose calls today were all free keeps working,
        without cloud sub-agents. A session with cloud spend today (its own or a
        sub-agent's), no calls today yet or no session id is still refused."""
        self.spend(GATE * 1.5)
        self.spend(None, session="local")
        self.spend(None, session="mixed")
        self.spend(0.5, session="mixed")
        self.spend(None, days_ago=2, session="yesterday")
        cases = {"local": True, "cloud": False, "mixed": False, "yesterday": False, "unknown": False, None: False}
        for session, allowed in cases.items():
            self.assertEqual(self.check("bash", {"command": "ls"}, session) is None, allowed, session)
        self.assertIsNone(self.check("task", {"agent_type": "local-coder"}, "local"))
        self.assertIsNone(self.check("task", {"agent_type": "explore", "model": "llamacpp/dsv4"}, "local"))
        self.assertIn("no new cloud sub-agents", self.check("task", {"agent_type": "explore"}, "local"))
        self.assertIn("Only a person", self.check("bash", {"command": "python3 ai_budget.py continue"}, "local"))
        # Without sessionId in the payload, the id comes from the hook's environment.
        stdin = json.dumps({"toolName": "bash", "toolArgs": {"command": "ls"}})
        self.assertEqual(self.run_script("check", stdin=stdin, session_env="local"), (0, ""))
        self.assertIn("deny", self.run_script("check", stdin=stdin, session_env="cloud")[1])

    def test_local_session_waits_for_its_first_call_to_be_logged(self):
        """A session's first model call may be logged just after its first tool
        call is checked, so a session with no calls yet is re-read for a moment."""
        since = ai_budget.day_start()[1]
        timer = threading.Timer(0.5, self.spend, (None,), {"session": "new"})
        self.addCleanup(timer.cancel)
        with mock.patch.dict(os.environ, {"COPILOT_HOME": str(self.home)}):
            timer.start()
            self.assertTrue(ai_budget.local_session("new", since))
            self.assertFalse(ai_budget.local_session("never", since, wait_s=0.2))

    def test_spend_before_today_does_not_count(self):
        """Only today's spend counts towards the gate."""
        self.spend(GATE * 5, days_ago=2)
        self.spend(10)
        self.assertIsNone(self.check("bash", {"command": "ls"}))
        _, out = self.run_script("context", stdin="{}")
        self.assertIn("$10 of the $%.0f" % GATE, json.loads(out)["additionalContext"])

    def test_continue_reopens_the_gate_for_today_only(self):
        """A person's continue lifts today's gate; a reopened gate from another day is ignored."""
        self.spend(GATE * 1.5)
        self.assertEqual(self.run_script("continue", "50")[0], 0)
        state = json.loads((self.home / "ai-budget-state.json").read_text())
        self.assertEqual(state["gate_usd"], GATE * 1.5 + 50)
        self.assertIsNone(self.check("bash", {"command": "ls"}))
        state["day"] = "2000-01-01"
        (self.home / "ai-budget-state.json").write_text(json.dumps(state))
        self.assertIsNotNone(self.check("bash", {"command": "ls"}))

    def test_agent_cannot_reopen_the_gate(self):
        """Running continue or changing the state file is refused even while the gate is open."""
        self.spend(1)
        for cmd in ("python3 .github/hooks/ai_budget.py continue",
                    'python3 "%s" continue 500' % SCRIPT,
                    "echo '{}' > ~/.copilot/ai-budget-state.json"):
            self.assertIn("Only a person", self.check("bash", {"command": cmd}), cmd)
        self.assertIsNotNone(self.check("edit", {"path": str(self.home / "ai-budget-state.json")}))
        self.assertIsNone(self.check("view", {"path": str(self.home / "ai-budget-state.json")}))
        self.assertIsNone(self.check("edit", {"path": str(SCRIPT)}))

    def test_reserve_refuses_new_cloud_subagents_only(self):
        """Near the gate a cloud sub-agent is refused; local agents and other tools still run."""
        decide = ai_budget.decide
        near, far = GATE - 5, 0
        self.assertIsNotNone(decide("task", {"agent_type": "explore"}, near, GATE, 25))
        self.assertIsNotNone(decide("task", {"agent_type": "local-coder", "model": "claude-opus-5.5"}, near, GATE, 25))
        self.assertIsNotNone(decide("run_dynamic_workflow", {"name": "x"}, near, GATE, 25))
        self.assertIsNone(decide("task", {"agent_type": "local-coder"}, near, GATE, 25))
        self.assertIsNone(decide("task", {"agent_type": "explore", "model": "ollama/qwen"}, near, GATE, 25))
        self.assertIsNone(decide("task", {"agent_type": "explore", "model": "llamacpp/dsv4"}, near, GATE, 25))
        self.assertIsNone(decide("bash", {"command": "ls"}, near, GATE, 25))
        self.assertIsNone(decide("task", {"agent_type": "explore"}, far, GATE, 25))

    def test_fails_open(self):
        """No usage log, an unreadable one or bad input lets the call run, never an error exit."""
        self.db.write_bytes(b"not a database")
        self.assertIsNone(self.check("bash", {"command": "ls"}))
        self.db.unlink()
        self.assertIsNone(self.check("bash", {"command": "ls"}))
        self.assertEqual(self.run_script("check", stdin="not json"), (0, ""))

    def test_hook_commands_fail_open(self):
        """Copilot refuses a tool call when a preToolUse command fails, so every
        command must exit 0 even when Python itself is missing."""
        hooks = json.loads((GITHUB_DIR / "hooks" / "fleet-hooks.json").read_text())["hooks"]
        for event, entries in hooks.items():
            for entry in entries:
                self.assertTrue(entry["bash"].endswith("|| true"), event)
                self.assertTrue(entry["powershell"].endswith("exit 0"), event)


if __name__ == "__main__":
    unittest.main()
