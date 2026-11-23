"""The fleet model policy (.github/model-policy.json) and the agents that pin it.

The coding ladder's agent files must pin the same model the policy names, and the
model ledger must read the repo's agent files when no personal copy exists.
"""
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

GITHUB_DIR = pathlib.Path(__file__).resolve().parent.parent
LOCALSTAT = GITHUB_DIR.parent / ".claude" / "skills" / "model-ledger" / "localstat.py"


def load_policy():
    """Return the parsed model-policy.json."""
    return json.loads((GITHUB_DIR / "model-policy.json").read_text())


def ladder_rungs():
    """Return the coding ladder rungs that name an agent."""
    return [r for r in load_policy()["coding"]["ladder"] if r.get("agent")]


class ModelPolicyTests(unittest.TestCase):
    """Checks that the policy, the agent files and the model ledger agree."""

    def test_ladder_agents_pin_the_policy_model(self):
        """Each ladder agent file pins the model the policy gives its rung."""
        for rung in ladder_rungs():
            with self.subTest(agent=rung["agent"]):
                path = GITHUB_DIR / "agents" / (rung["agent"] + ".agent.md")
                self.assertTrue(path.is_file(), path)
                m = re.search(r"(?m)^model:\s*(\S+)", path.read_text())
                self.assertIsNotNone(m, "no model: line in " + str(path))
                self.assertEqual(m.group(1), rung["model"])

    def test_ledger_reads_the_repo_agent(self):
        """The ledger finds a repo agent's pinned model with no personal copies."""
        with tempfile.TemporaryDirectory() as home, \
                mock.patch.dict(os.environ, {"COPILOT_HOME": home}), \
                mock.patch.object(sys, "dont_write_bytecode", True):
            spec = importlib.util.spec_from_file_location("localstat", LOCALSTAT)
            localstat = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(localstat)
            expected = next(r["model"] for r in ladder_rungs() if r["agent"] == "cloud-coder")
            self.assertEqual(localstat.agent_model("cloud-coder"), expected)
            self.assertEqual(localstat.agent_model("no-such-agent"), "")

    def test_ledger_writes_to_a_missing_stats_folder(self):
        """outcome and import-bench create the ledger folder on a clean setup."""
        with tempfile.TemporaryDirectory() as tmp:
            stats = os.path.join(tmp, "no", "stats")
            bench = os.path.join(tmp, "cloudbench.jsonl")
            with open(bench, "w") as f:
                f.write(json.dumps({"stage": "fix", "ok": True, "model": "m", "task": "t"}) + "\n")
            env = dict(os.environ, LOCAL_STATS_DIR=stats, COPILOT_HOME=tmp)
            subprocess.run([sys.executable, str(LOCALSTAT), "import-bench", bench],
                           env=env, check=True, capture_output=True)
            shutil.rmtree(stats)
            subprocess.run([sys.executable, str(LOCALSTAT), "outcome", "--agent", "x", "--model", "m",
                            "--task", "edit", "--result", "pass", "--usd", "0"],
                           env=env, check=True, capture_output=True)
            self.assertTrue(os.path.isfile(os.path.join(stats, "outcomes.jsonl")))


if __name__ == "__main__":
    unittest.main()
