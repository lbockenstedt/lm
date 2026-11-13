"""smoke.sh must know which repo it is in from the origin remote.

AppBuilder clones every repo into `<tmp>/repo`, and developers use worktrees
named after the feature. smoke.sh used the directory name, so in both places
lm was not recognised as lm: it ran the generic branch with ci.yml's literal
`"$c/tests"` path, pytest found no such directory, and every AppBuilder fix to
lm failed its smoke test with `file or directory not found: "$c/tests"`.
"""
import pathlib
import subprocess
import tempfile
import unittest

SMOKE_SH = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "smoke.sh"


def _smoke_in(dirname, origin):
    """Run smoke.sh in an empty git repo called `dirname` and return its output.

    The helpers directory is empty, so the script stops at its first check,
    which names the repo: "missing ... (clone ab and lm next to <name>)"."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = pathlib.Path(tmp) / dirname
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        if origin:
            subprocess.run(["git", "remote", "add", "origin", origin], cwd=repo, check=True)
        result = subprocess.run(
            ["bash", str(SMOKE_SH), "--no-fleet-rules", "--no-fetch"],
            cwd=repo, capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                 "SMOKE_HELPERS": tmp + "/no-helpers"})
        return result.stdout + result.stderr


class SmokeRepoName(unittest.TestCase):
    def test_appbuilder_clone_named_repo_is_lm(self):
        out = _smoke_in("repo", "https://github.com/lbockenstedt/lm.git")
        self.assertIn("next to lm)", out)

    def test_origin_without_dot_git(self):
        out = _smoke_in("wt-feature", "git@github.com:lbockenstedt/lm")
        self.assertIn("next to lm)", out)

    def test_no_origin_falls_back_to_directory_name(self):
        out = _smoke_in("netbox", None)
        self.assertIn("next to netbox)", out)


if __name__ == "__main__":
    unittest.main()
