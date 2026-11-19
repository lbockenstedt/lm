"""The promotion PR body quotes every carried unit's own intent.

promote.sh can extend the oldest unit of work over later units that change
the same files, so one promotion PR may carry several. The body used to quote
only one PR's intent, and AB's review panel denied ab#586 because the other
units had no stated intent to be judged by. These tests run the workflow
step's real shell against a scratch repository, with a fake `gh` that serves
PR bodies (and the commit each PR was merged as) and keeps the body of the PR
it is asked to open.
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

GITHUB_DIR = pathlib.Path(__file__).resolve().parent.parent
PROMOTE_YML = GITHUB_DIR / "workflows" / "promote-reusable.yml"
STEP_NAME = "- name: Open or update the promotion PR"

FAKE_GH = """#!/bin/sh
# Serves `gh pr view N --json body,mergeCommit -q '.mergeCommit.oid // "", .body'`
# from $FAKE_GH_DIR: line 1 is pr-<n>.oid (blank when absent, as for a PR
# never merged), then pr-<n>.body. pr-<n>.fail makes the call fail as an outage
# does; a PR with neither file gets GitHub's real "no such PR" answer. Logs
# each PR viewed; keeps the created body.
case "$1 $2" in
  "pr view")
    echo "$3" >> "$FAKE_GH_DIR/viewed"
    if [ -f "$FAKE_GH_DIR/pr-$3.fail" ]; then
      echo "HTTP 502: Bad Gateway (https://api.github.com/graphql)" >&2
      exit 1
    fi
    if [ -f "$FAKE_GH_DIR/pr-$3.body" ]; then
      if [ -f "$FAKE_GH_DIR/pr-$3.oid" ]; then cat "$FAKE_GH_DIR/pr-$3.oid"; else echo; fi
      cat "$FAKE_GH_DIR/pr-$3.body"
      exit 0
    fi
    echo "GraphQL: Could not resolve to a PullRequest with the number of $3. (repository.pullRequest)" >&2
    exit 1 ;;
  "pr list") exit 0 ;;
  "pr create")
    while [ $# -gt 0 ]; do
      if [ "$1" = "--body-file" ]; then cp "$2" "$FAKE_GH_DIR/created.md"; fi
      shift
    done
    exit 0 ;;
esac
echo "fake gh: unexpected call: $*" >&2
exit 1
"""


def step_script():
    """Return the PR step's `run: |` block, dedented.

    Read as text so the test needs no YAML library: the block is every line
    after `run: |` that is blank or indented deeper than the `run:` key.
    """
    lines = PROMOTE_YML.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == STEP_NAME)
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip())
    block = []
    for line in lines[run + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        block.append(line)
    return textwrap.dedent("\n".join(block)) + "\n"


def intent_section(body):
    """Return the Intent section the way AB reads it.

    AB's extractor ends the section at the first line that starts with `#`,
    so a quoted line that escaped its `> ` prefix would cut it short here.
    """
    match = re.search(r"^## Intent & Problem Statement\n(.*?)(?=^#)", body, re.S | re.M)
    if match is None:
        raise AssertionError("no Intent section in:\n" + body)
    return match.group(1)


class PromotionBodyQuotesEveryUnit(unittest.TestCase):
    """Runs the PR step on a qa <- dev promotion that carries four units."""

    def setUp(self):
        """Build qa and dev in a scratch origin, plus a fake gh and sleep."""
        # Step 1: an isolated git identity, so no user config (signing, hooks)
        # can change what the commits look like.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        (self.root / "gitconfig").write_text("")
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=str(self.root / "gitconfig"),
                        GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
        self.work = self.root / "work"
        self.git(self.root, "init", "-q", "--bare", "origin.git")
        self.git(self.root, "init", "-q", "work")
        self.git(self.work, "remote", "add", "origin", str(self.root / "origin.git"))

        # Step 2: qa, then the four dev units, oldest first.
        self.git(self.work, "checkout", "-q", "-b", "qa")
        self.write("VERSION", "1.00\n")
        self.write("a.txt", "a\n")
        self.commit("init")
        self.git(self.work, "checkout", "-q", "-b", "dev")
        self.git(self.work, "checkout", "-q", "-b", "feat")
        self.write("a.txt", "a2\n")
        self.commit("feat a")
        self.git(self.work, "checkout", "-q", "dev")
        self.git(self.work, "merge", "-q", "--no-ff", "--no-commit", "feat")
        self.commit("Merge pull request #11 from x/feat", "Add feature A")
        sha11 = self.head()
        self.write("b.txt", "b\n")
        self.commit("Tune the widget",
                    "#123 is the issue this fixes.\n"
                    "## Not a heading here\n"
                    "<!-- an unclosed comment\n"
                    "\n"
                    "The old path keeps working.\n"
                    "\n"
                    "Co-authored-by: Someone <s@example.com>")
        self.write("VERSION", "2.00\n")
        self.commit("chore: bump VERSION")
        self.write("c.txt", "c\n")
        self.commit("fix: thing (#12)",
                    "Squash of the thing fix.\n\nCo-authored-by: Someone <s@example.com>")
        self.sha12 = self.head()
        self.promote()

        # Step 3: the fake gh serves #11 with an Intent section and #12
        # without one, each recorded as merged as its own unit; sleep is
        # instant so gh_retry's backoff costs nothing.
        self.ghdir = self.root / "gh"
        self.ghdir.mkdir()
        fakebin = self.root / "bin"
        fakebin.mkdir()
        self.install(fakebin / "gh", FAKE_GH)
        self.install(fakebin / "sleep", "#!/bin/sh\nexit 0\n")
        self.env["PATH"] = str(fakebin) + os.pathsep + os.environ["PATH"]
        self.pr_body(11, "## Intent & Problem Statement\n\n"
                         "Feature A lets the widget\nreport its state.\n\n"
                         "<!-- template\nplaceholder -->\n"
                         "## Proposed Solution & Changes\n\nNot part of the intent.\n",
                     oid=sha11)
        self.pr_body(12, "Fixes the thing.\n", oid=self.sha12)

    def git(self, cwd, *args):
        """Run git in cwd and return its stdout."""
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout

    def head(self):
        """Return the full sha of the work tree's HEAD."""
        return self.git(self.work, "rev-parse", "HEAD").strip()

    def write(self, name, text):
        """Write a file in the work tree and stage it."""
        (self.work / name).write_text(text)
        self.git(self.work, "add", name)

    def commit(self, subject, body=""):
        """Commit with the message kept verbatim (lines starting `#` stay)."""
        msg = self.root / "msg"
        msg.write_text(subject + ("\n\n" + body if body else "") + "\n")
        self.git(self.work, "commit", "-q", "--allow-empty", "--cleanup=verbatim", "-F", str(msg))

    def promote(self):
        """Push qa and dev, then build the promotion branch from them."""
        self.git(self.work, "push", "-q", "-f", "origin", "qa", "dev")
        self.git(self.work, "fetch", "-q", "origin")
        self.dev_tip = self.git(self.work, "rev-parse", "origin/dev").strip()
        self.git(self.work, "checkout", "-q", "-B", "promote/dev-to-qa", "origin/qa")
        self.git(self.work, "merge", "-q", "--no-ff", "--no-edit", "origin/dev")

    def install(self, path, text):
        """Write an executable script."""
        path.write_text(text)
        path.chmod(0o755)

    def pr_body(self, number, text, oid=None):
        """Make the fake gh serve this body for PR `number`, and the commit
        GitHub records it as merged as, when `oid` is given."""
        (self.ghdir / ("pr-%d.body" % number)).write_text(text)
        if oid is not None:
            (self.ghdir / ("pr-%d.oid" % number)).write_text(oid + "\n")

    def viewed(self):
        """Return the PR numbers the fake gh was asked to view."""
        log = self.ghdir / "viewed"
        return log.read_text().split() if log.exists() else []

    def run_step(self, **overrides):
        """Run the step under `bash -e -o pipefail`; return (process, created body)."""
        runner = self.root / "runner"
        runner.mkdir(exist_ok=True)
        env = dict(self.env, SRC="dev", TGT="qa", BR="promote/dev-to-qa",
                   UNIT_SHA=self.dev_tip, UNIT_PR="11", UNIT_SUBJECT="Add feature A (+3 more)",
                   REMAINING="0", RUNNER_TEMP=str(runner), GH_TOKEN="x",
                   FAKE_GH_DIR=str(self.ghdir))
        env.update(overrides)
        script = self.root / "step.sh"
        script.write_text(step_script())
        proc = subprocess.run(["bash", "-e", "-o", "pipefail", str(script)], cwd=self.work,
                              env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc, (self.ghdir / "created.md").read_text()

    def test_every_unit_is_quoted_with_its_own_intent(self):
        """Each unit gets a header and its own intent, in order."""
        proc, body = self.run_step()
        intent = intent_section(body)
        self.assertIn("Opened by `promote.yml`", intent)
        self.assertIn("(fleet\nrule 2.1)", intent)
        self.assertIn("**4 unit(s) of work**", intent)
        heads = re.findall(r"^\*\*Unit (\d) of 4: (.*?)\*\*", intent, re.M)
        self.assertEqual(heads, [("1", "#11 Add feature A"), ("2", "Tune the widget"),
                                 ("3", "chore: bump VERSION"), ("4", "#12 fix: thing (#12)")])
        # A merged PR: its Intent section only, template comment stripped.
        self.assertIn("> Feature A lets the widget\n> report its state.\n\n**Unit 2", intent)
        self.assertNotIn("Not part of the intent", body)
        self.assertNotIn("placeholder", body)
        # A direct push: its message quoted, trailer dropped, the unclosed
        # comment escaped, the paragraph break kept inside the quote.
        self.assertIn("direct push)", intent)
        self.assertIn("> #123 is the issue this fixes.\n> ## Not a heading here\n"
                      "> &lt;!-- an unclosed comment\n>\n> The old path keeps working.\n", intent)
        self.assertNotIn("Co-authored-by", body)
        self.assertNotIn("<!--", body)
        self.assertIn("_Changes only `VERSION` files, which promotion pins to `qa`", intent)
        # A PR written without the template: its description is quoted, not
        # the squash commit's message.
        self.assertIn("_#12 has no Intent & Problem Statement section, so its description\n"
                      "is quoted instead._\n\n> Fixes the thing.\n", intent)
        self.assertNotIn("Squash of the thing fix.", body)
        self.assertNotIn("adds nothing", body)
        self.assertNotIn("::warning::", proc.stdout)
        # The sections after the intent are still there.
        self.assertIn("\n## Proposed Solution & Changes\n", body)
        self.assertIn("\n## Guardrails & Side-Effect Assessment\n", body)

    def test_a_failed_fetch_is_unknown_not_absent(self):
        """A PR that cannot be read is not reported as stating no intent, nor
        named as the unit's PR; the commit's own message is the context."""
        (self.ghdir / "pr-12.fail").write_text("")
        proc, body = self.run_step()
        intent = intent_section(body)
        self.assertIn("**Unit 4 of 4: fix: thing (#12)** (`", intent)
        self.assertNotIn("**Unit 4 of 4: #12", intent)
        self.assertIn("_Could not read #12 (the GitHub fetch failed), so its intent is\n"
                      "UNKNOWN -- not absent, and so is whether this commit is that PR's merge._\n"
                      "\n_Its own commit message reads:_\n\n> Squash of the thing fix.\n", intent)
        self.assertNotIn("#12 has no Intent", intent)
        self.assertNotIn("Co-authored-by", body)
        self.assertIn("::warning::Could not read #12", proc.stdout)
        self.assertEqual(self.viewed().count("12"), 5)

    def test_a_number_that_is_no_pr_is_a_direct_push(self):
        """A subject's "(#N)" that GitHub says is no PR (an issue, or a number
        from before the repo moved) is a direct push, asked about once."""
        (self.ghdir / "pr-12.body").unlink()
        proc, body = self.run_step()
        intent = intent_section(body)
        self.assertRegex(intent, r"\*\*Unit 4 of 4: fix: thing \(#12\)\*\* \(`[0-9a-f]+`, direct push\)"
                                 r"\n\n> Squash of the thing fix.\n")
        self.assertNotIn("UNKNOWN", intent)
        self.assertNotIn("::warning::", proc.stdout)
        self.assertEqual(self.viewed().count("12"), 1)

    def test_a_pr_not_merged_as_this_commit_is_not_its_intent(self):
        """A subject ending "(#N)" names a PR GitHub merged as another commit:
        the unit is a direct push judged by its own message."""
        self.pr_body(12, "Fixes the thing.\n", oid="0" * 40)
        _, body = self.run_step()
        intent = intent_section(body)
        self.assertRegex(intent, r"\*\*Unit 4 of 4: fix: thing \(#12\)\*\* \(`[0-9a-f]+`, direct push\)"
                                 r"\n\n> Squash of the thing fix.\n")
        self.assertNotIn("Fixes the thing.", body)

    def test_a_pr_with_no_description(self):
        """A PR whose description is only a template comment has no intent."""
        self.pr_body(12, "<!-- only template -->\n")
        _, body = self.run_step()
        intent = intent_section(body)
        self.assertIn("_#12 has no description, so there is no stated intent to carry;\n"
                      "judge it by its changes, enumerated below._", intent)
        self.assertNotIn("only template", body)

    def test_a_unit_already_in_the_target_adds_nothing(self):
        """A back-merge whose files already match the target is labelled as
        adding nothing and is not fetched, while a unit with a file of the
        same awkward name that the target lacks is still quoted."""
        self.git(self.work, "checkout", "-q", "qa")
        self.write('hot "fix" 1.txt', "hot\n")
        self.commit("hotfix on qa")
        self.git(self.work, "checkout", "-q", "dev")
        self.git(self.work, "merge", "-q", "--no-ff", "--no-commit", "qa")
        self.commit("Merge pull request #13 from x/backmerge/qa-to-dev", "backmerge: qa -> dev")
        self.write('hot "fix" 2.txt', "new\n")
        self.commit("Add the second fix", "The target has no such file yet.")
        self.promote()
        proc, body = self.run_step()
        intent = intent_section(body)
        self.assertIn("**6 unit(s) of work**", intent)
        self.assertIn("**Unit 5 of 6: Merge pull request #13 from x/backmerge/qa-to-dev** (`", intent)
        self.assertIn("_Every file it changes, `VERSION` aside, already matches `qa`, so it\n"
                      "adds nothing to this diff and no intent is quoted for it._", intent)
        self.assertNotIn("13", self.viewed())
        self.assertRegex(intent, r"\*\*Unit 6 of 6: Add the second fix\*\* \(`[0-9a-f]+`, direct push\)"
                                 r"\n\n> The target has no such file yet.\n")
        self.assertEqual(intent.count("adds nothing"), 1)
        self.assertNotIn("hotfix on qa", intent)
        self.assertNotIn("::warning::", proc.stdout)

    def test_an_unreadable_commit_is_unknown(self):
        """A commit git cannot read is UNKNOWN, and the other units render."""
        tune = self.git(self.work, "rev-parse", "origin/dev~2").strip()
        gitbin = self.root / "gitbin"
        gitbin.mkdir()
        real_git = shutil.which("git", path=self.env["PATH"])
        self.install(gitbin / "git",
                     '#!/bin/sh\n'
                     'if [ "$1" = log ]; then\n'
                     '  for a in "$@"; do [ "$a" = "$FAIL_LOG_SHA" ] && exit 128; done\n'
                     'fi\n'
                     'exec "%s" "$@"\n' % real_git)
        _, body = self.run_step(PATH=str(gitbin) + os.pathsep + self.env["PATH"],
                                FAIL_LOG_SHA=tune)
        intent = intent_section(body)
        self.assertIn("**Unit 2 of 4: (could not be read)** (`%s`)\n\n"
                      "_Could not read this commit (`git log` failed), so its intent is\n"
                      "UNKNOWN -- not absent, and so is whether it came from a PR._" % tune[:7], intent)
        self.assertNotIn("The old path keeps working", body)
        self.assertIn("**Unit 1 of 4: #11 Add feature A**", intent)
        self.assertIn("**Unit 4 of 4: #12 fix: thing (#12)**", intent)

    def test_units_that_cannot_be_listed_are_unknown(self):
        """An empty or unknown unit_sha says UNKNOWN and warns."""
        for sha in ("", "0" * 40):
            with self.subTest(unit_sha=sha):
                proc, body = self.run_step(UNIT_SHA=sha)
                intent = intent_section(body)
                self.assertIn("could not be listed", intent)
                self.assertIn("UNKNOWN --\nnot absent", intent)
                self.assertNotIn("**Unit", intent)
                self.assertIn("::warning::Could not list the units", proc.stdout)

    def test_long_intents_share_the_budget(self):
        """Two long intents are cut to equal shares, each with a note."""
        long_text = "\n".join("Line %03d of a long statement of intent." % i for i in range(600))
        self.pr_body(11, "## Intent & Problem Statement\n\n" + long_text + "\n")
        self.pr_body(12, "## Intent & Problem Statement\n\n" + long_text + "\n")
        _, body = self.run_step()
        intent = intent_section(body)
        cuts = re.findall(r"Cut to its share of the review budget \((\d+) of (\d+) characters\);"
                          r" the full text is in (#\d+)", intent)
        self.assertEqual([cut[2] for cut in cuts], ["#11", "#12"])
        self.assertLessEqual(abs(int(cuts[0][0]) - int(cuts[1][0])), 1)
        self.assertIn("**Unit 4 of 4", intent)
        # Uncut, the two quotes alone would be about 50,000 characters.
        self.assertLess(len(intent), 19000)

    def test_at_most_forty_units_are_quoted(self):
        """A batched queue quotes the oldest 40 units and says the rest exist."""
        self.git(self.work, "checkout", "-q", "dev")
        for i in range(42):
            self.commit("unit %d" % i)
        self.promote()
        _, body = self.run_step()
        intent = intent_section(body)
        self.assertIn("**46 unit(s) of work**", intent)
        self.assertIn("**Unit 40 of 46: unit 35**", intent)
        self.assertNotIn("**Unit 41 of 46", intent)
        self.assertIn("_Units 41 to 46 are not quoted", intent)


if __name__ == "__main__":
    unittest.main()
