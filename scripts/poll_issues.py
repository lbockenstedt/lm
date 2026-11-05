"""List open GitHub issues labelled "automated-fix" across every repo under the current dir.

Walks the working directory looking for git checkouts, works out each checkout's
GitHub "owner/name" from its origin remote, and asks the `gh` CLI for issues that
carry the automated-fix label. Output is either a human summary or raw JSON
(--json) so other automation can consume it.
"""
# Walk the directory tree to find git checkouts.
import os
# Run the `git` and `gh` command-line tools.
import subprocess
# Parse the JSON that `gh` prints and emit JSON with --json.
import json
# Parse command-line flags (--json).
import argparse
# Type hint for "may return None".
from typing import Optional

def get_repo_name(path: str) -> Optional[str]:
    """Return "owner/name" for the GitHub origin remote of the repo at path, or None."""
    # Any failure (not a repo, no origin remote, git missing) just means "no repo name".
    try:
        # Ask git for the URL of the "origin" remote; check=True raises if git fails.
        result = subprocess.run(["git", "-C", path, "remote", "get-url", "origin"], capture_output=True, text=True, check=True)
        url = result.stdout.strip()
        # Only GitHub remotes can be queried with `gh`; other hosts fall through to None.
        if "github.com" in url:
            # Strip everything up to "github.com/" and any ".git" suffix, leaving owner/name parts.
            # This expects the https form (https://github.com/owner/repo.git); SSH-style
            # "git@github.com:owner/repo" URLs have no "github.com/" and will not parse.
            parts = url.split("github.com/")[-1].split(".git")[0].split("/")
            # Need at least owner and repo name to build the "owner/name" identifier.
            if len(parts) >= 2: return f"{parts[0]}/{parts[1]}"
    # Swallow errors on purpose: a broken repo should not stop the scan of the others.
    except Exception: pass
    # Not a GitHub repo, or we could not tell.
    return None

def get_pending_ai_issues():
    """Return every open "automated-fix" issue from all GitHub repos found below ".".

    Each issue dict gets an extra "repo" key so callers know where it came from.
    """
    # Accumulates issues from all repos found during the walk.
    all_issues = []
    # Walk every directory below the current one; `dirs` can be edited to prune the walk.
    for root, dirs, files in os.walk("."):
        # A directory containing ".git" is the root of a git checkout.
        if ".git" in dirs:
            # Work out which GitHub repo this checkout points at.
            repo_name = get_repo_name(root)
            # Skip checkouts that are not hosted on GitHub.
            if repo_name:
                # gh command: list issues in that repo with the automated-fix label, as JSON fields.
                cmd = ["gh", "issue", "list", "-R", repo_name, "--label", "automated-fix", "--json", "number,title,body,url"]
                # Run gh without check=True so a failure for one repo does not abort the scan.
                result = subprocess.run(cmd, capture_output=True, text=True)
                # Only parse output when gh succeeded.
                if result.returncode == 0:
                    # gh output should be JSON, but guard against malformed output.
                    try:
                        # Turn the JSON text into a list of issue dicts.
                        issues = json.loads(result.stdout)
                        # Tag each issue with its repo so the caller can tell repos apart.
                        for i in issues: i["repo"] = repo_name
                        # Add this repo's issues to the overall list.
                        all_issues.extend(issues)
                    # Unparseable output is ignored; the repo simply contributes no issues.
                    except json.JSONDecodeError: pass
            # Do not descend into the .git folder itself; it holds no nested checkouts.
            dirs.remove(".git")
    # All issues found across every repo.
    return all_issues

def main():
    """Parse flags, collect pending issues, and print them as JSON or a readable list."""
    # Build the command-line parser; --json switches to machine-readable output.
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    # Scan all repos below the current directory for automated-fix issues.
    issues = get_pending_ai_issues()
    # JSON mode: print the whole list as one JSON document for other scripts.
    if args.json:
        print(json.dumps(issues))
    # Human mode: print a count header, then one line per issue.
    else:
        print(f"🔍 Found {len(issues)} pending AI issues.")
        for i in issues: print(f"[{i['repo']}] #{i['number']} - {i['title']}")

# Only run main() when executed as a script, not when imported.
if __name__ == "__main__":
    main()
