import os
import subprocess
import json
import argparse
from typing import List, Dict, Optional

def get_repo_name(path: str) -> Optional[str]:
    try:
        result = subprocess.run(["git", "-C", path, "remote", "get-url", "origin"], capture_output=True, text=True, check=True)
        url = result.stdout.strip()
        if "github.com" in url:
            parts = url.split("github.com/")[-1].split(".git")[0].split("/")
            if len(parts) >= 2: return f"{parts[0]}/{parts[1]}"
    except Exception: pass
    return None

def get_pending_ai_issues():
    all_issues = []
    for root, dirs, files in os.walk("."):
        if ".git" in dirs:
            repo_name = get_repo_name(root)
            if repo_name:
                cmd = ["gh", "issue", "list", "-R", repo_name, "--label", "automated-fix", "--json", "number,title,body,url"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    try:
                        issues = json.loads(result.stdout)
                        for i in issues: i["repo"] = repo_name
                        all_issues.extend(issues)
                    except json.JSONDecodeError: pass
            dirs.remove(".git")
    return all_issues

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    issues = get_pending_ai_issues()
    if args.json:
        print(json.dumps(issues))
    else:
        print(f"🔍 Found {len(issues)} pending AI issues.")
        for i in issues: print(f"[{i['repo']}] #{i['number']} - {i['title']}")

if __name__ == "__main__":
    main()
