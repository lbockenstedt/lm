#!/usr/bin/env python3
"""Local-model statistics: record task outcomes and report failure patterns.

Two JSON Lines logs live in this folder:
- calls-YYYY-MM.jsonl: written by ~/.copilot/ollama-proxy/proxy.py, one line per
  chat call to a local model (agent, prompt size, speed, tool calls, errors and
  corruption signals). Automatic.
- outcomes.jsonl: written by `localstat.py outcome` after the cloud agent has
  reviewed a local agent's result. Only the reviewer knows if the work was right.

Usage:
  localstat.py outcome --agent local-coder --task edit --result fail \
      --reason corrupt_code --note "odd indent in docstring" [--redo cloud]
  localstat.py report [--days 30]
Stdlib only.
"""
import argparse
import glob
import json
import os
import statistics
import time
from collections import Counter, defaultdict

DIR = os.path.expanduser(os.environ.get("LOCAL_STATS_DIR", "~/.copilot/local-stats"))
OUTCOMES = os.path.join(DIR, "outcomes.jsonl")
AGENTS = ["local-coder", "local-scout", "local-summarizer", "local-docs", "direct"]
TASKS = ["search", "trace", "explain", "edit", "test", "docs", "summarize", "commit_msg", "json", "other"]
RESULTS = ["pass", "partial", "fail"]
REASONS = ["corrupt_code", "wrong_answer", "incomplete", "off_spec", "bad_citation", "tool_misuse",
           "loop_or_stall", "timeout", "crash", "too_slow", "other"]
READY, WEAK, MIN_N = 0.90, 0.60, 5  # pass-rate bars for the offload advice, and samples needed


def read_jsonl(paths, since):
    """Yield records from JSON Lines files whose ts is on or after `since` (ISO string)."""
    for p in paths:
        with open(p) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("ts", "") >= since:
                    yield r


def cmd_outcome(a):
    """Append one reviewed outcome."""
    if a.result != "pass" and not a.reason:
        raise SystemExit("--reason is required unless --result pass")
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "agent": a.agent, "task": a.task,
           "result": a.result, "reasons": a.reason or [], "redo": a.redo, "minutes": a.minutes,
           "repo": a.repo, "note": a.note}
    os.makedirs(DIR, exist_ok=True)
    with open(OUTCOMES, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("recorded:", json.dumps(rec))


def pct(n, d):
    """Format n/d as a whole percentage, or '-' when d is 0."""
    return f"{100 * n / d:.0f}%" if d else "-"


def med(xs):
    """Median of the non-None values, or None."""
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 1) if xs else None


def table(title, header, rows):
    """Print a simple aligned table."""
    print(f"\n## {title}")
    if not rows:
        print("(no data)")
        return
    w = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    for r in [header] + rows:
        print("  ".join(str(x).ljust(n) for x, n in zip(r, w)))


def call_anomalies(c):
    """List the problems one proxy call shows (empty list means it looked healthy)."""
    out = []
    if c.get("error") or (c.get("status") or 200) >= 400:
        out.append("http_error")
    for k in ("empty", "think_leak", "truncated"):
        if c.get(k):
            out.append(k)
    if c.get("bad_tool_args"):
        out.append("bad_tool_args")
    if c.get("indent_drift"):
        out.append("indent_drift")
    if c.get("py_syntax_error"):
        out.append("py_syntax_error")
    if c.get("finish") == "length":
        out.append("hit_max_tokens")
    return out


def report_calls(calls):
    """Summarise proxy calls per agent/model, per prompt size, and per conversation."""
    # Step 1: per agent / model / host.
    groups = defaultdict(list)
    for c in calls:
        groups[(c.get("agent"), c.get("model"), c.get("host"))].append(c)
    rows = []
    for (agent, model, host), cs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        bad = sum(1 for c in cs if call_anomalies(c))
        rows.append([agent, model, host, len(cs), len({c.get("conv") for c in cs}), pct(bad, len(cs)),
                     sum(c.get("prev_tool_errors", 0) for c in cs), sum(1 for c in cs if c.get("fallback_from")),
                     med(c.get("ttft_s") for c in cs), med(c.get("duration_s") for c in cs)])
    table("Calls by agent / model / host",
          ["agent", "model", "host", "calls", "convs", "anomaly", "tool_errs", "fallbacks", "ttft_s", "dur_s"], rows)

    kinds = Counter(k for c in calls for k in call_anomalies(c))
    table("Call anomalies (what went wrong at the API level)", ["anomaly", "calls"], kinds.most_common())

    # Step 2: does failure grow with prompt size? Tokens when Ollama reported them, else chars/4.
    buckets = defaultdict(list)
    for c in calls:
        tok = c.get("prompt_tokens") or (c.get("prompt_chars") or 0) // 4
        b = next((f"<{n // 1000}k" for n in (8000, 16000, 24000, 32000, 48000) if tok < n), ">=48k")
        buckets[b].append(c)
    order = ["<8k", "<16k", "<24k", "<32k", "<48k", ">=48k"]
    table("Prompt size vs problems", ["prompt", "calls", "anomaly", "tool_err_calls", "dur_s"],
          [[b, len(buckets[b]), pct(sum(1 for c in buckets[b] if call_anomalies(c)), len(buckets[b])),
            pct(sum(1 for c in buckets[b] if c.get("prev_tool_errors")), len(buckets[b])),
            med(c.get("duration_s") for c in buckets[b])] for b in order if buckets[b]])

    # Step 3: conversations: how many turns an agent needed, and whether its tools failed.
    convs = defaultdict(list)
    for c in calls:
        convs[c.get("conv")].append(c)
    per_agent = defaultdict(list)
    for cs in convs.values():
        per_agent[cs[0].get("agent")].append(cs)
    table("Agent runs (conversations)", ["agent", "runs", "median_turns", "max_turns", "runs_w_tool_errs", "median_min"],
          [[a, len(rs), med(len(r) for r in rs), max(len(r) for r in rs),
            pct(sum(1 for r in rs if any(c.get("prev_tool_errors") for c in r)), len(rs)),
            med(sum(c.get("duration_s") or 0 for c in r) / 60 for r in rs)] for a, rs in sorted(per_agent.items())])

    errs = Counter(t[:80] for c in calls for t in c.get("prev_tool_error_text", []))
    table("Most common tool errors seen by local agents", ["count", "error (first 80 chars)"],
          [[n, t.replace("\n", " ")] for t, n in errs.most_common(10)])


def report_outcomes(outs):
    """Summarise reviewed outcomes and say which task classes are ready to offload more."""
    groups = defaultdict(list)
    for o in outs:
        groups[(o["agent"], o["task"])].append(o)
    rows, advice = [], []
    for (agent, task), os_ in sorted(groups.items()):
        n = len(os_)
        r = Counter(o["result"] for o in os_)
        reasons = Counter(x for o in os_ for x in o.get("reasons", []))
        rate = r["pass"] / n
        rows.append([agent, task, n, pct(r["pass"], n), pct(r["partial"], n), pct(r["fail"], n),
                     sum(1 for o in os_ if o.get("redo") == "cloud"),
                     ", ".join(f"{k}:{v}" for k, v in reasons.most_common(3))])
        top = reasons.most_common(1)[0][0] if reasons else "unknown"
        if n < MIN_N:
            advice.append(f"{agent}/{task}: only {n} samples, keep collecting")
        elif rate >= READY:
            advice.append(f"{agent}/{task}: {pct(r['pass'], n)} pass, ready to offload more of this")
        elif rate < WEAK:
            advice.append(f"{agent}/{task}: {pct(r['pass'], n)} pass, keep in cloud or tune (top cause: {top})")
        else:
            advice.append(f"{agent}/{task}: {pct(r['pass'], n)} pass, usable with review; tune {top}")
    table("Reviewed outcomes by agent / task",
          ["agent", "task", "n", "pass", "partial", "fail", "redone_in_cloud", "top reasons"], rows)
    table("Failure reasons overall", ["reason", "count"],
          Counter(x for o in outs for x in o.get("reasons", [])).most_common())
    print("\n## Offload advice")
    print("\n".join(f"- {a}" for a in advice) or "(no outcomes recorded yet)")
    fails = [o for o in outs if o["result"] != "pass" and o.get("note")][-10:]
    table("Latest failure notes", ["ts", "agent", "task", "reasons", "note"],
          [[o["ts"], o["agent"], o["task"], ",".join(o.get("reasons", [])), o["note"][:90]] for o in fails])


def cmd_report(a):
    """Print the call and outcome reports for the last N days."""
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - a.days * 86400))
    calls = list(read_jsonl(sorted(glob.glob(os.path.join(DIR, "calls-*.jsonl"))), since))
    outs = list(read_jsonl([OUTCOMES] if os.path.exists(OUTCOMES) else [], since))
    print(f"# Local model report, last {a.days} days: {len(calls)} calls, {len(outs)} reviewed outcomes")
    report_calls(calls)
    report_outcomes(outs)


def main():
    """Parse arguments and run the sub-command."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("outcome", help="record a reviewed local-agent result")
    o.add_argument("--agent", required=True, choices=AGENTS)
    o.add_argument("--task", required=True, choices=TASKS)
    o.add_argument("--result", required=True, choices=RESULTS)
    o.add_argument("--reason", action="append", choices=REASONS, help="repeat for several")
    o.add_argument("--redo", choices=["cloud", "local", "none"], default="none", help="who redid the work")
    o.add_argument("--minutes", type=float, help="wall time the local agent took")
    o.add_argument("--repo", default="")
    o.add_argument("--note", default="", help="one line: what went wrong or what made it work")
    o.set_defaults(func=cmd_outcome)
    r = sub.add_parser("report", help="summarise calls and outcomes")
    r.add_argument("--days", type=int, default=30)
    r.set_defaults(func=cmd_report)
    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
