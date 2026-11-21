## Offload bounded work to local models

This Mac runs Ollama with specialist models exposed as custom agents. They
are free (no AI credits). Use them by default for the tasks below instead of
a cloud explore/task subagent, or instead of reading large output into the
main context. Keep cloud tokens for judgement and hard work.

With these installed, `local-coder` is rung 0 of the coding ladder: try it
first for a small single-file edit when Ollama is up, then `cloud-coder`.

### Routing table

| Task | Agent (model) | Why it fits (Nov 2026 benchmark) |
|---|---|---|
| Read-only code search: "where is X defined/used", trace a call path, list the files a change touches, explain one file or function | `local-scout` (qwen3.8-27b) | Tool selection 100%, tool round-trips 100% |
| Small, fully specified edit: fix a bug you have already diagnosed, one file plus one focused test, mechanical rename | `local-coder` (qwen3.6-35b-coding) | End-to-end edits 2/2; 77–118s vs qwen3.8's 121–190s; real header edit reviewed and passed |
| Documentation, docstrings and comments from exact, verified behavior facts | `local-docs` (gemma4-12b) | Synthetic docs score 1.00; main agent supplies facts and checks every claim |
| Condense long output: test/CI/build logs, journalctl, JSON or API dumps, changelogs; draft commit or PR text from a diff; turn text into a JSON object | `local-summarizer` (gemma4-12b) | Log facts 5/5, JSON 100%, instructions 100% |

Gemma's end-to-end docs fixture preserved all five supplied facts. Both
Gemma and qwen3.8 got source citations wrong when counting unnumbered view
output, so the scout now uses grep/glob only and requires numbered grep
evidence. Retain qwen3.8 rather than promoting Gemma on synthetic scores
alone. A correct answer with bad citations is a partial failure, not a pass.

### Always local (default unless the user says otherwise)
These are always routed to a local agent in **background** mode, without
weighing it each time. The main agent keeps working and reviews the result
before committing:
- **Documentation updates** (`docs/*.md`, README, CHANGELOG, in-app help)
  once the code is final. The main agent passes the exact behaviour facts
  (states, defaults, routes, caveats) and the file and section to edit, and
  `local-docs` writes the prose. The local model supplies wording, never
  facts; check every claim against the code before committing.
- **Docstrings and `//` comments** for code that is already written
  (`local-docs`).
- **Commit messages and PR intent text**, drafted from the diff
  (`local-summarizer`). The main agent adds any cross-repo evidence the diff
  can't show.
- **Condensing logs, CI and test output, and JSON dumps** (`local-summarizer`).

Exceptions, which stay with the main agent: a doc change of 5 lines or
fewer (the agent's ~2 min start-up costs more than the edit), and anything
the user is waiting on right now. If the local agent fails once, do the
work directly.

### Offload when
- The answer can be checked cheaply: a `path:line` citation, a passing test,
  or facts you can spot-check.
- The input is large but the question is narrow, e.g. more than ~200 lines
  of output or more than 3 files to grep through.
- The task is independent, so the local agent can run in parallel with your
  own work.

### Scope first, then offload the edit
A change that sounds open-ended ("strip X everywhere", "fix every place
that…") is usually a small mechanical edit once scoped. Don't send it whole
to a cloud agent:
1. Scope it first: find the exact functions, lines and tests to change, and
   confirm nothing else depends on them. Do this yourself with a few
   grep/view calls, or in the background (`local-scout`) while you keep
   working.
2. Once the edit is exact (which lines become what, which tests assert
   what), hand it to `local-coder`, even across 2-4 files in one repo.
3. Review its diff, run the tests and smoke, and commit yourself.

Use a cloud agent only when the task still needs judgement after scoping.
The "multi-file" rule below covers changes that need design across
files, not exact edits that happen to touch several files.

### Secondary requests default to local
When the user adds a request while another task is active ("in the
background", "also…", "add this to the list"), or the work is not what the
user is waiting on right now, route its bounded parts to local agents by
default: `local-scout` for the code trace, `local-coder` for the exact edit,
`local-summarizer` for logs. "Don't block when the user is waiting" applies
only to the task they are waiting on, not to secondary ones. Live production
actions in the secondary request still stay with you.

Before starting each new request, state in one line which parts go local
and which stay cloud, so missed offloads are visible.

### Do not offload
- Anything the benchmark showed local models get wrong: writing new code
  from a dense written spec (every model failed name/format parsing), or
  parsing rules with subtle edge cases. Write those yourself, with tests.
- Design, planning, root-cause diagnosis across services, multi-file or
  cross-repo changes.
- Security, auth, tenant isolation, credentials or secrets, even read-only.
- Live production actions (Azure, NetBox, hub, AB VMs) and anything that
  needs network or git writes.
- Final reviews, and answers the user is waiting on where a wrong answer is
  costly.
- Trivial lookups you can do in 1-2 direct grep/view calls.

### Latency (measured Nov 2026; plan around it)
- A cold local agent call reads a ~15-20k-token Copilot prompt. The measured
  20k-token prefill was about 25s on qwen3.6's coding MoE, 90s on gemma,
  and 161s on qwen3.8. Model loading adds a few seconds. Later turns reuse
  the prompt cache; these measurements are not end-to-end task guarantees.
- So always launch local agents in **background** mode, and keep working on
  something independent meanwhile. Never block on a local agent when the
  user is waiting or your very next step needs the answer; do that
  yourself.
- Best value: big, slow-to-read inputs (long logs, many files) and scoped
  mechanical edits, where one local call replaces many cloud tokens.

### How to use them
- Check Ollama is up first (`curl -s -m 2 localhost:11434/api/version`). If
  it isn't, do the work yourself; don't start Ollama.
- Give the agent a precise, self-contained prompt: repo path, files, the
  exact question or change, and the test command. Use absolute project and
  file paths: a relative-path qwen3.6 test invented a session directory and
  looped over grep without editing. Stop a run that repeats an unchanged
  search; do not treat successful tool calls as evidence of progress.
- For non-interactive CLI tests, pass both `--agent <name>` and the explicit
  `--model ollama/<id>`. A test with only `--agent` used a cloud model.
  Use `--usage-output-file <path>` to verify which model actually ran.
  Expose only the tools needed; denied shell attempts are harness failures,
  not proof that the model's answer is wrong. Bound unattended test processes
  with a hard timeout; a prompt's tool-call limit is not an enforced limit.
- Treat results as drafts. Spot-check cited `path:line` claims, and review
  every `local-coder` diff before building on it or committing.
- If the local agent errors, times out, or returns an unusable answer once,
  fall back to doing it yourself or to a cloud subagent. Don't retry in a
  loop.
- Concurrency: at most one large qwen coding/scout job plus one gemma
  docs/summarizer job at a time. Models load on demand; never pin them.
- Batch local work: send related questions in one prompt rather than many
  small calls.

### Record every outcome (statistics for tuning)
The proxy logs every local call automatically to
`~/.copilot/local-stats/calls-YYYY-MM.jsonl`. Only the reviewer knows whether
the work was right, so after reviewing each local agent's result, record one
outcome, including passes (the pass rate is the point):

    python3 ~/.copilot/local-stats/localstat.py outcome --agent local-coder \
        --task edit --result fail --reason corrupt_code --redo cloud \
        --minutes 3 --repo lm --note "one line: what went wrong or what worked"

- `--task`: search, trace, explain, edit, test, docs, summarize, commit_msg,
  json, other. `--result`: pass, partial or fail.
- `--reason` (needed unless pass; repeatable): corrupt_code, wrong_answer,
  incomplete, off_spec, bad_citation, tool_misuse, loop_or_stall, timeout,
  crash, too_slow, other. `--redo`: who redid the work (cloud, local, none).
- `localstat.py report --days 30` shows failure rates by agent and task,
  their causes, prompt size vs problems, and which task classes are ready to
  offload more (90%+ pass over 5+ samples) or should stay in the cloud.
  Check it before changing the routing table, and when asked how the local
  models are doing. Put the exact model ID in `--note` when comparing models;
  outcomes are grouped by agent/task, so a model switch otherwise mixes them.
  Benchmark inputs and raw scores are preserved under
  `~/.copilot/local-stats/benchmarks/2026-11-17/`, not just in `/tmp`.

## Local model environment

- Ollama is pinned at 0.40.16 (Nov 2026), run from `~/Ollama.app` because
  BeyondTrust blocks changes to `/Applications`. 0.34.2's MLX runner
  corrupted qwen indentation (4/4 files, 7/8 tool calls); 0.40.16 had 0
  errors at 63 tok/s. Do not choose solely by MLX/GGUF: the newer qwen3.6
  coding MoE read the agent prompt much faster than the dense MLX qwen3.8. Do not
  upgrade without first testing the new build side by side on a spare port
  (`OLLAMA_HOST=127.0.0.1:11500 ollama serve`) and checking open regressions.
- Models: `qwen3.6-35b-coding-64k` (coder), `qwen3.8-27b-64k` (scout),
  and `gemma4-12b-64k` (docs and summarizer). Each is a 64k-context alias
  registered in `~/.copilot/providers.json`. qwen3.6 and gemma fit together
  on this Mac; do not assume both qwen models plus gemma fit simultaneously.
  The qwen3.8 scout is pooled to the other GPU Mac with local fallback.
  qwen3.6 stays local because its alias is not installed on the other Mac.
  Retain benchmark candidates until the owner approves their removal.
- Thinking must stay off. Copilot sends `reasoning_effort: "medium"` (or
  nothing, which Ollama treats as thinking on), so `providers.json` points
  at a proxy on 127.0.0.1:11435 (`~/.copilot/ollama-proxy/proxy.py`,
  launchd `com.lrb.ollama-proxy`) that forces `reasoning_effort: "none"`
  and forwards to Ollama on 11434. With thinking on, a local-coder edit
  took 6 min instead of 70 s, and a 4-file edit stalled 46 min with no
  edits. The proxy also caps gemma at temperature 0.7 / top_p 0.8 (at
  Copilot's 1.0 it failed a codegen run; qwen scored the same at any
  temperature). If local agents are slow, check the proxy first
  (`curl -s 127.0.0.1:11435/api/version`). qwen3.5-coder and
  glm-4.7-flash were benchmarked and removed (weaker on reasoning/code).
- Models load on demand and unload after 5 minutes idle (Ollama default).
  Never pin them with a long or negative `keep_alive`, and unload any you
  load by hand for testing (`keep_alive: 0`).
