# Copilot setup for the Lab Manager fleet

The cloud setup needs no installer. A Copilot CLI session started inside any
fleet repo (lm or any repo the fleet sync covers) reads everything from the
repo itself:

- `AGENTS.md`: the fleet rules;
- `.github/copilot-instructions.md`: the coordinator, coding ladder, spend
  gate and model ledger rules;
- `.github/agents`: the specialist agents and the `cloud-coder` /
  `cloud-coder-plus` coding agents;
- `.claude/skills`: the skills, including `review` and `model-ledger`;
- `.github/hooks/fleet-hooks.json`: the spend gate hook (it runs once the
  folder is trusted).

A new user clones lm (or any fleet repo) and starts `copilot` in it. Or, in
any Copilot session, ask it to pull the Lab Manager development rules: it
clones or pulls `lbockenstedt/lm` and works from there. These files are
edited only in lm; `sync-fleet-files.yml` copies them to every fleet repo.

Why not a Copilot plugin: a plugin cannot set up Ollama, the thinking-off
proxy or `providers.json`, and the repo already delivers the rest.

## The optional installer

`install.sh` adds only what a repo cannot:

```bash
bash <fleet>/lm/scripts/copilot-setup/install.sh                  # links and settings
bash <fleet>/lm/scripts/copilot-setup/install.sh --gate           # also the user-wide spend gate
bash <fleet>/lm/scripts/copilot-setup/install.sh --local          # also the local-model setup
bash <fleet>/lm/scripts/copilot-setup/install.sh --local --models # also pull the Ollama models
```

Run it from an lm checkout that stays put (not a temporary worktree), then
restart Copilot CLI. A file it changes is first backed up as
`<file>.bak-<timestamp>`. It never deletes anything. When it finds an old
installed copy of the fleet rules (`~/.copilot/copilot-instructions.md`) or
of the `cloud-coder` agents (`~/.copilot/agents/`), it prints a note:
remove them, because they now load from the repo.

| Option | Piece | Installed to |
|---|---|---|
| default | Fleet rules, agents and Copilot instructions for a session started in the fleet folder itself (not inside a repo) | links `<fleet>/AGENTS.md`, `<fleet>/.github/agents`, `<fleet>/.github/copilot-instructions.md` |
| default | Coordinator model and effort (from `.github/model-policy.json`), lm's skills folder | `~/.copilot/settings.json` (other keys kept) |
| `--gate` | Daily AI spend gate (fleet rule 1.10) as a user-wide hook, so it also covers sessions outside fleet repos | `~/.copilot/ai-budget/`, hook `~/.copilot/hooks/ai-budget.json` |
| `--local` | Local agents, provider list, thinking-off proxy, local-model rules | `~/.copilot/agents/`, `~/.copilot/providers.json`, `~/.copilot/ollama-proxy/`, `~/.copilot/instructions/local-models.instructions.md`, launchd `com.copilot.ollama-proxy` |
| `--models` | The three Ollama models and their 64k-context aliases | Ollama |

## The spend gate

Once a local day's cloud AI spend reaches `gate_usd` ($100) no new work
starts: the hook refuses cloud sub-agents, workflows, agent messages and
`copilot -p` runs, and work already running finishes. At `gate_usd` plus
`overrun_usd` ($25) it refuses every tool call of a cloud session, to stop a
runaway, until a person reopens it. Within `reserve_usd` of the gate no new
cloud sub-agents start.

Inside a fleet repo the same script is `.github/hooks/ai_budget.py`; the
paths below are the `--gate` install.

```bash
python3 ~/.copilot/ai-budget/hooks/ai_budget.py status          # today's spend
python3 ~/.copilot/ai-budget/hooks/ai_budget.py continue [USD]  # reopen for USD more (default $100)
rm ~/.copilot/hooks/ai-budget.json                              # uninstall the hook
```

An agent can never reopen the gate itself. AB enforces the same numbers.

## The model policy

`lm/.github/model-policy.json` says which model and effort each role uses:

- the coordinator (the main CLI session) plans, scopes, reviews diffs and
  commits, but does not code;
- coding climbs `coding.ladder`, cheapest first, one rung each time the
  tests still fail;
- reviews run one reviewer per panel on the review ladder (adopted for local
  sessions by the review skill; AB's own panels are not changed yet).

AB's fixes read `coding.ladder` from the same file; its review panels do not yet (see the docs). Edit it only in lm; the fleet sync copies it to every
repo. See `docs/agents-and-skills.md`, "The model policy", for the evidence.

## The model ledger

After reviewing any agent's result, the coordinator records it with
`localstat.py outcome` (model, task, pass/fail, why, and the cost read from
Copilot's usage log). `localstat.py report` turns the ledger into a cost per
action matrix: for each task type and model, the pass rate, USD per try, USD
per passing result (failed tries included), the top failure reasons, and the
cheapest model that passes often enough. Use it to move a model up or down the
ladder for a kind of work. `localstat.py import-bench FILE` adds benchmark
runs (cloudbench.jsonl) to the same matrix. The script is the `model-ledger`
skill (`lm/.claude/skills/model-ledger/localstat.py`); the ledger is per
user, in `~/.copilot/local-stats/outcomes.jsonl`. For a `copilot -p` run (a
reviewer, say), pass `--usage-output-file F` to copilot and `--usage-file F`
to `localstat.py outcome`, so the run's cost is recorded.

## Local models (`--local`)

Optional and free. It needs [Ollama](https://ollama.com) and a GPU Mac with
enough memory (the three models are about 50 GB; `--models` pulls them and
creates the 64k-context aliases). The proxy on 127.0.0.1:11435 turns model
thinking off, which Copilot cannot do. To share a model with another Ollama
host, write `~/.copilot/ollama-proxy/pools.json`, e.g.
`{"qwen3.8-27b-64k": [["192.0.2.10", 11434], ["127.0.0.1", 11434]]}`, and
restart the proxy. Each local call is logged to
`~/.copilot/local-stats/calls-YYYY-MM.jsonl`.
