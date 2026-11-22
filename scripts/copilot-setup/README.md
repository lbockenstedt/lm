# Copilot setup for the Lab Manager fleet

One command sets up GitHub Copilot CLI the way the fleet owner works, so
every person and AppBuilder (AB) follow the same model policy and spend gate.

```bash
bash <fleet>/lm/scripts/copilot-setup/install.sh            # Copilot cloud models only
bash <fleet>/lm/scripts/copilot-setup/install.sh --local    # plus local Ollama agents
```

Run it from an lm checkout that stays put (not a temporary worktree), then
restart Copilot CLI. Re-run it after `git pull` whenever the policy, the gate,
the agents or the rules change. A file it changes is first backed up as
`<file>.bak-<timestamp>`.

## What it installs

| Piece | Source in lm | Installed to |
|---|---|---|
| Daily AI spend gate (fleet rule 1.10) | `.github/hooks/ai_budget.py`, `.github/ai-budget.json` | `~/.copilot/ai-budget/`, hook `~/.copilot/hooks/ai-budget.json` |
| Coordinator and ladder rules | `copilot-instructions.md` (+ `local-models.md` with `--local`) | `~/.copilot/copilot-instructions.md` |
| Coding agents `cloud-coder`, `cloud-coder-plus` | `agents/`, models from `.github/model-policy.json` | `~/.copilot/agents/` |
| Coordinator model and effort, fleet skills | `.github/model-policy.json`, `.claude/skills` | `~/.copilot/settings.json` (other keys kept) |
| Fleet rules and specialist agents for every repo | `.github/fleet-rules.md`, `.github/agents` | links `<fleet>/AGENTS.md`, `<fleet>/.github/agents` |
| Model ledger: outcomes and cost per model and task | `local-stats/localstat.py` | `~/.copilot/local-stats/` |
| `--local`: local agents, provider list, proxy | `agents-local/`, `providers.json`, `ollama-proxy/` | `~/.copilot/...`, launchd `com.copilot.ollama-proxy` |

## The spend gate

Once a local day's cloud AI spend reaches `gate_usd` ($100) every agent
stops: the hook refuses tool calls until a person reopens it. Within
`reserve_usd` of the gate no new cloud sub-agents start.

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
- the review ladder is proposed and not yet applied to AB.

AB is to read the same file (not wired yet; see the docs). Edit it only in lm; the fleet sync copies it to every
repo. See `docs/agents-and-skills.md`, "The model policy", for the evidence.

## The model ledger

After reviewing any agent's result, the coordinator records it with
`localstat.py outcome` (model, task, pass/fail, why, and the cost read from
Copilot's usage log). `localstat.py report` turns the ledger into a cost per
action matrix: for each task type and model, the pass rate, USD per try, USD
per passing result (failed tries included), the top failure reasons, and the
cheapest model that passes often enough. Use it to move a model up or down the
ladder for a kind of work. `localstat.py import-bench FILE` adds benchmark
runs (cloudbench.jsonl) to the same matrix. The ledger is per user, in
`~/.copilot/local-stats/outcomes.jsonl`.

## Local models (`--local`)

Optional and free. It needs [Ollama](https://ollama.com) and a GPU Mac with
enough memory (the three models are about 50 GB; `--models` pulls them and
creates the 64k-context aliases). The proxy on 127.0.0.1:11435 turns model
thinking off, which Copilot cannot do. To share a model with another Ollama
host, write `~/.copilot/ollama-proxy/pools.json`, e.g.
`{"qwen3.8-27b-64k": [["192.0.2.10", 11434], ["127.0.0.1", 11434]]}`, and
restart the proxy. Each local call is logged to
`~/.copilot/local-stats/calls-YYYY-MM.jsonl`.
