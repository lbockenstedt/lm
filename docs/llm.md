# Local LLM workers

`llm` is a loadable Linux agent role. It starts a pre-provisioned, dedicated
Ollama service after approval and tenant assignment. The hub routes to an idle
worker in the caller's tenant, or to explicitly Shared workers if the tenant
has no approved pool. A busy reply can move to another worker; an ambiguous
disconnect is not automatically replayed. Direct inference requests are local-only.

## Provision a worker VM

Provision the approved Ollama 0.40.16 runtime at `/opt/lm-llm/bin/ollama` and
stage approved, CPU-compatible weights in `/var/lib/lm-llm/models`. The agent
installer stages the dedicated unit without enabling it independently. It binds
loopback port 11438, disables cloud, and uses one slot with no artificial CPU
cap. For either runtime, obtain the correct Linux architecture release from
the approved distribution channel, verify the archive against an independently
trusted SHA-256, and stage the full extracted bundle (including runtime libraries)
in a root-owned, non-writable-by-service directory. Do not use an unversioned
install script or overwrite the serving binary to run a trial.
Load **LLM Worker (CPU)** in the agent role picker. Unloading the role
drains active work and stops its service without deleting models.

On a fresh worker, pass `--llm-bundle /path/to/serving.tar --llm-bundle-sha256 <trusted-sha256>` to the agent installer. The offline archive contains executable `bin/ollama`, its runtime libraries under `lib/`, a digest catalog `llm-models.json`, and the approved `models/manifests/` and `models/blobs/`. Use regular files, not links: Ollama 0.40.16 writes `models/manifests-v2/` entries as links, so ship the regular-file `models/manifests/` tree instead. The installer verifies the archive, stages a read-only model store, and never replaces an existing runtime. The serving unit sets `OLLAMA_NOPRUNE=1`, because Ollama's startup pruning exits when it cannot remove an empty directory or unused blob from that store. The bundle catalog is used only if neither the role config nor `/etc/lm/llm-models.json` supplies a catalog.

Set `/etc/lm/llm-models.json` to a JSON object mapping exact installed model
names, including the tag, to their approved 64-character lowercase digests.
An explicit role `config.models` object overrides the file. Only stage
CPU-compatible artifacts whose licenses and provenance you have checked.
The prior CLI benchmarks are a starting shortlist: `gemma4-12b-64k` for
summaries and docs, `qwen3.6-35b-coding-64k` for small coding drafts, and
`qwen3.8-27b-64k` for read-only scouting. These are CLI aliases, not
automatically approved Ollama artifacts.
GPU results do not qualify those same weights or context sizes for a CPU VM.
The role does not download model tags or upgrade the runtime.
After Linux CPU qualification and review of open regressions, VM provisioning
can set `LM_LLM_OLLAMA_VERSION` in the `lm-agent` service environment to pin
the vetted replacement. The role rejects mismatched or invalid pins instead
of serving with an unapproved version.

## API and diagnostics

- `GET /api/llm/models?tenant=…` returns the selected tenant's model digests
  and readiness issues from current reports.
- `POST /api/llm/complete?tenant=…` accepts `model`, `digest`, `prompt`, and
  optional `format` (`text`, `json`, or `python`). JSON must be an object or
  array. Python drafts are syntax-checked but never executed. Outputs are
  advisory, not verified for correctness.
- Alternatively, supply `task` instead of `model` and `digest`. The hub's
  `llm_task_models` setting in `POST /setup/config` maps task names to ordered
  lists of `{model, digest}` records. The hub tries the next approved artifact
  only when the preferred one cannot accept the job. No task is enabled by
  default.
- `POST /api/llm/check?tenant=…` accepts an exact `model`, `digest`, and
  `fixture` (`json` or `indentation`). It runs a synthetic pool smoke test,
  checks that the output kept the expected structure and content, and reports
  timings or a recommended fix without returning the generated text.

The native Ollama call disables thinking and streaming, loads one model on
demand, and allows roughly 15 minutes for CPU inference. Successful replies
include Ollama timing counters when present (nanoseconds and token count).
Compare load, prompt processing, and generation separately. Slow valid
responses pass, with an advisory at ten minutes; timeouts, output-token truncation, malformed JSON, and
invalid Python receive distinct error codes with suggested resolutions.
Replay synthetic JSON and indentation fixtures on the target CPU VM before
approving a model. Test candidate runtimes side by side on a spare port and
check open regressions before changing the pin. No prompts or completions are
written to the pool's metadata or offline mailbox.

## AppBuilder and cloud routing

Opt advisory PR summaries in by listing exact `owner/repo` names in AB's
`pr_review_lm_summary_repos` setting. In hub `POST /setup/config`, map each
repository under `llm_ab_pr_repos` to its `tenant` and pinned AB SAN
(`certificate`), and define the ordered `pr_summary` task in `llm_task_models`.
This does not change validation, final review, builds, or log triage. An
unavailable hub summary is omitted rather than sent through AB's own providers.

Optional cloud overflow is limited to explicitly opted-in **public** repositories
(`allow_public_cloud: true` on the hub repo mapping, plus confirmed public GitHub
visibility from AB). Enable only for repositories cleared for that provider.
Cloud runs only after local no-capacity, never for a private repository or after
an ambiguous inference failure. `llm_cloud_profiles` accepts ordered records
with `task: "pr_summary"`, `tenant`, `model`, `url` (public HTTPS
`/chat/completions` endpoint), and `vault_credential: {bucket, name}` from that
tenant's Vault bucket. Select `max_tokens` (default) or `max_completion_tokens`
according to the endpoint and model. LM sends one capped request, never
resubmitting to negotiate this field. Cloud profiles do not expose or store inline keys.
# Qualification and fleet telemetry

Global admins can use **LLM** to inspect worker readiness, active jobs, and the latest 200 finished attempts. The dashboard JSON is available at `GET /api/llm/admin/dashboard`; it contains no prompts, generated text, credentials, or provider URLs. History resets on hub restart; export it to a downstream system for longer-term analysis.

Use **LLM → Settings** to append reported, digest-pinned models in task priority order, bind exact AppBuilder repositories to a tenant and certificate SAN, select an approved Shared worker for a staged candidate, or create a Vault-backed cloud overflow profile. Edit an existing candidate by saving its staged key again. The worker restarts its serving daemon after three failed idle API health probes, at most once in five minutes; it does not interrupt an active inference or qualification.

Workers report CPU mode, CPU model when available, CPU architecture, logical vCPUs and total guest RAM in bytes, even before Ollama is ready. These are VM totals, not free memory or service cgroup limits. An `llm_task_models` entry can set `min_vcpus` and `min_ram_bytes` from qualification results: the hub skips narrower or unreported capacity for that entry, then tries the next ordered artifact without bypassing tenant boundaries. Entries without minima retain older-worker compatibility. An entry can also set optional `temperature` (0–2) and `top_p` (0–1) in **LLM → Settings**; leave them blank for Ollama's defaults. The hub sends them only with that artifact, and the worker rejects any other option or out-of-range value. Workers never choose sampling from a model's name; the CLI trials capped Gemma drafts at temperature 0.7 and top-p 0.8, so set those values on a Gemma entry. Workers released before this setting ignore it and keep their built-in Gemma cap (0.7/0.8 for model names starting with `gemma`), so update every worker before relying on per-profile sampling.

The routing forms read their field constraints from the hub settings schema.
Model choices come from reporting workers, and repository bindings offer only
non-Shared tenants.

`POST /api/llm/admin/qualify` accepts `{"candidate":"trial"}` and returns 202 when scheduled. Set the hub's `llm_qualification_candidates.trial` to `{"worker":"<Shared LLM registration ID>","label":"CPU trial"}`; that worker is excluded from tenant inference. On the dedicated VM, stage the vetted candidate at `/opt/lm-llm-candidate/bin/ollama`, or on a fresh install pass `--llm-candidate-bundle /path/to/candidate.tar --llm-candidate-bundle-sha256 <trusted-sha256>`. That archive holds only `bin/ollama` and `lib/` as regular files; the installer verifies it like the serving bundle, rejects a bundled model store, and never replaces an existing candidate (remove the old one by hand first). The installer supplies a disabled candidate unit; the role starts it for the job on loopback port 11439 and stops it afterward. It uses `/var/lib/lm-llm-candidate/models`, not the baseline store on port 11438. Set the root-managed `/etc/lm/llm-qualification.json` to `{"trial":{"model":"<public tag>","digest":"<64 hex>","version":"<x.y.z>","baseline":{"model":"<installed tag>","digest":"<64 hex>","version":"<x.y.z>"}}}`. Only the candidate service pulls a model. Both runtimes run the same fixed CPU JSON and indentation fixtures; inspect correctness and timing separately. The hub waits up to 1,800 seconds for a result: the worker's worst case, with every step at its timeout, is about 1,470 seconds. No test automatically activates an artifact or upgrades Ollama. Check open release regressions before staging the candidate.
