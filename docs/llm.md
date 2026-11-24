# Local LLM workers

`llm` is a loadable Linux agent role. It starts a pre-provisioned, dedicated
Ollama service after approval and tenant assignment. The hub routes to an idle
worker in the caller's tenant, or to explicitly Shared workers if the tenant
has no approved pool. A busy reply can move to another worker; an ambiguous
disconnect is not automatically replayed. Direct inference requests are local-only.
Loading the role restores missing service-unit files and reloads systemd, but
does not itself install the Ollama bundle or download models.

## Provision a worker VM

Provision the approved Ollama 0.40.16 runtime at `/opt/lm-llm/bin/ollama` and
stage approved, CPU-compatible weights in `/var/lib/lm-llm/models`. The agent
installer stages the dedicated unit without enabling it independently. It binds
loopback port 11438, disables cloud, and uses one slot with no artificial CPU
cap. The port is fixed rather than a setting: it never leaves the VM, and
keeping off Ollama's default 11434 means a system Ollama is never mistaken for
the worker's runtime. For either runtime, obtain the correct Linux architecture release from
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
The role does not automatically upgrade an existing runtime.
After Linux CPU qualification and review of open regressions, VM provisioning
can set `LM_LLM_OLLAMA_VERSION` in the `lm-agent` service environment to pin
the vetted replacement. The role rejects mismatched or invalid pins instead
of serving with an unapproved version.

## API and diagnostics

- `GET /api/llm/models?tenant=…` returns the selected tenant's model digests
  and readiness issues from current reports. Any member of the tenant can read it.
- `POST /api/llm/complete` and `POST /api/llm/check` run a job on a CPU slot,
  so they need edit access to the tenant (a write user, tenant admin, or global
  admin); a view-only member gets 403. AppBuilder uses its own
  certificate-bound path, not these routes.
- `POST /api/llm/complete?tenant=…` accepts `model`, `digest`, `prompt`, and
  optional `format` (`text`, `json`, or `python`). JSON must be an object or
  array. Python drafts are syntax-checked but never executed. Outputs are
  advisory, not verified for correctness.
- Alternatively, supply `task` instead of `model` and `digest`. The hub's
  `llm_task_models` setting in `POST /setup/config` maps task names to ordered
  lists of `{model, digest}` records. The hub tries the next approved artifact
  only when the preferred one cannot accept the job. No task is enabled by
  default.
- `POST /api/llm/check?tenant=…` accepts either an exact `model` and `digest`
  or a `task`, plus a `fixture` (`json` or `indentation`). A task check uses
  the task's configured model order and options. It runs a synthetic pool smoke test,
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
The hub does not re-check repository visibility itself; it relies on the AB
client bound to that certificate, so enable `allow_public_cloud` only on
certificate mappings held by an AB you trust to report it.

## Qualification and fleet telemetry

Global admins can use **LLM** to inspect worker readiness, active jobs, and the latest 200 finished attempts. The dashboard JSON is available at `GET /api/llm/admin/dashboard`; it contains no prompts, generated text, credentials, or provider URLs. History resets on hub restart; export it to a downstream system for longer-term analysis.

Use **LLM → Settings** to append reported, digest-pinned models in task priority order, bind exact AppBuilder repositories to a tenant and certificate SAN, select an approved Shared worker for a staged candidate, or create a Vault-backed cloud overflow profile. Edit an existing candidate by saving its staged key again. The worker restarts its serving daemon after three failed idle API health probes, at most once in five minutes; it does not interrupt an active inference or qualification.

Workers report CPU mode, CPU model when available, CPU architecture, logical vCPUs and total guest RAM in bytes, even before Ollama is ready. These are VM totals, not free memory or service cgroup limits. An `llm_task_models` entry can set `min_vcpus` and `min_ram_bytes` from qualification results: the hub skips narrower or unreported capacity for that entry, then tries the next ordered artifact without bypassing tenant boundaries. Entries without minima retain older-worker compatibility. An entry can also set `temperature` (0–2), `top_p` (0–1), integer `top_k` (0–256), `repeat_penalty` (>0–2), and integer `num_ctx` (1–131072) in **LLM → Settings**; leave them blank for Ollama's defaults. The hub sends them only with that artifact, and the worker rejects any other option or out-of-range value. Workers advertise supported options; a worker that omits this field retains compatibility with the earlier `temperature` and `top_p` profile options, but cannot receive the newer options until it advertises them. Still older workers may ignore those earlier options, so update workers before relying on exact sampling. Workers never choose sampling from a model's name; the CLI trials capped Gemma drafts at temperature 0.7 and top-p 0.8, so set those values on a Gemma entry. A 65,536-token context can require substantial CPU VM memory and must be tested on that VM.

Workers report lifecycle status every 30 seconds. Start failures distinguish a
missing service unit (`runtime_unit_missing`), missing Ollama binary
(`runtime_binary_missing`), and other start failures (`runtime_start_failed`).
A unit or binary that exists but is unusable (for example a directory in place
of the unit, or a binary without execute permission) is `runtime_start_failed`,
not missing: unit staging never overwrites an existing entry, so inspect it on
the worker. The bundle installer never replaces an existing `/opt/lm-llm`, so
for `runtime_binary_missing` on a partial runtime, remove that directory before
reinstalling. An invalid or masked service-unit symlink is reported as
`runtime_unit_symlink`; inspect its target before changing it. If unit staging
or `systemctl daemon-reload` fails during role load, the agent retries once a
minute while the LLM role remains loaded, without requiring another hub
command. That retry only repairs the units; it never starts Ollama. The hub
requests runtime starts only on approved workers bound to a tenant; explicit
candidate activation may also start the serving runtime. The hub retries
transient runtime-start failures every two minutes, which covers a
worker whose units were just repaired. Missing binaries and masked or broken
unit links remain visible for operator repair.
The agent logs the first repair failure, and any change in its error, as a
warning; identical repeats are logged at debug level. The worker's runtime
start and restart results (logger `LLMSpoke`) appear in the hub's agent logs
under the LLM sub-spoke (`<agent>-llm`), not the base agent.
Stopped workers keep the `runtime_not_started` status code for compatibility
with older hubs and include the current, re-evaluated cause in `detail_code`:
`runtime_unit_missing`, `runtime_unit_symlink`, `runtime_binary_missing` or
`runtime_start_failed`. The hub ignores any other `detail_code`, so no other
code can end the start retry.
The hub logs issue transitions and recovery once per change, and the admin
dashboard exposes the same stable codes without retaining raw systemd output.
Hub log lines name the worker by its display name with its key in parentheses
(the key alone if it has no display name). A start reply with a stable code is
logged as `runtime start rejected: <code>`. A timeout, an updating spoke, a
busy worker or an unrecognised reply is logged as
`runtime start outcome unknown` instead, because it says nothing about the
runtime; the next status report decides any retry.

The routing forms read their field constraints from the hub settings schema.
Model choices come from reporting workers, and repository bindings offer only
non-Shared tenants.

For a first Shared worker, **Prepare and test** selects an owner-approved public
CPU candidate and downloads the pinned x86_64 Ollama 0.40.16 release and model
on the worker, not through the hub. The worker needs access to GitHub's release
assets and the Ollama registry, plus disk space for the 1.55 GB runtime archive,
model download, and a second model copy during activation. On a Debian-family
worker missing `zstd`, preparation installs it through apt before downloading
the runtime; the package manager and configured repositories must be usable.
Other architectures,
changed model tags, or an incompatible existing runtime fail instead of being
silently substituted. The dashboard shows runtime, pull and fixture phases, not
byte-level download progress. An interrupted preparation is retried after an
authorized hub reconnect. It runs two synthetic fixtures with thinking disabled;
passing them is **not certification**. After inspecting the result, use
**Activate** to publish that exact artifact. An operator-managed catalog or
role catalog override blocks automatic activation. Activation does not configure
or enable a task profile.

The public candidates use a 65,536-token context. Gemma 4 12B uses temperature
0.7, top-p 0.8 and top-k 64; Qwen 3.6 coding uses 0.6, 0.95, 20 and repeat
penalty 1; Qwen 3.8 scouting uses 1, 0.95, 20 and repeat penalty 1. The Gemma
values include the tested proxy overrides; Qwen values are observed alias
defaults, not verified per-request overrides. These public artifacts are
candidates, not necessarily the same weights or format tested on the Macs.
Selecting an exact candidate artifact in a task profile prefills these options;
they can be changed, and blank fields use Ollama defaults. Benchmark correctness and timing on the
target worker before routing real work. The previous shadow review backtest
did not establish local models as replacements for AB's cloud voting panels.

`POST /api/llm/admin/qualify` accepts `{"candidate":"trial"}` and returns 202 when scheduled. Set the hub's `llm_qualification_candidates.trial` to `{"worker":"<Shared LLM registration ID>","label":"CPU trial"}`; that worker is excluded from tenant inference. On the dedicated VM, stage the vetted candidate at `/opt/lm-llm-candidate/bin/ollama`, or on a fresh install pass `--llm-candidate-bundle /path/to/candidate.tar --llm-candidate-bundle-sha256 <trusted-sha256>`. That archive holds only `bin/ollama` and `lib/` as regular files; the installer verifies it like the serving bundle, rejects a bundled model store, and never replaces an existing candidate (remove the old one by hand first). The installer supplies a disabled candidate unit; the role starts it for the job on loopback port 11439 and stops it afterward. It uses `/var/lib/lm-llm-candidate/models`, not the baseline store on port 11438. Set the root-managed `/etc/lm/llm-qualification.json` to `{"trial":{"model":"<public tag>","digest":"<64 hex>","version":"<x.y.z>","baseline":{"model":"<installed tag>","digest":"<64 hex>","version":"<x.y.z>"}}}`. Only the candidate service pulls a model. Both runtimes run fixed CPU JSON and indentation fixtures with the same options; inspect correctness and timing separately. The hub waits up to 15,000 seconds, including up to two hours for a pull and up to 15 minutes per tuned fixture. A qualification test does not automatically activate an artifact or upgrade Ollama. Check open release regressions before staging the candidate.

On the first Shared test worker, where no baseline exists, the root-managed manifest can instead use `"bootstrap": true` and an `"options"` object containing `num_ctx` and any other intended sampling settings; omit `baseline`. The candidate alone runs the two fixtures with those options, CPU-only and thinking disabled. `bootstrap_smoke_passed` means only those fixtures passed, not that the model is certified or usable for real work. For this operator-managed qualification path the candidate runtime and manifest must be staged by an operator; a passing smoke test does not publish the model. Activation re-verifies the pulled manifest: it must hash to the pinned digest, or be the rewritten manifest newer Ollama clients store, which is accepted only when it references the pinned registry manifest (present in the store and hashing to the pin) and carries exactly that manifest's config and layers. Task checks use the eligible tenant pool, not necessarily a particular worker.
