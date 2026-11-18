// LLM → Dashboard: global-admin view of workers, jobs, and metrics.
// An ES module: the main nav opens it through lmViews.llm(container).
// Fetches GET /api/llm/admin/dashboard and POST /api/llm/admin/qualify.
import { safeHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

const settingsPath = '/api/llm/admin/settings';

// Read JSON from a hub route and surface the server's validation message.
async function apiJson(path, init) {
    const response = await fetch(path, init);
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
}

// Render routing inputs from the hub schema with choices from cached inventory.
function routingFields(fields, choices) {
    return fields.map(field => {
        const required = field.required ? safeHtml` required` : '';
        if (field.source) {
            return safeHtml`<div><label for="llm-routing-${field.name}">${field.label}</label>
                <select id="llm-routing-${field.name}" name="${field.name}"${required}>
                <option value="">${field.placeholder}</option>
                ${choices[field.source].map(({ value, label }) => safeHtml`<option value="${value}">${label}</option>`)}
                </select></div>`;
        }
        if (field.type === 'checkbox') {
            return safeHtml`<label><input name="${field.name}" type="checkbox"> ${field.label}</label>`;
        }
        const bounds = field.type === 'number' ? safeHtml` min="0" max="${field.maximum}" step="1"` : '';
        const pattern = field.pattern ? safeHtml` pattern="${field.pattern}"` : '';
        const length = field.maxlength ? safeHtml` maxlength="${field.maxlength}"` : '';
        return safeHtml`<label>${field.label} <input name="${field.name}" type="${field.type || 'text'}"
            placeholder="${field.placeholder || ''}"${required}${bounds}${pattern}${length}></label>`;
    });
}

// Render ordered model rules and exact repository bindings without raw JSON edits.
function routingMarkup(config, models, tenants) {
    const schema = config.routing_form_schema;
    const choices = {
        models: models.map((model, value) => ({ value, label: `${model.name} (${model.digest.slice(0, 12)})` })),
        tenants: tenants.map(t => ({ value: t.id, label: t.name })),
    };
    return safeHtml`
        <h4 class="font-bold">Ordered task models</h4>
        <p>New models are appended in priority order. To change priority, remove and re-add a model.</p>
        ${Object.entries(config.llm_task_models).map(([task, rows]) => rows.map((row, index) => safeHtml`
            <div>${task} — ${index + 1}. <span title="${row.digest}">${row.model}</span>
                (${row.min_vcpus || 0} vCPUs, ${row.min_ram_bytes || 0} RAM bytes minimum)
                <button type="button" data-action="removeModel" data-task="${task}" data-index="${index}" class="hpe-btn hpe-btn-secondary">Remove</button>
            </div>`))}
        <form data-submit="addModel" class="flex flex-wrap items-end gap-2">
            ${routingFields(schema.addModel, choices)}
            <button class="ml-auto hpe-btn hpe-btn-primary" ${models.length ? '' : safeHtml`disabled`}>Add model</button>
        </form>
        <h4 class="font-bold">AppBuilder repository policies</h4>
        ${Object.entries(config.llm_ab_pr_repos).map(([repo, row]) => safeHtml`
            <div>${repo} — ${tenants.find(t => t.id === row.tenant)?.name || 'Unknown tenant'}
                (${row.allow_public_cloud ? 'public cloud overflow enabled' : 'local only'})
                <button type="button" data-action="removeRepo" data-repo="${repo}" class="hpe-btn hpe-btn-secondary">Remove</button>
            </div>`)}
        <form data-submit="repo" class="flex flex-wrap items-end gap-2">
            ${routingFields(schema.repo, choices)}
            <button class="ml-auto hpe-btn hpe-btn-primary" ${tenants.length ? '' : safeHtml`disabled`}>Save repository</button>
        </form>`;
}

// Render only nonsecret cloud settings; the picker stores bucket/name references.
function settingsMarkup(config, credentials, models, tenants) {
    return safeHtml`<section class="space-y-4 border-t pt-4">
        <h3 class="font-bold">LLM Settings</h3>
        ${routingMarkup(config, models, tenants)}
        <h4 class="font-bold">Qualification candidates</h4>
        ${Object.entries(config.llm_qualification_candidates).map(([key, row]) => safeHtml`
            <div>${row.label} <button type="button" data-action="removeCandidate" data-key="${key}" class="hpe-btn hpe-btn-secondary">Remove</button></div>`)}
        <form data-submit="candidate" class="flex flex-wrap items-end gap-2">
            <label>Staged key <input name="key" required pattern="[A-Za-z0-9_\\-]{1,64}"></label>
            <label>Label <input name="label" required maxlength="100"></label>
            <label>Shared test worker <select name="worker" required>
                <option value="">Select worker</option>
                ${config.test_workers.map(w => safeHtml`<option value="${w.key}">${w.label}</option>`)}
            </select></label>
            <button class="hpe-btn hpe-btn-primary">Save candidate</button>
        </form>
        <h4 class="font-bold">Cloud overflow for opted-in public PR summaries</h4>
        ${config.llm_cloud_profiles.map((row, i) => safeHtml`<div>${row.model} — ${row.url}
            (${row.vault_credential.name}) <button type="button" data-action="removeCloud" data-index="${i}" class="hpe-btn hpe-btn-secondary">Remove</button></div>`)}
        <form data-submit="cloud" class="flex flex-wrap items-end gap-2">
            <label>HTTPS chat-completions URL <input name="endpoint" type="url" required></label>
            <label>Model <input name="model" required maxlength="200"></label>
            <label>Token limit field <select name="tokenLimitField">
                <option value="max_tokens">max_tokens</option>
                <option value="max_completion_tokens">max_completion_tokens</option>
            </select></label>
            <label>Credential Vault (required) <select name="credential" required>
                <option value="">Select a credential</option>
                ${credentials.map((c, i) => safeHtml`<option value="${i}">${c.label}</option>`)}
            </select></label>
            ${credentials.length ? safeHtml`<button class="hpe-btn hpe-btn-primary" type="submit">Add cloud profile</button>`
                : safeHtml`<button class="hpe-btn hpe-btn-primary" type="submit" disabled>Add cloud profile</button>`}
        </form>
        ${credentials.length ? '' : 'No automation-readable Vault credentials are available.'}
    </section>`;
}

// Open settings on demand; never replace an active settings form on a data refresh.
async function openSettings(root, isCurrent, onSave, workers) {
    root.textContent = 'Loading settings…';
    const live = () => isCurrent() && root.isConnected;
    try {
        const [config, credentials, directory] = await Promise.all([
            apiJson(settingsPath), _instanceVaultCredOptions(), apiJson('/setup/tenants'),
        ]);
        if (!live()) return;
        const tenants = (directory.tenants || []).filter(t => !t.shared && t.id !== directory.shared_tenant_id);
        const models = [...new Map(workers.filter(w => !w.qualification)
            .flatMap(w => w.models || []).map(m => [`${m.name}:${m.digest}`, m])).values()];
        const view = createView({ el: root, render: () => settingsMarkup(config, credentials, models, tenants) });
        let saving = false;
        // Apply a successful server write to the rendered snapshot.
        async function save(build) {
            if (saving) return;
            saving = true;
            try {
                const data = build();
                await apiJson(settingsPath, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
                if (!live()) return;
                Object.assign(config, data);
                view.refresh();
                showToast('LLM settings saved.', 'success');
                await onSave();
            } catch (err) {
                if (live()) showToast(err.message, 'error');
            } finally {
                saving = false;
            }
        }
        delegate(root, {
            addModel: form => save(() => {
                const { task, artifact, vcpus, ram } = form.elements;
                const selected = artifact.value;
                const model = selected && models[Number(selected)];
                if (!model) throw new Error('Select a reported model.');
                const rows = Object.hasOwn(config.llm_task_models, task.value) ? config.llm_task_models[task.value] : [];
                if (rows.some(row => row.model === model.name && row.digest === model.digest)) {
                    throw new Error('This model is already in the task order.');
                }
                return { llm_task_models: { ...config.llm_task_models, [task.value]: [...rows, {
                    model: model.name, digest: model.digest,
                    min_vcpus: Number(vcpus.value), min_ram_bytes: Number(ram.value),
                }] } };
            }),
            removeModel: button => save(() => {
                const { task, index } = button.dataset;
                const tasks = { ...config.llm_task_models };
                tasks[task] = tasks[task].filter((_, i) => i !== Number(index));
                if (!tasks[task].length) delete tasks[task];
                return { llm_task_models: tasks };
            }),
            repo: form => save(() => {
                const { repo, tenant, certificate, overflow } = form.elements;
                return { llm_ab_pr_repos: { ...config.llm_ab_pr_repos, [repo.value.trim()]: {
                    tenant: tenant.value, certificate: certificate.value.trim(), allow_public_cloud: overflow.checked,
                } } };
            }),
            removeRepo: button => save(() => ({
                llm_ab_pr_repos: Object.fromEntries(
                    Object.entries(config.llm_ab_pr_repos).filter(([repo]) => repo !== button.dataset.repo)),
            })),
            candidate: form => save(() => ({ llm_qualification_candidates: {
                ...config.llm_qualification_candidates,
                [form.elements.key.value]: { label: form.elements.label.value, worker: form.elements.worker.value },
            } })),
            removeCandidate: button => save(() => ({
                llm_qualification_candidates: Object.fromEntries(
                    Object.entries(config.llm_qualification_candidates).filter(([key]) => key !== button.dataset.key)),
            })),
            cloud: form => save(() => {
                const choice = form.elements.credential.value;
                if (!choice || !credentials[Number(choice)]) throw new Error('Select a Credential Vault credential.');
                const { bucket, name } = credentials[Number(choice)];
                return { llm_cloud_profiles: [...config.llm_cloud_profiles, {
                    url: form.elements.endpoint.value, model: form.elements.model.value,
                    token_limit_field: form.elements.tokenLimitField.value,
                    task: 'pr_summary', tenant: bucket, vault_credential: { bucket, name },
                }] };
            }),
            removeCloud: button => save(() => ({
                llm_cloud_profiles: config.llm_cloud_profiles.filter((_, i) => i !== Number(button.dataset.index)),
            })),
        });
        view.refresh();
    } catch (err) {
        if (live()) root.textContent = err.message;
    }
}

const th = 'px-3 py-1.5 text-left text-xs font-bold text-slate-500 whitespace-nowrap';
const td = 'px-3 py-1.5 text-xs text-slate-700 whitespace-nowrap';
const tdM = 'px-3 py-1.5 text-xs text-slate-700 font-mono whitespace-nowrap';

// Worker state badge.
function workerBadge(state) {
    const cls = state === 'ready'
        ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
        : state === 'busy'
            ? 'bg-amber-100 text-amber-800 border-amber-200'
            : state === 'error'
                ? 'bg-red-100 text-red-800 border-red-200'
                : 'bg-slate-100 text-slate-600 border-slate-200';
    return safeHtml`<span class="px-2 py-0.5 rounded text-xs font-bold border ${cls}">${state}</span>`;
}

// Model row: { name, digest } — show name, never digest in the body.
function modelRow(m) {
    return safeHtml`<tr><td class="${td}" title="${m.digest || ''}">${m.name || '—'}</td></tr>`;
}

// One worker row.
function workerRow(w) {
    const models = (w.models || []).map(modelRow);
    const cap = w.capabilities || {};
    return safeHtml`<tr class="border-b border-slate-100">
        <td class="${td} font-medium">${w.name || '—'}</td>
        <td class="${td}" title="${(w.issues || []).map(issue => issue.resolution).join(' ')}">${workerBadge(w.state)}
            ${w.version || ''} ${w.qualification ? '(Qualification only)' : ''}</td>
        <td class="${td} align-middle">${models.length ? safeHtml`<table class="text-xs">${models}</table>` : safeHtml`<span class="text-slate-400">—</span>`}</td>
        <td class="${td}">${cap.mode || '—'}</td>
        <td class="${td}">${cap.cpu_model || '—'}</td>
        <td class="${td}">${cap.vcpus ?? '—'}</td>
        <td class="${td}">${cap.ram_bytes == null ? '—' : `${(cap.ram_bytes / (1024 ** 3)).toFixed(1)} GiB`}</td>
        <td class="${td}">${cap.arch || '—'}</td>
    </tr>`;
}

// Job state badge.
function jobBadge(state) {
    const cls = state === 'passed'
        ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
        : state === 'failed'
            ? 'bg-red-100 text-red-800 border-red-200'
            : state === 'running'
                ? 'bg-blue-100 text-blue-800 border-blue-200'
                : 'bg-slate-100 text-slate-600 border-slate-200';
    return safeHtml`<span class="px-2 py-0.5 rounded text-xs font-bold border ${cls}">${state}</span>`;
}

// One job row.
function jobRow(j) {
    return safeHtml`<tr class="border-b border-slate-100">
        <td class="${td}">${j.kind || '—'}</td>
        <td class="${td}">${jobBadge(j.state)}</td>
        <td class="${td}">${j.model || j.candidate || '—'} ${j.version || ''} (${j.tier})</td>
        <td class="${tdM}">${j.elapsed_s != null ? (j.elapsed_s < 60 ? Math.round(j.elapsed_s * 10) / 10 + 's' : Math.round(j.elapsed_s / 60) + 'm') : '—'}</td>
        <td class="${td} text-slate-500" title="${j.resolution || (j.issues || []).map(issue => issue.resolution).join(' ')}">
            ${j.code || ''}
            ${(j.fixture_deltas || []).map((delta, i) => safeHtml`<div>
                ${delta.fixture}: ${j.baseline.fixtures[i].passed ? 'pass' : 'fail'}
                to ${j.fixtures[i].passed ? 'pass' : 'fail'}
                ${delta.elapsed_s_delta == null ? '' : `(${delta.elapsed_s_delta} s vs baseline)`}
            </div>`)}
        </td>
    </tr>`;
}

// One metrics row.
function metricsRow(m) {
    return safeHtml`<tr class="border-b border-slate-100">
        <td class="${td} font-medium" title="${m.digest || ''}">${m.model || '—'} ${m.version || ''}</td>
        <td class="${td}">${m.tier || '—'} / ${m.kind}</td>
        <td class="${tdM}">${m.completed != null ? m.completed : '—'}</td>
        <td class="${tdM}">${m.failed != null ? m.failed : '—'}</td>
        <td class="${tdM}">${m.no_capacity}</td>
        <td class="${tdM}">${m.mean_elapsed_s != null ? (Math.round(m.mean_elapsed_s * 10) / 10 + 's') : '—'}</td>
    </tr>`;
}

// ── Render helpers ──────────────────────────────────────────────────────────

// Surface action feedback without replacing the data snapshot.
function renderStatus(status) {
    if (!status.type) return '';
    const cls = status.type === 'error'
        ? 'bg-red-50 text-red-700 border-red-200'
        : 'bg-emerald-50 text-emerald-700 border-emerald-200';
    return safeHtml`<div class="mb-3 p-2 rounded text-xs border ${cls}">${status.message}</div>`;
}

// Show registered workers even when no runtime is available.
function renderWorkersSection(workers) {
    if (!workers.length) {
        return safeHtml`<div class="mb-4">
            <h3 class="text-sm font-bold text-slate-600 mb-2">Workers</h3>
            <div class="border border-slate-200 rounded-md overflow-x-auto">
                <table class="w-full text-left">
                    <thead><tr class="border-b border-slate-200">
                        <th class="${th}">Name</th><th class="${th}">State</th><th class="${th}">Models</th><th class="${th}">Mode</th><th class="${th}">CPU</th><th class="${th}">VCPUs</th><th class="${th}">RAM</th><th class="${th}">Arch</th>
                    </tr></thead><tbody><tr><td colspan="8" class="${td} text-slate-400 italic">No workers.</td></tr></tbody>
                </table>
            </div>
        </div>`;
    }
    return safeHtml`<div class="mb-4">
        <h3 class="text-sm font-bold text-slate-600 mb-2">Workers</h3>
        <div class="border border-slate-200 rounded-md overflow-x-auto">
            <table class="w-full text-left">
                <thead><tr class="border-b border-slate-200">
                    <th class="${th}">Name</th><th class="${th}">State</th><th class="${th}">Models</th><th class="${th}">Mode</th><th class="${th}">CPU</th><th class="${th}">VCPUs</th><th class="${th}">RAM</th><th class="${th}">Arch</th>
                </tr></thead><tbody>${workers.map(workerRow)}</tbody>
            </table>
        </div>
    </div>`;
}

// Keep active jobs visible alongside recent terminal outcomes.
function renderJobsSection(jobs) {
    if (!jobs.length) {
        return safeHtml`<div class="mb-4">
            <h3 class="text-sm font-bold text-slate-600 mb-2">Jobs</h3>
            <div class="border border-slate-200 rounded-md overflow-x-auto">
                <table class="w-full text-left">
                    <thead><tr class="border-b border-slate-200">
                        <th class="${th}">Kind</th><th class="${th}">State</th><th class="${th}">Model</th><th class="${th}">Elapsed</th><th class="${th}">Code</th>
                    </tr></thead><tbody><tr><td colspan="5" class="${td} text-slate-400 italic">No jobs.</td></tr></tbody>
                </table>
            </div>
        </div>`;
    }
    return safeHtml`<div class="mb-4">
        <h3 class="text-sm font-bold text-slate-600 mb-2">Jobs</h3>
        <div class="border border-slate-200 rounded-md overflow-x-auto">
            <table class="w-full text-left">
                <thead><tr class="border-b border-slate-200">
                    <th class="${th}">Kind</th><th class="${th}">State</th><th class="${th}">Model</th><th class="${th}">Elapsed</th><th class="${th}">Code</th>
                </tr></thead><tbody>${jobs.map(jobRow)}</tbody>
            </table>
        </div>
    </div>`;
}

// Separate availability counts from completed inference timings.
function renderMetricsSection(metrics) {
    if (!metrics.length) {
        return safeHtml`<div class="mb-4">
            <h3 class="text-sm font-bold text-slate-600 mb-2">Metrics</h3>
            <div class="border border-slate-200 rounded-md overflow-x-auto">
                <table class="w-full text-left">
                    <thead><tr class="border-b border-slate-200">
                        <th class="${th}">Model</th><th class="${th}">Tier / Kind</th><th class="${th}">Passed</th><th class="${th}">Failed</th><th class="${th}">No capacity</th><th class="${th}">Mean Elapsed</th>
                    </tr></thead><tbody><tr><td colspan="6" class="${td} text-slate-400 italic">No metrics.</td></tr></tbody>
                </table>
            </div>
        </div>`;
    }
    return safeHtml`<div class="mb-4">
        <h3 class="text-sm font-bold text-slate-600 mb-2">Metrics</h3>
        <div class="border border-slate-200 rounded-md overflow-x-auto">
            <table class="w-full text-left">
                <thead><tr class="border-b border-slate-200">
                    <th class="${th}">Model</th><th class="${th}">Tier / Kind</th><th class="${th}">Passed</th><th class="${th}">Failed</th><th class="${th}">No capacity</th><th class="${th}">Mean Elapsed</th>
                </tr></thead><tbody>${metrics.map(metricsRow)}</tbody>
            </table>
        </div>
    </div>`;
}

// Display permitted candidate profiles with the worker name, not its ID.
function renderCandidatesSection(candidates) {
    const options = candidates.map(c =>
        safeHtml`<option value="${c.key}">${c.label} (${c.worker})</option>`
    );
    return safeHtml`<div class="mb-4 flex items-center gap-2 flex-wrap">
        <label for="llm-candidate-select" class="text-xs font-bold text-slate-600">Qualification candidate:</label>
        <select id="llm-candidate-select" class="text-xs border border-slate-300 rounded px-2 py-1">${options}</select>
        <button data-action="qualify" type="button" class="hpe-btn hpe-btn-primary">Qualify</button>
    </div>`;
}

// ── Public API ───────────────────────────────────────────────────────────────

// Ignore stale requests if a second load reuses the same root element.
const visits = new WeakMap();
// Keep the dashboard and settings form on independent render lifecycles.
async function renderLlmDashboard(container) {
    if (!container) return;
    const visit = {};
    visits.set(container, visit);
    const isCurrent = () => visits.get(container) === visit && currentView === 'llm' && container.isConnected;

    const state = {
        workers: [],
        jobs: [],
        metrics: [],
        candidates: [],
    };
    let status = { type: '', message: '' };
    let loading = false;
    container.innerHTML = safeHtml`<div data-llm-snapshot></div><div data-llm-settings class="mt-4"></div>`;
    const snapshot = container.querySelector('[data-llm-snapshot]');
    const settings = container.querySelector('[data-llm-settings]');

    // Refresh only the snapshot so unsaved settings survive.
    const view = createView({ el: snapshot, state, render: () => safeHtml`
            <div class="space-y-4">
                ${renderStatus(status)}
                <div class="flex items-center justify-between mb-2">
                    <h2 class="text-base font-bold text-slate-700">LLM Dashboard</h2>
                    <div class="flex items-center gap-2">
                        <a id="llm-download-json" href="/api/llm/admin/dashboard" class="text-xs text-primary-text hover:underline" download>Download JSON</a>
                        <button data-action="refresh" type="button" class="hpe-btn hpe-btn-secondary">Refresh</button>
                        <button data-action="settings" type="button" class="hpe-btn hpe-btn-secondary">Settings</button>
                    </div>
                </div>
                ${renderWorkersSection(state.workers)}
                ${renderJobsSection(state.jobs)}
                ${renderMetricsSection(state.metrics)}
                ${state.candidates.length ? renderCandidatesSection(state.candidates) : ''}
            </div>` });
    // Bind once; morphing keeps delegated listeners on the snapshot root.
        delegate(snapshot, {
            qualify: async (el) => {
                if (loading) return;
                const sel = snapshot.querySelector('#llm-candidate-select');
                const key = sel?.value;
                if (!key) { showToast('Select a qualification candidate.', 'error'); return; }
                el.disabled = true;
                loading = true;
                try {
                    await apiJson('/api/llm/admin/qualify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ candidate: key }),
                    });
                    status = { type: 'success', message: 'Qualification scheduled. Refresh to check progress.' };
                } catch (e) {
                    status = { type: 'error', message: e.message || String(e) };
                } finally {
                    loading = false;
                }
                if (!isCurrent()) return;
                el.disabled = false;
                showToast(status.message, status.type);
                await load();
            },
            refresh: () => { load(); },
            settings: () => {
                if (!settings.hasChildNodes()) openSettings(settings, isCurrent, load, state.workers);
                else settings.scrollIntoView({ block: 'nearest' });
            },
        });

    // Keep the cached snapshot visible while refreshing.
    async function load(feedback = { type: '', message: '' }) {
        if (loading) return;
        loading = true;
        status = feedback;
        try {
            const data = await apiJson('/api/llm/admin/dashboard');
            if (!isCurrent()) return;
            state.workers = data.workers || [];
            state.jobs = data.jobs || [];
            state.metrics = data.metrics || [];
            state.candidates = data.candidates || [];
        } catch (e) {
            if (!isCurrent()) return;
            status = { type: 'error', message: 'Dashboard load failed: ' + (e.message || e) };
        } finally {
            loading = false;
        }
        if (isCurrent()) view.refresh();
    }

    // Initial load.
    view.refresh();
    await load();
}

lmViews.llm = renderLlmDashboard;
