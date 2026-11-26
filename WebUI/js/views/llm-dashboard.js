// LLM → Dashboard: a simple global-admin view.
//   Workers: one card per worker with its status badge (Ready / Busy / Provisioning / Offline / Needs attention),
//            hardware, and a badge per model (serving, passed, failed) plus any issue codes.
//   Jobs:    recent jobs with Refresh and "Clear finished jobs".
//   Metrics: the compact per-model metrics table, kept for performance evaluation.
// An ES module: the main nav opens it through lmViews.llm(container).
//   AppBuilder work: which tenant and tasks may use the pool (the llm_ab_work setting).
// Fetches GET /api/llm/admin/dashboard, POSTs /api/llm/admin/jobs/clear, and reads and saves
// /api/llm/admin/settings (llm_ab_work only) with the tenant list from /setup/tenants.
import { safeHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

// Read JSON from a hub route and surface the server's validation message.
async function apiJson(path, init) {
    const response = await fetch(path, init);
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
}

const th = 'px-4 py-2 text-left font-medium whitespace-nowrap';
const td = 'px-4 py-2 text-xs text-slate-700 whitespace-nowrap';
const tdM = 'px-4 py-2 text-xs text-slate-700 font-mono whitespace-nowrap';
const ROW = 'border-b border-slate-100 hover:bg-slate-50';
const BADGE = 'px-2 py-0.5 rounded-full text-xs font-bold border';

const GREEN = 'bg-emerald-100 text-emerald-800 border-emerald-200';
const AMBER = 'bg-amber-100 text-amber-800 border-amber-200';
const RED = 'bg-red-100 text-red-800 border-red-200';
const BLUE = 'bg-blue-100 text-blue-800 border-blue-200';
const GREY = 'bg-slate-100 text-slate-600 border-slate-200';

// Map the API worker state to the label and colour shown in the badge.
// An unknown state shows its raw text so a new backend state is never hidden.
function workerStatus(w) {
    switch (w.state) {
    case 'ready': return { label: 'Ready', cls: GREEN };
    case 'busy': return { label: 'Busy', cls: AMBER };
    case 'provisioning': return { label: w.detail ? `Provisioning: ${w.detail}` : 'Provisioning', cls: BLUE };
    case 'disconnected':
    case 'no_fresh_report': return { label: 'Offline', cls: GREY };
    case 'attention':
    case 'unavailable': return { label: 'Needs attention', cls: RED };
    case 'pending': return { label: 'Pending approval', cls: GREY };
    case 'draining': return { label: 'Draining', cls: GREY };
    default: return { label: String(w.state ?? '—'), cls: GREY };
    }
}

// Build the tooltip text: CPU, RAM, models and, when present, issue codes.
function workerTooltip(w) {
    const cap = w.capabilities || {};
    const ram = cap.ram_bytes == null ? '—' : `${(cap.ram_bytes / (1024 ** 3)).toFixed(1)} GiB`;
    const models = (w.models || []).map(m => m.name).filter(Boolean);
    const lines = [
        `CPU: ${cap.cpu_model || '—'} (${cap.vcpus ?? '—'} vCPUs${cap.arch ? `, ${cap.arch}` : ''})`,
        `RAM: ${ram}`,
        `Models: ${models.length ? models.join(', ') : '—'}`,
    ];
    const codes = (w.issues || []).map(issue => issue.code).filter(Boolean);
    if (codes.length) lines.push(`Issues: ${codes.join(', ')}`);
    if (w.detail) lines.push(w.detail);
    if (w.qualification) lines.push('Qualification only');
    return lines.join('\n');
}

// Models cell: one chip per catalog model with an explicit state from the worker/hub,
// never inferred from job history (clearing finished jobs must not change it).
function modelChips(w) {
    const states = {
        serving: [GREEN, 'Serving', ''],
        preparing: [BLUE, 'Preparing', ' · preparing'],
        failed: [RED, 'Failed', ' · failed'],
        too_small: [GREY, 'Worker too small for this model', ' · too small'],
        not_loaded: [GREY, 'Not loaded', ' · not loaded'],
    };
    const chips = (w.catalog || []).map(c => {
        const [cls, tip, suffix] = states[c.state] || [GREY, String(c.state), ''];
        const title = c.state === 'failed' && c.code ? `Failed: ${c.code}` : tip;
        return safeHtml`<span class="${BADGE} ${cls}" title="${title}">${c.model}${suffix}</span>`;
    });
    return chips.length ? chips : '—';
}

// One worker card: name and status badge, hardware line, then one row per model.
function workerCard(w) {
    const { label, cls } = workerStatus(w);
    const cap = w.capabilities || {};
    const ram = cap.ram_bytes == null ? '—' : `${(cap.ram_bytes / (1024 ** 3)).toFixed(1)} GiB`;
    const hardware = `${cap.cpu_model || '—'} · ${cap.vcpus ?? '—'} vCPUs · ${ram}${cap.arch ? ` · ${cap.arch}` : ''}`;
    const codes = (w.issues || []).map(issue => issue.code).filter(Boolean);
    const notes = [...codes, w.detail].filter(Boolean).join(' — ');
    return safeHtml`<div class="border border-slate-200 rounded-lg p-4 space-y-2 bg-white" title="${workerTooltip(w)}">
        <div class="flex items-center justify-between gap-2">
            <span class="text-sm font-bold text-slate-700">${w.name || '—'}</span>
            <span class="${BADGE} ${cls}">${label}</span>
        </div>
        <div class="text-xs text-slate-500">${hardware}</div>
        ${w.qualification ? safeHtml`<div class="text-xs text-slate-500">Qualification only</div>` : ''}
        <div class="text-xs font-bold text-slate-500 pt-1">Models</div>
        <div class="flex flex-wrap gap-1">${modelChips(w)}</div>
        ${notes ? safeHtml`<div class="text-xs text-red-700">${notes}</div>` : ''}
    </div>`;
}

// Job state badge; "queued" and "no_capacity" get readable labels.
function jobBadge(state) {
    const labels = { queued: 'Queued', running: 'Running', passed: 'Passed', failed: 'Failed', cancelled: 'Cancelled', no_capacity: 'No capacity' };
    const colours = { passed: GREEN, failed: RED, running: BLUE, queued: AMBER };
    return safeHtml`<span class="${BADGE} ${colours[state] || GREY}">${labels[state] || String(state ?? '—')}</span>`;
}

// One job row; the Kind cell appears only when the list mixes kinds.
function jobRow(j, showKind) {
    return safeHtml`<tr class="${ROW}">
        ${showKind ? safeHtml`<td class="${td}">${j.kind || '—'}</td>` : ''}
        <td class="${td}">${jobBadge(j.state)}</td>
        <td class="${td}">${j.model || j.candidate || '—'} ${j.version || ''} (${j.tier})${j.worker && j.kind === 'inference' ? safeHtml`<div class="text-slate-500">on ${j.worker}</div>` : ''}</td>
        <td class="${tdM}">${j.elapsed_s != null ? (j.elapsed_s < 60 ? Math.round(j.elapsed_s * 10) / 10 + 's' : Math.round(j.elapsed_s / 60) + 'm') : '—'}</td>
        <td class="${td} text-slate-500" title="${j.resolution || (j.issues || []).map(issue => issue.resolution).join(' ')}">
            ${j.code || ''}
            ${j.phase ? safeHtml`<div>Phase: ${j.phase}</div>` : ''}
            ${j.mode === 'bootstrap' ? safeHtml`<div>Smoke test only; not certified.</div>` : ''}
            ${j.options ? safeHtml`<div>Context ${j.options.num_ctx ?? 'default'}; temperature ${j.options.temperature ?? 'default'};
                    top-p ${j.options.top_p ?? 'default'}; top-k ${j.options.top_k ?? 'default'};
                    repeat penalty ${j.options.repeat_penalty ?? 'default'}</div>` : ''}
            ${j.mode === 'bootstrap' ? (j.fixtures || []).map(fixture => safeHtml`<div>${fixture.fixture}:
                    ${fixture.passed ? 'pass' : 'fail'} (${fixture.elapsed_s ?? '—'} s${fixture.done_reason && !fixture.passed ? `, ${fixture.done_reason}, ${fixture.eval_count ?? '?'} tokens${fixture.shape ? `, ${fixture.shape}` : ''}` : ''})</div>`) : ''}
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
    return safeHtml`<tr class="${ROW}">
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

// Wrap a table's header cells and body rows in the shared bordered table markup.
function renderTable(headers, rows, emptyText) {
    const body = rows.length
        ? rows
        : safeHtml`<tr><td colspan="${headers.length}" class="${td} text-slate-400 italic">${emptyText}</td></tr>`;
    return safeHtml`<div class="border border-slate-200 rounded-lg overflow-x-auto">
        <table class="w-full text-left">
            <thead class="bg-slate-50 text-xs text-slate-500"><tr class="border-b border-slate-200">${headers.map(h => safeHtml`<th class="${th}">${h}</th>`)}</tr></thead>
            <tbody>${body}</tbody>
        </table>
    </div>`;
}

// Workers: one card per worker, in a responsive grid.
function renderWorkersSection(workers) {
    const cards = workers.length
        ? workers.map(workerCard)
        : safeHtml`<p class="text-sm text-slate-500 italic">No workers.</p>`;
    return safeHtml`<div class="hpe-card rounded-lg p-5 shadow-sm space-y-3">
        <h3 class="text-sm font-bold text-slate-500">Workers</h3>
        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">${cards}</div>
    </div>`;
}

// Jobs: active rows next to recent outcomes, with Refresh and Clear finished jobs.
function renderJobsSection(jobs) {
    // Offer the clear control only when a row is terminal; running and queued rows are never cleared.
    const finished = jobs.some(job => job.state !== 'running' && job.state !== 'queued');
    const clear = safeHtml`<button data-action="clearJobs" type="button" class="bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full px-3 py-1.5 text-xs font-bold${finished ? '' : ' opacity-50 cursor-not-allowed'}"${finished ? '' : safeHtml` disabled`}>Clear finished jobs</button>`;
    // A Kind column that says the same thing on every row carries no information.
    const showKind = new Set(jobs.map(job => job.kind)).size > 1;
    const headers = [...(showKind ? ['Kind'] : []), 'State', 'Model', 'Elapsed', 'Code'];
    return safeHtml`<div class="hpe-card rounded-lg p-5 shadow-sm space-y-3">
        <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-slate-600">Jobs</h3>
            <div class="flex items-center gap-2">
                <button data-action="refresh" type="button" class="bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full px-3 py-1.5 text-xs font-bold">Refresh</button>
                ${clear}
            </div>
        </div>
        ${renderTable(headers, jobs.map(job => jobRow(job, showKind)), 'No jobs.')}
    </div>`;
}

// Metrics: availability counts and completed inference timings per model.
function renderMetricsSection(metrics) {
    const headers = ['Model', 'Tier / Kind', 'Passed', 'Failed', 'No capacity', 'Mean Elapsed'];
    return safeHtml`<div class="hpe-card rounded-lg p-5 shadow-sm space-y-3">
        <h3 class="text-sm font-bold text-slate-500">Metrics</h3>
        ${renderTable(headers, metrics.map(metricsRow), 'No metrics.')}
    </div>`;
}

// Tasks AppBuilder can send to the pool, with what each one runs on.
const AB_TASKS = [
    ['scout', 'Scout: code search and triage (Qwen 3.8)'],
    ['coding', 'Coding: builds and fixes (Qwen 3.6)'],
    ['summary', 'Summary: PR and log summaries (Gemma 4)'],
    ['review', 'Review: first-pass reviewer (Qwen 3.8)'],
    ['review_deep', 'Review deep: second-pass reviewer (DeepSeek R1)'],
];
const INPUT = 'w-full border border-slate-300 rounded px-2 py-1.5 text-sm';

// AppBuilder work: the allowlist the hub applies to AppBuilder's LLM_COMPLETE requests.
function renderAbWorkSection(ab, tenants) {
    // Keep a saved task that is not in the known list so saving never drops it.
    const tasks = [...AB_TASKS, ...ab.tasks.filter(t => !AB_TASKS.some(([k]) => k === t)).map(t => [t, t])];
    const ready = !!ab.tenant;
    return safeHtml`<div class="hpe-card rounded-lg p-5 shadow-sm space-y-3">
        <h3 class="text-sm font-bold text-slate-500">AppBuilder work</h3>
        <p class="text-xs text-slate-500">Lets AppBuilder run the selected tasks on the local models. The AppBuilder certificate is the one marked in the Certificates (LE) module. A task that is not ticked is refused and AppBuilder uses its own providers.</p>
        <label class="block text-xs font-bold text-slate-500">Tenant
            <select data-action="abTenant" class="${INPUT}" title="Tenant the work is scoped to; the shared tenant uses the shared workers">
                <option value=""${ab.tenant ? '' : ' selected'}>Select a tenant</option>
                ${tenants.map(t => safeHtml`<option value="${t.id}"${t.id === ab.tenant ? ' selected' : ''}>${t.name}</option>`)}
            </select></label>
        <div class="space-y-1">${tasks.map(([key, label]) => safeHtml`
            <label class="flex items-center gap-2 text-xs text-slate-700"><input type="checkbox" data-action="abTask" value="${key}"${ab.tasks.includes(key) ? ' checked' : ''}>${label}</label>`)}</div>
        <div class="flex justify-end"><button data-action="saveAbWork" type="button" class="bg-navy text-white rounded-full px-4 py-1.5 text-xs font-bold${ready ? '' : ' opacity-50 cursor-not-allowed'}"${ready ? '' : safeHtml` disabled`} title="Save the AppBuilder work rule">Save</button></div>
    </div>`;
}

// ── Public API ───────────────────────────────────────────────────────────────

// Ignore stale requests if a second load reuses the same root element.
const visits = new WeakMap();

// Render the dashboard into the container and load the first snapshot.
async function renderLlmDashboard(container) {
    if (!container) return;
    const visit = {};
    visits.set(container, visit);
    // Stale-render guard: ignore async results once the user navigated away.
    const isCurrent = () => visits.get(container) === visit && currentView === 'llm' && container.isConnected;

    const state = { workers: [], jobs: [], metrics: [], tenants: [], ab: { tenant: '', tasks: [] } };
    let status = { type: '', message: '' };
    let loading = false;

    const view = createView({ el: container, state, render: () => safeHtml`
            <div class="space-y-4">
                ${renderStatus(status)}
                <h2 class="text-lg font-bold text-navy">LLM Dashboard</h2>
                ${renderWorkersSection(state.workers)}
                ${renderJobsSection(state.jobs)}
                ${renderMetricsSection(state.metrics)}
                ${renderAbWorkSection(state.ab, state.tenants)}
            </div>` });
    // Bind once; morphing keeps delegated listeners on the container.
    delegate(container, {
        // Clear finished history on the hub, then show a toast and reload the snapshot.
        clearJobs: async (el) => {
            if (loading) return;
            el.disabled = true;
            loading = true;
            try {
                const data = await apiJson('/api/llm/admin/jobs/clear', { method: 'POST' });
                status = { type: 'success', message: `Cleared ${data.removed} finished job${data.removed === 1 ? '' : 's'}.` };
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
        // Form edits stay in state so a refresh keeps what was typed.
        abTenant: (el) => { state.ab.tenant = el.value; view.refresh(); },
        abTask: (el) => {
            const tasks = state.ab.tasks.filter(t => t !== el.value);
            state.ab.tasks = el.checked ? [...tasks, el.value] : tasks;
        },
        // Save only llm_ab_work; the hub validates the tenant, certificate and task names.
        saveAbWork: async (el) => {
            el.disabled = true;
            try {
                await apiJson('/api/llm/admin/settings', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ llm_ab_work: {
                        tenant: state.ab.tenant, tasks: state.ab.tasks } }),
                });
                if (isCurrent()) showToast('AppBuilder work saved.', 'success');
            } catch (e) {
                if (isCurrent()) showToast(e.message || String(e), 'error');
            }
            if (isCurrent()) el.disabled = false;
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
        } catch (e) {
            if (!isCurrent()) return;
            status = { type: 'error', message: 'Dashboard load failed: ' + (e.message || e) };
        } finally {
            loading = false;
        }
        if (isCurrent()) view.refresh();
    }

    // Load the saved AppBuilder rule and the tenant choices once; config pages never auto-refresh.
    async function loadAbWork() {
        try {
            const [settings, tenants] = await Promise.all([
                apiJson('/api/llm/admin/settings'), apiJson('/setup/tenants', { credentials: 'same-origin' })]);
            if (!isCurrent()) return;
            const rule = settings.llm_ab_work || {};
            state.ab = { tenant: rule.tenant || '',
                         tasks: Array.isArray(rule.tasks) ? rule.tasks : [] };
            state.tenants = (tenants.tenants || []).filter(t => !t.is_group);
            view.refresh();
        } catch (e) {
            if (isCurrent()) showToast('AppBuilder settings load failed: ' + (e.message || e), 'error');
        }
    }

    // Initial load.
    view.refresh();
    await Promise.all([load(), loadAbWork()]);
}

lmViews.llm = renderLlmDashboard;
