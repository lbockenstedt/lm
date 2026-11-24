// LLM → Dashboard: a simple global-admin view with three tables.
//   Workers: name plus a status badge (Ready / Busy / Provisioning / Offline / Needs attention);
//            hover the badge for CPU, RAM, models and any issue codes.
//   Jobs:    recent jobs with Refresh and "Clear finished jobs".
//   Metrics: the compact per-model metrics table, kept for performance evaluation.
// An ES module: the main nav opens it through lmViews.llm(container).
// Fetches GET /api/llm/admin/dashboard and POSTs /api/llm/admin/jobs/clear.
import { safeHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

// Read JSON from a hub route and surface the server's validation message.
async function apiJson(path, init) {
    const response = await fetch(path, init);
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
}

const th = 'px-3 py-1.5 text-left text-xs font-bold text-slate-500 whitespace-nowrap';
const td = 'px-3 py-1.5 text-xs text-slate-700 whitespace-nowrap';
const tdM = 'px-3 py-1.5 text-xs text-slate-700 font-mono whitespace-nowrap';

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
    if (w.qualification) lines.push('Qualification only');
    return lines.join('\n');
}

// One worker row: name and status badge with the details in its tooltip.
function workerRow(w) {
    const { label, cls } = workerStatus(w);
    return safeHtml`<tr class="border-b border-slate-100">
        <td class="${td} font-medium">${w.name || '—'}</td>
        <td class="${td}" title="${workerTooltip(w)}"><span class="px-2 py-0.5 rounded text-xs font-bold border ${cls}">${label}</span></td>
    </tr>`;
}

// Job state badge; "queued" and "no_capacity" get readable labels.
function jobBadge(state) {
    const labels = { queued: 'Queued', running: 'Running', passed: 'Passed', failed: 'Failed', cancelled: 'Cancelled', no_capacity: 'No capacity' };
    const colours = { passed: GREEN, failed: RED, running: BLUE, queued: AMBER };
    return safeHtml`<span class="px-2 py-0.5 rounded text-xs font-bold border ${colours[state] || GREY}">${labels[state] || String(state ?? '—')}</span>`;
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
            ${j.phase ? safeHtml`<div>Phase: ${j.phase}</div>` : ''}
            ${j.mode === 'bootstrap' ? safeHtml`<div>Smoke test only; not certified.</div>` : ''}
            ${j.options ? safeHtml`<div>Context ${j.options.num_ctx ?? 'default'}; temperature ${j.options.temperature ?? 'default'};
                    top-p ${j.options.top_p ?? 'default'}; top-k ${j.options.top_k ?? 'default'};
                    repeat penalty ${j.options.repeat_penalty ?? 'default'}</div>` : ''}
            ${j.mode === 'bootstrap' ? (j.fixtures || []).map(fixture => safeHtml`<div>${fixture.fixture}:
                    ${fixture.passed ? 'pass' : 'fail'} (${fixture.elapsed_s ?? '—'} s)</div>`) : ''}
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

// Wrap a table's header cells and body rows in the shared bordered table markup.
function renderTable(headers, rows, emptyText) {
    const body = rows.length
        ? rows
        : safeHtml`<tr><td colspan="${headers.length}" class="${td} text-slate-400 italic">${emptyText}</td></tr>`;
    return safeHtml`<div class="border border-slate-200 rounded-md overflow-x-auto">
        <table class="w-full text-left">
            <thead><tr class="border-b border-slate-200">${headers.map(h => safeHtml`<th class="${th}">${h}</th>`)}</tr></thead>
            <tbody>${body}</tbody>
        </table>
    </div>`;
}

// Workers: name and status only; details live in the tooltip.
function renderWorkersSection(workers) {
    return safeHtml`<div class="mb-4">
        <h3 class="text-sm font-bold text-slate-600 mb-2">Workers</h3>
        ${renderTable(['Name', 'Status'], workers.map(workerRow), 'No workers.')}
    </div>`;
}

// Jobs: active rows next to recent outcomes, with Refresh and Clear finished jobs.
function renderJobsSection(jobs) {
    // Offer the clear control only when a row is terminal; running and queued rows are never cleared.
    const finished = jobs.some(job => job.state !== 'running' && job.state !== 'queued');
    const clear = safeHtml`<button data-action="clearJobs" type="button" class="hpe-btn hpe-btn-secondary"${finished ? '' : safeHtml` disabled`}>Clear finished jobs</button>`;
    const headers = ['Kind', 'State', 'Model', 'Elapsed', 'Code'];
    return safeHtml`<div class="mb-4">
        <div class="flex items-center justify-between mb-2">
            <h3 class="text-sm font-bold text-slate-600">Jobs</h3>
            <div class="flex items-center gap-2">
                <button data-action="refresh" type="button" class="hpe-btn hpe-btn-secondary">Refresh</button>
                ${clear}
            </div>
        </div>
        ${renderTable(headers, jobs.map(jobRow), 'No jobs.')}
    </div>`;
}

// Metrics: availability counts and completed inference timings per model.
function renderMetricsSection(metrics) {
    const headers = ['Model', 'Tier / Kind', 'Passed', 'Failed', 'No capacity', 'Mean Elapsed'];
    return safeHtml`<div class="mb-4">
        <h3 class="text-sm font-bold text-slate-600 mb-2">Metrics</h3>
        ${renderTable(headers, metrics.map(metricsRow), 'No metrics.')}
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

    const state = { workers: [], jobs: [], metrics: [] };
    let status = { type: '', message: '' };
    let loading = false;

    const view = createView({ el: container, state, render: () => safeHtml`
            <div class="space-y-4">
                ${renderStatus(status)}
                <h2 class="text-base font-bold text-slate-700">LLM Dashboard</h2>
                ${renderWorkersSection(state.workers)}
                ${renderJobsSection(state.jobs)}
                ${renderMetricsSection(state.metrics)}
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

    // Initial load.
    view.refresh();
    await load();
}

lmViews.llm = renderLlmDashboard;
