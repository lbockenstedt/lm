// LLM → Dashboard: global-admin view of workers, jobs, and metrics.
// An ES module: the main nav opens it through lmViews.llm(container).
// Fetches GET /api/llm/admin/dashboard and POST /api/llm/admin/qualify.
import { safeHtml } from '../core/safe-html.js';
import { delegate } from '../core/view.js';

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
    return safeHtml`<tr class="border-b border-slate-100">
        <td class="${td} font-medium">${w.name || '—'}</td>
        <td class="${td}" title="${(w.issues || []).map(issue => issue.resolution).join(' ')}">${workerBadge(w.state)}
            ${w.version || ''} ${w.qualification ? '(Qualification only)' : ''}</td>
        <td class="${td} align-middle">${models.length ? safeHtml`<table class="text-xs">${models}</table>` : safeHtml`<span class="text-slate-400">—</span>`}</td>
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

function renderStatus(status) {
    if (!status.type) return '';
    const cls = status.type === 'error'
        ? 'bg-red-50 text-red-700 border-red-200'
        : 'bg-emerald-50 text-emerald-700 border-emerald-200';
    return safeHtml`<div class="mb-3 p-2 rounded text-xs border ${cls}">${status.message}</div>`;
}

function renderWorkersSection(workers) {
    if (!workers.length) {
        return safeHtml`<div class="mb-4">
            <h3 class="text-sm font-bold text-slate-600 mb-2">Workers</h3>
            <div class="border border-slate-200 rounded-md overflow-x-auto">
                <table class="w-full text-left">
                    <thead><tr class="border-b border-slate-200">
                        <th class="${th}">Name</th><th class="${th}">State</th><th class="${th}">Models</th>
                    </tr></thead><tbody><tr><td colspan="3" class="${td} text-slate-400 italic">No workers.</td></tr></tbody>
                </table>
            </div>
        </div>`;
    }
    return safeHtml`<div class="mb-4">
        <h3 class="text-sm font-bold text-slate-600 mb-2">Workers</h3>
        <div class="border border-slate-200 rounded-md overflow-x-auto">
            <table class="w-full text-left">
                <thead><tr class="border-b border-slate-200">
                    <th class="${th}">Name</th><th class="${th}">State</th><th class="${th}">Models</th>
                </tr></thead><tbody>${workers.map(workerRow)}</tbody>
            </table>
        </div>
    </div>`;
}

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

    // Reject HTTP errors before consuming the snapshot.
    async function apiJson(path, init) {
        const response = await fetch(path, init);
        const body = await response.json();
        if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
        return body;
    }

    function render() {
        if (!isCurrent()) return;
        container.innerHTML = safeHtml`
            <div class="space-y-4">
                ${renderStatus(status)}
                <div class="flex items-center justify-between mb-2">
                    <h2 class="text-base font-bold text-slate-700">LLM Dashboard</h2>
                    <div class="flex items-center gap-2">
                        <a id="llm-download-json" href="/api/llm/admin/dashboard" class="text-xs text-primary-text hover:underline" download>Download JSON</a>
                        <button data-action="refresh" type="button" class="hpe-btn hpe-btn-secondary">Refresh</button>
                    </div>
                </div>
                ${renderWorkersSection(state.workers)}
                ${renderJobsSection(state.jobs)}
                ${renderMetricsSection(state.metrics)}
                ${state.candidates.length ? renderCandidatesSection(state.candidates) : ''}
            </div>`;
        delegate(container, {
            qualify: async (el) => {
                if (loading) return;
                const sel = container.querySelector('#llm-candidate-select');
                const key = sel?.value;
                if (!key) { status = { type: 'error', message: 'Select a worker to qualify.' }; render(); return; }
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
                if (isCurrent()) await load(status);
            },
            refresh: () => { load(); },
        });
    }

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
        if (isCurrent()) render();
    }

    // Initial load.
    render();
    await load();
}

lmViews.llm = renderLlmDashboard;
