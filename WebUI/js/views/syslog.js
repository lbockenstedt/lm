// Syslog page (left nav "Syslog", shown once the tenant has a `logging` spoke).
// An ES module: classic code opens it through lmViews.syslog(container, tab)
// from VIEW_LOADERS / initView in main.js; nothing here is a window global.
// Tabs (VIEW_SUBMENUS.syslog):
//   Search                POST /api/syslog/query (local store or the archive)
//   Live Tail             POST /api/syslog/query with after_ts every 3 s
//   Sources               GET  /api/syslog/overview -> sources
//   Drop Rules            GET/PUT /api/syslog/settings, POST /api/syslog/drop-preview
//   Collectors & Archive  GET  /api/syslog/overview (hub cache)
//   Settings              GET/PUT /api/syslog/settings, PUT/DELETE /api/syslog/archive
//   Diagnostics           GET  /api/syslog/diagnostics?collector=<name>
// Every route is tenant-scoped (_tenantQS). Collectors are shown by name only.
// Each tab render bumps a sequence number; async results and the Live Tail
// poll stop as soon as the user has moved to another tab or page.
import { safeHtml, rawHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

const SEV = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];
const SEV_CLS = [
    'bg-red-100 text-red-800 border-red-200', 'bg-red-100 text-red-800 border-red-200',
    'bg-red-100 text-red-800 border-red-200', 'bg-red-50 text-red-700 border-red-200',
    'bg-amber-50 text-amber-800 border-amber-200', 'bg-blue-50 text-blue-800 border-blue-200',
    'bg-slate-100 text-slate-700 border-slate-200', 'bg-slate-50 text-slate-500 border-slate-200',
];
const RANGES = [['15 min', 900], ['1 h', 3600], ['24 h', 86400], ['7 d', 604800], ['30 d', 2592000]];
const LIMITS = [100, 500, 1000, 5000];
const TAIL_MS = 3000;
const TAIL_CAP = 2000;
const TAIL_START_S = 900;
const STALE_S = 300;
const SILENT_S = 3600;
const REFRESH_MS = 60000;
const FIELDS = ['host', 'program', 'msg', 'severity'];
const OPS = { host: ['equals', 'contains', 'regex'], program: ['equals', 'contains', 'regex'],
    msg: ['equals', 'contains', 'regex'], severity: ['equals', 'gte'] };
const OP_TITLE = 'equals: whole value matches · contains: substring · regex: regular expression · gte (severity): this level and anything less severe';
const MAX_RULES = 50;

const C = {
    card: 'hpe-card rounded-lg p-5 shadow-sm space-y-3',
    h3: 'text-sm font-bold text-slate-500',
    input: 'bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800 disabled:bg-slate-50 disabled:text-slate-500',
    label: 'text-xs text-slate-500 font-bold',
    btn: 'bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-full text-sm font-bold disabled:opacity-50 disabled:cursor-not-allowed',
    btnSec: 'bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-full text-sm font-medium border border-slate-200 disabled:opacity-50 disabled:cursor-not-allowed',
    btnDanger: 'bg-red-50 hover:bg-red-100 text-red-700 px-4 py-2 rounded-full text-sm font-medium border border-red-200 disabled:opacity-50',
    chip: 'px-3 py-1 rounded-full text-xs border',
    th: 'px-3 py-2 text-left text-xs font-medium text-slate-500 whitespace-nowrap',
    td: 'px-3 py-2 text-xs text-slate-700 whitespace-nowrap',
    pre: 'text-xs font-mono bg-slate-50 border border-slate-200 rounded p-3 overflow-auto max-h-96 whitespace-pre',
};

let _seq = 0;
let _poll = null;
let _pendingTail = null;   // {host, collector} handed from Sources to Live Tail

// ── shared helpers ──────────────────────────────────────────────────────────

// Stop the page's recurring timer (Live Tail poll or a data-page refresh).
function stopPoll() {
    if (_poll !== null) { pollManager.unregister(_poll); _poll = null; }
}

// Start a recurring timer that stops itself once the tab is no longer shown.
function startPoll(pg, fn, ms) {
    stopPoll();
    const id = pollManager.register(() => {
        if (!pg.alive()) { if (_poll === id) stopPoll(); else pollManager.unregister(id); return; }
        fn();
    }, ms);
    _poll = id;
}

// A tab render context: alive() is false once the user moved on (stale guard).
function newPage(tab) {
    const token = ++_seq;
    stopPoll();
    return { tab, alive: () => token === _seq && currentView === 'syslog' && currentSubView === tab };
}

// Tenant admins (and the Global Admin) change syslog settings; others read.
function canWrite() {
    return isAdmin() || isTenantAdmin();
}

// Call a hub syslog route; throws with the hub's detail on a non-2xx answer.
async function api(path, method = 'GET', body = undefined, background = false) {
    const init = { method, headers: { 'Content-Type': 'application/json' } };
    if (body !== undefined) init.body = JSON.stringify(body);
    if (background) init._background = true;
    const r = await fetch(path + _tenantQS(path.includes('?') ? '&' : '?'), init);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
        const d = j && j.detail;
        throw new Error((typeof d === 'string' ? d : d ? JSON.stringify(d) : '') || `${r.status} ${r.statusText}`);
    }
    return j || {};
}

// Epoch seconds (or an ISO string) -> epoch seconds, null when absent.
function toEpoch(v) {
    if (v === null || v === undefined || v === '') return null;
    if (typeof v === 'number') return v > 1e12 ? v / 1000 : v;
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t / 1000;
}

// Local date-time with the time zone (docs/webui-style.md "Time").
function fmtTime(ts) {
    const t = toEpoch(ts);
    return t === null ? '—' : new Date(t * 1000).toLocaleString();
}

// "5m ago" for an epoch time, with the full time as a tooltip.
function ago(ts) {
    const t = toEpoch(ts);
    if (t === null) return safeHtml`<span class="text-slate-500">never</span>`;
    const s = Math.max(0, Math.floor(Date.now() / 1000 - t));
    const age = s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m`
        : s < 86400 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`;
    return safeHtml`<span title="${fmtTime(t)}">${age} ago</span>`;
}

// Bytes as B / KB / MB / GB.
function fmtBytes(n) {
    if (n === null || n === undefined) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = Number(n) || 0;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

// Status dot: green ok, red failed, grey unknown; title is the tooltip.
function dot(ok, title) {
    const cls = ok === true ? 'bg-green-500' : ok === false ? 'bg-red-500' : 'bg-slate-300';
    return safeHtml`<span class="inline-block w-2.5 h-2.5 rounded-full ${cls}" title="${title || ''}"></span>`;
}

// Severity badge (number 0..7 -> name, coloured).
function sevBadge(n) {
    const i = Number(n);
    const known = Number.isInteger(i) && i >= 0 && i < 8;
    return safeHtml`<span class="px-2 py-0.5 rounded text-xs font-bold border ${known ? SEV_CLS[i] : 'bg-slate-50 text-slate-500 border-slate-200'}" title="Syslog severity ${known ? i : '?'}">${known ? SEV[i] : String(n)}</span>`;
}

// One error entry from the hub ("text" or {collector, error}) as text.
function errText(e) {
    if (!e) return '';
    if (typeof e === 'string') return e;
    const who = e.collector || e.name || '';
    const what = e.error || e.detail || e.message || JSON.stringify(e);
    return who ? `${who}: ${what}` : what;
}

// Lines (string or array) as one text block.
function asText(v) {
    if (v === null || v === undefined) return '';
    if (Array.isArray(v)) return v.map(x => (typeof x === 'string' ? x : JSON.stringify(x))).join('\n');
    if (typeof v === 'object') return JSON.stringify(v, null, 2);
    return String(v);
}

// "cached" badge, only when the hub's copy is more than 5 minutes old.
function cachedBadge(cachedAt) {
    const t = toEpoch(cachedAt);
    if (t === null || Date.now() / 1000 - t <= STALE_S) return '';
    return safeHtml`<span class="px-2 py-0.5 rounded text-xs border bg-amber-50 text-amber-700 border-amber-200" title="The hub's copy is from ${fmtTime(t)}; the collectors did not answer the last refresh.">cached</span>`;
}

// Title row of a tab, with the Help icon.
function head(title, tip, extra) {
    return safeHtml`<div class="flex items-center justify-between gap-3">
        <h3 class="${C.h3}">${title} ${rawHtml(helpIcon('syslog', null, 'Syslog help'))}${tip ? safeHtml` <span class="cursor-help font-normal text-slate-500" title="${tip}">ⓘ</span>` : ''}</h3>
        <span class="flex items-center gap-2">${extra || ''}</span>
    </div>`;
}

// A collector's status, whether the hub flattened SYSLOG_STATUS or kept its parts.
function colStatus(c) {
    return Object.assign({}, c, c.collector || {});
}

// The address devices should send to (the hub adds the agent's IP).
function colAddress(c) {
    return c.address || c.ip || c.primary_ip || c.host || '';
}

// <option> list of collector names, with an optional "all" entry first.
function collectorOptions(names, chosen, allLabel) {
    return safeHtml`${allLabel ? safeHtml`<option value="">${allLabel}</option>` : ''}${names.map(n =>
        safeHtml`<option value="${n}" ${n === chosen ? 'selected' : ''}>${n}</option>`)}`;
}

// Collector names from the overview payload (names, never ids).
function collectorNames(ov) {
    return ((ov && ov.collectors) || []).map(c => c.name).filter(Boolean);
}

// Copy text to the clipboard and confirm with a toast.
function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => showToast('Copied to the clipboard', 'success'),
            () => showToast('Could not copy: the browser blocked clipboard access', 'error'));
    } else {
        showToast('Could not copy: no clipboard access in this browser', 'error');
    }
}

// Results of a settings push: "saved" plus any collector that failed to apply.
function pushToast(what, j) {
    const res = j.results || j.collectors || j.push || [];
    const list = Array.isArray(res) ? res : Object.keys(res).map(k => Object.assign({ collector: k }, res[k]));
    const failed = list.filter(r => r && (r.ok === false || String(r.status || '').toUpperCase() === 'ERROR' || r.error));
    if (failed.length) {
        showToast(`${what} saved, but ${failed.length} collector(s) did not apply it: ${failed.map(errText).join('; ')}`, 'error');
    } else {
        showToast(`${what} saved${list.length ? ` and applied on ${list.length} collector(s)` : ''}`, 'success');
    }
}

// The messages table shared by Search and Live Tail. Text never wraps;
// columns size to their content and the box scrolls sideways.
function messageTable(msgs) {
    if (!msgs.length) return safeHtml`<p class="text-xs text-slate-500 italic py-4">No messages.</p>`;
    return safeHtml`<div class="overflow-x-auto"><table class="text-left">
        <thead><tr class="bg-slate-50 border-b border-slate-200">
            <th class="${C.th}">Time</th><th class="${C.th}">Collector</th><th class="${C.th}">Host</th>
            <th class="${C.th}">Source IP</th><th class="${C.th}">Program</th><th class="${C.th}">Severity</th>
            <th class="${C.th}">Message</th></tr></thead>
        <tbody>${msgs.map(m => safeHtml`<tr class="border-b border-slate-100 hover:bg-slate-50 align-top">
            <td class="${C.td}">${fmtTime(m.ts)}</td><td class="${C.td}">${m.collector || '—'}</td>
            <td class="${C.td}">${m.host || '—'}</td><td class="${C.td} font-mono">${m.src_ip || ''}</td>
            <td class="${C.td}">${m.program || ''}</td><td class="${C.td}">${sevBadge(m.severity)}</td>
            <td class="${C.td} font-mono">${m.msg || ''}</td></tr>`)}</tbody></table></div>`;
}

// Local / Archive / Partial badges for a query answer, then any per-collector errors.
function sourceBadges(res) {
    const src = res.sources || {};
    const errs = (res.errors || []).map(errText).filter(Boolean);
    const b = [];
    if (src.local) b.push(safeHtml`<span class="${C.chip} bg-green-50 text-green-800 border-green-200" title="Read from the collectors' local store (last ${24} h by default)">Local · ${src.local}</span>`);
    if (src.archive) b.push(safeHtml`<span class="${C.chip} bg-blue-50 text-blue-800 border-blue-200" title="Older than the collectors' local data, so read from the archive server">Archive · ${src.archive}</span>`);
    if (src['local-partial']) b.push(safeHtml`<span class="${C.chip} bg-amber-50 text-amber-800 border-amber-200 cursor-help" title="The archive could not answer, so only local data is shown: ${errs.join(' · ') || 'no detail'}">Partial · ${src['local-partial']}</span>`);
    return safeHtml`<div class="flex flex-wrap items-center gap-2">${b}</div>
        ${errs.length ? safeHtml`<ul class="text-xs text-red-700 space-y-0.5">${errs.map(e => safeHtml`<li>${e}</li>`)}</ul>` : ''}`;
}

// ── Search ──────────────────────────────────────────────────────────────────

async function renderSearch(root, pg) {
    const st = { range: 3600, busy: false, error: '', result: null, limit: 500, names: [], hosts: [] };
    root.innerHTML = safeHtml`<div class="${C.card}">
        ${head('Search', 'Messages from the last 24 hours come from the collectors; older ones from the archive server, when there is one. A badge on the results says which.')}
        <form data-submit="search" class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
                <span class="${C.label}">Range</span>
                ${RANGES.map(([label, s]) => safeHtml`<button type="button" data-action="range" data-s="${s}" class="${C.chip} ${s === st.range ? 'bg-brand/10 border-brand text-primary-text font-bold' : 'border-slate-200 text-slate-600'}">${label}</button>`)}
                <span class="${C.label} ml-3" title="Set a start and/or end to search a custom range instead">Custom</span>
                <input type="datetime-local" name="start" class="${C.input}" title="Start (local time)">
                <span class="text-xs text-slate-500">to</span>
                <input type="datetime-local" name="end" class="${C.input}" title="End (local time); empty = now">
            </div>
            <div class="flex flex-wrap items-end gap-3">
                <div class="space-y-1"><label class="${C.label} block">Host</label><input name="host" list="syslog-host-list" class="${C.input} w-44" placeholder="any" title="Device hostname as it sent it (exact match)"></div>
                <div class="space-y-1"><label class="${C.label} block">Program</label><input name="program" class="${C.input} w-36" placeholder="any" title="Syslog tag / program name"></div>
                <div class="space-y-1"><label class="${C.label} block">Max severity</label><select name="severity_max" class="${C.input}" title="Show this severity and anything more severe">
                    <option value="">any</option>${SEV.map((n, i) => safeHtml`<option value="${i}">${i} ${n}</option>`)}</select></div>
                <div class="space-y-1 flex-1 min-w-[12rem]"><label class="${C.label} block">Text</label><input name="text" class="${C.input} w-full" placeholder="words in the message" title="Case-insensitive text in the message"></div>
                <div class="space-y-1"><label class="${C.label} block">Collector</label><select name="collector" id="syslog-search-collector" class="${C.input}" title="Search one collector or all of them"><option value="">All collectors</option></select></div>
                <div class="space-y-1"><label class="${C.label} block">Limit</label><select name="limit" class="${C.input}" title="Most messages to return (newest first)">${LIMITS.map(n => safeHtml`<option value="${n}" ${n === st.limit ? 'selected' : ''}>${n}</option>`)}</select></div>
                <button type="submit" class="${C.btn} ml-auto">Search</button>
            </div>
            <datalist id="syslog-host-list"></datalist>
        </form>
    </div>
    <div class="${C.card}" id="syslog-results"></div>`;

    const results = createView({ el: 'syslog-results', state: st, render: s => {
        if (s.busy) return safeHtml`<p class="text-xs text-slate-500 animate-pulse py-4">Searching…</p>`;
        if (s.error) return safeHtml`<p class="text-xs text-red-700">Search failed: ${s.error}</p>`;
        if (!s.result) return safeHtml`<p class="text-xs text-slate-500 italic">Pick a range and filters, then Search.</p>`;
        const msgs = s.result.messages || [];
        const more = msgs.length >= s.limit ? safeHtml`<span class="text-xs text-amber-700" title="There may be more matches: narrow the range or filters, or raise the limit">showing the newest ${msgs.length}</span>` : safeHtml`<span class="text-xs text-slate-500">${msgs.length} message${msgs.length === 1 ? '' : 's'}</span>`;
        return safeHtml`<div class="flex flex-wrap items-center justify-between gap-2">${sourceBadges(s.result)}${more}</div>${messageTable(msgs)}`;
    } });
    const pickers = createView({ el: 'syslog-search-collector', state: st, render: s => collectorOptions(s.names, '', 'All collectors') });
    const hostList = createView({ el: 'syslog-host-list', state: st, render: s => safeHtml`${s.hosts.map(h => safeHtml`<option value="${h}"></option>`)}` });

    delegate(root, {
        range(el) {
            st.range = Number(el.dataset.s);
            root.querySelectorAll('[data-action="range"]').forEach(b => {
                const on = b === el;
                b.classList.toggle('bg-brand/10', on); b.classList.toggle('border-brand', on);
                b.classList.toggle('text-primary-text', on); b.classList.toggle('font-bold', on);
                b.classList.toggle('border-slate-200', !on); b.classList.toggle('text-slate-600', !on);
            });
            root.querySelector('[name="start"]').value = '';
            root.querySelector('[name="end"]').value = '';
        },
        async search(form) {
            const f = new FormData(form);
            const now = Date.now() / 1000;
            const cs = f.get('start');
            const ce = f.get('end');
            const start = cs ? Date.parse(cs) / 1000 : now - st.range;
            const end = ce ? Date.parse(ce) / 1000 : now;
            if (!(start < end)) { showToast('The start must be before the end', 'error'); return; }
            const body = { start: Math.floor(start), end: Math.ceil(end), limit: Number(f.get('limit')) || 500 };
            ['host', 'program', 'text', 'collector'].forEach(k => { const v = String(f.get(k) || '').trim(); if (v) body[k] = v; });
            if (f.get('severity_max') !== '') body.severity_max = Number(f.get('severity_max'));
            st.limit = body.limit;
            results.setState({ busy: true, error: '' });
            try {
                const j = await api('/api/syslog/query', 'POST', body);
                if (!pg.alive()) return;
                results.setState({ busy: false, result: j });
            } catch (e) {
                if (!pg.alive()) return;
                results.setState({ busy: false, error: e.message });
            }
        },
    });
    results.refresh();

    try {
        const ov = await api('/api/syslog/overview');
        if (!pg.alive()) return;
        st.names = collectorNames(ov);
        st.hosts = [...new Set((ov.sources || []).map(s => s.host).filter(Boolean))].sort();
        pickers.refresh();
        hostList.refresh();
    } catch (e) {
        if (pg.alive()) showToast('Syslog: could not list collectors: ' + e.message, 'error');
    }
}

// ── Live Tail ───────────────────────────────────────────────────────────────

async function renderTail(root, pg) {
    const preset = _pendingTail || {};
    _pendingTail = null;
    const st = { names: [], filter: { collector: preset.collector || '', host: preset.host || '', program: '', text: '' },
        rows: [], lastTs: null, paused: false, inflight: false, gen: 0, error: '', errors: [], started: 0 };
    root.innerHTML = safeHtml`<div class="${C.card}">
        ${head('Live Tail', 'Shows the last 15 minutes, then new messages every 3 seconds while this tab is open and visible. Keeps the newest ' + TAIL_CAP + ' rows.')}
        <form data-submit="apply" class="flex flex-wrap items-end gap-3">
            <div class="space-y-1"><label class="${C.label} block">Collector</label><select name="collector" id="syslog-tail-collector" class="${C.input}"><option value="">All collectors</option></select></div>
            <div class="space-y-1"><label class="${C.label} block">Host</label><input name="host" value="${st.filter.host}" class="${C.input} w-44" placeholder="any" title="Device hostname (exact match)"></div>
            <div class="space-y-1"><label class="${C.label} block">Program</label><input name="program" class="${C.input} w-36" placeholder="any"></div>
            <div class="space-y-1 flex-1 min-w-[12rem]"><label class="${C.label} block">Text</label><input name="text" class="${C.input} w-full" placeholder="words in the message"></div>
            <button type="submit" class="${C.btnSec}" title="Restart the tail with these filters">Apply</button>
            <span id="syslog-tail-ctl"></span>
        </form>
    </div>
    <div class="${C.card}" id="syslog-tail-body"></div>`;

    const ctl = createView({ el: 'syslog-tail-ctl', state: st, render: s => safeHtml`<button type="button" data-action="pause" class="${s.paused ? C.btn : C.btnSec}" title="${s.paused ? 'Start polling again' : 'Stop polling; the rows stay on screen'}">${s.paused ? 'Resume' : 'Pause'}</button>` });
    const body = createView({ el: 'syslog-tail-body', state: st, render: s => safeHtml`
        <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="text-xs text-slate-500">${s.paused ? 'Paused' : 'Live'} · ${s.rows.length} row${s.rows.length === 1 ? '' : 's'}${s.rows.length >= TAIL_CAP ? ' (oldest dropped)' : ''}</span>
            ${s.error ? safeHtml`<span class="text-xs text-red-700">${s.error}</span>` : ''}
        </div>
        ${s.errors.length ? safeHtml`<ul class="text-xs text-red-700">${s.errors.map(e => safeHtml`<li>${e}</li>`)}</ul>` : ''}
        ${s.started ? messageTable(s.rows) : safeHtml`<p class="text-xs text-slate-500 animate-pulse py-4">Loading the last 15 minutes…</p>`}` });
    const picker = createView({ el: 'syslog-tail-collector', state: st, render: s => collectorOptions(s.names, s.filter.collector, 'All collectors') });

    // One poll: the last 15 minutes first, then only messages newer than the newest shown.
    async function tick() {
        if (!pg.alive() || st.paused || st.inflight || document.hidden) return;
        const gen = st.gen;
        const now = Date.now() / 1000;
        const req = { start: Math.floor(st.lastTs !== null ? st.lastTs : now - TAIL_START_S), end: Math.ceil(now) + 5, limit: 500 };
        Object.keys(st.filter).forEach(k => { if (st.filter[k]) req[k] = st.filter[k]; });
        if (st.lastTs !== null) req.after_ts = st.lastTs;
        st.inflight = true;
        try {
            const j = await api('/api/syslog/query', 'POST', req, true);
            if (!pg.alive() || gen !== st.gen) return;
            const fresh = (j.messages || []).filter(m => st.lastTs === null || Number(m.ts) > st.lastTs);
            if (fresh.length) {
                st.rows = fresh.concat(st.rows).slice(0, TAIL_CAP);
                st.lastTs = Math.max(st.lastTs || 0, ...fresh.map(m => Number(m.ts) || 0));
            } else if (st.lastTs === null) {
                st.lastTs = now - TAIL_START_S;
            }
            st.errors = (j.errors || []).map(errText).filter(Boolean);
            st.error = '';
        } catch (e) {
            if (!pg.alive() || gen !== st.gen) return;
            st.error = 'Poll failed: ' + e.message;
        } finally {
            if (gen === st.gen) st.inflight = false;
        }
        st.started = 1;
        body.refresh();
    }

    // Restart from scratch (new filters).
    function restart() {
        st.gen++;
        st.inflight = false;
        st.rows = [];
        st.lastTs = null;
        st.started = 0;
        st.error = '';
        body.refresh();
        tick();
    }

    delegate(root, {
        apply(form) {
            const f = new FormData(form);
            Object.keys(st.filter).forEach(k => { st.filter[k] = String(f.get(k) || '').trim(); });
            restart();
        },
        pause() {
            st.paused = !st.paused;
            ctl.refresh();
            body.refresh();
            if (!st.paused) tick();
        },
    });
    ctl.refresh();
    body.refresh();
    startPoll(pg, tick, TAIL_MS);
    tick();

    try {
        const ov = await api('/api/syslog/overview');
        if (!pg.alive()) return;
        st.names = collectorNames(ov);
        picker.refresh();
    } catch (e) { /* the picker keeps "All collectors"; the tail still runs */ }
}

// ── Sources ─────────────────────────────────────────────────────────────────

async function renderSources(root, pg) {
    const st = { ov: null, error: '' };
    root.innerHTML = safeHtml`<div class="${C.card}" id="syslog-sources"></div>`;
    const view = createView({ el: 'syslog-sources', state: st, render: s => {
        const sources = ((s.ov && s.ov.sources) || []).slice().sort((a, b) => (toEpoch(b.last_ts) || 0) - (toEpoch(a.last_ts) || 0));
        const now = Date.now() / 1000;
        const table = sources.length ? safeHtml`<div class="overflow-x-auto"><table class="text-left">
            <thead><tr class="bg-slate-50 border-b border-slate-200"><th class="${C.th}">Host</th><th class="${C.th}">Source IP</th>
                <th class="${C.th}">Collector</th><th class="${C.th}">Last seen</th><th class="${C.th}">Messages (1 h)</th><th class="${C.th}">By severity</th></tr></thead>
            <tbody>${sources.map(src => {
                const silent = (toEpoch(src.last_ts) || 0) < now - SILENT_S;
                const sev = src.by_severity || {};
                return safeHtml`<tr data-action="tailHost" data-host="${src.host || ''}" data-collector="${src.collector || ''}" tabindex="0" role="button"
                    class="border-b border-slate-100 cursor-pointer ${silent ? 'bg-amber-50 hover:bg-amber-100' : 'hover:bg-slate-50'}"
                    title="${silent ? 'Silent for over an hour. ' : ''}Click to open Live Tail for this host">
                    <td class="${C.td} font-medium">${src.host || '—'}${silent ? safeHtml` <span class="text-amber-700">· silent</span>` : ''}</td>
                    <td class="${C.td} font-mono">${src.src_ip || ''}</td><td class="${C.td}">${src.collector || '—'}</td>
                    <td class="${C.td}">${ago(src.last_ts)}</td><td class="${C.td}">${src.count === undefined ? '—' : src.count}</td>
                    <td class="${C.td}"><span class="flex gap-1">${SEV.map((n, i) => (sev[i] || sev[String(i)])
                        ? safeHtml`<span class="px-1.5 rounded border ${SEV_CLS[i]}" title="${n}">${sev[i] || sev[String(i)]}</span>` : '')}</span></td></tr>`;
            })}</tbody></table></div>`
            : safeHtml`<p class="text-xs text-slate-500 italic py-4">${s.ov ? 'No device has sent syslog in the last hour. Point devices at a collector (Settings tab).' : 'Loading…'}</p>`;
        return safeHtml`${head('Sources', 'Every device seen in the last hour, newest first. Highlighted rows have sent nothing for over an hour.', cachedBadge(s.ov && s.ov.cached_at))}
            ${s.error ? safeHtml`<p class="text-xs text-red-700">Could not load sources: ${s.error}</p>` : ''}${table}`;
    } });
    delegate(root, {
        tailHost(el) {
            _pendingTail = { host: el.dataset.host, collector: el.dataset.collector };
            setSubView('Live Tail');
        },
    });
    view.refresh();
    const load = async background => {
        try {
            const ov = await api('/api/syslog/overview', 'GET', undefined, background);
            if (!pg.alive()) return;
            view.setState({ ov, error: '' });
        } catch (e) {
            if (pg.alive()) view.setState({ error: e.message });
        }
    };
    startPoll(pg, () => load(true), REFRESH_MS);
    await load(false);
}

// ── Drop Rules ──────────────────────────────────────────────────────────────

// Why a rule can't be saved, or '' when it is valid.
function ruleError(r) {
    if (!FIELDS.includes(r.field)) return 'Pick a field';
    if (!(OPS[r.field] || []).includes(r.op)) return 'Pick an operator';
    if (r.field === 'severity') {
        const n = Number(r.value);
        return Number.isInteger(n) && n >= 0 && n <= 7 && String(r.value) !== '' ? '' : 'Pick a severity';
    }
    if (String(r.value || '').trim() === '') return 'Enter a value';
    if (r.op === 'regex') {
        // Python inline flags such as (?i) are valid on the hub; JS rejects them.
        try { new RegExp(String(r.value).replace(/^\(\?[aiLmsux]+\)/, '')); } catch (e) { return 'Invalid regular expression'; }
    }
    return '';
}

// Drop Rules tab: list, edit, preview and save the tenant's drop rules.
async function renderDropRules(root, pg) {
    const st = { rules: [], loaded: false, error: '', preview: null, previewing: false, saving: false };
    const write = canWrite();
    root.innerHTML = safeHtml`<div class="${C.card}" id="syslog-rules"></div>`;
    const view = createView({ el: 'syslog-rules', state: st, render: s => {
        const errs = s.rules.map(ruleError);
        const invalid = errs.some(Boolean);
        const per = (s.preview && s.preview.per_rule) || [];
        const dis = write ? '' : 'disabled';
        const rows = s.rules.map((r, i) => safeHtml`<tr class="border-b border-slate-100 ${errs[i] ? 'bg-red-50' : ''}">
            <td class="${C.td}"><select id="syslog-rule-${i}-field" data-action="ruleSet" data-i="${i}" data-k="field" class="${C.input}" ${dis}>
                ${FIELDS.map(f => safeHtml`<option value="${f}" ${f === r.field ? 'selected' : ''}>${f}</option>`)}</select></td>
            <td class="${C.td}"><select id="syslog-rule-${i}-op" data-action="ruleSet" data-i="${i}" data-k="op" class="${C.input}" title="${OP_TITLE}" ${dis}>
                ${(OPS[r.field] || []).map(o => safeHtml`<option value="${o}" ${o === r.op ? 'selected' : ''}>${o}</option>`)}</select></td>
            <td class="${C.td}">${r.field === 'severity'
                ? safeHtml`<select id="syslog-rule-${i}-sev" data-action="ruleSet" data-i="${i}" data-k="value" class="${C.input}" ${dis}>
                    ${SEV.map((n, j) => safeHtml`<option value="${j}" ${String(j) === String(r.value) ? 'selected' : ''}>${j} ${n}</option>`)}</select>`
                : safeHtml`<input id="syslog-rule-${i}-value" data-input="ruleType" data-i="${i}" data-k="value" value="${r.value}" class="${C.input} w-64 font-mono" placeholder="${r.op === 'regex' ? 'regular expression' : 'value'}" ${dis}>`}</td>
            <td class="${C.td} text-center"><input type="checkbox" data-action="ruleSet" data-i="${i}" data-k="enabled" class="w-4 h-4 rounded" ${r.enabled ? 'checked' : ''} ${dis} title="Off = kept in the list but not applied"></td>
            <td class="${C.td}"><input id="syslog-rule-${i}-note" data-input="ruleType" data-i="${i}" data-k="note" value="${r.note || ''}" class="${C.input} w-56" placeholder="why this rule exists" ${dis}></td>
            <td class="${C.td}" title="Messages from the last hour this rule would drop">${per[i] === undefined ? '' : per[i]}</td>
            <td class="${C.td}">${errs[i] ? safeHtml`<span class="text-red-700">${errs[i]}</span>` : ''}</td>
            <td class="${C.td}">${write ? safeHtml`<button type="button" data-action="removeRule" data-i="${i}" class="text-xs font-bold text-red-700 hover:underline" title="Remove this rule (takes effect on Save)">Remove</button>` : ''}</td>
        </tr>`);
        const p = s.preview;
        const pct = p && p.scanned ? ` (${Math.round(100 * p.dropped / p.scanned)}%)` : '';
        return safeHtml`${head('Drop rules', 'A message that matches any enabled rule is dropped on the collector: it is not stored locally AND not forwarded to the archive.')}
            <p class="text-xs text-slate-500">Rules apply to the local store <b>and</b> the archive: a dropped message is never kept anywhere. Up to ${MAX_RULES} rules.${write ? '' : ' Read-only: only a Tenant Admin can change them.'}</p>
            ${s.error ? safeHtml`<p class="text-xs text-red-700">${s.error}</p>` : ''}
            ${!s.loaded ? safeHtml`<p class="text-xs text-slate-500 animate-pulse">Loading…</p>` : safeHtml`<div class="overflow-x-auto"><table class="text-left">
                <thead><tr class="bg-slate-50 border-b border-slate-200"><th class="${C.th}">Field</th><th class="${C.th}" title="${OP_TITLE}">Operator</th><th class="${C.th}">Value</th>
                    <th class="${C.th}">Enabled</th><th class="${C.th}">Note</th><th class="${C.th}">Preview</th><th class="${C.th}"></th><th class="${C.th}"></th></tr></thead>
                <tbody>${rows.length ? rows : safeHtml`<tr><td colspan="8" class="${C.td} italic text-slate-500">No drop rules: every message is kept.</td></tr>`}</tbody></table></div>`}
            ${p ? safeHtml`<p class="text-xs text-slate-600">Preview over the last hour: ${p.scanned} messages scanned, ${p.dropped} would be dropped${pct}.</p>` : ''}
            <div class="flex flex-wrap items-center gap-2">
                ${write ? safeHtml`<button type="button" data-action="addRule" class="${C.btnSec}" ${s.rules.length >= MAX_RULES ? 'disabled' : ''}>+ Add rule</button>` : ''}
                <button type="button" data-action="preview" class="${C.btnSec}" ${invalid || s.previewing || !s.loaded ? 'disabled' : ''} title="Count what these rules would drop from the last hour of local data (nothing is changed)">${s.previewing ? 'Previewing…' : 'Preview'}</button>
                <span class="ml-auto"></span>
                <button type="button" data-action="save" class="${C.btn}" ${!write || invalid || s.saving || !s.loaded ? 'disabled' : ''}
                    title="${!write ? 'Only a Tenant Admin can change drop rules' : invalid ? 'Fix the highlighted rows first' : 'Save and push the rules to every collector'}">${s.saving ? 'Saving…' : 'Save'}</button>
            </div>`;
    } });

    // Normalise a value typed into a row so it fits the row's field.
    const setRule = (i, k, v) => {
        const r = st.rules[i];
        if (!r) return;
        r[k] = v;
        if (k === 'field') {
            if (!(OPS[v] || []).includes(r.op)) r.op = OPS[v][0];
            if (v === 'severity') r.value = Number.isInteger(Number(r.value)) && r.value !== '' && Number(r.value) <= 7 ? Number(r.value) : 7;
            else if (typeof r.value === 'number') r.value = '';
        }
        if (k === 'value' && r.field === 'severity') r.value = Number(v);
        st.preview = null;
        view.refresh();
    };
    delegate(root, {
        ruleSet: el => setRule(Number(el.dataset.i), el.dataset.k, el.type === 'checkbox' ? el.checked : el.value),
        ruleType: el => setRule(Number(el.dataset.i), el.dataset.k, el.value),
        addRule() {
            if (st.rules.length >= MAX_RULES) return;
            st.rules.push({ field: 'msg', op: 'contains', value: '', enabled: true, note: '' });
            view.refresh();
        },
        removeRule(el) {
            st.rules.splice(Number(el.dataset.i), 1);
            st.preview = null;
            view.refresh();
        },
        async preview() {
            view.setState({ previewing: true });
            try {
                const j = await api('/api/syslog/drop-preview', 'POST', { drop_rules: st.rules });
                if (!pg.alive()) return;
                view.setState({ previewing: false, preview: j });
                (j.errors || []).forEach(e => showToast('Preview: ' + errText(e), 'error'));
            } catch (e) {
                if (!pg.alive()) return;
                view.setState({ previewing: false });
                showToast('Preview failed: ' + e.message, 'error');
            }
        },
        async save() {
            view.setState({ saving: true });
            try {
                const j = await api('/api/syslog/settings', 'PUT', { drop_rules: st.rules });
                if (!pg.alive()) return;
                view.setState({ saving: false });
                pushToast('Drop rules', j);
            } catch (e) {
                if (!pg.alive()) return;
                view.setState({ saving: false });
                showToast('Saving drop rules failed: ' + e.message, 'error');
            }
        },
    });
    view.refresh();
    try {
        const j = await api('/api/syslog/settings');
        if (!pg.alive()) return;
        const cfg = j.settings || j;
        st.rules = (cfg.drop_rules || []).map(r => ({ field: r.field, op: r.op, value: r.value === undefined ? '' : r.value,
            enabled: r.enabled !== false, note: r.note || '' }));
        view.setState({ loaded: true });
    } catch (e) {
        if (pg.alive()) view.setState({ error: 'Could not load the rules: ' + e.message });
    }
}

// ── Collectors & Archive ────────────────────────────────────────────────────

// The archive status block (shared by Collectors & Archive and Settings).
function archiveSummary(a) {
    if (!a || a.configured === false || !(a.host || a.backend)) {
        return safeHtml`<p class="text-xs text-slate-500">No archive server: messages are kept only on the collectors (24 h by default). Connect one under Settings → Archive, or deploy the "Syslog Archive (Graylog)" role on an agent.</p>`;
    }
    const units = a.units || a.unit_states || null;
    const unitList = Array.isArray(units) ? units.map(u => [u.name || u.unit, u.state || u.active])
        : units ? Object.keys(units).map(k => [k, units[k]]) : [];
    const managedBy = a.managed_by_role ? `LM-installed (${a.managed_by_role}${a.managed_by ? ' on ' + a.managed_by : a.agent_name ? ' on ' + a.agent_name : ''})` : 'External server';
    return safeHtml`<div class="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2 text-xs text-slate-700">
        <div><span class="${C.label}">Backend</span><div>${a.backend === 'syslog' ? 'Generic syslog (forward only)' : a.backend || '—'}</div></div>
        <div><span class="${C.label}">Host</span><div class="font-mono">${a.host || '—'}${a.input_port ? ':' + a.input_port : ''}${a.tls ? ' (TLS)' : ''}</div></div>
        <div><span class="${C.label}">Reachable</span><div class="flex items-center gap-1.5">${dot(a.reachable === true ? true : a.reachable === false ? false : null)}${a.reachable === true ? 'yes' : a.reachable === false ? 'no' : 'unknown'}</div></div>
        <div><span class="${C.label}">Version</span><div>${a.version || '—'}</div></div>
        <div><span class="${C.label}">Managed by</span><div>${managedBy}</div></div>
        ${unitList.length ? safeHtml`<div><span class="${C.label}">Services</span><div>${unitList.map(([n, v]) => safeHtml`<span class="mr-2">${dot(v === 'active' || v === true)} ${n}</span>`)}</div></div>` : ''}
    </div>
    ${a.error ? safeHtml`<p class="text-xs text-red-700">Archive error: ${a.error}</p>` : ''}
    ${a.ui_url ? safeHtml`<a href="${a.ui_url}" target="_blank" rel="noopener" class="${C.btnSec} inline-block" title="Opens the archive's own web UI. Global Admin only, for troubleshooting and upgrades; day-to-day searching happens on this page.">Open Graylog ↗</a>` : ''}`;
}

// Collectors tab: each collector's status, listeners and diagnostics.
async function renderCollectors(root, pg) {
    const st = { ov: null, error: '' };
    root.innerHTML = safeHtml`<div id="syslog-collectors" class="space-y-4"></div>`;
    const view = createView({ el: 'syslog-collectors', state: st, render: s => {
        const cols = ((s.ov && s.ov.collectors) || []).map(colStatus);
        const table = cols.length ? safeHtml`<div class="overflow-x-auto"><table class="text-left">
            <thead><tr class="bg-slate-50 border-b border-slate-200"><th class="${C.th}">Collector</th><th class="${C.th}">Receiving</th>
                <th class="${C.th}">Oldest local</th><th class="${C.th}">Newest local</th><th class="${C.th}" title="Local store size vs. its cap (Settings → Max size)">Size</th>
                <th class="${C.th}">Last 5 min</th><th class="${C.th}">Disk free</th><th class="${C.th}" title="Messages waiting to be forwarded to the archive">Forward queue</th>
                <th class="${C.th}">Archive link</th></tr></thead>
            <tbody>${cols.map(c => {
                const fwd = c.forward || {};
                const arch = c.archive || {};
                const maxB = (Number(c.max_mb) || 0) * 1048576;
                const pct = maxB ? Math.min(100, Math.round(100 * (Number(c.bytes) || 0) / maxB)) : null;
                return safeHtml`<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="${C.td} font-medium"><span class="flex items-center gap-1.5">${dot(c.online !== false, c.online === false ? 'Offline' : 'Online')}${c.name}</span>
                        ${c.error ? safeHtml`<div class="text-red-700 font-normal">${c.error}</div>` : ''}</td>
                    <td class="${C.td}">${c.active === true ? 'yes' : c.active === false ? safeHtml`<span class="text-red-700">no</span>` : '—'}</td>
                    <td class="${C.td}">${c.oldest_ts ? fmtTime(c.oldest_ts) : '—'}</td>
                    <td class="${C.td}">${c.newest_ts ? ago(c.newest_ts) : '—'}</td>
                    <td class="${C.td}"><span class="flex items-center gap-2">${fmtBytes(c.bytes)}${c.max_mb ? ` / ${c.max_mb} MB` : ''}
                        ${pct === null ? '' : safeHtml`<span class="inline-block w-16 h-1.5 bg-slate-100 rounded"><span class="block h-1.5 rounded ${pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-amber-500' : 'bg-primary'}" style="width:${pct}%"></span></span>`}</span></td>
                    <td class="${C.td}">${c.msgs_last_5m === undefined ? '—' : c.msgs_last_5m}</td>
                    <td class="${C.td}">${c.disk_free_mb == null ? '—' : fmtBytes(Number(c.disk_free_mb) * 1048576)}</td>
                    <td class="${C.td}">${fwd.queue_bytes === undefined ? '—' : fmtBytes(fwd.queue_bytes)}</td>
                    <td class="${C.td}">${arch.configured ? safeHtml`<span class="flex items-center gap-1.5" title="${arch.error || ''}">${dot(arch.reachable === true ? true : arch.reachable === false ? false : null)}${arch.reachable === false ? 'unreachable' : arch.reachable ? 'ok' : 'unknown'}</span>` : '—'}</td>
                </tr>`;
            })}</tbody></table></div>`
            : safeHtml`<p class="text-xs text-slate-500 italic py-4">${s.ov ? 'No collectors yet. Deploy the "Syslog Collector" role on an agent (Setup → Spokes & Agents).' : 'Loading…'}</p>`;
        return safeHtml`<div class="${C.card}">
            ${head('Collectors', 'Each collector receives device syslog and keeps its own rolling local store.', cachedBadge(s.ov && s.ov.cached_at))}
            ${s.error ? safeHtml`<p class="text-xs text-red-700">Could not load the overview: ${s.error}</p>` : ''}${table}</div>
            <div class="${C.card}">${head('Archive', 'Long-term storage. Every collector in this tenant forwards a copy to it over TLS.')}
            ${s.ov ? archiveSummary(s.ov.archive) : ''}</div>`;
    } });
    view.refresh();
    const load = async background => {
        try {
            const ov = await api('/api/syslog/overview', 'GET', undefined, background);
            if (!pg.alive()) return;
            view.setState({ ov, error: '' });
        } catch (e) {
            if (pg.alive()) view.setState({ error: e.message });
        }
    };
    startPoll(pg, () => load(true), REFRESH_MS);
    await load(false);
}

// ── Settings ────────────────────────────────────────────────────────────────

// Copy-paste device config for one collector address.
function sendExamples(ip) {
    return [
        ['Aruba CX (UDP)', `logging ${ip} udp`],
        ['Aruba CX (TCP)', `logging ${ip} tcp 514`],
        ['Generic rsyslog (TCP)', `*.* @@${ip}:514`],
        ['Generic rsyslog (UDP)', `*.* @${ip}:514`],
    ];
}

// Settings tab: retention, archive install or link, and archive status.
async function renderSettings(root, pg) {
    const write = canWrite();
    const dis = write ? '' : 'disabled';
    root.innerHTML = safeHtml`<div class="${C.card}">
        ${head('Retention', 'How much each collector keeps locally. Older messages are deleted (or only kept in the archive, when there is one).')}
        <form data-submit="saveRetention" data-input="checkRetention" class="flex flex-wrap items-end gap-3">
            <div class="space-y-1"><label class="${C.label} block">Keep (hours)</label><input type="number" min="1" max="720" step="1" name="retention_hours" id="syslog-ret-hours" class="${C.input} w-28" ${dis} title="Hours of messages each collector keeps on its own disk (1–720)"></div>
            <div class="space-y-1"><label class="${C.label} block">Max size (MB)</label><input type="number" min="64" step="64" name="max_mb" id="syslog-ret-mb" class="${C.input} w-28" ${dis} title="Cap on each collector's local store; the oldest hours are deleted first when it is reached"></div>
            <span class="ml-auto"></span>
            <button type="submit" id="syslog-ret-save" class="${C.btn}" disabled title="${write ? 'Save and push to every collector' : 'Only a Tenant Admin can change retention'}">Save</button>
        </form>
    </div>
    <div class="${C.card}" id="syslog-send"></div>
    <div class="${C.card}" id="syslog-archive"><p class="text-xs text-slate-500 animate-pulse">Loading…</p></div>`;

    const st = { ov: null };
    const send = createView({ el: 'syslog-send', state: st, render: s => {
        const cols = ((s.ov && s.ov.collectors) || []).map(colStatus);
        return safeHtml`${head('Send logs to', 'Point each device at one collector. Devices are configured by hand; LM does not change device config.')}
            ${!s.ov ? safeHtml`<p class="text-xs text-slate-500 animate-pulse">Loading…</p>` : !cols.length ? safeHtml`<p class="text-xs text-slate-500">No collectors yet. Deploy the "Syslog Collector" role on an agent first.</p>` : ''}
            ${cols.map(c => {
                const ip = colAddress(c);
                return safeHtml`<div class="border border-slate-200 rounded-md p-3 space-y-2">
                    <div class="flex flex-wrap items-center gap-3 text-sm"><span class="font-bold text-slate-700">${c.name}</span>
                        ${ip ? safeHtml`<span class="font-mono">${ip}</span>` : safeHtml`<span class="text-xs text-amber-700" title="The hub did not report this collector's address; see Setup → Spokes & Agents">address unknown</span>`}
                        <span class="text-xs text-slate-500">UDP 514 · TCP 514 · TLS 6514</span></div>
                    ${ip ? safeHtml`<div class="grid gap-1">${sendExamples(ip).map(([label, line]) => safeHtml`<div class="flex items-center gap-2 text-xs">
                        <span class="w-40 text-slate-500 whitespace-nowrap">${label}</span><code class="font-mono bg-slate-50 border border-slate-200 rounded px-2 py-0.5 whitespace-nowrap">${line}</code>
                        <button type="button" data-action="copy" data-text="${line}" class="text-xs text-primary-text hover:underline" title="Copy this line">Copy</button></div>`)}</div>` : ''}
                </div>`;
            })}
            <p class="text-xs text-slate-500">TLS (6514) uses the collector's LM certificate, signed by the hub CA: import the hub CA on devices that verify it.</p>`;
    } });
    send.refresh();

    const archiveRoot = root.querySelector('#syslog-archive');
    let archive = null;

    // Enable Save only when the values are usable.
    const checkRetention = () => {
        const h = Number(root.querySelector('#syslog-ret-hours').value);
        const mb = Number(root.querySelector('#syslog-ret-mb').value);
        root.querySelector('#syslog-ret-save').disabled = !(write && Number.isInteger(h) && h >= 1 && h <= 720 && mb >= 64);
    };
    // Enable the archive Save only when the external form is complete.
    const checkArchive = () => {
        const save = archiveRoot.querySelector('#syslog-arch-save');
        if (!save) return;
        const ext = (archiveRoot.querySelector('input[name="archmode"]:checked') || {}).value === 'external';
        archiveRoot.querySelector('#syslog-arch-form').classList.toggle('hidden', !ext);
        const backend = archiveRoot.querySelector('#syslog-arch-backend').value;
        archiveRoot.querySelector('#syslog-arch-graylog').classList.toggle('hidden', backend !== 'graylog');
        const host = archiveRoot.querySelector('#syslog-arch-host').value.trim();
        const port = Number(archiveRoot.querySelector('#syslog-arch-port').value);
        const apiUrl = archiveRoot.querySelector('#syslog-arch-api').value.trim();
        const ok = ext && host && Number.isInteger(port) && port > 0 && port < 65536
            && (backend !== 'graylog' || /^https?:\/\//.test(apiUrl));
        save.disabled = !(write && ok);
    };

    delegate(root, {
        checkRetention,
        checkArchive,
        archMode: checkArchive,
        archBackend(el) {
            const port = archiveRoot.querySelector('#syslog-arch-port');
            if (!port.value || port.value === '1514' || port.value === '6514') port.value = el.value === 'graylog' ? '1514' : '6514';
            checkArchive();
        },
        copy: el => copyText(el.dataset.text),
        async saveRetention(form) {
            const btn = form.querySelector('#syslog-ret-save');
            btn.disabled = true;
            try {
                const j = await api('/api/syslog/settings', 'PUT', {
                    retention_hours: Number(form.retention_hours.value), max_mb: Number(form.max_mb.value) });
                if (!pg.alive()) return;
                pushToast('Retention', j);
            } catch (e) {
                if (pg.alive()) showToast('Saving retention failed: ' + e.message, 'error');
            }
            if (pg.alive()) checkRetention();
        },
        async saveArchive(el) {
            const q = sel => archiveRoot.querySelector(sel);
            const backend = q('#syslog-arch-backend').value;
            const body = { backend, host: q('#syslog-arch-host').value.trim(), input_port: Number(q('#syslog-arch-port').value),
                tls: true, ca_pem: q('#syslog-arch-ca').value.trim() || null };
            if (backend === 'graylog') {
                body.api_url = q('#syslog-arch-api').value.trim();
                body.tls_name = q('#syslog-arch-tlsname').value.trim() || null;
                body.user = q('#syslog-arch-user').value.trim() || null;
                if (_vaultCredMissing('syslog-arch-vault')) return;
                const pw = q('#syslog-arch-password');
                if (pw && !pw.dataset.vaultHidden && pw.value) body.password = pw.value;
                const vc = _collectVaultCred('syslog-arch-vault');
                if (vc !== undefined) body.vault_credential = vc;
            }
            el.disabled = true;
            try {
                const j = await api('/api/syslog/archive', 'PUT', body);
                if (!pg.alive()) return;
                pushToast('Archive', j);
                loadArchive();
            } catch (e) {
                if (!pg.alive()) return;
                showToast('Saving the archive failed: ' + e.message, 'error');
                checkArchive();
            }
        },
        async disconnectArchive(el) {
            el.disabled = true;
            try {
                const j = await api('/api/syslog/archive', 'DELETE');
                if (!pg.alive()) return;
                pushToast('Archive disconnected;', j);
                loadArchive();
            } catch (e) {
                if (!pg.alive()) return;
                el.disabled = false;
                showToast('Disconnecting the archive failed: ' + e.message, 'error');
            }
        },
    });

    // The Archive section: status, then None / LM-installed / External server.
    function drawArchive() {
        const a = archive && archive.configured !== false && (archive.host || archive.backend) ? archive : null;
        if (a && a.managed_by_role) {
            const where = a.managed_by || a.agent_name || a.host;
            archiveRoot.innerHTML = safeHtml`${head('Archive', 'Where collectors forward a copy of every message for long-term storage.')}
                ${archiveSummary(a)}
                <p class="text-xs text-slate-600">LM installed this archive with the <b>${(AGENT_ROLES[a.managed_by_role] || {}).name || a.managed_by_role}</b> role on <b>${where}</b>, so it can't be edited here. To replace it, unload that role on ${where} (Setup → Spokes & Agents), then connect the new server here.</p>`;
            return;
        }
        const ext = !!a;
        const e = a || {};
        const backend = e.backend === 'syslog' ? 'syslog' : 'graylog';
        archiveRoot.innerHTML = safeHtml`${head('Archive', 'Where collectors forward a copy of every message for long-term storage. Collectors send RFC 5424 syslog over TLS to host:port (always encrypted); a Graylog archive can also be searched from this page.')}
            ${a ? archiveSummary(a) : ''}
            <div class="flex flex-wrap gap-4 text-sm text-slate-700">
                <label class="flex items-center gap-2 cursor-pointer" title="No archive: messages are kept only on the collectors"><input type="radio" name="archmode" value="none" data-action="archMode" ${ext ? '' : 'checked'} ${dis}> None</label>
                <label class="flex items-center gap-2 text-slate-500" title="Deploy the &quot;Syslog Archive (Graylog)&quot; role on an agent (Setup → Spokes & Agents); LM then connects every collector to it automatically"><input type="radio" disabled> LM-installed (deploy the Syslog Archive role)</label>
                <label class="flex items-center gap-2 cursor-pointer" title="A syslog server you run yourself"><input type="radio" name="archmode" value="external" data-action="archMode" ${ext ? 'checked' : ''} ${dis}> External server</label>
            </div>
            <div id="syslog-arch-form" class="space-y-3 ${ext ? '' : 'hidden'}">
                <div class="flex flex-wrap items-end gap-3">
                    <div class="space-y-1"><label class="${C.label} block">Backend</label><select id="syslog-arch-backend" data-action="archBackend" class="${C.input}" ${dis} title="Graylog can also be searched from this page; a generic syslog server only receives a copy">
                        <option value="graylog" ${backend === 'graylog' ? 'selected' : ''}>Graylog</option><option value="syslog" ${backend === 'syslog' ? 'selected' : ''}>Generic syslog (forward only)</option></select></div>
                    <div class="space-y-1"><label class="${C.label} block">Host</label><input id="syslog-arch-host" data-input="checkArchive" value="${e.host || ''}" class="${C.input} w-56" placeholder="10.0.0.60 or archive.example.com" ${dis}></div>
                    <div class="space-y-1"><label class="${C.label} block">Port</label><input id="syslog-arch-port" type="number" min="1" max="65535" data-input="checkArchive" value="${e.input_port || (backend === 'graylog' ? 1514 : 6514)}" class="${C.input} w-24" ${dis} title="The server's syslog TCP+TLS input port (always encrypted)"></div>
                </div>
                <div class="space-y-1"><label class="${C.label} block">CA certificate (optional)</label>
                    <textarea id="syslog-arch-ca" rows="3" class="${C.input} w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE----- … (blank = the server uses a certificate from the LM hub CA)" ${dis} title="PEM of the CA that signed the server's TLS certificate">${e.ca_pem || ''}</textarea></div>
                <div id="syslog-arch-graylog" class="grid grid-cols-1 md:grid-cols-3 gap-3 ${backend === 'graylog' ? '' : 'hidden'}">
                    <div class="space-y-1"><label class="${C.label} block">API URL</label><input id="syslog-arch-api" data-input="checkArchive" value="${e.api_url || ''}" class="${C.input} w-full" placeholder="https://archive.example.com:9000/api" ${dis} title="Graylog REST API, used to search messages older than the collectors keep"></div>
                    <div class="space-y-1"><label class="${C.label} block">TLS name</label><input id="syslog-arch-tlsname" value="${e.tls_name || ''}" class="${C.input} w-full" placeholder="archive.example.com" ${dis} title="The name the archive's certificate is issued for. Required when the host is an IP address; blank = use the host name."></div>
                    <div class="space-y-1"><label class="${C.label} block">User</label><input id="syslog-arch-user" value="${e.user || ''}" class="${C.input} w-full" placeholder="read-only user" ${dis} title="A Graylog user that can search (read-only is enough)"></div>
                    <div class="space-y-2"><label class="${C.label} block">Password</label><input id="syslog-arch-password" type="password" class="${C.input} w-full" autocomplete="new-password" placeholder="${e.has_password || e.password_set ? '(unchanged)' : 'password'}" ${dis}></div>
                    <div class="md:col-span-3">${write ? rawHtml(_vaultCredSelectHtml('syslog-arch-vault')) : ''}</div>
                </div>
            </div>
            <div class="flex items-center gap-2">
                ${ext ? safeHtml`<button type="button" data-action="disconnectArchive" class="${C.btnDanger}" ${dis} title="Stop forwarding to this server; collectors keep only their local store">Disconnect</button>` : ''}
                <span class="ml-auto"></span>
                <button type="button" id="syslog-arch-save" data-action="saveArchive" class="${C.btn}" disabled title="${write ? 'Save and push to every collector' : 'Only a Tenant Admin can change the archive'}">Save</button>
            </div>`;
        if (write) _fillVaultCredSelect('syslog-arch-vault', e.vault_credential, { inputIds: ['syslog-arch-password'], required: false });
        checkArchive();
    }

    // Load the overview and fill the archive section (stale renders ignored).
    async function loadArchive() {
        try {
            const ov = await api('/api/syslog/overview');
            if (!pg.alive()) return;
            st.ov = ov;
            archive = ov.archive || null;
            send.refresh();
            drawArchive();
        } catch (e) {
            if (!pg.alive()) return;
            archiveRoot.innerHTML = safeHtml`<p class="text-xs text-red-700">Could not load the archive status: ${e.message}</p>`;
        }
    }

    const settingsLoad = api('/api/syslog/settings').then(j => {
        if (!pg.alive()) return;
        const cfg = j.settings || j;
        root.querySelector('#syslog-ret-hours').value = cfg.retention_hours === undefined ? 24 : cfg.retention_hours;
        root.querySelector('#syslog-ret-mb').value = cfg.max_mb === undefined ? 2048 : cfg.max_mb;
        checkRetention();
    }).catch(e => { if (pg.alive()) showToast('Could not load syslog settings: ' + e.message, 'error'); });
    await Promise.all([settingsLoad, loadArchive()]);
}

// ── Diagnostics ─────────────────────────────────────────────────────────────

// One collapsible section of a SYSLOG_DIAG answer.
function diagSection(title, content, open) {
    return safeHtml`<details class="border border-slate-200 rounded-md" ${open ? 'open' : ''}>
        <summary class="px-3 py-2 text-sm font-bold text-slate-600 cursor-pointer">${title}</summary>
        <div class="px-3 pb-3 space-y-2">${content}</div></details>`;
}

function pre(v) {
    const t = asText(v);
    return t ? safeHtml`<pre class="${C.pre}">${t}</pre>` : safeHtml`<p class="text-xs text-slate-500 italic">Nothing reported.</p>`;
}

function okLine(label, v) {
    const bad = v && v !== 'ok' && v !== true;
    return safeHtml`<div class="flex items-center gap-2 text-xs">${dot(v === undefined || v === null ? null : !bad)}<span class="w-32 text-slate-500">${label}</span><span class="font-mono">${v === true ? 'ok' : asText(v) || '—'}</span></div>`;
}

function diagBody(d) {
    const rs = d.rsyslog || {};
    const store = d.store || {};
    const probe = d.archive_probe || {};
    const apiProbe = probe.api || {};
    const fq = d.forward_queue || {};
    const known = ['rsyslog', 'listeners', 'files', 'store', 'forward_queue', 'archive_probe', 'installer_log', 'recent_errors',
        'status', 'collector', 'name'];
    const extra = Object.keys(d).filter(k => !known.includes(k));
    return safeHtml`
        ${diagSection('rsyslog', safeHtml`${okLine('Service', rs.active === true ? 'active' : rs.active === false ? 'inactive' : rs.active)}
            <div class="text-xs text-slate-600">Version: ${rs.version || '—'}</div>
            <div class="${C.label}">Config check (rsyslogd -N1)</div>${pre(rs.config_check)}
            <div class="${C.label}">Journal (last 100 lines)</div>${pre(rs.journal)}`, true)}
        ${diagSection('Listeners (514 / 6514)', pre(d.listeners))}
        ${diagSection('Rendered config files', Object.keys(d.files || {}).length
            ? Object.keys(d.files).map(f => safeHtml`<div class="${C.label} font-mono">${f}</div>${pre(d.files[f])}`)
            : pre(''))}
        ${diagSection('Local store', safeHtml`<div class="text-xs text-slate-600">Directory <span class="font-mono">${store.dir || '—'}</span> · oldest ${fmtTime(store.oldest_ts)} · newest ${fmtTime(store.newest_ts)} · disk free ${store.disk_free_mb == null ? '—' : fmtBytes(store.disk_free_mb * 1048576)}</div>
            ${(store.hours || []).length ? safeHtml`<div class="overflow-x-auto max-h-72"><table class="text-left"><thead><tr class="bg-slate-50"><th class="${C.th}">Hour</th><th class="${C.th}">Size</th><th class="${C.th}">Compressed</th></tr></thead>
                <tbody>${store.hours.map(h => safeHtml`<tr class="border-b border-slate-100"><td class="${C.td} font-mono">${h.hour}</td><td class="${C.td}">${fmtBytes(h.bytes)}</td><td class="${C.td}">${h.gz ? 'yes' : 'no'}</td></tr>`)}</tbody></table></div>` : ''}`)}
        ${diagSection('Forward queue', safeHtml`<div class="text-xs text-slate-600">${fq.files === undefined ? '—' : fq.files} file(s), ${fmtBytes(fq.bytes)}</div>`)}
        ${diagSection('Archive probe', safeHtml`${okLine('TCP connect', probe.tcp_connect)}${okLine('TLS handshake', probe.tls_handshake)}
            ${okLine('API', apiProbe.error ? apiProbe.error : apiProbe.status)}<div class="text-xs text-slate-600">Archive version: ${apiProbe.version || '—'}</div>`, true)}
        ${diagSection('Installer log (last 100 lines)', pre(d.installer_log))}
        ${diagSection('Recent errors and warnings', pre(d.recent_errors), true)}
        ${extra.length ? diagSection('Other', pre(Object.fromEntries(extra.map(k => [k, d[k]])))) : ''}`;
}

async function renderDiagnostics(root, pg) {
    const st = { names: [], collector: '', busy: false, error: '', diag: null, at: null };
    root.innerHTML = safeHtml`<div class="${C.card}">
        ${head('Diagnostics', 'Everything needed to troubleshoot a collector without shell access: rsyslog state and config check, listeners, rendered config, local store, forward queue, archive probe, installer log and recent errors. Secrets are never included.')}
        <div class="flex flex-wrap items-end gap-3">
            <div class="space-y-1"><label class="${C.label} block">Collector</label><select id="syslog-diag-collector" data-action="pick" class="${C.input}"></select></div>
            <button type="button" data-action="run" class="${C.btnSec}" title="Ask the collector again (can take up to a minute)">↻ Run again</button>
            <span class="ml-auto"></span>
            <button type="button" data-action="copyAll" class="${C.btnSec}" title="Copy the whole report as text, for a bug report">Copy all</button>
        </div>
    </div>
    <div class="${C.card}" id="syslog-diag-body"></div>`;
    const picker = createView({ el: 'syslog-diag-collector', state: st, render: s => s.names.length
        ? collectorOptions(s.names, s.collector, '') : safeHtml`<option value="">No collectors</option>` });
    const body = createView({ el: 'syslog-diag-body', state: st, render: s => {
        if (s.busy) return safeHtml`<p class="text-xs text-slate-500 animate-pulse">Asking ${s.collector}… (up to a minute)</p>`;
        if (s.error) return safeHtml`<p class="text-xs text-red-700">Diagnostics for ${s.collector} failed: ${s.error}</p>`;
        if (!s.diag) return safeHtml`<p class="text-xs text-slate-500 italic">${s.names.length ? 'Pick a collector.' : 'No collectors in this tenant yet.'}</p>`;
        return safeHtml`<div class="text-xs text-slate-500">${s.collector} · collected ${fmtTime(s.at)}</div>${diagBody(s.diag)}`;
    } });

    async function run() {
        if (!st.collector) return;
        body.setState({ busy: true, error: '', diag: null });
        const who = st.collector;
        try {
            const j = await api('/api/syslog/diagnostics?collector=' + encodeURIComponent(who));
            if (!pg.alive() || who !== st.collector) return;
            body.setState({ busy: false, diag: j.diag || j, at: Date.now() / 1000 });
        } catch (e) {
            if (!pg.alive() || who !== st.collector) return;
            body.setState({ busy: false, error: e.message });
        }
    }

    delegate(root, {
        pick(el) { st.collector = el.value; run(); },
        run,
        copyAll() {
            if (!st.diag) { showToast('Nothing to copy yet', 'error'); return; }
            copyText(`Syslog diagnostics: ${st.collector} (${fmtTime(st.at)})\n` + JSON.stringify(st.diag, null, 2));
        },
    });
    body.refresh();
    try {
        const ov = await api('/api/syslog/overview');
        if (!pg.alive()) return;
        st.names = collectorNames(ov);
        st.collector = st.names[0] || '';
        picker.refresh();
        run();
    } catch (e) {
        if (pg.alive()) body.setState({ error: 'could not list collectors: ' + e.message });
    }
}

// ── entry point ─────────────────────────────────────────────────────────────

const TABS = {
    'Search': renderSearch,
    'Live Tail': renderTail,
    'Sources': renderSources,
    'Drop Rules': renderDropRules,
    'Collectors & Archive': renderCollectors,
    'Settings': renderSettings,
    'Diagnostics': renderDiagnostics,
};

// Draw one Syslog tab into `container` (#syslog-content); unknown tab -> Search.
function renderSyslog(container, subMenu) {
    if (!container) return;
    const tab = TABS[subMenu] ? subMenu : 'Search';
    const pg = newPage(tab);
    container.innerHTML = '';
    TABS[tab](container, pg).catch(e => console.error('syslog: ' + tab + ' failed', e));
}

lmViews.syslog = renderSyslog;
