// Firewalls → Overview: one "is it working" card per firewall, like the
// OPNsense lobby dashboard — CPU, memory, uptime, gateway (WAN) status and
// live interface throughput from GET /api/firewall/{id}/overview. Opened by
// loadOpnsenseManagement through lmViews.fwoverview(container, firewalls).
// Below the cards: performance history (5-minute averages kept 7 days by the
// spoke) from GET /api/firewall/{id}/performance/history, drawn with the
// shared charts and History range selector in js/perf-trends.js.
import { safeHtml, rawHtml } from '../core/safe-html.js';

function bits(bps) {
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let value = Number(bps) || 0;
    let i = 0;
    while (value >= 1000 && i < units.length - 1) { value /= 1000; i++; }
    return `${value.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function usageBar(label, percent, detail) {
    if (percent === null || percent === undefined) {
        return safeHtml`<div class="text-xs text-slate-500">${label}: n/a</div>`;
    }
    const color = percent >= 90 ? 'bg-red-500' : percent >= 70 ? 'bg-amber-500' : 'bg-primary';
    return safeHtml`<div>
        <div class="flex justify-between text-xs text-slate-600 mb-1"><span>${label}</span><span>${percent}%${detail ? ` · ${detail}` : ''}</span></div>
        <div class="h-2 bg-slate-100 rounded"><div class="h-2 rounded ${color}" style="width:${Math.min(100, percent)}%"></div></div>
    </div>`;
}

function dot(color) {
    return safeHtml`<span class="inline-block w-2.5 h-2.5 rounded-full ${color}"></span>`;
}

function errorCard(name, message) {
    return safeHtml`<div class="border border-slate-200 rounded-lg p-4">
        <div class="flex items-center gap-2 font-semibold text-slate-700">${dot('bg-red-500')}${name}</div>
        <div class="text-xs text-red-600 mt-2">Unreachable: ${message}</div>
    </div>`;
}

function firewallCard(name, reply) {
    const o = reply.data || {};
    const gateways = o.gateways || [];
    const healthy = gateways.every(g => g.online);
    const mem = o.memory || {};
    const memDetail = mem.total ? `${Math.round(mem.used / 1048576)} / ${Math.round(mem.total / 1048576)} MB` : '';
    const subtitle = [o.version, o.uptime && `up ${o.uptime}`, o.loadavg && `load ${o.loadavg}`].filter(Boolean).join(' · ');

    const gatewayRows = gateways.map(g => safeHtml`<tr>
        <td class="py-1 pr-3 whitespace-nowrap">${dot(g.online ? 'bg-green-500' : 'bg-red-500')} ${g.name}</td>
        <td class="py-1 pr-3 font-mono">${g.address}</td>
        <td class="py-1 pr-3">${g.status}</td>
        <td class="py-1 pr-3">${g.delay}</td>
        <td class="py-1">${g.loss}</td></tr>`);
    const trafficRows = (o.interfaces || []).map(t => safeHtml`<tr>
        <td class="py-1 pr-3">${t.name}</td>
        <td class="py-1 pr-3 font-mono">↓ ${bits(t.in_bps)}</td>
        <td class="py-1 font-mono">↑ ${bits(t.out_bps)}</td></tr>`);

    return safeHtml`<div class="border border-slate-200 rounded-lg p-4 space-y-3">
        <div class="flex items-center justify-between">
            <div class="flex items-center gap-2 font-semibold text-slate-700">${dot(healthy ? 'bg-green-500' : 'bg-amber-500')}${name}</div>
            <div class="text-xs text-slate-500">${o.hostname}${reply.stale ? ' (stale)' : ''}</div>
        </div>
        <div class="text-xs text-slate-500">${subtitle}</div>
        ${usageBar('CPU', o.cpu_percent)}
        ${usageBar('Memory', mem.percent, memDetail)}
        <div>
            <div class="text-xs font-semibold text-slate-600 mb-1">Gateways</div>
            ${gatewayRows.length
                ? safeHtml`<table class="w-full text-xs text-slate-600">${gatewayRows}</table>`
                : safeHtml`<div class="text-xs text-slate-500">No gateways reported</div>`}
        </div>
        <div>
            <div class="text-xs font-semibold text-slate-600 mb-1">Traffic</div>
            ${trafficRows.length
                ? safeHtml`<table class="w-full text-xs text-slate-600">${trafficRows}</table>`
                : safeHtml`<div class="text-xs text-slate-500">No traffic data</div>`}
        </div>
    </div>`;
}

async function fetchOverview(fw) {
    const r = await fetch(`/api/firewall/${encodeURIComponent(fw.id)}/overview`);
    if (r.ok) return r.json();
    const body = await r.json().catch(() => ({}));
    throw new Error(body.detail || `${r.status} ${r.statusText}`);
}

// ── Performance history ─────────────────────────────────────────────────────
// The default range (7 days) is served by the hub from its own copy; any other
// range is read from the spoke. perfRows[i] holds firewall i's rows so picking
// an interface redraws without fetching again.
const PERF_DEFAULT = 604800;
let perfRange = { preset: PERF_DEFAULT };
let perfFirewalls = [];
let perfRows = [];
const perfInterface = {};

// Interface names found in the rows' "if:<name>:in_bps" metrics.
function interfaceNames(rows) {
    const names = new Set();
    rows.forEach(r => Object.keys(r.metrics).forEach(k => {
        const m = /^if:(.*):in_bps$/.exec(k);
        if (m) names.add(m[1]);
    }));
    return [...names].sort();
}

// Draw firewall i's charts for the selected interface ('' = all interfaces).
function drawPerf(i, t0, t1) {
    const box = document.getElementById(`fw-trends-${i}`);
    if (!box) return;
    const rows = perfRows[i] || [];
    const iface = perfInterface[perfFirewalls[i].id] || '';
    const key = metric => (iface ? `if:${iface}:${metric}` : metric);
    const pps = v => `${Math.round(v).toLocaleString()} pps`;
    const pct = v => `${v.toFixed(1)}%`;
    const packets = [{ key: key('in_pps'), label: 'In', color: '#0ea5e9' }, { key: key('out_pps'), label: 'Out', color: '#f97316' }];
    if (!iface) packets.push({ key: 'errps', label: 'Errors', color: '#ef4444' });
    box.innerHTML = [
        perfTrendChart(`fw-bps-${i}`, 'Throughput', rows, [{ key: key('in_bps'), label: 'In', color: '#0ea5e9' }, { key: key('out_bps'), label: 'Out', color: '#f97316' }], bits, t0, t1),
        perfTrendChart(`fw-pps-${i}`, 'Packets', rows, packets, pps, t0, t1),
        perfTrendChart(`fw-sys-${i}`, 'CPU and memory', rows, [{ key: 'cpu', label: 'CPU', color: '#64748b' }, { key: 'mem', label: 'Memory', color: '#8b5cf6' }], pct, t0, t1),
        perfTrendChart(`fw-states-${i}`, 'Firewall states', rows, [{ key: 'states', label: 'States', color: '#10b981' }], v => Math.round(v).toLocaleString(), t0, t1),
    ].join('');
    perfTrendWire(box);
}

// Fetch every firewall's history for the selected range and draw it.
async function loadPerf() {
    const { t0, t1, qs } = perfRangeWindow('fw', perfRange, PERF_DEFAULT);
    await Promise.all(perfFirewalls.map(async (fw, i) => {
        const box = document.getElementById(`fw-trends-${i}`);
        if (!box) return;
        box.innerHTML = safeHtml`<div class="text-xs text-slate-400 animate-pulse py-4">Loading history…</div>`.toString();
        let rows = [];
        try {
            const r = await fetch(`/api/firewall/${encodeURIComponent(fw.id)}/performance/history${qs}`);
            const j = r.ok ? await r.json() : null;
            rows = (j && Array.isArray(j.data)) ? j.data : [];
        } catch (e) { /* empty chart */ }
        perfRows[i] = rows;
        // Offer the interfaces seen in this range.
        const select = document.querySelector(`[data-fw-iface="${i}"]`);
        if (select) {
            const names = interfaceNames(rows);
            if (!names.includes(perfInterface[fw.id])) perfInterface[fw.id] = '';
            const chosen = perfInterface[fw.id];
            select.innerHTML = safeHtml`<option value="">All interfaces</option>${names.map(n =>
                safeHtml`<option value="${n}" ${n === chosen ? 'selected' : ''}>${n}</option>`)}`.toString();
        }
        drawPerf(i, t0, t1);
    }));
}

// The history section: range selector, then a title, interface picker and charts per firewall.
function perfSection(firewalls) {
    return safeHtml`<div class="space-y-6 mt-6">
        ${rawHtml(perfRangeBar('fw', perfRange))}
        ${firewalls.map((fw, i) => safeHtml`<div>
            <div class="flex items-center gap-3 mb-2">
                <h3 class="font-semibold text-slate-700">${fw.name || fw.id}</h3>
                <select data-fw-iface="${i}" class="text-xs border border-slate-300 rounded px-1 py-0.5"><option value="">All interfaces</option></select>
            </div>
            <div id="fw-trends-${i}" class="grid grid-cols-1 xl:grid-cols-2 gap-3"></div>
        </div>`)}
        <div class="text-xs text-slate-500">Charts are 5-minute averages, kept 7 days by the firewall spoke. "All interfaces" adds up every interface, so routed traffic is counted on the way in and on the way out.</div>
    </div>`;
}

// Wire the range selector and interface pickers, then load the charts.
function wirePerf(container, firewalls) {
    perfFirewalls = firewalls;
    perfRows = [];
    perfRangeWire(container, 'fw', range => { perfRange = range; loadPerf(); });
    container.querySelectorAll('[data-fw-iface]').forEach(select => select.addEventListener('change', () => {
        const i = Number(select.dataset.fwIface);
        perfInterface[firewalls[i].id] = select.value;
        const { t0, t1 } = perfRangeWindow('fw', perfRange, PERF_DEFAULT);
        drawPerf(i, t0, t1);
    }));
    loadPerf();
}

async function renderFirewallOverview(container, firewalls) {
    const results = await Promise.allSettled(firewalls.map(fetchOverview));
    if (currentView !== 'opnsense' || currentSubView !== 'Overview') return;
    container.innerHTML = safeHtml`<div class="grid gap-4 lg:grid-cols-2">${firewalls.map((fw, i) => {
        const name = fw.name || fw.id;
        const res = results[i];
        return res.status === 'fulfilled'
            ? firewallCard(name, res.value)
            : errorCard(name, String((res.reason && res.reason.message) || res.reason));
    })}</div>${perfSection(firewalls)}`;
    wirePerf(container, firewalls);
}

lmViews.fwoverview = renderFirewallOverview;
