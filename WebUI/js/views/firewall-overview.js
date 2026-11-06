// Firewalls → Overview: one "is it working" card per firewall, like the
// OPNsense lobby dashboard — CPU, memory, uptime, gateway (WAN) status and
// live interface throughput from GET /api/firewall/{id}/overview. Opened by
// loadOpnsenseManagement through lmViews.fwoverview(container, firewalls).
import { safeHtml } from '../core/safe-html.js';

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
            <div class="text-[11px] text-slate-500">${o.hostname}${reply.stale ? ' (stale)' : ''}</div>
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

async function renderFirewallOverview(container, firewalls) {
    const results = await Promise.allSettled(firewalls.map(fetchOverview));
    if (currentView !== 'opnsense' || currentSubView !== 'Overview') return;
    container.innerHTML = safeHtml`<div class="grid gap-4 lg:grid-cols-2">${firewalls.map((fw, i) => {
        const name = fw.name || fw.id;
        const res = results[i];
        return res.status === 'fulfilled'
            ? firewallCard(name, res.value)
            : errorCard(name, String((res.reason && res.reason.message) || res.reason));
    })}</div>`;
}

lmViews.fwoverview = renderFirewallOverview;
