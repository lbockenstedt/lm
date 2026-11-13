// "Hardware (iLO/BMC)" section of a hypervisor node card on Proxmox → Diagnostics.
// An ES module: pxmx-console.js calls lmViews.ilohealth(node.hw_health) for the
// markup and lmViews.ilohealthWire(container) once the cards are on the page.
// node.hw_health comes from /api/pxmx/drive-health: the hub joins the node to
// its out-of-band controller (iLO, iDRAC, …) by chassis serial and adds the
// controller's last SNMP health reading (today only HPE iLO MIBs report one).
import { safeHtml } from '../core/safe-html.js';
import { delegate } from '../core/view.js';

const GROUPS = [
    ['power', 'Power supply'], ['memory', 'Memory'], ['fans', 'Fan'],
    ['temperatures', 'Temperature'], ['cpus', 'CPU'], ['storage', 'Storage'],
];
const RANK = { failed: 3, degraded: 2, ok: 1 };
const BADGE = {
    ok: 'bg-emerald-100 text-emerald-800 border-emerald-200',
    degraded: 'bg-amber-100 text-amber-800 border-amber-200',
    failed: 'bg-red-100 text-red-800 border-red-200',
};

// A condition badge (ok / degraded / failed; anything else reads "unknown").
function badge(condition) {
    const known = BADGE[condition] ? condition : 'unknown';
    const cls = BADGE[known] || 'bg-slate-100 text-slate-600 border-slate-200';
    return safeHtml`<span class="px-2 py-0.5 rounded text-xs font-bold border ${cls}">${known}</span>`;
}

// "5m ago" style age of an epoch-seconds time, with the full time as a tooltip.
function when(ts, now) {
    if (!ts) return '';
    const s = Math.max(0, Math.floor(now - ts));
    const age = s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m`
        : s < 86400 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`;
    return safeHtml`<span title="${new Date(ts * 1000).toLocaleString()}">${age} ago</span>`;
}

// Every reported component as {kind, name, location, condition, detail}; a
// group this page doesn't know yet is still listed, under its own key.
function components(health) {
    const groups = (health && health.components) || {};
    const known = GROUPS.map(([key]) => key);
    const kinds = [...GROUPS, ...Object.keys(groups).filter(k => !known.includes(k)).map(k => [k, k])];
    return kinds.flatMap(([key, kind]) => (Array.isArray(groups[key]) ? groups[key] : [])
        .map(c => ({ kind, ...c })));
}

// "Power supply ×2 · Memory ×16 · Fan ×6 …" for the all-OK line.
function counts(items) {
    const n = {};
    items.forEach(c => { n[c.kind] = (n[c.kind] || 0) + 1; });
    return Object.keys(n).map(k => `${k} ×${n[k]}`).join(' · ');
}

// The table of components that are not OK, worst first.
function problemTable(problems) {
    const th = 'px-3 py-1.5 text-left text-xs font-bold text-slate-500 whitespace-nowrap';
    const td = 'px-3 py-1.5 text-xs text-slate-800 whitespace-nowrap';
    return safeHtml`<table class="w-full"><thead><tr class="border-b border-slate-200">
        <th class="${th}">Component</th><th class="${th}">Name</th><th class="${th}">Location</th>
        <th class="${th}">Condition</th><th class="${th}">Detail</th></tr></thead><tbody>
        ${problems.map(c => safeHtml`<tr class="border-b border-slate-100">
            <td class="${td}">${c.kind}</td><td class="${td}">${c.name || '—'}</td>
            <td class="${td} text-slate-600">${c.location || '—'}</td><td class="${td}">${badge(c.condition)}</td>
            <td class="${td} text-slate-600">${c.detail || ''}</td></tr>`)}
        </tbody></table>`;
}

// The body under the header: the components, or why there are none.
function body(hw, now) {
    const h = hw.health;
    const err = hw.error ? safeHtml`<p class="text-xs text-amber-700">Last read failed ${when(hw.error_at, now)}: ${hw.error}${h ? ' — showing the previous reading.' : ''}</p>` : '';
    if (!h) {
        return err || safeHtml`<p class="text-xs text-slate-500" title="Needs SNMP set up on the controller under Setup → Network Devices, and an nw spoke with hardware-health support. The next poll fills this in.">Hardware health not reported yet.</p>`;
    }
    const items = components(h);
    if (!items.length) {
        return safeHtml`${err}<p class="text-xs text-slate-500" title="The controller answered but reported no health tables (older firmware, or the health agent MIBs are off).">The controller reports no hardware components.</p>`;
    }
    // Only "ok" counts as OK; other(1), unexpected or missing conditions are
    // listed as unknown after the failed and degraded ones, never as healthy.
    const ok = items.filter(c => c.condition === 'ok');
    const problems = items.filter(c => c.condition !== 'ok')
        .sort((a, b) => (RANK[b.condition] || 0) - (RANK[a.condition] || 0));
    if (!problems.length) {
        const all = items.length === 1 ? '1 component OK' : `All ${items.length} components OK`;
        // The MIB's own roll-up can flag something no table lists (e.g. a chassis check).
        const elsewhere = RANK[h.overall] > 1
            ? ` Overall condition is ${h.overall}: check the controller for a fault outside these components.`
            : h.overall !== 'ok' ? ' The controller did not report an overall condition.' : '';
        return safeHtml`${err}<p class="text-xs text-emerald-700">${all}: ${counts(items)}.${elsewhere}</p>`;
    }
    return safeHtml`${err}${problemTable(problems)}<p class="text-xs text-slate-500 mt-1">${ok.length} other component${ok.length === 1 ? '' : 's'} OK.</p>`;
}

// The whole "Hardware (iLO/BMC)" block for one node, given node.hw_health.
export function iloHealthHtml(hw, now = Date.now() / 1000) {
    const head = 'text-xs font-bold text-slate-500';
    if (hw && hw.unavailable) {
        return safeHtml`<div class="mx-4 my-3 text-xs text-amber-700"><span class="${head}">Hardware (iLO/BMC):</span>
            could not be loaded (see the hub log); drive data below is unaffected.</div>`;
    }
    if (!hw || !hw.controller) {
        return safeHtml`<div class="mx-4 my-3 text-xs text-slate-500"><span class="${head}">Hardware (iLO/BMC):</span>
            <span title="A controller (iLO, iDRAC, …) added under Setup → Network Devices is linked to this server when both report the same chassis serial number.">no controller linked to this server.</span></div>`;
    }
    const ctl = hw.controller;
    const h = hw.health;
    const label = [ctl.name, ctl.address].filter(Boolean).join(' · ') || 'controller';
    const stale = hw.stale ? safeHtml`<span class="px-2 py-0.5 rounded text-xs font-bold border bg-amber-50 text-amber-700 border-amber-200" title="No new reading for over a day (or the reading has no time): the controller or the nw spoke has not answered recent polls.">stale</span>` : '';
    const polled = h && h.polled_at ? safeHtml`<span class="text-xs text-slate-500">polled ${when(h.polled_at, now)}</span>` : '';
    return safeHtml`<div class="mx-4 my-3 p-3 border border-slate-200 rounded-md space-y-2" data-ilo-health>
        <div class="flex items-center gap-2 flex-wrap">
            <span class="${head}">Hardware (iLO/BMC)</span>${h ? badge(h.overall) : ''}${stale}
            <button type="button" data-action="openIlo" data-id="${ctl.id}" class="text-xs text-primary-text hover:underline" title="Open this controller in Network Devices">${label}</button>
            <span class="ml-auto">${polled}</span>
        </div>
        ${body(hw, now)}
    </div>`;
}

// Wire the controller links in a rendered Diagnostics page to the Network Devices
// detail view (nwShowDevice in nw.js).
function wireIloHealth(container) {
    delegate(container, { openIlo: el => nwShowDevice(el.dataset.id) });
}

lmViews.ilohealth = iloHealthHtml;
lmViews.ilohealthWire = wireIloHealth;
