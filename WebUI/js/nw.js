// nw.js — Network Devices management view (tables, topology, scan schedules, TrueNAS polling).
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// Network Devices management view (mirrors loadOpnsenseManagement).
// Per-sub-view column order for the NW sub-resource tables. Keeps the header
// set (and its order) identical whether we render one device's tab or the
// fused "All" view.
const _NW_SUBVIEW_KEYS = {
    'MAC Table':   ['device', 'mac', 'ip', 'os', 'vlan', 'interface'],
    'ARP':         ['device', 'ip', 'mac', 'os', 'interface'],
    'Interfaces':  ['device', 'name', 'status', 'speed', 'mode', 'ip', 'mac', 'vlan'],
    'IP Addresses':['device', 'ip', 'mac', 'os', 'vlan', 'interface'],
    'VLANs':       ['device', 'vlan', 'name', 'ports', 'macs', 'ips', 'gateway_ip'],
};

// Render one NW sub-resource table (shared by the per-device tabs and the
// fused "All" tab so both look identical).
function _nwSubViewTableHtml(subMenu, items, hideDevice) {
    let keys = _NW_SUBVIEW_KEYS[subMenu];
    if (!keys) keys = ['device', ...Object.keys(items[0] || {}).filter(k => k !== 'id' && k !== 'device' && !k.startsWith('_'))];
    if (hideDevice) keys = keys.filter(k => k !== 'device');
    const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
    const rows = items.map(item => {
        const cells = keys.map(k => {
            const val = item[k] !== undefined && item[k] !== null && item[k] !== '' ? String(item[k]) : '-';
            if (k === 'device') return `<td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(val)}</td>`;
            if (k === 'status') {
                const color = val === 'up' ? 'text-green-600' : 'text-slate-400';
                return `<td class="px-4 py-3 font-mono text-xs ${color}">${escapeHtml(val)}</td>`;
            }
            return `<td class="px-4 py-3 text-slate-600 font-mono text-xs max-w-[200px] truncate" title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
        }).join('');
        return `<tr class="hover:bg-slate-50 transition-colors">${cells}</tr>`;
    }).join('');
    return `<div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
        <table class="w-full text-left text-sm">
            <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}</tr></thead>
            <tbody class="divide-y divide-slate-200">${rows}</tbody>
        </table>
    </div>`;
}

// Device-centric drill-down (replaces the old fleet-wide per-device tabs, which
// didn't scale past a handful of devices). Flow: category tab (Gateways /
// Switches / Firewalls / Other) → device list → a single device's detail with
// lazy-loaded inner tabs (Overview / Interfaces / VLANs / MAC Table / ARP / IP
// Addresses). Each detail tab fetches /api/nw/{id}/{suffix} for just that one
// device on demand, so the page stays light no matter how large the fleet is.
// Cross-module search still queries every device server-side (/api/search), so
// nothing is hidden from a lookup.

// object_type → category tab. Unknown/blank types fall through to 'Other' so a
// new device kind still surfaces somewhere instead of vanishing.
function _nwCategoryOf(objectType) {
    switch (objectType) {
        case 'gateway':
            return 'Gateways';
        case 'aos_switch': case 'cx_switch': case 'ex_switch':
            return 'Switches';
        case 'firewall': case 'opnsense':
            return 'Firewalls';
        default:
            return 'Other';
    }
}

// Inner detail tabs and the /api/nw/{id}/<suffix> each one fetches. 'Overview'
// has no fetch (it renders the device meta already in hand).
const _NW_DETAIL_TABS = ['Overview', 'Interfaces', 'VLANs', 'MAC Table', 'ARP', 'IP Addresses'];
const _NW_DETAIL_SUFFIX = {
    'Interfaces':   'interfaces',
    'VLANs':        'vlans',
    'MAC Table':    'macs',
    'ARP':          'arp',
    'IP Addresses': 'endpoints',  // fused ARP+MAC
};

// Open one device's detail view inside the nw container. Reuses the device meta
// from the list we already fetched, plus a small per-tab cache so re-clicking a
// tab doesn't refetch.
window.nwOpenDevice = function (deviceId) {
    const list = (window._nwView && window._nwView.devices) || [];
    const dev = list.find(d => String(d.id) === String(deviceId));
    if (!dev) return;
    window._nwDetail = { dev, activeTab: 'Overview', cache: {} };
    const c = document.getElementById('nw-table-container');
    if (c) c.innerHTML = _nwDetailHtml();
};

// Back to the current category's device list (no refetch).
window.nwBackToList = function () {
    window._nwDetail = null;
    if (window._nwView) {
        if (window._nwView.category === 'Overview') _renderNwOverview(window._nwView.devices, window._nwView.counts);
        else _renderNwDeviceList(window._nwView.category, window._nwView.devices, window._nwView.counts);
    }
};

window.nwSelectDetailTab = function (tab) {
    const st = window._nwDetail;
    if (!st) return;
    st.activeTab = tab;
    const c = document.getElementById('nw-table-container');
    if (c) c.innerHTML = _nwDetailHtml();
    if (tab !== 'Overview') _nwLoadDetailTab(tab);
};

function _nwDetailHtml() {
    const st = window._nwDetail;
    if (!st) return '';
    const dev = st.dev;
    const typeLabel = _NW_OBJECT_TYPES[dev.object_type] || dev.object_type || '—';
    const transport = _NW_TRANSPORTS[dev.transport] || dev.transport || 'auto';
    const reachable = dev.reachable;
    const rcell = reachable === true || reachable === 'up'
        ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">up</span>'
        : reachable === false || reachable === 'down'
            ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-red-100 text-red-700">down</span>'
            : '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-100 text-amber-700" title="Reachability unknown — the Network Devices spoke is offline, so up/down can\'t be probed">unknown</span>';
    const cat = (window._nwView && window._nwView.category) || 'Devices';
    const tabs = _NW_DETAIL_TABS.map(t =>
        `<button onclick="nwSelectDetailTab('${escJsAttr(t)}')" class="px-3 py-1.5 rounded-md text-xs font-bold transition-colors ${t === st.activeTab ? 'bg-[#01A982]/10 text-[#01A982] border border-[#01A982]' : 'text-slate-500 hover:bg-slate-100 border border-transparent'}">${escapeHtml(t)}</button>`
    ).join('');

    let body;
    if (st.activeTab === 'Overview') {
        const cfg = (isAdmin() || isTenantAdmin())
            ? `<div class="flex gap-2 mt-3 pt-3 border-t border-slate-100">
                 <button onclick="pollNwDevice('${escJsAttr(dev.id)}','${escJsAttr(dev.name || dev.id)}', this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium">Poll Now</button>
                 <button onclick="showNwConfigModal('${escJsAttr(dev.id)}','${escJsAttr(dev.name || dev.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Configure</button>
               </div>`
            : '';
        const metaRow = (k, v) => `<div class="flex justify-between py-1.5 border-b border-slate-100 last:border-0"><span class="text-xs text-slate-400 uppercase tracking-wider">${k}</span><span class="text-xs text-slate-700 font-mono">${v}</span></div>`;
        // Identity datums captured on poll (surfaced by the list route from the
        // warm per-device cache) — help positively ID the physical box.
        const idRow = (k, val) => val ? metaRow(k, escapeHtml(String(val))) : '';
        body = `<div class="rounded-md border border-slate-200 bg-white p-4 max-w-lg">
            ${metaRow('Type', escapeHtml(typeLabel))}
            ${metaRow('Transport', escapeHtml(transport))}
            ${metaRow('Address', escapeHtml(dev.address || '—'))}
            ${idRow('Hostname', dev.hostname)}
            ${idRow('Model', dev.model)}
            ${idRow('Serial (SN)', dev.serial)}
            ${idRow('Base MAC', dev.mac)}
            ${idRow('Firmware', dev.firmware)}
            ${metaRow('Reachable', rcell)}
            ${cfg}
        </div>`;
    } else {
        body = st.cache[st.activeTab] !== undefined
            ? st.cache[st.activeTab]
            : `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${escapeHtml(st.activeTab)}…</div>`;
    }

    return `<div class="space-y-3">
        <div class="flex items-center gap-3">
            <button onclick="nwBackToList()" class="text-xs text-slate-500 hover:text-slate-700 font-medium">← ${escapeHtml(cat)}</button>
            <h3 class="text-sm font-bold text-slate-700">${escapeHtml(dev.name || dev.id)}</h3>
            ${rcell}
        </div>
        <div class="flex flex-wrap gap-1.5">${tabs}</div>
        ${body}
    </div>`;
}

// Lazy-fetch a single device's sub-resource for the active detail tab, cache the
// rendered table, then repaint if the user is still on that tab. Best-effort: a
// device/spoke error renders an inline note instead of blanking the page.
async function _nwLoadDetailTab(tab) {
    const st = window._nwDetail;
    if (!st) return;
    if (st.cache[tab] !== undefined) return;  // already rendered by _nwDetailHtml
    const suffix = _NW_DETAIL_SUFFIX[tab];
    if (!suffix) return;
    const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    let html;
    try {
        const r = await fetch(`/api/nw/${st.dev.id}/${suffix}${tenantQs}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        let items = Array.isArray(data)
            ? data
            : (Array.isArray(data?.data) ? data.data : (Array.isArray(data?.payload?.data) ? data.payload.data : []));
        html = items.length
            ? _nwSubViewTableHtml(tab, items, true)
            : `<div class="py-12 text-center text-slate-400 italic">No ${escapeHtml(tab)} on this device.</div>`;
    } catch (err) {
        html = `<div class="py-12 text-center text-amber-600 italic">Could not load ${escapeHtml(tab)}: ${escapeHtml(err.message)}</div>`;
    }
    st.cache[tab] = html;
    if (window._nwDetail === st && st.activeTab === tab) {
        const c = document.getElementById('nw-table-container');
        if (c) c.innerHTML = _nwDetailHtml();
    }
}
// Category tab loader (Gateways / Switches / Firewalls / Other). Lists the fleet
// once, filters to the selected category, and renders a device list; drilling
// into a device lazy-loads its per-resource detail (see nwOpenDevice). ?tenant=
// scopes the server-side subnet filter to the selected tenant (incl. admins via
// the switcher); without it admins bypass the filter (see access.filter_nw).
async function loadNwData(category) {
    const container = document.getElementById('nw-table-container');
    if (!container) return;
    category = category || currentSubView;
    // Map any stale/legacy submenu value (a cached currentSubView from the old
    // data-type tabs, or a deep link) onto a real category so the page never
    // blanks. 'Overview' is the tenant-wide summary landing tab.
    const CATEGORIES = ['Gateways', 'Switches', 'Firewalls', 'Other'];
    if (category === 'Topology') {
        window._nwView = null;
        window._nwDetail = null;
        const actions = document.getElementById('top-nav-actions');
        if (actions) actions.innerHTML = '';
        _renderNwTopologyTab();
        return;
    }
    if (category === 'Scan') {
        window._nwView = null;
        window._nwDetail = null;
        const actions = document.getElementById('top-nav-actions');
        if (actions) actions.innerHTML = '';
        _renderNwScanTab();
        return;
    }
    if (category !== 'Overview' && !CATEGORIES.includes(category)) category = 'Overview';
    window._nwDetail = null;
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Loading ${escapeHtml(category)}…</div>`;

    // Suppress the per-view "+ Add" action strip for nw (no add-from-view flow;
    // devices are managed on Setup → Network Devices).
    const actions = document.getElementById('top-nav-actions');
    if (actions) actions.innerHTML = '';

    const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    let r;
    try {
        r = await fetch(`/api/nw/devices${tenantQs}`);
    } catch (e) {
        container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Network Devices spoke not connected. Approve one in Setup → Spokes & Agents.</div>`;
        return;
    }
    if (!r.ok) {
        container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Network Devices spoke not connected (HTTP ${r.status}).</div>`;
        return;
    }
    let items;
    try {
        const data = await r.json();
        if (data && data.select_tenant) {
            // ADMIN (default) tenant: the hub no longer accumulates every
            // tenant's devices — pick a specific tenant to see its fleet.
            container.innerHTML = `<div class="py-12 text-center space-y-3">
                <svg class="w-10 h-10 mx-auto text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-3-4h.01M16 16h.01"/></svg>
                <p class="text-slate-600 text-sm font-semibold">Select a tenant to view its network devices</p>
                <p class="text-slate-400 text-xs max-w-md mx-auto">The ADMIN (default) view no longer aggregates every tenant's devices. Choose a specific tenant from the tenant picker to see that tenant's fleet.</p>
            </div>`;
            return;
        }
        items = Array.isArray(data) ? data : (Array.isArray(data?.data) ? data.data : []);
    } catch (err) {
        console.error(`[Network] Error in loadNwData:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading devices: ${escapeHtml(err.message)}</div>`;
        return;
    }
    const devices = items.filter(it => _nwCategoryOf(it.object_type) === category);
    // Per-category counts across the WHOLE fleet so the list view can show where
    // every device lives — otherwise, landing on an empty/small category (e.g.
    // Gateways) makes devices under another category look "missing".
    const counts = { Gateways: 0, Switches: 0, Firewalls: 0, Other: 0 };
    items.forEach(it => { counts[_nwCategoryOf(it.object_type)]++; });
    if (category === 'Overview') {
        // Tenant-wide summary landing (mirrors the Hypervisor Overview): keep the
        // full fleet on _nwView so a row click can drill into device detail and
        // the detail back-button repaints the overview without a refetch.
        window._nwView = { category: 'Overview', devices: items, counts };
        _renderNwOverview(items, counts);
        return;
    }
    window._nwView = { category, devices, counts };
    _renderNwDeviceList(category, devices, counts);
}

// Tenant-wide summary landing for the NW module (first tab), mirroring the
// Hypervisor Overview: reachability stat cards + clickable per-category cards +
// a compact fleet table (click a row → device detail). All figures are scoped
// to the selected tenant by the /api/nw/devices?tenant= fetch in loadNwData.
function _renderNwOverview(devices, counts) {
    const container = document.getElementById('nw-table-container');
    if (!container) return;
    counts = counts || { Gateways: 0, Switches: 0, Firewalls: 0, Other: 0 };
    const isUp   = it => it.reachable === true  || it.reachable === 'up';
    const isDown = it => it.reachable === false || it.reachable === 'down';
    const total = devices.length;
    const up    = devices.filter(isUp).length;
    const down  = devices.filter(isDown).length;
    const unknown = total - up - down;

    if (!total) {
        container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No network devices configured for this tenant. Add one in Setup → Network Devices.</div>`;
        return;
    }

    // Reachability stat cards (non-clickable summary).
    const stat = (label, n, valueCls) => `
        <div class="bg-white rounded-xl border border-slate-200 p-5">
            <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">${label}</p>
            <p class="text-3xl font-bold ${valueCls || 'text-[#263040]'}">${n}</p>
        </div>`;
    const statCards = `<div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        ${stat('Total Devices', total)}
        ${stat('Reachable', up, 'text-green-600')}
        ${stat('Unreachable', down, 'text-red-500')}
        ${stat('Unknown', unknown, 'text-amber-500')}
    </div>`;

    // Per-category cards → click navigates to that category tab.
    const CATEGORIES = ['Gateways', 'Switches', 'Firewalls', 'Other'];
    const catCard = c => `
        <div onclick="setSubView('${c}')" class="cursor-pointer bg-white rounded-xl border border-slate-200 p-5 hover:border-[#01A982] hover:shadow-md transition-all" title="Filter network devices by ${c}">
            <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">${c}</p>
            <p class="text-3xl font-bold text-[#263040]">${counts[c] || 0}</p>
        </div>`;
    const catCards = `<div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        ${CATEGORIES.map(catCard).join('')}
    </div>`;

    // Compact fleet table — every device in the tenant, click to drill in.
    const rows = devices.map(it => {
        const typeLabel = _NW_OBJECT_TYPES[it.object_type] || it.object_type || '—';
        const category  = _nwCategoryOf(it.object_type);
        const rcell = isUp(it)
            ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">up</span>'
            : isDown(it)
                ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-red-100 text-red-700">down</span>'
                : '<span class="text-slate-400 text-xs">—</span>';
        return `<tr onclick="nwOpenDevice('${escJsAttr(it.id)}')" class="hover:bg-slate-50 transition-colors cursor-pointer" title="View device details">
            <td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(it.name || it.id)}${(it.serial || it.mac) ? `<div class="text-[10px] font-mono font-normal text-slate-400 mt-0.5">${it.serial ? 'SN ' + escapeHtml(String(it.serial)) : ''}${(it.serial && it.mac) ? ' · ' : ''}${it.mac ? escapeHtml(String(it.mac)) : ''}</div>` : ''}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(typeLabel)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(category)}</td>
            <td class="px-4 py-3 text-slate-600 font-mono text-xs">${escapeHtml(it.address || '—')}</td>
            <td class="px-4 py-3">${rcell}</td>
            <td class="px-4 py-3 text-right"><span class="text-slate-300">›</span></td>
        </tr>`;
    }).join('');
    const headers = ['device', 'type', 'category', 'address', 'reachable']
        .map(k => `<th class="px-4 py-3">${k.toUpperCase()}</th>`).join('');

    container.innerHTML = `
        <div class="space-y-4">
            <h3 class="text-base font-semibold text-[#263040] px-1">Fleet Overview
                <span class="text-xs text-slate-400 font-normal">(${total} device${total === 1 ? '' : 's'} in this tenant)</span></h3>
            ${statCards}
            ${catCards}
            <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}<th class="px-4 py-3"></th></tr></thead>
                    <tbody class="divide-y divide-slate-200">${rows}</tbody>
                </table>
            </div>
        </div>`;
}

// ── Tenant NW "Scan" tab ─────────────────────────────────────────────────────
// A per-tenant surface (admin & tenant-admin only) to configure + run network
// discovery scans on THIS tenant's NW spoke(s), plus per-tenant poll jitter/caps
// and a recurring scan schedule. All state is read/written via
// /api/nw/tenant-config (tenant-scoped; never clobbers the global admin config);
// scans run via /setup/nw-scan/run (also tenant-scoped). Poll knobs left on
// "Inherit global" clear the tenant override so the admin default applies.
const _NW_JITTER_OPTS = [['', 'Inherit global'], ['0', 'Off'], ['0.05', '±5%'],
    ['0.15', '±15%'], ['0.3', '±30%'], ['0.5', '±50%']];
const _NW_SCHED_INTERVALS = [['0', 'Off'], ['3600', 'Every hour'],
    ['21600', 'Every 6 hours'], ['43200', 'Every 12 hours'],
    ['86400', 'Daily'], ['604800', 'Weekly']];

// ── Network → Topology ───────────────────────────────────────────────────────
// The map. Links come from three sources and are drawn distinctly, because an
// LLDP adjacency is a fact while a MAC-table link is a GUESS and an operator
// must be able to tell them apart at a glance:
//   lldp   — solid slate   (both ends advertised the adjacency)
//   manual — solid green   (a human declared it)
//   netbox — solid blue    (from NetBox's cable inventory)
//   mac    — dashed amber  (inferred: exactly one MAC learned on that port)
// Layout is a small deterministic force simulation — no library, no build step
// (the WebUI is dependency-free vanilla JS by design).
const _NW_TOPO_EDGE_STYLE = {
    lldp:   { stroke: '#64748b', dash: '',     label: 'LLDP' },
    manual: { stroke: '#01A982', dash: '',     label: 'Declared' },
    netbox: { stroke: '#0ea5e9', dash: '',     label: 'NetBox cable' },
    mac:    { stroke: '#d97706', dash: '5 4',  label: 'Inferred (MAC)' },
};

function _nwTopoLayout(nodes, edges, colW, rowH, collapsed) {
    // Layered left-to-right tree (Aruba Central style): the best-connected
    // device of each component is the root column, and every hop away from it
    // is one column further right. Rows are ordered by neighbour barycentre to
    // keep links from crossing needlessly. Deterministic: no randomness.
    // `collapsed` node ids keep their place but hide every BFS-tree descendant,
    // so collapsing never re-roots or reshuffles the rest of the map.
    const ids = new Set(nodes.map(n => n.id));
    const adj = {};
    nodes.forEach(n => { adj[n.id] = new Set(); });
    edges.forEach(e => {
        if (ids.has(e.a) && ids.has(e.b) && e.a !== e.b) { adj[e.a].add(e.b); adj[e.b].add(e.a); }
    });
    const linked = nodes.filter(n => adj[n.id].size);
    const loose = nodes.filter(n => !adj[n.id].size);
    const rank = n => (n.kind === 'switch' ? 1 : 0) * 1000 + adj[n.id].size;
    const depth = {};
    const parent = {};
    const children = {};
    const comps = [];
    linked.slice().sort((x, y) => rank(y) - rank(x) || String(x.name).localeCompare(String(y.name)))
        .forEach(root => {
            if (depth[root.id] !== undefined) return;
            const comp = [root.id];
            depth[root.id] = 0;
            children[root.id] = [];
            for (let i = 0; i < comp.length; i++) {
                [...adj[comp[i]]].sort().forEach(nb => {
                    if (depth[nb] === undefined) {
                        depth[nb] = depth[comp[i]] + 1;
                        parent[nb] = comp[i];
                        children[comp[i]].push(nb);
                        children[nb] = [];
                        comp.push(nb);
                    }
                });
            }
            comps.push(comp);
        });
    const hidden = new Set();
    const hiddenCount = {};
    if (collapsed) {
        collapsed.forEach(id => {
            if (!children[id]) return;
            const visited = new Set();
            hiddenCount[id] = 0;
            const queue = [id];
            while (queue.length) {
                const nodeId = queue.shift();
                if (visited.has(nodeId)) continue;
                visited.add(nodeId);
                if (nodeId !== id) hidden.add(nodeId);
                children[nodeId].forEach(child => {
                    if (!visited.has(child)) {
                        queue.push(child);
                        hiddenCount[id]++;
                    }
                });
            }
        });
    }
    const pos = {};
    let yCursor = 44, maxX = 0;
    comps.forEach(comp => {
        const filteredComp = comp.filter(id => !hidden.has(id));
        const layers = [];
        filteredComp.forEach(id => { (layers[depth[id]] = layers[depth[id]] || []).push(id); });
        const nameOf = {};
        nodes.forEach(n => { nameOf[n.id] = String(n.name || n.id); });
        layers.forEach(l => l.sort((x, y) => nameOf[x].localeCompare(nameOf[y])));
        const row = {};
        layers.forEach(l => l.forEach((id, i) => { row[id] = i; }));
        for (let sweep = 0; sweep < 4; sweep++) {
            for (let d = 1; d < layers.length; d++) {
                const bc = id => {
                    const prev = [...adj[id]].filter(n => depth[n] === d - 1 && !hidden.has(n));
                    return prev.length ? prev.reduce((t, n) => t + row[n], 0) / prev.length : row[id];
                };
                layers[d].sort((x, y) => bc(x) - bc(y) || nameOf[x].localeCompare(nameOf[y]));
                layers[d].forEach((id, i) => { row[id] = i; });
            }
        }
        const tallest = Math.max(...layers.map(l => l.length));
        const height = Math.max(1, tallest) * rowH;
        layers.forEach((l, d) => {
            const off = (height - l.length * rowH) / 2;
            l.forEach((id, i) => {
                pos[id] = { x: 70 + d * colW, y: yCursor + off + i * rowH + rowH / 2 };
                maxX = Math.max(maxX, pos[id].x);
            });
        });
        yCursor += height + rowH * 0.6;
    });
    return { pos, loose, width: maxX + 120, height: yCursor, depth, children, hiddenCount, hidden };
}

function _nwTopoNodeColor(node) {
    if (node.kind === 'gateway') return '#0ea5e9';
    if (node.kind === 'switch') return '#01A982';
    if (node.manual) return '#7c3aed';
    return '#94a3b8';
}

function _nwTopoIcon(nd, x, y, color) {
    const r = 17;
    const g = (nd.kind === 'gateway')
        ? `<path d="M-7 0h14M0 -7v14M-7 0l3 -3M-7 0l3 3M7 0l-3 -3M7 0l-3 3M0 -7l-3 3M0 -7l3 3M0 7l-3 -3M0 7l3 -3" stroke="#0f172a" stroke-width="1.6" fill="none"/>`
        : (nd.kind === 'switch')
            ? `<rect x="-9" y="-6" width="18" height="12" rx="2" fill="none" stroke="#0f172a" stroke-width="1.6"/><path d="M-5 -1h9M1 -3l3 2l-3 2M5 3h-9M-1 1l-3 2l3 2" stroke="#0f172a" stroke-width="1.3" fill="none"/>`
            : `<rect x="-6" y="-5" width="12" height="10" rx="2" fill="none" stroke="#475569" stroke-width="1.5"/>`;
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}" fill="#fff" stroke="${color}" stroke-width="3"/>` +
           `<g transform="translate(${x.toFixed(1)} ${y.toFixed(1)})">${g}</g>`;
}

// Fold each device's leaf endpoints (non-infra, single link) into one
// "N endpoints" group node so a switch with dozens of MACs stays readable.
// Groups are closed unless their id ('eg:<parent>') is in openSet; an open
// group hangs the endpoints off the group node, labelled with the switch port.
function _nwTopoGroupEndpoints(nodes, edges, openSet) {
    const byId = {}, deg = {};
    nodes.forEach(n => { byId[n.id] = n; deg[n.id] = 0; });
    edges.forEach(e => { deg[e.a] = (deg[e.a] || 0) + 1; deg[e.b] = (deg[e.b] || 0) + 1; });
    const leafEdge = {}, byParent = {};
    edges.forEach(e => {
        [[e.a, e.b], [e.b, e.a]].forEach(([leaf, par]) => {
            const ln = byId[leaf], pn = byId[par];
            if (ln && pn && ln.infra === false && deg[leaf] === 1 && pn.infra !== false) {
                leafEdge[leaf] = e;
                (byParent[par] = byParent[par] || []).push(leaf);
            }
        });
    });
    const dropNodes = new Set(), dropEdges = new Set();
    const addNodes = [], addEdges = [];
    Object.keys(byParent).forEach(par => {
        const leaves = byParent[par];
        if (leaves.length < 2) return;
        const gid = 'eg:' + par;
        addNodes.push({ id: gid, name: leaves.length + ' endpoints', kind: 'epgroup', infra: false,
                        group_parent: par, group_size: leaves.length,
                        addresses: [], macs: [], sources: ['group'] });
        addEdges.push({ a: par, a_port: '', b: gid, b_port: '', source: 'mac',
                        detail: leaves.length + ' endpoints' });
        const open = openSet && openSet.has(gid);
        leaves.forEach(leaf => {
            const e = leafEdge[leaf];
            dropEdges.add(e);
            if (!open) { dropNodes.add(leaf); return; }
            const port = _nwTopoPort(e, e.a === par ? 'a' : 'b');
            addEdges.push({ a: gid, a_port: '', b: leaf, b_port: '', source: e.source,
                            detail: port ? 'port ' + port + (e.detail ? ' — ' + e.detail : '') : e.detail });
        });
    });
    return {
        nodes: nodes.filter(n => !dropNodes.has(n.id)).concat(addNodes),
        edges: edges.filter(e => !dropEdges.has(e)).concat(addEdges),
    };
}

// A VSX unit's edges carry the physical member that owns the port.
function _nwTopoPort(e, side) {
    const port = e[side + '_port'] || '';
    const member = e[side + '_member'] || '';
    if (!member) return port;
    const short = member.split(/[-.]/).filter(Boolean).pop() || member;
    return port ? short + ' ' + port : short;
}

function _nwTopoSvg(graph, view) {
    const showEndpoints = !!(view && view.showEndpoints);
    const collapsed = (view && view.collapsed) || new Set();
    const allNodes = graph.nodes || [];
    let nodes = showEndpoints ? allNodes : allNodes.filter(nd => nd.infra !== false);
    const keep = new Set(nodes.map(n => n.id));
    let edges = (graph.edges || []).filter(e => keep.has(e.a) && keep.has(e.b));
    if (showEndpoints) {
        ({ nodes, edges } = _nwTopoGroupEndpoints(nodes, edges, view.epOpen));
    }
    if (!allNodes.length) {
        return `<div class="py-12 text-center text-slate-400 italic">No devices in this tenant's topology yet.</div>`;
    }
    if (!nodes.length) {
        return `<div class="py-12 text-center text-slate-400 italic">No infrastructure devices found. Tick “Show endpoints” to see everything.</div>`;
    }
    const colW = 240, rowH = 64, W0 = 900;
    const lay = _nwTopoLayout(nodes, edges, colW, rowH, collapsed);
    const pos = lay.pos;
    const byId = {};
    nodes.forEach(nd => { byId[nd.id] = nd; });
    const tipOf = nd => [nd.name, nd.object_type || nd.kind,
                     (nd.addresses || []).join(', '), (nd.macs || []).join(', '),
                     nd.unit === 'vsx' ? 'VSX pair: ' + (nd.members || []).map(m => m.name).join(' + ') : '',
                     (nd.stack_members || []).length ? 'Stack members: ' + nd.stack_members.join(', ') : '',
                     nd.lldp_capable ? 'LLDP' : '', nd.manual ? 'Declared' : '',
                     'via ' + (nd.sources || []).join('+')].filter(Boolean).join('\n');
    const lines = edges.map(e => {
        const a = pos[e.a], b = pos[e.b];
        if (!a || !b) return '';
        const st = _NW_TOPO_EDGE_STYLE[e.source] || _NW_TOPO_EDGE_STYLE.mac;
        const ap = _nwTopoPort(e, 'a'), bp = _nwTopoPort(e, 'b');
        const tip = `${(byId[e.a] || {}).name || ''} ${ap ? '(' + ap + ')' : ''} — ` +
                    `${(byId[e.b] || {}).name || ''} ${bp ? '(' + bp + ')' : ''}` +
                    `\n${st.label}${e.detail ? ' — ' + e.detail : ''}`;
        const [l, r] = a.x <= b.x ? [a, b] : [b, a];
        const mx = (l.x + r.x) / 2;
        const same = Math.abs(l.x - r.x) < 1;
        const d = same
            ? `M${l.x.toFixed(1)} ${l.y.toFixed(1)}C${(l.x + 60).toFixed(1)} ${l.y.toFixed(1)} ${(r.x + 60).toFixed(1)} ${r.y.toFixed(1)} ${r.x.toFixed(1)} ${r.y.toFixed(1)}`
            : `M${l.x.toFixed(1)} ${l.y.toFixed(1)}C${mx.toFixed(1)} ${l.y.toFixed(1)} ${mx.toFixed(1)} ${r.y.toFixed(1)} ${r.x.toFixed(1)} ${r.y.toFixed(1)}`;
        return `<path d="${d}" fill="none" stroke="${st.stroke}" stroke-width="1.5"
            ${st.dash ? `stroke-dasharray="${st.dash}"` : ''} opacity="0.85"><title>${escapeHtml(tip)}</title></path>`;
    }).join('');
    window._nwTopoLevels = {};
    Object.keys(lay.pos).forEach(id => {
        if (lay.children[id] && lay.children[id].length > 0) {
            const depth = lay.depth[id];
            if (!window._nwTopoLevels[depth]) window._nwTopoLevels[depth] = [];
            window._nwTopoLevels[depth].push(id);
        }
    });
    const drawNode = (nd, p) => {
        const isGroup = nd.kind === 'epgroup';
        const groupOpen = isGroup && view.epOpen && view.epOpen.has(nd.id);
        const kids = isGroup ? 1 : (lay.children[nd.id] || []).length;
        let tooltipLines = isGroup ? [nd.name] : tipOf(nd).split('\n');
        if (isGroup) {
            tooltipLines.push(groupOpen ? 'Click to hide these endpoints' : 'Click to show these endpoints');
        } else if (kids > 0) {
            tooltipLines.push(collapsed.has(nd.id) ? 'Click to expand' : 'Click to collapse');
        }
        const tip = tooltipLines.join('\n');
        const badgeText = isGroup ? (groupOpen ? '−' : '+' + nd.group_size)
            : collapsed.has(nd.id) ? '+' + (lay.hiddenCount[nd.id] || 0) : '−';
        return `<g data-topo-node="${escapeHtml(nd.id)}" style="cursor:${kids ? 'pointer' : 'default'}">
            <title>${escapeHtml(tip)}</title>
            ${_nwTopoIcon(nd, p.x, p.y, _nwTopoNodeColor(nd))}
            <text x="${p.x.toFixed(1)}" y="${(p.y + 32).toFixed(1)}" text-anchor="middle"
              style="font-size:10px" fill="#334155">${escapeHtml(String(nd.name || nd.id).slice(0, 34))}</text>
            ${kids > 0 ? `<circle cx="${(p.x + 15).toFixed(1)}" cy="${(p.y - 15).toFixed(1)}" r="8" fill="#0f172a"/>
                <text x="${(p.x + 15).toFixed(1)}" y="${(p.y - 11.5).toFixed(1)}" text-anchor="middle"
                  style="font-size:10px; font-weight:700; fill:#fff">${badgeText}</text>` : ''}
        </g>`;
    };
    const dots = nodes.filter(nd => pos[nd.id]).map(nd => drawNode(nd, pos[nd.id])).join('');
    // Level headers
    let levelHeaders = '';
    Object.keys(window._nwTopoLevels).forEach(d => {
        const depth = parseInt(d);
        const allCollapsed = window._nwTopoLevels[d].every(id => collapsed.has(id));
        const textContent = (allCollapsed ? '▸ ' : '▾ ') + 'Level ' + (depth + 1);
        levelHeaders += `<text data-topo-level="${d}" x="${(70 + depth * colW).toFixed(1)}" y="18" text-anchor="middle"
            style="font-size:11px;font-weight:600;cursor:pointer" fill="#475569">
            <title>Collapse/expand every device at this level</title>${escapeHtml(textContent)}</text>`;
    });
    // Devices with no known link: a compact wrapped grid instead of a hairball.
    const W = Math.max(W0, lay.width);
    const perRow = Math.max(1, Math.floor((W - 40) / 150));
    let H = lay.height, looseSvg = '';
    if (lay.loose.length) {
        const top = H + 10;
        const rows = Math.ceil(lay.loose.length / perRow);
        looseSvg = `<text x="20" y="${top + 4}" style="font-size:11px;font-weight:600" fill="#64748b">Unlinked devices (${lay.loose.length})</text>` +
            lay.loose.map((nd, i) => drawNode(nd, {
                x: 20 + 75 + (i % perRow) * 150, y: top + 40 + Math.floor(i / perRow) * 76 })).join('');
        H = top + 40 + rows * 76 + 10;
    }
    return `<svg viewBox="0 0 ${W} ${H}" class="w-full" style="max-height:75vh">${lines}${levelHeaders}${dots}${looseSvg}</svg>`;
}

// Default view is infrastructure only (node.infra); endpoints are opt-in.
// Collapse state is per tenant and survives refreshes (node ids are stable).
function _nwTopoView() {
    if (window._nwTopoCollapsedTenant !== currentTenant) {
        window._nwTopoCollapsed = new Set();
        window._nwTopoCollapsedTenant = currentTenant;
    }
    if (!(window._nwTopoCollapsed instanceof Set)) {
        window._nwTopoCollapsed = new Set();
    }
    if (!(window._nwTopoEpOpen instanceof Set) || window._nwTopoEpOpenTenant !== currentTenant) {
        window._nwTopoEpOpen = new Set();
        window._nwTopoEpOpenTenant = currentTenant;
    }
    return { showEndpoints: !!window._nwTopoShowEndpoints, collapsed: window._nwTopoCollapsed,
             epOpen: window._nwTopoEpOpen };
}

function _nwTopoRedraw() {
    const host = document.getElementById('nw-topo-svg');
    if (!host || !window._nwTopo) return;
    host.innerHTML = _nwTopoSvg(window._nwTopo, _nwTopoView());
}

function _nwTopoBindView() {
    const svg = document.getElementById('nw-topo-svg');
    if (svg) {
        svg.onclick = ev => {
            const lvl = ev.target.closest('[data-topo-level]');
            if (lvl) {
                const ids = (window._nwTopoLevels || {})[lvl.getAttribute('data-topo-level')] || [];
                const set = _nwTopoView().collapsed;
                const allInSet = ids.every(id => set.has(id));
                if (allInSet) {
                    ids.forEach(id => set.delete(id));
                } else {
                    ids.forEach(id => set.add(id));
                }
                _nwTopoRedraw();
                return;
            }
            const node = ev.target.closest('[data-topo-node]');
            if (node && node.style.cursor === 'pointer') {
                const nodeId = node.getAttribute('data-topo-node');
                const set = nodeId.startsWith('eg:') ? _nwTopoView().epOpen : _nwTopoView().collapsed;
                if (set.has(nodeId)) {
                    set.delete(nodeId);
                } else {
                    set.add(nodeId);
                }
                _nwTopoRedraw();
            }
        };
    }

    const endpointsCheckbox = document.getElementById('nw-topo-endpoints');
    if (endpointsCheckbox) {
        endpointsCheckbox.checked = !!window._nwTopoShowEndpoints;
        endpointsCheckbox.onchange = () => {
            window._nwTopoShowEndpoints = endpointsCheckbox.checked;
            _nwTopoRedraw();
        };
    }

    const expandBtn = document.getElementById('nw-topo-expand');
    if (expandBtn) {
        expandBtn.onclick = () => {
            const v = _nwTopoView();
            v.collapsed.clear();
            if (v.showEndpoints) {
                _nwTopoGroupEndpoints((window._nwTopo.nodes || []), (window._nwTopo.edges || []), null)
                    .nodes.filter(n => n.kind === 'epgroup').forEach(n => v.epOpen.add(n.id));
            }
            _nwTopoRedraw();
        };
    }

    const collapseBtn = document.getElementById('nw-topo-collapse');
    if (collapseBtn) {
        collapseBtn.onclick = () => {
            const level0Ids = (window._nwTopoLevels || {})[0] || [];
            const set = _nwTopoView().collapsed;
            level0Ids.forEach(id => set.add(id));
            _nwTopoView().epOpen.clear();
            _nwTopoRedraw();
        };
    }
}

async function _renderNwTopologyTab(opts) {
    const c = document.getElementById('nw-table-container');
    if (!c) return;
    opts = opts || {};
    const infer = window._nwTopoInfer !== false;
    c.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">${
        opts.refresh ? 'Gathering LLDP and MAC tables from every device…' : 'Building topology…'}</div>`;

    const qs = new URLSearchParams();
    if (currentTenant) qs.set('tenant', currentTenant);
    if (opts.refresh) qs.set('refresh', '1');
    if (!infer) qs.set('infer', '0');
    let graph;
    try {
        const r = await fetch(`/api/nw/topology?${qs.toString()}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        graph = await r.json();
    } catch (e) {
        c.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Could not build topology: ${escapeHtml(e.message)}</div>`;
        return;
    }
    if (graph.select_tenant) {
        c.innerHTML = `<div class="py-12 text-center space-y-3">
            <p class="text-slate-600 text-sm font-semibold">Select a tenant to view its network topology</p>
            <p class="text-slate-400 text-xs max-w-md mx-auto">A map is only coherent within one tenant's slice, so the ADMIN (default) view does not aggregate every tenant's devices. Choose a specific tenant from the tenant picker.</p>
        </div>`;
        return;
    }
    window._nwTopo = graph;

    const st = graph.stats || {};
    const bySrc = st.edges_by_source || {};
    const legend = Object.keys(_NW_TOPO_EDGE_STYLE).map(k => {
        const s = _NW_TOPO_EDGE_STYLE[k];
        return `<span class="flex items-center gap-1.5 text-xs text-slate-500">
            <svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="${s.stroke}" stroke-width="2" ${s.dash ? `stroke-dasharray="${s.dash}"` : ''}/></svg>
            ${s.label} <b class="text-slate-700">${bySrc[k] || 0}</b></span>`;
    }).join('');

    const trunks = (graph.trunks || []).map(t => `<tr class="border-t border-slate-100">
        <td class="py-1 pr-3 font-mono text-xs">${escapeHtml(t.node_name || '')}</td>
        <td class="py-1 pr-3 font-mono text-xs">${escapeHtml(t.port)}</td>
        <td class="py-1 text-xs text-slate-500">${t.mac_count} MACs</td></tr>`).join('');

    const canEditTopo = isAdmin() || isTenantAdmin();
    c.innerHTML = `<div class="space-y-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div class="flex flex-wrap items-center gap-4">${legend}</div>
    <div class="flex items-center gap-3">
      <label class="flex items-center gap-1.5 text-xs text-slate-500" title="Draw a link for a switch port that has learned exactly one MAC belonging to a known device. A guess, not an advertised adjacency.">
        <input type="checkbox" id="nw-topo-infer" ${infer ? 'checked' : ''}> Infer links from MAC tables
      </label>
      <label class="flex items-center gap-1.5 text-xs text-slate-500" title="Include devices known only by a MAC address (hosts, VMs, phones). Off by default: the map shows infrastructure only.">
        <input type="checkbox" id="nw-topo-endpoints"> Show endpoints
      </label>
      <button id="nw-topo-expand" class="px-2 py-1.5 text-xs font-semibold rounded border border-slate-300 text-slate-600 hover:bg-slate-50">Expand all</button>
      <button id="nw-topo-collapse" class="px-2 py-1.5 text-xs font-semibold rounded border border-slate-300 text-slate-600 hover:bg-slate-50">Collapse all</button>
      <button id="nw-topo-refresh" class="px-3 py-1.5 text-xs font-semibold rounded bg-[#01A982] text-white hover:bg-[#018f6f]">Refresh from devices</button>
    </div>
  </div>
  <div class="flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-500">
    <span><b class="text-slate-700">${st.infra_nodes ?? st.nodes ?? 0}</b> infrastructure / <b class="text-slate-700">${st.nodes || 0}</b> devices</span>
    <span><b class="text-slate-700">${st.edges || 0}</b> links</span>
    <span><b class="text-slate-700">${st.nodes_without_lldp || 0}</b> without LLDP</span>
    <span><b class="text-slate-700">${st.trunk_ports || 0}</b> trunk/uplink ports</span>
    <span>NetBox inventory: <b class="text-slate-700">${graph.netbox ? 'included' : 'unavailable'}</b></span>
  </div>
  <div id="nw-topo-svg" class="border border-slate-200 rounded bg-white overflow-hidden">${_nwTopoSvg(graph, _nwTopoView())}</div>
  ${trunks ? `<div>
    <h4 class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Trunk / uplink ports</h4>
    <p class="text-xs text-slate-400 mb-2">These ports carry a whole downstream segment, so what is <em>directly</em> attached can't be inferred. Declare the link below if you know it.</p>
    <table class="w-full text-left"><tbody>${trunks}</tbody></table></div>` : ''}
  ${canEditTopo ? `<div class="border-t border-slate-200 pt-4 space-y-3">
    <h4 class="text-xs font-bold text-slate-500 uppercase tracking-wider">Devices that don't speak LLDP</h4>
    <p class="text-xs text-slate-400">Declare gear the fleet can't discover (unmanaged switches, media converters, PDUs, cameras). Give a MAC and it will be matched against switch MAC tables automatically — that is what puts it on the map.</p>
    <div id="nw-topo-manual"></div>
  </div>` : ''}
</div>`;

    const refreshBtn = document.getElementById('nw-topo-refresh');
    if (refreshBtn) refreshBtn.onclick = () => _renderNwTopologyTab({ refresh: true });
    const inferBox = document.getElementById('nw-topo-infer');
    if (inferBox) inferBox.onchange = () => {
        window._nwTopoInfer = inferBox.checked;
        _renderNwTopologyTab();
    };
    _nwTopoBindView();
    if (canEditTopo) _renderNwTopologyManual();
}

async function _renderNwTopologyManual() {
    const host = document.getElementById('nw-topo-manual');
    if (!host) return;
    const tenantQs = currentTenant && currentTenant !== 'default'
        ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    let cfg = { devices: [], links: [] };
    try {
        const r = await fetch(`/api/nw/topology/manual${tenantQs}`);
        if (r.ok) cfg = await r.json();
    } catch (e) { /* keep the empty editor rather than blanking the map */ }
    window._nwTopoManual = cfg;

    const names = ((window._nwTopo || {}).nodes || [])
        .map(n => n.name).filter(Boolean).sort();
    const options = names.map(n => `<option value="${escapeHtml(n)}"></option>`).join('');

    const devRows = (cfg.devices || []).map(d => `<tr class="border-t border-slate-100">
        <td class="py-1 pr-3 text-xs">${escapeHtml(d.name)}</td>
        <td class="py-1 pr-3 font-mono text-xs text-slate-500">${escapeHtml(d.mac || '')}</td>
        <td class="py-1 pr-3 font-mono text-xs text-slate-500">${escapeHtml(d.ip || '')}</td>
        <td class="py-1 pr-3 text-xs text-slate-500">${escapeHtml(d.note || '')}</td>
        <td class="py-1 text-right"><button data-del-dev="${escapeHtml(d.id)}" class="text-xs text-red-500 hover:underline">Remove</button></td>
      </tr>`).join('');
    const linkRows = (cfg.links || []).map(l => `<tr class="border-t border-slate-100">
        <td class="py-1 pr-3 text-xs">${escapeHtml(l.a)}${l.a_port ? ` <span class="text-slate-400 font-mono">${escapeHtml(l.a_port)}</span>` : ''}</td>
        <td class="py-1 pr-3 text-xs">${escapeHtml(l.b)}${l.b_port ? ` <span class="text-slate-400 font-mono">${escapeHtml(l.b_port)}</span>` : ''}</td>
        <td class="py-1 pr-3 text-xs text-slate-500">${escapeHtml(l.note || '')}</td>
        <td class="py-1 text-right"><button data-del-link="${escapeHtml(l.id)}" class="text-xs text-red-500 hover:underline">Remove</button></td>
      </tr>`).join('');

    const inp = 'px-2 py-1 text-xs border border-slate-300 rounded';
    host.innerHTML = `<div class="grid md:grid-cols-2 gap-6">
  <div>
    <table class="w-full text-left"><tbody>${devRows || `<tr><td class="py-1 text-xs text-slate-400 italic">None declared</td></tr>`}</tbody></table>
    <div class="flex flex-wrap gap-2 mt-2">
      <input id="nw-topo-dev-name" class="${inp}" placeholder="Name">
      <input id="nw-topo-dev-mac" class="${inp}" placeholder="MAC (optional)">
      <input id="nw-topo-dev-ip" class="${inp}" placeholder="IP (optional)">
      <input id="nw-topo-dev-note" class="${inp}" placeholder="Note">
      <button id="nw-topo-dev-add" class="px-3 py-1 text-xs font-semibold rounded bg-slate-700 text-white">Add device</button>
    </div>
  </div>
  <div>
    <h5 class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Declared links</h5>
    <table class="w-full text-left"><tbody>${linkRows || `<tr><td class="py-1 text-xs text-slate-400 italic">None declared</td></tr>`}</tbody></table>
    <datalist id="nw-topo-names">${options}</datalist>
    <div class="flex flex-wrap gap-2 mt-2">
      <input id="nw-topo-link-a" list="nw-topo-names" class="${inp}" placeholder="Device A">
      <input id="nw-topo-link-ap" class="${inp} w-20" placeholder="Port">
      <input id="nw-topo-link-b" list="nw-topo-names" class="${inp}" placeholder="Device B">
      <input id="nw-topo-link-bp" class="${inp} w-20" placeholder="Port">
      <input id="nw-topo-link-note" class="${inp}" placeholder="Note">
      <button id="nw-topo-link-add" class="px-3 py-1 text-xs font-semibold rounded bg-slate-700 text-white">Add link</button>
    </div>
  </div>
</div>`;

    const val = id => (document.getElementById(id).value || '').trim();
    const save = async (body) => {
        try {
            const r = await fetch('/api/nw/topology/manual', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign(
                    { tenant: currentTenant && currentTenant !== 'default' ? currentTenant : undefined },
                    body)),
            });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            showToast('Topology updated');
            _renderNwTopologyTab();
        } catch (e) {
            showToast(`Could not save: ${e.message}`, 'error');
        }
    };

    document.getElementById('nw-topo-dev-add').onclick = () => {
        const name = val('nw-topo-dev-name');
        if (!name) { showToast('A name is required', 'error'); return; }
        save({ devices: (cfg.devices || []).concat([{
            name, mac: val('nw-topo-dev-mac'), ip: val('nw-topo-dev-ip'),
            note: val('nw-topo-dev-note') }]) });
    };
    document.getElementById('nw-topo-link-add').onclick = () => {
        const a = val('nw-topo-link-a'), b = val('nw-topo-link-b');
        if (!a || !b) { showToast('Both ends are required', 'error'); return; }
        save({ links: (cfg.links || []).concat([{
            a, a_port: val('nw-topo-link-ap'), b, b_port: val('nw-topo-link-bp'),
            note: val('nw-topo-link-note') }]) });
    };
    host.querySelectorAll('[data-del-dev]').forEach(btn => {
        btn.onclick = () => save({
            devices: (cfg.devices || []).filter(d => d.id !== btn.dataset.delDev) });
    });
    host.querySelectorAll('[data-del-link]').forEach(btn => {
        btn.onclick = () => save({
            links: (cfg.links || []).filter(l => l.id !== btn.dataset.delLink) });
    });
}
async function _renderNwScanTab() {
    const c = document.getElementById('nw-table-container');
    if (!c) return;
    // The ADMIN tenant ("default") is a real tenant: an nw spoke bound to it
    // is offered by /api/nw/tenant-config and its scan config lives under
    // nw_tenant_cfg["default"]. Only prompt when no tenant is selected at all.
    if (isAdmin() && !currentTenant) {
        c.innerHTML = `<div class="py-12 text-center space-y-3">
            <p class="text-slate-600 text-sm font-semibold">Select a tenant to configure network scans</p>
            <p class="text-slate-400 text-xs max-w-md mx-auto">Scan settings, schedules and credential sets all belong to a specific tenant. Choose a tenant from the tenant picker to view and edit its scan configuration.</p>
        </div>`;
        return;
    }
    c.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Loading scan settings…</div>`;

    // Pull the tenant's effective config + its visible scan-credential sets in
    // parallel. Both are tenant-scoped server-side (tenant-admins see only their
    // own tenant + shared).
    let cfg = {}, creds = [];
    const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    try {
        const [cfgR, credR] = await Promise.all([
            setupFetch(`/api/nw/tenant-config${tenantQs}`),
            // Same tenant scope as the config — otherwise an admin sees every
            // tenant's credential sets listed under whichever tenant is selected.
            setupFetch(`/setup/nw-scan-credentials${tenantQs}`),
        ]);
        if (cfgR.ok) cfg = await cfgR.json();
        if (credR.ok) creds = (await credR.json()).instances || [];
    } catch (e) {
        c.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Could not load scan settings: ${escapeHtml(e.message)}</div>`;
        return;
    }
    window._nwScanCfg = cfg;

    const scan = cfg.scan || {};
    const poll = cfg.poll || {};
    const sched = cfg.scan_schedule || {};
    const chk = v => v ? 'checked' : '';
    const srcs = new Set(scan.ip_sources || ['netbox']);
    const selectedCreds = new Set((scan.credential_ids || []).map(String));

    const credRows = creds.length
        ? creds.map(cr => `<label class="flex items-center gap-2 text-sm text-slate-600">
            <input type="checkbox" class="nwt-cred rounded border-slate-300 text-[#01A982] focus:ring-green-500" value="${escapeHtml(String(cr.id))}" ${selectedCreds.has(String(cr.id)) ? 'checked' : ''}>
            <span class="font-mono">${escapeHtml(cr.name || cr.id)}</span>${cr.username ? `<span class="text-slate-400">· ${escapeHtml(cr.username)}</span>` : ''}
          </label>`).join('')
        : `<p class="text-xs text-slate-400 italic">No scan credential sets belong to this tenant (or the shared tenant). You can still run a <b>discovery-only</b> scan with none selected — it reports which hosts are reachable and what management ports they expose, but cannot identify or add devices. To identify devices, add a set in Setup → Network Devices → Scan Credentials, bind it to <b>this</b> tenant (or the shared tenant so every tenant can use it), and point it at a Credential Vault entry. Note a vault credential on its own is not enough — the scan uses the credential <em>set</em> that references it.</p>`;

    const opt = (opts, cur) => opts.map(([v, l]) =>
        `<option value="${escapeHtml(v)}" ${String(cur) === v ? 'selected' : ''}>${escapeHtml(l)}</option>`).join('');
    const pollVal = (k) => (poll.overridden && poll.overridden[k]) ? String(poll[k]) : '';

    // Agent picker — the tenant's own nw agents plus any shared one. Scans only
    // ever run on these; an agent belonging to another tenant is never offered.
    const nwSpokes = cfg.spokes || [];
    const spokeRows = nwSpokes.length
        ? `<select id="nwt-spoke" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
             ${nwSpokes.map(s => `<option value="${escapeHtml(s.spoke_id)}" ${String(scan.spoke_id || '') === s.spoke_id ? 'selected' : ''} ${s.connected ? '' : 'disabled'}>
               ${escapeHtml(s.name)} — ${s.scope === 'shared' ? 'shared' : 'your tenant'}${s.connected ? '' : ' (offline)'}
             </option>`).join('')}
           </select>`
        : `<p class="text-xs text-amber-600 italic">No Network Devices agent is deployed in this tenant, and no shared agent is available. Deploy the nw module to scan.</p>`;

    const card = 'bg-white rounded-xl border border-slate-200 p-5';
    const lblCls = 'block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1';
    const inCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selCls = inCls;

    c.innerHTML = `<div class="space-y-5 max-w-4xl">
      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Network Discovery Scan</h3>
        <p class="text-xs text-slate-400 mb-4">Discover manageable devices on your network and (optionally) add them to your fleet. Scans run on your tenant's Network Devices spoke.</p>
        <div class="mb-4">
          <p class="${lblCls}">Scan Agent</p>
          ${spokeRows}
        </div>
        <div class="mb-4">
          <p class="${lblCls}">Scan Credential Sets</p>
          <div id="nwt-creds" class="space-y-1.5">${credRows}</div>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-crawl" class="rounded border-slate-300 text-[#01A982]" ${chk(scan.crawl)}> Crawl LLDP neighbors</label>
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-snmp" class="rounded border-slate-300 text-[#01A982]" ${chk(scan.try_snmp !== false)}> Try SNMP</label>
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-autoadd" class="rounded border-slate-300 text-[#01A982]" ${chk(scan.auto_add)}> Auto-add discovered</label>
        </div>
        <div class="mb-4">
          <p class="${lblCls}">IP Sources</p>
          <div class="flex flex-wrap gap-4">
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-netbox" class="rounded border-slate-300 text-[#01A982]" ${chk(srcs.has('netbox'))}> NetBox prefixes</label>
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-nac" class="rounded border-slate-300 text-[#01A982]" ${chk(srcs.has('nac'))}> NAC endpoints</label>
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-dhcp" class="rounded border-slate-300 text-[#01A982]" ${chk(srcs.has('dhcp'))}> DHCP leases</label>
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-dns" class="rounded border-slate-300 text-[#01A982]" ${chk(srcs.has('dns'))}> DNS records</label>
          </div>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
          <div><label class="${lblCls}">Extra Subnets (optional)</label><textarea id="nwt-subnets" rows="2" placeholder="10.0.0.0/24, 192.168.1.0/24" class="${inCls} font-mono">${escapeHtml((scan.subnets || []).join(', '))}</textarea></div>
          <div><label class="${lblCls}">Extra Targets (optional)</label><textarea id="nwt-targets" rows="2" placeholder="10.0.0.1, 10.0.0.2" class="${inCls} font-mono"></textarea></div>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
          <div><label class="${lblCls}">TCP Ports</label><input type="text" id="nwt-ports" value="${escapeHtml((scan.tcp_ports || [22,443,80,23]).join(', '))}" class="${inCls}"></div>
          <div><label class="${lblCls}" title="Scans larger than this are split into batches of this size and run in parallel">Batch size</label><input type="number" id="nwt-maxtargets" min="1" max="4096" value="${escapeHtml(String(scan.max_targets || 1024))}" class="${inCls}"></div>
          <div><label class="${lblCls}">Concurrency</label><input type="number" id="nwt-concurrency" min="1" max="128" value="${escapeHtml(String(scan.concurrency || 32))}" class="${inCls}"></div>
        </div>
        <div class="flex flex-wrap gap-2 pt-2 border-t border-slate-100">
          <button onclick="saveNwTenantScanConfig(this)" class="px-4 py-2 rounded-md bg-[#01A982] text-white text-sm font-bold hover:bg-[#018f6f]" title="Save tenant network scan configuration">Save config</button>
          <button onclick="runNwTenantScan(this, true)" class="px-4 py-2 rounded-md bg-slate-100 text-slate-700 text-sm font-bold hover:bg-slate-200" title="Run discovery scan in preview mode without adding devices to inventory">Preview scan</button>
          <button onclick="runNwTenantScan(this, false)" class="px-4 py-2 rounded-md bg-blue-600 text-white text-sm font-bold hover:bg-blue-700" title="Execute discovery scan and automatically enroll discovered devices">Scan &amp; add</button>
        </div>
        <div id="nwt-results" class="text-xs mt-3"></div>
      </div>

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Background Supernet Sweep</h3>
        <p class="text-xs text-slate-400 mb-3">Slowly probes the rest of each NetBox supernet (e.g. a /16 split into /24s) for unknown hosts not covered by DNS, DHCP, NAC, child subnets or your extra targets. Runs separately from scheduled scans, reports only, and never adds devices.</p>
        <div id="nwt-sweep" class="text-xs text-slate-400 italic">Loading…</div>
      </div>
      ${(setTimeout(() => _nwtLoadSweep(), 0), '')}

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Recurring Scan Schedule</h3>
        <p class="text-xs text-slate-400 mb-4">Automatically re-scan your network on a schedule. Preview-only runs report discoveries without adding them.</p>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-sched-enabled" class="rounded border-slate-300 text-[#01A982]" ${chk(sched.enabled)}> Enable schedule</label>
          <div><label class="${lblCls}">Interval</label><select id="nwt-sched-interval" class="${selCls}">${opt(_NW_SCHED_INTERVALS, sched.interval_seconds || 0)}</select></div>
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-sched-dryrun" class="rounded border-slate-300 text-[#01A982]" ${chk(sched.dry_run !== false)}> Preview only (don't add)</label>
        </div>
      </div>

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Poll Cadence &amp; Anti-Stampede</h3>
        <p class="text-xs text-slate-400 mb-4">Tune how your NW spoke polls your devices. Leave a control on "Inherit global" to use the platform default.</p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div><label class="${lblCls}">Default Poll Interval</label><select id="nwt-poll-default" class="${selCls}">${opt([['', 'Inherit global'], ['900', '15 minutes'], ['3600', '1 hour'], ['21600', '6 hours'], ['43200', '12 hours'], ['86400', 'Daily']], pollVal('default_interval'))}</select></div>
          <div><label class="${lblCls}">Poll Jitter</label><select id="nwt-poll-jitter" class="${selCls}">${opt(_NW_JITTER_OPTS, pollVal('jitter_frac'))}</select></div>
          <div><label class="${lblCls}">Max Devices / Tick</label><select id="nwt-poll-maxtick" class="${selCls}">${opt([['', 'Inherit global'], ['5', '5'], ['10', '10'], ['25', '25'], ['50', '50'], ['100', '100']], pollVal('max_per_tick'))}</select></div>
          <div><label class="${lblCls}">Max Concurrent Polls</label><select id="nwt-poll-maxconc" class="${selCls}">${opt([['', 'Inherit global'], ['2', '2'], ['5', '5'], ['10', '10'], ['20', '20'], ['50', '50']], pollVal('max_concurrency'))}</select></div>
        </div>
        <div class="pt-3 mt-3 border-t border-slate-100">
          <button onclick="saveNwTenantPollSchedule(this)" class="px-4 py-2 rounded-md bg-[#01A982] text-white text-sm font-bold hover:bg-[#018f6f]" title="Save recurring scan schedule and polling cadence">Save schedule &amp; cadence</button>
        </div>
      </div>

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Scheduled Scans Already Set Up</h3>
        <p class="text-xs text-slate-400 mb-4">Every recurring scan configured across the tenants you can see — so you don't have to switch tenant and read one card at a time.</p>
        <div id="nwt-sched-list"><p class="text-xs text-slate-400 italic">Loading…</p></div>
      </div>
    </div>`;
    _loadNwScanSchedules();
}

// Fetch + render every configured recurring scan the caller may see. Separate
// from the card markup so it can be refreshed after a schedule is saved without
// repainting the whole tab.
async function _loadNwScanSchedules() {
    const el = document.getElementById('nwt-sched-list');
    if (!el) return;
    try {
        const r = await setupFetch('/api/nw/scan-schedules');
        if (!r.ok) { el.innerHTML = `<p class="text-xs text-amber-600 italic">Could not load scheduled scans (${r.status}).</p>`; return; }
        const d = await r.json();
        el.innerHTML = _nwScanSchedulesHtml(d);
    } catch (e) {
        el.innerHTML = `<p class="text-xs text-amber-600 italic">Could not load scheduled scans: ${escapeHtml(e.message)}</p>`;
    }
}

function _nwSchedEvery(secs) {
    const n = Number(secs || 0);
    if (!n) return 'off';
    const m = _NW_SCHED_INTERVALS.find(([v]) => Number(v) === n);
    if (m) return m[1].toLowerCase();
    if (n % 86400 === 0) return `every ${n / 86400}d`;
    if (n % 3600 === 0) return `every ${n / 3600}h`;
    return `every ${Math.round(n / 60)}m`;
}

// "in 3h 20m" / "2h ago" for the scheduler's wall-clock timestamps (seconds).
function _nwSchedWhen(ts, { future } = {}) {
    if (!ts) return '—';
    const diff = Math.abs(Date.now() / 1000 - Number(ts));
    const h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60);
    const span = h ? `${h}h ${m}m` : `${m}m`;
    return future ? `in ${span}` : `${span} ago`;
}

function _nwScanSchedulesHtml(d) {
    const rows = (d.schedules || []).filter(s => s.enabled);
    if (!rows.length) {
        return `<p class="text-xs text-slate-400 italic">No recurring scans are enabled${(d.schedules || []).length ? ' on any tenant you can see' : ''}. Enable one on the card above.</p>`;
    }
    // The scheduler's last/next-run state lives in hub memory, so a restart
    // clears it and every schedule re-defers a full interval. Say so rather
    // than letting a blank "last run" read as "it never ran".
    const note = d.runtime_since_restart
        ? ''
        : `<p class="text-[11px] text-slate-400 italic mb-2">The hub has not completed a scheduled run since it last restarted — last/next run are tracked in memory and each schedule re-defers one full interval after a restart.</p>`;
    let html = note + '<table class="w-full text-left"><thead><tr class="text-slate-400 uppercase text-[10px]"><th class="py-1">Tenant</th><th>Cadence</th><th>Mode</th><th>Credentials</th><th>Agent</th><th>Last run</th><th>Next due</th></tr></thead><tbody>';
    for (const s of rows) {
        const mode = s.dry_run
            ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 text-slate-600" title="Reports discoveries without adding them">preview</span>'
            : '<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 text-amber-700" title="Adds identified devices to the fleet automatically">auto-add</span>';
        const creds = s.discovery_only
            ? '<span class="text-amber-600" title="No credential sets selected — this run probes reachability and open ports only, and can never add a device">discovery only</span>'
            : escapeHtml(s.credential_names.join(', '));
        const agent = s.spoke_id
            ? (s.spoke_connected ? '<span class="text-emerald-600">connected</span>' : '<span class="text-red-500" title="This schedule will be skipped while its agent is offline">offline</span>')
            : '<span class="text-slate-400" title="No agent pinned — the hub picks a connected agent for this tenant">auto</span>';
        const last = s.last_status
            ? `${escapeHtml(_nwSchedWhen(s.last_run_at))} · ${escapeHtml(s.last_status)}${s.last_added ? ` (+${s.last_added})` : ''}`
            : _nwSchedWhen(s.last_run_at);
        html += `<tr class="border-t border-slate-100 text-slate-600"><td class="py-1 font-semibold">${escapeHtml(s.tenant_name)}</td><td>${escapeHtml(_nwSchedEvery(s.interval_seconds))}</td><td>${mode}</td><td class="text-xs">${creds}</td><td class="text-xs">${agent}</td><td class="text-xs">${last}</td><td class="text-xs">${escapeHtml(_nwSchedWhen(s.next_due_at, { future: true }))}</td></tr>`;
        if (s.last_error) {
            html += `<tr class="text-[11px] text-red-500"><td colspan="7" class="pb-1 pl-2">last error: ${escapeHtml(s.last_error)}</td></tr>`;
        }
    }
    return html + '</tbody></table>';
}

function _nwtSources() {
    const s = [];
    if (document.getElementById('nwt-src-netbox')?.checked) s.push('netbox');
    if (document.getElementById('nwt-src-nac')?.checked) s.push('nac');
    if (document.getElementById('nwt-src-dhcp')?.checked) s.push('dhcp');
    if (document.getElementById('nwt-src-dns')?.checked) s.push('dns');
    return s;
}
function _nwtSelectedCreds() {
    return Array.from(document.querySelectorAll('.nwt-cred'))
        .filter(el => el.checked).map(el => el.value);
}
function _nwtParseList(str) {
    return String(str || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
}
function _nwtScanConfigBody() {
    return {
        crawl: !!document.getElementById('nwt-crawl')?.checked,
        try_snmp: !!document.getElementById('nwt-snmp')?.checked,
        spoke_id: document.getElementById('nwt-spoke')?.value || '',
        auto_add: !!document.getElementById('nwt-autoadd')?.checked,
        credential_ids: _nwtSelectedCreds(),
        ip_sources: _nwtSources(),
        subnets: _nwtParseList(document.getElementById('nwt-subnets')?.value),
        tcp_ports: _nwtParseList(document.getElementById('nwt-ports')?.value)
            .map(p => parseInt(p, 10)).filter(n => !isNaN(n)),
        max_targets: parseInt(document.getElementById('nwt-maxtargets')?.value, 10) || 1024,
        concurrency: parseInt(document.getElementById('nwt-concurrency')?.value, 10) || 32,
    };
}

async function saveNwTenantScanConfig(btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    const body = { scan: _nwtScanConfigBody() };
    if (currentTenant) body.tenant = currentTenant;
    try {
        const r = await setupFetch('/api/nw/tenant-config', {
            method: 'POST', body: JSON.stringify(body),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) showToast('Scan configuration saved.', 'success');
        else showToast('Failed to save: ' + (d.detail || r.status), 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save config'; }
    }
}

async function saveNwTenantPollSchedule(btn) {
    const numOrNull = (id, parse) => {
        const el = document.getElementById(id);
        if (!el || el.value === '') return null;
        const n = parse(el.value);
        return isNaN(n) ? null : n;
    };
    const body = {
        poll: {
            default_interval: numOrNull('nwt-poll-default', v => parseInt(v, 10)),
            jitter_frac: numOrNull('nwt-poll-jitter', parseFloat),
            max_per_tick: numOrNull('nwt-poll-maxtick', v => parseInt(v, 10)),
            max_concurrency: numOrNull('nwt-poll-maxconc', v => parseInt(v, 10)),
        },
        scan_schedule: {
            enabled: !!document.getElementById('nwt-sched-enabled')?.checked,
            interval_seconds: parseInt(document.getElementById('nwt-sched-interval')?.value, 10) || 0,
            dry_run: !!document.getElementById('nwt-sched-dryrun')?.checked,
        },
    };
    if (currentTenant) body.tenant = currentTenant;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/api/nw/tenant-config', {
            method: 'POST', body: JSON.stringify(body),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) { showToast(`Schedule & cadence saved${d.pushed ? ` (pushed to ${d.pushed} spoke${d.pushed === 1 ? '' : 's'})` : ''}.`, 'success'); _loadNwScanSchedules(); }
        else showToast('Failed to save: ' + (d.detail || r.status), 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save schedule & cadence'; }
    }
}

async function _nwtLoadSweep() {
    const box = document.getElementById('nwt-sweep');
    if (!box) return;
    try {
        const r = await setupFetch('/api/nw/sweep' + (currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : ''));
        const d = await r.json();
        const pct = d.total ? Math.min(100, Math.round(100 * (d.cursor || 0) / d.total)) : 0;
        const rows = (d.discovered || []).slice(0, 200).map(x => `<tr><td class="py-1 pr-3 font-mono">${escapeHtml(x.address)}</td><td class="pr-3">${escapeHtml((x.open_ports || []).join(', ') || '—')}</td><td>${x.last_seen ? new Date(x.last_seen * 1000).toLocaleString() : ''}</td></tr>`).join('');
        box.className = 'text-xs text-slate-600';
        box.innerHTML = `<div class="flex flex-wrap items-center gap-3 mb-2">
            <label class="flex items-center gap-2"><input type="checkbox" ${d.enabled ? 'checked' : ''} onchange="nwtSweepAction({enabled: this.checked})"> Enable sweep</label>
            <button onclick="nwtSweepAction({run: true})" class="px-3 py-1 rounded bg-slate-100 text-slate-700 font-bold hover:bg-slate-200">Probe next batch now</button>
            <button onclick="nwtSweepAction({reset: true})" class="px-3 py-1 rounded bg-slate-100 text-slate-700 font-bold hover:bg-slate-200">Restart cycle</button>
            <span>${d.total ? `Progress ${pct}% of ${d.total} addresses · cycles ${d.cycles || 0}` : 'No supernet space to sweep yet'}${d.last_status ? ` · last: ${escapeHtml(d.last_status)}` : ''}${d.last_error ? ` (${escapeHtml(d.last_error)})` : ''}</span></div>
            ${rows ? `<table class="w-full text-left"><thead><tr class="text-slate-400"><th>Unknown host</th><th>Open ports</th><th>Last seen</th></tr></thead><tbody>${rows}</tbody></table>` : '<p class="italic text-slate-400">No unknown hosts found yet.</p>'}`;
    } catch (e) {
        box.textContent = 'Sweep status unavailable: ' + e.message;
    }
}

async function nwtSweepAction(body) {
    if (currentTenant) body.tenant = currentTenant;
    try {
        const r = await setupFetch('/api/nw/sweep', { method: 'POST', body: JSON.stringify(body) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { showToast(d.detail || 'Sweep action failed', 'error'); return; }
        if (body.run) showToast('Sweep batch: ' + ((d.run || {}).status || 'done'), 'success');
    } catch (e) { showToast(e.message, 'error'); }
    _nwtLoadSweep();
}

async function runNwTenantScan(btn, dryRun) {
    const out = document.getElementById('nwt-results');
    const label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = dryRun ? 'Scanning…' : 'Scanning & adding…'; }
    if (out) out.innerHTML = '<p class="text-slate-400 italic animate-pulse">Scanning — this can take a while for large subnets…</p>';
    const body = {
        dry_run: !!dryRun,
        auto_add: !dryRun,
        crawl: !!document.getElementById('nwt-crawl')?.checked,
        credential_ids: _nwtSelectedCreds(),
        ip_sources: _nwtSources(),
        subnets: _nwtParseList(document.getElementById('nwt-subnets')?.value),
        targets: _nwtParseList(document.getElementById('nwt-targets')?.value),
        max_targets: parseInt(document.getElementById('nwt-maxtargets')?.value, 10) || 1024,
    };
    const _sp = document.getElementById('nwt-spoke')?.value;
    if (_sp) body.spoke_id = _sp;
    if (currentTenant) body.tenant = currentTenant;
    try {
        const r = await setupFetch('/setup/nw-scan/run', {
            method: 'POST', body: JSON.stringify(body),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { if (out) out.innerHTML = `<p class="text-red-500">Scan failed: ${escapeHtml(d.detail || String(r.status))}</p>`; return; }
        _renderNwScanResults2(out, d);
        if (!dryRun && (d.added || []).length) showToast(`Added ${d.added.length} discovered device(s).`, 'success');
    } catch (e) {
        if (out) out.innerHTML = `<p class="text-red-500">Error: ${escapeHtml(e.message)}</p>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = label; }
    }
}

// Tenant-tab variant of _renderNwScanResults (renders into a passed element).
function _renderNwScanResults2(out, d) {
    if (!out) return;
    if (d.status === 'ok' && d.message && !(d.identified || []).length) {
        out.innerHTML = `<p class="text-slate-500 italic mt-1">${escapeHtml(d.message)}</p>`;
        return;
    }
    out.innerHTML = _nwScanResultsHtml(d);
}

// Render the device list for one category (click a row to open its detail).
// Kept separate from loadNwData so the detail back-button can repaint the list
// without a refetch. `counts` (per-category fleet totals) feeds only the
// empty-state hint (points at where devices actually are); the always-visible
// top-level category tabs (VIEW_SUBMENUS.nw) are the single category nav.
function _renderNwDeviceList(category, devices, counts) {
    const container = document.getElementById('nw-table-container');
    if (!container) return;
    counts = counts || (window._nwView && window._nwView.counts) || {};
    const CATEGORIES = ['Gateways', 'Switches', 'Firewalls', 'Other'];
    const addServerRow = `<div class="flex justify-end mb-2">${addServerButtonHtml('nw', 'Network Devices')}</div>`;
    if (!devices.length) {
        // Point the user at where devices actually are instead of a dead end.
        const elsewhere = CATEGORIES.filter(c => c !== category && counts[c]);
        const hint = elsewhere.length
            ? `No ${escapeHtml(category.toLowerCase())} configured — devices are under ${elsewhere.map(c => `<button onclick="setSubView('${c}')" class="text-[#01A982] hover:underline font-semibold">${escapeHtml(c)} (${counts[c]})</button>`).join(', ')}.`
            : `No ${escapeHtml(category.toLowerCase())} configured. Add one in Setup → Network Devices.`;
        container.innerHTML = addServerRow +
            `<div class="py-12 text-center text-slate-400 italic">${hint}</div>`;
        return;
    }
    const keys = ['device', 'object_type', 'transport', 'address', 'reachable'];
    const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
    const rows = devices.map(it => {
        const typeLabel = _NW_OBJECT_TYPES[it.object_type] || it.object_type || '—';
        const transport = _NW_TRANSPORTS[it.transport] || it.transport || 'auto';
        const reachable = it.reachable;
        const rcell = reachable === true || reachable === 'up'
            ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">up</span>'
            : reachable === false || reachable === 'down'
                ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-red-100 text-red-700">down</span>'
                : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-100 text-amber-700" title="Reachability unknown — the Network Devices spoke is offline, so up/down can't be probed">unknown</span>`;
        // event.stopPropagation() keeps the Poll/Configure buttons from also
        // triggering the row's drill-into-detail click.
        const cfg = (isAdmin() || isTenantAdmin())
            ? `<button onclick="event.stopPropagation();pollNwDevice('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}', this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium mr-3" title="Poll device interfaces and status now">Poll Now</button>` +
              `<button onclick="event.stopPropagation();showNwConfigModal('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium" title="Configure device connection parameters">Configure</button>`
            : '';
        return `<tr onclick="nwOpenDevice('${escJsAttr(it.id)}')" class="hover:bg-slate-50 transition-colors cursor-pointer" title="View device details">
            <td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(it.name || it.id)}${(it.serial || it.mac) ? `<div class="text-[10px] font-mono font-normal text-slate-400 mt-0.5">${it.serial ? 'SN ' + escapeHtml(String(it.serial)) : ''}${(it.serial && it.mac) ? ' · ' : ''}${it.mac ? escapeHtml(String(it.mac)) : ''}</div>` : ''}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(typeLabel)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(transport)}</td>
            <td class="px-4 py-3 text-slate-600 font-mono text-xs">${escapeHtml(it.address || '—')}</td>
            <td class="px-4 py-3">${rcell}</td>
            <td class="px-4 py-3 text-right whitespace-nowrap">${cfg}<span class="text-slate-300 ml-2">›</span></td>
        </tr>`;
    }).join('');
    container.innerHTML = addServerRow + `
        <div class="space-y-4">
            <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}<th class="px-4 py-3"></th></tr></thead>
                    <tbody class="divide-y divide-slate-200">${rows}</tbody>
                </table>
            </div>
        </div>`;
}

// Storage (TrueNAS) — Appliances → fleet list (/api/truenas/appliances);
// Pools / Datasets / Shares / Disks / Alerts / Capacity → per-appliance fetch
// merged across the fleet (/api/truenas/{id}/{pools|datasets|shares|disks|alerts|
// capacity}), each row tagged with its source appliance (_applianceId /
// appliance). ?tenant= scopes the server-side fleet filter to the selected
// tenant. Spoke-down serves the hub cache twin (no 503) — the route falls back
// to truenas_data.json when no spoke is connected.
async function loadTruenasData(subMenu) {
    const container = document.getElementById('truenas-table-container');
    if (!container) return;
    subMenu = subMenu || currentSubView;
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${subMenu} data…</div>`;

    // Suppress the per-view "+ Add" action strip; appliances are managed on
    // Setup → TrueNAS Appliances.
    const actions = document.getElementById('top-nav-actions');
    if (actions) actions.innerHTML = '';

    const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';

    const _endpointFor = sm => {
        if (sm === 'Pools') return 'pools';
        if (sm === 'Datasets') return 'datasets';
        if (sm === 'Shares') return 'shares';
        if (sm === 'Disks') return 'disks';
        if (sm === 'Alerts') return 'alerts';
        if (sm === 'Capacity') return 'capacity';
        return null;
    };

    // Normalize a fleet response (raw array or envelope) into a row list.
    const _fleetRows = data => {
        if (Array.isArray(data)) return data;
        if (data && typeof data === 'object') {
            if (Array.isArray(data.data)) return data.data;
            if (data.appliances && Array.isArray(data.appliances.data)) return data.appliances.data;
        }
        return [];
    };
    // Normalize a per-appliance endpoint response into the payload list/dict.
    const _extract = data => {
        if (Array.isArray(data)) return data;
        if (data && typeof data === 'object') {
            if (Array.isArray(data.data)) return data.data;
            if (data.data && typeof data.data === 'object') return data.data;
            if (data.payload && Array.isArray(data.payload.data)) return data.payload.data;
        }
        return [];
    };

    try {
        // ---- Appliance fleet list ----
        if (subMenu === 'Appliances') {
            let r;
            try {
                r = await fetch(`/api/truenas/appliances${tenantQs}`);
            } catch (e) {
                container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Storage spoke not connected. Approve one in Setup → Spokes & Agents, or add appliances in Setup → TrueNAS Appliances.</div>`;
                return;
            }
            if (!r.ok) {
                container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Storage spoke not connected (HTTP ${r.status}).</div>`;
                return;
            }
            const data = await r.json();
            const items = _fleetRows(data);
            if (!items.length) {
                container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No TrueNAS appliances configured. Add one in Setup → TrueNAS Appliances.</div>`;
                return;
            }
            const headers = ['NAME', 'HOST', 'TYPE', 'VERSION', 'STATUS', ''].map(h => `<th class="px-4 py-3">${h}</th>`).join('');
            const rows = items.map(it => {
                const info = (it.info && typeof it.info === 'object') ? it.info : {};
                const reachable = it.reachable;
                const rcell = reachable === true || reachable === 'up'
                    ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">online</span>'
                    : reachable === false || reachable === 'down'
                        ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-red-100 text-red-700">offline</span>'
                        : `<span class="text-slate-400 text-xs">—</span>`;
                const poll = isAdmin()
                    ? `<button onclick="pollTruenasAppliance('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}', this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium mr-3" title="Trigger immediate polling of pools, datasets, and disks">Poll Now</button>`
                    : '';
                return `<tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(it.name || it.id)}</td>
                    <td class="px-4 py-3 text-slate-600 font-mono text-xs">${escapeHtml(it.host || '—')}</td>
                    <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(info.product_name || info.product || it.object_type || 'TrueNAS')}</td>
                    <td class="px-4 py-3 text-slate-600 font-mono text-xs">${escapeHtml(info.version || '—')}</td>
                    <td class="px-4 py-3">${rcell}</td>
                    <td class="px-4 py-3 text-right">${poll}</td>
                </tr>`;
            }).join('');
            container.innerHTML = `
                <div class="space-y-4">
                    <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}</tr></thead>
                            <tbody class="divide-y divide-slate-200">${rows}</tbody>
                        </table>
                    </div>
                </div>`;
            return;
        }

        // ---- Per-appliance sub-resource, merged across the fleet ----
        const endpoint = _endpointFor(subMenu);
        if (!endpoint) return;

        let fleet = [];
        try {
            const dr = await fetch(`/api/truenas/appliances`);
            if (dr.ok) fleet = _fleetRows(await dr.json());
        } catch (e) { /* spoke down handled below */ }
        if (!fleet.length) {
            container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Storage spoke not connected or no appliances configured.</div>`;
            return;
        }

        const results = await Promise.allSettled(fleet.map(a =>
            fetch(`/api/truenas/${a.id}/${endpoint}${tenantQs}`)
                .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status} ${r.statusText}`)))
                .then(data => ({ app: a, data }))
        ));
        let items = [];
        const errors = [];
        results.forEach(res => {
            if (res.status === 'fulfilled') {
                const payload = _extract(res.value.data);
                // shares is a {smb, nfs, iscsi} map; flatten with kind tag.
                if (subMenu === 'Shares' && payload && typeof payload === 'object' && !Array.isArray(payload)) {
                    ['smb', 'nfs', 'iscsi'].forEach(kind => {
                        (Array.isArray(payload[kind]) ? payload[kind] : []).forEach(s => {
                            items.push({ ...s, _applianceId: res.value.app.id, appliance: res.value.app.name || res.value.app.id, kind: kind.toUpperCase() });
                        });
                    });
                } else if (Array.isArray(payload)) {
                    items = items.concat(payload.map(it => ({
                        ...it, _applianceId: res.value.app.id, appliance: res.value.app.name || res.value.app.id
                    })));
                }
            } else {
                errors.push(String((res.reason && res.reason.message) || res.reason));
            }
        });

        if (!items.length) {
            const errNote = errors.length ? `<div class="text-xs text-amber-600 mt-2">${errors.length} appliance(s) unreachable.</div>` : '';
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${subMenu} found.${errNote}</div>`;
            return;
        }

        let keys;
        if (subMenu === 'Pools') keys = ['appliance', 'name', 'status', 'healthy', 'size', 'allocated', 'free', 'path'];
        else if (subMenu === 'Datasets') keys = ['appliance', 'name', 'type', 'pool', 'used', 'available', 'mountpoint'];
        else if (subMenu === 'Shares') keys = ['appliance', 'kind', 'name', 'path', 'comment', 'enabled'];
        else if (subMenu === 'Disks') keys = ['appliance', 'name', 'serial', 'size', 'model', 'transport', 'smart'];
        else if (subMenu === 'Alerts') keys = ['appliance', 'level', 'category', 'message', 'state'];
        else if (subMenu === 'Capacity') keys = ['appliance', 'pool', 'used', 'avail', 'pct_used'];
        else keys = ['appliance', ...Object.keys(items[0] || {}).filter(k => k !== 'id' && k !== 'appliance' && !k.startsWith('_'))];

        const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
        const rows = items.map(item => {
            const cells = keys.map(k => {
                const val = item[k] !== undefined && item[k] !== null && item[k] !== '' ? String(item[k]) : '-';
                if (k === 'appliance') return `<td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(val)}</td>`;
                if (k === 'status') {
                    const color = val === 'ONLINE' || val === 'up' ? 'text-green-600' : (val === 'DEGRADED' || val === 'FAULTED' ? 'text-red-600' : 'text-slate-500');
                    return `<td class="px-4 py-3 font-mono text-xs ${color}">${escapeHtml(val)}</td>`;
                }
                if (k === 'healthy') {
                    const color = val === 'true' || val === 'True' ? 'text-green-600' : 'text-red-600';
                    return `<td class="px-4 py-3 font-mono text-xs ${color}">${escapeHtml(val)}</td>`;
                }
                if (k === 'level') {
                    const color = val === 'CRITICAL' || val === 'ALERT' ? 'text-red-600' : (val === 'WARNING' || val === 'NOTICE' ? 'text-amber-600' : 'text-slate-500');
                    return `<td class="px-4 py-3 font-mono text-xs ${color}">${escapeHtml(val)}</td>`;
                }
                return `<td class="px-4 py-3 text-slate-600 font-mono text-xs max-w-[260px] truncate" title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
            }).join('');
            return `<tr class="hover:bg-slate-50 transition-colors">${cells}</tr>`;
        }).join('');

        const errBanner = errors.length ? `<div class="text-xs text-amber-600">${errors.length} of ${fleet.length} appliance(s) unreachable.</div>` : '';
        container.innerHTML = `
            <div class="space-y-4">
                ${errBanner}
                <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}</tr></thead>
                        <tbody class="divide-y divide-slate-200">${rows}</tbody>
                    </table>
                </div>
            </div>`;
    } catch (err) {
        console.error(`[Storage] Error in loadTruenasData:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${subMenu}: ${err.message}</div>`;
    }
}

// Admin: trigger an immediate poll of one appliance (POST /api/truenas/{id}/poll).
async function pollTruenasAppliance(applianceId, name, btn) {
    if (btn) { btn.disabled = true; const orig = btn.textContent; btn.textContent = 'Polling…'; try { await pollTruenasApplianceRun(applianceId); btn.textContent = 'Done'; setTimeout(() => { btn.disabled = false; btn.textContent = orig; }, 1200); } catch (e) { btn.textContent = 'Failed'; btn.disabled = false; } }
}
async function pollTruenasApplianceRun(applianceId) {
    const r = await fetch(`/api/truenas/${encodeURIComponent(applianceId)}/poll`, { method: 'POST', credentials: 'same-origin' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    // Refresh the current sub-view to reflect the fresh poll.
    if (currentView === 'truenas') loadTruenasData(currentSubView);
}
window.pollTruenasAppliance = pollTruenasAppliance;

// Admin: apply a CLI/REST config snippet to a device (POST /api/nw/{id}/config).
function showNwConfigModal(deviceId, deviceName) {
    const modal = document.createElement('div');
    modal.id = 'nw-config-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Configure ${escapeHtml(deviceName)}</h3>
                <button onclick="closeNwConfigModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-3">
                <p class="text-xs text-slate-400">One command per line. Applied via the device's transport (SSH/CLI or REST) by the nw spoke.</p>
                <textarea id="nw-config-commands" rows="8" placeholder="show version\nshow running-config" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500"></textarea>
                <div id="nw-config-result" class="text-xs text-slate-500"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeNwConfigModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="submitNwConfig('${escapeHtml(deviceId)}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Apply</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    modal.dataset.deviceId = deviceId;
}

async function submitNwConfig(deviceId) {
    const ta = document.getElementById('nw-config-commands');
    const out = document.getElementById('nw-config-result');
    const commands = (ta?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
    if (!commands.length) { if (out) out.textContent = 'Enter at least one command.'; return; }
    if (out) out.textContent = 'Applying…';
    try {
        const r = await setupFetch(`/api/nw/${deviceId}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ commands })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data?.status === 'SUCCESS') {
            const applied = Array.isArray(data.applied) ? data.applied.length : 0;
            const errs = Array.isArray(data.errors) ? data.errors.length : 0;
            if (out) out.innerHTML = `<span class="text-green-600">Applied ${applied} command(s)${errs ? `, ${errs} error(s)` : ''}.</span>`;
        } else {
            if (out) out.innerHTML = `<span class="text-red-600">Failed: ${escapeHtml(data?.message || r.status)}</span>`;
        }
    } catch (e) {
        if (out) out.innerHTML = `<span class="text-red-600">Error: ${escapeHtml(e.message)}</span>`;
    }
}

function closeNwConfigModal() {
    const modal = document.getElementById('nw-config-modal');
    if (modal) modal.remove();
}

// ── Monitoring (vendor-neutral; backed by the monitoring spoke) ──────────────
async function loadMonitoringData() {
    const container = document.getElementById('monitoring-container');
    if (!container) return;
    const actions = document.getElementById('top-nav-actions');
    if (actions) actions.innerHTML = '';
    try {
        await _renderMonitoring(container);
    } catch (e) {
        console.error('monitoring render failed', e);
        container.innerHTML = `<div class="py-12 text-center text-red-600 italic">Monitoring failed to load: ${escapeHtml(String(e && e.message || e))}</div>`;
    }
}

// The hub relays the spoke's full response envelope; accept it or a bare payload.
function _monData(j) {
    let d = j && (j.result || j);
    if (d && d.payload) d = d.payload;
    if (d && d.data) d = d.data;
    return d || {};
}

// The tenant picker narrows the list server-side too (ADMIN/Default is its own tenant).
function _monTenantQuery() {
    const t = (typeof currentTenant !== 'undefined' && currentTenant) ? currentTenant : '';
    return t ? '?tenant=' + encodeURIComponent(t) : '';
}

// Bounded fetch so a slow spoke shows an error instead of "Loading" forever.
function _monFetch(url, ms = 45000) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), ms);
    return fetch(url, { signal: ac.signal }).catch(e => { console.warn('monitoring fetch failed', url, e); return null; }).finally(() => clearTimeout(t));
}

async function _renderMonitoring(container) {
    const admin = isAdmin();
    const [sr, hr] = await Promise.all([
        admin ? _monFetch('/api/monitoring/status') : Promise.resolve(undefined),
        _monFetch('/api/monitoring/hosts' + _monTenantQuery()),
    ]);
    const probe = admin ? sr : hr;
    if (!probe || !probe.ok) {
        container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Monitoring unavailable${probe ? ` (HTTP ${probe.status})` : ' (no response — monitoring spoke offline or timed out)'}.</div>`;
        return;
    }
    const res = (admin && sr && sr.ok) ? _monData(await sr.json()) : {};
    let hosts = [];
    if (hr && hr.ok) hosts = _monData(await hr.json()).hosts || [];
    const tenant = (typeof currentTenant !== 'undefined' && currentTenant) ? currentTenant : null;
    const shown = tenant ? hosts.filter(h => h.tenant === tenant) : hosts;
    const sevName = ['Not classified', 'Information', 'Warning', 'Average', 'High', 'Disaster'];
    const availCls = {available: 'bg-emerald-100 text-emerald-700', unavailable: 'bg-red-100 text-red-700', unknown: 'bg-slate-100 text-slate-500'};
    const up = shown.filter(h => h.availability === 'available').length;
    const down = shown.filter(h => h.availability === 'unavailable').length;
    const probs = shown.reduce((n, h) => n + (h.problem_count || (h.problems || []).length), 0);
    const tile = (label, val, cls) => `<div class="rounded border border-slate-200 px-4 py-3"><div class="text-[10px] uppercase tracking-wider text-slate-400">${label}</div><div class="text-2xl font-semibold ${cls || 'text-slate-700'}">${val}</div></div>`;
    const hostRows = shown.map(h => `<tr class="border-t border-slate-100">
        <td class="px-3 py-2 text-xs font-medium text-slate-700">${escapeHtml(h.name)}</td>
        <td class="px-3 py-2 text-xs text-slate-500">${escapeHtml(h.tenant)}</td>
        <td class="px-3 py-2 text-xs font-mono text-slate-500">${escapeHtml(h.ip)}</td>
        <td class="px-3 py-2 text-xs text-slate-500">${h.method}</td>
        <td class="px-3 py-2 text-xs"><span class="px-2 py-0.5 rounded ${availCls[h.availability] || availCls.unknown}" title="${escapeHtml(h.error || '')}">${h.availability}${h.enabled ? '' : ' (disabled)'}</span></td>
        <td class="px-3 py-2 text-xs text-slate-600">${(h.problems || []).map(p => `<div>${escapeHtml(sevName[p.severity] || '')}: ${escapeHtml(p.name)}</div>`).join('') || '<span class="text-slate-300">none</span>'}</td>
    </tr>`).join('');
    const table = shown.length
        ? `<table class="w-full text-left mt-4"><thead><tr class="text-[10px] uppercase tracking-wider text-slate-400"><th class="px-3 py-2">Device</th><th class="px-3 py-2">Tenant</th><th class="px-3 py-2">Address</th><th class="px-3 py-2">Method</th><th class="px-3 py-2">Status</th><th class="px-3 py-2">Problems</th></tr></thead><tbody>${hostRows}</tbody></table>`
        : `<div class="py-8 text-center text-slate-400 italic">No monitored devices${tenant ? ` for tenant "${escapeHtml(tenant)}"` : ''}.</div>`;
    const info = admin ? `<div class="mt-4 text-[11px] text-slate-400">Zabbix ${escapeHtml(String(res.version || '?'))} · ${escapeHtml(String(res.managed_hosts ?? '?'))} managed hosts</div>` : '';
    const sevCls = ['bg-slate-100 text-slate-600', 'bg-sky-100 text-sky-700', 'bg-yellow-100 text-yellow-800', 'bg-amber-100 text-amber-800', 'bg-orange-100 text-orange-800', 'bg-red-100 text-red-700'];
    const allProbs = shown.flatMap(h => (h.problems || []).map(p => ({...p, host: h.name, tenant: h.tenant})))
        .sort((a, b) => (b.severity - a.severity) || (b.clock - a.clock));
    const probRows = allProbs.map(p => `<tr class="border-t border-slate-100">
        <td class="px-3 py-2 text-xs"><span class="px-2 py-0.5 rounded ${sevCls[p.severity] || sevCls[0]}">${escapeHtml(sevName[p.severity] || '')}</span></td>
        <td class="px-3 py-2 text-xs font-medium text-slate-700">${escapeHtml(p.host)}</td>
        <td class="px-3 py-2 text-xs text-slate-500">${escapeHtml(p.tenant)}</td>
        <td class="px-3 py-2 text-xs text-slate-600">${escapeHtml(p.name)}</td>
        <td class="px-3 py-2 text-xs text-slate-400 whitespace-nowrap">${p.clock ? new Date(p.clock * 1000).toLocaleString() : ''}</td>
    </tr>`).join('');
    const problemsTable = `<h3 class="mt-6 text-sm font-semibold text-slate-700">Open problems (${allProbs.length})</h3>` + (allProbs.length
        ? `<div class="max-h-96 overflow-y-auto"><table class="w-full text-left mt-2"><thead class="sticky top-0 bg-white"><tr class="text-[10px] uppercase tracking-wider text-slate-400"><th class="px-3 py-2">Severity</th><th class="px-3 py-2">Device</th><th class="px-3 py-2">Tenant</th><th class="px-3 py-2">Problem</th><th class="px-3 py-2">Since</th></tr></thead><tbody>${probRows}</tbody></table></div>`
        : `<div class="py-4 text-slate-400 italic text-sm">No open problems.</div>`);
    const buttons = admin ? `<div class="flex gap-3 mt-4">
        <button onclick="monitoringAction('sync', true)" class="text-xs px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50">Dry-run sync</button>
        <button onclick="monitoringAction('sync', false)" class="text-xs px-3 py-1.5 rounded bg-[#01A982] text-white hover:opacity-90">Sync now</button>
        <button onclick="if (confirm('Rebuild monitoring entirely from the LM inventory?')) monitoringAction('rebuild', false)" class="text-xs px-3 py-1.5 rounded border border-red-300 text-red-600 hover:bg-red-50">Rebuild</button>
    </div><pre id="monitoring-result" class="mt-3 text-[11px] text-slate-600 whitespace-pre-wrap"></pre>` : '';
    container.innerHTML = `<div class="grid grid-cols-4 gap-3">${tile('Devices', shown.length)}${tile('Available', up, 'text-emerald-600')}${tile('Unavailable', down, down ? 'text-red-600' : '')}${tile('Open problems', probs, probs ? 'text-amber-600' : '')}</div>${table}${problemsTable}${info}${buttons}`;
}

async function saveMonitoringServer() {
    const msg = document.getElementById('monitoring-server-msg');
    const server = document.getElementById('monitoring-server').value.trim();
    const r = await fetch('/api/monitoring/config', {
        method: 'PUT', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({server})
    });
    if (msg) msg.textContent = r.ok ? 'Saved' : `Failed (HTTP ${r.status})`;
}

async function monitoringAction(action, dryRun) {
    const out = document.getElementById('monitoring-result');
    if (out) out.textContent = 'Working…';
    const r = await fetch(`/api/monitoring/${action}`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({dry_run: dryRun})
    });
    const text = await r.text();
    if (out) out.textContent = text.slice(0, 4000);
}
