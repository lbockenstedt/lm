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
                const color = val === 'up' ? 'text-green-600' : 'text-slate-500';
                return `<td class="px-4 py-3 font-mono text-xs ${color}">${escapeHtml(val)}</td>`;
            }
            return `<td class="px-4 py-3 text-slate-600 font-mono text-xs max-w-[200px] truncate" title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
        }).join('');
        return `<tr class="hover:bg-slate-50 transition-colors">${cells}</tr>`;
    }).join('');
    return `<div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
        <table class="w-full text-left text-sm">
            <thead class="bg-slate-100 text-slate-600 text-xs"><tr>${headers}</tr></thead>
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
        case 'ipmi':
            return 'IPMI';
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

// Device to open once the next device list loads; set by nwShowDevice.
let _nwPendingDevice = null;

// Open Network Devices on one device's detail page from another page (the
// iLO link on Proxmox → Diagnostics). The device must be in the selected tenant.
async function nwShowDevice(deviceId) {
    _nwPendingDevice = String(deviceId);
    await setView('nw');
    // setView can refuse (no Network access); don't open this device later.
    if (currentView !== 'nw') _nwPendingDevice = null;
}

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
        ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-green-100 text-green-700">up</span>'
        : reachable === false || reachable === 'down'
            ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">down</span>'
            : '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-700" title="Reachability unknown — the Network Devices spoke is offline, so up/down can\'t be probed">unknown</span>';
    const cat = (window._nwView && window._nwView.category) || 'Devices';
    const tabs = _NW_DETAIL_TABS.map(t =>
        `<button onclick="nwSelectDetailTab('${escJsAttr(t)}')" class="px-3 py-1.5 rounded-full text-xs font-bold transition-colors ${t === st.activeTab ? 'bg-brand/10 text-primary-text border border-brand' : 'text-slate-500 hover:bg-slate-100 border border-transparent'}">${escapeHtml(t)}</button>`
    ).join('');

    let body;
    if (st.activeTab === 'Overview') {
        const cfg = (isAdmin() || isTenantAdmin())
            ? `<div class="flex gap-2 mt-3 pt-3 border-t border-slate-100">
                 <button onclick="pollNwDevice('${escJsAttr(dev.id)}','${escJsAttr(dev.name || dev.id)}', this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium">Poll Now</button>
                 <button onclick="showNwConfigModal('${escJsAttr(dev.id)}','${escJsAttr(dev.name || dev.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Configure</button>
               </div>`
            : '';
        const metaRow = (k, v) => `<div class="flex justify-between py-1.5 border-b border-slate-100 last:border-0"><span class="text-xs text-slate-500">${k}</span><span class="text-xs text-slate-700 font-mono">${v}</span></div>`;
        // Identity datums captured on poll (surfaced by the list route from the
        // warm per-device cache) — help positively ID the physical box.
        const idRow = (k, val) => val ? metaRow(k, escapeHtml(String(val))) : '';
        body = `<div class="rounded-md border border-slate-200 bg-white p-4 max-w-lg">
            ${idRow('Type', typeLabel)}
            ${metaRow('Transport', escapeHtml(transport))}
            ${metaRow('Address', escapeHtml(dev.address || '—'))}
            ${idRow('Site', dev.site?.name || dev.site?.slug)}
            ${(dev._addresses || []).length > 1 ? metaRow('Also seen at', dev._addresses.filter(a => a !== dev.address).map(a => escapeHtml(a)).join('<br>')) : ''}
            ${idRow('Hostname', dev.hostname)}
            ${idRow('Model', dev.model)}
            ${idRow('Serial (SN)', dev.serial)}
            ${idRow('Host (same serial)', dev.linked_host?.name ? `${dev.linked_host.name}${dev.linked_host.kind ? ' (' + dev.linked_host.kind + ')' : ''}` : '')}
            ${idRow('Base MAC', dev.mac)}
            ${idRow('Firmware', dev.firmware)}
            ${metaRow('Reachable', rcell)}
            ${cfg}
        </div>`;
    } else {
        body = st.cache[st.activeTab] !== undefined
            ? st.cache[st.activeTab]
            : `<div class="py-12 text-center text-slate-500 animate-pulse">Fetching ${escapeHtml(st.activeTab)}…</div>`;
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
            : `<div class="py-12 text-center text-slate-500 italic">No ${escapeHtml(tab)} on this device.</div>`;
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
// The same physical box is often discovered at several addresses (every SVI /
// VLAN interface of a core switch answers SSH/SNMP), producing one row per IP.
// Collapse rows that are the same hardware, within a tenant: identical chassis
// serial, else (no serial yet) identical short hostname + object type — names
// are reconciled to the box hostname each poll. Base MAC is NOT a key: VSX
// peers can share a system MAC but are two boxes and stay two rows. A row only
// joins a name group whose serial doesn't contradict its own (mirrors the hub's
// nw_hardware_primaries, which keeps NetBox/Zabbix to one entry per box). The primary row (opened on click, used by Poll /
// Configure) is a reachable member when there is one.
function _nwCollapse(items) {
    const norm = v => String(v || '').trim().toLowerCase();
    const isUp = it => it.reachable === true || it.reachable === 'up';
    const groups = [];
    const byKey = new Map();
    const keyOf = (it, kind) => {
        const t = norm(it.tenant_id);
        if (kind === 'serial') return norm(it.serial) && `${t}|s|${norm(it.object_type)}|${norm(it.serial)}`;
        const n = norm(it.name || it.hostname);
        const short = /^\d{1,3}(\.\d{1,3}){3}$/.test(n) ? n : n.split('.')[0];
        return short && `${t}|n|${norm(it.object_type)}|${short}`;
    };
    const add = (g, it) => {
        g.members.push(it);
        ['serial', 'name'].forEach(k => { const key = keyOf(it, k); if (key && !byKey.has(key)) byKey.set(key, g); });
    };
    for (const it of items || []) {
        let g = keyOf(it, 'serial') && byKey.get(keyOf(it, 'serial'));
        if (!g) {
            const byName = keyOf(it, 'name') && byKey.get(keyOf(it, 'name'));
            // Don't merge two boxes that merely share a name but report
            // different hardware identities.
            const clash = byName && byName.members.some(m =>
                norm(it.serial) && norm(m.serial) && norm(m.serial) !== norm(it.serial));
            if (byName && !clash) g = byName;
        }
        if (!g) { g = { members: [] }; groups.push(g); }
        add(g, it);
    }
    return groups.map(g => {
        const m = g.members;
        const primary = m.find(isUp) || m[0];
        const pick = k => (primary[k] || (m.find(x => x[k]) || {})[k] || '');
        const anyUp = m.some(isUp);
        const anyKnown = m.some(x => x.reachable === false || x.reachable === 'down');
        return Object.assign({}, primary, {
            serial: pick('serial'), mac: pick('mac'), model: pick('model'),
            reachable: anyUp ? true : (anyKnown ? false : primary.reachable),
            _addresses: [...new Set(m.map(x => x.address).filter(Boolean))],
            _members: m,
        });
    });
}

// Address cell for a collapsed row: the primary address plus an expandable
// "+N more" list of the other addresses the same box answered on.
function _nwAddressCell(it) {
    const addrs = it._addresses || (it.address ? [it.address] : []);
    if (addrs.length <= 1) return escapeHtml(addrs[0] || '—');
    const others = addrs.filter(a => a !== it.address);
    return `${escapeHtml(it.address || addrs[0])}<details class="mt-0.5" onclick="event.stopPropagation()">
        <summary class="cursor-pointer text-xs text-primary-text font-sans font-semibold select-none" title="This device was discovered at ${addrs.length} addresses — shown once">+${others.length} more</summary>
        <div class="text-xs text-slate-500 leading-4">${others.map(a => escapeHtml(a)).join('<br>')}</div></details>`;
}

function _nwSerialCell(it) {
    return it.serial ? `<span class="font-mono">${escapeHtml(String(it.serial))}</span>` : '<span class="text-slate-500">—</span>';
}

async function loadNwData(category) {
    const container = document.getElementById('nw-table-container');
    if (!container) return;
    category = category || currentSubView;
    // Map any stale/legacy submenu value (a cached currentSubView from the old
    // data-type tabs, or a deep link) onto a real category so the page never
    // blanks. 'Overview' is the tenant-wide summary landing tab.
    const CATEGORIES = ['Gateways', 'Switches', 'Firewalls', 'IPMI', 'Other'];
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
    const openId = _nwPendingDevice;
    _nwPendingDevice = null;
    window._nwDetail = null;
    container.innerHTML = `<div class="py-12 text-center text-slate-500 animate-pulse">Loading ${escapeHtml(category)}…</div>`;

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
            if (openId) showToast('Select a tenant to open that controller.', 'error');
            // ADMIN (default) tenant: the hub no longer accumulates every
            // tenant's devices — pick a specific tenant to see its fleet.
            container.innerHTML = `<div class="py-12 text-center space-y-3">
                <svg class="w-10 h-10 mx-auto text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-3-4h.01M16 16h.01"/></svg>
                <p class="text-slate-600 text-sm font-semibold">Select a tenant to view its network devices</p>
                <p class="text-slate-500 text-xs max-w-md mx-auto">The ADMIN (default) view no longer aggregates every tenant's devices. Choose a specific tenant from the tenant picker to see that tenant's fleet.</p>
            </div>`;
            return;
        }
        items = Array.isArray(data) ? data : (Array.isArray(data?.data) ? data.data : []);
        items = _nwCollapse(items);
    } catch (err) {
        console.error(`[Network] Error in loadNwData:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading devices: ${escapeHtml(err.message)}</div>`;
        return;
    }
    const devices = items.filter(it => _nwCategoryOf(it.object_type) === category);
    // Per-category counts across the WHOLE fleet so the list view can show where
    // every device lives — otherwise, landing on an empty/small category (e.g.
    // Gateways) makes devices under another category look "missing".
    const counts = { Gateways: 0, Switches: 0, Firewalls: 0, IPMI: 0, Other: 0 };
    items.forEach(it => { counts[_nwCategoryOf(it.object_type)]++; });
    if (category === 'Overview') {
        // Tenant-wide summary landing (mirrors the Hypervisor Overview): keep the
        // full fleet on _nwView so a row click can drill into device detail and
        // the detail back-button repaints the overview without a refetch.
        window._nwView = { category: 'Overview', devices: items, counts };
        _renderNwOverview(items, counts);
        const row = openId && items.find(it => (it._members || [it]).some(m => String(m.id) === openId));
        if (row) nwOpenDevice(row.id);
        else if (openId) showToast('That controller is not in the selected tenant; pick its tenant to open it.', 'error');
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
    counts = counts || { Gateways: 0, Switches: 0, Firewalls: 0, IPMI: 0, Other: 0 };
    const isUp   = it => it.reachable === true  || it.reachable === 'up';
    const isDown = it => it.reachable === false || it.reachable === 'down';
    const total = devices.length;
    const up    = devices.filter(isUp).length;
    const down  = devices.filter(isDown).length;
    const unknown = total - up - down;

    if (!total) {
        container.innerHTML = `<div class="py-12 text-center text-slate-500 italic">No network devices configured for this tenant. Add one in Setup → Network Devices.</div>`;
        return;
    }

    // Reachability stat cards (non-clickable summary).
    const stat = (label, n, valueCls) => `
        <div class="bg-white rounded-lg border border-slate-200 px-3 py-2">
            <p class="text-xs font-bold text-slate-500">${label}</p>
            <p class="text-xl font-bold ${valueCls || 'text-navy'}">${n}</p>
        </div>`;
    const statCards = `<div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
        ${stat('Total Devices', total)}
        ${stat('Reachable', up, 'text-green-600')}
        ${stat('Unreachable', down, 'text-red-500')}
        ${stat('Unknown', unknown, 'text-amber-500')}
    </div>`;

    // Per-category cards → click navigates to that category tab.
    const CATEGORIES = ['Gateways', 'Switches', 'Firewalls', 'IPMI', 'Other'];
    const catCard = c => `
        <div onclick="setSubView('${c}')" class="cursor-pointer bg-white rounded-lg border border-slate-200 px-3 py-2 hover:border-brand hover:shadow-md transition-all" title="Filter network devices by ${c}">
            <p class="text-xs font-bold text-slate-500">${c}</p>
            <p class="text-xl font-bold text-navy">${counts[c] || 0}</p>
        </div>`;
    const catCards = `<div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-2 mt-2">
        ${CATEGORIES.map(catCard).join('')}
    </div>`;

    // Compact fleet table — every device in the tenant, click to drill in.
    const rows = devices.map(it => {
        const typeLabel = _NW_OBJECT_TYPES[it.object_type] || it.object_type || '—';
        const category  = _nwCategoryOf(it.object_type);
        const rcell = isUp(it)
            ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-green-100 text-green-700">up</span>'
            : isDown(it)
                ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">down</span>'
                : '<span class="text-slate-500 text-xs">—</span>';
        return `<tr onclick="nwOpenDevice('${escJsAttr(it.id)}')" class="hover:bg-slate-50 transition-colors cursor-pointer" title="View device details">
            <td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(it.name || it.id)}${it.mac ? `<div class="text-xs font-mono font-normal text-slate-500 mt-0.5">${escapeHtml(String(it.mac))}</div>` : ''}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(typeLabel)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(category)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${_nwSerialCell(it)}</td>
            <td class="px-4 py-3 text-slate-600 font-mono text-xs">${_nwAddressCell(it)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs" title="NetBox site of the prefix holding this address">${escapeHtml(it.site?.name || it.site?.slug || '—')}</td>
            <td class="px-4 py-3">${rcell}</td>
            <td class="px-4 py-3 text-right"><span class="text-slate-500">›</span></td>
        </tr>`;
    }).join('');
    const headers = ['device', 'type', 'category', 'serial', 'address', 'site', 'reachable']
        .map(k => `<th class="px-4 py-3">${k.toUpperCase()}</th>`).join('');

    container.innerHTML = `
        <div class="space-y-4">
            <h3 class="text-base font-semibold text-navy px-1">Fleet Overview
                <span class="text-xs text-slate-500 font-normal">(${total} device${total === 1 ? '' : 's'} in this tenant)</span></h3>
            ${statCards}
            ${catCards}
            <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 text-xs"><tr>${headers}<th class="px-4 py-3"></th></tr></thead>
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
// Layout is a deterministic tidy tree rooted at the gateways — no library, no
// build step (the WebUI is dependency-free vanilla JS by design).
const _NW_TOPO_EDGE_STYLE = {
    lldp:   { stroke: '#64748b', dash: '',     label: 'LLDP' },
    manual: { stroke: '#01A982', dash: '',     label: 'Declared' },
    netbox: { stroke: '#0ea5e9', dash: '',     label: 'NetBox cable' },
    mac:    { stroke: '#d97706', dash: '5 4',  label: 'Inferred (MAC)' },
};

// Link sources that are facts (advertised, declared or cabled). The drawn tree
// is built from these first; a MAC-table guess only places a device no fact
// reaches, so an inferred link can never re-parent a device LLDP placed.
const _NW_TOPO_STRONG = new Set(['lldp', 'manual', 'netbox']);

// Pixel geometry per orientation. tb = top-down, the New Central default (one
// row per hop); lr = left to right (one column per hop). `at(slot, depth)`
// turns a tree slot and hop count into a point; `label` is the name length
// that fits between neighbours.
const _NW_TOPO_GEOM = {
    tb: { at: (s, d) => ({ x: 96 + s * 150, y: 56 + d * 110 }), label: 22 },
    lr: { at: (s, d) => ({ x: 70 + d * 240, y: 76 + s * 64 }), label: 34 },
};

// Lay the map out as a tidy tree per connected component, like New Central.
// Roots: the device the operator pinned ("Start map here"), else the
// component's gateways, else the switch with the most fact links. The tree is
// breadth-first over fact links, then MAC links only for devices still
// unplaced. Leaves take consecutive slots depth-first and each parent sits
// over the middle of its children. `opts.collapsed` ids keep their place but
// hide their tree descendants. Deterministic, so a refresh doesn't reshuffle.
function _nwTopoLayout(nodes, edges, opts) {
    opts = opts || {};
    const collapsed = opts.collapsed || new Set();
    const geo = _NW_TOPO_GEOM[opts.orient === 'lr' ? 'lr' : 'tb'];
    // 1. Adjacency over every link, and over fact links only.
    const byId = {}, all = {}, strong = {};
    nodes.forEach(n => { byId[n.id] = n; all[n.id] = new Set(); strong[n.id] = new Set(); });
    edges.forEach(e => {
        if (!byId[e.a] || !byId[e.b] || e.a === e.b) return;
        all[e.a].add(e.b); all[e.b].add(e.a);
        if (_NW_TOPO_STRONG.has(e.source)) { strong[e.a].add(e.b); strong[e.b].add(e.a); }
    });
    const nameOf = id => String(byId[id].name || id);
    const byName = (x, y) => nameOf(x).localeCompare(nameOf(y)) || (x < y ? -1 : x > y ? 1 : 0);
    const loose = nodes.filter(n => !all[n.id].size);
    // 2. Connected components, largest first.
    const comps = [], seen = new Set();
    nodes.map(n => n.id).filter(id => all[id].size).sort(byName).forEach(start => {
        if (seen.has(start)) return;
        const comp = [start];
        seen.add(start);
        for (let i = 0; i < comp.length; i++) {
            all[comp[i]].forEach(nb => { if (!seen.has(nb)) { seen.add(nb); comp.push(nb); } });
        }
        comps.push(comp);
    });
    comps.sort((p, q) => q.length - p.length || byName(p[0], q[0]));
    // 3. Roots, then the fact-links-first breadth-first tree.
    const depth = {}, parent = {}, children = {}, rootsOf = [];
    const rank = id => (byId[id].kind === 'switch' ? 1e6 : 0) + strong[id].size * 1000 + all[id].size;
    comps.forEach(comp => {
        let roots = comp.filter(id => id === opts.root);
        if (!roots.length) roots = comp.filter(id => byId[id].kind === 'gateway').sort(byName);
        if (!roots.length) roots = [comp.slice().sort((x, y) => rank(y) - rank(x) || byName(x, y))[0]];
        const order = [];
        const reach = (id, from) => {
            depth[id] = from === null ? 0 : depth[from] + 1;
            children[id] = [];
            if (from !== null) { parent[id] = from; children[from].push(id); }
            order.push(id);
        };
        const grow = start => {
            for (let i = start; i < order.length; i++) {
                [...strong[order[i]]].sort(byName).forEach(nb => {
                    if (depth[nb] === undefined) reach(nb, order[i]);
                });
            }
        };
        roots.forEach(id => reach(id, null));
        grow(0);
        // A MAC link places what no fact reaches, from the shallowest device.
        while (order.length < comp.length) {
            const before = order.length;
            order.slice().sort((x, y) => depth[x] - depth[y]).forEach(id => {
                [...all[id]].sort(byName).forEach(nb => { if (depth[nb] === undefined) reach(nb, id); });
            });
            if (order.length === before) break;
            grow(before);
        }
        rootsOf.push(roots);
    });
    // 4. A collapsed device hides every tree descendant.
    const hidden = new Set(), hiddenCount = {};
    collapsed.forEach(id => {
        if (!children[id]) return;
        const stack = children[id].slice();
        hiddenCount[id] = 0;
        while (stack.length) {
            const k = stack.pop();
            hidden.add(k);
            hiddenCount[id]++;
            stack.push(...children[k]);
        }
    });
    // 5. Tidy tree: a leaf takes the next slot, a parent centres over its children.
    const slot = {};
    let cursor = 0;
    const place = id => {
        const kids = collapsed.has(id) ? [] : children[id].slice().sort(byName);
        if (!kids.length) { slot[id] = cursor++; return; }
        kids.forEach(place);
        slot[id] = (slot[kids[0]] + slot[kids[kids.length - 1]]) / 2;
    };
    comps.forEach((comp, ci) => {
        const roots = rootsOf[ci];
        const lone = roots.length > 1 ? roots.filter(r => !children[r].length) : [];
        roots.filter(r => !lone.includes(r)).forEach(place);
        // A gateway with nothing of its own sits over the device it links to
        // (VPNC2 next to VPNC1, both over the core).
        lone.forEach(r => {
            const nbs = [...all[r]].filter(nb => slot[nb] !== undefined);
            slot[r] = nbs.length ? nbs.reduce((t, nb) => t + slot[nb], 0) / nbs.length : cursor++;
        });
        const top = roots.slice().sort((x, y) => slot[x] - slot[y] || byName(x, y));
        for (let i = 1; i < top.length; i++) slot[top[i]] = Math.max(slot[top[i]], slot[top[i - 1]] + 1);
        cursor = Math.max(cursor, ...top.map(r => slot[r] + 1)) + 0.6;
    });
    // 6. Slots and hops to pixels; levels that have children get a header.
    const pos = {}, levels = {};
    let maxX = 0, maxY = 0;
    Object.keys(slot).forEach(id => {
        pos[id] = geo.at(slot[id], depth[id]);
        maxX = Math.max(maxX, pos[id].x);
        maxY = Math.max(maxY, pos[id].y);
        if (children[id].length) (levels[depth[id]] = levels[depth[id]] || []).push(id);
    });
    return { pos, loose, width: maxX + 100, height: maxY + 50, depth, parent, children,
             hiddenCount, hidden, levels, roots: [].concat(...rootsOf) };
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

// The devices and links the map draws for this view: infrastructure only
// unless endpoints are shown, and then folded into per-switch groups.
function _nwTopoDrawable(graph, view) {
    let nodes = graph.nodes || [];
    if (!view.showEndpoints) nodes = nodes.filter(nd => nd.infra !== false);
    const keep = new Set(nodes.map(n => n.id));
    let edges = (graph.edges || []).filter(e => keep.has(e.a) && keep.has(e.b));
    if (view.showEndpoints) ({ nodes, edges } = _nwTopoGroupEndpoints(nodes, edges, view.epOpen));
    return { nodes, edges };
}

// A link's curve: vertical S-bends top-down, horizontal ones left to right;
// a link between two devices on the same level bows away from the tree.
function _nwTopoCurve(a, b, tb) {
    const f = v => v.toFixed(1);
    if (tb) {
        if (Math.abs(a.y - b.y) < 1) {
            return `M${f(a.x)} ${f(a.y)}C${f(a.x)} ${f(a.y + 48)} ${f(b.x)} ${f(b.y + 48)} ${f(b.x)} ${f(b.y)}`;
        }
        const [t, u] = a.y <= b.y ? [a, b] : [b, a];
        const my = (t.y + u.y) / 2;
        return `M${f(t.x)} ${f(t.y)}C${f(t.x)} ${f(my)} ${f(u.x)} ${f(my)} ${f(u.x)} ${f(u.y)}`;
    }
    const [l, r] = a.x <= b.x ? [a, b] : [b, a];
    if (Math.abs(l.x - r.x) < 1) {
        return `M${f(l.x)} ${f(l.y)}C${f(l.x + 60)} ${f(l.y)} ${f(r.x + 60)} ${f(r.y)} ${f(r.x)} ${f(r.y)}`;
    }
    const mx = (l.x + r.x) / 2;
    return `M${f(l.x)} ${f(l.y)}C${f(mx)} ${f(l.y)} ${f(mx)} ${f(r.y)} ${f(r.x)} ${f(r.y)}`;
}

// Build the map's SVG at zoom `z`. Returns { html, lay, pos, W, H } so the
// caller can zoom (resize the SVG) and scroll to devices without a redraw.
// A selected device keeps its links and neighbours bright; the rest dims.
function _nwTopoSvg(graph, view, z) {
    // 1. What to draw, and the empty states.
    const collapsed = view.collapsed || new Set();
    const empty = msg => ({ html: `<div class="py-12 text-center text-slate-500 italic">${msg}</div>`,
                            lay: null, pos: {}, W: 0, H: 0 });
    if (!(graph.nodes || []).length) return empty("No devices in this tenant's topology yet.");
    const { nodes, edges } = _nwTopoDrawable(graph, view);
    if (!nodes.length) return empty('No infrastructure devices found. Tick “Show endpoints” to see everything.');
    // 2. Layout; unlinked devices go in a wrapped grid under the tree.
    const tb = view.orient !== 'lr';
    const geo = _NW_TOPO_GEOM[tb ? 'tb' : 'lr'];
    const lay = _nwTopoLayout(nodes, edges, { collapsed, root: view.root, orient: view.orient });
    const pos = Object.assign({}, lay.pos);
    const W = Math.max(900, lay.width);
    const perRow = Math.max(1, Math.floor((W - 40) / 150));
    const looseTop = lay.height + 10;
    lay.loose.forEach((nd, i) => {
        pos[nd.id] = { x: 95 + (i % perRow) * 150, y: looseTop + 40 + Math.floor(i / perRow) * 76 };
    });
    const H = lay.loose.length ? looseTop + 40 + Math.ceil(lay.loose.length / perRow) * 76 + 10 : lay.height;
    // 3. Selection: the device, its links and its neighbours stay bright.
    const sel = view.selected && pos[view.selected] ? view.selected : '';
    const near = new Set([sel]);
    if (sel) edges.forEach(e => { if (e.a === sel) near.add(e.b); if (e.b === sel) near.add(e.a); });
    const byId = {};
    nodes.forEach(nd => { byId[nd.id] = nd; });
    // 4. Links. An inferred link that didn't place a device in the tree only
    // shows while either end is selected: drawn always, the core's MAC links
    // to devices elsewhere in the tree would cross the whole map.
    const inTree = e => lay.parent[e.a] === e.b || lay.parent[e.b] === e.a;
    const lines = edges.map(e => {
        const a = pos[e.a], b = pos[e.b];
        if (!a || !b) return '';
        if (!_NW_TOPO_STRONG.has(e.source) && !inTree(e) && e.a !== sel && e.b !== sel) return '';
        const st = _NW_TOPO_EDGE_STYLE[e.source] || _NW_TOPO_EDGE_STYLE.mac;
        const ap = _nwTopoPort(e, 'a'), bp = _nwTopoPort(e, 'b');
        const tip = `${(byId[e.a] || {}).name || ''} ${ap ? '(' + ap + ')' : ''} — ` +
                    `${(byId[e.b] || {}).name || ''} ${bp ? '(' + bp + ')' : ''}` +
                    `\n${st.label}${e.detail ? ' — ' + e.detail : ''}`;
        const on = sel && (e.a === sel || e.b === sel);
        return `<path d="${_nwTopoCurve(a, b, tb)}" fill="none" stroke="${st.stroke}"
            stroke-width="${on ? 3 : 1.5}" ${st.dash ? `stroke-dasharray="${st.dash}"` : ''}
            opacity="${sel ? (on ? 1 : 0.12) : 0.85}"><title>${escapeHtml(tip)}</title></path>`;
    }).join('');
    // 5. Devices: icon, name, and a −/+N badge on anything with children.
    const tipOf = nd => [nd.name, nd.object_type || nd.kind,
                     (nd.addresses || []).join(', '), (nd.macs || []).join(', '),
                     nd.unit === 'vsx' ? 'VSX pair: ' + (nd.members || []).map(m => m.name).join(' + ') : '',
                     (nd.stack_members || []).length ? 'Stack members: ' + nd.stack_members.join(', ') : '',
                     nd.lldp_capable ? 'LLDP' : '', nd.manual ? 'Declared' : '',
                     'via ' + (nd.sources || []).join('+')].filter(Boolean).join('\n');
    const short = (t, n) => (t.length > n ? t.slice(0, n - 1) + '…' : t);
    const drawNode = (nd, p) => {
        const isGroup = nd.kind === 'epgroup';
        const groupOpen = isGroup && view.epOpen && view.epOpen.has(nd.id);
        const kids = isGroup ? 1 : (lay.children[nd.id] || []).length;
        const tip = isGroup ? nd.name + '\n' + (groupOpen ? 'Click to hide these endpoints' : 'Click to show these endpoints')
            : tipOf(nd) + '\nClick for details';
        const badge = isGroup ? (groupOpen ? '−' : '+' + nd.group_size)
            : collapsed.has(nd.id) ? '+' + (lay.hiddenCount[nd.id] || 0) : '−';
        const bw = Math.max(16, 6 + 6.5 * badge.length);
        const halo = nd.id === sel
            ? `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="24" fill="none" stroke="#01A982" stroke-width="4" opacity="0.35"/>` : '';
        return `<g data-topo-node="${escapeHtml(nd.id)}" style="cursor:pointer" opacity="${sel && !near.has(nd.id) ? 0.25 : 1}">
            <title>${escapeHtml(tip)}</title>${halo}
            ${_nwTopoIcon(nd, p.x, p.y, _nwTopoNodeColor(nd))}
            <text x="${p.x.toFixed(1)}" y="${(p.y + 32).toFixed(1)}" text-anchor="middle"
              style="font-size:11px" fill="#334155">${escapeHtml(short(String(nd.name || nd.id), geo.label))}</text>
            ${kids > 0 ? `<g data-topo-toggle><title>${isGroup ? '' : collapsed.has(nd.id) ? 'Click to expand' : 'Click to collapse'}</title>
                <rect x="${(p.x + 15 - bw / 2).toFixed(1)}" y="${(p.y - 23).toFixed(1)}"
                  width="${bw.toFixed(1)}" height="16" rx="8" fill="#0f172a"/>
                <text x="${(p.x + 15).toFixed(1)}" y="${(p.y - 11.5).toFixed(1)}" text-anchor="middle"
                  style="font-size:10px; font-weight:700; fill:#fff">${badge}</text></g>` : ''}
        </g>`;
    };
    const dots = nodes.filter(nd => pos[nd.id]).map(nd => drawNode(nd, pos[nd.id])).join('');
    // 6. Level headers (click to fold a whole level) and the unlinked caption.
    const headers = Object.keys(lay.levels).map(d => {
        const allCollapsed = lay.levels[d].every(id => collapsed.has(id));
        const p = geo.at(0, Number(d));
        const at = tb ? `x="10" y="${(p.y + 4).toFixed(1)}"` : `x="${p.x.toFixed(1)}" y="18" text-anchor="middle"`;
        return `<text data-topo-level="${d}" ${at} style="font-size:11px;font-weight:600;cursor:pointer" fill="#475569">
            <title>Collapse/expand every device at this level</title>${allCollapsed ? '▸' : '▾'} Level ${Number(d) + 1}</text>`;
    }).join('');
    const looseCap = lay.loose.length
        ? `<text x="20" y="${looseTop + 4}" style="font-size:11px;font-weight:600" fill="#64748b">Unlinked devices (${lay.loose.length})</text>` : '';
    const html = `<svg width="${(W * z).toFixed(0)}" height="${(H * z).toFixed(0)}" viewBox="0 0 ${W} ${H}"
        style="display:block;margin:0 auto">${lines}${headers}${dots}${looseCap}</svg>`;
    return { html, lay, pos, W, H };
}

// Map state for the Topology tab, kept in this module rather than window
// globals. Collapse and open groups are per tenant and survive refreshes (node
// ids are stable); zoom, scroll and selection reset on each full render.
const _nwTopoState = {
    graph: null, tenant: null, collapsed: new Set(), epOpen: new Set(), showEndpoints: false,
    infer: true, zoom: 1, selected: '', drawn: null, seq: 0, drag: null, dragged: false,
    // The tenant's fold state is settled: auto-folded once, or folded /
    // expanded by the user, so a refresh never refolds what they opened.
    // Reset with the collapse state when the tenant changes.
    foldSettled: false,
};

// Read (value undefined) or write a saved map preference. Storage can be
// unavailable (private mode, full quota); the map must still work then.
function _nwTopoPref(key, value) {
    try {
        if (value === undefined) return localStorage.getItem(key) || '';
        if (value) localStorage.setItem(key, value); else localStorage.removeItem(key);
    } catch (e) { /* the preference lasts for this page only */ }
    return value || '';
}

// Each tenant pins its own start device.
function _nwTopoRootKey() {
    return 'lm_nw_topo_root_' + (currentTenant || 'default');
}

// The current view settings; collapse and selection reset on a tenant change.
// fresh (a full render) also drops the selection, so the new SVG is not
// drawn dimmed around a node the details panel no longer shows.
function _nwTopoView(fresh) {
    const s = _nwTopoState;
    if (fresh) s.selected = '';
    if (s.tenant !== currentTenant) {
        s.tenant = currentTenant;
        s.collapsed = new Set();
        s.epOpen = new Set();
        s.foldSettled = false;
        s.selected = '';
    }
    return { showEndpoints: s.showEndpoints, collapsed: s.collapsed, epOpen: s.epOpen,
             orient: _nwTopoPref('lm_nw_topo_orient') === 'lr' ? 'lr' : 'tb',
             root: _nwTopoPref(_nwTopoRootKey()), selected: s.selected };
}

// Redraw the map in place, keeping the zoom and scroll position.
function _nwTopoRedraw() {
    const host = document.getElementById('nw-topo-svg');
    const s = _nwTopoState;
    if (!host || !s.graph) return;
    const left = host.scrollLeft, top = host.scrollTop;
    s.drawn = _nwTopoSvg(s.graph, _nwTopoView(), s.zoom);
    host.innerHTML = s.drawn.html;
    host.scrollLeft = left;
    host.scrollTop = top;
    _nwTopoDetails();
    _nwTopoFindList();
}

// Left gap of a map narrower than the frame: the SVG is centred with
// `margin:0 auto`, so map x 0 sits this far in from the frame's edge.
function _nwTopoInset(host, z) {
    const d = _nwTopoState.drawn;
    return Math.max(0, (host.clientWidth - d.W * z) / 2);
}

// Zoom to `z` (10%–300%) keeping frame point (px, py) still; with no point,
// zoom around the middle of the frame. Only the SVG's size changes.
function _nwTopoZoom(z, px, py) {
    const host = document.getElementById('nw-topo-svg');
    const svg = host && host.querySelector('svg');
    const s = _nwTopoState;
    if (!svg || !s.drawn || !s.drawn.lay) return;
    z = Math.min(3, Math.max(0.1, z));
    if (px === undefined) { px = host.clientWidth / 2; py = host.clientHeight / 2; }
    // Map point under (px, py), allowing for the centring gap at the old zoom.
    const cx = (host.scrollLeft + px - _nwTopoInset(host, s.zoom)) / s.zoom;
    const cy = (host.scrollTop + py) / s.zoom;
    s.zoom = z;
    svg.setAttribute('width', (s.drawn.W * z).toFixed(0));
    svg.setAttribute('height', (s.drawn.H * z).toFixed(0));
    host.scrollLeft = cx * z + _nwTopoInset(host, z) - px;
    host.scrollTop = cy * z - py;
    const pct = document.getElementById('nw-topo-zoom-pct');
    if (pct) pct.textContent = Math.round(z * 100) + '%';
}

// The zoom that shows the whole map in the frame, never above 100%.
function _nwTopoFitZoom() {
    const host = document.getElementById('nw-topo-svg');
    const d = _nwTopoState.drawn;
    if (!host || !d || !d.W) return 1;
    return Math.min(1, (host.clientWidth - 16) / d.W, (host.clientHeight - 16) / d.H);
}

// Scroll so map point p (unzoomed) is in the middle of the frame.
function _nwTopoScrollTo(p) {
    const host = document.getElementById('nw-topo-svg');
    if (!host || !p) return;
    const z = _nwTopoState.zoom;
    host.scrollLeft = p.x * z + _nwTopoInset(host, z) - host.clientWidth / 2;
    host.scrollTop = p.y * z - host.clientHeight / 2;
}

// First view of a freshly rendered map: the whole map when its names are
// still legible (70% or more), else 80% scrolled to the top of the tree.
function _nwTopoInitialView() {
    const host = document.getElementById('nw-topo-svg');
    const d = _nwTopoState.drawn;
    if (!host || !d || !d.lay) return;
    const fit = _nwTopoFitZoom();
    _nwTopoZoom(fit >= 0.7 ? fit : 0.8);
    const roots = d.lay.roots.map(r => d.pos[r]).filter(Boolean);
    if (fit >= 0.7 || !roots.length) { host.scrollLeft = 0; host.scrollTop = 0; return; }
    _nwTopoScrollTo({ x: roots.reduce((t, p) => t + p.x, 0) / roots.length,
                      y: roots.reduce((t, p) => t + p.y, 0) / roots.length });
    if (_nwTopoView().orient === 'lr') host.scrollLeft = 0; else host.scrollTop = 0;
}

// The first time a tenant's map is too big to read whole (under 50%), fold
// the deepest levels one at a time until it fits, but never above Level 4,
// so gateway → core → aggregation → access always shows. The badges and
// "Expand all" undo it. A map that fits is checked again on the next render
// (a refresh can grow it); once folded, or once the user folds or expands
// anything, the tenant is settled until the tenant changes (which also
// drops its collapse state). Returns true when it folded anything.
function _nwTopoAutoFold() {
    const s = _nwTopoState;
    const host = document.getElementById('nw-topo-svg');
    if (!host || !s.graph || s.foldSettled || s.collapsed.size) return false;
    const view = _nwTopoView();
    const { nodes, edges } = _nwTopoDrawable(s.graph, view);
    const fits = lay => Math.min((host.clientWidth - 16) / Math.max(900, lay.width),
                                 (host.clientHeight - 16) / lay.height) >= 0.5;
    const full = _nwTopoLayout(nodes, edges, view);
    if (fits(full)) return false;
    const levels = Object.keys(full.levels).map(Number).filter(d => d >= 3).sort((a, b) => b - a);
    for (const d of levels) {
        full.levels[d].forEach(id => s.collapsed.add(id));
        if (fits(_nwTopoLayout(nodes, edges, Object.assign({}, view, { collapsed: s.collapsed })))) break;
    }
    s.foldSettled = true;
    return s.collapsed.size > 0;
}

// Select a device: expand whatever hides it, highlight its links, open its
// details and scroll it into view. An endpoint turns endpoints on and opens
// its group.
function _nwTopoFocus(id) {
    const s = _nwTopoState;
    const node = (s.graph && s.graph.nodes || []).find(n => n.id === id);
    if (!node) return;
    if (node.infra === false) {
        s.showEndpoints = true;
        const box = document.getElementById('nw-topo-endpoints');
        if (box) box.checked = true;
        (s.graph.edges || []).forEach(e => {
            if (e.a === id) s.epOpen.add('eg:' + e.b);
            if (e.b === id) s.epOpen.add('eg:' + e.a);
        });
    }
    s.selected = id;
    // Two passes: opening a group can put the device under a collapsed branch.
    for (let pass = 0; pass < 2; pass++) {
        const par = (s.drawn && s.drawn.lay && s.drawn.lay.parent) || {};
        for (let p = par[id]; p; p = par[p]) s.collapsed.delete(p);
        _nwTopoRedraw();
        if (s.drawn.pos[id]) break;
    }
    _nwTopoScrollTo(s.drawn.pos[id]);
}

// Fill the search box's suggestions with the names currently on the map.
function _nwTopoFindList() {
    const list = document.getElementById('nw-topo-find-list');
    const s = _nwTopoState;
    if (!list || !s.graph) return;
    const names = [...new Set(_nwTopoDrawable(s.graph, _nwTopoView()).nodes
        .filter(n => n.kind !== 'epgroup').map(n => String(n.name || n.id)))].sort();
    list.replaceChildren(...names.map(n => { const o = document.createElement('option'); o.value = n; return o; }));
}

// Find a device by name (exact, else the first partial match) and focus it.
function _nwTopoFind(text) {
    const q = String(text || '').trim().toLowerCase();
    const nodes = (_nwTopoState.graph && _nwTopoState.graph.nodes) || [];
    if (!q) return;
    const hit = nodes.find(n => String(n.name || '').toLowerCase() === q)
        || nodes.find(n => String(n.name || '').toLowerCase().includes(q)
            || (n.addresses || []).some(a => String(a).toLowerCase() === q));
    if (hit) _nwTopoFocus(hit.id);
    else showToast(`No device matches “${text}”`, 'error');
}

// The details panel for the selected device: what it is, and every link with
// its ports and source. Built from DOM text nodes so names and port strings
// from devices are never parsed as markup.
function _nwTopoDetails() {
    const panel = document.getElementById('nw-topo-details');
    const s = _nwTopoState;
    if (!panel) return;
    const nodes = (s.graph && s.graph.nodes) || [];
    const node = s.selected ? nodes.find(n => n.id === s.selected) : null;
    panel.replaceChildren();
    panel.style.display = node ? 'block' : 'none';
    if (!node) return;
    const el = (tag, cls, text) => {
        const x = document.createElement(tag);
        if (cls) x.className = cls;
        if (text !== undefined) x.textContent = text;
        return x;
    };
    // 1. Name and close.
    const head = el('div', 'flex items-start justify-between gap-2 mb-2');
    head.append(el('div', 'text-sm font-bold text-slate-800 break-all', node.name || node.id));
    const close = el('button', 'text-slate-500 hover:text-slate-800 text-lg leading-none', '×');
    close.title = 'Close';
    close.dataset.topoAct = 'close';
    head.append(close);
    panel.append(head);
    // 2. Facts.
    [['Type', node.object_type || node.kind],
     ['Addresses', (node.addresses || []).join(', ')],
     ['MACs', (node.macs || []).join(', ')],
     ['VSX pair', node.unit === 'vsx' ? (node.members || []).map(m => m.name).join(' + ') : ''],
     ['Stack', (node.stack_members || []).join(', ')],
     ['Seen via', (node.sources || []).join(', ')]].forEach(([k, v]) => {
        if (!v) return;
        const row = el('div', 'mb-1');
        row.append(el('span', 'text-slate-500', k + ': '), el('span', 'text-slate-700 break-all', v));
        panel.append(row);
    });
    // 3. Where the map starts. An unlinked device has no tree to start, so
    // it is offered only "Use default start" (if it was pinned earlier).
    const pinned = _nwTopoPref(_nwTopoRootKey());
    const lay = s.drawn && s.drawn.lay;
    const loose = !!lay && lay.loose.some(n => n.id === node.id);
    const act = el('button', 'mt-3 px-3 py-1 text-xs font-semibold rounded-full border border-slate-300 text-slate-600 hover:bg-slate-50',
        pinned === node.id ? 'Use default start' : 'Start map here');
    act.dataset.topoAct = pinned === node.id ? 'unroot' : 'root';
    act.title = pinned === node.id
        ? 'Root the map at the gateways again (or the best-connected switch)'
        : 'Draw the map with this device at the top (saved in this browser)';
    if (!loose || pinned === node.id) panel.append(act);
    // 4. Links, facts first, each neighbour clickable.
    const byId = {};
    nodes.forEach(n => { byId[n.id] = n; });
    const links = (s.graph.edges || []).filter(e => e.a === node.id || e.b === node.id)
        .map(e => {
            const mine = e.a === node.id ? 'a' : 'b', other = mine === 'a' ? 'b' : 'a';
            return { e, mine, other, nb: byId[e[other]] || { id: e[other], name: e[other] } };
        })
        .sort((p, q) => Number(_NW_TOPO_STRONG.has(q.e.source)) - Number(_NW_TOPO_STRONG.has(p.e.source))
            || String(p.nb.name).localeCompare(String(q.nb.name)));
    panel.append(el('div', 'text-xs font-bold text-slate-500 mt-3 mb-1', `Links (${links.length})`));
    links.forEach(({ e, mine, other, nb }) => {
        const st = _NW_TOPO_EDGE_STYLE[e.source] || _NW_TOPO_EDGE_STYLE.mac;
        const row = el('div', 'py-1 border-t border-slate-100');
        const jump = el('button', 'text-primary-text font-semibold hover:underline text-left break-all', nb.name || nb.id);
        jump.dataset.topoJump = nb.id;
        jump.title = 'Show this device';
        const lp = _nwTopoPort(e, mine), rp = _nwTopoPort(e, other);
        const ports = (lp || '?') + ' → ' + (rp || '?');
        row.append(jump, el('div', 'text-slate-500 font-mono', ports + ' · ' + st.label));
        panel.append(row);
    });
}

// Fullscreen the map frame, or leave fullscreen.
function _nwTopoFullscreen() {
    const frame = document.getElementById('nw-topo-frame');
    if (!frame) return;
    if (document.fullscreenElement) { document.exitFullscreen().catch(() => {}); return; }
    if (frame.requestFullscreen) frame.requestFullscreen().catch(() => {});
}

// The scroll area fills the screen while the map is fullscreen.
function _nwTopoOnFullscreen() {
    const frame = document.getElementById('nw-topo-frame');
    const host = document.getElementById('nw-topo-svg');
    if (!frame || !host) return;
    host.style.height = document.fullscreenElement === frame ? '100vh' : '70vh';
}
document.addEventListener('fullscreenchange', _nwTopoOnFullscreen);

// Wire the map: click to select / fold, wheel to zoom, drag to pan, keys,
// the zoom controls, the details panel and the toolbar.
function _nwTopoBindView() {
    const s = _nwTopoState;
    const host = document.getElementById('nw-topo-svg');
    if (!host) return;
    // 1. Clicks: level header, badge, endpoint group, device, background.
    host.onclick = ev => {
        if (s.dragged) { s.dragged = false; return; }
        const lvl = ev.target.closest('[data-topo-level]');
        const node = ev.target.closest('[data-topo-node]');
        if (lvl) {
            const ids = ((s.drawn && s.drawn.lay && s.drawn.lay.levels) || {})[lvl.getAttribute('data-topo-level')] || [];
            const fold = !ids.every(id => s.collapsed.has(id));
            ids.forEach(id => (fold ? s.collapsed.add(id) : s.collapsed.delete(id)));
            s.foldSettled = true;
        } else if (node) {
            const id = node.getAttribute('data-topo-node');
            const toggle = ev.target.closest('[data-topo-toggle]');
            if (id.startsWith('eg:') || toggle) {
                const set = id.startsWith('eg:') ? s.epOpen : s.collapsed;
                if (set.has(id)) set.delete(id); else set.add(id);
                if (set === s.collapsed) s.foldSettled = true;
            } else {
                s.selected = s.selected === id ? '' : id;
            }
        } else {
            s.selected = '';
        }
        _nwTopoRedraw();
    };
    // 2. Wheel zooms around the pointer, like New Central.
    host.addEventListener('wheel', ev => {
        ev.preventDefault();
        const dy = ev.deltaMode === 1 ? ev.deltaY * 16 : ev.deltaY;
        const r = host.getBoundingClientRect();
        _nwTopoZoom(s.zoom * Math.exp(-Math.max(-100, Math.min(100, dy)) * 0.0025),
                    ev.clientX - r.left, ev.clientY - r.top);
    }, { passive: false });
    // 3. Dragging the background pans; the click that ends a drag is ignored.
    host.onpointerdown = ev => {
        if (ev.button !== 0 || ev.target.closest('[data-topo-node],[data-topo-level]')) return;
        s.drag = { x: ev.clientX, y: ev.clientY, l: host.scrollLeft, t: host.scrollTop };
        s.dragged = false;
        host.setPointerCapture(ev.pointerId);
        host.style.cursor = 'grabbing';
    };
    host.onpointermove = ev => {
        if (!s.drag) return;
        const dx = ev.clientX - s.drag.x, dy = ev.clientY - s.drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 4) s.dragged = true;
        host.scrollLeft = s.drag.l - dx;
        host.scrollTop = s.drag.t - dy;
    };
    host.onpointerup = host.onpointercancel = () => { s.drag = null; host.style.cursor = 'grab'; };
    // 4. Keys while the map has focus: + / − zoom, 0 fits.
    host.onkeydown = ev => {
        if (ev.key === '+' || ev.key === '=') _nwTopoZoom(s.zoom * 1.25);
        else if (ev.key === '-' || ev.key === '_') _nwTopoZoom(s.zoom / 1.25);
        else if (ev.key === '0') _nwTopoZoom(_nwTopoFitZoom());
        else return;
        ev.preventDefault();
    };
    // 5. Zoom controls in the corner.
    const controls = document.getElementById('nw-topo-controls');
    if (controls) controls.onclick = ev => {
        const b = ev.target.closest('[data-topo-zoom]');
        const what = b && b.getAttribute('data-topo-zoom');
        if (what === 'in') _nwTopoZoom(s.zoom * 1.25);
        else if (what === 'out') _nwTopoZoom(s.zoom / 1.25);
        else if (what === 'fit') { _nwTopoZoom(_nwTopoFitZoom()); host.scrollLeft = 0; host.scrollTop = 0; }
        else if (what === 'one') _nwTopoZoom(1);
        else if (what === 'full') _nwTopoFullscreen();
    };
    // 6. Details panel: close, jump to a neighbour, pin or unpin the start.
    const panel = document.getElementById('nw-topo-details');
    if (panel) panel.onclick = ev => {
        const jump = ev.target.closest('[data-topo-jump]');
        const act = ev.target.closest('[data-topo-act]');
        if (jump) { _nwTopoFocus(jump.dataset.topoJump); return; }
        if (!act) return;
        const what = act.dataset.topoAct;
        if (what === 'close') s.selected = '';
        if (what === 'root' || what === 'unroot') {
            _nwTopoPref(_nwTopoRootKey(), what === 'root' ? s.selected : '');
            _nwTopoRedraw();
            _nwTopoScrollTo(s.drawn.pos[s.selected]);
            return;
        }
        _nwTopoRedraw();
    };
    // 7. Toolbar: search, orientation, endpoints, expand / collapse all.
    const find = document.getElementById('nw-topo-find');
    if (find) {
        // Enter also fires `change` on an edited box; run that search once.
        let searched = null;
        find.oninput = () => { searched = null; };
        find.onchange = () => { if (find.value !== searched) _nwTopoFind(find.value); searched = null; };
        find.onkeydown = ev => {
            if (ev.key !== 'Enter') return;
            ev.preventDefault();
            searched = find.value;
            _nwTopoFind(find.value);
        };
    }
    const orient = document.getElementById('nw-topo-orient');
    if (orient) {
        orient.value = _nwTopoView().orient;
        orient.onchange = () => {
            _nwTopoPref('lm_nw_topo_orient', orient.value === 'lr' ? 'lr' : 'tb');
            _nwTopoRedraw();
            _nwTopoInitialView();
        };
    }
    const endpointsCheckbox = document.getElementById('nw-topo-endpoints');
    if (endpointsCheckbox) {
        endpointsCheckbox.checked = s.showEndpoints;
        endpointsCheckbox.onchange = () => {
            s.showEndpoints = endpointsCheckbox.checked;
            _nwTopoRedraw();
        };
    }
    const expandBtn = document.getElementById('nw-topo-expand');
    if (expandBtn) expandBtn.onclick = () => {
        s.collapsed.clear();
        s.foldSettled = true;
        if (s.showEndpoints) {
            _nwTopoGroupEndpoints(s.graph.nodes || [], s.graph.edges || [], null)
                .nodes.filter(n => n.kind === 'epgroup').forEach(n => s.epOpen.add(n.id));
        }
        _nwTopoRedraw();
    };
    const collapseBtn = document.getElementById('nw-topo-collapse');
    if (collapseBtn) collapseBtn.onclick = () => {
        (((s.drawn && s.drawn.lay && s.drawn.lay.levels) || {})[0] || []).forEach(id => s.collapsed.add(id));
        s.foldSettled = true;
        s.epOpen.clear();
        _nwTopoRedraw();
    };
}

async function _renderNwTopologyTab(opts) {
    const c = document.getElementById('nw-table-container');
    if (!c) return;
    opts = opts || {};
    const s = _nwTopoState;
    // A newer render, or another tab drawing into the container while this
    // fetch runs, makes this render stale: it must not overwrite that page.
    const seq = ++s.seq;
    const stale = () => seq !== s.seq || !c.isConnected || !c.querySelector(`[data-nw-topo-loading="${seq}"]`);
    c.innerHTML = `<div data-nw-topo-loading="${seq}" class="py-12 text-center text-slate-500 animate-pulse">${
        opts.refresh ? 'Gathering LLDP and MAC tables from every device…' : 'Building topology…'}</div>`;

    const qs = new URLSearchParams();
    if (currentTenant) qs.set('tenant', currentTenant);
    if (opts.refresh) qs.set('refresh', '1');
    if (!s.infer) qs.set('infer', '0');
    let graph;
    try {
        const r = await fetch(`/api/nw/topology?${qs.toString()}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        graph = await r.json();
    } catch (e) {
        if (stale()) return;
        c.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Could not build topology: ${escapeHtml(e.message)}</div>`;
        return;
    }
    if (stale()) return;
    if (graph.select_tenant) {
        c.innerHTML = `<div class="py-12 text-center space-y-3">
            <p class="text-slate-600 text-sm font-semibold">Select a tenant to view its network topology</p>
            <p class="text-slate-500 text-xs max-w-md mx-auto">A map is only coherent within one tenant's slice, so the ADMIN (default) view does not aggregate every tenant's devices. Choose a specific tenant from the tenant picker.</p>
        </div>`;
        return;
    }
    const view = _nwTopoView(true);
    s.graph = graph;
    s.zoom = 1;
    s.drawn = _nwTopoSvg(graph, view, 1);

    const st = graph.stats || {};
    const bySrc = st.edges_by_source || {};
    const legend = Object.keys(_NW_TOPO_EDGE_STYLE).map(k => {
        const ls = _NW_TOPO_EDGE_STYLE[k];
        return `<span class="flex items-center gap-1.5 text-xs text-slate-500">
            <svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="${ls.stroke}" stroke-width="2" ${ls.dash ? `stroke-dasharray="${ls.dash}"` : ''}/></svg>
            ${ls.label} <b class="text-slate-700">${bySrc[k] || 0}</b></span>`;
    }).join('');

    const trunks = (graph.trunks || []).map(t => `<tr class="border-t border-slate-100">
        <td class="py-1 pr-3 font-mono text-xs">${escapeHtml(t.node_name || '')}</td>
        <td class="py-1 pr-3 font-mono text-xs">${escapeHtml(t.port)}</td>
        <td class="py-1 text-xs text-slate-500">${t.mac_count} MACs</td></tr>`).join('');

    const btn = 'px-2 py-1.5 text-xs font-semibold rounded-full border border-slate-300 text-slate-600 hover:bg-slate-50';
    const zbtn = 'px-2 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50 rounded';
    const canEditTopo = isAdmin() || isTenantAdmin();
    c.innerHTML = `<div class="space-y-4">
  <div class="flex flex-wrap items-center gap-4">${legend}</div>
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div class="flex flex-wrap items-center gap-3">
      <input id="nw-topo-find" list="nw-topo-find-list" class="px-2 py-1 text-xs border border-slate-300 rounded w-48"
        placeholder="Find a device…" title="Type a device name or IP and press Enter to show it on the map">
      <datalist id="nw-topo-find-list"></datalist>
      <select id="nw-topo-orient" class="px-2 py-1 text-xs border border-slate-300 rounded" title="Draw the map top-down (gateways at the top, like Aruba Central) or left to right">
        <option value="tb">Top-down</option><option value="lr">Left to right</option>
      </select>
      <label class="flex items-center gap-1.5 text-xs text-slate-500" title="Draw a link for a switch port that has learned exactly one MAC belonging to a known device. A guess, not an advertised adjacency.">
        <input type="checkbox" id="nw-topo-infer" ${s.infer ? 'checked' : ''}> Infer links from MAC tables
      </label>
      <label class="flex items-center gap-1.5 text-xs text-slate-500" title="Include devices known only by a MAC address (hosts, VMs, phones). Off by default: the map shows infrastructure only.">
        <input type="checkbox" id="nw-topo-endpoints"> Show endpoints
      </label>
    </div>
    <div class="flex items-center gap-3">
      <button id="nw-topo-expand" class="${btn}">Expand all</button>
      <button id="nw-topo-collapse" class="${btn}">Collapse all</button>
      <button id="nw-topo-refresh" class="px-3 py-1.5 text-xs font-semibold rounded-full bg-primary text-white hover:bg-[#018f6f]">Refresh from devices</button>
    </div>
  </div>
  <div class="flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-500">
    <span><b class="text-slate-700">${st.infra_nodes ?? st.nodes ?? 0}</b> infrastructure / <b class="text-slate-700">${st.nodes || 0}</b> devices</span>
    <span><b class="text-slate-700">${st.edges || 0}</b> links</span>
    <span><b class="text-slate-700">${st.nodes_without_lldp || 0}</b> without LLDP</span>
    <span><b class="text-slate-700">${st.trunk_ports || 0}</b> trunk/uplink ports</span>
    <span>NetBox inventory: <b class="text-slate-700">${graph.netbox ? 'included' : 'unavailable'}</b></span>
  </div>
  <div id="nw-topo-frame" class="relative border border-slate-200 rounded bg-white">
    <div id="nw-topo-svg" tabindex="0" style="height:70vh;overflow:auto;cursor:grab;outline:none;touch-action:none">${s.drawn.html}</div>
    <div id="nw-topo-details" class="absolute bg-white border border-slate-200 rounded shadow-lg p-3 text-xs"
      style="display:none;top:8px;right:8px;width:300px;max-height:calc(100% - 64px);overflow:auto"></div>
    <div id="nw-topo-controls" class="absolute flex items-center gap-1 bg-white border border-slate-200 rounded shadow" style="right:8px;bottom:8px;padding:2px">
      <button data-topo-zoom="out" class="${zbtn}" title="Zoom out (−)">−</button>
      <span id="nw-topo-zoom-pct" class="text-xs text-slate-500 font-mono" style="min-width:3em;text-align:center">100%</span>
      <button data-topo-zoom="in" class="${zbtn}" title="Zoom in (+)">+</button>
      <button data-topo-zoom="fit" class="${zbtn}" title="Fit the whole map (0)">Fit</button>
      <button data-topo-zoom="one" class="${zbtn}" title="Actual size">1:1</button>
      <button data-topo-zoom="full" class="${zbtn}" title="Full screen">⛶</button>
    </div>
  </div>
  <p class="text-xs text-slate-500">Scroll to zoom, drag to pan, click a device for its links. The −/+ badge folds a branch. An inferred link that doesn't place a device shows when either end is selected.</p>
  ${trunks ? `<div>
    <h4 class="text-xs font-bold text-slate-500 mb-1">Trunk / uplink ports</h4>
    <p class="text-xs text-slate-500 mb-2">These ports carry a whole downstream segment, so what is <em>directly</em> attached can't be inferred. Declare the link below if you know it.</p>
    <table class="w-full text-left"><tbody>${trunks}</tbody></table></div>` : ''}
  ${canEditTopo ? `<div class="border-t border-slate-200 pt-4 space-y-3">
    <h4 class="text-xs font-bold text-slate-500">Devices that don't speak LLDP</h4>
    <p class="text-xs text-slate-500">Declare gear the fleet can't discover (unmanaged switches, media converters, PDUs, cameras). Give a MAC and it will be matched against switch MAC tables automatically — that is what puts it on the map.</p>
    <div id="nw-topo-manual"></div>
  </div>` : ''}
</div>`;

    const refreshBtn = document.getElementById('nw-topo-refresh');
    if (refreshBtn) refreshBtn.onclick = () => _renderNwTopologyTab({ refresh: true });
    const inferBox = document.getElementById('nw-topo-infer');
    if (inferBox) inferBox.onchange = () => {
        s.infer = inferBox.checked;
        _renderNwTopologyTab();
    };
    _nwTopoBindView();
    if (_nwTopoAutoFold()) _nwTopoRedraw();
    _nwTopoFindList();
    _nwTopoInitialView();
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

    const names = ((_nwTopoState.graph || {}).nodes || [])
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
        <td class="py-1 pr-3 text-xs">${escapeHtml(l.a)}${l.a_port ? ` <span class="text-slate-500 font-mono">${escapeHtml(l.a_port)}</span>` : ''}</td>
        <td class="py-1 pr-3 text-xs">${escapeHtml(l.b)}${l.b_port ? ` <span class="text-slate-500 font-mono">${escapeHtml(l.b_port)}</span>` : ''}</td>
        <td class="py-1 pr-3 text-xs text-slate-500">${escapeHtml(l.note || '')}</td>
        <td class="py-1 text-right"><button data-del-link="${escapeHtml(l.id)}" class="text-xs text-red-500 hover:underline">Remove</button></td>
      </tr>`).join('');

    const inp = 'px-2 py-1 text-xs border border-slate-300 rounded';
    host.innerHTML = `<div class="grid md:grid-cols-2 gap-6">
  <div>
    <table class="w-full text-left"><tbody>${devRows || `<tr><td class="py-1 text-xs text-slate-500 italic">None declared</td></tr>`}</tbody></table>
    <div class="flex flex-wrap gap-2 mt-2">
      <input id="nw-topo-dev-name" class="${inp}" placeholder="Name">
      <input id="nw-topo-dev-mac" class="${inp}" placeholder="MAC (optional)">
      <input id="nw-topo-dev-ip" class="${inp}" placeholder="IP (optional)">
      <input id="nw-topo-dev-note" class="${inp}" placeholder="Note">
      <button id="nw-topo-dev-add" class="px-3 py-1 text-xs font-semibold rounded-full bg-slate-700 text-white">Add device</button>
    </div>
  </div>
  <div>
    <h5 class="text-xs font-bold text-slate-500 mb-1">Declared links</h5>
    <table class="w-full text-left"><tbody>${linkRows || `<tr><td class="py-1 text-xs text-slate-500 italic">None declared</td></tr>`}</tbody></table>
    <datalist id="nw-topo-names">${options}</datalist>
    <div class="flex flex-wrap gap-2 mt-2">
      <input id="nw-topo-link-a" list="nw-topo-names" class="${inp}" placeholder="Device A">
      <input id="nw-topo-link-ap" class="${inp} w-20" placeholder="Port">
      <input id="nw-topo-link-b" list="nw-topo-names" class="${inp}" placeholder="Device B">
      <input id="nw-topo-link-bp" class="${inp} w-20" placeholder="Port">
      <input id="nw-topo-link-note" class="${inp}" placeholder="Note">
      <button id="nw-topo-link-add" class="px-3 py-1 text-xs font-semibold rounded-full bg-slate-700 text-white">Add link</button>
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
// Render Network → Scan for the selected tenant: its scan config and
// credential sets (saved vault logins a vault conflict hides are kept on
// #nwt-creds), then its scan schedules.
async function _renderNwScanTab() {
    const c = document.getElementById('nw-table-container');
    if (!c) return;
    // The ADMIN tenant ("default") is a real tenant: an nw spoke bound to it
    // is offered by /api/nw/tenant-config and its scan config lives under
    // nw_tenant_cfg["default"]. Only prompt when no tenant is selected at all.
    if (isAdmin() && !currentTenant) {
        c.innerHTML = `<div class="py-12 text-center space-y-3">
            <p class="text-slate-600 text-sm font-semibold">Select a tenant to configure network scans</p>
            <p class="text-slate-500 text-xs max-w-md mx-auto">Scan settings, schedules and credential sets all belong to a specific tenant. Choose a tenant from the tenant picker to view and edit its scan configuration.</p>
        </div>`;
        return;
    }
    c.innerHTML = `<div class="py-12 text-center text-slate-500 animate-pulse">Loading scan settings…</div>`;

    // Pull the tenant's effective config + its visible scan-credential sets in
    // parallel. Both are tenant-scoped server-side (tenant-admins see only their
    // own tenant + shared).
    let cfg = {}, creds = [], vaultError = '';
    const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    try {
        const [cfgR, credR] = await Promise.all([
            setupFetch(`/api/nw/tenant-config${tenantQs}`),
            // Same tenant scope as the config — otherwise an admin sees every
            // tenant's credential sets listed under whichever tenant is selected.
            setupFetch(`/setup/nw-scan-credentials${tenantQs}`),
        ]);
        if (cfgR.ok) cfg = await cfgR.json();
        if (credR.ok) {
            const cj = await credR.json();
            creds = cj.instances || [];
            // Set when several vault buckets name the tenant: no vault login is offered.
            vaultError = cj.vault_error || '';
        }
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
            <input type="checkbox" class="nwt-cred rounded border-slate-300 text-primary-text focus:ring-green-500" value="${escapeHtml(String(cr.id))}" ${selectedCreds.has(String(cr.id)) ? 'checked' : ''}>
            <span class="font-mono">${escapeHtml(cr.name || cr.id)}</span>${cr.username ? `<span class="text-slate-500">· ${escapeHtml(cr.username)}</span>` : ''}
          </label>`).join('')
        // A refused scan is not discovery-only, so that hint is dropped when
        // the vault error below explains why no vault login is listed.
        : vaultError ? '' : `<p class="text-xs text-slate-500 italic">No scan credential sets belong to this tenant (or the shared tenant). Scans run <b>discovery-only</b> until one exists — it reports which hosts are reachable and what management ports they expose, but cannot identify or add devices. To identify devices, add a set in Setup → Network Devices → Scan Credentials, bind it to <b>this</b> tenant (or the shared tenant so every tenant can use it), and point it at a Credential Vault entry. Note a vault credential on its own is not enough — the scan uses the credential <em>set</em> that references it.</p>`;

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
    const lblCls = 'block text-xs font-bold text-slate-500 mb-1';
    const inCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selCls = inCls;

    c.innerHTML = `<div class="space-y-5 max-w-4xl">
      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Network Discovery Scan</h3>
        <p class="text-xs text-slate-500 mb-4">Discover manageable devices on your network and add them to your fleet automatically. Scans run on your tenant's Network Devices spoke; with no credential set ticked, a scan uses the saved selection, or every set your tenant owns when none is saved.</p>
        <div class="mb-4">
          <p class="${lblCls}">Scan Agent</p>
          ${spokeRows}
        </div>
        <div class="mb-4">
          <p class="${lblCls}">Scan Credential Sets</p>
          <div id="nwt-creds" class="space-y-1.5">${credRows}</div>
          ${vaultError ? '<p class="text-xs text-red-600 mt-1">No vault login is offered; saved ones are kept, though not shown. A scan is refused while a vault login is saved, or when no set is ticked and none is saved: <span id="nwt-vault-error"></span></p>' : ''}
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-crawl" class="rounded border-slate-300 text-primary-text" ${chk(scan.crawl)}> Crawl LLDP neighbors</label>
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-snmp" class="rounded border-slate-300 text-primary-text" ${chk(scan.try_snmp !== false)}> Try SNMP</label>
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-autoadd" class="rounded border-slate-300 text-primary-text" ${chk(scan.auto_add)}> Auto-add discovered</label>
        </div>
        <div class="mb-4">
          <p class="${lblCls}">IP Sources</p>
          <div class="flex flex-wrap gap-4">
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-netbox" class="rounded border-slate-300 text-primary-text" ${chk(srcs.has('netbox'))}> NetBox prefixes</label>
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-nac" class="rounded border-slate-300 text-primary-text" ${chk(srcs.has('nac'))}> NAC endpoints</label>
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-dhcp" class="rounded border-slate-300 text-primary-text" ${chk(srcs.has('dhcp'))}> DHCP leases</label>
            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-src-dns" class="rounded border-slate-300 text-primary-text" ${chk(srcs.has('dns'))}> DNS records</label>
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
          <button onclick="saveNwTenantScanConfig(this)" class="px-4 py-2 rounded-full bg-primary text-white text-sm font-bold hover:bg-[#018f6f]" title="Save tenant network scan configuration">Save config</button>
          <button onclick="runNwTenantScan(this, true)" class="px-4 py-2 rounded-full bg-slate-100 text-slate-700 text-sm font-bold hover:bg-slate-200" title="Run discovery scan in preview mode without adding devices to inventory">Preview scan</button>
          <button onclick="runNwTenantScan(this, false)" class="px-4 py-2 rounded-full bg-blue-600 text-white text-sm font-bold hover:bg-blue-700" title="Execute discovery scan and automatically enroll discovered devices">Scan &amp; add</button>
        </div>
        <div id="nwt-results" class="text-xs mt-3"></div>
      </div>

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Background Supernet Sweep</h3>
        <p class="text-xs text-slate-500 mb-3">First pings the gateway (.1 and .254) of every /24 in your NetBox supernets that isn't a NetBox prefix yet, and adds each /24 that answers to NetBox so scheduled scans cover it. Then it slowly pings the rest of the supernet space and probes hosts that answer (SSH, Telnet, HTTP/HTTPS, NETCONF, SNMP). Hosts it finds are only reported, never added as devices.</p>
        <div id="nwt-sweep" class="text-xs text-slate-500 italic">Loading…</div>
      </div>
      ${(setTimeout(() => _nwtLoadSweep(), 0), '')}

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Recurring Scan Schedule</h3>
        <p class="text-xs text-slate-500 mb-4">On by default (every 6 hours) once your tenant has a Network Devices spoke; discovered devices are added automatically. Tick Preview only to report discoveries without adding them.</p>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-sched-enabled" class="rounded border-slate-300 text-primary-text" ${chk(sched.enabled)}> Enable schedule</label>
          <div><label class="${lblCls}">Interval</label><select id="nwt-sched-interval" class="${selCls}">${opt(_NW_SCHED_INTERVALS, sched.interval_seconds || 0)}</select></div>
          <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwt-sched-dryrun" class="rounded border-slate-300 text-primary-text" ${chk(sched.dry_run !== false)}> Preview only (don't add)</label>
        </div>
      </div>

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Poll Cadence &amp; Anti-Stampede</h3>
        <p class="text-xs text-slate-500 mb-4">Tune how your NW spoke polls your devices. Leave a control on "Inherit global" to use the platform default.</p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div><label class="${lblCls}">Default Poll Interval</label><select id="nwt-poll-default" class="${selCls}">${opt([['', 'Inherit global'], ['900', '15 minutes'], ['3600', '1 hour'], ['21600', '6 hours'], ['43200', '12 hours'], ['86400', 'Daily']], pollVal('default_interval'))}</select></div>
          <div><label class="${lblCls}">Poll Jitter</label><select id="nwt-poll-jitter" class="${selCls}">${opt(_NW_JITTER_OPTS, pollVal('jitter_frac'))}</select></div>
          <div><label class="${lblCls}">Max Devices / Tick</label><select id="nwt-poll-maxtick" class="${selCls}">${opt([['', 'Inherit global'], ['5', '5'], ['10', '10'], ['25', '25'], ['50', '50'], ['100', '100']], pollVal('max_per_tick'))}</select></div>
          <div><label class="${lblCls}">Max Concurrent Polls</label><select id="nwt-poll-maxconc" class="${selCls}">${opt([['', 'Inherit global'], ['2', '2'], ['5', '5'], ['10', '10'], ['20', '20'], ['50', '50']], pollVal('max_concurrency'))}</select></div>
        </div>
        <div class="pt-3 mt-3 border-t border-slate-100">
          <button onclick="saveNwTenantPollSchedule(this)" class="px-4 py-2 rounded-full bg-primary text-white text-sm font-bold hover:bg-[#018f6f]" title="Save recurring scan schedule and polling cadence">Save schedule &amp; cadence</button>
        </div>
      </div>

      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-700 mb-1">Scheduled Scans Already Set Up</h3>
        <p class="text-xs text-slate-500 mb-4">Every recurring scan configured for the selected tenant — or, with no tenant selected, across the tenants you can see.</p>
        <div id="nwt-sched-list"><p class="text-xs text-slate-500 italic">Loading…</p></div>
      </div>
    </div>`;
    // Fill in the vault error as text, so the server's message is never parsed as markup.
    const vaultErrEl = document.getElementById('nwt-vault-error');
    if (vaultErrEl) vaultErrEl.textContent = vaultError;
    // A vault conflict lists no vault login, so keep the saved ones on the
    // list itself: Save config and a scan send them back (_nwtSelectedCreds)
    // instead of dropping them. With no conflict an unlisted saved id is a
    // deleted login, which a save drops as before.
    const credsEl = document.getElementById('nwt-creds');
    if (credsEl) credsEl.dataset.hiddenCreds = JSON.stringify(
        vaultError ? _nwtHiddenVaultCreds(scan.credential_ids, creds) : []);
    _loadNwScanSchedules();
}

// The saved vault login ids (vault:<bucket>:<name>) that the listed sets
// don't include: every saved one while a vault conflict hides them.
function _nwtHiddenVaultCreds(savedIds, shownSets) {
    const shown = new Set((shownSets || []).map(cr => String(cr.id)));
    return (savedIds || []).map(String)
        .filter(id => id.startsWith('vault:') && !shown.has(id));
}

// Fetch + render every configured recurring scan the caller may see. Separate
// from the card markup so it can be refreshed after a schedule is saved without
// repainting the whole tab.
async function _loadNwScanSchedules() {
    const el = document.getElementById('nwt-sched-list');
    if (!el) return;
    try {
        const r = await setupFetch(`/api/nw/scan-schedules${currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : ''}`);
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
        return `<p class="text-xs text-slate-500 italic">No recurring scans are enabled${(d.schedules || []).length ? ' on any tenant you can see' : ''}. Enable one on the card above.</p>`;
    }
    // The scheduler's last/next-run state lives in hub memory, so a restart
    // clears it and every schedule re-defers a full interval. Say so rather
    // than letting a blank "last run" read as "it never ran".
    const note = d.runtime_since_restart
        ? ''
        : `<p class="text-xs text-slate-500 italic mb-2">The hub has not completed a scheduled run since it last restarted — last/next run are tracked in memory and each schedule re-defers one full interval after a restart.</p>`;
    let html = note + '<table class="w-full text-left"><thead><tr class="text-slate-500 text-xs"><th class="py-1">Tenant</th><th>Cadence</th><th>Mode</th><th>Credentials</th><th>Agent</th><th>Last run</th><th>Next due</th></tr></thead><tbody>';
    for (const s of rows) {
        const mode = s.dry_run
            ? '<span class="px-1.5 py-0.5 rounded text-xs font-bold bg-slate-100 text-slate-600" title="Reports discoveries without adding them">preview</span>'
            : '<span class="px-1.5 py-0.5 rounded text-xs font-bold bg-amber-100 text-amber-700" title="Adds identified devices to the fleet automatically">auto-add</span>';
        // Several vault buckets naming the tenant is a configuration error of a
        // scan that needs its vault logins (a run that reaches them is refused),
        // so it is neither discovery-only nor using its sets. The cell names the
        // conflict, not a run's outcome: the Agent and Last run columns say
        // whether a run happens (skipped while the agent is offline).
        const creds = s.vault_error
            ? '<span class="text-red-600" title="Several Credential Vault buckets name this tenant. Until a Global Admin keeps one, a run that needs its vault logins is refused">vault conflict</span>'
            : s.discovery_only
            ? '<span class="text-amber-600" title="No credential sets selected — this run probes reachability and open ports only, and can never add a device">discovery only</span>'
            : escapeHtml(s.credential_names.join(', '));
        const agent = s.spoke_id
            ? (s.spoke_connected ? '<span class="text-emerald-600">connected</span>' : '<span class="text-red-500" title="This schedule will be skipped while its agent is offline">offline</span>')
            : '<span class="text-slate-500" title="No agent pinned — the hub picks a connected agent for this tenant">auto</span>';
        const last = s.last_status
            ? `${escapeHtml(_nwSchedWhen(s.last_run_at))} · ${escapeHtml(s.last_status)}${s.last_added ? ` (+${s.last_added})` : ''}`
            : _nwSchedWhen(s.last_run_at);
        html += `<tr class="border-t border-slate-100 text-slate-600"><td class="py-1 font-semibold">${escapeHtml(s.tenant_name)}</td><td>${escapeHtml(_nwSchedEvery(s.interval_seconds))}</td><td>${mode}</td><td class="text-xs">${creds}</td><td class="text-xs">${agent}</td><td class="text-xs">${last}</td><td class="text-xs">${escapeHtml(_nwSchedWhen(s.next_due_at, { future: true }))}</td></tr>`;
        // The vault error, then the last run's error unless it is the same message.
        const errs = [s.vault_error,
            s.last_error && s.last_error !== s.vault_error && `last error: ${s.last_error}`].filter(Boolean);
        if (errs.length) {
            html += `<tr class="text-xs text-red-500"><td colspan="7" class="pb-1 pl-2">${escapeHtml(errs.join(' · '))}</td></tr>`;
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
// The credential set ids Save config and a scan send: the ticked sets, plus
// the saved vault logins a vault conflict hides (kept on #nwt-creds by
// _renderNwScanTab), so neither drops a tenant's saved vault ids.
function _nwtSelectedCreds() {
    const ticked = Array.from(document.querySelectorAll('.nwt-cred'))
        .filter(el => el.checked).map(el => el.value);
    const hidden = JSON.parse(document.getElementById('nwt-creds')?.dataset.hiddenCreds || '[]');
    return ticked.concat(hidden);
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
        const look = {running: ['Running', 'text-emerald-700'], waiting: ['Waiting for next batch', 'text-slate-500'],
            stalled: ['Stalled', 'text-red-700'], error: ['Error', 'text-red-700'], stopped: ['Stopped', 'text-slate-500'],
            gateway: ['Gateway pass running', 'text-emerald-700'], idle: ['Nothing to sweep', 'text-slate-500'],
            'no-agent': ['No nw agent', 'text-amber-700']}[d.health] || ['Stopped', 'text-slate-500'];
        // Seconds as a short "90s" / "5 min" / "3 h" / "2 days" label.
        const ago = s => s < 120 ? `${s}s` : s < 7200 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`;
        const state = `<span class="font-bold ${look[1]}">${look[0]}</span>`
            + (d.last_batch_ago_s != null ? ` · last batch ${ago(d.last_batch_ago_s)} ago` : '')
            + (d.last_batch_s ? ` (took ${ago(Math.round(d.last_batch_s))})` : '')
            + (d.eta_s != null && d.health !== 'stopped' ? ` · about ${ago(d.eta_s)} left this cycle` : '');
        box.className = 'text-xs text-slate-600';
        box.innerHTML = `<div class="flex flex-wrap items-center gap-3 mb-2">
            <label class="flex items-center gap-2"><input type="checkbox" ${d.enabled ? 'checked' : ''} onchange="nwtSweepAction({enabled: this.checked})"> Enable sweep</label>
            <button onclick="nwtSweepAction({run: true})" class="px-3 py-1 rounded-full bg-slate-100 text-slate-700 font-bold hover:bg-slate-200">Probe next batch now</button>
            <button onclick="nwtSweepAction({reset: true})" class="px-3 py-1 rounded-full bg-slate-100 text-slate-700 font-bold hover:bg-slate-200">Restart cycle</button>
            <span>${state} · ${Number(d.found || 0)} host(s) found · ${d.total ? `Progress ${pct}% of ${d.total} addresses · cycles ${d.cycles || 0}` : 'No supernet space to sweep yet'}${d.last_status ? ` · last: ${escapeHtml(d.last_status)}` : ''}${d.last_error ? ` (${escapeHtml(d.last_error)})` : ''}</span></div>
            <div id="nwt-gw" class="mb-3 p-2 rounded bg-slate-50"></div>`;
        _nwtRenderGateway(document.getElementById('nwt-gw'), d.gateway || {});
    } catch (e) {
        box.textContent = 'Sweep status unavailable: ' + e.message;
    }
}

// Gateway pass status + the /24s it found. Built with textContent (values
// come from the spoke/NetBox) and addEventListener, not inline HTML.
function _nwtRenderGateway(box, g) {
    if (!box) return;
    const el = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };
    const head = el('div', null, 'flex flex-wrap items-center gap-3 mb-1');
    head.append(el('span', 'Subnet discovery (gateway ping)', 'font-bold'));
    const btn = el('button', 'Find subnets now', 'px-3 py-1 rounded bg-slate-100 text-slate-700 font-bold hover:bg-slate-200');
    btn.addEventListener('click', () => { btn.disabled = true; btn.textContent = 'Pinging gateways…'; nwtSweepAction({find_subnets: true}); });
    head.append(btn);
    const found = g.found || [];
    const added = found.filter(f => !f.error).length;
    let status = 'Not run yet';
    if (g.total) {
        const pct = g.cursor ? Math.round(100 * g.cursor / g.total) : (g.cycles ? 100 : 0);
        status = `${pct}% of ${g.total} /24s checked · ${added} subnet(s) added to NetBox · passes ${g.cycles || 0}`;
    } else if (g.last_status === 'no-supernets') {
        status = 'No supernets in NetBox to search';
    }
    if (g.last_error) status += ` · ${g.last_error}`;
    head.append(el('span', status));
    box.replaceChildren(head);
    if (!found.length) return;
    const table = el('table', null, 'w-full text-left mt-1');
    const hr = el('tr', null, 'text-slate-500');
    ['Subnet', 'Gateway', 'Found', 'NetBox'].forEach(h => hr.append(el('th', h)));
    table.append(el('thead'), el('tbody'));
    table.tHead.append(hr);
    found.slice(0, 200).forEach(f => {
        const tr = el('tr');
        tr.append(el('td', f.prefix, 'py-1 pr-3 font-mono'), el('td', f.gateway, 'pr-3 font-mono'),
            el('td', f.found_at ? new Date(f.found_at * 1000).toLocaleString() : '', 'pr-3'),
            el('td', f.error ? `not added: ${f.error}` : 'added', f.error ? 'text-amber-600' : 'text-emerald-700'));
        table.tBodies[0].append(tr);
    });
    box.append(table);
}

async function nwtSweepAction(body) {
    if (currentTenant) body.tenant = currentTenant;
    try {
        const r = await setupFetch('/api/nw/sweep', { method: 'POST', body: JSON.stringify(body) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { showToast(d.detail || 'Sweep action failed', 'error'); return; }
        if (body.run) showToast('Sweep batch: ' + ((d.run || {}).status || 'done'), 'success');
        if (body.find_subnets) {
            const run = d.run || {};
            showToast(run.status === 'ok' ? `Checked ${run.checked} /24s, added ${run.added} subnet(s)` : `Subnet discovery: ${run.reason || run.status}`, run.status === 'ok' ? 'success' : 'error');
        }
    } catch (e) { showToast(e.message, 'error'); }
    _nwtLoadSweep();
}

async function runNwTenantScan(btn, dryRun) {
    const out = document.getElementById('nwt-results');
    const label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = dryRun ? 'Scanning…' : 'Scanning & adding…'; }
    if (out) out.innerHTML = '<p class="text-slate-500 italic animate-pulse">Scanning — this can take a while for large subnets…</p>';
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
    const CATEGORIES = ['Gateways', 'Switches', 'Firewalls', 'IPMI', 'Other'];
    const addServerRow = `<div class="flex justify-end mb-2">${addServerButtonHtml('nw', 'Network Devices')}</div>`;
    if (!devices.length) {
        // Point the user at where devices actually are instead of a dead end.
        const elsewhere = CATEGORIES.filter(c => c !== category && counts[c]);
        const hint = elsewhere.length
            ? `No ${escapeHtml(category.toLowerCase())} configured — devices are under ${elsewhere.map(c => `<button onclick="setSubView('${c}')" class="text-primary-text hover:underline font-semibold">${escapeHtml(c)} (${counts[c]})</button>`).join(', ')}.`
            : `No ${escapeHtml(category.toLowerCase())} configured. Add one in Setup → Network Devices.`;
        container.innerHTML = addServerRow +
            `<div class="py-12 text-center text-slate-500 italic">${hint}</div>`;
        return;
    }
    const keys = ['device', 'object_type', 'transport', 'serial', 'address', 'reachable'];
    const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
    const rows = devices.map(it => {
        const typeLabel = _NW_OBJECT_TYPES[it.object_type] || it.object_type || '—';
        const transport = _NW_TRANSPORTS[it.transport] || it.transport || 'auto';
        const reachable = it.reachable;
        const rcell = reachable === true || reachable === 'up'
            ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-green-100 text-green-700">up</span>'
            : reachable === false || reachable === 'down'
                ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">down</span>'
                : `<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-700" title="Reachability unknown — the Network Devices spoke is offline, so up/down can't be probed">unknown</span>`;
        // event.stopPropagation() keeps the Poll/Configure buttons from also
        // triggering the row's drill-into-detail click.
        const cfg = (isAdmin() || isTenantAdmin())
            ? `<button onclick="event.stopPropagation();pollNwDevice('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}', this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium mr-3" title="Poll device interfaces and status now">Poll Now</button>` +
              `<button onclick="event.stopPropagation();showNwConfigModal('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium" title="Configure device connection parameters">Configure</button>`
            : '';
        return `<tr onclick="nwOpenDevice('${escJsAttr(it.id)}')" class="hover:bg-slate-50 transition-colors cursor-pointer" title="View device details">
            <td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(it.name || it.id)}${it.mac ? `<div class="text-xs font-mono font-normal text-slate-500 mt-0.5">${escapeHtml(String(it.mac))}</div>` : ''}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(typeLabel)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(transport)}</td>
            <td class="px-4 py-3 text-slate-600 text-xs">${_nwSerialCell(it)}</td>
            <td class="px-4 py-3 text-slate-600 font-mono text-xs">${_nwAddressCell(it)}</td>
            <td class="px-4 py-3">${rcell}</td>
            <td class="px-4 py-3 text-right whitespace-nowrap">${cfg}<span class="text-slate-500 ml-2">›</span></td>
        </tr>`;
    }).join('');
    container.innerHTML = addServerRow + `
        <div class="space-y-4">
            <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 text-xs"><tr>${headers}<th class="px-4 py-3"></th></tr></thead>
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

// Performance chart range: a preset (seconds back from now) or a custom start/end.
// The view opens on 24 hours, the same as Firewalls → Overview. Only the last
// hour comes from the hub's warm cache; any other range is read from the spoke,
// which stores 7 days of 5-minute averages.
// Charts and the selector are shared with Firewalls → Overview (js/perf-trends.js).
let _tnRange = { preset: 86400 };
let _tnPerfFleet = [];

// Draw every appliance's trend charts for the selected range.
async function _tnLoadTrends() {
    const { t0, t1, qs } = perfRangeWindow('tn', _tnRange, 3600);
    const pct = v => `${v.toFixed(1)}%`;
    const bytes = v => {
        const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        let i = 0;
        while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
        return `${v.toFixed(i ? 1 : 0)} ${u[i]}/s`;
    };
    await Promise.all(_tnPerfFleet.map(async (a, i) => {
        const box = document.getElementById(`tn-trends-${i}`);
        if (!box) return;
        box.innerHTML = `<div class="text-xs text-slate-400 animate-pulse py-4">Loading history…</div>`;
        let rows = [];
        try {
            const r = await fetch(`/api/truenas/${a.id}/performance/history${qs}`);
            const j = r.ok ? await r.json() : null;
            rows = (j && Array.isArray(j.data)) ? j.data : [];
        } catch (e) { /* empty chart */ }
        box.innerHTML = `
            ${perfTrendChart(`tn-iops-${i}`, 'IOPS', rows, [{ key: 'read_ops', label: 'Read', color: '#0ea5e9' }, { key: 'write_ops', label: 'Write', color: '#f97316' }], v => Math.round(v).toLocaleString(), t0, t1)}
            ${perfTrendChart(`tn-tput-${i}`, 'Throughput', rows, [{ key: 'read_bytes', label: 'Read', color: '#0ea5e9' }, { key: 'write_bytes', label: 'Write', color: '#f97316' }], bytes, t0, t1)}
            ${perfTrendChart(`tn-net-${i}`, 'Network', rows, [{ key: 'net_rx', label: 'Receive', color: '#10b981' }, { key: 'net_tx', label: 'Send', color: '#8b5cf6' }], bytes, t0, t1)}
            ${perfTrendChart(`tn-util-${i}`, 'Utilization', rows, [{ key: 'busy', label: 'Disk busy', color: '#ef4444' }, { key: 'cpu', label: 'CPU', color: '#64748b' }], pct, t0, t1)}`;
        perfTrendWire(box);
    }));
}

async function loadTruenasData(subMenu) {
    const container = document.getElementById('truenas-table-container');
    if (!container) return;
    subMenu = subMenu || currentSubView;
    container.innerHTML = `<div class="py-12 text-center text-slate-500 animate-pulse">Fetching ${subMenu} data…</div>`;

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
    // Human-readable byte count (1024-based).
    const _fmtBytes = n => {
        if (typeof n !== 'number' || !isFinite(n)) return '-';
        const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
        let i = 0;
        while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
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
                container.innerHTML = `<div class="py-12 text-center text-slate-500 italic">No TrueNAS appliances configured. Add one in Setup → TrueNAS Appliances.</div>`;
                return;
            }
            const headers = ['NAME', 'HOST', 'TYPE', 'VERSION', 'STATUS', ''].map(h => `<th class="px-4 py-3">${h}</th>`).join('');
            const rows = items.map(it => {
                const info = (it.info && typeof it.info === 'object') ? it.info : {};
                const reachable = it.reachable;
                const rcell = reachable === true || reachable === 'up'
                    ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-green-100 text-green-700">online</span>'
                    : reachable === false || reachable === 'down'
                        ? '<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">offline</span>'
                        : `<span class="text-slate-500 text-xs">—</span>`;
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
                            <thead class="bg-slate-100 text-slate-600 text-xs"><tr>${headers}</tr></thead>
                            <tbody class="divide-y divide-slate-200">${rows}</tbody>
                        </table>
                    </div>
                </div>`;
            return;
        }

        // ---- Live performance: one card per appliance ----
        if (subMenu === 'Overview') {
            let fleet = [];
            try {
                const dr = await fetch(`/api/truenas/appliances${tenantQs}`);
                if (dr.ok) fleet = _fleetRows(await dr.json());
            } catch (e) { /* handled below */ }
            if (!fleet.length) {
                container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Storage spoke not connected or no appliances configured.</div>`;
                return;
            }
            const results = await Promise.allSettled(fleet.map(a =>
                fetch(`/api/truenas/${a.id}/performance`)
                    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))));
            const num = v => (typeof v === 'number' && isFinite(v)) ? v : null;
            const ops = v => num(v) === null ? '—' : Math.round(v).toLocaleString();
            const rate = v => num(v) === null ? '—' : `${_fmtBytes(v)}/s`;
            const tile = (label, value) => `<div class="rounded-md border border-slate-200 bg-slate-50 px-4 py-3">
                <div class="text-xs text-slate-500">${label}</div>
                <div class="text-lg font-semibold text-slate-800 font-mono">${value}</div></div>`;
            _tnPerfFleet = fleet;
            const names = fleet.map(a => escapeHtml(a.name || a.id));
            // Live tiles for every appliance, then the History selector, then
            // the charts: the same layout as Firewalls → Overview.
            container.innerHTML = `<div class="space-y-6">${fleet.map((a, i) => {
                const res = results[i];
                const name = names[i];
                if (res.status !== 'fulfilled') {
                    return `<div><h3 class="font-semibold text-slate-700 mb-2">${name}</h3>
                        <div class="text-sm text-amber-600">Performance unavailable (${escapeHtml(String(res.reason && res.reason.message || res.reason))}).</div></div>`;
                }
                const p = _extract(res.value) || {};
                const d = p.disks || {};
                const stale = res.value && res.value.stale ? ' <span class="text-xs text-amber-600 font-normal">(last poll — spoke offline)</span>' : '';
                const ifRows = (Array.isArray(p.interfaces) ? p.interfaces : [])
                    .filter(f => f.link_state === 'LINK_STATE_UP').map(f => `<tr>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(f.name || '')}</td>
                    <td class="px-4 py-2 font-mono text-xs">${num(f.speed) ? `${f.speed} Mb/s` : '—'}</td>
                    <td class="px-4 py-2 font-mono text-xs">${rate(f.received_bytes_rate)}</td>
                    <td class="px-4 py-2 font-mono text-xs">${rate(f.sent_bytes_rate)}</td></tr>`).join('');
                return `<div>
                    <h3 class="font-semibold text-slate-700 mb-2">${name}${stale}</h3>
                    <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                        ${tile('Read IOPS', ops(d.read_ops))}
                        ${tile('Write IOPS', ops(d.write_ops))}
                        ${tile('Read throughput', rate(d.read_bytes))}
                        ${tile('Write throughput', rate(d.write_bytes))}
                        ${tile('Disk busy', num(d.busy) === null ? '—' : `${d.busy.toFixed(1)}%`)}
                        ${tile('CPU', num(p.cpu_usage) === null ? '—' : `${p.cpu_usage.toFixed(1)}%`)}
                    </div>
                    ${ifRows ? `<div class="mt-3 overflow-x-auto rounded-md border border-slate-200 bg-white">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-100 text-slate-600 text-xs"><tr><th class="px-4 py-2">INTERFACE</th><th class="px-4 py-2">SPEED</th><th class="px-4 py-2">RECEIVE</th><th class="px-4 py-2">SEND</th></tr></thead>
                            <tbody class="divide-y divide-slate-200">${ifRows}</tbody>
                        </table></div>` : ''}
                </div>`;
            }).join('')}
            ${perfRangeBar('tn', _tnRange)}
            ${fleet.map((_, i) => `<div>
                <h3 class="font-semibold text-slate-700 mb-2">${names[i]}</h3>
                <div id="tn-trends-${i}" class="grid grid-cols-1 xl:grid-cols-2 gap-3"></div>
            </div>`).join('')}
            <div class="text-xs text-slate-500">Tiles are a live sample from each appliance (all disks combined); charts are 5-minute averages, kept 7 days by the storage spoke. <button data-tn-refresh class="text-emerald-600 hover:text-emerald-800 font-medium ml-1">Refresh</button></div>
            </div>`;
            container.querySelector('[data-tn-refresh]').addEventListener('click', () => loadTruenasData('Overview'));
            perfRangeWire(container, 'tn', range => { _tnRange = range; _tnLoadTrends(); });
            _tnLoadTrends();
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
            container.innerHTML = `<div class="py-12 text-center text-slate-500 italic">No ${subMenu} found.${errNote}</div>`;
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
                let raw = item[k];
                // TrueNAS ZFS properties arrive as {value, rawvalue, parsed}; show the readable value.
                if (raw && typeof raw === 'object') raw = raw.value ?? raw.parsed ?? raw.rawvalue ?? JSON.stringify(raw);
                if (subMenu === 'Capacity' && (k === 'used' || k === 'avail') && typeof raw === 'number') raw = _fmtBytes(raw);
                if (k === 'pct_used' && typeof raw === 'number') raw = `${raw}%`;
                const val = raw !== undefined && raw !== null && raw !== '' ? String(raw) : '-';
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
                        <thead class="bg-slate-100 text-slate-600 text-xs"><tr>${headers}</tr></thead>
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
                <h3 class="text-lg font-bold text-navy">Configure ${escapeHtml(deviceName)}</h3>
                <button onclick="closeNwConfigModal()" class="text-slate-500 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-3">
                <p class="text-xs text-slate-500">One command per line. Applied via the device's transport (SSH/CLI or REST) by the nw spoke.</p>
                <textarea id="nw-config-commands" rows="8" placeholder="show version\nshow running-config" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500"></textarea>
                <div id="nw-config-result" class="text-xs text-slate-500"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeNwConfigModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="submitNwConfig('${escapeHtml(deviceId)}')" class="bg-brand/10 hover:bg-brand/20 text-primary-text border border-brand px-6 py-2 rounded-full text-sm font-bold transition-all shadow-sm">Apply</button>
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
    const tile = (label, val, cls) => `<div class="rounded border border-slate-200 px-4 py-3"><div class="text-xs text-slate-500">${label}</div><div class="text-2xl font-semibold ${cls || 'text-slate-700'}">${val}</div></div>`;
    const hostRows = shown.map(h => {
        const pl = (h.problems || []).map(p => `<div>${escapeHtml(sevName[p.severity] || '')}: ${escapeHtml(p.name)}</div>`).join('') || '<span class="text-slate-500">none</span>';
        return `<tr class="border-t border-slate-100">
        <td class="px-3 pt-2 pb-0 text-xs font-medium text-slate-700 whitespace-nowrap">${escapeHtml(String(h.name || '').toUpperCase())}</td>
        <td class="px-3 pt-2 pb-0 text-xs text-slate-500">${escapeHtml(h.tenant)}</td>
        <td class="px-3 pt-2 pb-0 text-xs font-mono text-slate-500">${escapeHtml(h.ip)}</td>
        <td class="px-3 pt-2 pb-0 text-xs text-slate-500">${h.method}</td>
        <td class="px-3 pt-2 pb-0 text-xs"><span class="px-2 py-0.5 rounded ${availCls[h.availability] || availCls.unknown}" title="${escapeHtml(h.error || '')}">${h.availability}${h.enabled ? '' : ' (disabled)'}</span></td>
    </tr><tr><td colspan="5" class="px-3 pt-0 pb-2 text-xs text-slate-600">${pl}</td></tr>`;
    }).join('');
    const table = shown.length
        ? `<table class="w-full text-left mt-4"><thead><tr class="text-xs text-slate-500"><th class="px-3 py-2 whitespace-nowrap min-w-[28rem]">Device / Problems</th><th class="px-3 py-2">Tenant</th><th class="px-3 py-2">Address</th><th class="px-3 py-2">Method</th><th class="px-3 py-2">Status</th></tr></thead><tbody>${hostRows}</tbody></table>`
        : `<div class="py-8 text-center text-slate-500 italic">No monitored devices${tenant ? ` for tenant "${escapeHtml(tenant)}"` : ''}.</div>`;
    const info = admin ? `<div class="mt-4 text-xs text-slate-500">Zabbix ${escapeHtml(String(res.version || '?'))} · ${escapeHtml(String(res.managed_hosts ?? '?'))} managed hosts</div>` : '';
    const sevCls = ['bg-slate-100 text-slate-600', 'bg-sky-100 text-sky-700', 'bg-yellow-100 text-yellow-800', 'bg-amber-100 text-amber-800', 'bg-orange-100 text-orange-800', 'bg-red-100 text-red-700'];
    const allProbs = shown.flatMap(h => (h.problems || []).map(p => ({...p, host: h.name, tenant: h.tenant})))
        .sort((a, b) => (b.severity - a.severity) || (b.clock - a.clock));
    const probRows = allProbs.map(p => `<tr class="border-t border-slate-100">
        <td class="px-3 py-2 text-xs"><span class="px-2 py-0.5 rounded ${sevCls[p.severity] || sevCls[0]}">${escapeHtml(sevName[p.severity] || '')}</span></td>
        <td class="px-3 py-2 text-xs font-medium text-slate-700">${escapeHtml(p.host)}</td>
        <td class="px-3 py-2 text-xs text-slate-500">${escapeHtml(p.tenant)}</td>
        <td class="px-3 py-2 text-xs text-slate-600">${escapeHtml(p.name)}</td>
        <td class="px-3 py-2 text-xs text-slate-500 whitespace-nowrap">${p.clock ? new Date(p.clock * 1000).toLocaleString() : ''}</td>
    </tr>`).join('');
    const problemsTable = `<h3 class="mt-6 text-sm font-semibold text-slate-700">Open problems (${allProbs.length})</h3>` + (allProbs.length
        ? `<div class="max-h-96 overflow-y-auto"><table class="w-full text-left mt-2"><thead class="sticky top-0 bg-white"><tr class="text-xs text-slate-500"><th class="px-3 py-2">Severity</th><th class="px-3 py-2">Device</th><th class="px-3 py-2">Tenant</th><th class="px-3 py-2">Problem</th><th class="px-3 py-2">Since</th></tr></thead><tbody>${probRows}</tbody></table></div>`
        : `<div class="py-4 text-slate-500 italic text-sm">No open problems.</div>`);
    const buttons = admin ? `<p class="text-xs text-slate-500 mt-4">Monitoring syncs with the inventory automatically (schedule and Sync now: System → Sync).</p>` : '';
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

