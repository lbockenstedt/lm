// netbox.js — NetBox IPAM / DCIM.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── NetBox IPAM / DCIM ──────────────────────────────────────────────────────

async function loadNetboxData(subMenu) {
    const container = document.getElementById('netbox-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    // Show/hide the "+ Add" button based on writable sub-views. It lives in the
    // menu strip (far-right #top-nav-actions) rather than the page body.
    const writable = ['Devices', 'Racks', 'Prefixes', 'IP Addresses'];
    const actions = document.getElementById('top-nav-actions');
    if (actions) {
        if (writable.includes(subMenu)) {
            // The Prefixes sub-view also gets an "Add Prefix" finder button:
            // it searches for the closest available subnet to one the tenant
            // already has (RFC1918 free-space scan) and assigns the pick. The
            // manual "+ Add" (carve-from-parent) flow stays alongside it.
            const findBtn = subMenu === 'Prefixes'
                ? `<button onclick="showFindSubnetModal()" class="bg-white border border-[#01A982] text-[#01A982] hover:bg-[#01A982] hover:text-white px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm mr-2" title="Scan for and allocate the next available contiguous subnet">Add Prefix</button>`
                : '';
            // Admin-only Excel rack-layout importer (Setup → Module Management
            // gating is mirrored here: only admins see the button; the hub
            // routes are admin-gated too — defense in depth).
            const importBtn = (subMenu === 'Racks' && isAdmin())
                ? `<button onclick="showRackImportModal()" class="bg-white border border-indigo-500 text-indigo-600 hover:bg-indigo-500 hover:text-white px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm mr-2" title="Import rack elevation layout from an Excel spreadsheet">Import .xlsx</button>`
                : '';
            actions.innerHTML = canEdit()
                ? `${importBtn}${findBtn}<button onclick="showNetboxAddModal()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm" title="Add a new item to NetBox">+ Add</button>`
                : importBtn;
        } else {
            actions.innerHTML = '';
        }
    }

    const th = tableHead, tw = tableWrap;  // shared table helpers
    const escAttr = s => String(s == null ? '' : s).replace(/"/g, '&quot;');
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;
    const viewIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>`;

    try {
        if (subMenu === 'Overview') {
            // Tenant-scoped summary: fan out to the four IPAM endpoints in
            // parallel and render a card grid (Hosts, Racks, Subnets, IPs).
            // allSettled so one spoke-down response degrades just that card to
            // "Unavailable" instead of blanking the whole overview. Each card
            // navigates to its management sub-view on click. Counts mirror the
            // tenant-filtered fetches each sub-view already makes.
            const t = encodeURIComponent(currentTenant);
            const get = (url, key) => fetch(url)
                .then(r => r.json().then(d => ({ ok: r.ok, d, key })));
            const results = await Promise.allSettled([
                get(`/api/netbox/devices?tenant=${t}`, 'devices'),
                get(`/api/netbox/racks?tenant=${t}`, 'racks'),
                get(`/api/netbox/prefixes?tenant=${t}`, 'prefixes'),
                get(`/api/netbox/ips?tenant=${t}`, 'ip_addresses'),
            ]);
            const count = i => {
                const res = results[i];
                if (res.status !== 'fulfilled' || !res.value.ok || res.value.d.status === 'ERROR') return null;
                return (res.value.d[res.value.key] || []).length;
            };
            const card = (label, n, target) => `
                <div onclick="setSubView('${target}')" class="cursor-pointer bg-white rounded-xl border border-slate-200 p-5 hover:border-[#01A982] hover:shadow-md transition-all">
                    <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">${label}</p>
                    <p class="text-3xl font-bold text-[#263040]">${n === null ? '<span class="text-base font-medium text-amber-600">Unavailable</span>' : n}</p>
                </div>`;
            container.innerHTML = `
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 p-4">
                    ${card('Hosts', count(0), 'Devices')}
                    ${card('Racks', count(1), 'Racks')}
                    ${card('Subnets', count(2), 'Prefixes')}
                    ${card('IPs', count(3), 'IP Addresses')}
                </div>`;

        } else if (subMenu === 'Devices') {
            const r = await fetch(`/api/netbox/devices?tenant=${encodeURIComponent(currentTenant)}`);
            // Spoke-down is now a 503 with {detail} (see api.py error contract); older
            // builds returned 200+{status:'ERROR',message}. Handle both so the operator
            // sees the "spoke not connected" notice either way instead of "No devices".
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p><p class="px-4 pb-4 text-xs text-slate-400">Verify the NetBox URL and API Token in Setup → IPAM.</p>`; return; }
            const devices = d.devices || [];
            window._nbDevices = devices;
            const cols = ['Name', 'Status', 'Site', 'Rack', 'Unit', 'Role', 'Type', 'Primary IP', ''];
            const rows = devices.map(dv => {
                const statusCls = dv.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-medium">${dv.name}</td>
                    <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${dv.status}</span></td>
                    <td class="px-4 py-2 text-xs">${dv.site || '—'}</td>
                    <td class="px-4 py-2 text-xs">${dv.rack || '—'}</td>
                    <td class="px-4 py-2 text-center text-xs">${dv.position ?? '—'}</td>
                    <td class="px-4 py-2 text-xs">${dv.role || '—'}</td>
                    <td class="px-4 py-2 text-xs">${dv.device_type || '—'}</td>
                    <td class="px-4 py-2 text-xs font-mono">${dv.primary_ip || '—'}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="editNetboxDevice(${dv.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="deleteNetboxDevice(${dv.id})" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = devices.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No devices found in NetBox.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'Racks') {
            // Tenant-scoped like Devices/Prefixes/IPs: the spoke's get_racks
            // filters by tenant slug when one is passed, so send currentTenant
            // to keep racks inside the tenant boundary instead of listing all.
            const r = await fetch(`/api/netbox/racks?tenant=${encodeURIComponent(currentTenant)}`);
            // 503 {detail} (new) or 200+{status:'ERROR'} (old) — both mean spoke-down.
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p>`; return; }
            const racks = d.racks || [];
            window._nbRacks = racks;
            const cols = ['Name', 'Site', 'Facility ID', 'Height (U)', ''];
            const rows = racks.map(rk => `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-medium">${rk.name}</td>
                <td class="px-4 py-2 text-xs">${rk.site || '—'}</td>
                <td class="px-4 py-2 text-xs font-mono">${rk.facility_id || '—'}</td>
                <td class="px-4 py-2 text-center">${rk.u_height}</td>
                <td class="px-4 py-2 whitespace-nowrap">
                    <button onclick="showRackElevationModal(${rk.id})" title="View elevation" class="p-1 text-slate-400 hover:text-[#01A982] transition-colors">${viewIcon}</button>
                    <button onclick="editNetboxRack(${rk.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                    <button onclick="deleteNetboxRack(${rk.id})" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                </td>
            </tr>`).join('');
            container.innerHTML = racks.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No racks found in NetBox.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'Prefixes') {
            const r = await fetch(`/api/netbox/prefixes?tenant=${encodeURIComponent(currentTenant)}`);
            // 503 {detail} (new) or 200+{status:'ERROR'} (old) — both mean spoke-down.
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p>`; return; }
            const prefixes = d.prefixes || [];
            window._nbPrefixes = prefixes;
            const cols = ['Prefix', 'Status', 'DHCP', 'Site', 'VRF', 'Description', ''];
            const rows = prefixes.map(p => {
                const statusCls = p.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
                const cf = p.custom_fields || {};
                const isDhcp = !!cf.dhcp_enabled && p.status !== 'container';
                const dhcpBadge = isDhcp
                    ? '<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800" title="DHCP scope enabled">DHCP</span>'
                    : '<span class="text-slate-300 text-xs">—</span>';
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(p.prefix)}</td>
                    <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${escapeHtml(p.status)}</span></td>
                    <td class="px-4 py-2 text-center">${dhcpBadge}</td>
                    <td class="px-4 py-2 text-xs">${p.site || '—'}</td>
                    <td class="px-4 py-2 text-xs">${p.vrf || 'Global'}</td>
                    <td class="px-4 py-2 text-xs">${p.description || '—'}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="showNetboxAllocateIPModal('${p.prefix}')" title="Allocate IP address in this subnet" class="p-1 text-slate-400 hover:text-[#01A982] transition-colors text-xs font-medium">+IP</button>
                        <button onclick="releaseSubnetToPool(${p.id}, '${p.prefix}')" title="Return to pool — releases subnet and all its allocated IPs back to available pool for reassignment" class="p-1 text-slate-400 hover:text-amber-600 transition-colors text-xs font-medium">Pool</button>
                        <button onclick="editNetboxPrefix(${p.id})" title="Edit subnet details" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="deleteNetboxPrefix(${p.id})" title="Delete subnet directly from NetBox" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = prefixes.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No prefixes found in NetBox.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'IP Addresses') {
            const r = await fetch(`/api/netbox/ips?tenant=${encodeURIComponent(currentTenant)}`);
            // 503 {detail} (new) or 200+{status:'ERROR'} (old) — both mean spoke-down.
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p>`; return; }
            const ips = d.ip_addresses || [];
            window._nbIPs = ips;
            const cols = ['Address', 'Status', 'MAC', 'DNS Name', 'Description', 'Assigned To', 'Device', ''];
            const rows = ips.map(ip => {
                const statusCls = ip.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
                // mac_address is a NetBox custom field, written by the
                // firewall/Kea→NetBox discovery sync. It was already fetched
                // (the CPPM endpoint sync needs it) but never shown, and it is
                // what a DHCP reservation matches the client on — so surface it
                // and gate the Reserve action on it.
                const nbMac = (ip.custom_fields || {}).mac_address || '';
                const reserveBtn = nbMac
                    ? `<button onclick="reserveNetboxIP(${ip.id})" title="Create a DHCP reservation pinning this address to ${escapeHtml(nbMac)}" class="p-1 text-slate-400 hover:text-[#01A982] transition-colors text-xs font-medium">Reserve</button>`
                    : `<span title="No MAC on this NetBox IP record yet — a DHCP reservation needs one to match the client. Discovery fills it in once the device is seen." class="p-1 text-slate-200 text-xs cursor-not-allowed">Reserve</span>`;
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(ip.address)}</td>
                    <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${escapeHtml(ip.status)}</span></td>
                    <td class="px-4 py-2 text-xs font-mono">${nbMac ? escapeHtml(nbMac) : '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.dns_name || '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.description || '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.assigned_to || '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.device || '—'}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        ${reserveBtn}
                        <button onclick="editNetboxIP(${ip.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="releaseNetboxIP(${ip.id})" title="Release" class="p-1 text-slate-300 hover:text-red-500 transition-colors text-xs">Release</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = ips.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No IP addresses found.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);
        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

function showNetboxAddModal() {
    const subMenu = currentSubView;
    if (subMenu === 'Devices') showNetboxAddDeviceModal();
    else if (subMenu === 'Racks') showNetboxRackModal();
    else if (subMenu === 'Prefixes') showNetboxAllocatePrefixModal();
    else if (subMenu === 'IP Addresses') showNetboxAllocateIPModal('');
}

async function showCPPMDeviceDetail(mac) {
    const modal = openModal('cppm-device-modal', `
        <div class="flex justify-between items-start">
            <p class="font-mono text-base font-bold text-[#263040]">${mac}</p>
            <button class="cppm-modal-close text-slate-400 hover:text-slate-600 text-xl leading-none" title="Close modal">&times;</button>
        </div>
        <div class="cppm-modal-body"><p class="text-xs text-slate-400 italic">Loading…</p></div>`, { card: 'w-full max-w-xl p-6 space-y-4 max-h-[90vh] overflow-y-auto', backdropClose: true });
    modal.querySelector('.cppm-modal-close').addEventListener('click', () => modal.remove());

    const body = modal.querySelector('.cppm-modal-body');
    try {
        const tparam = currentTenant && currentTenant !== 'default' ? `&tenant=${encodeURIComponent(currentTenant)}` : '';
        const [enrichRes, sessRes] = await Promise.all([
            fetch(`/api/cppm/device-enrich?mac=${encodeURIComponent(mac)}${tparam}`),
            fetch(`/api/cppm/device-sessions?mac=${encodeURIComponent(mac)}${tparam}`),
        ]);
        const ep = enrichRes.ok ? await enrichRes.json() : {};
        const sd = sessRes.ok ? await sessRes.json() : {};
        const sources = ep.sources || {};

        const srcBadge = key => sources[key] && sources[key] !== 'ClearPass'
            ? `<span class="ml-1 text-[9px] font-bold uppercase px-1 py-0.5 rounded bg-blue-50 text-blue-500">${sources[key]}</span>` : '';
        const field = (label, val, srcKey) => val
            ? `<div><p class="text-[10px] text-slate-400 uppercase font-bold tracking-wide mb-0.5">${label}${srcKey ? srcBadge(srcKey) : ''}</p><p class="text-sm text-slate-700">${val}</p></div>`
            : '';

        const statusVal = ep.status_val || '';
        const statusCls = statusVal === 'Known' ? 'bg-green-100 text-green-700' : statusVal === 'Unknown' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-500';
        // Full endpoint attribute dump (the summary grid above shows the common
        // fields; this section lists EVERY attribute on the endpoint record so a
        // click on a My Devices / Unknown Devices row surfaces the whole set,
        // including Tenant / Tenant_Slug / NetBox_Tenant_* and profiler attrs).
        const allAttrs = ep.attributes || {};
        // Untagged = assigned to no tenant → eligible to Claim into NetBox.
        const isUntagged = !(allAttrs["NetBox_Tenant_Slug"] || allAttrs["Tenant_Slug"]);
        const attrEntries = Object.entries(allAttrs).filter(([, v]) => v != null && v !== '');
        const attrSection = attrEntries.length
            ? `<div class="mt-3">
                <p class="text-xs text-slate-500 font-bold uppercase tracking-wide mb-2">Endpoint Attributes</p>
                <div class="border border-slate-100 rounded-md p-3 bg-slate-50/50 space-y-1 max-h-56 overflow-y-auto">${attrEntries.map(([k, v]) =>
                    `<div class="flex gap-2 text-xs"><span class="text-slate-400 font-mono min-w-[140px] shrink-0">${k}</span><span class="text-slate-700 break-all">${v}</span></div>`
                ).join('')}</div>
            </div>`
            : '<p class="text-xs text-slate-400 italic mt-3">No endpoint attributes.</p>';

        const sessions = sd.sessions || [];
        const sessionHtml = sessions.length === 0
            ? '<p class="text-xs text-slate-400 italic">No RADIUS accounting sessions found for this device.</p>'
            : `<table class="w-full text-left text-xs border-collapse">
                <thead><tr class="border-b border-slate-200 text-slate-400 uppercase text-[10px]">
                    <th class="px-3 py-1.5">Username</th><th class="px-3 py-1.5">IP</th>
                    <th class="px-3 py-1.5">NAS</th><th class="px-3 py-1.5">Port</th><th class="px-3 py-1.5">Role</th>
                    <th class="px-3 py-1.5">Start</th><th class="px-3 py-1.5">State</th>
                </tr></thead><tbody>${sessions.map(s => `<tr class="border-b border-slate-100">
                    <td class="px-3 py-1.5">${s.username || '—'}</td>
                    <td class="px-3 py-1.5 font-mono">${s.ip || '—'}</td>
                    <td class="px-3 py-1.5">${s.nas_name || '—'}</td>
                    <td class="px-3 py-1.5 font-mono" title="${s.nas_port_type || ''}">${s.nas_port || '—'}</td>
                    <td class="px-3 py-1.5">${s.role || '—'}</td>
                    <td class="px-3 py-1.5">${fmtSessionStart(s.start_time)}</td>
                    <td class="px-3 py-1.5">${s.state || '—'}</td>
                </tr>`).join('')}</tbody></table>`;

        body.innerHTML = `
            <div class="flex items-center gap-2 mb-1">
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${statusVal || '—'}</span>
                ${ep.description ? `<span class="text-xs text-slate-500">${ep.description}</span>` : ''}
            </div>
            <div class="grid grid-cols-2 gap-3">
                ${field('Hostname', ep.hostname, 'hostname')}
                ${field('IP Address', ep.ip, 'ip')}
                ${field('Vendor', ep.device_vendor)}
                ${field('OS', ep.device_os)}
                ${field('Type', ep.device_type)}
            </div>
            ${attrSection}
            <div class="mt-3">
                <p class="text-xs text-slate-500 font-bold uppercase tracking-wide mb-2">Session History</p>
                ${sessionHtml}
            </div>
            ${isUntagged ? `<div class="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between">
                <p class="text-xs text-slate-400">Not assigned to any tenant - claim this device to your tenant.</p>
                <button onclick="showClaimDeviceModal('${encodeURIComponent(mac)}')" title="Claim this unassigned device into NetBox IPAM" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-5 py-2 rounded-md text-sm font-bold shrink-0">Claim Device</button>
            </div>` : ''}`;
    } catch (e) {
        body.innerHTML = `<p class="text-xs text-red-400 italic">Error: ${e.message}</p>`;
    }
}

async function showClaimDeviceModal(mac) {
    const dev = (window._cppmDeviceMap || {})[mac] || {};
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selCls = inputCls;

    // Fetch the NetBox picklists (sites, device types, roles, tenants) so the
    // user chooses from real NetBox values. Server already filters tenants to
    // the non-admin's own; admins see all.
    let opts = { sites: [], device_types: [], device_roles: [], tenants: [] };
    try {
        const r = await fetch('/api/netbox/claim-device/options');
        if (r.ok) opts = await r.json();
    } catch (e) { console.error('showClaimDeviceModal: netbox claim-device options fetch failed — falling back to empty lists', e); }

    const preTenant = currentTenant && currentTenant !== 'default' ? currentTenant : '';
    const tenantLocked = !isAdmin();
    const opt = (arr, slug, label) => (arr || []).map(o =>
        `<option value="${esc(o.slug)}" ${o.slug === slug ? 'selected' : ''}>${esc(label(o))}</option>`).join('');
    const nameDefault = dev.hostname || `endpoint-${(mac || '').replace(/[^a-fA-F0-9]/g, '').toLowerCase()}`;

    const modal = openModal('nb-claim-modal', `
        <h3 class="text-lg font-bold text-[#263040]">Claim in NetBox</h3>
        <p class="text-xs text-slate-500">Creates a NetBox device owned by a tenant and attaches this endpoint's IP. After a sync, the device leaves Unknown Devices and appears under My Devices.</p>
        <div class="rounded-md bg-slate-50 border border-slate-100 p-3 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            <div><span class="text-slate-400">MAC:</span> <span class="font-mono text-slate-700">${esc(dev.mac || mac || '—')}</span></div>
            <div><span class="text-slate-400">IP:</span> <span class="font-mono text-slate-700">${esc(dev.ip || '—')}</span></div>
            <div><span class="text-slate-400">Hostname:</span> <span class="text-slate-700">${esc(dev.hostname || '—')}</span></div>
            <div><span class="text-slate-400">Vendor/OS:</span> <span class="text-slate-700">${esc([dev.device_vendor, dev.device_os].filter(Boolean).join(' / ') || '—')}</span></div>
        </div>
        <div class="grid grid-cols-2 gap-3">
            <div class="col-span-2 space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Name</label><input id="cl-name" value="${esc(nameDefault)}" class="${inputCls}" placeholder="router-01" title="Device name in NetBox"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site <span class="text-red-400">*</span></label><select id="cl-site" class="${selCls}" title="NetBox site to assign device to"><option value="">Select site…</option>${opt(opts.sites, '', o => o.name)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Tenant <span class="text-red-400">*</span></label><select id="cl-tenant" class="${selCls}" ${tenantLocked ? 'disabled' : ''} title="Tenant that owns this device"><option value="">Select tenant…</option>${opt(opts.tenants, preTenant, o => o.name)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Type <span class="text-red-400">*</span></label><select id="cl-type" class="${selCls}" title="Hardware model and manufacturer"><option value="">Select type…</option>${opt(opts.device_types, '', o => `${o.model}${o.manufacturer ? ' (' + o.manufacturer + ')' : ''}`)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Role</label><select id="cl-role" class="${selCls}" title="Functional role in the network"><option value="">Select role…</option>${opt(opts.device_roles, '', o => o.name)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="cl-status" class="${selCls}" title="Operational status in NetBox"><option value="active">active</option><option value="planned">planned</option><option value="offline">offline</option><option value="failed">failed</option><option value="inventory">inventory</option></select></div>
            <div class="col-span-2 space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Description</label><input id="cl-desc" class="${inputCls}" placeholder="optional" title="Optional description or notes"></div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button id="cl-submit" onclick="submitClaimDevice('${encodeURIComponent(mac)}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="Provision device into NetBox and tag endpoint">Claim Device</button>
            <button onclick="document.getElementById('nb-claim-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Cancel device claim">Cancel</button>
        </div>`, { backdropClose: true });
}

async function submitClaimDevice(mac) {
    const modal = document.getElementById('nb-claim-modal');
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const name = get('cl-name');
    const site = get('cl-site');
    const device_type = get('cl-type');
    const tenant = get('cl-tenant');
    if (!name) { showToast('Device name is required', 'error'); return; }
    if (!site) { showToast('Site is required', 'error'); return; }
    if (!device_type) { showToast('Device type is required', 'error'); return; }
    if (!tenant) { showToast('Tenant is required', 'error'); return; }
    const dev = (window._cppmDeviceMap || {})[mac] || {};
    const payload = {
        name, site, device_type, tenant,
        role: get('cl-role'),
        status: get('cl-status') || 'active',
        description: get('cl-desc'),
        mac: dev.mac || mac || '',
        ip: dev.ip || '',
    };
    const btn = document.getElementById('cl-submit');
    if (btn) { btn.disabled = true; btn.textContent = 'Claiming…'; }
    try {
        const r = await fetch('/api/netbox/claim-device', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.status === 'SUCCESS') {
            document.getElementById('nb-claim-modal')?.remove();
            document.getElementById('cppm-device-modal')?.remove();
            showToast('Claimed — syncing to ClearPass');
            loadCPPMData('Unknown Devices');
        } else {
            if (btn) { btn.disabled = false; btn.textContent = 'Claim Device'; }
            showToast('Claim failed: ' + (d.detail || d.message || `HTTP ${r.status}`), 'error');
        }
    } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Claim Device'; }
        showToast('Claim failed: ' + e.message, 'error');
    }
}

function editNetboxDevice(id) {
    const item = (window._nbDevices || []).find(d => d.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxAddDeviceModal(item);
}

function showNetboxAddDeviceModal(editItem, prefill) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = openModal('nb-device-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} Device</h3>
        <div class="grid grid-cols-2 gap-3">
            <div class="col-span-2 space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Name</label><input id="nb-d-name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="router-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site Slug</label><input id="nb-d-site" value="${val(editItem?.site)}" class="${inputCls}" placeholder="lab-a" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Rack Name</label><input id="nb-d-rack" value="${val(editItem?.rack)}" class="${inputCls}" placeholder="Rack-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Rack Unit</label><input id="nb-d-unit" type="number" min="1" value="${val(editItem?.position)}" class="${inputCls}" placeholder="1"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Face</label><select id="nb-d-face" class="${inputCls}"><option value="front">Front</option><option value="rear">Rear</option></select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Type Slug</label><input id="nb-d-type" class="${inputCls}" placeholder="cisco-catalyst-9200" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Role Slug</label><input id="nb-d-role" class="${inputCls}" placeholder="access-switch" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="nb-d-status" class="${inputCls}"><option value="active">active</option><option value="planned">planned</option><option value="offline">offline</option><option value="failed">failed</option><option value="inventory">inventory</option></select></div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="submitNetboxAddDevice()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="${editing ? 'Save changes to device' : 'Register new device in NetBox'}">${editing ? 'Save Changes' : 'Add Device'}</button>
            <button onclick="document.getElementById('nb-device-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Close dialog without saving">Cancel</button>
        </div>`, { card: 'w-full max-w-lg p-6 space-y-4' });
    if (editing) modal.dataset.deviceId = editItem.id;
    if (editing && editItem.status) {
        const st = document.getElementById('nb-d-status');
        if (st) st.value = editItem.status;
    }
    // Add-mode prefill (e.g. opened from the rack elevation view): seed the
    // rack/site/unit/face fields but keep them editable + stay in add (POST) mode.
    if (!editing && prefill) {
        const setv = (id, v) => { const el = document.getElementById(id); if (el && v != null && v !== '') el.value = v; };
        setv('nb-d-site', prefill.site);
        setv('nb-d-rack', prefill.rack);
        setv('nb-d-unit', prefill.rack_unit);
        const face = document.getElementById('nb-d-face');
        if (face && prefill.face) face.value = prefill.face;
        // Remember the elevation we came from so a successful add refreshes it.
        if (prefill.elevRackId != null) modal.dataset.elevRackId = String(prefill.elevRackId);
    }
}

async function submitNetboxAddDevice() {
    const modal = document.getElementById('nb-device-modal');
    const editing = modal && modal.dataset.deviceId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const deviceId = editing ? parseInt(modal.dataset.deviceId) : null;
    if (editing) {
        const payload = {
            name: get('nb-d-name'),
            status: get('nb-d-status') || 'active',
            rack: get('nb-d-rack'),
            rack_unit: get('nb-d-unit') ? parseInt(get('nb-d-unit')) : '',
        };
        try {
            const d = await apiJson(`/api/netbox/devices/${deviceId}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
            if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('Devices'); }
            else showToast('Error: ' + (d.message || 'Update failed'), 'error');
        } catch (e) { showToast('Error: ' + e.message, 'error'); }
        return;
    }
    const payload = {
        name: get('nb-d-name'), site: get('nb-d-site'), rack: get('nb-d-rack'),
        rack_unit: parseInt(get('nb-d-unit')) || 1, face: get('nb-d-face'),
        device_type: get('nb-d-type'), role: get('nb-d-role'), status: get('nb-d-status') || 'active',
    };
    try {
        const d = await apiJson('/api/netbox/devices', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        if (d.status === 'SUCCESS') {
            const elevRackId = modal && modal.dataset.elevRackId;
            document.getElementById('nb-device-modal')?.remove();
            showToast('Device added', 'success');
            // Came from the rack elevation view → re-open it so the new device shows;
            // otherwise refresh the Devices list.
            if (elevRackId) showRackElevationModal(elevRackId);
            else loadNetboxData('Devices');
        } else {
            showToast('Error: ' + (d.message || 'Unknown error'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteNetboxDevice(deviceId) {
    if (!await showConfirmToast('Delete this device from NetBox?')) return;
    try {
        const d = await apiJson(`/api/netbox/devices/${deviceId}`, { method: 'DELETE' });
        if (d.status === 'SUCCESS') loadNetboxData('Devices');
        else showToast('Error: ' + (d.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

function editNetboxRack(id) {
    const item = (window._nbRacks || []).find(r => r.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxRackModal(item);
}

async function showNetboxRackModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const esc = escapeHtml;
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';

    // Pull the real NetBox sites so the user picks from a dropdown instead of
    // typing a free-text slug. /api/netbox/sites → { sites: [{id,name,slug}] }.
    // add_rack takes a site SLUG, so option values are slugs. On edit the site
    // is immutable (update_rack doesn't take it) → disabled select, preselected
    // by matching the rack's stored site NAME (get_racks returns the name, not
    // the slug). Falls back to a free-text slug input if the sites list is
    // empty / fetch fails, so the form still works offline.
    let sites = [];
    try {
        const r = await fetch('/api/netbox/sites');
        if (r.ok) { const d = await r.json(); sites = d.sites || []; }
    } catch (e) { console.error('showNetboxRackModal: sites fetch failed — falling back to free-text', e); }

    const curSiteName = val(editItem?.site);
    let siteField;
    if (sites.length) {
        const matched = sites.find(s => s.name === curSiteName);
        const opts = sites.map(s => {
            const sel = (matched ? s.slug === matched.slug : s.name === curSiteName) ? 'selected' : '';
            return `<option value="${esc(s.slug)}" ${sel}>${esc(s.name)} <${esc(s.slug)}></option>`;
        }).join('');
        // When editing a rack whose site isn't in the current list, show the
        // stored name as a disabled-looking placeholder so the field isn't blank.
        const placeholder = (editing && !matched)
            ? `<option value="" selected>${esc(curSiteName) || '—'}</option>`
            : `<option value="">Select site…</option>`;
        siteField = `<select id="nb-r-site" class="${inputCls}" ${editing ? 'disabled' : ''}>${placeholder}${opts}</select>`;
    } else {
        siteField = `<input id="nb-r-site" value="${curSiteName}" class="${inputCls}" placeholder="lab-a" ${editing ? 'readonly' : ''}>`;
    }

    const modal = openModal('nb-rack-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} Rack</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Rack Name</label><input id="nb-r-name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="Rack-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site</label>${siteField}</div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Height (U)</label><input id="nb-r-uheight" type="number" min="1" value="${val(editItem?.u_height) || 42}" class="${inputCls}" placeholder="42"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Facility ID (optional)</label><input id="nb-r-facility" value="${val(editItem?.facility_id)}" class="${inputCls}" placeholder="A1"></div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="submitNetboxRack()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="${editing ? 'Save changes to rack' : 'Add new rack to NetBox'}">${editing ? 'Save Changes' : 'Add Rack'}</button>
            <button onclick="document.getElementById('nb-rack-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Close dialog without saving">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    if (editing) modal.dataset.rackId = editItem.id;
}

async function submitNetboxRack() {
    const modal = document.getElementById('nb-rack-modal');
    const editing = modal && modal.dataset.rackId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        name: get('nb-r-name'),
        site: get('nb-r-site'),
        u_height: parseInt(get('nb-r-uheight')) || 42,
        facility_id: get('nb-r-facility') || undefined,
        // Stamp the current tenant so a rack created from a tenant view lands in
        // that tenant (mirrors submitNetboxAllocatePrefix). 'default' = global.
        tenant: (currentTenant && currentTenant !== 'default') ? currentTenant : undefined,
    };
    if (!payload.name || (!editing && !payload.site)) {
        showToast('Name and Site are required', 'error');
        return;
    }
    try {
        // See submitNetboxAllocatePrefix: 'default' (Admin tenant) can't be
        // stamped into the body (also the unscoped/global sentinel), so pass
        // it as ?tenant= context — the server resolves it through that
        // tenant's configured NetBox link instead of creating it unassigned.
        const qs = (!editing) ? `?tenant=${encodeURIComponent(currentTenant || 'default')}` : '';
        const url = editing ? `/api/netbox/racks/${modal.dataset.rackId}` : `/api/netbox/racks${qs}`;
        const d = await apiJson(url, { method: editing ? 'PUT' : 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('Racks'); }
        else showToast('Error: ' + (d.message || 'Operation failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteNetboxRack(rackId) {
    if (!await showConfirmToast('Delete this rack from NetBox?')) return;
    try {
        const d = await apiJson(`/api/netbox/racks/${rackId}`, { method: 'DELETE' });
        if (d.status === 'SUCCESS') loadNetboxData('Racks');
        else showToast('Error: ' + (d.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

function editNetboxPrefix(id) {
    const item = (window._nbPrefixes || []).find(p => p.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxAllocatePrefixModal(item);
}

async function showNetboxAllocatePrefixModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selectCls = inputCls;
    const allocFields = editing ? '' : `
        <div class="space-y-1">
            <label class="text-xs text-slate-500 font-bold uppercase">Parent Prefix</label>
            <select id="nb-p-parent" class="${selectCls}"><option value="">Loading…</option></select>
        </div>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Prefix Length</label><input id="nb-p-len" type="number" min="1" max="32" value="24" class="${inputCls}"></div>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Subnet (optional)</label><input id="nb-p-prefix" class="${inputCls}" placeholder="10.0.0.16/28 — exact subnet to create; blank = auto"></div>`;
    const statusOpts = ['active', 'container', 'reserved', 'deprecated'].map(s =>
        `<option value="${s}"${editing && editItem.status === s ? ' selected' : ''}>${s}</option>`).join('');
    // dhcp_enabled is the explicit opt-in checkbox: a prefix only becomes a
    // Kea DHCP scope when this is checked (and status isn't "container") —
    // so allocating a large parent block (e.g. a tenant's /17) never turns
    // the WHOLE block into one giant scope. Carve smaller child prefixes
    // below it and check this only on the ones meant to actually hand out
    // addresses.
    const cf = editItem?.custom_fields || {};
    const dhcpChecked = editing ? !!cf.dhcp_enabled : false;
    // DHCP option fields all live on the same NetBox prefix custom_fields
    // (see lm's dns_dhcp_sync.build_dhcp_payload / kea_manager.build_subnet4
    // for the full option → Kea option-data mapping) — Gateway/DNS/Search
    // Domain are the common ones an operator sets on nearly every scope;
    // everything else is tucked behind "Advanced options" so the common case
    // stays a short form.
    const opt = (id, label, placeholder, value) =>
        `<div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">${label}</label><input id="${id}" value="${val(value)}" class="${inputCls}" placeholder="${placeholder}"></div>`;
    const leaseVal = (cf.lease_time != null && String(cf.lease_time).trim() !== '') ? cf.lease_time : '2419200';
    const exclVal = cf.exclusion_ranges || cf.exclusions || '';
    const commonOptionFields = `
            ${opt('nb-p-gateway', 'Gateway', 'e.g. 10.0.0.1', cf.gateway)}
            ${opt('nb-p-dns', 'DNS Servers', 'comma-separated, e.g. 10.0.0.53, 10.0.0.54', cf.dns_servers)}
            ${opt('nb-p-domain', 'Domain Name', 'e.g. lab.local', cf.domain_name)}
            ${opt('nb-p-search', 'Search Domain', 'comma-separated, e.g. lab.local', cf.search_domain)}
            ${opt('nb-p-lease', 'Lease Time (seconds)', '2419200', leaseVal)}
            ${opt('nb-p-exclusions', 'Exclusion Range(s)', 'comma-separated, e.g. 10.0.0.1-10.0.0.20, 10.0.0.200-10.0.0.254', exclVal)}`;
    const advancedOptionFields = `
            ${opt('nb-p-ntp', 'NTP Servers', 'comma-separated', cf.ntp_servers)}
            ${opt('nb-p-tftp', 'TFTP Server Name', 'e.g. tftp.lab.local', cf.tftp_server_name)}
            ${opt('nb-p-bootfile', 'Boot File Name', 'e.g. pxelinux.0', cf.boot_file_name)}
            ${opt('nb-p-netbios', 'NetBIOS Name Servers', 'comma-separated', cf.netbios_name_servers)}
            ${opt('nb-p-bcast', 'Broadcast Address', 'e.g. 10.0.0.255', cf.broadcast_address)}`;
    const modal = openModal('nb-prefix-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Allocate'} Subnet${editing ? ` — <span class="font-mono text-sm">${val(editItem.prefix)}</span>` : ''}</h3>
        <div class="space-y-4">
            ${allocFields ? `<div class="grid grid-cols-1 md:grid-cols-3 gap-3">${allocFields}</div>` : ''}
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Description</label><input id="nb-p-desc" value="${val(editItem?.description)}" class="${inputCls}" placeholder="e.g. Lab Tenant A VLAN10"></div>
                <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site Slug (optional)</label><input id="nb-p-site" value="${val(editItem?.site)}" class="${inputCls}" placeholder="lab-a"></div>
                ${editing ? `<div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="nb-p-status" class="${selectCls}">${statusOpts}</select></div>` : ''}
            </div>
            <div>
                <label class="flex items-center gap-2 text-sm text-slate-600">
                    <input type="checkbox" id="nb-p-dhcp" class="rounded border-slate-300 text-[#01A982]" ${dhcpChecked ? 'checked' : ''}>
                    Enable DHCP scope for this subnet
                </label>
                <p class="text-xs text-slate-400 mt-0.5">Only checked, non-container prefixes are synced to Kea as a DHCP scope. Leave unchecked on a parent/aggregate block — carve smaller child subnets and enable this on those instead.</p>
            </div>
            <div class="border-t border-slate-200 pt-3 space-y-3">
                <div class="text-xs font-bold uppercase text-slate-500">DHCP Options</div>
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                    ${commonOptionFields}
                </div>
                <div>
                    <button type="button" onclick="document.getElementById('nb-p-advanced').classList.toggle('hidden'); this.textContent = this.textContent.startsWith('Show') ? 'Hide advanced options' : 'Show advanced options ▾'" class="text-xs font-bold text-[#01A982] hover:underline" title="Toggle visibility of advanced DHCP options (NTP, TFTP, Bootfile, NetBIOS, Broadcast)">Show advanced options ▾</button>
                </div>
                <div id="nb-p-advanced" class="hidden grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-1">${advancedOptionFields}</div>
            </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="submitNetboxAllocatePrefix()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="${editing ? 'Save changes to prefix' : 'Allocate subnet prefix in NetBox'}">${editing ? 'Save Changes' : 'Allocate'}</button>
            <button onclick="document.getElementById('nb-prefix-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Close dialog without saving">Cancel</button>
        </div>`, { card: 'w-full max-w-4xl p-6 space-y-4 max-h-[90vh] overflow-y-auto' });
    if (editing) modal.dataset.prefixId = editItem.id;

    if (editing) return;

    // Populate parent prefix dropdown from NetBox
    try {
        const url = currentTenant && currentTenant !== 'default'
            ? `/api/netbox/prefixes?tenant=${encodeURIComponent(currentTenant)}`
            : '/api/netbox/prefixes';
        const r = await fetch(url, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        const prefixes = (d.prefixes || []).map(p => p.prefix).sort();
        const sel = document.getElementById('nb-p-parent');
        if (sel) {
            sel.innerHTML = prefixes.length
                ? `<option value="">— select parent prefix —</option>` + prefixes.map(p => `<option value="${p}">${p}</option>`).join('')
                : `<option value="">No prefixes found in NetBox</option>`;
        }
    } catch (err) {
        console.error('showNetboxAllocatePrefixModal: could not load parent prefixes', err);
        const sel = document.getElementById('nb-p-parent');
        if (sel) sel.innerHTML = `<option value="">Could not load prefixes</option>`;
    }
}

async function submitNetboxAllocatePrefix() {
    const modal = document.getElementById('nb-prefix-modal');
    const editing = modal && modal.dataset.prefixId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const dhcpEnabled = !!document.getElementById('nb-p-dhcp')?.checked;
    // Every DHCP option lives in NetBox custom_fields (see
    // custom_fields_spec.CUSTOM_FIELDS_SPEC in the netbox repo) — shared by
    // both the create and edit submit paths so they can never drift.
    const dhcpOptionFields = {
        gateway:               get('nb-p-gateway'),
        dns_servers:           get('nb-p-dns'),
        search_domain:         get('nb-p-search'),
        domain_name:           get('nb-p-domain'),
        ntp_servers:           get('nb-p-ntp'),
        tftp_server_name:      get('nb-p-tftp'),
        boot_file_name:        get('nb-p-bootfile'),
        netbios_name_servers:  get('nb-p-netbios'),
        broadcast_address:     get('nb-p-bcast'),
        lease_time:            get('nb-p-lease') ? parseInt(get('nb-p-lease')) || undefined : undefined,
        exclusion_ranges:      get('nb-p-exclusions'),
    };
    if (editing) {
        const payload = {
            description: get('nb-p-desc'),
            status: get('nb-p-status') || 'active',
            site: get('nb-p-site') || undefined,
            custom_fields: { dhcp_enabled: dhcpEnabled, ...dhcpOptionFields },
        };
        try {
            const d = await apiJson(`/api/netbox/prefixes/${modal.dataset.prefixId}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
            if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('Prefixes'); }
            else showToast('Error: ' + (d.message || 'Update failed'), 'error');
        } catch (e) { showToast('Error: ' + e.message, 'error'); }
        return;
    }
    const payload = {
        parent_prefix: get('nb-p-parent'),
        prefix_length: parseInt(get('nb-p-len')) || 24,
        requested_prefix: get('nb-p-prefix') || undefined,
        description: get('nb-p-desc'),
        site: get('nb-p-site') || undefined,
        status: 'active',
        custom_fields: { dhcp_enabled: dhcpEnabled, ...dhcpOptionFields },
        tenant: (currentTenant && currentTenant !== 'default') ? currentTenant : undefined,
    };
    try {
        // 'default' (the built-in Admin tenant) can't be stamped into the body
        // above — it's also the unscoped/global sentinel — so pass it as the
        // same ?tenant= context every read route already uses; the server
        // resolves it through that tenant's configured NetBox link (if any)
        // instead of silently creating the prefix unassigned.
        const qs = `?tenant=${encodeURIComponent(currentTenant || 'default')}`;
        const d = await apiJson(`/api/netbox/prefixes${qs}`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-prefix-modal')?.remove();
            showToast(`Allocated: ${d.prefix}`, 'success');
            loadNetboxData('Prefixes');
        } else {
            showToast('Error: ' + (d.message || 'Allocation failed'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteNetboxPrefix(prefixId) {
    if (!await showConfirmToast('Delete this prefix from NetBox? Any IP addresses under it may also be removed.')) return;
    try {
        const d = await apiJson(`/api/netbox/prefixes/${prefixId}`, { method: 'DELETE' });
        if (d.status === 'SUCCESS') loadNetboxData('Prefixes');
        else showToast('Error: ' + (d.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ─── Add Prefix finder + release-to-pool ─────────────────────────────────────
//
// "Add Prefix": search for the closest available subnet to one the tenant
// already has (free = undefined-in-NetBox or defined-but-unassigned, RFC1918
// only), ranked by numeric distance; the user picks one and Assigns it. Size is
// given as a prefix length or as a host count (smallest mask that fits). If
// nothing is available, the user can type a subnet — the exact typed CIDR is
// tried first, else the nearest free one. "Pool" on a prefix row returns it to
// the pool (deletes it from NetBox).

function _maskForHosts(hosts) {
    hosts = parseInt(hosts) || 1;
    for (let L = 30; L >= 22; L--) {
        if ((1 << (32 - L)) - 2 >= hosts) return L;
    }
    return 22;
}
function _usableForMask(L) { return (1 << (32 - L)) - 2; }

async function showFindSubnetModal() {
    const existing = document.getElementById('nb-find-modal');
    if (existing) { existing.remove(); return; }
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = openModal('nb-find-modal', `
        <h3 class="text-lg font-bold text-[#263040]">Add Prefix</h3>
        <p class="text-xs text-slate-500 -mt-2">Finds the closest available subnet to one you already have (RFC1918 only; free = not in NetBox or unassigned).</p>
        <div class="space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="space-y-1">
                    <label class="text-xs text-slate-500 font-bold uppercase">Close to (your existing subnet)</label>
                    <select id="nb-f-near" class="${inputCls}"><option value="">Loading…</option></select>
                </div>
                <div class="space-y-1">
                    <label class="text-xs text-slate-500 font-bold uppercase">Size</label>
                    <div class="flex gap-2 items-center">
                        <select id="nb-f-size-mode" class="${inputCls} flex-none w-36" onchange="_onFindSizeModeChange()">
                            <option value="mask">Prefix length</option>
                            <option value="hosts">Hosts needed</option>
                        </select>
                        <select id="nb-f-mask" class="${inputCls} flex-1">
                            ${[22,23,24,25,26,27,28,29,30].map(m => `<option value="${m}">/${m}</option>`).join('')}
                        </select>
                        <input id="nb-f-hosts" type="number" min="1" value="60" class="${inputCls} flex-1 hidden" oninput="_updateFindSizeHint()">
                    </div>
                    <p id="nb-f-size-hint" class="text-[10px] text-slate-400"></p>
                </div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="space-y-1">
                    <label class="text-xs text-slate-500 font-bold uppercase">Description (optional)</label>
                    <input id="nb-f-desc" class="${inputCls}" placeholder="e.g. Lab Tenant A VLAN11">
                </div>
                <div class="space-y-1 flex items-end">
                    <button onclick="searchAvailableSubnets()" class="bg-slate-700 hover:bg-slate-800 text-white px-4 py-2 rounded-md text-sm font-bold w-full h-[38px]">Search Available Subnets</button>
                </div>
            </div>
            <div class="space-y-1 hidden" id="nb-f-typewrap">
                <label class="text-xs text-slate-500 font-bold uppercase">Type a subnet to search near (exact tried first, else nearest)</label>
                <input id="nb-f-typed" class="${inputCls}" placeholder="10.50.0.0/24">
            </div>
            <div id="nb-f-results" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 max-h-48 overflow-y-auto"></div>
            <div>
                <label class="flex items-center gap-2 text-sm text-slate-600">
                    <input type="checkbox" id="nb-f-dhcp" class="rounded border-slate-300 text-[#01A982]">
                    Enable DHCP scope for this subnet
                </label>
                <p class="text-xs text-slate-400 mt-0.5">Only checked, non-container prefixes are synced to Kea as a DHCP scope.</p>
            </div>
            <div class="border-t border-slate-200 pt-3 space-y-3">
                <div class="text-xs font-bold uppercase text-slate-500">DHCP Options</div>
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                    <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Gateway</label><input id="nb-f-gateway" class="${inputCls}" placeholder="e.g. 10.0.0.1"></div>
                    <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">DNS Servers</label><input id="nb-f-dns" class="${inputCls}" placeholder="comma-separated, e.g. 10.0.0.53, 10.0.0.54"></div>
                    <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Domain Name</label><input id="nb-f-domain" class="${inputCls}" placeholder="e.g. lab.local"></div>
                    <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Search Domain</label><input id="nb-f-search" class="${inputCls}" placeholder="comma-separated, e.g. lab.local"></div>
                    <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Lease Time (seconds)</label><input id="nb-f-lease" class="${inputCls}" placeholder="2419200" value="2419200"></div>
                    <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Exclusion Range(s)</label><input id="nb-f-exclusions" class="${inputCls}" placeholder="comma-separated, e.g. 10.0.0.1-10.0.0.20"></div>
                </div>
            </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button id="nb-f-assign-btn" onclick="submitFindSubnetAssign()" disabled class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold disabled:opacity-40 disabled:cursor-not-allowed">Assign</button>
            <button onclick="document.getElementById('nb-find-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>`, { card: 'w-full max-w-4xl p-6 space-y-4 max-h-[90vh] overflow-y-auto', backdropClose: true });
    window._nbFindAvail = [];
    window._nbFindSelected = null;

    // Populate "close to" with the tenant's own prefixes; default the mask to
    // the first one's mask.
    try {
        const url = currentTenant && currentTenant !== 'default'
            ? `/api/netbox/prefixes?tenant=${encodeURIComponent(currentTenant)}`
            : '/api/netbox/prefixes';
        const r = await fetch(url, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        const prefixes = (d.prefixes || []).map(p => p.prefix).sort();
        const sel = document.getElementById('nb-f-near');
        if (sel) {
            sel.innerHTML = prefixes.length
                ? `<option value="">— select an existing subnet —</option>` + prefixes.map(p => `<option value="${p}">${p}</option>`).join('')
                : `<option value="">No existing subnets — type one below</option>`;
        }
        if (prefixes.length) {
            const m = prefixes[0].split('/')[1];
            const maskSel = document.getElementById('nb-f-mask');
            if (maskSel && m) maskSel.value = m;
        }
    } catch (err) {
        console.error('showFindSubnetModal: could not load prefixes', err);
        const sel = document.getElementById('nb-f-near');
        if (sel) sel.innerHTML = `<option value="">Could not load prefixes</option>`;
    }
    _updateFindSizeHint();
}

function _onFindSizeModeChange() {
    const mode = document.getElementById('nb-f-size-mode').value;
    document.getElementById('nb-f-mask').classList.toggle('hidden', mode === 'hosts');
    document.getElementById('nb-f-hosts').classList.toggle('hidden', mode === 'mask');
    _updateFindSizeHint();
}

function _updateFindSizeHint() {
    const mode = document.getElementById('nb-f-size-mode')?.value;
    const hint = document.getElementById('nb-f-size-hint');
    if (!hint) return;
    if (mode === 'hosts') {
        const L = _maskForHosts(document.getElementById('nb-f-hosts').value);
        hint.textContent = `→ /${L} (${_usableForMask(L)} usable hosts)`;
    } else {
        const L = parseInt(document.getElementById('nb-f-mask').value);
        hint.textContent = `/${L} = ${_usableForMask(L)} usable hosts`;
    }
}

function _findPrefixLength() {
    const mode = document.getElementById('nb-f-size-mode').value;
    if (mode === 'hosts') return _maskForHosts(document.getElementById('nb-f-hosts').value);
    return parseInt(document.getElementById('nb-f-mask').value) || 24;
}

async function searchAvailableSubnets() {
    const near = document.getElementById('nb-f-near')?.value?.trim() || '';
    const typed = document.getElementById('nb-f-typed')?.value?.trim() || '';
    const anchor = near || typed;
    if (!anchor) { showToast('Pick an existing subnet or type one to search near.', 'success'); return; }
    const prefixLength = _findPrefixLength();
    const resultsEl = document.getElementById('nb-f-results');
    const assignBtn = document.getElementById('nb-f-assign-btn');
    resultsEl.innerHTML = '<p class="text-xs text-slate-400 italic">Searching…</p>';
    assignBtn.disabled = true;
    window._nbFindSelected = null;
    try {
        const params = new URLSearchParams({ near: anchor, prefix_length: String(prefixLength), count: '20' });
        if (typed) params.set('exact', typed);
        const r = await fetch(`/api/netbox/available-subnets?${params}`, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        if (d.status === 'ERROR') { resultsEl.innerHTML = `<p class="text-xs text-red-500">${d.message || 'Search failed'}</p>`; return; }
        const avail = d.available || [];
        if (!avail.length) {
            resultsEl.innerHTML = `<p class="text-xs text-amber-600">No subnets available near ${anchor}. Type one below and search again.</p>`;
            document.getElementById('nb-f-typewrap').classList.remove('hidden');
            return;
        }
        document.getElementById('nb-f-typewrap').classList.add('hidden');
        window._nbFindAvail = avail;
        resultsEl.innerHTML = avail.map((a, i) => {
            const distLabel = a.distance === 0 ? 'exact' : `${a.distance} away`;
            return `<label class="flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-slate-50 cursor-pointer border border-slate-100">
                <input type="radio" name="nb-f-pick" value="${i}" onchange="_pickFindSubnet(${i})">
                <span class="font-mono text-sm">${a.prefix}</span>
                <span class="text-[10px] text-slate-400 ml-auto">${distLabel}</span>
            </label>`;
        }).join('');
        _pickFindSubnet(0);
    } catch (e) {
        resultsEl.innerHTML = `<p class="text-xs text-red-500">Error: ${e.message}</p>`;
    }
}

function _pickFindSubnet(i) {
    const a = (window._nbFindAvail || [])[i];
    if (!a) return;
    window._nbFindSelected = a.prefix;
    document.querySelectorAll('input[name="nb-f-pick"]').forEach(el => { el.checked = parseInt(el.value) === i; });
    document.getElementById('nb-f-assign-btn').disabled = false;
}

async function submitFindSubnetAssign() {
    const prefix = window._nbFindSelected;
    if (!prefix) { showToast('Search and pick a subnet first.', 'success'); return; }
    const desc = document.getElementById('nb-f-desc')?.value?.trim() || '';
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const dhcpEnabled = !!document.getElementById('nb-f-dhcp')?.checked;
    // Mirrors submitNetboxAllocatePrefix's custom_fields shape — see
    // custom_fields_spec.CUSTOM_FIELDS_SPEC in the netbox repo — so the "Add
    // Prefix" finder's DHCP checkbox actually takes effect at creation time
    // instead of being silently dropped (previously the only way to enable
    // DHCP on a prefix created through this flow was a separate Edit step).
    const customFields = {
        dhcp_enabled:     dhcpEnabled,
        gateway:          get('nb-f-gateway'),
        dns_servers:      get('nb-f-dns'),
        domain_name:      get('nb-f-domain'),
        search_domain:    get('nb-f-search'),
        lease_time:       get('nb-f-lease') ? parseInt(get('nb-f-lease')) || undefined : undefined,
        exclusion_ranges: get('nb-f-exclusions'),
    };
    try {
        const d = await apiJson('/api/netbox/subnet-assign' + _tenantQS(), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prefix, description: desc, status: 'active', custom_fields: customFields }),
            credentials: 'same-origin',
        });
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-find-modal')?.remove();
            showToast(`Subnet assigned: ${d.prefix}`, 'success');
            loadNetboxData('Prefixes');
        } else {
            showToast('Error: ' + (d.message || 'Assign failed'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function releaseSubnetToPool(prefixId, prefixStr) {
    let ipCount = 0;
    try {
        const r = await fetch(`/api/netbox/ips?prefix=${encodeURIComponent(prefixStr)}`, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        ipCount = (d.ip_addresses || []).length;
    } catch { /* unknown — proceed without a count */ }
    const msg = ipCount > 0
        ? `Return ${prefixStr} to the pool? This removes the subnet and its ${ipCount} IP address(es) from NetBox.`
        : `Return ${prefixStr} to the pool? This removes the subnet from NetBox.`;
    if (!await showConfirmToast(msg)) return;
    try {
        const d = await apiJson(`/api/netbox/prefixes/${prefixId}`, { method: 'DELETE' });
        if (d.status === 'SUCCESS') { showToast('Returned to pool', 'success'); loadNetboxData('Prefixes'); }
        else showToast('Error: ' + (d.message || 'Release failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

function editNetboxIP(id) {
    const item = (window._nbIPs || []).find(ip => ip.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxAllocateIPModal('', item);
}

function showNetboxAllocateIPModal(prefixHint, editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const allocFields = editing ? '' : `
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Prefix</label><input id="nb-ip-prefix" value="${prefixHint}" class="${inputCls}" placeholder="10.0.0.0/24"></div>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">IP Address (optional)</label><input id="nb-ip-address" class="${inputCls}" placeholder="10.0.0.5 — exact address; blank = auto"></div>`;
    const statusOpts = ['active', 'reserved', 'deprecated', 'dhcp'].map(s =>
        `<option value="${s}"${editing && editItem.status === s ? ' selected' : ''}>${s}</option>`).join('');
    const modal = openModal('nb-ip-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Allocate'} IP Address${editing ? ` — <span class="font-mono text-sm">${val(editItem.address)}</span>` : ''}</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            ${allocFields}
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">DNS Name (optional)</label><input id="nb-ip-dns" value="${val(editItem?.dns_name)}" class="${inputCls}" placeholder="host.example.com"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Description (optional)</label><input id="nb-ip-desc" value="${val(editItem?.description)}" class="${inputCls}" placeholder="e.g. Gateway VM"></div>
            ${editing ? `<div class="space-y-1 col-span-1 md:col-span-2"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="nb-ip-status" class="${inputCls}">${statusOpts}</select></div>` : ''}
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="submitNetboxAllocateIP()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="${editing ? 'Save changes to IP address' : 'Allocate next available IP address in subnet'}">${editing ? 'Save Changes' : 'Allocate'}</button>
            <button onclick="document.getElementById('nb-ip-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Close dialog without saving">Cancel</button>
        </div>`, { card: 'w-full max-w-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto' });
    if (editing) modal.dataset.ipId = editItem.id;
}

async function submitNetboxAllocateIP() {
    const modal = document.getElementById('nb-ip-modal');
    const editing = modal && modal.dataset.ipId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    if (editing) {
        const payload = {
            dns_name: get('nb-ip-dns'),
            description: get('nb-ip-desc'),
            status: get('nb-ip-status') || 'active',
        };
        try {
            const d = await apiJson(`/api/netbox/ips/${modal.dataset.ipId}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
            if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('IP Addresses'); }
            else showToast('Error: ' + (d.message || 'Update failed'), 'error');
        } catch (e) { showToast('Error: ' + e.message, 'error'); }
        return;
    }
    const payload = { prefix: get('nb-ip-prefix'), address: get('nb-ip-address') || undefined, dns_name: get('nb-ip-dns'), description: get('nb-ip-desc'), status: 'active' };
    try {
        const d = await apiJson('/api/netbox/ips', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-ip-modal')?.remove();
            showToast(`Allocated: ${d.address}`, 'success');
            loadNetboxData('IP Addresses');
        } else {
            showToast('Error: ' + (d.message || 'Allocation failed'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function releaseNetboxIP(ipId) {
    if (!await showConfirmToast('Release this IP address? This will delete it from NetBox.')) return;
    try {
        const d = await apiJson(`/api/netbox/ips/${ipId}`, { method: 'DELETE' });
        if (d.status === 'SUCCESS') loadNetboxData('IP Addresses');
        else showToast('Error: ' + (d.message || 'Release failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}
