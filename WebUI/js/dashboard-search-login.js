// dashboard-search-login.js — Tenant aggregate dashboard, global search, login, What's New.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── Tenant Aggregate Dashboard (Phase 5) ────────────────────────────────────

async function loadAllTenantsOverview(forceRefresh = false) {
    const container = document.getElementById('all-tenants-overview');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic">Loading tenants…</p>';
    try {
        const url = '/api/dashboard/all-tenants' + (forceRefresh ? '?refresh=1' : '');
        const r = await fetch(url);
        // Read the body as text first so a non-JSON response (e.g. the SPA
        // catch-all serving index.html when the hub hasn't loaded the new
        // route yet) surfaces a clear message instead of Safari's cryptic
        // "The string did not match the expected pattern." from r.json().
        const text = await r.text();
        let d;
        try { d = JSON.parse(text); }
        catch (_) {
            throw new Error(`HTTP ${r.status} — non-JSON response${text ? ' (' + text.slice(0, 120).replace(/\s+/g, ' ') + ')' : ''}. Hub may need a restart to load the all-tenants route.`);
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}: ${d.detail || text.slice(0, 120)}`);
        const tenants = (d.tenants || []).slice().sort((a, b) => a.name.localeCompare(b.name));
        if (!tenants.length) {
            container.innerHTML = '<p class="text-sm text-slate-400 italic">No tenants configured.</p>';
            return;
        }
        const esc = escapeHtml;  // shared escaper (escapes &<>"')
        const num = v => (v == null || v === '' ? '—' : v);
        const cell = 'px-4 py-2 text-sm text-slate-700';
        // Spokes column: "N up · M down" (red when any down), plus a count of
        // decommissioned. Built from the per-tenant roster the backend now ships
        // (O(spokes), no fan-out) so OFFLINE spokes the connected-spoke count
        // queries hide still surface here — the user's "I can't see them" gap.
        const spokeCell = sp => {
            if (!sp) return num(null);
            const up = sp.up || 0, down = sp.down || 0, decomm = sp.decommissioned || 0;
            const downPart = down > 0
                ? `<span class="text-red-600 font-semibold">${down} down</span>`
                : `<span class="text-slate-400">0 down</span>`;
            return `<span class="whitespace-nowrap"><span class="text-slate-700">${up} up</span> · ${downPart}${decomm ? ` <span class="text-slate-400">· ${decomm} decomm</span>` : ''}</span>`;
        };
        // Expandable list of down spokes under a tenant row — each entry links
        // to Setup → Spokes & Agents filtered to that tenant so the operator can
        // decommission/force-delete the stale box.
        const ago = epoch => {
            if (epoch == null) return 'never seen';
            const s = Math.max(0, Math.floor(Date.now() / 1000 - epoch));
            if (s < 60) return `${s}s ago`;
            if (s < 3600) return `${Math.floor(s / 60)}m ago`;
            if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
            return `${Math.floor(s / 86400)}d ago`;
        };
        const downList = (sp, tid) => {
            const ds = (sp && sp.down_spokes) || [];
            if (!ds.length) return '';
            const items = ds.map(d => `<div class="flex items-center gap-2 py-0.5">
                <span class="inline-block w-2 h-2 rounded-full bg-red-500"></span>
                <span class="font-mono text-xs text-slate-600 truncate">${esc(d.name || d.spoke_id)}</span>
                ${d.module_type ? `<span class="text-[10px] text-slate-400">${esc(d.module_type)}</span>` : ''}
                <span class="text-[10px] text-red-500">offline · ${esc(ago(d.last_seen_epoch))}</span>
                <button class="text-[11px] text-blue-500 hover:text-blue-700 font-medium ml-1" data-jump-tid="${esc(tid)}">manage →</button>
            </div>`).join('');
            return `<div class="pl-4 py-1 border-l-2 border-red-200 ml-4 mb-1">${items}</div>`;
        };
        const shared = d.shared_spokes || null;
        const rows = tenants.map(t => {
            const active = t.id === currentTenant;
            const sp = t.spokes || null;
            const hasDown = sp && (sp.down || 0) > 0;
            return `<tr class="border-b border-slate-100 hover:bg-slate-50 cursor-pointer at-row ${active ? 'bg-green-50/60' : ''}" data-tid="${esc(t.id)}">
                <td class="px-4 py-2 text-sm">
                    <span class="font-medium text-[#263040] ${active ? 'text-[#01A982]' : ''}">${esc(t.name)}</span>
                    ${t.description ? `<span class="block text-xs text-slate-400">${esc(t.description)}</span>` : ''}
                </td>
                <td class="${cell}">${num(t.devices)}</td>
                <td class="${cell}">${num(t.vms)}</td>
                <td class="${cell}">${num(t.sessions)}</td>
                <td class="${cell}">${num(t.prefixes)}</td>
                <td class="${cell}">${num(t.ips_used)}</td>
                <td class="${cell}">${spokeCell(sp)}</td>
                <td class="px-4 py-2 text-xs text-slate-400 text-right">${active ? '<span class="text-[#01A982] font-medium">viewing</span>' : 'View →'}</td>
            </tr>${hasDown ? `<tr class="bg-red-50/30"><td colspan="8">${downList(sp, t.id)}</td></tr>` : ''}`;
        }).join('');
        // Shared/unassigned spokes (untagged) get their own trailing block so an
        // offline shared spoke is never lost from the overview.
        const sharedBlock = shared && ((shared.down || 0) + (shared.decommissioned || 0) + (shared.up || 0)) > 0
            ? `<tr class="border-b border-slate-100 bg-slate-50/60 at-row" data-tid="__all__">
                <td class="px-4 py-2 text-sm"><span class="font-medium text-slate-500">Shared / unassigned</span><span class="block text-xs text-slate-400">spokes bound to no tenant</span></td>
                <td class="${cell}" colspan="5"></td>
                <td class="${cell}">${spokeCell(shared)}</td>
                <td class="px-4 py-2 text-xs text-slate-400 text-right">View →</td>
            </tr>${(shared.down || 0) > 0 ? `<tr class="bg-red-50/30"><td colspan="8">${downList(shared, '__all__')}</td></tr>` : ''}`
            : '';
        container.innerHTML = `<table class="w-full text-left">
            <thead class="text-slate-400 uppercase text-xs border-b border-slate-200"><tr>
                <th class="px-4 py-2">Tenant</th>
                <th class="px-4 py-2">Devices</th>
                <th class="px-4 py-2">VMs</th>
                <th class="px-4 py-2">NAC Sessions</th>
                <th class="px-4 py-2">Prefixes</th>
                <th class="px-4 py-2">IPs Used</th>
                <th class="px-4 py-2">Spokes</th>
                <th class="px-4 py-2"></th>
            </tr></thead>
            <tbody>${rows}${sharedBlock}</tbody>
        </table>
        <p class="mt-2 text-xs text-slate-400">Click a row to view as that tenant. Spokes shows up/down from the spoke roster (offline spokes included). “manage →” jumps to Spokes &amp; Agents for that tenant. Counts cached 60s — use Refresh for live numbers.</p>`;
        container.querySelectorAll('.at-row').forEach(tr => {
            tr.addEventListener('click', () => {
                const tid = tr.dataset.tid;
                if (tid === '__all__') { setView('setup'); setSubView('Spokes & Agents'); return; }
                viewAsTenant(tid);
            });
        });
        // The per-down-spoke "manage →" buttons jump straight to Spokes & Agents
        // filtered to the owning tenant (or All tenants for the shared block).
        container.querySelectorAll('[data-jump-tid]').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const tid = btn.dataset.jumpTid;
                if (typeof setView === 'function') setView('setup');
                if (typeof setSubView === 'function') setSubView('Spokes & Agents');
                const sel = document.getElementById('sa-tenant-filter');
                if (sel) {
                    const has = v => [...sel.options].some(o => o.value === v);
                    sel.value = has(tid) ? tid : '__all__';
                    if (typeof _onSaTenantFilterChange === 'function') _onSaTenantFilterChange();
                    else if (typeof loadSpokesAndAgents === 'function') loadSpokesAndAgents();
                }
            });
        });
    } catch (err) {
        container.innerHTML = `<p class="text-sm text-red-500">Overview unavailable: ${err.message}</p>`;
        console.warn('All-tenants overview failed:', err.message);
    }
}

async function loadDashboardSummary() {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

    const nameEl = document.getElementById('dash-tenant-name');
    if (nameEl) nameEl.textContent = currentTenant;

    // Mark loading
    ['dash-devices','dash-vms','dash-sessions','dash-prefixes','dash-ips'].forEach(id => set(id, '…'));

    try {
        const d = await apiJson(`/api/dashboard/summary?tenant=${encodeURIComponent(currentTenant)}`);

        set('dash-devices',  d.devices  ?? '—');
        set('dash-vms',      d.vms      ?? '—');
        set('dash-sessions', d.sessions ?? '—');
        set('dash-prefixes', d.prefixes ?? '—');
        set('dash-ips',      d.ips_used ?? '—');
    } catch (err) {
        ['dash-devices','dash-vms','dash-sessions','dash-prefixes','dash-ips'].forEach(id => set(id, '—'));
        console.warn('Dashboard summary unavailable:', err.message);
    }
}

// Hub/spoke/agent up-down summary tile on the Dashboard Overview. Tenant-scoped:
// a Global Admin sees ALL; a tenant user sees its own spokes + shared infra.
async function loadInfraStatus() {
    const el = document.getElementById('infra-status-body');
    if (!el) return;
    const tenantParam = isAdmin() ? 'all' : encodeURIComponent(currentTenant || 'default');
    let d = {};
    try {
        const r = await fetch(`/api/dashboard/infra-status?tenant=${tenantParam}`);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        d = await r.json();
    } catch (e) { el.innerHTML = '<p class="text-xs text-slate-400 italic">Status unavailable</p>'; return; }
    const c = d.counts || {};
    const items = d.items || [];
    const dot = s => `<span class="inline-block w-2.5 h-2.5 rounded-full ${s === 'green' ? 'bg-green-500' : s === 'yellow' ? 'bg-amber-400' : 'bg-red-500'}"></span>`;
    const pill = (label, n, cls) => `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full ${cls} text-xs font-bold">${label} ${n}</span>`;
    const rows = items.map(i => `<div class="flex items-center justify-between gap-3 py-1 border-b border-slate-100 last:border-0">
        <span class="flex items-center gap-2 min-w-0">${dot(i.status)}<span class="font-mono text-xs text-slate-600 truncate">${escapeHtml(i.name)}</span>${i.type ? `<span class="text-[10px] text-slate-400">${escapeHtml(i.type)}</span>` : ''}</span>
        <span class="text-[10px] ${i.online ? (i.tier === 'warning' ? 'text-amber-600' : 'text-slate-400') : 'text-red-500'}">${i.online ? (i.tier === 'warning' ? 'warning' : 'online') : 'offline'}</span></div>`).join('');
    el.innerHTML = `
      <div class="flex flex-wrap items-center gap-2 mb-3">
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-100 text-green-700 text-xs font-bold">${dot('green')} Hub online</span>
        ${pill('Healthy', c.green || 0, 'bg-green-100 text-green-700')}
        ${pill('Warning', c.yellow || 0, 'bg-amber-100 text-amber-700')}
        ${pill('Down', c.red || 0, 'bg-red-100 text-red-700')}
        <span class="text-[11px] text-slate-400 ml-auto">${items.length} spoke/agent(s)${d.all_tenants ? ' · all tenants' : ''}</span>
      </div>
      <div class="max-h-56 overflow-y-auto">${items.length ? rows : '<p class="text-xs text-slate-400 italic">No spokes/agents in scope.</p>'}</div>`;
}

// ─── Global Cross-System Search ──────────────────────────────────────────────

let _searchTimer = null;

function handleSearch(value) {
    clearTimeout(_searchTimer);
    const dropdown = document.getElementById('search-results');
    if (!value || value.trim().length < 2) {
        dropdown.classList.add('hidden');
        dropdown.innerHTML = '';
        return;
    }
    dropdown.classList.remove('hidden');
    dropdown.innerHTML = '<p class="text-xs text-slate-400 italic px-2 py-1">Searching…</p>';

    _searchTimer = setTimeout(async () => {
        try {
            // Scope the search to the picked tenant when one is selected (an
            // admin browsing tenant "acme" sees acme + shared results; "default"
            // → unscoped/all). The hub enforces scoping spoke-side; this just
            // tells it which tenant to scope to.
            const tnt = (currentTenant && currentTenant !== 'default')
                ? `&tenant=${encodeURIComponent(currentTenant)}` : '';
            const r = await fetch(`/api/search?q=${encodeURIComponent(value.trim())}${tnt}`);
            const d = r.ok ? await r.json() : null;
            if (!d) { dropdown.innerHTML = '<p class="text-xs text-red-400 px-2 py-1">Search failed</p>'; return; }

            const legNames = { NETBOX_SEARCH: 'NetBox', SEARCH_VMS: 'VMs', SEARCH_SESSIONS: 'NAC sessions', SEARCH_USERS: 'Directory', SEARCH_DHCP: 'DHCP' };
            const degradedNote = (Array.isArray(d.degraded) && d.degraded.length)
                ? `<p class="text-[10px] text-amber-600 px-2 pt-1 border-t border-slate-100">Some sources did not answer: ${d.degraded.map(c => legNames[c] || c).join(', ')}</p>` : '';
            if (d.total === 0) {
                dropdown.innerHTML = '<p class="text-xs text-slate-400 italic px-2 py-1">No results</p>' + degradedNote;
                return;
            }

            const sourceIcon = {
                netbox:    '📦',
                pxmx:      '🖥️',
                kvm:       '🖥️',
                cppm:      '🔐',
                ldap:      '👤',
                opnsense:  '🔥',
                console:   '🔌',
                credvault: '🔑',
            };
            const typeLabel = {
                device:      'Device',
                ip:          'IP Address',
                prefix:      'Prefix',
                vm:          'VM',
                lxc:         'Container',
                session:     'NAC Session',
                endpoint:    'Endpoint',
                user:        'User',
                group:       'Group',
                computer:    'Computer',
                dhcp_lease:  'DHCP Lease',
                dhcp_static: 'DHCP Reservation',
                rack:        'Rack',
                vlan:        'VLAN',
                site:        'Site',
                console:     'Console',
            };

            const rows = d.results.slice(0, 12).map(item => {
                const icon  = sourceIcon[item.source] || '•';
                const label = item.source === 'credvault' ? 'Credential' : (typeLabel[item.type] || item.type);
                const subParts = [item.ip, item.mac, item.cluster, item.dn];
                if (item.source === 'console') {
                    // Console rows carry connect coordinates, not IP/MAC — show
                    // the serial device + baud so the operator knows the line.
                    subParts.length = 0;
                    if (item.device) subParts.push(item.device);
                    if (item.baud)   subParts.push(item.baud + 'bps');
                    if (item.model || item.vendor) subParts.push(item.model || item.vendor);
                }
                if (item.source === 'credvault') {
                    // Credential Vault hits are METADATA only (name/type/bucket)
                    // — never a secret value. Show the bucket + secret type.
                    subParts.length = 0;
                    if (item.bucket_label || item.bucket) subParts.push(item.bucket_label || item.bucket);
                    if (item.type) subParts.push(item.type);
                }
                if (item.vid != null) subParts.push(`VLAN ${item.vid}`);
                if (item.site) subParts.push(item.site);
                if (item.rack) subParts.push(item.rack);
                const sub = subParts.filter(Boolean).join(' · ');
                return `<div class="flex items-start gap-2 px-2 py-1.5 rounded-lg hover:bg-slate-50 cursor-pointer"
                             onclick="openSearchResult(${JSON.stringify(item).replace(/"/g, '&quot;')})">
                    <span class="text-base leading-none mt-0.5">${icon}</span>
                    <div class="min-w-0">
                        <div class="text-xs font-medium text-slate-800 truncate">${item.name || item.ip || '—'}</div>
                        <div class="text-[10px] text-slate-400 truncate">${label} · ${item.source}${sub ? ' · ' + sub : ''}</div>
                    </div>
                </div>`;
            }).join('');

            const more = d.total > 12 ? `<p class="text-[10px] text-slate-400 px-2 pt-1 border-t border-slate-100">${d.total - 12} more — narrow your search</p>` : '';
            dropdown.innerHTML = rows + more + degradedNote;
        } catch (err) {
            dropdown.innerHTML = `<p class="text-xs text-red-400 px-2 py-1">Error: ${err.message}</p>`;
        }
    }, 300);
}

function openSearchResult(item) {
    const inp = document.getElementById('global-search');
    const dd  = document.getElementById('search-results');
    if (inp) inp.value = '';
    if (dd)  { dd.classList.add('hidden'); dd.innerHTML = ''; }
    // /api/device-detail is admin-only, so non-admins cannot use the device dashboard.
    // A console hit already carries its connect coordinates: open the terminal directly
    // for them; admins keep the richer inventory dashboard.
    if (item.source === 'console' && item.spoke_id && item.port_id && !isAdmin()) {
        if (typeof openConsoleTerminal === 'function') {
            openConsoleTerminal(item.spoke_id, item.port_id);
            return;
        }
    }
    // A credential-vault hit → open the Credential Vault at that bucket (the
    // secret VALUE is never in the search payload; reveal still needs the
    // bucket pass-phrase there).
    if (item.source === 'credvault') {
        if (item.bucket) _cvCurrentBucket = item.bucket;
        if (typeof setView === 'function') setView('credvault');
        return;
    }
    showDeviceDashboard(item);
}

// Open the Proxmox VNC console for a VM discovered via the device dashboard.
// The dashboard's proxmox leg (SEARCH_VMS) may surface a VM that isn't in the
// PXMX page's window._pxmxVms cache that pxmxOpenConsole() looks up, so seed it
// first, close the dashboard, then delegate to the existing console flow.
function ddOpenVnc(vm) {
    if (!vm || !vm.unique_id) { showToast('VM console identifiers unavailable', 'error'); return; }
    window._pxmxVms = window._pxmxVms || [];
    if (!window._pxmxVms.find(v => v.unique_id === vm.unique_id)) {
        window._pxmxVms.push(vm);
    }
    document.getElementById('device-dashboard-modal')?.remove();
    if (typeof pxmxOpenConsole === 'function') {
        pxmxOpenConsole(vm.unique_id);
    } else {
        showToast('Console unavailable in this view', 'error');
    }
}

async function showDeviceDashboard(item) {
    document.getElementById('device-dashboard-modal')?.remove();

    const modal = document.createElement('div');
    modal.id = 'device-dashboard-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-start justify-center z-50 pt-12 overflow-y-auto';

    const panel = document.createElement('div');
    panel.className = 'bg-white rounded-xl shadow-2xl w-full max-w-3xl mx-4 mb-12';
    panel.innerHTML = `
        <div class="flex items-center justify-between px-6 py-4 border-b border-slate-100">
            <div>
                <p class="text-xs text-slate-400 uppercase font-bold tracking-widest mb-0.5">Device Dashboard</p>
                <p class="text-base font-bold text-[#263040] font-mono" id="dd-identity">Searching…</p>
            </div>
            <button class="dd-close text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div id="dd-body" class="p-6 grid grid-cols-1 gap-4">
            <p class="text-sm text-slate-400 italic col-span-full">Loading data from all modules…</p>
        </div>`;
    modal.appendChild(panel);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    panel.querySelector('.dd-close').addEventListener('click', () => modal.remove());
    document.body.appendChild(modal);

    const params = new URLSearchParams();
    if (item.mac)     params.set('mac', item.mac);
    if (item.ip)      params.set('ip', item.ip);
    if (item.serial)  params.set('serial', item.serial);
    if (item.port_id) params.set('port_id', item.port_id);
    if (item.device)  params.set('device', item.device);
    const nameAsHostname = !item.mac && !item.ip && item.name;
    if (nameAsHostname) params.set('hostname', item.name);

    try {
        const d = await apiJson(`/api/device-detail?${params}`);

        const id = d.identity || {};
        const identParts = [id.hostname, id.serial ? `SN: ${id.serial}` : null, id.ip, id.mac].filter(Boolean);
        document.getElementById('dd-identity').textContent = identParts.join('  ·  ') || item.name || '—';

        const badge = (label, cls) => `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${cls}">${label}</span>`;
        const row = (label, val) => val ? `<div class="flex justify-between text-xs py-1 border-b border-slate-50"><span class="text-slate-400">${label}</span><span class="font-medium text-slate-700 font-mono">${val}</span></div>` : '';

        const card = (title, color, content) => `
            <div class="rounded-lg border border-slate-100 overflow-hidden">
                <div class="px-4 py-2 ${color} flex items-center gap-2">
                    <span class="text-xs font-bold uppercase tracking-wide">${title}</span>
                </div>
                <div class="px-4 py-3">${content}</div>
            </div>`;

        const empty = '<p class="text-xs text-slate-400 italic">No data from this module.</p>';
        const cards = [];

        // NAC / ClearPass
        const nac = d.nac;
        if (nac) {
            const statusCls = nac.status_val === 'Known' ? 'bg-green-100 text-green-700' : nac.status_val === 'Unknown' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-500';
            const sessCount = (nac.sessions || []).length;
            cards.push(card('ClearPass NAC', 'bg-[#263040]/10 text-[#263040]', `
                ${nac.status_val ? badge(nac.status_val, statusCls) : ''}
                <div class="mt-2">
                    ${row('Vendor', nac.device_vendor)}
                    ${row('OS', nac.device_os)}
                    ${row('Type', nac.device_type)}
                    ${row('Description', nac.description)}
                    ${row('RADIUS Sessions', sessCount > 0 ? `${sessCount} found` : 'None')}
                </div>`));
        } else {
            cards.push(card('ClearPass NAC', 'bg-slate-50 text-slate-400', empty));
        }

        // DHCP
        const dhcp = d.dhcp;
        cards.push(card('DHCP', dhcp ? 'bg-blue-50 text-blue-700' : 'bg-slate-50 text-slate-400', dhcp ? `
            ${row('IP Address', dhcp.ip)}
            ${row('Hostname', dhcp.hostname !== 'unknown' ? dhcp.hostname : null)}
            ${row('MAC', dhcp.mac)}
            ${row('Lease Expires', dhcp.lease_end)}` : empty));

        // NetBox
        const nb = d.netbox || [];
        cards.push(card('NetBox Inventory', nb.length ? 'bg-green-50 text-green-700' : 'bg-slate-50 text-slate-400',
            nb.length ? nb.slice(0, 5).map(n => {
                const meta = [
                    n.device_type ? `Type: ${n.device_type}` : (n.type && n.type !== 'device' ? n.type : ''),
                    n.serial ? `Serial: ${n.serial}` : '',
                    n.role ? `Role: ${n.role}` : '',
                    n.site ? `Site: ${n.site}` : '',
                    n.rack ? `Rack: ${n.rack}` : '',
                    n.ip ? `IP: ${n.ip}` : '',
                ].filter(Boolean).join(' · ');
                return `
                <div class="py-1.5 border-b border-slate-50 last:border-0">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-semibold text-slate-700">${escapeHtml(n.name || n.ip || '—')}</span>
                        ${n.status ? `<span class="px-1.5 py-0.5 rounded text-[9px] uppercase font-bold ${n.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}">${escapeHtml(n.status)}</span>` : ''}
                    </div>
                    ${meta ? `<div class="text-[10px] text-slate-500 font-mono mt-0.5">${escapeHtml(meta)}</div>` : ''}
                </div>`;
            }).join('') : empty));

        // Proxmox
        const px = d.proxmox || [];
        cards.push(card('Proxmox', px.length ? 'bg-orange-50 text-orange-700' : 'bg-slate-50 text-slate-400',
            px.length ? px.slice(0, 3).map(v => {
                const meta = `${v.type || 'VM'} ${v.ip ? '· ' + v.ip : ''} ${v.cluster ? '· ' + v.cluster : ''}`;
                // VNC console: only when the VM carries the identifiers the
                // console relay needs (unique_id/vmid/node). Off-repo agents
                // that don't yet surface them simply render no button.
                const canVnc = v.unique_id && v.vmid != null && v.node;
                const vmArg = JSON.stringify({
                    unique_id: v.unique_id, vmid: v.vmid, node: v.node,
                    type: v.type || 'qemu', agent_id: v.agent_id || '', name: v.name || ''
                }).replace(/"/g, '&quot;');
                const btn = canVnc
                    ? `<button onclick="ddOpenVnc(${vmArg})" class="text-[11px] px-2 py-1 rounded bg-orange-100 hover:bg-orange-200 text-orange-700 border border-orange-300 font-bold shrink-0">🖥 VNC Console</button>`
                    : '';
                return `<div class="flex items-center justify-between gap-2 py-1 border-b border-slate-50 last:border-0">
                    <div class="min-w-0">
                        <span class="text-xs font-medium text-slate-700">${v.name || '—'}</span>
                        <span class="text-slate-400 ml-2 text-[10px]">${meta}</span>
                    </div>${btn}
                </div>`;
            }).join('') : empty));

        // Network (NW): which switch/gateway sees this ip/mac, and where (port /
        // VLAN) — stitched from the NW module's ARP/MAC/endpoint/interface data.
        const nwHits = d.nw || [];
        cards.push(card('Network (NW)', nwHits.length ? 'bg-indigo-50 text-indigo-700' : 'bg-slate-50 text-slate-400',
            nwHits.length ? nwHits.map(h => {
                const loc = [];
                (h.arp || []).forEach(a => loc.push(`ARP ${a.ip || ''} → ${a.mac || ''} @ ${a.interface || '?'}${a.vlan ? ' · vlan ' + a.vlan : ''}`));
                (h.mac || []).forEach(m => loc.push(`MAC ${m.mac || ''} @ ${m.interface || '?'}${m.vlan ? ' · vlan ' + m.vlan : ''}`));
                (h.endpoints || []).forEach(e => loc.push(`Endpoint ${e.ip || ''} / ${e.mac || ''} @ ${e.interface || '?'}`));
                (h.interfaces || []).forEach(i => loc.push(`Iface ${i.name || ''}${i.ip ? ' · ' + i.ip : ''}${i.status ? ' · ' + i.status : ''}`));
                const selfBadge = h.is_self ? badge('THIS DEVICE', 'bg-indigo-100 text-indigo-700') : '';
                const lines = loc.length
                    ? loc.slice(0, 6).map(l => `<div class="text-[10px] text-slate-500 font-mono truncate">${escapeHtml(l)}</div>`).join('')
                    : (h.is_self ? '' : empty);
                return `<div class="py-1.5 border-b border-slate-50 last:border-0">
                    <div class="text-xs font-medium text-slate-700 truncate">${escapeHtml(h.name || h.address || '—')} ${selfBadge}<span class="text-slate-400 ml-1 text-[10px]">${escapeHtml(h.object_type || '')}${h.address ? ' · ' + escapeHtml(h.address) : ''}</span></div>
                    ${lines}
                </div>`;
            }).join('') : empty));

        // LDAP
        const ld = d.ldap || [];
        cards.push(card('Directory (LDAP)', ld.length ? 'bg-yellow-50 text-yellow-700' : 'bg-slate-50 text-slate-400',
            ld.length ? ld.slice(0, 3).map(u => `
                <div class="text-xs py-1 border-b border-slate-50 last:border-0">
                    <span class="font-medium text-slate-700">${u.name || u.dn || '—'}</span>
                    <span class="text-slate-400 ml-2">${u.type || ''}</span>
                </div>`).join('') : empty));

        // Console: serial-console port(s) mapped to this device, each with a
        // direct connect button (opens the serial terminal for the line).
        let con = d.console || [];
        if (con.length === 0 && item.source === 'console') {
            con = [item];
        }
        cards.push(card('Console', con.length ? 'bg-[#01A982]/10 text-[#01A982]' : 'bg-slate-50 text-slate-400',
            con.length ? con.map(c => {
                const meta = [c.device, c.baud ? c.baud + 'bps' : '', c.model || c.vendor || '', c.agent_name || '']
                    .filter(Boolean).join(' · ');
                const busy = c.in_use ? `<span class="ml-2 px-1.5 py-0.5 rounded text-[9px] bg-amber-100 text-amber-700 font-bold">IN USE</span>` : '';
                const canConnect = c.spoke_id && c.port_id;
                const btn = canConnect
                    ? `<button onclick="openConsoleTerminal('${escJsAttr(c.spoke_id)}','${escJsAttr(c.port_id)}','${escJsAttr(c.name || '')}')" class="text-[11px] px-2 py-1 rounded bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] font-bold shrink-0">🖥 Connect</button>`
                    : '';
                return `<div class="flex items-center justify-between gap-2 py-1.5 border-b border-slate-50 last:border-0">
                    <div class="min-w-0">
                        <div class="text-xs font-medium text-slate-700 truncate">${escapeHtml(c.name || c.device || '—')}${busy}</div>
                        <div class="text-[10px] text-slate-400 truncate font-mono">${escapeHtml(meta)}</div>
                    </div>${btn}
                </div>`;
            }).join('') : empty));

        document.getElementById('dd-body').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-2 gap-4">${cards.join('')}</div>`;
    } catch (e) {
        const body = document.getElementById('dd-body');
        if (body) body.innerHTML = `<p class="text-sm text-red-400 italic">Error loading device data: ${e.message}</p>`;
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', e => {
    const inp = document.getElementById('global-search');
    const dd  = document.getElementById('search-results');
    if (dd && inp && !inp.contains(e.target) && !dd.contains(e.target)) {
        dd.classList.add('hidden');
    }
    // Same treatment for the "What's New" popover.
    const wnWrap  = document.getElementById('whats-new-wrap');
    const wnPanel = document.getElementById('whats-new-panel');
    if (wnPanel && wnWrap && !wnWrap.contains(e.target) && !wnPanel.classList.contains('hidden')) {
        closeWhatsNew();
    }
});

// ── "What's New" popover ────────────────────────────────────────────────────
// A header info-icon that lists recently committed features (bug-store reports
// with type=feature + status=fixed, served by GET /api/whats-new — readable by
// any signed-in user). Mirrors the header search-results dropdown: click
// toggles, click-outside/Esc dismisses, data fetched on open.
function toggleWhatsNew(evt) {
    if (evt) evt.stopPropagation();
    const panel = document.getElementById('whats-new-panel');
    if (!panel) return;
    if (panel.classList.contains('hidden')) openWhatsNew();
    else closeWhatsNew();
}

function openWhatsNew() {
    const panel = document.getElementById('whats-new-panel');
    const btn   = document.getElementById('whats-new-btn');
    if (!panel) return;
    panel.classList.remove('hidden');
    if (btn) btn.setAttribute('aria-expanded', 'true');
    loadWhatsNew();
}

function closeWhatsNew() {
    const panel = document.getElementById('whats-new-panel');
    const btn   = document.getElementById('whats-new-btn');
    if (panel) panel.classList.add('hidden');
    if (btn) btn.setAttribute('aria-expanded', 'false');
}

// Esc dismisses the "What's New" popover (only acts when it's open).
document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    const panel = document.getElementById('whats-new-panel');
    if (panel && !panel.classList.contains('hidden')) closeWhatsNew();
});

async function loadWhatsNew() {
    const body = document.getElementById('whats-new-body');
    if (!body) return;
    body.innerHTML = '<p class="text-xs text-slate-400 italic px-2 py-1">Loading…</p>';
    try {
        const r = await fetch('/api/whats-new');
        const d = r.ok ? await r.json() : null;
        if (!d) { body.innerHTML = '<p class="text-xs text-red-400 px-2 py-1">Could not load updates.</p>'; return; }
        const feats = Array.isArray(d.features) ? d.features : [];
        if (feats.length === 0) {
            body.innerHTML = '<p class="text-xs text-slate-400 italic px-2 py-1">No bug fixes or features merged in the last 2 weeks.</p>';
            return;
        }
        body.innerHTML = feats.map(f => {
            const when    = f.fixed_at ? fmtDate(f.fixed_at) : '';
            const summary = escapeHtml(String(f.summary || ''));
            const isBug   = f.type === 'bug';
            const badge   = `<span class="inline-block shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide ${isBug ? 'bg-red-50 text-red-600' : 'bg-emerald-50 text-emerald-600'}">${isBug ? 'Bug fix' : 'Feature'}</span>`;
            const inner   = `<div class="flex items-start gap-1.5">${badge}<div class="text-xs font-medium text-slate-800">${summary}</div></div>`
                + (when ? `<div class="text-[10px] text-slate-400 mt-0.5">${escapeHtml(when)}</div>` : '');
            if (f.issue_url) {
                return `<a href="${escapeHtml(String(f.issue_url))}" target="_blank" rel="noopener noreferrer"
                            class="block px-2 py-1.5 rounded-lg hover:bg-slate-50 cursor-pointer no-underline">${inner}</a>`;
            }
            return `<div class="px-2 py-1.5 rounded-lg">${inner}</div>`;
        }).join('');
    } catch (err) {
        body.innerHTML = `<p class="text-xs text-red-400 px-2 py-1">Error: ${escapeHtml(err.message || String(err))}</p>`;
    }
}
