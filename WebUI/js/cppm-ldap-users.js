// cppm-ldap-users.js — CPPM / NAC, OPNsense edit, LDAP, user modals.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── CPPM / NAC ──────────────────────────────────────────────────────────────

// Shared 403 hint rendered under a ClearPass API error card. CPPM requires an
// OAuth2 API Client; a 403 almost always means one isn't configured or the
// credentials in Setup → NAC don't match. Used by loadCPPMData() in
// both the sessions branch (NAC Status / Access Tracker) and the devices
// branch (My Devices / Unknown Devices).
// Routes: GET /api/cppm/sessions, /api/cppm/devices, /api/cppm/unknown-devices
// — see core/src/api.py get_cppm_sessions / get_cppm_devices.
function _cppm403Hint(status) {
    return status === 403
        ? '<p class="mt-3 text-xs text-amber-600">ClearPass returned 403 — check that an OAuth2 API Client is configured in CPPM and that the credentials in Setup → NAC match.</p>'
        : '';
}

// Shared error panel for the CPPM (NAC) data views. A 503 here means the module
// has NO spoke connected (not an actual ClearPass API fault), so render the
// SAME neutral, generic "No spoke connected" message every module uses — not a
// red "ClearPass API Error" that misattributes a missing spoke to ClearPass.
// Any other status keeps the API-error framing (+ the 403 credential hint).
function _cppmErrorPanel(r, e) {
    if (r.status === 503) {
        return `<div class="p-6 text-center">
            <p class="text-slate-500 font-medium text-sm">No spoke connected</p>
        </div>`;
    }
    return `<div class="p-6 text-center">
        <p class="text-red-500 font-medium text-sm mb-1">ClearPass API Error (${r.status})</p>
        <p class="text-xs text-slate-500 font-mono">${e.detail || r.statusText}</p>
        ${_cppm403Hint(r.status)}
    </div>`;
}

async function loadCPPMNACStatus() {
    try {
        const r = await fetch('/api/cppm/nac-status');
        if (r.ok) {
            const d = await r.json();
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v ?? '—'; };
            set('nac-sessions', d.active_sessions);
            set('nac-total', d.total_devices);
            set('nac-known', d.known_devices);
            set('nac-unknown', d.unknown_devices);
        }
    } catch (err) { console.error('loadCPPMNACStatus: nac-status fetch failed', err); }
    loadCPPMData('NAC Status');
}

// _renderCppmSessions() — the Access Tracker / NAC Status branch of
// loadCPPMData. Extracted from the loader; the fetch lives here, the loading
// placeholder + th/tableWrap helpers stay in the caller. Output HTML preserved.
async function _renderCppmSessions(container, subMenu, th, tableWrap) {
    const limit = window._cppmSessionLimit || 200;
    const tparam = currentTenant && currentTenant !== 'default' ? `&tenant=${encodeURIComponent(currentTenant)}` : '';
    const r = await fetch(`/api/cppm/sessions?limit=${limit}${tparam}`);
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        container.innerHTML = _cppmErrorPanel(r, e);
        return;
    }
    const d = await r.json();
    // Server scopes by the selected tenant's subnets (incl. admins); no
    // client re-filter (its session-tenant prefixes are wrong once a
    // tenant is switched).
    const sessions = d.sessions || [];
    // Admin combined view (2+ nac spokes): sessions are tagged _tenant by the
    // merge fanout — see the matching comment in _renderCppmDevices.
    const showSessTenantCol = sessions.some(s => s && s._tenant);
    const cols = (showSessTenantCol ? ['Tenant'] : []).concat(
        ['Username', 'MAC / Station', 'IP', 'Role', 'NAS', 'Port', 'Service', 'Start Time', 'State']);
    const rows = sessions.map(s => `<tr class="border-b border-slate-100 hover:bg-slate-50">
        ${showSessTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${escapeHtml(s._tenant || '—')}</td>` : ''}
        <td class="px-4 py-2 font-medium">${s.username || '—'}</td>
        <td class="px-4 py-2 font-mono text-xs">${s.calling_station || s.mac || '—'}</td>
        <td class="px-4 py-2 font-mono text-xs">${s.ip || '—'}</td>
        <td class="px-4 py-2">${s.role || '—'}</td>
        <td class="px-4 py-2 text-xs">${s.nas_name || '—'}</td>
        <td class="px-4 py-2 text-xs font-mono" title="${s.nas_port_type || ''}">${s.nas_port || '—'}</td>
        <td class="px-4 py-2 text-xs">${s.service || '—'}</td>
        <td class="px-4 py-2 text-xs">${fmtSessionStart(s.start_time)}</td>
        <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${s.state === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}">${s.state || '—'}</span></td>
    </tr>`).join('');
    const sessRefreshBtn = !isAdmin() ? `<button onclick="refreshModuleCache('cppm_sessions').then(()=>loadCPPMData('${subMenu}'))"
        title="Refresh session cache from ClearPass"
        class="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        Refresh</button>` : '';
    const limitSel = `<select onchange="window._cppmSessionLimit=+this.value; loadCPPMData('${subMenu}')"
        title="Number of session records to display"
        class="text-xs border border-slate-200 rounded px-2 py-0.5 text-slate-500 bg-white">
        ${[50,100,200,500,1000].map(n => `<option value="${n}"${n===limit?' selected':''}>${n} records</option>`).join('')}
    </select>`;
    container.innerHTML = `<div class="flex justify-between items-center mb-1 px-1">
        <h3 class="text-base font-semibold text-[#263040]">Access Tracker <span class="text-xs text-slate-400 font-normal">(${sessions.length} of ${d.total ?? sessions.length})</span> ${helpIcon('cppm', null, 'NAC help')}</h3>
        <div class="flex items-center gap-2">${addServerButtonHtml('cppm', 'ClearPass')}${limitSel}${sessRefreshBtn}</div>
    </div>` + tableWrap(th(cols) + `<tbody>${rows || `<tr><td colspan="${cols.length}" class="px-4 py-6 text-center text-slate-400">No active sessions</td></tr>`}</tbody>`);
}

// _renderCppmDevices() — the My Devices / Unknown Devices branch of
// loadCPPMData. Extracted from the loader; fetch + row click wiring live here.
// Output HTML preserved.
async function _renderCppmDevices(container, subMenu, th, tableWrap) {
    const isUnknown = subMenu === 'Unknown Devices';
    const tparam = currentTenant && currentTenant !== 'default' ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    const r = await fetch(isUnknown ? `/api/cppm/unknown-devices${tparam}` : `/api/cppm/devices${tparam}`);
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        container.innerHTML = _cppmErrorPanel(r, e);
        return;
    }
    const d = await r.json();
    const allDevices = d.devices || d.items || (Array.isArray(d) ? d : []);
    // Server scopes by the selected tenant (incl. admins); no client
    // re-filter — its session-tenant prefixes are wrong once a tenant
    // is switched. 'Unknown Devices' are untagged endpoints (assigned to
    // no tenant), subnet-scoped to the selected tenant's network.
    const devices = allDevices;
    // Admin combined view (2+ nac spokes, one per tenant): each device is
    // tagged _tenant by the merge fanout (see cppm.py::_nac_merge_fanout).
    // Show a Tenant column then — otherwise (the normal single-tenant case,
    // server-side filtered to the caller's own tenant) it would be either
    // always-the-same-value noise for a user or an unwanted label for an
    // admin who selected one specific tenant.
    const showTenantCol = devices.some(d => d && d._tenant);
    const cols = showTenantCol
        ? ['Tenant', 'MAC Address', 'Status', 'Hostname', 'IP', 'Vendor', 'OS', 'Type', 'Attributes']
        : ['MAC Address', 'Status', 'Hostname', 'IP', 'Vendor', 'OS', 'Type', 'Attributes'];
    const statusBadge = s => {
        const cls = s === 'Known' ? 'bg-green-100 text-green-700' : s === 'Unknown' ? 'bg-amber-100 text-amber-700' : 'bg-red-100 text-red-700';
        return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${s || '—'}</span>`;
    };
    // Compact chip list of an endpoint's attributes (key: value). Pinned
    // tenant tags render first so the tenant is visible at a glance; the
    // rest follow. Capped with a scroll so profiler-heavy endpoints don't
    // blow out the row height.
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    // Tenant identity is NOT shown in the list — the list is filtered
    // server-side by the logged-in user's tenant ID (/api/cppm/devices),
    // so showing the tenant tags here would be noise for a user (only
    // ever their own tenant) and an unwanted label for admins. Other
    // endpoint attributes still render as chips.
    const HIDDEN_ATTRS = new Set(['Tenant', 'Tenant_Slug', 'NetBox_Tenant_Slug', 'NetBox_Tenant_Name', 'NetBox_Tenant_ID']);
    const attrChips = attrs => {
        const entries = Object.entries(attrs || {})
            .filter(([k, v]) => v != null && v !== '' && !HIDDEN_ATTRS.has(k))
            .sort((a, b) => a[0].localeCompare(b[0]));
        if (!entries.length) return '<span class="text-slate-300">—</span>';
        return `<div class="flex flex-wrap gap-1 max-h-16 overflow-y-auto pr-1">${entries.map(([k, v]) =>
            `<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono whitespace-nowrap" title="${esc(k)}: ${esc(v)}"><span class="text-slate-400">${esc(k)}</span>:${esc(v)}</span>`
        ).join('')}</div>`;
    };
    window._cppmDeviceMap = Object.fromEntries(devices.map(d => [d.mac, d]));
    const rows = devices.map(d => `<tr class="border-b border-slate-100 hover:bg-slate-50 cursor-pointer cppm-dev-row" data-mac="${d.mac || ''}">
        ${showTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${escapeHtml(d._tenant || '—')}</td>` : ''}
        <td class="px-4 py-2 font-mono text-xs text-[#01A982] hover:underline">${d.mac || '—'}</td>
        <td class="px-4 py-2">${statusBadge(d.status)}</td>
        <td class="px-4 py-2 text-xs">${d.hostname || '—'}</td>
        <td class="px-4 py-2 font-mono text-xs">${d.ip || '—'}</td>
        <td class="px-4 py-2 text-xs">${d.device_vendor || '—'}</td>
        <td class="px-4 py-2 text-xs">${d.device_os || '—'}</td>
        <td class="px-4 py-2 text-xs">${d.device_type || '—'}</td>
        <td class="px-4 py-2">${attrChips(d.attributes)}</td>
    </tr>`).join('');
    const devRefreshBtn = !isAdmin() ? `<button id="cppm-dev-refresh"
        title="Refresh device cache from ClearPass"
        class="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        Refresh</button>` : '';
    const devTitle = isUnknown ? 'Unknown Devices' : 'My Devices';
    container.innerHTML = `<div class="flex justify-between items-center mb-1 px-1">
        <h3 class="text-base font-semibold text-[#263040]">${devTitle} <span class="text-xs text-slate-400 font-normal">(${devices.length} devices)</span> ${helpIcon('cppm', null, 'NAC help')}</h3>
        <div class="flex items-center gap-2">${addServerButtonHtml('cppm', 'ClearPass')}${devRefreshBtn}</div>
    </div>` + tableWrap(th(cols) + `<tbody>${rows || `<tr><td colspan="${cols.length}" class="px-4 py-6 text-center text-slate-400">No devices found</td></tr>`}</tbody>`);
    document.getElementById('cppm-dev-refresh')?.addEventListener('click', () => refreshModuleCache('cppm_devices').then(() => loadCPPMData(subMenu)));
    container.querySelectorAll('.cppm-dev-row').forEach(tr => {
        tr.addEventListener('click', () => showCPPMDeviceDetail(tr.dataset.mac));
    });
}

// _renderCppmMyUsers() — NAC → My Users: the tenant's JIT 802.1X accounts the
// simulation engine created (Entra ID / LDAP tenant OU / ClearPass local user,
// per the 1X cell's Account location in Config → Engine). Passwords are never
// shown: Reset generates a new random one, stores it in the vault and pushes it
// to the sim client(s); Delete removes the account (the engine re-creates it
// if the client is still on a JIT 1X cell).
async function _renderCppmMyUsers(container, th, tableWrap) {
    const tparam = currentTenant && currentTenant !== 'default' ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    const r = await fetch(`/api/cppm/my-users${tparam}`);
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        container.innerHTML = _cppmErrorPanel(r, e);
        return;
    }
    const d = await r.json();
    const users = d.users || [];
    const esc = escapeHtml;
    const showTenantCol = !d.tenant && users.length > 0;
    const fmt = ts => ts ? new Date(ts * 1000).toLocaleString() : '—';
    const statusBadge = u => {
        const cls = u.status === 'active' ? 'bg-green-100 text-green-700'
            : u.status === 'pending_delete' ? 'bg-amber-100 text-amber-700' : 'bg-red-100 text-red-700';
        const lbl = u.status === 'pending_delete' ? 'deleting' : u.status;
        return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}" title="${esc(u.last_error || '')}">${esc(lbl || '—')}</span>`;
    };
    const cols = (showTenantCol ? ['Tenant'] : []).concat(
        ['Username', 'Location', 'Identity', 'Clients', 'SSID cells', 'Created', 'Password set', 'Next rotation', 'Last active', 'Stored in', 'Status', '']);
    window._cppmMyUsers = users;
    const rows = users.map((u, i) => `<tr class="border-b border-slate-100 hover:bg-slate-50">
        ${showTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${esc(u.tenant_id || '—')}</td>` : ''}
        <td class="px-4 py-2 font-medium">${esc(u.username)}</td>
        <td class="px-4 py-2 text-xs">${esc(u.backend_label || u.backend)}</td>
        <td class="px-4 py-2 font-mono text-xs">${esc(u.identity || '—')}</td>
        <td class="px-4 py-2 text-xs" title="${esc((u.hostnames || []).join(', '))}">${(u.hostnames || []).length ? esc((u.hostnames || []).slice(0, 3).join(', ')) + ((u.hostnames || []).length > 3 ? ` +${u.hostnames.length - 3}` : '') : '<span class="text-slate-300">none</span>'}</td>
        <td class="px-4 py-2 text-xs">${esc((u.cells || []).join(', ') || '—')}</td>
        <td class="px-4 py-2 text-xs">${fmt(u.created_at)}</td>
        <td class="px-4 py-2 text-xs">${fmt(u.rotated_at)}</td>
        <td class="px-4 py-2 text-xs">${fmt(u.next_rotation_at)}</td>
        <td class="px-4 py-2 text-xs">${fmt(u.last_active_at)}</td>
        <td class="px-4 py-2 text-xs">${u.password_store === 'vault' ? 'Vault' : 'Local (encrypted)'}</td>
        <td class="px-4 py-2">${statusBadge(u)}</td>
        <td class="px-4 py-2 text-right whitespace-nowrap">
            <button onclick="cppmMyUserAction(${i}, 'reset')" class="text-xs text-[#01A982] hover:underline font-semibold mr-3">Reset password</button>
            <button onclick="cppmMyUserAction(${i}, 'delete')" class="text-xs text-red-600 hover:underline font-semibold">Delete</button>
        </td>
    </tr>`).join('');
    const rot = d.rotate_days || 30;
    container.innerHTML = `<div class="flex justify-between items-center mb-1 px-1">
        <h3 class="text-base font-semibold text-[#263040]">My Users <span class="text-xs text-slate-400 font-normal">(${users.length} simulation 802.1X accounts)</span> ${helpIcon('cppm', null, 'NAC help')}</h3>
        <button onclick="loadCPPMData('My Users')" class="text-xs text-slate-400 hover:text-slate-600">Refresh</button>
    </div>
    <p class="text-xs text-slate-500 mb-2 px-1">Accounts the simulation engine created for clients on a 1X SSID cell with an Account location (Config → Engine → SSID matrix). Passwords are random, kept in the vault (or the hub's encrypted store when no vault is enabled), rotate every ${esc(rot)} days and are never displayed. An account is removed when its client leaves the 1X cell or is torn down; unused accounts are swept after 30 days.</p>`
        + tableWrap(th(cols) + `<tbody>${rows || `<tr><td colspan="${cols.length}" class="px-4 py-6 text-center text-slate-400">No simulation-created 802.1X accounts</td></tr>`}</tbody>`);
}

window.cppmMyUserAction = async function (idx, action) {
    const u = (window._cppmMyUsers || [])[idx];
    if (!u) return;
    const what = `${u.username} (${u.backend_label || u.backend})`;
    const msg = action === 'reset'
        ? `Reset the password for ${what}? A new random password is stored in the vault and pushed to its simulation client(s).`
        : `Delete ${what}? If a client is still assigned to its 1X SSID the engine will re-create it on the next sweep.`;
    if (!await showConfirmToast(msg)) return;
    try {
        const r = await fetch(`/api/cppm/my-users/${action}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: u.tenant_id, backend: u.backend, username: u.username }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || r.statusText);
        showToast(action === 'reset' ? `Password reset for ${u.username}` : `Deleted ${u.username}`, 'success');
    } catch (e) {
        showToast(`${action === 'reset' ? 'Reset' : 'Delete'} failed: ${e.message}`, 'error');
    }
    loadCPPMData('My Users');
};

async function loadCPPMData(subMenu) {
    const container = document.getElementById('cppm-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    const th = tableHead;  // shared helpers (tableWrap used directly)

    try {
        if (subMenu === 'NAC Status' || subMenu === 'Access Tracker') {
            await _renderCppmSessions(container, subMenu, th, tableWrap);
        } else if (subMenu === 'My Devices' || subMenu === 'Unknown Devices') {
            await _renderCppmDevices(container, subMenu, th, tableWrap);
        } else if (subMenu === 'My Users') {
            await _renderCppmMyUsers(container, th, tableWrap);
        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error loading ${subMenu}: ${err.message}</p>`;
    }
}

async function deleteOpnsenseItem(fwId, subMenu, itemId) {
    if (!await showConfirmToast(`Delete this ${subMenu.replace(/s$/, '')}?`)) return;
    let url = '';
    if (subMenu === 'Firewall Rules') url = `/api/firewall/${fwId}/rules/${encodeURIComponent(itemId)}`;
    else if (subMenu === 'NAT Policies') url = `/api/firewall/${fwId}/nat/${encodeURIComponent(itemId)}`;
    else if (subMenu === 'DNS Records') url = `/api/firewall/${fwId}/dns/${encodeURIComponent(itemId)}`;
    else if (subMenu === 'Aliases') url = `/api/firewall/${fwId}/aliases/${encodeURIComponent(itemId)}`;
    else return;
    try {
        const r = await fetch(url + _taTenantQuery(), { method: 'DELETE' });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || r.statusText); }
        loadOpnsenseManagement();
    } catch (e) {
        showToast('Error deleting: ' + e.message, 'error');
    }
}

function showOpnsenseAddModal(subMenu) {
    const existing = document.getElementById('opn-add-modal');
    if (existing) existing.remove();

    const input = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800';
    const label = 'text-xs text-slate-500 uppercase font-bold';

    // Target firewall: auto-select when only one is configured, otherwise show a
    // picker as the first field. submitOpnsenseAdd reads #add-opn-fw (or falls
    // back to the single configured firewall).
    const fwPicker = _opnFirewalls.length > 1
        ? `<div class="space-y-1"><label class="${label}">Firewall</label><select id="add-opn-fw" class="${input}" title="Select target firewall">${_opnFirewalls.map(fw => `<option value="${fw.id}">${fw.name || fw.id}</option>`).join('')}</select></div>`
        : '';

    let fields = '';
    let submitFn = '';

    if (subMenu === 'Firewall Rules') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Interface</label><input type="text" id="add-opn-iface" placeholder="lan" class="${input}" title="Network interface (e.g. lan, wan)"></div>
                <div class="space-y-1"><label class="${label}">Action</label><select id="add-opn-action" class="${input}" title="Filter action: pass, block, or reject"><option value="pass">Pass</option><option value="block">Block</option><option value="reject">Reject</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}" title="Transport protocol (TCP, UDP, ICMP, any)"><option>TCP</option><option>UDP</option><option>TCP/UDP</option><option>ICMP</option><option>any</option></select></div>
                <div class="space-y-1"><label class="${label}">Source</label><input type="text" id="add-opn-source" placeholder="any" class="${input}" title="Source IP address, subnet CIDR, or alias (default: any)"></div>
                <div class="space-y-1"><label class="${label}">Destination</label><input type="text" id="add-opn-dest" placeholder="any" class="${input}" title="Destination IP address, subnet CIDR, or alias (default: any)"></div>
                <div class="space-y-1"><label class="${label}">Dest Port</label><input type="text" id="add-opn-dport" placeholder="any" class="${input}" title="Destination port number or range (default: any)"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="Rule description" class="${input}" title="Brief rule description or purpose"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    } else if (subMenu === 'Aliases') {
        fields = `
            <div class="space-y-1"><label class="${label}">Name</label><input type="text" id="add-opn-name" placeholder="my_alias" class="${input}" title="Alias name (letters, digits, underscores)"></div>
            <div class="space-y-1"><label class="${label}">Type</label><select id="add-opn-type" class="${input}" title="Alias type: Host, Network, Port, or URL"><option value="host">Host</option><option value="network">Network</option><option value="port">Port</option><option value="url">URL</option></select></div>
            <div class="space-y-1"><label class="${label}">Content (comma-separated)</label><input type="text" id="add-opn-content" placeholder="192.168.1.10, 192.168.1.20" class="${input}" title="Comma-separated IP addresses, CIDRs, or ports"></div>
            <div class="space-y-1"><label class="${label}">Category</label><input type="text" id="add-opn-category" placeholder="tenant name (optional, attributes this alias to a tenant)" class="${input}" title="Optional category / tenant attribution tag"></div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="Optional description" class="${input}" title="Optional alias description"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    } else if (subMenu === 'NAT Policies') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">NAT Type</label><select id="add-opn-nat-type" class="${input}" title="NAT rule type: Port forward (d_nat), Outbound (source_nat), or 1:1 NAT"><option value="d_nat">Destination NAT (Port Forward)</option><option value="source_nat">Source NAT (Outbound)</option><option value="nat_1to1">1:1 NAT</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}" title="Transport protocol"><option>TCP</option><option>UDP</option><option>TCP/UDP</option><option>any</option></select></div>
                <div class="space-y-1"><label class="${label}">External IP</label><input type="text" id="add-opn-ext-ip" placeholder="any" class="${input}" title="External listening IP address or WAN interface"></div>
                <div class="space-y-1"><label class="${label}">External Port</label><input type="text" id="add-opn-ext-port" placeholder="80" class="${input}" title="External listening port number or range"></div>
                <div class="space-y-1"><label class="${label}">Internal IP</label><input type="text" id="add-opn-int-ip" placeholder="192.168.1.100" class="${input}" title="Internal target host IP address"></div>
                <div class="space-y-1"><label class="${label}">Internal Port</label><input type="text" id="add-opn-int-port" placeholder="80" class="${input}" title="Internal target port number"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="NAT rule description" class="${input}" title="NAT rule description"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    } else if (subMenu === 'DNS Records') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Hostname</label><input type="text" id="add-opn-hostname" placeholder="myserver" class="${input}" title="DNS host name"></div>
                <div class="space-y-1"><label class="${label}">Domain</label><input type="text" id="add-opn-domain" placeholder="example.com" class="${input}" title="DNS domain name"></div>
                <div class="space-y-1 col-span-2"><label class="${label}">IP Address</label><input type="text" id="add-opn-ip" placeholder="192.168.1.100" class="${input}" title="IPv4 or IPv6 address"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="Optional description" class="${input}" title="Optional description"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    }

    const modal = document.createElement('div');
    modal.id = 'opn-add-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Add ${subMenu.replace(/s$/, '')}</h3>
                <button onclick="document.getElementById('opn-add-modal').remove()" class="text-slate-400 hover:text-slate-600" title="Close dialog"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">${fwPicker}${fields}</div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="document.getElementById('opn-add-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800" title="Cancel and discard changes">Cancel</button>
                <button onclick="${submitFn}" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm" title="Submit and save ${subMenu.replace(/s$/, '')}">Add</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

async function submitOpnsenseAdd(subMenu) {
    const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    const btn = document.querySelector('#opn-add-modal button:last-child');
    if (btn) { btn.disabled = true; btn.textContent = 'Adding…'; }
    const fwSel = document.getElementById('add-opn-fw');
    const fwId = (fwSel && fwSel.value) || (_opnFirewalls[0] && _opnFirewalls[0].id);
    if (!fwId) { showToast('No firewall selected.', 'success'); return; }
    let url = '', body = {};

    try {
        if (subMenu === 'Firewall Rules') {
            url = `/api/firewall/${fwId}/rules`;
            body = { rule: {
                interface: g('add-opn-iface') || 'lan',
                action: g('add-opn-action') || 'pass',
                protocol: g('add-opn-proto') || 'any',
                source_net: g('add-opn-source') || 'any',
                destination_net: g('add-opn-dest') || 'any',
                destination_port: g('add-opn-dport') || 'any',
                description: g('add-opn-desc'),
                enabled: '1',
            }};
        } else if (subMenu === 'Aliases') {
            url = `/api/firewall/${fwId}/aliases`;
            body = { name: g('add-opn-name'), type: g('add-opn-type'), content: g('add-opn-content'), description: g('add-opn-desc'), category: g('add-opn-category') };
            if (!body.name) { showToast('Name is required.', 'error'); return; }
        } else if (subMenu === 'NAT Policies') {
            url = `/api/firewall/${fwId}/nat`;
            body = {
                nat_type: g('add-opn-nat-type') || 'd_nat',
                rule: {
                    protocol: g('add-opn-proto'),
                    'destination.network': g('add-opn-ext-ip') || 'any',
                    destination_port: g('add-opn-ext-port'),
                    target: g('add-opn-int-ip'),
                    'local-port': g('add-opn-int-port'),
                    descr: g('add-opn-desc'),
                    enabled: '1',
                }
            };
        } else if (subMenu === 'DNS Records') {
            url = `/api/firewall/${fwId}/dns`;
            body = { hostname: g('add-opn-hostname'), domain: g('add-opn-domain'), ip: g('add-opn-ip'), description: g('add-opn-desc') };
            if (!body.hostname || !body.ip) { showToast('Hostname and IP are required.', 'error'); return; }
        } else return;

        const r = await fetch(url + _taTenantQuery(), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || r.statusText); }
        document.getElementById('opn-add-modal')?.remove();
        loadOpnsenseManagement();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function showOpnsenseEditModal(fwId, subMenu, itemIdx) {
    const item = _opnCurrentItems[itemIdx];
    if (!item) { showToast('Item data not found — try refreshing the page.', 'error'); return; }
    const itemId = item.id || item.uuid || '';

    const existing = document.getElementById('opn-add-modal');
    if (existing) existing.remove();

    const input = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800';
    const label = 'text-xs text-slate-500 uppercase font-bold';
    const v = k => (item[k] !== undefined && item[k] !== null ? String(item[k]) : '').replace(/"/g, '&quot;');

    let fields = '';
    if (subMenu === 'Firewall Rules') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Interface</label><input type="text" id="add-opn-iface" value="${v('interface')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Action</label><select id="add-opn-action" class="${input}"><option value="pass" ${item.action==='pass'?'selected':''}>Pass</option><option value="block" ${item.action==='block'?'selected':''}>Block</option><option value="reject" ${item.action==='reject'?'selected':''}>Reject</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}"><option ${item.protocol==='TCP'?'selected':''}>TCP</option><option ${item.protocol==='UDP'?'selected':''}>UDP</option><option ${item.protocol==='TCP/UDP'?'selected':''}>TCP/UDP</option><option ${item.protocol==='ICMP'?'selected':''}>ICMP</option><option ${item.protocol==='any'?'selected':''}>any</option></select></div>
                <div class="space-y-1"><label class="${label}">Source</label><input type="text" id="add-opn-source" value="${v('source')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Destination</label><input type="text" id="add-opn-dest" value="${v('destination')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Dest Port</label><input type="text" id="add-opn-dport" value="${v('destination_port')}" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else if (subMenu === 'Aliases') {
        fields = `
            <div class="space-y-1"><label class="${label}">Name</label><input type="text" id="add-opn-name" value="${v('name')}" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Type</label><select id="add-opn-type" class="${input}"><option value="host" ${item.type==='host'?'selected':''}>Host</option><option value="network" ${item.type==='network'?'selected':''}>Network</option><option value="port" ${item.type==='port'?'selected':''}>Port</option><option value="url" ${item.type==='url'?'selected':''}>URL</option></select></div>
            <div class="space-y-1"><label class="${label}">Content (comma-separated)</label><input type="text" id="add-opn-content" value="${v('content')}" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Category</label><input type="text" id="add-opn-category" value="${v('category')}" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else if (subMenu === 'NAT Policies') {
        const natType = item.type || 'd_nat';
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">NAT Type</label><select id="add-opn-nat-type" class="${input}"><option value="d_nat" ${natType==='d_nat'?'selected':''}>Destination NAT (Port Forward)</option><option value="source_nat" ${natType==='source_nat'?'selected':''}>Source NAT (Outbound)</option><option value="nat_1to1" ${natType==='nat_1to1'?'selected':''}>1:1 NAT</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}"><option ${item.protocol==='TCP'?'selected':''}>TCP</option><option ${item.protocol==='UDP'?'selected':''}>UDP</option><option ${item.protocol==='TCP/UDP'?'selected':''}>TCP/UDP</option><option ${item.protocol==='any'?'selected':''}>any</option></select></div>
                <div class="space-y-1"><label class="${label}">External IP</label><input type="text" id="add-opn-ext-ip" value="${v('external_ip')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">External Port</label><input type="text" id="add-opn-ext-port" value="${v('external_port')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Internal IP</label><input type="text" id="add-opn-int-ip" value="${v('internal_ip')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Internal Port</label><input type="text" id="add-opn-int-port" value="${v('internal_port')}" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else if (subMenu === 'DNS Records') {
        const hostParts = (item.hostname || '').split('.');
        const hostname = hostParts[0] || '';
        const domain = item.domain || (hostParts.length > 1 ? hostParts.slice(1).join('.') : '');
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Hostname</label><input type="text" id="add-opn-hostname" value="${hostname.replace(/"/g,'&quot;')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Domain</label><input type="text" id="add-opn-domain" value="${domain.replace(/"/g,'&quot;')}" class="${input}"></div>
                <div class="space-y-1 col-span-2"><label class="${label}">IP Address</label><input type="text" id="add-opn-ip" value="${v('ip')}" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else return;

    const modal = document.createElement('div');
    modal.id = 'opn-add-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Edit ${subMenu.replace(/s$/, '')}</h3>
                <button onclick="document.getElementById('opn-add-modal').remove()" class="text-slate-400 hover:text-slate-600" title="Close dialog"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">${fields}</div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="document.getElementById('opn-add-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800" title="Cancel and discard changes">Cancel</button>
                <button onclick="submitOpnsenseEdit('${fwId}','${subMenu}','${itemId.replace(/'/g,"\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm" title="Save changes to ${subMenu.replace(/s$/, '')}">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

async function submitOpnsenseEdit(fwId, subMenu, itemId) {
    const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    const btn = document.querySelector('#opn-add-modal button:last-child');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    let url = '', body = {};

    try {
        const encodedId = encodeURIComponent(itemId);
        if (subMenu === 'Firewall Rules') {
            url = `/api/firewall/${fwId}/rules/${encodedId}`;
            body = { rule: {
                interface: g('add-opn-iface') || 'lan',
                action: g('add-opn-action') || 'pass',
                protocol: g('add-opn-proto') || 'any',
                source_net: g('add-opn-source') || 'any',
                destination_net: g('add-opn-dest') || 'any',
                destination_port: g('add-opn-dport') || 'any',
                description: g('add-opn-desc'),
                enabled: '1',
            }};
        } else if (subMenu === 'Aliases') {
            url = `/api/firewall/${fwId}/aliases/${encodedId}`;
            body = { name: g('add-opn-name'), type: g('add-opn-type'), content: g('add-opn-content'), description: g('add-opn-desc'), category: g('add-opn-category') };
            if (!body.name) { showToast('Name is required.', 'error'); return; }
        } else if (subMenu === 'NAT Policies') {
            url = `/api/firewall/${fwId}/nat/${encodedId}`;
            body = {
                nat_type: g('add-opn-nat-type') || 'd_nat',
                rule: {
                    protocol: g('add-opn-proto'),
                    'destination.network': g('add-opn-ext-ip') || 'any',
                    destination_port: g('add-opn-ext-port'),
                    target: g('add-opn-int-ip'),
                    'local-port': g('add-opn-int-port'),
                    descr: g('add-opn-desc'),
                    enabled: '1',
                }
            };
        } else if (subMenu === 'DNS Records') {
            url = `/api/firewall/${fwId}/dns/${encodedId}`;
            body = { hostname: g('add-opn-hostname'), domain: g('add-opn-domain'), ip: g('add-opn-ip'), description: g('add-opn-desc') };
            if (!body.hostname || !body.ip) { showToast('Hostname and IP are required.', 'error'); return; }
        } else return;

        const r = await fetch(url + _taTenantQuery(), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || r.statusText); }
        document.getElementById('opn-add-modal')?.remove();
        loadOpnsenseManagement();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

// ── Directory (LDAP/Entra) — tenant-scoped user + group management ───────────
// TENANT == OU (1:1). The tenant picker selects which OU to manage; the server
// injects + guards the tenant_slug (a tenant-admin cannot cross tenants). Auth
// mode per user: Entra-backed (UPN, no local password) or Local (set password).

const LDAP_ICONS = {
    edit: `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`,
    del:  `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`,
    pw:   `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>`,
    mem:  `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a4 4 0 00-3-3.87M9 20H4v-2a4 4 0 013-3.87m6-1.13a4 4 0 10-4-4 4 4 0 004 4z"></path></svg>`,
};

// Currently-selected tenant id (the OU to manage). Populated by ensureLDAPTenants.
window._ldapTenant = window._ldapTenant || '';

async function ensureLDAPTenants(force) {
    if (!window._ldapTenants || force) {
        try {
            const data = await apiJson('/api/ldap/tenants');
            window._ldapTenants = data.tenants || [];
        } catch (e) {
            window._ldapTenants = [];
        }
    }
    const ts = window._ldapTenants || [];
    const sel = document.getElementById('ldap-tenant-select');
    if (sel) {
        if (!ts.length) {
            sel.innerHTML = '<option value="">No tenants</option>';
            window._ldapTenant = '';
        } else {
            // BUG: We are intentionally ignoring the global 'currentTenant' here.
            // Even if a tenant is selected globally, we default to the first available
            // LDAP tenant or keep the existing _ldapTenant, creating a state desync.
            if (!window._ldapTenant) {
                window._ldapTenant = ts[0].id;
            }
            sel.innerHTML = ts.map(t => `<option value="${escapeHtml(t.id)}" ${t.id === window._ldapTenant ? 'selected' : ''}>${escapeHtml(t.name || t.id)}</option>`).join('');
        }
        _updateLDAPOuHint();
    }
    return ts;
}

function _updateLDAPOuHint() {
    const hint = document.getElementById('ldap-ou-hint');
    if (!hint) return;
    const cur = (window._ldapTenants || []).find(t => t.id === window._ldapTenant);
    hint.textContent = cur ? ('ou=' + (cur.slug || cur.id)) : '';
}

function onLDAPTenantChange() {
    const sel = document.getElementById('ldap-tenant-select');
    if (sel) window._ldapTenant = sel.value;
    _updateLDAPOuHint();
    loadLDAPData(currentSubView || 'Users');
}

function _ldapTenantQuery() {
    return window._ldapTenant ? ('?tenant=' + encodeURIComponent(window._ldapTenant)) : '';
}

async function loadLDAPData(subMenu) {
    subMenu = (subMenu === 'Groups') ? 'Groups' : 'Users';
    const headEl = document.getElementById('ldap-table-head');
    const bodyEl = document.getElementById('ldap-table-body');
    if (!headEl || !bodyEl) return;

    await ensureLDAPTenants();
    if (!window._ldapTenant) {
        headEl.innerHTML = '';
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">No tenant available to manage.</td></tr>`;
        return;
    }
    const canWrite = isAdmin() || isTenantAdmin();

    try {
        const endpoint = (subMenu === 'Groups' ? '/api/ldap/groups' : '/api/ldap/users') + _ldapTenantQuery();
        const headers = (subMenu === 'Groups')
            ? ['Group', 'Members', 'Actions']
            : ['Username', 'Name', 'Auth', 'Email / UPN', 'Actions'];
        headEl.innerHTML = headers.map(h => `<th class="px-4 py-3 font-bold">${h}</th>`).join('');
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">Fetching ${subMenu.toLowerCase()}…</td></tr>`;

        const data = await apiJson(endpoint);
        const items = (data && (data.users || data.groups || data.data)) || (Array.isArray(data) ? data : []);
        window._ldapRows = items;

        if (!items.length) {
            bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">No ${subMenu.toLowerCase()} in this tenant.</td></tr>`;
            return;
        }

        bodyEl.innerHTML = items.map(it => {
            if (subMenu === 'Groups') {
                const cn = escapeHtml(it.cn || it.name || '');
                const members = it.members || it.member || [];
                const memCount = Array.isArray(members) ? members.length : (it.member_count || 0);
                const eCn = String(it.cn || it.name || '').replace(/'/g, "\\'");
                const actions = canWrite ? `<td class="px-4 py-3 text-right whitespace-nowrap">
                    <button onclick="showLDAPMembersModal('${eCn}')" title="Manage group members" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${LDAP_ICONS.mem}</button>
                    <button onclick="deleteLDAPGroup('${eCn}')" title="Delete group" class="p-1 text-slate-400 hover:text-red-600 transition-colors">${LDAP_ICONS.del}</button>
                </td>` : '<td></td>';
                return `<tr class="hover:bg-slate-50 transition-colors"><td class="px-4 py-3 font-medium text-slate-700">${cn}</td><td class="px-4 py-3 text-slate-500 text-xs">${memCount} members</td>${actions}</tr>`;
            }
            const uid = escapeHtml(it.uid || it.username || '');
            const eUid = String(it.uid || it.username || '').replace(/'/g, "\\'");
            const isEntra = it.auth_mode === 'entra';
            const name = escapeHtml(it.name || [it.first_name, it.last_name].filter(Boolean).join(' ') || '');
            const email = escapeHtml(it.email || it.upn || '');
            const badge = isEntra
                ? '<span title="Authenticates via Entra — no local password" class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-700">Entra</span>'
                : '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-600">Local</span>';
            const actions = canWrite ? `<td class="px-4 py-3 text-right whitespace-nowrap">
                <button onclick="editLDAPUser('${eUid}')" title="Edit user details" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${LDAP_ICONS.edit}</button>
                ${isEntra ? '' : `<button onclick="showLDAPPasswordModal('${eUid}')" title="Reset user password" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${LDAP_ICONS.pw}</button>`}
                <button onclick="deleteLDAPUser('${eUid}')" title="Delete user" class="p-1 text-slate-400 hover:text-red-600 transition-colors">${LDAP_ICONS.del}</button>
            </td>` : '<td></td>';
            return `<tr class="hover:bg-slate-50 transition-colors"><td class="px-4 py-3 font-medium text-slate-700">${uid}</td><td class="px-4 py-3 text-slate-600">${name}</td><td class="px-4 py-3">${badge}</td><td class="px-4 py-3 text-slate-600">${email}</td>${actions}</tr>`;
        }).join('');
    } catch (err) {
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-red-500">${escapeHtml(err.message || String(err))}</td></tr>`;
    }
}

function editLDAPUser(uid) {
    const item = (window._ldapRows || []).find(r => (r.uid || r.username) === uid);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showLDAPModal('Users', item);
}

function showLDAPModal(subMenu, editItem) {
    subMenu = (subMenu === 'Groups') ? 'Groups' : 'Users';
    const editing = !!editItem;
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50';
    modal.id = 'ldap-modal';  // close by id after save (querySelector('.fixed') grabbed the wrong element)
    const inp = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));

    let fields = '';
    let title = '';
    if (subMenu === 'Groups') {
        title = 'Add Group';
        fields = `<div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Group Name (cn)</label><input type="text" id="ldap-group-cn" title="Common Name (cn) for the new group" class="${inp}"></div>`;
    } else {
        title = editing ? 'Edit User' : 'Add User';
        const curMode = editing ? (editItem.auth_mode === 'entra' ? 'entra' : 'local') : 'local';
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Username (uid)</label><input type="text" id="ldap-user-uid" value="${val(editItem && (editItem.uid || editItem.username))}" ${editing ? 'readonly' : ''} title="Unique directory identifier (uid)" class="${inp} ${editing ? 'bg-slate-100 text-slate-500' : ''}"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Auth Mode</label>
                    <select id="ldap-user-auth" ${editing ? 'disabled' : ''} onchange="_syncLDAPAuthFields()" title="Authentication mode (Local password or Azure AD Entra-backed)" class="${inp} ${editing ? 'bg-slate-100 text-slate-500' : ''}">
                        <option value="local" ${curMode === 'local' ? 'selected' : ''}>Local (password)</option>
                        <option value="entra" ${curMode === 'entra' ? 'selected' : ''}>Entra-backed (UPN)</option>
                    </select>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">First Name</label><input type="text" id="ldap-user-first" value="${val(editItem && editItem.first_name)}" title="User given name" class="${inp}"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Last Name</label><input type="text" id="ldap-user-last" value="${val(editItem && editItem.last_name)}" title="User surname / family name" class="${inp}"></div>
                <div class="space-y-2 col-span-2"><label class="text-xs text-slate-500 uppercase font-bold">Email</label><input type="text" id="ldap-user-email" value="${val(editItem && editItem.email)}" title="User email address" class="${inp}"></div>
            </div>
            <div id="ldap-entra-wrap" class="space-y-2 ${curMode === 'entra' ? '' : 'hidden'}"><label class="text-xs text-slate-500 uppercase font-bold">UPN (Entra user principal name)</label><input type="text" id="ldap-user-upn" value="${val(editItem && editItem.upn)}" placeholder="user@tenant.onmicrosoft.com" title="Entra User Principal Name (UPN)" class="${inp}"></div>
            ${editing ? '' : `<div id="ldap-local-wrap" class="space-y-2 ${curMode === 'local' ? '' : 'hidden'}"><label class="text-xs text-slate-500 uppercase font-bold">Password <span class="text-slate-400 normal-case font-normal">(leave blank to auto-generate)</span></label><input type="password" id="ldap-user-password" title="Initial password (leave blank to auto-generate)" class="${inp}"></div>`}
        `;
    }

    modal.innerHTML = `
        <div class="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden border border-slate-200">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-[#263040]">${title}</h3>
                <button onclick="this.closest('.fixed').remove()" title="Close dialog" class="text-slate-400 hover:text-slate-600"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">${fields}</div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="this.closest('.fixed').remove()" title="Cancel and close dialog" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                <button onclick="${subMenu === 'Groups' ? 'saveLDAPGroup()' : `saveLDAPUser(${editing ? 'true' : 'false'})`}" title="Save directory changes" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

function _syncLDAPAuthFields() {
    const mode = document.getElementById('ldap-user-auth')?.value;
    const entra = document.getElementById('ldap-entra-wrap');
    const local = document.getElementById('ldap-local-wrap');
    if (entra) entra.classList.toggle('hidden', mode !== 'entra');
    if (local) local.classList.toggle('hidden', mode !== 'local');
}

async function saveLDAPUser(editing) {
    const uid = document.getElementById('ldap-user-uid')?.value.trim();
    if (!uid) { showToast('Username (uid) is required', 'error'); return; }
    const authEl = document.getElementById('ldap-user-auth');
    const authMode = authEl ? authEl.value : 'local';
    const attrs = {
        first_name: document.getElementById('ldap-user-first')?.value.trim() || '',
        last_name: document.getElementById('ldap-user-last')?.value.trim() || '',
        email: document.getElementById('ldap-user-email')?.value.trim() || '',
    };
    const body = { tenant_id: window._ldapTenant, uid, attrs };
    if (!editing) {
        body.auth_mode = authMode;
        if (authMode === 'entra') {
            const upn = document.getElementById('ldap-user-upn')?.value.trim();
            if (!upn) { showToast('UPN is required for an Entra-backed user', 'error'); return; }
            body.upn = upn;
        } else {
            const pw = document.getElementById('ldap-user-password')?.value;
            if (pw) body.password = pw;
        }
    } else if (authMode === 'entra') {
        const upn = document.getElementById('ldap-user-upn')?.value.trim();
        if (upn) body.upn = upn;
    }
    try {
        const res = await fetch('/api/ldap/users', {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) {
            const result = await res.json().catch(() => ({}));
            if (!editing && result.password) {
                showToast(`User created!\n\nGenerated password: ${result.password}\n\nPlease record this — it will not be shown again.`, 'success');
            } else {
                showToast(editing ? 'User updated.' : 'User created.', 'success');
            }
            document.getElementById('ldap-modal')?.remove();
            loadLDAPData('Users');
        } else {
            const err = await res.json().catch(() => ({}));
            showToast('Error: ' + (err.detail || err.message || 'Failed to save user'), 'error');
        }
    } catch (e) {
        showToast('Request failed: ' + e.message, 'error');
    }
}

async function saveLDAPGroup() {
    const cn = document.getElementById('ldap-group-cn')?.value.trim();
    if (!cn) { showToast('Group name (cn) is required', 'error'); return; }
    try {
        const res = await fetch('/api/ldap/groups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: window._ldapTenant, cn }),
        });
        if (res.ok) {
            showToast('Group created.', 'success');
            document.getElementById('ldap-modal')?.remove();
            loadLDAPData('Groups');
        } else {
            const err = await res.json().catch(() => ({}));
            showToast('Error: ' + (err.detail || err.message || 'Failed to create group'), 'error');
        }
    } catch (e) {
        showToast('Request failed: ' + e.message, 'error');
    }
}

async function deleteLDAPUser(uid) {
    if (!await showConfirmToast(`Delete user "${uid}"?`)) return;
    try {
        const res = await fetch('/api/ldap/users', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: window._ldapTenant, uid }),
        });
        if (res.ok) { showToast('User deleted.', 'success'); loadLDAPData('Users'); }
        else { const err = await res.json().catch(() => ({})); showToast('Error: ' + (err.detail || err.message || 'Failed to delete user'), 'error'); }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
}

async function deleteLDAPGroup(cn) {
    if (!await showConfirmToast(`Delete group "${cn}"?`)) return;
    try {
        const res = await fetch('/api/ldap/groups', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: window._ldapTenant, cn }),
        });
        if (res.ok) { showToast('Group deleted.', 'success'); loadLDAPData('Groups'); }
        else { const err = await res.json().catch(() => ({})); showToast('Error: ' + (err.detail || err.message || 'Failed to delete group'), 'error'); }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
}

function showLDAPPasswordModal(uid) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50';
    modal.id = 'ldap-pw-modal';
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const eUid = String(uid).replace(/'/g, "\\'");
    modal.innerHTML = `
        <div class="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden border border-slate-200">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-[#263040]">Reset Password</h3>
                <button onclick="this.closest('.fixed').remove()" title="Close dialog" class="text-slate-400 hover:text-slate-600">✕</button>
            </div>
            <div class="p-6 space-y-4">
                <p class="text-xs text-slate-500 font-mono">${escapeHtml(uid)}</p>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">New Password</label><input type="password" id="ldap-new-password" title="Enter new user password" class="${inputCls}" autocomplete="new-password"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Confirm Password</label><input type="password" id="ldap-confirm-password" title="Re-enter new user password to confirm" class="${inputCls}" autocomplete="new-password"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="this.closest('.fixed').remove()" title="Cancel and close dialog" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
                <button onclick="changeUserPassword('${eUid}')" title="Apply new password" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all">Set Password</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

async function changeUserPassword(uid) {
    const pw = document.getElementById('ldap-new-password')?.value;
    const confirm = document.getElementById('ldap-confirm-password')?.value;
    if (!pw) { showToast('Password cannot be empty', 'error'); return; }
    if (pw !== confirm) { showToast('Passwords do not match', 'error'); return; }
    try {
        const r = await fetch('/api/ldap/users/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: window._ldapTenant, uid, password: pw }),
        });
        if (r.ok) {
            showToast('Password changed.', 'success');
            document.getElementById('ldap-pw-modal')?.remove();
        } else {
            const err = await r.json().catch(() => ({}));
            showToast('Error: ' + (err.detail || err.message || 'Failed to change password'), 'error');
        }
    } catch (e) {
        showToast('Request failed: ' + e.message, 'error');
    }
}

async function showLDAPMembersModal(cn) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50';
    modal.dataset.cn = cn;
    modal.innerHTML = `
        <div class="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden border border-slate-200">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-[#263040]">Members — ${escapeHtml(cn)}</h3>
                <button onclick="this.closest('.fixed').remove()" title="Close dialog" class="text-slate-400 hover:text-slate-600">✕</button>
            </div>
            <div class="p-6 space-y-4">
                <div class="flex items-center gap-2">
                    <select id="ldap-member-add" title="Select user to add to group" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading users…</option></select>
                    <button onclick="addLDAPMember('${String(cn).replace(/'/g, "\\'")}')" title="Add selected user to group" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Add</button>
                </div>
                <div id="ldap-members-list" class="space-y-1 max-h-64 overflow-y-auto"><p class="text-xs text-slate-400 italic">Loading members…</p></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end">
                <button onclick="this.closest('.fixed').remove()" title="Close dialog" class="px-4 py-2 text-sm text-slate-600">Close</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    _renderLDAPMembers(cn);
}

async function _renderLDAPMembers(cn) {
    const listEl = document.getElementById('ldap-members-list');
    const addSel = document.getElementById('ldap-member-add');
    try {
        const [gData, uData] = await Promise.all([
            apiJson('/api/ldap/groups' + _ldapTenantQuery()),
            apiJson('/api/ldap/users' + _ldapTenantQuery()),
        ]);
        const groups = (gData && (gData.groups || gData.data)) || (Array.isArray(gData) ? gData : []);
        const users = (uData && (uData.users || uData.data)) || (Array.isArray(uData) ? uData : []);
        const grp = groups.find(g => (g.cn || g.name) === cn) || {};
        const members = (grp.members || grp.member || []).map(m => String(m));
        if (listEl) {
            listEl.innerHTML = members.length
                ? members.map(m => `<div class="flex items-center justify-between px-3 py-1.5 bg-slate-50 rounded-md text-sm"><span class="text-slate-700">${escapeHtml(m)}</span><button onclick="removeLDAPMember('${String(cn).replace(/'/g, "\\'")}','${String(m).replace(/'/g, "\\'")}')" title="Remove user from group" class="text-xs font-bold text-red-600 hover:text-red-700">Remove</button></div>`).join('')
                : '<p class="text-xs text-slate-400 italic">No members.</p>';
        }
        if (addSel) {
            const avail = users.map(u => u.uid || u.username).filter(u => u && !members.includes(String(u)));
            addSel.innerHTML = avail.length
                ? avail.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('')
                : '<option value="">No users to add</option>';
        }
    } catch (e) {
        if (listEl) listEl.innerHTML = `<p class="text-xs text-red-500">${escapeHtml(e.message || String(e))}</p>`;
    }
}

async function addLDAPMember(cn) {
    const uid = document.getElementById('ldap-member-add')?.value;
    if (!uid) { showToast('Select a user to add', 'info'); return; }
    try {
        const res = await fetch('/api/ldap/groups/members', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: window._ldapTenant, cn, uid }),
        });
        if (res.ok) { showToast('Member added.', 'success'); _renderLDAPMembers(cn); }
        else { const err = await res.json().catch(() => ({})); showToast('Error: ' + (err.detail || err.message || 'Failed to add member'), 'error'); }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
}

async function removeLDAPMember(cn, uid) {
    try {
        const res = await fetch('/api/ldap/groups/members', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: window._ldapTenant, cn, uid }),
        });
        if (res.ok) { showToast('Member removed.', 'success'); _renderLDAPMembers(cn); }
        else { const err = await res.json().catch(() => ({})); showToast('Error: ' + (err.detail || err.message || 'Failed to remove member'), 'error'); }
    } catch (e) { showToast('Request failed: ' + e.message, 'error'); }
}

async function showAddUserModal() {
    const tadm = isTenantAdmin();
    // Tenant picklist for the Assigned Tenants multi-select (Global admins only —
    // a Tenant Admin creates users in their OWN tenant, no picker). Required when
    // "Admin (tenant)" is checked; the backend rejects a tenant_admin with none.
    if (!tadm) { try { await ensureTenants(); } catch (e) {} }
    const _tenants = tadm ? [] : (window._allTenants || []);
    const _tenantRows = _tenants.length
        ? _tenants.map(t => `<label class="flex items-center gap-2 text-sm text-slate-600 py-1"><input type="checkbox" value="${escapeHtml(t.id)}" class="new-user-tenant w-4 h-4 text-amber-600 border-slate-300 rounded focus:ring-amber-500"> ${escapeHtml(t.name || t.id)}</label>`).join('')
        : '<span class="text-[11px] text-slate-400 italic">No tenants defined yet.</span>';
    const modal = document.createElement('div');
    modal.id = 'add-user-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Add New User</h3>
                <button onclick="closeAddUserModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">User ID / Username</label><input type="text" id="new-user-id" placeholder="e.g. jsmith" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Auth Type</label>
                        <select id="new-user-auth-type" onchange="document.getElementById('new-user-password-wrap').classList.toggle('hidden', this.value==='ldap')" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="local">Local</option>
                            <option value="ldap">LDAP</option>
                        </select>
                    </div>
                </div>
                <div id="new-user-password-wrap" class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Password <span class="text-slate-400 normal-case font-normal">(leave blank to set later)</span></label>
                    <input type="password" id="new-user-password" placeholder="••••••••" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="grid grid-cols-6 gap-3">
                    ${tadm ? '' : `<div><label class="text-xs text-slate-500 uppercase font-bold" title="System-wide admin (all tenants + system config)">Global Admin</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-admin" onchange="document.getElementById('perm-tenant_admin').checked = false" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold" title="Tenant-level admin (admin within assigned tenants only)">Admin (tenant)</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-tenant_admin" onchange="document.getElementById('perm-admin').checked = false" class="w-4 h-4 text-amber-600 border-slate-300 rounded focus:ring-amber-500"></div></div>`}
                    <div><label class="text-xs text-slate-500 uppercase font-bold">View</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-view" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Edit</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-edit" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Hypervisor</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-pxmx" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Firewall</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-firewall" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">DNS</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-dns" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">DHCP</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-dhcp" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">NAC</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-nac" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Network Devices</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-nw" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">IPAM</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-ipam" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Simulations</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-cs" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Console</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-console" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Console Write</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-console_write" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                </div>
                ${tadm ? `<div class="space-y-2 border-t border-slate-200 pt-3"><label class="text-xs text-slate-500 uppercase font-bold">Tenant</label><div class="text-sm text-slate-600">User is created in <span class="font-mono font-bold text-green-700">${escapeHtml(currentTenant || 'default')}</span> (your tenant). Module rights only — admin roles are Global-Admin-only.</div></div>` : `<div class="space-y-2 border-t border-slate-200 pt-3">
                    <label class="text-xs text-slate-500 uppercase font-bold">Assigned Tenants <span class="text-slate-400 normal-case font-normal">(required for Tenant Admin; also confines a regular user)</span></label>
                    <div id="new-user-tenants" class="grid grid-cols-3 gap-x-4 gap-y-1 mt-1 max-h-36 overflow-y-auto pr-1">${_tenantRows}</div>
                </div>
                <div class="space-y-2 border-t border-slate-200 pt-3">
                    <label class="text-xs text-slate-500 uppercase font-bold">Permission Groups <span class="text-slate-400 normal-case font-normal">(bundle access; unioned with the flags above)</span></label>
                    <div id="new-user-groups" class="flex flex-wrap gap-2 text-sm text-slate-400 italic">Loading groups…</div>
                </div>`}
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeAddUserModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveUser()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Create User</button>
            </div>
        </div>
    `;
    _mountModal(modal);
    if (document.getElementById('new-user-groups')) {
        _populateUserGroupChecklist('new-user-groups', []);
    }
}

function closeAddUserModal() {
    const modal = document.getElementById('add-user-modal');
    if (modal) modal.remove();
}

async function saveUser() {
    const userId = document.getElementById('new-user-id').value.trim();
    if (!userId) { showToast('Please enter a User ID', 'error'); return; }

    const tadm = isTenantAdmin();
    // A tenant Admin may only grant module rights — never an admin tier. The
    // role checkboxes are hidden in the modal for tenant_admin, but force the
    // keys false regardless so a crafted client value can't escalate.
    const permissions = {
        admin: tadm ? false : document.getElementById('perm-admin')?.checked,
        tenant_admin: tadm ? false : document.getElementById('perm-tenant_admin')?.checked,
        view: document.getElementById('perm-view').checked,
        edit: document.getElementById('perm-edit').checked,
        pxmx: document.getElementById('perm-pxmx').checked,
        firewall: document.getElementById('perm-firewall').checked,
        dns: document.getElementById('perm-dns').checked,
        dhcp: document.getElementById('perm-dhcp').checked,
        nac: document.getElementById('perm-nac').checked,
        nw: document.getElementById('perm-nw').checked,
        ipam: document.getElementById('perm-ipam').checked,
        cs: document.getElementById('perm-cs').checked,
        console: document.getElementById('perm-console').checked,
        console_write: document.getElementById('perm-console_write').checked,
    };
    const auth_type = document.getElementById('new-user-auth-type')?.value || 'local';
    const password = document.getElementById('new-user-password')?.value || '';
    const groups = tadm ? undefined : _collectCheckedGroups('new-user-groups');
    // Assigned tenants (Global-admin path). A Tenant Admin MUST have ≥1 — guard
    // client-side for a clear message before the backend 400s.
    const tenants = tadm ? undefined : Array.from(
        document.querySelectorAll('#new-user-tenants input.new-user-tenant:checked')).map(el => el.value);
    if (!tadm && permissions.tenant_admin && (!tenants || tenants.length === 0)) {
        showToast('Tenant Admin requires at least one assigned tenant — select one under "Assigned Tenants".', 'success');
        return;
    }
    const base = _taUsersBase();

    try {
        const response = await setupFetch(base ? base : '/setup/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(base
                ? { user_id: userId, permissions, auth_type, password }
                : { user_id: userId, permissions, auth_type, password, groups, tenants, create: true })
        });
        if (response.ok) {
            showToast('User created successfully', 'success');
            closeAddUserModal();
            await loadUsers();
        } else {
            const d = await response.json().catch(() => ({}));
            showToast(d.detail || 'Failed to create user', 'error');
        }
    } catch (err) {
        showToast('Error creating user: ' + err.message, 'error');
    }
}

async function editUser(userId) {
    try {
        const tadm = isTenantAdmin();
        const base = _taUsersBase();
        // Tenant Admins use the tenant-scoped user list + their own allowed
        // tenants (the /setup/tenants + /setup/groups routes are Global-only).
        const fetches = tadm
            ? [setupFetch(base)]
            : [setupFetch('/setup/users'), setupFetch('/setup/tenants'), setupFetch('/setup/groups')];
        const results = await Promise.all(fetches);
        const userResp = results[0];
        const tenantResp = tadm ? null : results[1];
        const groupResp = tadm ? null : results[2];
        if (!userResp.ok) throw new Error('Failed to load user data');

        const userData = await userResp.json();
        const tenantData = tenantResp ? await tenantResp.json() : { tenants: (userAllowedTenants() || []).map(id => ({ id, name: id })) };
        const groupData = groupResp && groupResp.ok ? await groupResp.json() : { groups: {} };

        const users = userData.users || {};
        const user = users[userId];
        if (!user) throw new Error('User not found');
        if (user.protected) { showToast('This account is protected and cannot be edited.', 'error'); return; }

        const tenants = tenantData.tenants || [];
        const userTenants = user.tenants || [];
        const allGroups = groupData.groups || {};
        const userGroups = user.groups || [];

        const modal = document.createElement('div');
        modal.id = 'edit-user-modal';
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

        const perms = user.effective_permissions || user.permissions || {};
        // Tenant Admins may only edit module rights — hide the Global Admin /
        // tenant Admin tier checkboxes (the backend rejects them anyway).
        const permFields = [
            ...(tadm ? [] : [{id: 'admin', label: 'Global Admin'}, {id: 'tenant_admin', label: 'Admin (tenant)'}]),
            {id: 'view', label: 'View'},
            {id: 'edit', label: 'Edit'},
            {id: 'pxmx', label: 'Hypervisor'},
            {id: 'firewall', label: 'Firewall'},
            {id: 'dns', label: 'DNS'},
            {id: 'dhcp', label: 'DHCP'},
            {id: 'nac', label: 'NAC'},
            {id: 'nw', label: 'Network Devices'},
            {id: 'ipam', label: 'IPAM'},
            {id: 'cs', label: 'Simulations'},
            {id: 'console', label: 'Console'},
            {id: 'console_write', label: 'Console Write'},
        ];

        const permHtml = permFields.map(p => {
            // Admin uses two equivalent forms; check the box if either is set so
            // editing a role-only admin shows it checked (and saving preserves it).
            // The two admin tiers (Global Admin / tenant Admin) are mutually
            // exclusive — checking one unchecks the other.
            const isChecked = p.id === 'admin'
                ? (perms.admin === true || perms.role === 'admin')
                : p.id === 'tenant_admin'
                    ? (perms.role === 'tenant_admin')
                    : !!perms[p.id];
            const onchange = p.id === 'admin'
                ? `onchange="document.getElementById('edit-perm-tenant_admin').checked = false"`
                : p.id === 'tenant_admin'
                    ? `onchange="document.getElementById('edit-perm-admin').checked = false"`
                    : '';
            return `
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">${p.label}</label>
                <div class="flex items-center gap-2 py-2">
                    <input type="checkbox" id="edit-perm-${p.id}" ${isChecked ? 'checked' : ''} ${onchange} class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                </div>
            </div>
        `;
        }).join('');

        const tenantHtml = tenants.map(t => `
            <div class="flex items-center gap-3 p-2 hover:bg-slate-100 rounded-md transition-colors cursor-pointer">
                <input type="checkbox" id="edit-tenant-${t.id}" ${userTenants.includes(t.id) ? 'checked' : ''} value="${t.id}" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                <label for="edit-tenant-${t.id}" class="text-sm text-slate-700 cursor-pointer flex-1">${t.name}</label>
            </div>
        `).join('');

        const groupHtml = Object.entries(allGroups).map(([gid, g]) => `
            <div class="flex items-center gap-3 p-2 hover:bg-slate-100 rounded-md transition-colors cursor-pointer">
                <input type="checkbox" id="edit-grp-${gid}" ${userGroups.includes(gid) ? 'checked' : ''} value="${gid}" class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">
                <label for="edit-grp-${gid}" class="text-sm text-slate-700 cursor-pointer flex-1">${g.name || gid}<span class="text-[10px] text-slate-400 ml-1">${Object.keys(g.permissions || {}).filter(k => k !== 'role').join(', ')}</span></label>
            </div>
        `).join('');

        modal.innerHTML = `
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                    <h3 class="text-lg font-bold text-[#263040]">Edit User: ${userId}</h3>
                    <button onclick="closeEditUserModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
                </div>
                <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div class="space-y-6"><div><h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Permissions</h4><div class="grid grid-cols-2 gap-4">${permHtml}</div></div></div>
                    <div class="space-y-6">
                        ${tadm ? '' : `<div><h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Permission Groups</h4><div class="border border-slate-200 rounded-lg overflow-hidden bg-slate-50 max-h-40 overflow-y-auto p-2 space-y-1">${groupHtml || '<div class="text-xs text-slate-400 italic p-2">No groups defined.</div>'}</div></div>`}
                        <div><h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Tenant Associations</h4><div class="border border-slate-200 rounded-lg overflow-hidden bg-slate-50 max-h-40 overflow-y-auto p-2 space-y-1">${tenantHtml || '<div class="text-xs text-slate-400 italic p-2">No tenants available.</div>'}</div></div>
                    </div>
                </div>
                <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-between items-center gap-3">
                    <button onclick="promptSetPassword('${userId}')" class="text-xs text-slate-500 hover:text-blue-600 transition-colors">Set Password</button>
                    <div class="flex justify-end gap-3">
                        <button onclick="closeEditUserModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                        <button onclick="saveUserEdits('${userId}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
                    </div>
                </div>
            </div>
        `;
        _mountModal(modal);
    } catch (err) {
        showToast('Error opening edit modal: ' + err.message, 'error');
    }
}

function closeEditUserModal() {
    const modal = document.getElementById('edit-user-modal');
    if (modal) modal.remove();
}

async function saveUserEdits(userId) {
    try {
        const tadm = isTenantAdmin();
        const base = _taUsersBase();
        // The admin-tier checkboxes are absent for a tenant Admin; use optional
        // chaining so the read is false (and force false regardless — a tenant
        // admin must never grant an admin tier; the backend rejects it too).
        const permissions = {
            admin: tadm ? false : document.getElementById('edit-perm-admin')?.checked,
            tenant_admin: tadm ? false : document.getElementById('edit-perm-tenant_admin')?.checked,
            view: document.getElementById('edit-perm-view').checked,
            edit: document.getElementById('edit-perm-edit').checked,
            pxmx: document.getElementById('edit-perm-pxmx').checked,
            firewall: document.getElementById('edit-perm-firewall').checked,
            dns: document.getElementById('edit-perm-dns').checked,
            dhcp: document.getElementById('edit-perm-dhcp').checked,
            nac: document.getElementById('edit-perm-nac').checked,
            nw: document.getElementById('edit-perm-nw').checked,
            ipam: document.getElementById('edit-perm-ipam').checked,
            cs: document.getElementById('edit-perm-cs').checked,
            console: document.getElementById('edit-perm-console').checked,
            console_write: document.getElementById('edit-perm-console_write').checked,
        };

        const tenantCheckboxes = document.querySelectorAll('input[id^="edit-tenant-"]');
        const selectedTenants = Array.from(tenantCheckboxes).filter(cb => cb.checked).map(cb => cb.value);

        if (tadm) {
            // One tenant-scoped POST: permissions + tenant membership (the route
            // intersects the requested tenants with the admin's owned tenants and
            // always retains the path tenant). No groups, no separate
            // assign/remove-tenant calls.
            const resp = await setupFetch(`${base}/${encodeURIComponent(userId)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ permissions, tenants: selectedTenants })
            });
            if (!resp.ok) {
                const d = await resp.json().catch(() => ({}));
                throw new Error(d.detail || 'Failed to update user');
            }
            showToast('User updated successfully', 'success');
            closeEditUserModal();
            await loadUsers();
            return;
        }

        const groupCheckboxes = document.querySelectorAll('input[id^="edit-grp-"]');
        const selectedGroups = Array.from(groupCheckboxes).filter(cb => cb.checked).map(cb => cb.value);

        await apiJson('/setup/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, permissions: permissions, groups: selectedGroups })
        });

        const userData = await apiJson('/setup/users');
        const currentTenants = userData.users[userId].tenants || [];

        const tenantsToAssign = selectedTenants.filter(t => !currentTenants.includes(t));
        const tenantsToRemove = currentTenants.filter(t => !selectedTenants.includes(t));

        // One batched call applies the whole add/remove delta (was one POST per
        // changed tenant) — a single session invalidation server-side.
        if (tenantsToAssign.length || tenantsToRemove.length) {
            await setupFetch('/setup/users/set-tenants', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, add: tenantsToAssign, remove: tenantsToRemove }),
            });
        }

        showToast('User updated successfully', 'success');
        closeEditUserModal();
        await loadUsers();
    } catch (err) {
        showToast('Error saving user edits: ' + err.message, 'error');
    }
}

async function promptSetPassword(userId) {
    const pw = prompt(`Set password for ${userId}:`);
    if (!pw) return;
    try {
        const base = _taUsersBase();
        const url = base
            ? `${base}/${encodeURIComponent(userId)}/set-password`
            : `/setup/users/${encodeURIComponent(userId)}/set-password`;
        const resp = await setupFetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw }),
        });
        if (resp.ok) {
            showToast('Password updated.', 'success');
        } else {
            const d = await resp.json().catch(() => ({}));
            showToast('Failed: ' + (d.detail || resp.statusText), 'error');
        }
    } catch (err) {
        showToast('Error: ' + err.message, 'error');
    }
}

function showAddFirewallModal() {
    const modal = document.createElement('div');
    modal.id = 'firewall-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]" id="fw-modal-title">Add New Firewall</h3>
                <button onclick="closeFirewallModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Firewall Name</label><input type="text" id="fw-name" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Model</label><select id="fw-model" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="opnsense">OPNsense</option><option value="juniper">Juniper</option><option value="fortigate">Fortigate</option><option value="pfsense">pfSense</option></select></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label><select id="fw-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading spokes...</option></select></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Host/IP</label><input type="text" id="fw-host" placeholder="172.16.1.1" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Port</label><input type="text" id="fw-port" placeholder="8443" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Key</label><input type="text" id="fw-api-key" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Secret</label><input type="password" id="fw-api-secret" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeFirewallModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveFirewall()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Firewall</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('fw-spoke');
        if (selector) {
            const fwSpokes = spokes.filter(s =>
                (s.module_type === 'firewall' ||
                 /^(opn|fw|firewall|pfsense|fortigate|juniper)/.test(s.spoke_id))
                && _spokeBindable(s)
            );
            selector.innerHTML = fwSpokes.length > 0
                ? '<option value="">— select spoke —</option>' + fwSpokes.map(s => `<option value="${s.spoke_id}" title="${escapeHtml(s.spoke_id)}">${escapeHtml(_spokeName(s))}</option>`).join('')
                : '<option value="">No firewall spokes found</option>';
        }
    });
}

async function editFirewall(id) {
    const firewalls = await loadFirewalls();
    const fw = firewalls.find(f => f.id === id);
    if (!fw) return;

    showAddFirewallModal();
    document.getElementById('fw-modal-title').textContent = 'Edit Firewall';
    document.getElementById('fw-name').value = fw.name;
    document.getElementById('fw-model').value = fw.model;
    document.getElementById('fw-host').value = fw.host;
    document.getElementById('fw-port').value = fw.port;
    document.getElementById('fw-api-key').value = fw.api_key;
    document.getElementById('fw-api-secret').value = fw.api_secret;

    setTimeout(() => {
        const selector = document.getElementById('fw-spoke');
        if (selector) selector.value = fw.spoke_id || '';
    }, 100);

    document.getElementById('firewall-modal').dataset.firewallId = id;
}

async function saveFirewall() {
    const modal = document.getElementById('firewall-modal');
    const id = modal.dataset.firewallId;
    const config = {
        name: document.getElementById('fw-name').value,
        model: document.getElementById('fw-model').value,
        spoke_id: document.getElementById('fw-spoke').value,
        host: document.getElementById('fw-host').value,
        port: parseInt(document.getElementById('fw-port').value) || 8443,
        api_key: document.getElementById('fw-api-key').value,
        api_secret: document.getElementById('fw-api-secret').value,
    };

    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `/setup/firewalls/${id}` : '/setup/firewalls';
        const payload = id ? { config: config } : { firewall: config };
        const response = await setupFetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            showToast(`Firewall ${id ? 'updated' : 'added'} successfully!`, 'success');
            closeFirewallModal();
            setView(currentView);
        } else {
            const err = await response.json().catch(() => ({}));
            showToast('Failed to save firewall configuration: ' + (err.detail || response.status), 'error');
        }
    } catch (err) {
        showToast('Error saving firewall: ' + err.message, 'error');
    }
}

function closeFirewallModal() {
    const modal = document.getElementById('firewall-modal');
    if (modal) modal.remove();
}
