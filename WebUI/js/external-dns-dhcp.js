// external-dns-dhcp.js — External DNS providers, HE.NET, DHCP (Kea).
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── External DNS (internet-facing DNS providers) ───────────────────────────
// Public/internet DNS services managed from the hub, surfaced under
// DNS → External DNS (the DNS module is "all things DNS" — internal AND
// external). Each connected provider gets its own tile; picking one drills into
// its record management. To add a provider, append an entry here (a stable id,
// display name, description, its window.activeProducts product key, and a loader
// that renders into #dns-content) and wire its spoke — the subtab visibility,
// the tile grid, and nav-gating all derive from this registry automatically.
const EXTERNAL_DNS_PROVIDERS = [
    {
        id: 'henet',
        product: 'henet',
        name: 'HE.NET',
        desc: 'Hurricane Electric public DNS — A/AAAA records pushed to dns.he.net over its dynamic-DNS API.',
        load: () => loadHenet(),
    },
];

// External DNS providers whose spoke/product is currently active (approved).
function _externalDnsConnected() {
    const active = window.activeProducts;
    return EXTERNAL_DNS_PROVIDERS.filter(p => active && active.has(p.product));
}

// Breadcrumb/back bar shown atop a provider's records view — only when more than
// one external provider is connected (so the operator can return to the tiles).
// With a single provider there is no tile hop, so no back bar.
function _extDnsBackBar(name) {
    if (!window._extDnsMulti) return '';
    return `<div class="mb-3 flex items-center gap-2 text-xs">
        <button onclick="loadExternalDNS()" class="inline-flex items-center gap-1 text-slate-500 hover:text-[#01A982] font-medium" title="Back to External DNS providers">← External DNS</button>
        <span class="text-slate-300">/</span>
        <span class="font-bold text-slate-600">${escapeHtml(name)}</span>
      </div>`;
}

// DNS → External DNS landing. No provider → empty state. Exactly one → drill
// straight into it (no needless tile hop). Multiple → a tile per provider,
// each opening that provider's record management.
async function loadExternalDNS() {
    const container = document.getElementById('dns-content');
    if (!container) return;
    const providers = _externalDnsConnected();
    if (providers.length === 0) {
        container.innerHTML = '<p class="p-4 text-slate-400 italic text-sm">No external DNS provider connected. Connect a provider spoke (e.g. HE.NET) to manage internet-facing DNS here.</p>';
        return;
    }
    if (providers.length === 1) {
        window._extDnsMulti = false;
        return providers[0].load();
    }
    window._extDnsMulti = true;
    container.innerHTML = `<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 p-1">` +
        providers.map(p => `
          <button onclick="openExternalDns('${p.id}')" class="text-left bg-white border border-slate-200 rounded-lg p-4 hover:border-[#01A982] hover:shadow-md transition-all" title="Manage ${escapeHtml(p.name)} external DNS records">
            <div class="flex items-center justify-between mb-1">
              <span class="text-sm font-bold text-[#263040]">${escapeHtml(p.name)}</span>
              <span class="text-[10px] font-mono text-slate-400">${escapeHtml(p.id)}</span>
            </div>
            <p class="text-xs text-slate-500 leading-snug">${escapeHtml(p.desc)}</p>
            <span class="inline-block mt-3 text-[11px] font-bold text-[#01A982]">Manage records →</span>
          </button>`).join('') + `</div>`;
}

function openExternalDns(id) {
    const p = EXTERNAL_DNS_PROVIDERS.find(x => x.id === id);
    if (p) p.load();
}

// ─── HE.NET (Hurricane Electric public DNS) ─────────────────────────────────
// Manages A/AAAA records at dns.he.net over HE's dynamic-DNS update API. The HE
// DDNS key is NEVER sent from the browser — the operator picks a Credential
// Vault secret of type 'henet' (a {bucket,name} reference) and the hub resolves
// it unattended (net_services._henet_resolve_vault_cred). Each record carries
// an explicit tenant_id (global "" for Global-Admin-managed, or the owning
// tenant's) — a Global Admin sees + manages everything; a tenant-admin (or
// DNS-view user, read-only) sees only their own tenant's records. Record/
// credential writes need tenant-admin tier (or admin); bulk sync/import stay
// Global-Admin-only (see api.py _ADMIN_INFRA_WRITE_PREFIXES /
// _HENET_TENANT_WRITE_PREFIXES).

// Collect every automation-readable Credential Vault secret of type 'henet' as
// {bucket, name, label} options for the DDNS-key picker. Uses the same
// server-side ``automation-secrets`` endpoint the LE module uses: it returns
// hub-mode secrets across every reachable bucket INCLUDING the Global-Admin
// (__admin__) infra slot, with no pass-phrase needed — unlike a per-bucket
// ``secrets?bucket=`` listing, which is PSK-gated and skips the admin slot
// (that's why the HE key never showed up here before).
//
// A single Hurricane Electric credential serves BOTH modules, so the picker
// lists ``henet`` DDNS-key secrets AND shared LE DNS-01 "Hurricane Electric
// (account login)" secrets (``dns`` secrets carrying he_username/he_password).
// The hub reformats whichever shape into the dyndns push password
// (net_services._henet_extract_ddns_key), so the operator never keeps two
// copies of the same key.
async function _henetVaultCredOptions() {
    try {
        const v = await apiJson('/tenant/cred-vault/automation-secrets');
        const isHeUsable = s =>
            s.type === 'henet' ||
            (s.type === 'dns' && (s.fields || []).some(f => f === 'he_username' || f === 'he_password' || f === 'ddns_key'));
        return ((v && v.secrets) || []).filter(isHeUsable).map(s => ({
            bucket: s.bucket,
            name: s.name,
            label: `${s.is_admin_slot ? 'Global Admin' : s.bucket} › ${s.name}`
                + (s.type === 'dns' ? ' (LE HE credential)' : ''),
        }));
    } catch (e) { return []; }
}

// ── Credential Vault picker for module connection secrets (NAC / NW device) ──
// Lets an operator BACK a connection's secret (ClearPass client secret, device
// password / enable secret / API token / SNMP community) with a Credential Vault
// entry instead of typing it inline. Selecting one stores a NON-secret
// {bucket,name} reference on the instance/device; the hub resolves the value
// server-side at push time (instance_vault.overlay), so the plaintext never
// lives in global_config nor returns to the browser. Same automation-readable
// source the LE/HE.NET pickers use, so admin-slot secrets show up too.
async function _instanceVaultCredOptions() {
    try {
        const v = await apiJson('/tenant/cred-vault/automation-secrets');
        const opts = ((v && v.secrets) || []).map(s => ({
            bucket: s.bucket, name: s.name,
            label: `${s.is_admin_slot ? 'Global Admin' : s.bucket} › ${s.name}${s.type ? ' (' + _cvTypeLabel(s.type) + ')' : ''}`,
        }));
        opts.vaultAvailable = !!(v && v.vault_available);
        return opts;
    } catch (e) { return []; }
}

// The <select> markup for a Vault-credential picker (options filled async by
// _fillVaultCredSelect). The accompanying inline secret inputs stay optional —
// when a credential is picked they may be left blank.
function _vaultCredSelectHtml(elId) {
    const cls = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    return `<div class="space-y-1">
        <label class="text-xs text-slate-500 uppercase font-bold" title="Optionally back this connection's secret with a Credential Vault entry instead of typing it inline. The hub resolves the value at push time and never stores the plaintext.">Credential Vault (optional)</label>
        <select id="${elId}" title="Pick a Vault secret to supply this connection's password/secret, or leave as “— none —” to enter it inline." class="${cls}"><option value="">Loading…</option></select>
        <p class="text-[11px] text-slate-400 leading-snug">When set, the secret field(s) below may be left blank — the hub fills them from the Vault at push time and never stores the plaintext.</p>
    </div>`;
}

// Populate a Vault-credential <select> and preselect the record's existing
// {bucket,name} reference (if any). Options are cached on the element so the
// save handler can map the chosen index back to a {bucket,name}.
//
// ``vaultOnly`` = {inputIds, required}: when the hub's cloud vault is enabled
// the server rejects inline secrets, so those inputs are hidden (and skipped on
// save), and with ``required`` a vault credential must be picked.
async function _fillVaultCredSelect(elId, current, vaultOnly) {
    const el = document.getElementById(elId);
    if (!el) return;
    const opts = await _instanceVaultCredOptions();
    el._opts = opts;
    const cur = current && current.bucket && current.name ? current : null;
    let curIdx = '';
    el.innerHTML = '<option value="">— none (enter secret inline) —</option>' +
        opts.map((o, i) => {
            if (cur && o.bucket === cur.bucket && o.name === cur.name) curIdx = String(i);
            return `<option value="${i}">${escapeHtml(o.label)}</option>`;
        }).join('');
    // A stored reference that isn't automation-listable (e.g. reach changed) is
    // still shown "(current)" so the operator sees it's set and doesn't silently
    // clear it just by saving.
    if (cur && curIdx === '') {
        el.innerHTML += `<option value="keep" selected>🔐 ${escapeHtml(cur.bucket)} › ${escapeHtml(cur.name)} (current)</option>`;
        el._keep = cur;
    } else {
        el.value = curIdx;
    }
    if (vaultOnly && opts.vaultAvailable) _vaultOnlyForm(el, opts, vaultOnly);
}

function _vaultOnlyForm(el, opts, { inputIds = [], required = false }) {
    inputIds.forEach(id => {
        const input = document.getElementById(id);
        if (!input) return;
        input.dataset.vaultHidden = '1';
        (input.closest('.space-y-2') || input).style.display = 'none';
    });
    const box = el.parentElement;
    const label = box.querySelector('label');
    if (label) label.textContent = required ? 'Credential Vault (required)' : 'Credential Vault';
    const none = el.querySelector('option[value=""]');
    if (none) none.textContent = required ? '— select a vault credential —' : '— none —';
    const hint = box.querySelector('p');
    if (hint) hint.textContent = (opts.length ? '' : 'No automation-readable secrets yet — add one in Credential Vault first. ')
        + 'The Credential Vault is enabled, so connection secrets come from the vault and are not entered here.';
    el.dataset.required = required ? '1' : '';
}

// True (after telling the user) when a required vault credential is not picked.
function _vaultCredMissing(elId) {
    const el = document.getElementById(elId);
    if (!el || el.dataset.required !== '1' || _collectVaultCred(elId)) return false;
    showToast('Select a Credential Vault credential — the vault is enabled, so secrets cannot be entered inline.', 'error');
    return true;
}

// Resolve a Vault-credential <select> to the value to send: a {bucket,name}
// when one is picked/kept, or null to explicitly clear it (switch back to
// inline). Returns undefined when the picker isn't present.
function _collectVaultCred(elId) {
    const el = document.getElementById(elId);
    if (!el) return undefined;
    if (el.value === 'keep' && el._keep) return el._keep;
    if (el.value === '') return null;
    const o = (el._opts || [])[+el.value];
    return o ? { bucket: o.bucket, name: o.name } : null;
}

// The current HE.NET tenant scope for a Global Admin, derived from the top
// tenant selector: a specific tenant id, or "" for the Admin (global) slot. A
// non-admin is always server-pinned to their own tenant, so this returns null
// and callers omit any tenant hint.
function _henetScope() {
    if (!isAdmin()) return null;
    return (currentTenant && currentTenant !== 'default') ? currentTenant : '';
}

function _henetPushBadge(r) {
    if (!r.last_push_status) return '<span class="text-slate-400">—</span>';
    if (r.last_push_status === 'imported') {
        const detail = r.last_push_detail ? ` title="${escapeHtml(String(r.last_push_detail))}"` : '';
        return `<span class="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-700"${detail}>imported</span>`;
    }
    const ok = r.last_push_status === 'ok';
    const cls = ok ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700';
    const detail = r.last_push_detail ? ` title="${escapeHtml(String(r.last_push_detail))}"` : '';
    return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}"${detail}>${ok ? 'pushed' : 'error'}</span>`;
}

async function loadHenet() {
    const container = document.getElementById('dns-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    const th = tableHead, tw = tableWrap;
    const admin = isAdmin();
    // Record/credential writes need tenant-admin tier (or admin) — a plain
    // DNS-view user sees records read-only, matching the server's
    // _can_edit_shared gate on /api/henet/record and /api/henet/credential.
    const canWrite = admin || isTenantAdmin();
    // Global Admin honors the top tenant selector (like nw/ipam/firewall/dns):
    // a specific tenant scopes the view to that tenant; the default/Admin
    // selection ("" scope) shows the global/admin-managed set. A non-admin is
    // always pinned to their own tenant server-side, so scope is irrelevant.
    const adminScope = admin ? ((currentTenant && currentTenant !== 'default') ? currentTenant : '') : null;
    const backBar = _extDnsBackBar('HE.NET');
    const btnCls = 'bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold shadow-sm';
    const btnClsDanger = 'bg-red-50 hover:bg-red-100 text-red-600 border border-red-300 px-3 py-1.5 rounded-md text-xs font-bold shadow-sm';
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;

    // Status line (HE dyndns reachability + record count — fleet-wide, not
    // per-tenant data).
    let statusHtml = '';
    try {
        const s = await _spokeFetch('/api/henet/status');
        if (s.ok && s.data && s.data.status === 'SUCCESS') {
            const dot = s.data.reachable ? 'text-emerald-600' : 'text-amber-600';
            const why = (!s.data.reachable && s.data.detail)
                ? ` <span class="text-amber-500" title="${escapeHtml(String(s.data.detail))}">(${escapeHtml(String(s.data.detail))})</span>` : '';
            statusHtml = `<span class="${dot} font-medium">● HE DNS ${s.data.reachable ? 'reachable' : 'unreachable'}</span>${why} · ${s.data.record_count} managed record(s)`;
        }
    } catch (e) { /* status is best-effort */ }

    // Scheduled-sync badge (admin only) — shows the current schedule so it's
    // discoverable without opening the modal. Best-effort; config route is
    // read-only + authed.
    let scheduleHtml = '';
    if (admin) {
        try {
            const sc = await _spokeFetch('/api/henet/sync-config');
            if (sc.ok && sc.data && sc.data.config) {
                window._henetScheduleCfg = sc.data.config;
                const cfg = sc.data.config;
                if (cfg.enabled) {
                    const when = cfg.mode === 'daily'
                        ? `daily at ${escapeHtml(String(cfg.daily_time || '02:00'))}`
                        : `every ${_henetFmtInterval(cfg.interval_seconds)}`;
                    scheduleHtml = ` · <span class="text-slate-600" title="Automatic HE.NET re-sync is on">⏱ auto-sync ${when}</span>`;
                }
            }
        } catch (e) { /* best-effort */ }
    }

    // Assigned DDNS credential — the slot for the CURRENT scope. A non-admin
    // gets their own tenant's slot. A Global Admin gets the selected tenant's
    // slot when a tenant is picked, or the Admin (global) slot — plus the
    // "tenants with their own credential" overview — on the default selection.
    // Stored as a non-secret {bucket,name} reference (GET /api/henet/credential).
    let assignedCred = null;
    let tenantCreds = {};
    try {
        const credUrl = (admin && adminScope)
            ? '/api/henet/credential?tenant=' + encodeURIComponent(adminScope)
            : '/api/henet/credential';
        const c = await _spokeFetch(credUrl);
        if (c.ok && c.data) {
            assignedCred = c.data.credential || null;
            tenantCreds = c.data.tenants || {};
        }
    } catch (e) { /* best-effort */ }
    window._henetAssignedCred = assignedCred;
    // Label the scope: "Admin" for the global slot, nothing for a tenant slot
    // (the record list already makes the selected tenant obvious).
    const credScope = (admin && !adminScope) ? 'Admin ' : '';
    const credInfo = canWrite
        ? (assignedCred
            ? ` · <span class="text-slate-600">${credScope}DNS credential: <span class="font-mono">🔐 ${escapeHtml(assignedCred.name)}</span></span>`
            : ` · <span class="text-amber-600 font-medium">no ${credScope.toLowerCase()}DNS credential assigned</span>`)
        : '';
    const tenantCredN = Object.keys(tenantCreds).length;
    const tenantCredInfo = admin && tenantCredN
        ? ` · <span class="text-slate-500">${tenantCredN} tenant${tenantCredN === 1 ? '' : 's'} with ${tenantCredN === 1 ? 'its' : 'their'} own credential</span>`
        : '';

    // Add/Change-credential is write-tier (own slot for a tenant-admin, global
    // slot for admin). Import/Sync are bulk, no per-object tenant model, so
    // they stay admin-only — same as the server's _ADMIN_INFRA_WRITE_PREFIXES.
    const actionBar = `<div class="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div class="text-xs text-slate-500">${statusHtml}${credInfo}${tenantCredInfo}${scheduleHtml}</div>
        <div class="flex gap-2">
          ${canWrite ? `<button onclick="showHenetCredModal()" class="${btnCls}" title="${assignedCred ? 'Change the assigned HE DDNS credential' : 'Assign an HE DDNS credential from the Credential Vault'}">🔐 ${assignedCred ? 'Change credential' : 'Assign credential'}</button>` : ''}
          ${canWrite ? `<button onclick="showHenetRecordModal()" class="${btnCls}" title="Add a new DNS record to manage at HE.NET">+ Add Record</button>` : ''}
          ${admin && assignedCred ? `<button onclick="importHenet()" class="${btnCls}" title="Read the existing records already in your HE.NET zone (via the account login) and bring them under management">⇩ Import existing</button>` : ''}
          ${admin && assignedCred ? `<button onclick="syncHenet()" class="${btnCls}" title="Re-push every managed A/AAAA record to HE.NET">↻ Sync all</button>` : ''}
          ${admin ? `<button onclick="showHenetScheduleModal()" class="${btnCls}" title="Schedule an automatic re-sync of every managed HE.NET record">⏱ Schedule…</button>` : ''}
          ${admin ? `<button onclick="showHenetMoveAllModal()" class="${btnCls}" title="Re-home every record in the current view to another tenant (metadata only — the HE.NET zone is untouched)">➡ Move all…</button>` : ''}
          ${canWrite ? `<button onclick="deconfigureHenetScope()" class="${btnClsDanger}" title="Remove every record in the current view from management (the HE.NET zone is left unchanged)">🧹 Deconfigure</button>` : ''}
        </div>
      </div>`;

    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/records');
        if (!ok) {
            container.innerHTML = backBar + actionBar + `${_spokeErrorBanner(detail, 'HE.NET spoke not connected')}${_isSpokeUpdating(detail) ? '' : '<p class="px-4 pb-4 text-xs text-slate-400">Load the “HE.NET” role on an agent and store an HE DDNS key in the Credential Vault (secret type “HE.NET DDNS key”).</p>'}`;
            return;
        }
        // A non-admin only ever gets their own tenant's records back (the
        // server filters — see henet_list_records); a Global Admin gets
        // everything (global + every tenant's), each tagged with tenant_id, and
        // we scope it here to the tenant picked in the top selector.
        const allRecords = d.records || [];
        const records = admin
            ? allRecords.filter(r => (r.tenant_id || '') === adminScope)
            : allRecords;
        window._henetRecords = records;
        // Keep the record modal's tenant default + push-free re-home target in
        // step with the selector (the modal reads _henetActiveTab).
        if (admin) window._henetActiveTab = adminScope;
        const cols = ['Name', 'Type', 'Value', 'TTL', 'Last Push'].concat(canWrite ? [''] : []);
        const rowHtml = (r) => {
            const eName = String(r.name).replace(/'/g, "\\'");
            const eType = String(r.type).replace(/'/g, "\\'");
            return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-mono font-medium">${escapeHtml(r.name)}</td>
                <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-700">${escapeHtml(r.type)}</span></td>
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.value)}</td>
                <td class="px-4 py-2 text-center text-xs">${escapeHtml(String(r.ttl))}</td>
                <td class="px-4 py-2 text-center">${_henetPushBadge(r)}</td>
                ${canWrite ? `<td class="px-4 py-2 whitespace-nowrap">
                    <button onclick="editHenetRecord('${eName}','${eType}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                    <button onclick="deleteHenetRecord('${eName}','${eType}')" title="Remove from management" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                </td>` : ''}
            </tr>`;
        };
        const bodyHtml = tw(th(cols) + `<tbody>${records.map(rowHtml).join('')}</tbody>`);
        container.innerHTML = backBar + actionBar + (records.length === 0
            ? '<p class="p-4 text-slate-400 italic text-sm">No HE.NET records under management yet.' + (canWrite ? ' Use “+ Add Record”.' : '') + '</p>'
            : bodyHtml);
    } catch (err) {
        container.innerHTML = backBar + actionBar + `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

function editHenetRecord(name, type) {
    const rec = (window._henetRecords || []).find(r => r.name === name && r.type === type);
    showHenetRecordModal(rec || { name, type });
}

async function showHenetRecordModal(editItem) {
    const editing = !!(editItem && editItem.value != null);
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const typeOpts = ['A', 'AAAA'].map(t =>
        `<option value="${t}"${editItem && editItem.type === t ? ' selected' : ''}>${t}</option>`).join('');
    const cred = window._henetAssignedCred;
    // Admin-only tenant selector: assign/re-home a record to a tenant (or
    // Global). A non-admin's records are always their own tenant's (server-
    // pinned), so they never see this field. Defaults to the active tab on add.
    let tenantField = '';
    if (isAdmin()) {
        await ensureTenants();
        const tenants = window._allTenants || [];
        const cur = (editItem && editItem.tenant_id != null)
            ? String(editItem.tenant_id) : String(window._henetActiveTab || '');
        const opts = [`<option value=""${cur === '' ? ' selected' : ''}>Admin (admin-managed / shared)</option>`]
            .concat(tenants.map(t => `<option value="${escapeHtml(t.id)}"${String(t.id) === cur ? ' selected' : ''}>${escapeHtml(t.name || t.id)}</option>`))
            .join('');
        tenantField = `<div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Tenant</label><select id="henet-r-tenant" class="${inputCls}" title="Which tenant owns this record. Admin = admin-managed / shared. A tenant only sees and manages its own records — pick a tenant to move this record to that tenant.">${opts}</select></div>`;
    }
    const modal = openModal('henet-record-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} HE.NET Record</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Name</label><input id="henet-r-name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="host.example.com" title="Fully-qualified DNS record name to manage at HE.NET (e.g. host.example.com) — must have dynamic DNS enabled at dns.he.net" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Type</label><select id="henet-r-type" class="${inputCls}" title="Record type: A (IPv4) or AAAA (IPv6) — HE's dyndns endpoint only updates A/AAAA" ${editing ? 'disabled' : ''}>${typeOpts}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Value (IP)</label><input id="henet-r-value" value="${val(editItem?.value)}" class="${inputCls}" placeholder="203.0.113.5" title="IP address the record resolves to (A = IPv4, AAAA = IPv6)"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">TTL</label><input id="henet-r-ttl" type="number" min="60" value="${val(editItem?.ttl) || 300}" class="${inputCls}" title="Time-to-live in seconds (minimum 60; default 300)"></div>
            ${tenantField}
            <p class="text-[11px] text-slate-400">Records are created/updated directly in your HE.NET zone using the assigned account login${cred ? ` (<span class="font-mono">🔐 ${escapeHtml(cred.name)}</span>)` : ''} — no per-record DDNS key needed.${editing && isAdmin() ? ` To just move this record to another tenant's tab, change <b>Tenant</b> and leave <b>Value</b> unchanged — it's re-homed without touching HE.NET.` : ''}</p>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="saveHenetRecord()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="${editing ? 'Save changes to this HE.NET record' : 'Add record to HE.NET management'}">${editing ? 'Save Changes' : 'Add Record'}</button>
            <button onclick="document.getElementById('henet-record-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Cancel and close dialog">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    if (editing) { modal.dataset.editName = editItem.name; modal.dataset.editType = editItem.type; modal.dataset.editTenant = String(editItem.tenant_id || ''); modal.dataset.editValue = String(editItem.value || ''); }
}

// ── HE DDNS credential assignment ───────────────────────────────────────────
// Pick a Credential Vault 'henet' secret once; the hub uses it for every
// add/sync (POST /api/henet/credential). Server-derives WHICH slot this
// writes to from the caller: a Global Admin (no ?tenant=) gets the global
// slot; a tenant-admin always gets their own tenant's slot — never
// client-choosable, so this same modal/save path works unmodified for both.
async function showHenetCredModal() {
    const creds = await _henetVaultCredOptions();
    const assigned = window._henetAssignedCred;
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const opts = creds.length
        ? creds.map(c => {
            const v = `${c.bucket}|${c.name}`;
            const sel = assigned && assigned.bucket === c.bucket && assigned.name === c.name ? ' selected' : '';
            return `<option value="${escapeHtml(v)}"${sel}>${escapeHtml(c.label)}</option>`;
          }).join('')
        : '';
    openModal('henet-cred-modal', `
        <h3 class="text-lg font-bold text-[#263040]">Assign HE.NET DDNS credential</h3>
        <p class="text-sm text-slate-500">The HE.NET module uses this Credential Vault secret to push records — assign it once and you won't be asked per record. Use the SAME Hurricane Electric credential as certificates: add it under <b>Credential Vault → + Add secret → DNS → Hurricane Electric (account login)</b> (automation mode), or reuse an existing one — the same HE credential works for both certs and DNS.</p>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">DDNS credential</label>
          ${creds.length
            ? `<select id="henet-assign-cred" class="${inputCls}" title="Credential Vault Hurricane Electric credential (shared with certificate DNS-01 issuance) used to push records unattended">${opts}</select>`
            : `<p class="text-sm text-amber-600 italic">No automation-readable Hurricane Electric credential found in the Credential Vault. Add a <b>DNS → Hurricane Electric (account login)</b> secret first (it serves both certs and DNS).</p>`}
        </div>
        <div class="flex justify-end gap-2 pt-2">
            ${assigned ? `<button onclick="_henetClearCred()" class="bg-red-50 hover:bg-red-100 text-red-600 border border-red-200 px-4 py-2 rounded-md text-sm mr-auto" title="Clear assigned HE.NET DDNS credential">Clear</button>` : ''}
            ${creds.length ? `<button onclick="_henetSaveCred()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="Save assigned HE.NET credential">Save</button>` : ''}
            <button onclick="document.getElementById('henet-cred-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Cancel and close dialog">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
}

async function _henetSaveCred() {
    const sel = document.getElementById('henet-assign-cred')?.value || '';
    const [bucket, name] = String(sel).split('|');
    if (!bucket || !name) { showToast('Add a Hurricane Electric credential to the Credential Vault first', 'error'); return; }
    try {
        const payload = { bucket, name };
        const scope = _henetScope();
        if (scope !== null) payload.tenant = scope;  // admin: selected tenant, or "" = Admin slot
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/credential', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && d.status === 'SUCCESS') {
            document.getElementById('henet-cred-modal')?.remove();
            showToast('HE.NET DDNS credential assigned', 'success');
            loadHenet();
        } else showToast('Error: ' + (detail || d?.message || 'Failed to assign credential'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function _henetClearCred() {
    try {
        const scope = _henetScope();
        const url = scope
            ? '/api/henet/credential?tenant=' + encodeURIComponent(scope)
            : '/api/henet/credential';
        const { ok, data: d, detail } = await _spokeFetch(url, { method: 'DELETE' });
        if (ok && d.status === 'SUCCESS') {
            document.getElementById('henet-cred-modal')?.remove();
            showToast('HE.NET DDNS credential cleared', 'success');
            loadHenet();
        } else showToast('Error: ' + (detail || d?.message || 'Failed to clear credential'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// Human-friendly "every N" for a seconds interval (used by the schedule badge).
function _henetFmtInterval(secs) {
    const n = parseInt(secs, 10) || 3600;
    if (n % 86400 === 0) { const d = n / 86400; return d === 1 ? 'day' : `${d} days`; }
    if (n % 3600 === 0) { const h = n / 3600; return h === 1 ? 'hour' : `${h} hours`; }
    const m = Math.round(n / 60); return m === 1 ? 'minute' : `${m} minutes`;
}

// Scheduled auto-sync config (Global Admin only). Re-applies every managed
// HE.NET record on a schedule — the automatic twin of "Sync all". Opt-in.
async function showHenetScheduleModal() {
    const inputCls = 'w-full px-3 py-2 border border-slate-300 rounded-md text-sm focus:ring-2 focus:ring-[#01A982] focus:border-[#01A982]';
    let cfg = window._henetScheduleCfg || null;
    if (!cfg) {
        try {
            const { ok, data } = await _spokeFetch('/api/henet/sync-config');
            if (ok && data && data.config) cfg = data.config;
        } catch (e) { /* fall back to defaults */ }
    }
    cfg = cfg || { enabled: false, mode: 'interval', interval_seconds: 3600, daily_time: '02:00' };
    const intMin = Math.max(5, Math.round((parseInt(cfg.interval_seconds, 10) || 3600) / 60));
    const isDaily = cfg.mode === 'daily';
    openModal('henet-schedule-modal', `
        <h3 class="text-lg font-bold text-[#263040]">Scheduled HE.NET re-sync</h3>
        <p class="text-sm text-slate-500">Automatically re-apply every managed HE.NET record at Hurricane Electric (via the account-login web panel) on a schedule — the hands-off twin of <b>Sync all</b>. Records are written per tenant using each tenant's assigned credential. Off by default.</p>
        <label class="flex items-center gap-2 text-sm font-medium text-slate-700">
          <input type="checkbox" id="henet-sched-enabled" ${cfg.enabled ? 'checked' : ''} class="rounded border-slate-300 text-[#01A982] focus:ring-[#01A982]" title="Enable or disable scheduled auto-sync">
          Enable scheduled auto-sync
        </label>
        <div class="space-y-1">
          <label class="text-xs text-slate-500 font-bold uppercase">Schedule</label>
          <select id="henet-sched-mode" class="${inputCls}" title="Select sync schedule type: interval in minutes or daily at a set time">
            <option value="interval" ${isDaily ? '' : 'selected'}>Every N minutes</option>
            <option value="daily" ${isDaily ? 'selected' : ''}>Once daily at a set time</option>
          </select>
        </div>
        <div class="space-y-1" id="henet-sched-interval-wrap" style="${isDaily ? 'display:none' : ''}">
          <label class="text-xs text-slate-500 font-bold uppercase">Interval (minutes)</label>
          <input type="number" id="henet-sched-interval" min="5" value="${intMin}" class="${inputCls}" title="Minimum 5 minutes">
        </div>
        <div class="space-y-1" id="henet-sched-daily-wrap" style="${isDaily ? '' : 'display:none'}">
          <label class="text-xs text-slate-500 font-bold uppercase">Daily time (24h, HH:MM)</label>
          <input type="time" id="henet-sched-daily" value="${escapeHtml(String(cfg.daily_time || '02:00'))}" class="${inputCls}" title="Time of day (24-hour HH:MM) to run daily HE.NET synchronization">
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button onclick="_henetSaveSchedule()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="Save scheduled auto-sync settings">Save</button>
          <button onclick="document.getElementById('henet-schedule-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Cancel and close dialog">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    const modeSel = document.getElementById('henet-sched-mode');
    if (modeSel) modeSel.onchange = () => {
        const daily = modeSel.value === 'daily';
        document.getElementById('henet-sched-interval-wrap').style.display = daily ? 'none' : '';
        document.getElementById('henet-sched-daily-wrap').style.display = daily ? '' : 'none';
    };
}

async function _henetSaveSchedule() {
    const mode = document.getElementById('henet-sched-mode')?.value || 'interval';
    const payload = {
        enabled: !!document.getElementById('henet-sched-enabled')?.checked,
        mode,
    };
    if (mode === 'daily') {
        payload.daily_time = document.getElementById('henet-sched-daily')?.value || '02:00';
    } else {
        const mins = parseInt(document.getElementById('henet-sched-interval')?.value, 10);
        if (!mins || mins < 5) { showToast('Interval must be at least 5 minutes', 'error'); return; }
        payload.interval_seconds = mins * 60;
    }
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/sync-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && d.status === 'SUCCESS') {
            window._henetScheduleCfg = d.config;
            document.getElementById('henet-schedule-modal')?.remove();
            showToast(payload.enabled ? 'HE.NET auto-sync scheduled' : 'HE.NET auto-sync disabled', 'success');
            loadHenet();
        } else showToast('Error: ' + (detail || d?.message || 'Failed to save schedule'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function saveHenetRecord() {
    const modal = document.getElementById('henet-record-modal');
    const editing = modal && modal.dataset.editName;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        name: editing ? modal.dataset.editName : get('henet-r-name'),
        type: editing ? modal.dataset.editType : get('henet-r-type'),
        value: get('henet-r-value'),
        ttl: parseInt(get('henet-r-ttl')) || 300,
    };
    // Admin-only tenant assignment (the field is absent for non-admins, whom the
    // server pins to their own tenant regardless).
    const tenantSel = document.getElementById('henet-r-tenant');
    if (tenantSel) payload.tenant = tenantSel.value;
    if (!payload.name || !payload.value) { showToast('Name and Value are required', 'error'); return; }

    // Push-free tenant re-home: when editing, an admin who only changes the
    // Tenant (leaving the Value unchanged) is re-organising tabs, not editing the
    // zone — move the record's tab (metadata only) without touching HE.NET.
    if (editing && tenantSel && get('henet-r-value') === (modal.dataset.editValue || '')) {
        const origTenant = modal.dataset.editTenant || '';
        if (String(tenantSel.value) !== String(origTenant)) {
            try {
                const { ok, data: d, detail } = await _spokeFetch('/api/henet/record/tenant', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: payload.name, type: payload.type, tenant: tenantSel.value }),
                });
                if (ok && d.status === 'SUCCESS') {
                    modal.remove();
                    window._henetActiveTab = tenantSel.value;  // jump to the destination tab
                    const dest = tenantSel.value ? ((window._allTenantsName || {})[tenantSel.value] || tenantSel.value) : 'Admin';
                    showToast(`Record moved to ${dest}`, 'success');
                    loadHenet();
                } else showToast('Error: ' + (detail || d?.message || 'Move failed'), 'error');
            } catch (e) { showToast('Error: ' + e.message, 'error'); }
            return;
        }
    }

    if (!window._henetAssignedCred) { showToast('Assign an HE.NET account credential first', 'error'); return; }
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/record', {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && (d.status === 'SUCCESS' || d.status === 'PARTIAL')) {
            modal.remove();
            if (d.status === 'PARTIAL') showToast('HE.NET reported: ' + (d.errors || []).join('; '), 'error');
            else showToast('Record saved at HE.NET', 'success');
            loadHenet();
        } else showToast('Error: ' + (detail || d?.message || 'Operation failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteHenetRecord(name, type) {
    if (!await showConfirmToast(`Remove ${name} (${type}) from HE.NET management? (The zone entry at dns.he.net is left unchanged — delete it there if you want it gone.)`)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/record', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, type }),
        });
        if (ok && d.status === 'SUCCESS') loadHenet();
        else showToast('Error: ' + (detail || d?.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// Human label for the records currently in view — the scope the bulk actions
// (Deconfigure / Move all) operate on. Admin sees "Admin (shared)" for the
// global slot or the selected tenant's name; a non-admin only ever sees their
// own tenant's records, so the label is generic.
function _henetCurrentScopeLabel() {
    if (!isAdmin()) return 'this tenant';
    if (currentTenant && currentTenant !== 'default') {
        return (window._allTenantsName || {})[currentTenant] || currentTenant;
    }
    return 'Admin (shared)';
}

// Bulk "Deconfigure" — remove EVERY record currently in view from management
// (looping the same DELETE the per-row trash icon uses). The HE.NET zone at
// dns.he.net is never touched; this only drops LM's management records.
async function deconfigureHenetScope() {
    const recs = (window._henetRecords || []).slice();
    const scope = _henetCurrentScopeLabel();
    if (!recs.length) { showToast(`No HE.NET records under management for ${scope}.`, 'success'); return; }
    if (!await showConfirmToast(`Deconfigure HE.NET for ${scope}?\n\nThis removes all ${recs.length} managed record(s) from management. The zone entries at dns.he.net are left unchanged — delete them there if you want them gone.`)) return;
    let okN = 0, failN = 0;
    for (const r of recs) {
        try {
            const { ok, data: d } = await _spokeFetch('/api/henet/record', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: r.name, type: r.type }),
            });
            if (ok && d && d.status === 'SUCCESS') okN++; else failN++;
        } catch (e) { failN++; }
    }
    showToast(`Deconfigured ${scope} — removed ${okN} record(s)${failN ? `, ${failN} failed` : ''}.`, failN ? 'error' : 'success');
    loadHenet();
}

// Bulk "Move all → tenant" — re-home every record in the current view to
// another tenant (or Admin/shared) in one shot. Metadata-only, reusing the
// push-free /api/henet/record/tenant endpoint the record modal uses. Lands the
// operator on the destination tenant so they see the moved records. Admin only.
async function showHenetMoveAllModal() {
    if (!isAdmin()) { showToast('Admin only', 'error'); return; }
    const recs = (window._henetRecords || []);
    if (!recs.length) { showToast('No records in the current view to move.', 'success'); return; }
    await ensureTenants();
    const tenants = window._allTenants || [];
    const curScope = (currentTenant && currentTenant !== 'default') ? currentTenant : '';
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const opts = [`<option value=""${curScope === '' ? ' disabled' : ''}>Admin (admin-managed / shared)</option>`]
        .concat(tenants.map(t => `<option value="${escapeHtml(t.id)}"${t.id === curScope ? ' disabled' : ''}>${escapeHtml(t.name || t.id)}</option>`)).join('');
    openModal('henet-moveall-modal', `
        <h3 class="text-lg font-bold text-[#263040]">Move all records → tenant</h3>
        <p class="text-xs text-slate-500">Re-home all ${recs.length} record(s) currently shown (<span class="font-medium">${escapeHtml(_henetCurrentScopeLabel())}</span>) to another tenant. Metadata only — the HE.NET zone at dns.he.net is untouched.</p>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Destination</label><select id="henet-moveall-target" class="${inputCls}" title="Select destination tenant to re-home these records to">${opts}</select></div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="_henetMoveAll()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="Move all records in current view to selected destination tenant">Move all</button>
            <button onclick="document.getElementById('henet-moveall-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Cancel and close dialog">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
}

async function _henetMoveAll() {
    const sel = document.getElementById('henet-moveall-target');
    if (!sel) return;
    const tgt = sel.value;
    const recs = (window._henetRecords || []).slice();
    if (!recs.length) { showToast('Nothing to move.', 'success'); return; }
    let okN = 0, failN = 0;
    for (const r of recs) {
        try {
            const { ok, data: d } = await _spokeFetch('/api/henet/record/tenant', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: r.name, type: r.type, tenant: tgt }),
            });
            if (ok && d && d.status === 'SUCCESS') okN++; else failN++;
        } catch (e) { failN++; }
    }
    const destName = tgt ? ((window._allTenantsName || {})[tgt] || tgt) : 'Admin';
    document.getElementById('henet-moveall-modal')?.remove();
    showToast(`Moved ${okN} record(s) → ${destName}${failN ? `, ${failN} failed` : ''}.`, failN ? 'error' : 'success');
    window._henetActiveTab = tgt;
    // Land on the destination tenant so the operator sees the moved records.
    await viewAsTenant(tgt || 'default');
}

async function importHenet() {
    if (!window._henetAssignedCred) { showToast('Assign an HE.NET credential first', 'error'); return showHenetCredModal(); }
    if (!await showConfirmToast('Read the existing records in your HE.NET zone(s) and bring any A/AAAA records not already managed under management? (Reads the dns.he.net web panel with the assigned account login — nothing is pushed or changed at HE.)')) return;
    try {
        const scope = _henetScope();
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scope ? { tenant: scope } : {}),
        });
        if (ok && d.status === 'SUCCESS') {
            const skipped = d.skipped_types && Object.keys(d.skipped_types).length
                ? ` · skipped ${Object.entries(d.skipped_types).map(([t, n]) => `${n} ${t}`).join(', ')} (HE dyndns manages A/AAAA only)`
                : '';
            const already = d.skipped_existing ? `, ${d.skipped_existing} already managed` : '';
            showToast(`Imported ${d.imported || 0} record(s)${already}${skipped}`, 'success');
            loadHenet();
        } else showToast('Error: ' + (detail || d?.message || 'Import failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function syncHenet() {
    const records = (window._henetRecords || []).filter(r => r.type === 'A' || r.type === 'AAAA')
        .map(r => ({ name: r.name, type: r.type, value: r.value, ttl: r.ttl }));
    if (!records.length) { showToast('No A/AAAA records under management yet — use “⇩ Import existing” to pull in the records already in your HE.NET zone.', 'error'); return; }
    if (!window._henetAssignedCred) { showToast('Assign an HE.NET account credential first', 'error'); return showHenetCredModal(); }
    if (!await showConfirmToast(`Re-apply all ${records.length} managed A/AAAA record(s) at HE.NET using your account login?\n\nEach record is create/updated in the dns.he.net control panel — no per-record DDNS key needed.`)) return;
    try {
        const scope = _henetScope();
        const { ok, data: d, detail } = await _spokeFetch('/api/henet/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scope ? { records, tenant: scope } : { records }),
        });
        if (ok && (d.status === 'SUCCESS' || d.status === 'PARTIAL')) {
            const nErr = d.errors ? d.errors.length : 0;
            showToast(`Synced — ${d.pushed || 0} applied${nErr ? `, ${nErr} error(s)` : ''}`, nErr ? 'error' : 'success');
            loadHenet();
        } else showToast('Error: ' + (detail || d?.message || 'Sync failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ─── DHCP (Kea) ──────────────────────────────────────────────────────────────

async function loadDHCPData(subMenu, skipWorkerDiscovery = false) {
    const container = document.getElementById('dhcp-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    // ALL per-tab action buttons — "+ Add Reservation" (Reservations tab
    // only) — render into the trailing #top-nav-actions strip in the sub-nav
    // bar, pinned right next to the help "i" icon (see renderTopNav), rather
    // than a page-body button row. No "+ Add Server" here: a DHCP module is
    // provisioned by loading the DHCP Server (Kea) role onto a host
    // (Fleet → Load Role), not by self-service onboarding a standalone spoke.
    const navActions = document.getElementById('top-nav-actions');
    if (navActions) {
        const addResBtn = (subMenu === 'Reservations' && (isAdmin() || isTenantAdmin()))
            ? `<button id="dhcp-add-btn" onclick="showDhcpReservationModal()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm" title="Create a new static DHCP host reservation">+ Add Reservation</button>`
            : '';
        navActions.innerHTML = addResBtn;
    }

    const th = tableHead, tw = tableWrap;  // shared table helpers
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;

    try {
        if (!skipWorkerDiscovery && (typeof isAdmin === 'function') && isAdmin()) {
            window._dhcpWorkerDiscovery = window._dhcpWorkerDiscovery || fetch(
                '/api/dhcp/ha/discover' + _tenantQS(), { method: 'POST' })
                .then(async res => {
                    const data = await res.json().catch(() => ({}));
                    if (!res.ok) throw new Error(data.detail || 'DHCP worker discovery failed');
                    const configuring = (data.workers || [])
                        .filter(w => w.status === 'configuring').length;
                    const configured = (data.workers || [])
                        .filter(w => w.status === 'configured').length;
                    if (configuring) {
                        showToast(`Discovered ${configuring} DHCP Server worker(s); configuring the HA pair now.`, 'success');
                    } else if (configured) {
                        showToast('Discovered and configured the two-server DHCP HA pair.', 'success');
                    }
                    if (configuring || configured) {
                        loadDHCPData(subMenu, true);
                    }
                    return data;
                })
                .catch(err => {
                    console.warn('DHCP worker auto-discovery:', err);
                    showToast(err.message || 'DHCP worker discovery failed', 'error');
                    return null;
                })
                .finally(() => {
                    window._dhcpWorkerDiscovery = null;
                });
        }
        // ── Overview: Kea pool utilization + packet counters (OPNsense-grade) ─
        if (subMenu === 'Overview') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/stats' + _tenantQS());
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'Kea statistics unavailable'); return;
            }
            const g = d.global || {};
            const subnets = d.subnets || [];
            // Kea CA not running on this spoke → the spoke returns a SUCCESS
            // idle result (kea_running:false + note) instead of an ERROR, so
            // show a neutral info banner rather than the red "Error: Kea CA
            // unreachable …" the stats-ERROR path used to render. Empty stats
            // tiles + "No subnets configured." follow naturally below.
            const idleNote = (d.kea_running === false && d.note)
                ? `<div class="mb-4 p-3 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-500">${escapeHtml(d.note)}</div>` : '';
            const syncLine = await _ddSyncStatusLine('dhcp');
            const tiles = [
                _ddTile('Pool Utilization', `${g.utilization_pct || 0}%`, `${(g.assigned_addresses || 0).toLocaleString()} / ${(g.total_addresses || 0).toLocaleString()} addresses`,
                        (g.utilization_pct || 0) >= 90 ? 'text-red-600' : (g.utilization_pct || 0) >= 70 ? 'text-amber-600' : 'text-emerald-600'),
                _ddTile('Assigned Leases', (g.assigned_addresses || 0).toLocaleString(), `${(g.declined_addresses || 0).toLocaleString()} declined`),
                _ddTile('DISCOVER / REQUEST', `${(g.pkt4_discover || 0).toLocaleString()} / ${(g.pkt4_request || 0).toLocaleString()}`, `${(g.pkt4_received || 0).toLocaleString()} received`),
                _ddTile('OFFER / ACK / NAK', `${(g.pkt4_offer_sent || 0).toLocaleString()} / ${(g.pkt4_ack_sent || 0).toLocaleString()} / ${(g.pkt4_nak_sent || 0).toLocaleString()}`),
            ].join('');
            const subnetRows = subnets.map(s => {
                // A subnet with no NetBox-sourced CIDR/description is not a
                // real scope — most likely stale Kea state left over from a
                // prior sync (e.g. a removed prefix). Flag it instead of
                // rendering a meaningless "subnet <id>" label.
                const label = s.subnet
                    ? escapeHtml(s.subnet) + (s.description ? ` <span class="text-slate-400 font-normal">(${escapeHtml(s.description)})</span>` : '')
                    : '<span class="text-red-500 italic">Unknown scope (not in NetBox — stale?)</span>';
                return `
                <div class="py-2 border-b border-slate-100 last:border-0">
                    <div class="flex items-center justify-between mb-1">
                        <span class="font-mono text-sm font-medium text-slate-700">${label}</span>
                        <span class="text-xs text-slate-500">${(s.assigned_addresses || 0).toLocaleString()} / ${(s.total_addresses || 0).toLocaleString()}${s.declined_addresses ? ` · ${s.declined_addresses} declined` : ''}</span>
                    </div>
                    ${_ddBar(s.utilization_pct)}
                </div>`;
            }).join('');
            container.innerHTML = `
                ${idleNote}
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">${tiles}</div>
                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <div class="text-sm font-semibold text-slate-700 mb-2">Scope Utilization</div>
                    ${subnetRows || '<p class="text-slate-400 italic text-sm">No subnets configured.</p>'}
                </div>
                ${syncLine}`;
            return;
        }

        if (subMenu === 'Diagnostics') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/diagnostics' + _tenantQS());
            // Real-time DNS hook status is a separate, best-effort fetch — a
            // spoke running an older version without the route/command must
            // not blank the whole Diagnostics tab. A 200 carrying
            // status:ERROR is treated as unavailable, not as 'disabled'.
            const dnsHook = await (async () => {
                try {
                    const r = await fetch('/api/dhcp/dns-hook' + _tenantQS());
                    if (!r.ok) return null;
                    const j = await r.json();
                    if (!j || j.status === 'ERROR') return null;
                    return j;
                } catch (e) { return null; }
            })();
            window._dhcpDnsHookStatus = dnsHook;
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP diagnostics unavailable') + _dhcpDnsHookPanel(dnsHook); return; }
            const updating = !!(d.updating || (d.cluster && d.cluster.updating));
            // "Running" means answering clients. A node re-reading a freshly
            // synced config is out of sync but the pair is still serving, so
            // don't paint the whole page red for a routine NetBox sync.
            const good = !!d.healthy || (updating && !!(d.serving || (d.cluster && d.cluster.serving)));
            const units = d.units || {};
            const dhcp4 = units['kea-dhcp4-server'] || {};
            const caUnit = units['kea-ctrl-agent'] || {};
            const ca = d.ca || {};
            const cfg = d.config_test || {};
            const caCfg = d.ca_config_test || {};
            const caRecentErrors = Array.isArray(d.ca_recent_errors) ? d.ca_recent_errors : [];
            const listeners = d.listeners || {};
            const missing = Array.isArray(d.interface_missing) ? d.interface_missing : [];
            const subnets = Array.isArray(d.subnets) ? d.subnets : [];
            const recommendations = Array.isArray(d.recommendations) ? d.recommendations : [];
            const unitText = u => `${u.ActiveState || '?'} / ${u.SubState || '?'}${u.NRestarts && u.NRestarts !== '0' ? ` · ${u.NRestarts} restart(s)` : ''}`;
            const check = (label, pass, detailText, actionHtml) => _ddTile(
                label, pass ? 'PASS' : 'FAIL', detailText || '',
                pass ? 'text-emerald-600' : 'text-red-600', actionHtml);
            window._dhcpConfigTest = cfg;
            const hasCfgDetails = Boolean((cfg.output || cfg.error) && String(cfg.output || cfg.error).trim());
            const cfgSub = cfg.ok ? 'syntax valid' : (cfg.error || cfg.output ? 'syntax error' : 'syntax invalid');
            const cfgAction = hasCfgDetails ? `<button onclick="_showDhcpConfigDetailsModal()" class="text-xs text-[#01A982] hover:underline font-semibold ml-auto flex-shrink-0" title="View detailed Kea configuration test output">Details</button>` : '';
            const subnetRows = subnets.map(s => `<tr class="border-b border-slate-100">
                <td class="px-4 py-2 text-xs">${escapeHtml(String(s.id == null ? '—' : s.id))}</td>
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(s.subnet || '—')}</td>
                <td class="px-4 py-2 font-mono text-xs">${(s.pools || []).map(escapeHtml).join(', ') || '—'}</td>
            </tr>`).join('');
            // HA pair: the module drives two Kea nodes. The evidence tiles below
            // are ONE named node's (diagnostics_source); the HA panel carries
            // pair state, lease sync and config drift.
            const haCluster = d.cluster && d.cluster.enabled !== false ? d.cluster : null;
            const haPanel = _dhcpHaPanel(haCluster);
            const nodeEvidence = haCluster ? _ddMemberEvidence(d.members, 'dhcp', haCluster.updating_members) : '';
            container.innerHTML = `
                <div class="flex items-center justify-between gap-3 mb-4">
                    <div>
                        <div class="text-sm font-semibold ${updating ? 'text-sky-700' : (good ? 'text-emerald-700' : 'text-red-700')}">${updating ? (haCluster ? 'Kea HA pair updating — applying configuration' : 'Kea DHCP server updating — applying configuration') : (good ? (haCluster ? 'Kea HA pair healthy' : 'Kea DHCP server healthy') : (haCluster ? 'Kea HA pair needs attention' : 'Kea DHCP server needs attention'))}</div>
                        <div class="text-xs text-slate-400">${haCluster ? `HA pair (${escapeHtml(haCluster.mode || 'hot-standby')}); evidence below is from ${escapeHtml(d.diagnostics_source_name || d.diagnostics_source || 'no reachable node')}.` : 'Live checks mirror the Sim DHCP (Kea) diagnostics: units, config, interfaces, listeners, control agent, and leases.'}</div>
                    </div>
                    <div class="flex items-center gap-2">
                        ${serviceClusterButton('dhcp', haCluster)}
                        <button onclick="loadDHCPData('Diagnostics')" title="Run DHCP diagnostics again" class="px-3 py-1.5 rounded-md text-xs font-bold bg-white border border-slate-300 hover:bg-slate-50">Run again</button>
                    </div>
                </div>
                ${haPanel}
                ${nodeEvidence}
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
                    ${check('DHCP4 Service', dhcp4.ActiveState === 'active', unitText(dhcp4))}
                    ${check('Control Agent', caUnit.ActiveState === 'active' && !!ca.reachable, ca.error || (caCfg.ok === false ? `config error: ${(caCfg.error || caCfg.output || '').slice(0, 120)}` : unitText(caUnit)))}
                    ${check('Configuration', !!cfg.ok, cfgSub, cfgAction)}
                    ${check('UDP/67 Listener', (listeners.dhcp4 || []).length > 0, (listeners.dhcp4 || []).length ? `${listeners.dhcp4.length} listener(s)` : (listeners.error || 'not listening'))}
                </div>
                ${recommendations.length ? `<div class="mb-4 p-4 rounded-lg bg-amber-50 border border-amber-200">
                    <div class="text-sm font-semibold text-amber-800 mb-2">Recommended checks</div>
                    <ul class="list-disc pl-5 space-y-1 text-xs text-amber-800">${recommendations.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>
                </div>` : ''}
                <div class="grid lg:grid-cols-2 gap-4 mb-4">
                    <div class="bg-white border border-slate-200 rounded-lg p-4">
                        <div class="text-sm font-semibold text-slate-700 mb-2">Interfaces</div>
                        <div class="font-mono text-xs text-slate-600">${(d.interfaces_configured || []).map(i => `${escapeHtml(i)}${missing.includes(i) ? ' (missing)' : ''}`).join('<br>') || 'none configured'}</div>
                        <div class="text-sm font-semibold text-slate-700 mt-4 mb-2">Lease database</div>
                        <div class="font-mono text-xs text-slate-600">${escapeHtml((d.lease_db || {}).path || 'not reported')}</div>
                        <div class="text-xs text-slate-500">${(d.lease_db || {}).exists ? 'present' : 'missing'} · ${((d.lease_db || {}).leases == null) ? 'lease count unavailable' : `${d.lease_db.leases} active lease(s)`}</div>
                    </div>
                    <div class="bg-white border border-slate-200 rounded-lg p-4">
                        <div class="text-sm font-semibold text-slate-700 mb-2">Listeners</div>
                        <pre class="text-[11px] whitespace-pre-wrap break-all text-slate-600">${escapeHtml([...(listeners.dhcp4 || []), ...(listeners.control_agent || [])].join('\n') || listeners.error || 'none')}</pre>
                    </div>
                    ${(caUnit.ActiveState !== 'active') ? `<div class="bg-white border border-slate-200 rounded-lg p-4">
                        <div class="text-sm font-semibold text-slate-700 mb-2">Control Agent log</div>
                        <div class="text-xs text-slate-500 mb-1">${caCfg.ok === false ? `kea-ctrl-agent.conf syntax check: <span class="text-red-600">FAIL</span>` : caCfg.ok === true ? `kea-ctrl-agent.conf syntax check: <span class="text-emerald-600">OK</span>` : 'kea-ctrl-agent.conf syntax check unavailable'}</div>
                        <pre class="text-[11px] whitespace-pre-wrap break-all text-slate-600">${escapeHtml(caRecentErrors.join('\n') || caCfg.error || caCfg.output || 'no recent log entries')}</pre>
                    </div>` : ''}
                </div>
                <div class="bg-white border border-slate-200 rounded-lg overflow-hidden mb-4">
                    <div class="px-4 py-3 text-sm font-semibold text-slate-700 border-b border-slate-200">Configured scopes</div>
                    ${subnetRows ? tw(th(['ID', 'Subnet', 'Pools']) + `<tbody>${subnetRows}</tbody>`) : '<p class="p-4 text-slate-400 italic text-sm">No subnets reported.</p>'}
                </div>
                ${(d.last_errors || []).length ? `<div class="bg-white border border-slate-200 rounded-lg p-4">
                    <div class="text-sm font-semibold text-slate-700 mb-2">Recent service warnings/errors</div>
                    <pre class="text-[11px] whitespace-pre-wrap break-all text-slate-600">${escapeHtml(d.last_errors.join('\n'))}</pre>
                </div>` : ''}
                ${_dhcpPacketTracePanel()}
                ${_dhcpDnsHookPanel(dnsHook)}`;
            return;
        }

        if (subMenu === 'Subnets') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/subnets?tenant=' + encodeURIComponent(currentTenant));
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); return; }
            const subnets = d.subnets || [];
            // Admin combined view (2+ dhcp spokes): tagged _tenant by the merge
            // fanout — see net_services.py's _dhcp_merge_fanout.
            const showTenantCol = subnets.some(s => s && s._tenant);
            const cols = (showTenantCol ? ['Tenant'] : []).concat(['Subnet', 'Pools']);
            const rows = subnets.map(s => {
                const pools = (s.pools || []).map(p => p.pool || p).join(', ');
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    ${showTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${escapeHtml(s._tenant || '—')}</td>` : ''}
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(s.subnet)}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(pools || '—')}</td>
                </tr>`;
            }).join('');
            container.innerHTML = _spokeCachedBadge(d) + _dhcpDegradedBanner(d) + (subnets.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No subnets configured.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`));

        } else if (subMenu === 'Leases') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/leases?tenant=' + encodeURIComponent(currentTenant));
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); return; }
            const leases = d.leases || [];
            window._dhcpLeases = leases;
            const showTenantCol = leases.some(l => l && l._tenant);
            const cols = (showTenantCol ? ['Tenant'] : []).concat(['IP Address', 'MAC', 'Hostname', 'State', 'Valid Until', '']);
            const rows = leases.map(l => {
                const ip = l['ip-address'] || l.ip || '';
                const mac = l['hw-address'] || l.mac || '';
                const host = l.hostname || '';
                const eIp = escJsAttr(ip);
                const eSpoke = escJsAttr(l._spoke || '');
                const rawState = l.state !== undefined ? l.state : l['state'];
                let stateLabel = 'Active';
                let stateBadge = 'bg-emerald-50 text-emerald-700 border-emerald-200';
                if (rawState === 1 || rawState === '1' || rawState === 'declined') {
                    stateLabel = 'Declined';
                    stateBadge = 'bg-rose-50 text-rose-700 border-rose-200';
                } else if (rawState === 2 || rawState === '2' || rawState === 'expired') {
                    stateLabel = 'Expired';
                    stateBadge = 'bg-amber-50 text-amber-700 border-amber-200';
                }
                let validUntil = '—';
                const cltt = Number(l.cltt || l['cltt']);
                const validLft = Number(l['valid-lft'] || l.valid_lft || l['valid_lft']);
                const exp = Number(l.expire || l.expires || l['expire-time'] || l['expire_time']);
                if (exp && !isNaN(exp)) {
                    const d = new Date(exp > 1e11 ? exp : exp * 1000);
                    if (!isNaN(d.getTime())) validUntil = d.toLocaleString();
                } else if (cltt && !isNaN(cltt) && validLft && !isNaN(validLft)) {
                    const d = new Date((cltt + validLft) * 1000);
                    if (!isNaN(d.getTime())) validUntil = d.toLocaleString();
                } else if (l['valid-until'] || l['valid_until'] || l.validUntil) {
                    const d = new Date(l['valid-until'] || l['valid_until'] || l.validUntil);
                    if (!isNaN(d.getTime())) validUntil = d.toLocaleString();
                } else if (l['valid-lft'] !== undefined && l['valid-lft'] !== null && String(l['valid-lft']).trim() !== '') {
                    validUntil = String(l['valid-lft']);
                }
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    ${showTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${escapeHtml(l._tenant || '—')}</td>` : ''}
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(ip || '—')}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(mac || '—')}</td>
                    <td class="px-4 py-2 text-xs">${escapeHtml(host || '—')}</td>
                    <td class="px-4 py-2 text-xs"><span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${stateBadge}">${escapeHtml(stateLabel)}</span></td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(validUntil)}</td>
                    <td class="px-4 py-2 whitespace-nowrap text-right">
                        ${ip && mac ? `<button onclick="convertLeaseToReservation('${eIp}', '${eSpoke}')" title="Convert to static reservation" class="text-xs bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-2.5 py-1 rounded transition-colors font-medium">Reserve</button>` : ''}
                        ${ip ? `<button onclick="deleteDhcpLease('${eIp}', '${eSpoke}')" title="Delete lease" class="p-1 text-slate-300 hover:text-red-500 transition-colors ml-1">${delIcon}</button>` : ''}
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = _spokeCachedBadge(d) + _dhcpDegradedBanner(d) + (leases.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No active leases.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`));

        } else if (subMenu === 'Reservations') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/reservations?tenant=' + encodeURIComponent(currentTenant));
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); _clearTopNavActions(); return; }
            const res = d.reservations || [];
            window._dhcpReservations = res;
            const showTenantCol = res.some(r => r && r._tenant);
            const cols = (showTenantCol ? ['Tenant'] : []).concat(['IP Address', 'MAC', 'Hostname', 'Subnet', '']);
            const rows = res.map(r => {
                const eIp = escJsAttr(r.ip);
                const eSpoke = escJsAttr(r._spoke || '');
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    ${showTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${escapeHtml(r._tenant || '—')}</td>` : ''}
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(r.ip)}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.mac)}</td>
                    <td class="px-4 py-2 text-xs">${escapeHtml(r.hostname || '—')}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.subnet || '—')}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="editDhcpReservation('${eIp}', '${eSpoke}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="deleteDhcpReservation('${eIp}', '${eSpoke}')" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = _spokeCachedBadge(d) + _dhcpDegradedBanner(d) + (res.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No static reservations configured.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`));
        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

async function _loadDhcpSubnetOptions(selId, preferredSubnetId, spoke, preferredIp) {
    const sel = document.getElementById(selId);
    if (!sel) return;
    sel.innerHTML = '<option value="">Loading…</option>';
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/subnets?tenant=' + encodeURIComponent(currentTenant));
        let subnets = ok ? (d.subnets || []) : [];
        // In the admin combined view the list spans every dhcp spoke. Offering
        // another cluster's scopes here would let the reservation be filed
        // against a subnet the target Kea does not have.
        if (spoke && subnets.some(s => s && s._spoke)) {
            subnets = subnets.filter(s => s._spoke === spoke);
        }
        sel.innerHTML = subnets.length
            ? subnets.map(s => {
                const desc = s.description || (s['user-context'] && s['user-context'].description) || (s.user_context && s.user_context.description) || '';
                const label = desc ? `${s.subnet} (${desc})` : s.subnet;
                // data-spoke lets the save path route an Add (which has no
                // originating row) to the Kea that owns the chosen scope.
                return `<option value="${escapeHtml(String(s.id))}" data-spoke="${escapeHtml(String(s._spoke || ''))}">${escapeHtml(label)}</option>`;
            }).join('')
            : `<option value="">${ok ? 'No subnets configured' : (detail || 'Could not load subnets')}</option>`;
        if (subnets.length) {
            const byIp = preferredIp
                ? subnets.find(s => s.subnet && _isIPInCIDR(preferredIp, s.subnet))
                : null;
            if (preferredSubnetId != null && subnets.some(s => String(s.id) === String(preferredSubnetId))) {
                sel.value = String(preferredSubnetId);
            } else if (byIp) {
                // No usable subnet-id (an IPAM row has none, and a lease's can
                // miss after a Kea reconfigure) — fall back to the scope that
                // actually contains the address rather than silently leaving
                // whichever option happens to sort first selected, which files
                // the reservation against the wrong scope.
                sel.value = String(byIp.id);
            } else if (subnets.length === 1) {
                sel.value = String(subnets[0].id);
            }
        }
    } catch (err) {
        console.error('_loadDhcpSubnetOptions: could not load subnets', err);
        sel.innerHTML = '<option value="">Could not load subnets</option>';
    }
}

function convertLeaseToReservation(ip, spoke) {
    const leases = window._dhcpLeases || [];
    const match = l => (l['ip-address'] || l.ip) === ip && (!spoke || l._spoke === spoke);
    const item = leases.find(match);
    if (!item) { showToast('Lease data not found — refresh and try again', 'error'); return; }
    showDhcpReservationModal({
        ip: item['ip-address'] || item.ip || '',
        mac: item['hw-address'] || item.mac || '',
        hostname: item.hostname || '',
        subnet_id: item['subnet-id'] ?? item.subnet_id ?? null,
        _spoke: item._spoke || '',
    }, true);
}

function editDhcpReservation(ip, spoke) {
    const item = (window._dhcpReservations || []).find(
        r => r.ip === ip && (!spoke || r._spoke === spoke));
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showDhcpReservationModal(item);
}

// IPAM → DHCP: create a Kea reservation straight from a NetBox IP record.
// The address is already allocated in NetBox, but that alone does not pin the
// client to it — only a DHCP reservation does. A reservation matches on MAC,
// which lives in the IP record's mac_address custom field (written by the
// discovery sync), so this refuses rather than opening a modal that cannot be
// submitted. Opens the shared modal in prefill mode: a plain Add with the
// fields filled in, NOT an edit of an existing reservation and not a lease
// conversion (there may be no lease to purge).
function reserveNetboxIP(id) {
    const item = (window._nbIPs || []).find(r => String(r.id) === String(id));
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    const mac = (item.custom_fields || {}).mac_address || '';
    if (!mac) {
        showToast('This IP has no MAC on its NetBox record — a DHCP reservation needs one to match the client', 'error');
        return;
    }
    showDhcpReservationModal({
        // NetBox stores the address as CIDR; Kea wants the bare host address.
        ip: String(item.address || '').split('/')[0],
        mac,
        hostname: item.dns_name || '',
    }, false, true);
}

function showDhcpReservationModal(editItem, isConvert = false, prefillOnly = false) {
    // prefillOnly = an ADD with the fields pre-populated from another module's
    // row (IPAM). Without it, passing an editItem implies "edit this existing
    // reservation" and the save would PUT against a reservation that does not
    // exist yet.
    const editing = !isConvert && !prefillOnly && !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const title = editing ? 'Edit DHCP Reservation' : (isConvert ? 'Convert Lease to Reservation' : 'Add DHCP Reservation');
    const btnText = editing ? 'Save Changes' : 'Add Reservation';
    const modal = openModal('dhcp-res-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${title}</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Subnet</label><select id="dhcp-res-subnet" class="${inputCls}" title="Select target DHCP subnet scope"><option value="">Loading…</option></select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">IP Address</label><input id="dhcp-res-ip" value="${val(editItem?.ip)}" class="${inputCls}" placeholder="10.0.0.50" title="Static IP address to assign"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">MAC Address</label><input id="dhcp-res-mac" value="${val(editItem?.mac)}" class="${inputCls}" placeholder="aa:bb:cc:dd:ee:ff" title="Client hardware MAC address (e.g. aa:bb:cc:dd:ee:ff)"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Hostname (optional)</label><input id="dhcp-res-host" value="${val(editItem?.hostname)}" class="${inputCls}" placeholder="printer-01" title="Optional client hostname"></div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="saveDhcpReservation()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold" title="${btnText}">${btnText}</button>
            <button onclick="document.getElementById('dhcp-res-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm" title="Cancel and close dialog">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    if (editing) modal.dataset.editIp = editItem.ip;
    if (isConvert && editItem?.ip) modal.dataset.oldLeaseIp = editItem.ip;
    // Which dhcp spoke this row came from (admin combined view tags rows with
    // _spoke). Every dhcp spoke is a separate Kea, so the write has to go back
    // to the same one or it lands in the wrong cluster.
    if (editItem?._spoke) modal.dataset.spokeId = editItem._spoke;
    _loadDhcpSubnetOptions('dhcp-res-subnet', editItem?.subnet_id, editItem?._spoke, editItem?.ip);
}

async function saveDhcpReservation() {
    const modal = document.getElementById('dhcp-res-modal');
    const editing = modal && modal.dataset.editIp;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        subnet_id: get('dhcp-res-subnet'),
        ip: get('dhcp-res-ip'),
        mac: get('dhcp-res-mac'),
        hostname: get('dhcp-res-host'),
    };
    if (!payload.subnet_id || !payload.ip || !payload.mac) {
        showToast('Subnet, IP, and MAC are required', 'error');
        return;
    }
    if (editing) payload.old_ip = modal.dataset.editIp;
    else if (modal.dataset.oldLeaseIp) payload.old_ip = modal.dataset.oldLeaseIp;
    if (modal.dataset.spokeId) payload.spoke_id = modal.dataset.spokeId;
    else {
        // Plain "Add Reservation": no originating row, so take the owning spoke
        // from the selected scope (admin combined view tags subnets too).
        const opt = document.getElementById('dhcp-res-subnet')?.selectedOptions?.[0];
        if (opt?.dataset?.spoke) payload.spoke_id = opt.dataset.spoke;
    }
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/reservation' + _taTenantQuery(), {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && d.status === 'SUCCESS') {
            modal.remove();
            loadDHCPData('Reservations');
            const w = _reservationWritebackWarning(d);
            if (w) showToast(w, 'error');
        }
        else if (ok && d.status === 'PARTIAL') {
            // The reservation applied but the old lease survived, so the client
            // stays on its current address. Close and refresh (the reservation
            // IS live) but say so rather than reporting a clean success.
            modal.remove();
            loadDHCPData('Reservations');
            showToast(d.message || 'Reservation saved, but the previous lease could not be removed', 'error');
        }
        else showToast('Error: ' + (detail || d?.message || 'Operation failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// A reservation lives in Kea, but core.dns_dhcp_sync rebuilds Kea's entire
// subnet4 from NetBox alone and config-sets it — so a reservation whose MAC
// never landed on a NetBox IP object is deleted by the next sync, minutes
// later and silently. The hub now creates that IP object when NetBox is
// missing it (status 'created'), so this warning is left for the cases it
// genuinely cannot fix: no containing prefix, no ipam spoke, or a NetBox
// error. The API reports that outcome in netbox_writeback
// (see _with_writeback in core/src/routes/net_services.py); surface it instead
// of showing a clean success the operator has no way to act on.
// `removing` flips the message for the delete path, where a write-back that
// failed to CLEAR the MAC means the next sync recreates what was just deleted.
function _reservationWritebackWarning(d, removing) {
    const w = d && d.netbox_writeback;
    // 'created' = NetBox had no IP object, so the hub minted one carrying the
    // MAC; the reservation is durable and there is nothing to warn about.
    if (!w || w.status === 'ok' || w.status === 'unchanged'
        || w.status === 'created') return '';
    const ip = w.ip || 'this address';
    const why = w.status === 'not_found'
        ? `NetBox has no IP object for ${ip}`
        : (w.reason || w.error || 'the NetBox write-back failed');
    return removing
        ? `Removed from Kea, but ${why} — the next NetBox sync may restore this reservation.`
        : `Saved to Kea, but ${why} — the next NetBox sync will drop this reservation.`;
}

async function deleteDhcpLease(ip, spoke) {
    if (!await showConfirmToast(`Delete active lease for ${ip}?`)) return;
    try {
        const body = { ip };
        if (spoke) body.spoke_id = spoke;
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/lease' + _taTenantQuery(), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (ok && d.status === 'SUCCESS') {
            showToast(`Lease for ${ip} deleted`, 'success');
            loadDHCPData('Leases');
        } else {
            showToast('Error: ' + (detail || d?.message || 'Delete lease failed'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteDhcpReservation(ip, spoke) {
    if (!await showConfirmToast(`Delete reservation for ${ip}?`)) return;
    try {
        const body = { ip };
        if (spoke) body.spoke_id = spoke;
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/reservation' + _taTenantQuery(), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (ok && d.status === 'SUCCESS') {
            loadDHCPData('Reservations');
            const w = _reservationWritebackWarning(d, true);
            if (w) showToast(w, 'error');
        }
        else showToast('Error: ' + (detail || d?.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}
