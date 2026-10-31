// sync-sources.js — Learned values and the sync sources (endpoint, VM, firewall discovery, console NetBox, USB).
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// Global Learned Values (Global Admin only) — now the "Learned Values" tab of
// the Setup → Simulations tile (panel #simtab-glv; markup lives in
// _renderSetupSimulationsTile, loaded lazily by _simSetupTab('glv')). A learning
// tenant's lab rows produce stable learned_op values; the Admin selects one per
// alert and Publishes it here so every other tenant's learning-OFF consumer rows
// seed/lift from it (applied_op = max(own, global)). Endpoints in
// simulations/routes.py: GET /sim/api/superadmin/learned-values/candidates,
// GET/PUT .../global-learned-values.
let _glvCandidates = [];
let _glvPublished = {};
let _glvPending = {};

// seconds → compact "Xs" / "Ym" / "Zh Ym" (time_to_stable_s human formatter).
function _glvDurHuman(s) {
    s = Math.max(0, Math.round(Number(s) || 0));
    if (s < 60) return `${s}s`;
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
    return `${m}m`;
}

async function loadGlobalLearnedValues() {
    try {
        const [candRes, pubRes] = await Promise.all([
            setupFetch('/sim/api/superadmin/learned-values/candidates'),
            setupFetch('/sim/api/superadmin/global-learned-values'),
        ]);
        const cand = await candRes.json().catch(() => ({}));
        const pub = await pubRes.json().catch(() => ({}));
        _glvCandidates = Array.isArray(cand.candidates) ? cand.candidates : [];
        _glvPublished = (pub && typeof pub.published === 'object' && pub.published) || {};
        renderGlvPublished();
        renderGlvCandidates();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Load failed: ' + e.message, 'error');
    }
    // Pending known-good proposals (best-effort; older backends lack this route).
    try {
        const pend = await apiJson('/sim/api/superadmin/global-learned-pending');
        _glvPending = (pend && typeof pend.pending === 'object' && pend.pending) || {};
    } catch (e) {
        _glvPending = {};
    }
    renderGlvPending();
}

function renderGlvPending() {
    const el = document.getElementById('glv-pending');
    if (!el) return;
    const keys = Object.keys(_glvPending || {}).sort();
    if (!keys.length) {
        el.innerHTML = '<p class="text-xs text-slate-400 italic">No pending known-good proposals.</p>';
        return;
    }
    el.innerHTML = keys.map(k => {
        const v = _glvPending[k] || {};
        const knobs = (v.knobs && typeof v.knobs === 'object') ? v.knobs : {};
        const knobStr = Object.keys(knobs).length
            ? Object.entries(knobs).map(([kk, vv]) => `${escapeHtml(kk)} ${escapeHtml(String(vv))}`).join(', ')
            : 'no knob changes';
        const when = v.proposed_at ? new Date(Number(v.proposed_at) * 1000).toLocaleString() : '';
        return `<div class="flex flex-wrap items-center gap-3 text-xs py-1.5 border-b border-slate-100 last:border-0"${when ? ` title="proposed ${escapeHtml(when)}"` : ''}>
            <span class="font-mono text-slate-700 font-semibold min-w-[12rem]">${escapeHtml(k)}</span>
            ${v.source_tenant ? `<span class="text-slate-400">from ${escapeHtml(v.source_tenant)}</span>` : ''}
            <span class="text-slate-600">${escapeHtml(String(v.count ?? '—'))} clients</span>
            <span class="text-slate-400">stable in ${escapeHtml(_glvDurHuman(v.time_to_stable_s))}</span>
            ${v.floor != null ? `<span class="text-slate-400">floor ${escapeHtml(String(v.floor))}</span>` : ''}
            <span class="text-slate-400">knobs: ${knobStr}</span>
            <div class="ml-auto flex gap-2">
              <button onclick="approveGlvPending('${escJsAttr(k)}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold">Approve</button>
              <button onclick="rejectGlvPending('${escJsAttr(k)}')" class="bg-red-50 hover:bg-red-100 text-red-700 border border-red-300 px-3 py-1 rounded-md text-xs font-bold">Reject</button>
            </div>
        </div>`;
    }).join('');
}

async function approveGlvPending(alertKey) {
    try {
        const data = await apiJson('/sim/api/superadmin/global-learned-pending/approve', {
            method: 'POST', body: JSON.stringify({ alert_key: alertKey }),
        });
        const n = Array.isArray(data && data.approved) ? data.approved.length : 1;
        if (typeof showToast === 'function') showToast(`Approved ${n} known-good value(s) — published platform-wide`, 'success');
        loadGlobalLearnedValues();  // refresh pending + published (approve moves it over)
    } catch (e) {
        if (typeof showToast === 'function') showToast('Approve failed: ' + e.message, 'error');
    }
}

async function rejectGlvPending(alertKey) {
    if (typeof confirm === 'function' &&
        !confirm(`Reject the pending known-good proposal for ${alertKey}?`)) return;
    try {
        await apiJson('/sim/api/superadmin/global-learned-pending/reject', {
            method: 'POST', body: JSON.stringify({ alert_key: alertKey }),
        });
        if (typeof showToast === 'function') showToast(`Rejected ${alertKey}`, 'success');
        loadGlobalLearnedValues();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Reject failed: ' + e.message, 'error');
    }
}

function renderGlvPublished() {
    const el = document.getElementById('glv-published');
    if (!el) return;
    const keys = Object.keys(_glvPublished).sort();
    if (!keys.length) {
        el.innerHTML = '<p class="text-xs text-slate-400 italic">Nothing published yet. Publish a candidate below.</p>';
        return;
    }
    el.innerHTML = keys.map(k => {
        const v = _glvPublished[k] || {};
        const when = v.published_at ? new Date(Number(v.published_at) * 1000).toLocaleString() : '';
        return `<div class="flex flex-wrap items-center gap-3 text-xs py-1 border-b border-slate-100 last:border-0">
            <span class="font-mono text-slate-700 flex-1 min-w-[12rem]">${escapeHtml(k)}</span>
            <span class="font-semibold text-emerald-700">op ${escapeHtml(String(v.op))}</span>
            ${v.floor != null ? `<span class="text-slate-400">floor ${escapeHtml(String(v.floor))}</span>` : ''}
            ${v.source_tenant ? `<span class="text-slate-400">from ${escapeHtml(v.source_tenant)}</span>` : ''}
            ${when ? `<span class="text-slate-400">${escapeHtml(when)}</span>` : ''}
            <button onclick="unpublishGlv('${escJsAttr(k)}')" class="text-xs text-red-600 hover:text-red-800 font-bold">Unpublish</button>
        </div>`;
    }).join('');
}

function renderGlvCandidates() {
    const el = document.getElementById('glv-candidates');
    if (!el) return;
    if (!_glvCandidates.length) {
        el.innerHTML = '<p class="text-xs text-slate-400 italic">No stable learned values yet. Mark a quota row as a Learning lab (Config → Engine) and let it settle (phase = stable).</p>';
        return;
    }
    // Group by alert_key; within a group, highest op first.
    const groups = {};
    for (const c of _glvCandidates) {
        (groups[c.alert_key] = groups[c.alert_key] || []).push(c);
    }
    const alertKeys = Object.keys(groups).sort();
    el.innerHTML = alertKeys.map(ak => {
        const rows = groups[ak].sort((a, b) => b.op - a.op);
        const pub = _glvPublished[ak];
        const isPublished = pub && rows[0] && pub.op === rows[0].op && pub.source_tenant === rows[0].source_tenant;
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center gap-2 mb-2">
                <span class="font-mono text-xs text-slate-700 font-semibold">${escapeHtml(ak)}</span>
                ${pub ? `<span class="text-[10px] uppercase tracking-wider text-emerald-700">published op ${escapeHtml(String(pub.op))}</span>` : ''}
            </div>
            <div class="space-y-1">
                ${rows.map(r => `<div class="flex flex-wrap items-center gap-3 text-xs py-0.5">
                    <span class="text-slate-600">op <b>${escapeHtml(String(r.op))}</b></span>
                    ${r.floor != null ? `<span class="text-slate-400">floor ${escapeHtml(String(r.floor))}</span>` : ''}
                    <span class="text-slate-400">${escapeHtml(r.source_tenant)} · ${escapeHtml(r.site || 'all sites')}</span>
                    <button onclick="publishGlv('${escJsAttr(ak)}', ${Number(r.op)||0}, ${r.floor!=null?Number(r.floor):'null'}, '${escJsAttr(r.source_tenant)}')" class="ml-auto ${isPublished && r === rows[0] ? 'bg-emerald-100 text-emerald-700 border border-emerald-300' : 'bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982]'} px-3 py-1 rounded-md text-xs font-bold">${isPublished && r === rows[0] ? 'Published' : 'Publish'}</button>
                </div>`).join('')}
            </div>
        </div>`;
    }).join('');
}

async function publishGlv(alertKey, op, floor, sourceTenant) {
    const next = { ..._glvPublished };
    next[alertKey] = { op, floor: floor != null ? floor : null, source_tenant: sourceTenant, published_at: Date.now() / 1000 };
    try {
        const data = await apiJson('/sim/api/superadmin/global-learned-values', {
            method: 'PUT', body: JSON.stringify({ values: next }),
        });
        _glvPublished = data.values || next;
        if (typeof showToast === 'function') showToast(`Published op ${op} for ${alertKey} (pushed to ${data.pushed_to_spokes ?? 0} spokes)`, 'success');
        renderGlvPublished();
        renderGlvCandidates();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Publish failed: ' + e.message, 'error');
    }
}

async function unpublishGlv(alertKey) {
    const next = { ..._glvPublished };
    delete next[alertKey];
    try {
        const data = await apiJson('/sim/api/superadmin/global-learned-values', {
            method: 'PUT', body: JSON.stringify({ values: next }),
        });
        _glvPublished = data.values || next;
        if (typeof showToast === 'function') showToast(`Unpublished ${alertKey}`, 'success');
        renderGlvPublished();
        renderGlvCandidates();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Unpublish failed: ' + e.message, 'error');
    }
}

// _renderSetupSection — dispatches to one of the _renderSetup*Tile helpers
// above based on the Setup submenu. Each tile renders its cards into `content`
// and triggers the matching load* fetch(es). Shared card/input/button class
// strings live in _SETUP_CLS so every tile uses identical styling. Endpoints
// cross-ref core/src/api.py (get_pending_spokes, get_tenants, get_users,
// get_firewalls, get_instances, get_endpoint_sync_*, get_vm_sync_*, get_generic_agents,
// get_setup_config, get_cache_config, get_appearance) and the Simulations
// sub-module under /sim/api/* (core/src/simulations/routes.py).
function _renderSetupSection(subMenu, container) {
    const content = container || document.getElementById('setup-content');
    if (!content) return;
    const tile = SETUP_TILES[subMenu] || _renderSetupGeneralTile;
    tile(content);
}

// ── Setup → Simulations admin overview ────────────────────────────────────
// Module subnet-filter toggles + global/per-tenant USB management. Admin-only
// (the submenu is hidden for non-admins and the backend 403s non-admins).
const _SUBNET_FILTER_MODULES = [
    { key: 'nac',       label: 'NAC' },
    { key: 'firewall',   label: 'Firewall' },
    { key: 'nw',         label: 'Network Devices' },
    { key: 'netbox',     label: 'IPAM' },
    { key: 'dns',        label: 'DNS' },
    { key: 'dhcp',       label: 'DHCP' },
    { key: 'hypervisor', label: 'Hypervisor' },
    { key: 'cs',         label: 'Simulations (tenant-ID scoped)' },
    { key: 'le',         label: 'Certificates (SAN → DNS → IP)' },
    { key: 'console',    label: 'Console (shared-tenant device IP)' },
];
let _subnetFilterState = {};

function _vpValid(v) { return /^[0-9a-f]{4}:[0-9a-f]{4}$/.test(String(v || '').trim().toLowerCase()); }

async function loadSimAdminOverview() {
    loadUsbOverview();
    loadDiscoveredUsb();
    loadDhcpServerStatus();
}

async function loadDhcpServerStatus() {
    const wrap = document.getElementById('cs-dhcp-server-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/sim/api/superadmin/dhcp-status', { credentials: 'same-origin' });
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    // Flatten tenant → spoke rows (each row carries its cached Kea status block).
    const rows = [];
    for (const t of (data.tenants || [])) {
        for (const sp of (t.spokes || [])) {
            rows.push({ tenant: t.tenant_name || t.tenant_id, spoke: sp });
        }
    }
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No cs spokes reporting.</p>';
        return;
    }
    wrap.innerHTML = rows.map(({ tenant, spoke }) => {
        const d = spoke.dhcp || {};
        const head = `<span class="text-sm font-bold text-slate-700">${esc(tenant)} <span class="text-xs font-mono text-slate-400">${esc(spoke.spoke_id)}</span></span>`;
        // Kea not installed → "Not configured" (ignore, per requirement).
        if (d.installed === false) {
            return `<div class="border border-slate-200 rounded-md p-3">
                <div class="flex items-center justify-between mb-1">${head}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-500">Not configured</span>
                </div><p class="text-xs text-slate-400">Kea (kea-dhcp4-sim) not installed on this spoke.</p></div>`;
        }
        // No dhcp block → spoke offline / hasn't reported.
        if (d.installed !== true) {
            return `<div class="border border-slate-200 rounded-md p-3">
                <div class="flex items-center justify-between mb-1">${head}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-400">No data</span>
                </div><p class="text-xs text-slate-400">No DHCP telemetry from this spoke (offline or not reporting).</p></div>`;
        }
        // installed === true → running pill + utilization bar.
        const running = !!d.running;
        const pill = running
            ? '<span class="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700">● Running</span>'
            : '<span class="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">● Not running</span>';
        // leases_used null = the spoke couldn't read the Kea lease file; show
        // "unknown" rather than an empty pool.
        const unknown = d.leases_used === null;
        const pct = Math.max(0, Math.min(100, Number(d.utilization_pct) || 0));
        const barColor = unknown ? 'bg-slate-300' : pct > 85 ? 'bg-red-500' : pct > 60 ? 'bg-amber-400' : 'bg-green-500';
        const used = Number(d.leases_used) || 0;
        const size = Number(d.pool_size) || 0;
        const leaseText = unknown
            ? `<span title="The spoke could not read the Kea lease file">leases unknown / ${size}</span>`
            : `leases ${used} / ${size} (${pct.toFixed(1)}%)`;
        const iface = d.iface ? `iface <span class="font-mono">${esc(d.iface)}</span>` : 'iface <span class="text-slate-400">—</span>';
        const subnet = d.subnet ? ` · <span class="font-mono">${esc(d.subnet)}</span>` : '';
        const pool = (d.pool_start && d.pool_end)
            ? `pool <span class="font-mono">${esc(d.pool_start)}–${esc(d.pool_end)}</span> (${size})`
            : (size ? `pool size ${size}` : 'pool <span class="text-slate-400">—</span>');
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-2">${head}${pill}</div>
            <p class="text-xs text-slate-500 mb-2">${iface}${subnet} · ${pool}</p>
            <div class="flex items-center gap-2">
                <div class="flex-1 bg-slate-200 rounded-full h-2 overflow-hidden">
                    <div class="${barColor} h-2 rounded-full" style="width:${pct}%"></div>
                </div>
                <span class="text-xs font-mono text-slate-600 whitespace-nowrap">${leaseText}</span>
            </div></div>`;
    }).join('');
}

// ── IPAM → NAC endpoint sync (System → Sync) ───────────────────────
async function loadEndpointSyncSources() {
    // Populate the IPAM source dropdown from the hub's IPAM_SOURCES registry
    // (data-driven: a new product added on the hub appears here with no UI
    // change) and mark each source's connected state.
    const sel = document.getElementById('ep-sync-source');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/endpoint-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
    } catch (e) { console.error('loadEndpointSyncSources failed', e); }
}

async function loadEndpointSyncConfig() {
    // Populate the enable/source/mode/interval/time inputs from global_config.
    // (loadSetupConfig runs once at setup init, before this card exists, so
    // we fetch fresh when the Sync card renders.)
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const epSync = (data.global_config || {}).netbox_cppm_sync || {};
        const epChk = document.getElementById('ep-sync-enabled');
        const epSrc = document.getElementById('ep-sync-source');
        const epMode = document.getElementById('ep-sync-mode');
        const epInt = document.getElementById('ep-sync-interval');
        const epTime = document.getElementById('ep-sync-time');
        if (epChk) epChk.checked = epSync.enabled === true;
        if (epSrc && epSync.source) epSrc.value = epSync.source;
        if (epMode) epMode.value = epSync.mode === 'daily' ? 'daily' : 'interval';
        if (epInt) epInt.value = Math.max(1, Math.round((epSync.interval_seconds || 3600) / 60));
        if (epTime) epTime.value = epSync.daily_time || '02:00';
    } catch (e) { console.error('loadEndpointSyncConfig failed', e); }
}

async function loadEndpointSyncStatus() {
    const wrap = document.getElementById('endpoint-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/endpoint-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const total = Number(t.endpoints_total) || 0;
        const skipped = Number(t.skipped) || 0;
        const skipDetails = Array.isArray(t.skipped_details) ? t.skipped_details : [];
        // Dedupe the CPPM spoke's per-record skip reasons into reason→count so
        // the operator sees WHY records were dropped, not just that they were.
        const skipReasons = {};
        for (const s of skipDetails) {
            const r = s && s.reason ? String(s.reason) : 'skipped';
            skipReasons[r] = (skipReasons[r] || 0) + 1;
        }
        const skipLine = skipped > 0
            ? ` · <span class="text-amber-600">skipped ${skipped}</span>`
            : '';
        const skipReasonHtml = Object.keys(skipReasons).length
            ? `<p class="text-xs text-amber-600 mt-1">Skipped: ${esc(Object.entries(skipReasons).map(([r, c]) => `${r} (${c})`).join('; '))}</p>`
            : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · errors ${errors} · endpoints ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
            ${skipReasonHtml}
        </div>`;
    }).join('');
}

async function runEndpointSyncNow() {
    const btn = document.getElementById('ep-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const data = await apiJson('/setup/endpoint-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadEndpointSyncStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveEndpointSyncConfig() {
    const enabled = document.getElementById('ep-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('ep-sync-source')?.value || 'netbox';
    const mode = document.getElementById('ep-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('ep-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('ep-sync-time')?.value || '02:00';
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { netbox_cppm_sync: {
                enabled, source, mode, interval_seconds: intervalMin * 60, daily_time: dailyTime
            } } })
        });
        if (r.ok) showToast('Endpoint sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// ── Realtime NAC → IPAM reverse sync (System → Sync, same "IPAM ↔ NAC" card) ──
async function loadRealtimeNacSyncConfig() {
    // Populate the enable/interval/lookback inputs from global_config.
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).realtime_ipam_nac_sync || {};
        const en = document.getElementById('rt-nac-sync-enabled');
        const intv = document.getElementById('rt-nac-sync-interval');
        const lb = document.getElementById('rt-nac-sync-lookback');
        if (en) en.checked = cfg.enabled === true;
        if (intv) intv.value = Math.max(1, Math.round((cfg.interval_seconds || 60) / 60));
        if (lb) lb.value = Math.max(1, cfg.lookback_minutes || 2);
    } catch (e) { console.error('loadRealtimeNacSyncConfig failed', e); }
}

async function loadRealtimeNacSyncStatus() {
    const wrap = document.getElementById('rt-nac-sync-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/realtime-nac-sync/status');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const skipped = Number(t.skipped) || 0;
        const total = Number(t.sessions_total) || 0;
        const skipLine = skipped > 0 ? ` · <span class="text-amber-600">skipped ${skipped}</span>` : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">added ${pushed} · already-present ${skipped} · errors ${errors} · sessions ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runRealtimeNacNow() {
    const btn = document.getElementById('rt-nac-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const data = await apiJson('/setup/realtime-nac-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} added, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadRealtimeNacSyncStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

// ── Real-time DHCP → DNS hook (System → Sync; global_config.dhcp_dns_hook) ──
// Default ON when unset; the hub's DNS/DHCP sync loop pushes it to the spokes.
async function loadDnsHookConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).dhcp_dns_hook || {};
        const en = document.getElementById('dns-hook-enabled');
        const ptr = document.getElementById('dns-hook-register-ptr');
        if (en) en.checked = cfg.enabled !== false;
        if (ptr) ptr.checked = cfg.register_ptr === true;
        const st = document.getElementById('dns-hook-status');
        const s = await _spokeFetch('/api/dns-dhcp/sync-status');
        const h = (s && s.ok && s.data && (s.data.status || {}).dns_hook) || {};
        if (st && h.last_run) {
            const errs = Object.entries(h.errors || {}).map(([k, v]) => `${k}: ${v}`).join('; ');
            st.innerHTML = `Last check: <span class="${h.status === 'ok' ? 'text-emerald-600' : 'text-red-500'} font-medium">${escapeHtml(h.status || '')}</span> · ${escapeHtml(new Date(h.last_run * 1000).toLocaleString())}${errs ? ' · ' + escapeHtml(errs) : ''}${h.reason ? ' · ' + escapeHtml(h.reason) : ''}`;
        }
    } catch (e) { console.error('loadDnsHookConfig failed', e); }
}

async function saveDnsHookConfig() {
    const r0 = await setupFetch('/setup/config');
    const prev = r0.ok ? (((await r0.json()).global_config || {}).dhcp_dns_hook || {}) : {};
    const enabled = !!document.getElementById('dns-hook-enabled')?.checked;
    const register_ptr = !!document.getElementById('dns-hook-register-ptr')?.checked;
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { dhcp_dns_hook: { ...prev, enabled, register_ptr } } })
        });
        if (r.ok) showToast(`Real-time DHCP → DNS ${enabled ? 'enabled' : 'disabled'} — applied on the next sync cycle.`, 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

async function saveRealtimeNacSyncConfig() {
    const enabled = document.getElementById('rt-nac-sync-enabled')?.checked ? true : false;
    const intervalMin = Math.max(1, parseInt(document.getElementById('rt-nac-sync-interval')?.value, 10) || 1);
    const lookback = Math.max(1, parseInt(document.getElementById('rt-nac-sync-lookback')?.value, 10) || 2);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { realtime_ipam_nac_sync: {
                enabled, interval_seconds: intervalMin * 60, lookback_minutes: lookback
            } } })
        });
        if (r.ok) showToast('Realtime reverse sync saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── NetBox staleness sweep (System → Sync, cluster-wide) ────────────────
async function loadStalenessSweepConfig() {
    // Populate enable/interval/stale-days/delete-days from global_config.
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).staleness_sweep || {};
        const en = document.getElementById('staleness-sweep-enabled');
        const intv = document.getElementById('staleness-sweep-interval');
        const sd = document.getElementById('staleness-sweep-stale-days');
        const dd = document.getElementById('staleness-sweep-delete-days');
        if (en) en.checked = cfg.enabled === true;
        if (intv) intv.value = Math.max(1, Math.round((cfg.interval_seconds || 3600) / 60));
        if (sd) sd.value = Math.max(1, cfg.stale_days || 7);
        if (dd) dd.value = Math.max(1, cfg.delete_days || 30);
    } catch (e) { console.error('loadStalenessSweepConfig failed', e); }
}

async function loadStalenessSweepStatus() {
    const wrap = document.getElementById('staleness-sweep-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/staleness-sweep/status');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    if (!data || !data.last_sync_ts) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No sweep recorded yet. Click “Sweep now” to run one.</p>';
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const st = String(data.status || '');
    const pill = st === 'success' ? 'bg-green-100 text-green-700'
        : st === 'error' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500';
    wrap.innerHTML = `<div class="border border-slate-200 rounded-md p-3">
        <div class="flex items-center justify-between mb-1">
            <span class="text-sm font-bold text-slate-700">Cluster-wide</span>
            <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
        </div>
        <p class="text-xs text-slate-500">scanned ${Number(data.scanned) || 0} · decommissioned ${Number(data.decommissioned) || 0} · deleted ${Number(data.deleted) || 0} · IPs freed ${Number(data.ip_freed) || 0} · errors ${Number(data.errors) || 0} <span class="text-slate-400">· last ${fmtDate(data.last_sync_ts)}</span></p>
        ${data.message ? `<p class="text-xs text-slate-400 mt-1">${esc(data.message)}</p>` : ''}
    </div>`;
}

async function runStalenessSweepNow() {
    const btn = document.getElementById('staleness-sweep-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Sweeping…'; }
    try {
        const data = await apiJson('/setup/staleness-sweep/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        showToast(`Sweep: ${s.decommissioned || 0} decommissioned, ${s.deleted || 0} deleted, ${s.ip_freed || 0} IPs freed${(s.errors || 0) ? `, ${s.errors} errors` : ''}.`,
                  (s.errors || 0) ? 'info' : 'success');
        await loadStalenessSweepStatus();
    } catch (e) {
        showToast('Sweep failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function runNetboxDedupe(apply) {
    const scanBtn = document.getElementById('netbox-dedupe-scan-btn');
    const mergeBtn = document.getElementById('netbox-dedupe-merge-btn');
    const wrap = document.getElementById('netbox-dedupe-status');
    if (apply && !confirm('Merge duplicate devices? The most complete record in each group is kept and the duplicates are deleted. This cannot be undone.')) return;
    [scanBtn, mergeBtn].forEach(b => { if (b) b.disabled = true; });
    if (wrap) wrap.innerHTML = '<p class="text-xs text-slate-400 italic">Running…</p>';
    try {
        const data = await apiJson('/setup/netbox-dedupe/run', {
            method: 'POST',
            body: JSON.stringify({ apply: !!apply })
        });
        renderNetboxDedupe(data.result || {}, !!apply);
        const r = data.result || {};
        showToast(apply
            ? `De-dupe: merged ${r.merged || 0} device(s) across ${(r.groups || []).length} group(s)${(r.errors || 0) ? `, ${r.errors} errors` : ''}.`
            : `De-dupe scan: ${(r.groups || []).length} duplicate group(s) across ${r.scanned || 0} device(s).`,
            (r.errors || 0) ? 'info' : 'success');
    } catch (e) {
        if (wrap) wrap.innerHTML = `<p class="text-xs text-red-500">Error: ${escapeHtml(String((e && e.message) || e))}</p>`;
        showToast('De-dupe failed: ' + (e && e.message || e), 'error');
    } finally {
        [scanBtn, mergeBtn].forEach(b => { if (b) b.disabled = false; });
    }
}

function renderNetboxDedupe(res, applied) {
    const wrap = document.getElementById('netbox-dedupe-status');
    if (!wrap) return;
    const groups = res.groups || [];
    const head = `<p class="text-xs text-slate-500">Scanned <strong>${res.scanned || 0}</strong> device(s) — <strong>${groups.length}</strong> duplicate group(s)${applied ? `, merged <strong>${res.merged || 0}</strong> device(s)` : ' (dry run — nothing changed)'}${res.errors ? `, <span class="text-red-500">${res.errors} error(s)</span>` : ''}.</p>`;
    if (!groups.length) { wrap.innerHTML = head + '<p class="text-xs text-slate-400 italic">No duplicate devices found.</p>'; return; }
    const rows = groups.map(g => {
        const dups = (g.duplicate_ids || []).map(id => '#' + id).join(', ');
        const name = g.survivor_name ? ' (' + escapeHtml(g.survivor_name) + ')' : '';
        return `<li class="text-xs text-slate-600"><code>${escapeHtml(g.key || '?')}</code> → keep #${g.survivor_id}${name}, ${applied ? 'merged' : 'would merge'} ${dups}</li>`;
    }).join('');
    wrap.innerHTML = head + `<ul class="space-y-1 list-none">${rows}</ul>`;
}

async function saveStalenessSweepConfig() {
    const enabled = document.getElementById('staleness-sweep-enabled')?.checked ? true : false;
    const intervalMin = Math.max(1, parseInt(document.getElementById('staleness-sweep-interval')?.value, 10) || 60);
    const staleDays = Math.max(1, parseInt(document.getElementById('staleness-sweep-stale-days')?.value, 10) || 7);
    const deleteDays = Math.max(1, parseInt(document.getElementById('staleness-sweep-delete-days')?.value, 10) || 30);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { staleness_sweep: {
                enabled, interval_seconds: intervalMin * 60,
                stale_days: staleDays, delete_days: deleteDays
            } } })
        });
        if (r.ok) showToast('Staleness sweep saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── GitHub repo sync (System → Sync; replaces the old auto-update loop) ───
// Pulls the hub tree + provisioning_repos/* locally and fans SPOKE_UPDATE out
// to every approved spoke every interval (default 15 min). Saved via /setup/config
// under global_config.repo_sync. Status from GET /setup/repo-sync/status,
// on-demand run from POST /setup/repo-sync/run.
async function loadRepoSyncConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).repo_sync || {};
        const en = document.getElementById('repo-sync-enabled');
        const intv = document.getElementById('repo-sync-interval');
        // Default: enabled, 15-minute interval.
        if (en) en.checked = cfg.enabled !== false;
        if (intv) intv.value = Math.max(1, Math.round((cfg.interval_seconds || 900) / 60));
    } catch (e) { console.error('loadRepoSyncConfig failed', e); }
}

async function loadRepoSyncStatus() {
    const wrap = document.getElementById('repo-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/repo-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    if (!data || !data.last_sync_ts) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No sync recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const hub = data.hub || {};
    const hs = String(hub.status || '');
    const pill = hs === 'success' ? 'bg-green-100 text-green-700'
        : hs === 'error' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500';
    const prov = Array.isArray(data.provisioning_repos) ? data.provisioning_repos : [];
    const okN = prov.filter(r => r.status === 'ok').length;
    const errN = prov.filter(r => r.status === 'error').length;
    const skipN = prov.filter(r => r.status === 'skipped').length;
    const changed = prov.filter(r => r.changed).map(r => r.name);
    const provRows = prov.length ? prov.map(r => {
        const dot = r.status === 'ok' ? 'bg-green-500'
            : r.status === 'error' ? 'bg-red-500' : 'bg-slate-300';
        return `<div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full ${dot}"></span>
            <span class="text-xs text-slate-600">${esc(r.name)}</span>
            <span class="text-xs text-slate-400">${esc(r.message || r.status)}</span></div>`;
    }).join('') : '<p class="text-xs text-slate-400 italic">No provisioning source repos present.</p>';
    // Per-module spoke fan-out results (from perform_update, threaded through
    // repo_sync). Each entry is "sid: <outcome> (repo)"; classify the outcome
    // into a colored dot so the REAL module updates (le, pxmx, opnsense, …) are
    // visible and distinct from the auxiliary provisioning_repos above.
    const spokes = Array.isArray(data.spokes) ? data.spokes : [];
    const _spokeDot = t => {
        const s = t.toLowerCase();
        if (s.includes('triggered')) return 'bg-green-500';
        if (s.includes('up-to-date')) return 'bg-slate-400';
        if (s.includes('offline') || s.includes('deferred') || s.includes('cooldown') || s.includes('backstop')) return 'bg-amber-400';
        if (s.includes('failed') || s.includes('unknown module') || s.includes('no repo')) return 'bg-red-500';
        return 'bg-slate-300';
    };
    const spokeRows = spokes.length ? spokes.map(line => {
        const str = String(line);
        const i = str.indexOf(':');
        const sid = (i >= 0 ? str.slice(0, i) : str).trim();
        const txt = i >= 0 ? str.slice(i + 1).trim() : '';
        // Resolve the spoke UUID → friendly name (same spokeHealth map the header
        // tray uses; /setup/diagnostics lists every approved spoke incl. offline).
        // Keep the raw id on hover. Falls back to the UUID if the map isn't loaded.
        const _h = (window.spokeHealth || {})[sid];
        const nm = (_h && _h.name && _h.name !== sid) ? _h.name : sid;
        return `<div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full ${_spokeDot(txt)}"></span>
            <span class="text-xs text-slate-600 font-medium" title="${esc(sid)}">${esc(nm)}</span>
            <span class="text-xs text-slate-400">${esc(txt)}</span></div>`;
    }).join('') : '<p class="text-xs text-slate-400 italic">No module updates this sync (the hub was current — spokes fan out only when the hub or a module repo advances, or on a forced Sync).</p>';
    wrap.innerHTML = `<div class="border border-slate-200 rounded-md p-3">
        <div class="flex items-center justify-between mb-1">
            <span class="text-sm font-bold text-slate-700">Hub update</span>
            <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(hs || '—')}</span>
        </div>
        ${hub.message ? `<p class="text-xs text-slate-400 mt-1">${esc(hub.message)}</p>` : ''}
        <div class="mt-3">
            <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2">Module updates <span class="text-slate-400 font-normal normal-case">(spokes — pxmx / opnsense / cs / cppm / netbox / ldap / nw / le / roles)</span></div>
            <div class="space-y-1">${spokeRows}</div>
        </div>
        <div class="mt-3 pt-2 border-t border-slate-100">
            <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2">Provisioning source repos <span class="text-slate-400 font-normal normal-case">(auxiliary services on the hub — not LM modules)</span></div>
            <p class="text-xs text-slate-500">${okN} ok · ${errN} error · ${skipN} skipped <span class="text-slate-400">· last ${fmtDate(data.last_sync_ts)}</span></p>
            ${changed.length ? `<p class="text-xs text-slate-500 mt-1">changed: ${esc(changed.join(', '))}</p>` : ''}
            <div class="mt-1 space-y-1">${provRows}</div>
        </div>
        ${data.message ? `<p class="text-xs text-slate-400 mt-2 pt-2 border-t border-slate-100">${esc(data.message)}</p>` : ''}
    </div>`;
}

async function runRepoSyncNow() {
    const btn = document.getElementById('repo-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const data = await apiJson('/setup/repo-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        const restarting = /restart/i.test(String((data.result || {}).message || ''));
        showToast(`Repo sync: ${s.provisioning_repos_ok || 0} repos ok, ${s.provisioning_repos_error || 0} errors${restarting ? ' — hub restarting' : ''}.`,
                  (s.provisioning_repos_error || 0) ? 'info' : 'success');
        await loadRepoSyncStatus();
    } catch (e) {
        showToast('Repo sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveRepoSyncConfig() {
    const enabled = document.getElementById('repo-sync-enabled')?.checked ? true : false;
    const intervalMin = Math.max(1, parseInt(document.getElementById('repo-sync-interval')?.value, 10) || 15);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { repo_sync: {
                enabled, interval_seconds: intervalMin * 60
            } } })
        });
        if (r.ok) showToast('Repo sync schedule saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── Source of Truth per module (System → Sync; saved via /setup/config) ──
const _SOT_DEFAULTS = { vm_sync: 'external', device_sync: 'netbox',
                        access_tracker: 'netbox', endpoint_sync: 'netbox' };

async function loadSourceOfTruthConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const sot = (data.global_config || {}).source_of_truth || {};
        for (const k of Object.keys(_SOT_DEFAULTS)) {
            const el = document.getElementById('sot-' + k.replace(/_/g, '-'));
            if (el) el.value = sot[k] || _SOT_DEFAULTS[k];
        }
    } catch (e) { console.error('loadSourceOfTruthConfig failed', e); }
}

async function saveSourceOfTruthConfig() {
    const sot = {};
    for (const k of Object.keys(_SOT_DEFAULTS)) {
        const el = document.getElementById('sot-' + k.replace(/_/g, '-'));
        sot[k] = el ? (el.value || _SOT_DEFAULTS[k]) : _SOT_DEFAULTS[k];
    }
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { source_of_truth: sot } })
        });
        if (r.ok) showToast('Source-of-truth saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── Spoke out-of-contact alerts (System → Sync; saved via /setup/config) ──
// global_config["spoke_alert"] = {enabled, warn_s, error_s}. The loop
// (core/src/spoke_alert_sync.py run_spoke_alert_loop) reads it fresh each cycle.
async function loadSpokeAlertConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).spoke_alert || {};
        const en = document.getElementById('spoke-alert-enabled');
        const wmin = document.getElementById('spoke-alert-warn-min');
        const emin = document.getElementById('spoke-alert-error-min');
        if (en) en.checked = cfg.enabled === true;
        if (wmin) wmin.value = Math.max(1, Math.round((cfg.warn_s || 300) / 60));
        if (emin) emin.value = Math.max(1, Math.round((cfg.error_s || 1800) / 60));
    } catch (e) { console.error('loadSpokeAlertConfig failed', e); }
}

async function saveSpokeAlertConfig() {
    const enabled = document.getElementById('spoke-alert-enabled')?.checked ? true : false;
    const warnMin = Math.max(1, parseInt(document.getElementById('spoke-alert-warn-min')?.value, 10) || 5);
    const errorMin = Math.max(1, parseInt(document.getElementById('spoke-alert-error-min')?.value, 10) || 30);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { spoke_alert: {
                enabled, warn_s: warnMin * 60, error_s: errorMin * 60
            } } })
        });
        if (r.ok) showToast('Spoke alert config saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── Hub-Contact Watchdog (fleet-wide, pushed to spokes) ──────────────────
async function loadHubWatchdog() {
    try {
        const r = await setupFetch('/setup/hub-watchdog');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const en = document.getElementById('hcw-enabled'); if (en) en.checked = !!c.enabled;
        const setMin = (id, s, def) => { const el = document.getElementById(id); if (el && document.activeElement !== el) el.value = Math.round((Number(s) || def * 60) / 60); };
        setMin('hcw-service-min', c.service_s, 5);
        setMin('hcw-reboot-min', c.reboot_s, 15);
        setMin('hcw-sleep-min', c.sleep_s, 60);
        const mr = document.getElementById('hcw-max-runs'); if (mr && document.activeElement !== mr) mr.value = c.max_runs || 3;
    } catch (e) { console.error('loadHubWatchdog failed', e); }
}

async function saveHubWatchdog() {
    const btn = document.getElementById('hcw-save-btn');
    const iv = id => parseInt(document.getElementById(id)?.value, 10);
    const serviceMin = Math.max(1, iv('hcw-service-min') || 5);
    const rebootMin = Math.max(2, iv('hcw-reboot-min') || 15);
    if (rebootMin <= serviceMin) { showToast('Reboot threshold must be greater than the service-restart threshold.', 'error'); return; }
    const cfg = {
        enabled: !!document.getElementById('hcw-enabled')?.checked,
        service_s: serviceMin * 60,
        reboot_s: rebootMin * 60,
        sleep_s: Math.max(1, iv('hcw-sleep-min') || 60) * 60,
        max_runs: Math.max(1, iv('hcw-max-runs') || 3),
    };
    if (btn) btn.disabled = true;
    try {
        const d = await apiJson('/setup/hub-watchdog', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) });
        const f = d.fanout || {};
        const msg = document.getElementById('hcw-msg');
        if (msg) msg.textContent = cfg.enabled
            ? `Enabled. Pushed to ${(f.pushed || []).length} node(s)${(f.queued || []).length ? ', queued for ' + f.queued.length + ' offline' : ''}.`
            : `Disabled. Pushed to ${(f.pushed || []).length} node(s)${(f.queued || []).length ? ', queued for ' + f.queued.length + ' offline' : ''}.`;
        showToast('Hub-contact watchdog saved.', 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) btn.disabled = false; }
}
window.loadHubWatchdog = loadHubWatchdog; window.saveHubWatchdog = saveHubWatchdog;

// ── Hub TLS Verification (fleet-wide, pushed to spokes/agents) ───────────
async function loadHubTlsVerify() {
    try {
        const r = await setupFetch('/setup/hub-tls-verify');
        const d = await r.json().catch(() => ({}));
        const sel = document.getElementById('htv-mode');
        if (sel && d.mode) sel.value = d.mode;
    } catch (e) { console.error('loadHubTlsVerify failed', e); }
}

async function saveHubTlsVerify() {
    const sel = document.getElementById('htv-mode');
    const mode = sel ? sel.value : 'install';
    if (mode === 'off' && !confirm('Turn OFF hub certificate verification on every spoke/agent? This exposes the hub connection to man-in-the-middle attacks.')) { loadHubTlsVerify(); return; }
    if (sel) sel.disabled = true;
    const msg = document.getElementById('htv-msg');
    if (msg) msg.textContent = 'Pushing to nodes…';
    try {
        const d = await apiJson('/setup/hub-tls-verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) });
        const f = d.fanout || {};
        const refused = f.refused || [];
        let t = `Saved. Pushed to ${(f.pushed || []).length} node(s)`;
        if ((f.queued || []).length) t += `, queued for ${f.queued.length} offline`;
        if ((f.failed || []).length) t += `, failed: ${f.failed.join(', ')}`;
        t += '.';
        if (refused.length) t += ' Refused (hub cert does not verify from these nodes — they keep their current setting): ' + refused.map(x => x.spoke_id).join(', ') + '.';
        if (msg) { msg.textContent = t; msg.className = 'text-xs mt-3 ' + (refused.length ? 'text-amber-600' : 'text-slate-400'); }
        showToast('Hub TLS verification saved.', refused.length ? 'warning' : 'success');
    } catch (e) {
        if (msg) msg.textContent = '';
        showToast('Save failed: ' + (e.message || e), 'error');
    } finally { if (sel) sel.disabled = false; }
}
window.loadHubTlsVerify = loadHubTlsVerify; window.saveHubTlsVerify = saveHubTlsVerify;

async function loadSpokeAlerts() {
    const wrap = document.getElementById('spoke-alerts-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/spoke-alerts');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const alerts = (data && data.active_alerts) || [];
    if (!alerts.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No active alerts — every approved spoke is in contact.</p>';
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    wrap.innerHTML = alerts.map(a => {
        const isErr = String(a.tier) === 'error';
        const pill = isErr ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700';
        const mins = Math.max(0, Math.round((a.duration_s || 0) / 60));
        // Resolve a friendly name (the alert entry carries only spoke_id) —
        // mirror the header-tray resolver: display_name/name on the entry, else
        // the spokeHealth map, else the raw id. Keep the UUID in a hover title.
        const _h = (window.spokeHealth || {})[a.spoke_id];
        const _nm = a.display_name || a.name || (_h && _h.name) || a.spoke_id;
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-mono text-slate-700" title="${esc(a.spoke_id)}">${esc(_nm)}</span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(a.tier)}</span>
            </div>
            <p class="text-xs text-slate-500">out of contact ${mins}m <span class="text-slate-400">· since ${fmtDate(a.since_ts)}</span></p>
            ${a.detail ? `<p class="text-xs text-slate-400 mt-1">${esc(a.detail)}</p>` : ''}
        </div>`;
    }).join('');
}

// ── Hypervisor → NetBox VM sync (System → Sync) ──────────────────────────
async function loadVmSyncSources() {
    // Populate the hypervisor source dropdown from the hub's HYPERVISOR_SOURCES
    // registry (data-driven) and mark each source's connected state. Also list
    // the connected pxmx agents (the real Proxmox servers) in the "Sync from
    // server" dropdown so the admin can scope the sync to one server.
    const sel = document.getElementById('vm-sync-source');
    const agSel = document.getElementById('vm-sync-agent');
    if (!sel) return;
    let savedAgent = '';
    if (agSel) savedAgent = agSel.value;
    try {
        const r = await setupFetch('/setup/vm-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
        if (agSel) {
            const agents = data.agents || [];
            agSel.innerHTML = '<option value="">All connected servers</option>'
                + agents.map(a => {
                    const nodes = (a.nodes || []).join(', ');
                    const label = `${a.cluster || a.hostname || a.agent_id}${nodes ? ' [' + nodes + ']' : ''} · ${a.vm_count || 0} VMs`;
                    return `<option value="${escapeHtml(a.agent_id)}">${escapeHtml(label)}</option>`;
                }).join('');
            if (!agents.length) {
                agSel.innerHTML = '<option value="">No servers connected</option>';
            }
            if (savedAgent) agSel.value = savedAgent;
        }
    } catch (e) { console.error('loadVmSyncSources failed', e); }
}

async function loadVmSyncConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const vmSync = (data.global_config || {}).pxmx_netbox_vm_sync || {};
        const chk = document.getElementById('vm-sync-enabled');
        const src = document.getElementById('vm-sync-source');
        const mode = document.getElementById('vm-sync-mode');
        const intv = document.getElementById('vm-sync-interval');
        const time = document.getElementById('vm-sync-time');
        const agSel = document.getElementById('vm-sync-agent');
        if (chk) chk.checked = vmSync.enabled === true;
        if (src && vmSync.source) src.value = vmSync.source;
        if (mode) mode.value = vmSync.mode === 'daily' ? 'daily' : 'interval';
        if (intv) intv.value = Math.max(1, Math.round((vmSync.interval_seconds || 3600) / 60));
        if (time) time.value = vmSync.daily_time || '03:00';
        // Restore the pinned server (agent_id) — sources may load after config;
        // re-apply once both have run.
        if (agSel && vmSync.agent_id) agSel.value = vmSync.agent_id;
    } catch (e) { console.error('loadVmSyncConfig failed', e); }
}

async function loadVmSyncStatus() {
    const wrap = document.getElementById('vm-sync-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/vm-sync/status');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const deleted = Number(t.deleted) || 0;
        const total = Number(t.vms_total) || 0;
        const skipped = Number(t.skipped) || 0;
        const skipLine = skipped > 0
            ? ` · <span class="text-amber-600">skipped ${skipped}</span>`
            : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · deleted ${deleted} · errors ${errors} · vms ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runVmSyncNow() {
    const btn = document.getElementById('vm-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const data = await apiJson('/setup/vm-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.deleted || 0} deleted, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadVmSyncStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveVmSyncConfig() {
    const enabled = document.getElementById('vm-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('vm-sync-source')?.value || 'proxmox';
    const mode = document.getElementById('vm-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('vm-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('vm-sync-time')?.value || '03:00';
    const agentId = document.getElementById('vm-sync-agent')?.value || '';
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { pxmx_netbox_vm_sync: {
                enabled, source, mode, interval_seconds: intervalMin * 60, daily_time: dailyTime,
                agent_id: agentId
            } } })
        });
        if (r.ok) showToast('VM sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// ── Firewall → IPAM device-discovery sync (System → Sync third card) ──
// Backing routes: /setup/fw-discovery-sync/{sources,status,run} + shared
// /setup/config (saved under global_config.opnsense_netbox_device_sync).
async function loadFwDiscoverySources() {
    // Populate the firewall-source dropdown from FIREWALL_DISCOVERY_SOURCES and
    // the firewall picker from global_config["firewalls"] (each marked with its
    // connected state). NetBox-down is flagged separately by the status card.
    const sel = document.getElementById('fw-sync-source');
    const fwSel = document.getElementById('fw-sync-firewall');
    if (!sel) return;
    let savedFw = '';
    if (fwSel) savedFw = fwSel.value;
    try {
        const r = await setupFetch('/setup/fw-discovery-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
        if (fwSel) {
            const fws = data.firewalls || [];
            fwSel.innerHTML = '<option value="">All connected firewalls</option>'
                + fws.map(f => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.name)}${f.connected ? '' : ' (not connected)'}</option>`).join('');
            if (!fws.length) {
                fwSel.innerHTML = '<option value="">No firewalls configured</option>';
            }
            if (savedFw) fwSel.value = savedFw;
        }
    } catch (e) { console.error('loadFwDiscoverySources failed', e); }
}

async function loadFwDiscoveryConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).opnsense_netbox_device_sync || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        const chk = document.getElementById('fw-sync-enabled');
        if (chk) chk.checked = cfg.enabled === true;
        set('fw-sync-source', cfg.source || 'auto');
        set('fw-sync-data', cfg.source_data || 'both');
        set('fw-sync-firewall', cfg.firewall_id || '');
        set('fw-sync-mode', cfg.mode === 'daily' ? 'daily' : 'interval');
        set('fw-sync-interval', Math.max(1, Math.round((cfg.interval_seconds || 3600) / 60)));
        set('fw-sync-time', cfg.daily_time || '02:00');
        const d = cfg.defaults || {};
        set('fw-sync-role', d.role || '');
        set('fw-sync-type', d.device_type || '');
        set('fw-sync-site', d.site || '');
    } catch (e) { console.error('loadFwDiscoveryConfig failed', e); }
}

async function loadFwDiscoveryStatus() {
    const wrap = document.getElementById('fw-sync-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/fw-discovery-sync/status');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const deleted = Number(t.deleted) || 0;
        const skipped = Number(t.skipped) || 0;
        const total = Number(t.discovered_total) || 0;
        const skipLine = skipped > 0 ? ` · <span class="text-amber-600">skipped ${skipped}</span>` : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · deleted ${deleted} · errors ${errors} · discovered ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runFwDiscoveryNow() {
    const btn = document.getElementById('fw-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const data = await apiJson('/setup/fw-discovery-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.deleted || 0} deleted, ${s.dropped_unattributed || 0} dropped, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadFwDiscoveryStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveFwDiscoveryConfig() {
    const enabled = document.getElementById('fw-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('fw-sync-source')?.value || 'auto';
    const sourceData = document.getElementById('fw-sync-data')?.value || 'both';
    const firewallId = document.getElementById('fw-sync-firewall')?.value || '';
    const mode = document.getElementById('fw-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('fw-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('fw-sync-time')?.value || '02:00';
    const defaults = {
        role: (document.getElementById('fw-sync-role')?.value || '').trim(),
        device_type: (document.getElementById('fw-sync-type')?.value || '').trim(),
        site: (document.getElementById('fw-sync-site')?.value || '').trim(),
    };
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { opnsense_netbox_device_sync: {
                enabled, source, source_data: sourceData, firewall_id: firewallId,
                mode, interval_seconds: intervalMin * 60, daily_time: dailyTime,
                defaults
            } } })
        });
        if (r.ok) showToast('Firewall discovery sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// Network Devices → IPAM discovery sync (System → Sync, 4th card).
// Backing routes: /setup/nw-discovery-sync/{sources,status,run} + shared
// /setup/config (saved under global_config.nw_netbox_device_sync). Mirrors the
// firewall-discovery card; the nw source pulls ARP from switches + gateways.
async function loadNwDiscoverySources() {
    const sel = document.getElementById('nw-sync-source');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/nw-discovery-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
    } catch (e) { console.error('loadNwDiscoverySources failed', e); }
}

async function loadNwDiscoveryConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).nw_netbox_device_sync || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        const chk = document.getElementById('nw-sync-enabled');
        if (chk) chk.checked = cfg.enabled === true;
        set('nw-sync-source', cfg.source || 'nw');
        set('nw-sync-mode', cfg.mode === 'daily' ? 'daily' : 'interval');
        set('nw-sync-interval', Math.max(1, Math.round((cfg.interval_seconds || 3600) / 60)));
        set('nw-sync-time', cfg.daily_time || '02:30');
        const d = cfg.defaults || {};
        set('nw-sync-role', d.role || '');
        set('nw-sync-type', d.device_type || '');
        set('nw-sync-site', d.site || '');
    } catch (e) { console.error('loadNwDiscoveryConfig failed', e); }
}

async function loadNwDiscoveryStatus() {
    const wrap = document.getElementById('nw-sync-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/nw-discovery-sync/status');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const deleted = Number(t.deleted) || 0;
        const skipped = Number(t.skipped) || 0;
        const total = Number(t.discovered_total) || 0;
        const skipLine = skipped > 0 ? ` · <span class="text-amber-600">skipped ${skipped}</span>` : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · deleted ${deleted} · errors ${errors} · discovered ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runNwDiscoveryNow() {
    const btn = document.getElementById('nw-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const data = await apiJson('/setup/nw-discovery-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.deleted || 0} deleted, ${s.dropped_unattributed || 0} dropped, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadNwDiscoveryStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function pollNwDevice(deviceId, name, btn) {
    // POLL NOW: full probe+info+interfaces+arp+mac poll on the spoke, then upsert
    // the device + interfaces into NetBox. Admin-only route. Refreshes the active
    // nw sub-view afterward so live data appears.
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Polling…'; }
    try {
        const d = await apiJson(`/api/nw/${encodeURIComponent(deviceId)}/poll`, {
            method: 'POST',
            body: JSON.stringify({})
        });
        const up = d.reachable ? 'up' : 'down';
        const nif = Array.isArray(d.interfaces) ? d.interfaces.length : 0;
        const narp = Array.isArray(d.arp) ? d.arp.length : 0;
        const nmac = Array.isArray(d.mac_table) ? d.mac_table.length : 0;
        const push = d.netbox_push || {};
        const pushTxt = push && push.status
            ? ` · NetBox: ${push.status === 'ERROR' ? 'errors=' + (push.errors || 0) : 'pushed=' + (push.pushed || 0) + ', ifaces=' + (push.interfaces_total || 0)}`
            : '';
        const errs = Array.isArray(d.errors) ? d.errors.length : 0;
        showToast(`Poll ${name}: reachable ${up} · ${nif} iface(s) · ${narp} arp · ${nmac} mac${pushTxt}${errs ? ` · ${errs} error(s)` : ''}`,
            d.reachable ? 'success' : 'error');
        // Refresh whatever nw sub-view is active (Devices shows new reachability;
        // ARP/Interfaces/MAC reload the live rows).
        await loadNwData(currentSubView);
    } catch (e) {
        showToast('Poll failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveNwDiscoveryConfig() {
    const enabled = document.getElementById('nw-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('nw-sync-source')?.value || 'nw';
    const mode = document.getElementById('nw-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('nw-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('nw-sync-time')?.value || '02:30';
    const defaults = {
        role: (document.getElementById('nw-sync-role')?.value || '').trim(),
        device_type: (document.getElementById('nw-sync-type')?.value || '').trim(),
        site: (document.getElementById('nw-sync-site')?.value || '').trim(),
    };
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { nw_netbox_device_sync: {
                enabled, source, mode, interval_seconds: intervalMin * 60,
                daily_time: dailyTime, defaults
            } } })
        });
        if (r.ok) showToast('Network Devices discovery sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// Console → IPAM device sync (System → Sync). Event-driven (no schedule): each
// Console auto-identify pushes the device to NetBox. Config lives in
// global_config.console_netbox_device_sync (enabled default true).
async function loadConsoleNetboxSync() {
    try {
        const data = await apiJson('/setup/console-netbox-sync');
        const cfg = data.config || {};
        const chk = document.getElementById('console-sync-enabled');
        // Enabled by default when unset (preserves the original always-on sync).
        if (chk) chk.checked = cfg.enabled !== false;
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        set('console-sync-sot', cfg.source_of_truth === 'netbox' ? 'netbox' : 'external');
        const d = cfg.defaults || {};
        set('console-sync-role', d.role || '');
        set('console-sync-type', d.device_type || '');
        set('console-sync-site', d.site || '');
    } catch (e) { console.error('loadConsoleNetboxSync failed', e); }
}

async function loadConsoleNetboxStatus() {
    const wrap = document.getElementById('console-sync-status');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/setup/console-netbox-sync/status');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = escapeHtml;
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No console syncs yet. A device is pushed the moment a Console spoke identifies it.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const synced = Number(t.synced) || 0;
        const errors = Number(t.errors) || 0;
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">synced ${synced} · errors ${errors}${t.last_device ? ` · last <span class="font-mono">${esc(t.last_device)}</span>` : ''} <span class="text-slate-400">· ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function saveConsoleNetboxSync() {
    const enabled = document.getElementById('console-sync-enabled')?.checked ? true : false;
    const sourceOfTruth = document.getElementById('console-sync-sot')?.value === 'netbox' ? 'netbox' : 'external';
    const defaults = {
        role: (document.getElementById('console-sync-role')?.value || '').trim(),
        device_type: (document.getElementById('console-sync-type')?.value || '').trim(),
        site: (document.getElementById('console-sync-site')?.value || '').trim(),
    };
    try {
        const r = await setupFetch('/setup/console-netbox-sync', {
            method: 'POST',
            body: JSON.stringify({ config: { enabled, source_of_truth: sourceOfTruth, defaults } })
        });
        if (r.ok) showToast('Console → NetBox sync settings saved.', 'success');
        else showToast('Failed to save settings.', 'error');
    } catch (e) {
        showToast('Error saving settings: ' + e.message, 'error');
    }
}

async function loadSubnetFilterToggles() {
    const wrap = document.getElementById('subnet-filter-toggles');
    if (!wrap) return;
    try {
        const d = await apiJson('/admin/subnet-filter-config', { credentials: 'same-origin' });
        _subnetFilterState = d.modules || {};
        wrap.innerHTML = _SUBNET_FILTER_MODULES.map(m => {
            const on = !!_subnetFilterState[m.key];
            return `<div class="flex items-center justify-between py-1.5 border-b border-slate-100 last:border-0">
                <span class="text-sm text-slate-700">${m.label}</span>
                <button onclick="toggleSubnetFilter('${m.key}')" class="relative inline-flex h-5 w-10 items-center rounded-full transition-colors ${on ? 'bg-[#01A982]' : 'bg-slate-300'}">
                    <span class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${on ? 'translate-x-5' : 'translate-x-1'}"></span>
                </button>
            </div>`;
        }).join('');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed to load: ${e.message}</p>`;
    }
}

async function toggleSubnetFilter(module) {
    const next = !(_subnetFilterState[module] || false);
    _subnetFilterState[module] = next;
    try {
        await apiJson('/admin/subnet-filter-config', {
            method: 'PUT', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ modules: _subnetFilterState }),
        });
        if (typeof showToast === 'function') showToast(`${module} subnet filter ${next ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast('Failed to update: ' + e.message, 'error');
        _subnetFilterState[module] = !next;
    }
    loadSubnetFilterToggles();
}

// Curated VID:PID → product name (common USB Wi-Fi adapter chipsets used as sim
// dongles) with a VID → vendor fallback, so the USB management UI can show a
// human-friendly name/type even when no live telemetry label is available.
const _USB_PRODUCT_NAMES = {
    '0bda:8812': 'Realtek RTL8812AU (AC1200)',
    '0bda:b812': 'Realtek RTL88x2BU',
    '0bda:c811': 'Realtek RTL8811CU',
    '0bda:8178': 'Realtek RTL8192CU',
    '0bda:818b': 'Realtek RTL8192EU',
    '0bda:f179': 'Realtek RTL8188FTV',
    '0e8d:7612': 'MediaTek MT7612U',
    '0e8d:7610': 'MediaTek MT7610U',
    '0e8d:7961': 'MediaTek MT7921U',
    '148f:5370': 'Ralink RT5370',
    '148f:3070': 'Ralink RT3070',
    '148f:7601': 'MT7601U',
    '0cf3:9271': 'Atheros AR9271',
    '2357:0120': 'TP-Link TL-WN722N v2/v3',
    '2357:010c': 'TP-Link Archer T2U',
};
const _USB_VENDOR_NAMES = {
    '0bda': 'Realtek',
    '0e8d': 'MediaTek',
    '148f': 'Ralink',
    '0cf3': 'Qualcomm Atheros',
    '2357': 'TP-Link',
    '0846': 'NETGEAR',
    '7392': 'Edimax',
    '2001': 'D-Link',
    '050d': 'Belkin',
    '13b1': 'Linksys',
    '8087': 'Intel',
    '0781': 'SanDisk',
    '1a86': 'QinHeng',
    '05e3': 'Genesys Logic',
    '2109': 'VIA Labs',
    '046d': 'Logitech',
};
function usbDeviceName(vidpid) {
    if (!vidpid) return '';
    const key = String(vidpid).toLowerCase();
    if (_USB_PRODUCT_NAMES[key]) return _USB_PRODUCT_NAMES[key];
    const vid = key.split(':')[0];
    if (_USB_VENDOR_NAMES[vid]) return `${_USB_VENDOR_NAMES[vid]} device`;
    return '';
}


async function loadUsbOverview() {
    let data;
    try {
        data = await apiJson('/sim/api/superadmin/tenants/usb', { credentials: 'same-origin' });
    } catch (e) {
        document.getElementById('global-usb-certified').innerHTML = `<span class="text-xs text-red-500">Failed: ${e.message}</span>`;
        return;
    }
    const g = data.global || {};
    const certWrap = document.getElementById('global-usb-certified');
    const ignWrap = document.getElementById('global-usb-ignored');
    // Rendered as full-width bordered rows to match the Discovered-devices list
    // below, each with an Un-approve / Un-ignore action.
    certWrap.innerHTML = (g.certified || []).length
        ? (g.certified || []).map(d => `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 border border-slate-200 rounded-md">
            <span class="font-mono text-xs text-slate-700 w-28">${escapeHtml(d.vidpid)}</span>
            <span class="text-xs text-slate-600 flex-1 min-w-[8rem]">${escapeHtml(d.label && d.label !== d.vidpid ? d.label : (usbDeviceName(d.vidpid) || '—'))}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-green-100 text-green-700">Certified globally</span>
            <button onclick="removeGlobalUsbCert('${d.vidpid}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-approve</button>
          </div>`).join('')
        : '<p class="text-xs text-slate-400 italic">None certified.</p>';
    ignWrap.innerHTML = (g.ignored || []).length
        ? (g.ignored || []).map(vp => `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 border border-slate-200 rounded-md">
            <span class="font-mono text-xs text-slate-700 w-28">${escapeHtml(vp)}</span>
            <span class="text-xs text-slate-600 flex-1 min-w-[8rem]">${escapeHtml(usbDeviceName(vp) || '—')}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-200 text-slate-600">Ignored globally</span>
            <button onclick="removeGlobalUsbIgnore('${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-ignore</button>
          </div>`).join('')
        : '<p class="text-xs text-slate-400 italic">None ignored.</p>';

    const list = document.getElementById('tenant-usb-list');
    const tenants = data.tenants || [];
    if (!tenants.length) { list.innerHTML = '<p class="text-xs text-slate-400 italic">No tenants configured.</p>'; return; }
    list.innerHTML = tenants.map(t => {
        const cert = (t.certified || []).map(d => `<div class="flex flex-wrap items-center gap-x-2 gap-y-1 px-2 py-1.5 border border-slate-200 rounded-md">
                <span class="font-mono text-xs text-slate-700">${escapeHtml(d.vidpid)}</span>
                <span class="text-xs text-slate-500 flex-1 min-w-[6rem]">${escapeHtml(usbDeviceName(d.vidpid) || d.type || '—')}</span>
                <button onclick="tenantUsbRemove('${t.id}','${d.vidpid}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-0.5 rounded text-[11px] font-bold">Un-approve</button>
              </div>`).join('') || '<span class="text-xs text-slate-400 italic">none</span>';
        const ign = (t.ignored || []).map(vp => `<div class="flex flex-wrap items-center gap-x-2 gap-y-1 px-2 py-1.5 border border-slate-200 rounded-md">
                <span class="font-mono text-xs text-slate-700">${escapeHtml(vp)}</span>
                <span class="text-xs text-slate-500 flex-1 min-w-[6rem]">${escapeHtml(usbDeviceName(vp) || '—')}</span>
                <button onclick="tenantUsbRemove('${t.id}','${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-0.5 rounded text-[11px] font-bold">Un-ignore</button>
              </div>`).join('') || '<span class="text-xs text-slate-400 italic">none</span>';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-2">
                <span class="text-sm font-bold text-slate-700">${t.name} <span class="text-xs font-mono text-slate-400">${t.id}</span></span>
            </div>
            <div class="grid grid-cols-2 gap-3 text-xs">
                <div><p class="text-[10px] uppercase font-bold text-slate-400 mb-1">Certified (local)</p><div class="flex flex-col gap-1 min-h-[1.5rem]">${cert}</div></div>
                <div><p class="text-[10px] uppercase font-bold text-slate-400 mb-1">Ignored (local)</p><div class="flex flex-col gap-1 min-h-[1.5rem]">${ign}</div></div>
            </div>
            <div class="flex gap-1 mt-2">
                <input id="tusbc-${t.id}" placeholder="1a2b:3c4d" class="w-28 font-mono text-xs ${'w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800'}" onkeydown="if(event.key==='Enter')tenantUsbAdd('${t.id}','certify')">
                <select id="tusbt-${t.id}" title="Dongle type" class="text-xs ${'w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800'}"><option>wireless</option><option>wired</option><option>storage</option><option>other</option></select>
                <button onclick="tenantUsbAdd('${t.id}','certify')" class="bg-green-100 text-green-700 px-2 py-1 rounded text-xs font-bold">Certify</button>
                <button onclick="tenantUsbAdd('${t.id}','ignore')" class="bg-slate-200 text-slate-600 px-2 py-1 rounded text-xs font-bold">Ignore</button>
            </div>
        </div>`;
    }).join('');
}

// vidpid → display name for the discovered list, so the Approve action can label
// the new certified entry without embedding free-text in an onclick attribute.
let _discoveredUsbByName = {};

async function loadDiscoveredUsb() {
    const wrap = document.getElementById('global-usb-discovered');
    if (!wrap) return;
    let data;
    try {
        data = await apiJson('/sim/api/superadmin/discovered-usb-vidpids', { credentials: 'same-origin' });
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const devs = data.devices || [];
    if (!devs.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No USB devices discovered yet.</p>';
        return;
    }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    _discoveredUsbByName = {};
    wrap.innerHTML = devs.map(d => {
        const vp = d.vidpid;
        _discoveredUsbByName[vp] = d.name || vp;
        const seen = (d.seen_on || []).map(s => `${esc(s.tenant_name)} / ${esc(s.spoke_name)}`).join(', ') || '—';
        let badge;
        if (d.is_global) badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-green-100 text-green-700">Certified globally</span>';
        else if (d.is_global_ignored) badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-200 text-slate-600">Ignored globally</span>';
        else if (d.locally_ignored) badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 text-amber-700">Locally ignored</span>';
        else badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 text-slate-500">Unapproved</span>';
        // Dongle-type picker paired with the approve button — the chosen type
        // becomes the device's certified `type` (wireless/wired/…), which the
        // pxmx agent uses as each provisioned VM's sim_phy. Defaults to
        // wireless (the agent's own default); hidden once already global.
        const approveBtn = d.is_global
            ? `<button onclick="removeGlobalUsbCert('${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-approve globally</button>`
            : `<select id="gusbt-${esc(vp)}" title="Dongle type" class="text-xs bg-white border border-slate-300 rounded-md px-2 py-1 outline-none focus:ring-2 focus:ring-green-500 text-slate-800"><option>wireless</option><option>wired</option><option>storage</option><option>other</option></select>
               <button onclick="approveGlobalUsb('${vp}')" class="bg-green-100 text-green-700 px-2 py-1 rounded text-xs font-bold">Approve globally</button>`;
        const ignoreBtn = d.is_global_ignored
            ? `<button onclick="removeGlobalUsbIgnore('${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-ignore globally</button>`
            : `<button onclick="ignoreGlobalUsb('${vp}')" class="bg-slate-200 text-slate-600 px-2 py-1 rounded text-xs font-bold">Ignore globally</button>`;
        // Per-tenant LOCAL un-approve — one button per tenant that certified this
        // device locally (drops it from that tenant's usb_vidpids).
        const localBtns = (d.locally_certified || []).map(c =>
            `<button onclick="tenantUsbRemove('${esc(c.tenant_id)}','${vp}')" title="Un-approve locally for ${esc(c.tenant_name)}" class="bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100 px-2 py-1 rounded text-[11px] font-bold">Un-approve @${esc(c.tenant_name)}</button>`
        ).join('');
        return `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 border border-slate-200 rounded-md">
            <span class="font-mono text-xs text-slate-700 w-28">${esc(vp)}</span>
            <span class="text-xs text-slate-600 flex-1 min-w-[8rem]">${esc(d.name || '—')}</span>
            <span class="text-[11px] text-slate-400 flex-1 min-w-[10rem]">${seen}</span>
            ${badge}
            <span class="flex flex-wrap gap-1">${approveBtn}${ignoreBtn}${localBtns}</span>
        </div>`;
    }).join('');
}

async function addGlobalUsbCert() {
    const vp = (document.getElementById('gusbc-vp').value || '').trim().toLowerCase();
    const label = (document.getElementById('gusbc-label').value || '').trim();
    const type = document.getElementById('gusbc-type').value;
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex (e.g. 1a2b:3c4d)', 'error'); return; }
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        const next = [...cur.filter(d => d.vidpid !== vp), { vidpid: vp, type, label: label || vp }];
        await apiJson('/sim/api/superadmin/global-usb-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        document.getElementById('gusbc-vp').value = ''; document.getElementById('gusbc-label').value = '';
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function removeGlobalUsbCert(vp) {
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        const next = cur.filter(d => d.vidpid !== vp);
        await fetch('/sim/api/superadmin/global-usb-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function addGlobalUsbIgnore() {
    const vp = (document.getElementById('gusbi-vp').value || '').trim().toLowerCase();
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex (e.g. 1a2b:3c4d)', 'error'); return; }
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        if (!cur.includes(vp)) cur.push(vp);
        await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: cur }),
        });
        document.getElementById('gusbi-vp').value = '';
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function removeGlobalUsbIgnore(vp) {
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        const next = cur.filter(x => x !== vp);
        await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

// Approve a discovered VID:PID globally: add to the global certified list and
// remove it from the global ignored list (mutually exclusive, matching the
// per-tenant cs_usb_vidpids semantics), then push to every tenant's spoke.
async function approveGlobalUsb(vp) {
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('Bad VID:PID', 'error'); return; }
    const label = _discoveredUsbByName[vp] || vp;
    // Read the per-row dongle-type picker (wireless/wired/…); default wireless
    // to match the pxmx agent's own default when a type is unset.
    const type = document.getElementById(`gusbt-${vp}`)?.value || 'wireless';
    try {
        const rc = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cert = rc.ok ? (await rc.json()).usb_vidpids || [] : [];
        const next = [...cert.filter(d => d.vidpid !== vp), { vidpid: vp, type, label: label || vp }];
        await apiJson('/sim/api/superadmin/global-usb-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        const ri = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const ign = ri.ok ? (await ri.json()).usb_vidpids || [] : [];
        const ignNext = ign.filter(x => x !== vp);
        if (ignNext.length !== ign.length) {
            await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
                method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ usb_vidpids: ignNext }),
            });
        }
        if (typeof showToast === 'function') showToast(`Approved ${vp} globally`, 'success');
        loadUsbOverview();
        loadDiscoveredUsb();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

// Ignore a discovered VID:PID globally: add to the global ignored list and
// remove it from the global certified list, then push to every tenant's spoke.
async function ignoreGlobalUsb(vp) {
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('Bad VID:PID', 'error'); return; }
    try {
        const ri = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const ign = ri.ok ? (await ri.json()).usb_vidpids || [] : [];
        const ignNext = ign.includes(vp) ? ign : [...ign, vp];
        await apiJson('/sim/api/superadmin/global-usb-ignored-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: ignNext }),
        });
        const rc = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cert = rc.ok ? (await rc.json()).usb_vidpids || [] : [];
        const certNext = cert.filter(d => d.vidpid !== vp);
        if (certNext.length !== cert.length) {
            await fetch('/sim/api/superadmin/global-usb-vidpids', {
                method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ usb_vidpids: certNext }),
            });
        }
        if (typeof showToast === 'function') showToast(`Ignored ${vp} globally`, 'success');
        loadUsbOverview();
        loadDiscoveredUsb();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function tenantUsbAdd(tid, action) {
    const inp = document.getElementById(`tusbc-${tid}`);
    const full = (inp?.value || '').trim().toLowerCase();
    if (!_vpValid(full)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex', 'error'); return; }
    const [vid, pid] = full.split(':');
    const type = document.getElementById(`tusbt-${tid}`)?.value || 'wireless';
    await _tenantUsbPost(tid, vid, pid, action, inp, type);
}

async function tenantUsbRemove(tid, vp) {
    const [vid, pid] = vp.split(':');
    await _tenantUsbPost(tid, vid, pid, 'remove', null);
}

async function _tenantUsbPost(tid, vid, pid, action, inp, type) {
    try {
        const body = { vid, pid, action };
        if (action === 'certify' && type) body.type = type;
        await apiJson(`/sim/api/${tid}/usb-vidpids?tenant_id=${tid}`, {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (inp) inp.value = '';
        if (typeof showToast === 'function') showToast(`${action} queued for ${vid}:${pid}`, 'success');
        loadUsbOverview();
        loadDiscoveredUsb();  // keep the discovered list's local-cert badges/buttons in sync
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

// Data Cache card (Settings → General): read-only status of the hub data
// cache (core/src/warm_cache.py) — one row per cached module with its number
// of entries, oldest data age, errors, and whether users are active on it
// (refreshed every 60s while active, 5min otherwise). Refresh/Purge only.
function _cacheAge(s) {
    if (s == null) return '—';
    if (s < 90) return `${Math.round(s)}s`;
    if (s < 5400) return `${Math.round(s / 60)}m`;
    return `${Math.round(s / 3600)}h`;
}

async function loadCacheStatus() {
    const container = document.getElementById('cache-status-rows');
    if (!container) return;
    try {
        const r = await fetch('/admin/cache/status', { credentials: 'same-origin' });
        if (!r.ok) { container.innerHTML = '<p class="py-3 text-center text-xs text-red-400">Not available</p>'; return; }
        const d = await r.json();
        const rows = (d.namespaces || []).map(n => {
            const entries = n.entries || [];
            const ages = entries.map(e => e.age).filter(a => a != null);
            const oldest = ages.length ? Math.max(...ages) : null;
            const errors = entries.filter(e => e.error).length;
            const active = entries.some(e => e.active);
            const kb = n.file_bytes != null ? `${Math.max(1, Math.round(n.file_bytes / 1024))} KB` : '—';
            return `
            <tr class="border-b border-slate-100">
                <td class="py-1.5 pr-3 text-slate-700">${escapeHtml(n.namespace)}</td>
                <td class="py-1.5 pr-3 text-center">${entries.length}</td>
                <td class="py-1.5 pr-3 text-center">${_cacheAge(oldest)}</td>
                <td class="py-1.5 pr-3 text-center">${active ? '<span class="text-green-600">active</span>' : '<span class="text-slate-400">idle</span>'}</td>
                <td class="py-1.5 pr-3 text-center ${errors ? 'text-red-500' : 'text-slate-400'}">${errors}</td>
                <td class="py-1.5 pr-3 text-right text-slate-400">${kb}</td>
                <td class="py-1.5 text-right"><button class="text-xs text-[#01A982] hover:underline" onclick="refreshCacheNamespace('${escapeHtml(n.namespace)}')">Refresh</button></td>
            </tr>`;
        }).join('');
        const iv = d.intervals || {};
        container.innerHTML = `
            <p class="text-xs text-slate-500 mb-2">Every page is served from this cache. Refreshed every ${iv.active_s || 60}s while users are active, ${Math.round((iv.idle_s || 300) / 60)}m otherwise.
               Stored on disk ${d.encrypted ? 'encrypted' : '<span class="text-red-500">unencrypted</span>'} so it survives a restart.</p>
            <table class="w-full text-xs">
                <thead><tr class="text-slate-400 uppercase tracking-wider">
                    <th class="text-left py-1">Module</th><th>Entries</th><th>Oldest</th><th>Users</th><th>Errors</th><th class="text-right">Disk</th><th></th>
                </tr></thead>
                <tbody>${rows || '<tr><td colspan="7" class="py-3 text-center text-slate-400 italic">Nothing cached yet</td></tr>'}</tbody>
            </table>`;
    } catch (e) {
        if (container) container.innerHTML = `<p class="py-3 text-center text-xs text-red-400">${escapeHtml(e.message)}</p>`;
    }
}

async function refreshCacheNamespace(ns) {
    try {
        const q = ns ? `?namespace=${encodeURIComponent(ns)}` : '';
        const d = await apiJson(`/admin/cache/refresh${q}`, { method: 'POST', credentials: 'same-origin' });
        showToast(`Refreshing ${d.refreshed || 0} cached item(s)`, 'success');
        setTimeout(loadCacheStatus, 3000);
    } catch (e) {
        showToast('Refresh failed: ' + e.message, 'error');
    }
}

async function purgeAllCaches() {
    if (!await showConfirmToast('Purge all cached data and fetch it again from the spokes?')) return;
    try {
        await apiJson('/admin/cache/purge', { method: 'POST', credentials: 'same-origin' });
        showToast('Cache purged — refetching in background', 'success');
        setTimeout(loadCacheStatus, 3000);
    } catch (e) {
        showToast('Purge failed: ' + e.message, 'error');
    }
}

async function loadFirewallsList() {
    const listEl = document.getElementById('firewalls-list');
    if (!listEl) return;
    try {
        const firewalls = await loadFirewalls();
        if (firewalls.length === 0) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No firewalls configured.</p>';
            return;
        }
        listEl.innerHTML = firewalls.map(fw => `
            <div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${fw.name || fw.id}</span><span class="ml-2 text-xs text-slate-400">${fw.model} · ${fw.host || ''}:${fw.port || ''}</span></div>
                <div class="flex gap-2">
                    <button onclick="editFirewall('${fw.id}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                    <button onclick="deleteFirewallEntry('${fw.id}')" class="text-xs text-red-400 hover:text-red-600 font-medium" title="Delete this firewall entry">Delete</button>
                </div>
            </div>`).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading firewalls: ${e.message}</p>`;
    }
}

async function deleteFirewallEntry(id) {
    if (!await showConfirmToast(`Delete firewall ${id}?`)) return;
    try {
        await apiJson(`/setup/firewalls/${id}`, { method: 'DELETE' });
        loadFirewallsList();
        loadFirewalls();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}
