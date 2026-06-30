/* ============================================================================
 * sim-views.js — Native Client-Sim (Simulations) views for the LM hub.
 *
 * Replaces the former <iframe src="/sim"> integration. The 7 Simulations
 * sub-nav tabs (Simulations / Clients / Central / VM Server / API Server /
 * Config / Setup) are rendered inline into #cs-content by loadCSData(), the
 * same way opnsense/ldap/netbox render into their #*-content containers.
 *
 * Data comes from the /sim/api/* tree (lm/core/src/simulations/routes.py),
 * called directly with the same-origin lm_session cookie — no sim_shim, no
 * iframe, no global fetch override. Tenant scoping reuses the hub's
 * currentTenant global (like netbox/pxmx).
 *
 * NOTE: several /sim/api/* endpoints are still backend stubs (UI-first phase).
 * Every renderer degrades gracefully to an empty state when data is absent.
 *
 * All top-level symbols are CS-prefixed to avoid colliding with main.js globals.
 * ========================================================================== */

(function () {
'use strict';

/* ---------------------------------------------------------------------------
 * Shared helpers
 * ------------------------------------------------------------------------- */

function csEl(id) { return document.getElementById(id); }

function csSet(html) {
    const el = csEl('cs-content');
    if (el) el.innerHTML = html;
}

function csSetToolbar(html) {
    const tb = csEl('cs-add-toolbar');
    if (!tb) return;
    tb.innerHTML = html || '';
    tb.classList.toggle('hidden', !html);
}

function csEscape(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

function csTenantRaw() {
    return (typeof currentTenant !== 'undefined' && currentTenant && currentTenant !== '')
        ? currentTenant : 'default';
}
function csTenant() { return encodeURIComponent(csTenantRaw()); }

/**
 * Authenticated wrapper around the browser `fetch` for Simulations sub-module
 * REST routes under /sim/api/* (served by core/src/simulations/routes.py).
 * Credentials ride the same-origin lm_session cookie automatically, so no
 * explicit Authorization header is added; only a JSON Content-Type header is
 * set (and merged with any caller-supplied headers).
 *
 * Behavior:
 *   - 401 → calls handleSessionExpired() (main.js) and throws
 *     `Error('Session expired')`; the caller's await never continues.
 *   - 404 → throws `Error('Not implemented (404)')`; used to detect backend
 *     stubs so renderers can fall back to an empty state.
 *   - other !res.ok → attempts to parse the response body as JSON and
 *     surfaces `detail` / `message` / `error` in the thrown message
 *     (`${status} ${detail}`) so callers can show a meaningful error instead
 *     of just the status code; falls back to `${status} ${statusText}` when
 *     the body is not JSON.
 *   - res.ok → returns parsed JSON when Content-Type is application/json,
 *     otherwise the response text.
 *
 * When to use which fetch helper:
 *   - csFetch(path)    -> Simulations ONLY. Prepends `/sim/api` to `path`.
 *                         See SIM_ROUTES above for the handler→endpoint map.
 *   - setupFetch(url)  -> hub /setup/* + /api/* admin routes (main.js).
 *   - raw fetch(url)   -> public/same-origin routes needing no JSON header.
 *
 * @param {string} path    Request path relative to /sim/api (e.g.
 *                         '/aggregate/clients?tenant_id=default'). The caller
 *                         is responsible for tenant scoping (csTenant()).
 * @param {RequestInit} [opts] Standard fetch options; `headers` are merged with
 *                         the default JSON Content-Type header.
 * @returns {Promise<any>} Parsed JSON (object/array) when the response is
 *                         JSON, otherwise a string (response text).
 * @throws {Error} On 401 (session expired), 404 (not implemented), or any
 *                         non-ok status with the server's detail surfaced.
 */
async function csFetch(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    const res = await fetch('/sim/api' + path, { ...opts, headers });
    if (res.status === 401) { handleSessionExpired(); throw new Error('Session expired'); }
    if (res.status === 404) throw new Error('Not implemented (404)');
    if (!res.ok) {
        // Surface the server's JSON error detail (e.g. FastAPI's {detail: ...})
        // so the caller can show a meaningful message instead of just "409 Error".
        let detail = '';
        try {
            const j = await res.json();
            detail = (j && (j.detail || j.message || j.error)) || '';
        } catch (_e) { console.error('csFetch: error response body was not JSON, falling back to empty detail', _e); detail = ''; }
        throw new Error(detail ? `${res.status} ${detail}` : `${res.status} ${res.statusText}`);
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
}

/* ---------------------------------------------------------------------------
 * SIM_ROUTES — handler → /sim/api/* endpoint map.
 *
 * The greppable sim-endpoint table. Every csFetch(...) call in this file is
 * listed here, mapped to its HTTP method (`m`), path (`p`, with `{tenant}` /
 * `{spoke_id}` placeholders — `csFetch` prepends `/sim/api` and the real tenant
 * id is substituted at call time), and the `api` handler function in
 * core/src/simulations/routes.py. Mirror of main.js's ROUTES, scoped to the
 * Simulations sub-module. Update this table whenever you add, remove, or rename
 * a sim handler or csFetch call site.
 * ------------------------------------------------------------------------- */
const SIM_ROUTES = {
    // ── Aggregate (read-only dashboard / tab data) ──
    csSimLoadCentral:            { m: 'GET',    p: '/aggregate/central',                         api: 'get_central' },
    csRenderClients:             { m: 'GET',    p: '/aggregate/clients',                         api: 'get_clients' },
    csRenderCentral:             { m: 'GET',    p: '/aggregate/central-status',                  api: 'get_central_status' },
    csRenderCentralAlerts:       { m: 'GET',    p: '/aggregate/central',                         api: 'get_central' },
    csRenderCentralClients:      { m: 'GET',    p: '/aggregate/central',                         api: 'get_central' },
    csRenderApiServer:           { m: 'GET',    p: '/aggregate/api-server',                      api: 'get_api_server' },
    csRenderConfig:              { m: 'GET',    p: '/aggregate/proxmox',                         api: 'get_proxmox' },          // PVE info on Config tab
    csSaveConfigPush:            { m: 'POST',   p: '/aggregate/config-push',                     api: 'config_push' },
    csVmLoad:                    { m: 'GET',    p: '/aggregate/proxmox',                         api: 'get_proxmox' },
    csRenderVmServerClients:     { m: 'GET',    p: '/aggregate/clients',                         api: 'get_clients' },
    csRenderVmServerCentral:     { m: 'GET',    p: '/aggregate/central',                         api: 'get_central' },
    csSaveCentralConn:           { m: 'POST',   p: '/aggregate/central',                         api: 'save_central' },

    // ── Central (Setup → Central API tab: status + sites / available / test) ──
    csRenderSetupCentralApi:     { m: 'GET',    p: '/aggregate/central-status',                  api: 'get_central_status',
                                   m2: 'GET',   p2: '/{tenant}/central-sites-config',            api2: 'get_central_sites' },
    csLoadCentralAvailable:      { m: 'GET',    p: '/{tenant}/central/available',                api: 'get_central_available' },
    csSaveCentralSites:          { m: 'POST',   p: '/{tenant}/central-sites-config',             api: 'set_central_sites' },
    csTestCentral:               { m: 'POST',   p: '/{tenant}/test-central',                     api: 'test_central' },

    // ── Hub-config (Setup → Hub Config card) ──
    csHubConfigCard:             { m: 'GET',    p: '/tenant/{tenant}/hub-config',                api: 'get_hub_config' },
    csSaveHubConfig:             { m: 'PUT',    p: '/tenant/{tenant}/hub-config',                api: 'set_hub_config' },

    // ── Config (simulation-conf editor) ──
    csRenderConfigSimulation:    { m: 'GET',    p: '/{tenant}/config/simulation-conf',           api: 'get_sim_conf' },
    csSaveSimConfStructured:     { m: 'PUT',    p: '/{tenant}/config/simulation-conf',           api: 'put_sim_conf' },

    // ── Settings / processing-modes / notifications ──
    csProcessingModesCard:       { m: 'GET',    p: '/{tenant}/settings',                         api: 'get_settings' },
    csNotificationsCard:         { m: 'GET',    p: '/{tenant}/settings',                         api: 'get_settings' },
    csSaveProcessingModes:       { m: 'PATCH',  p: '/hub/tenants/{tenant}/processing-modes',     api: 'set_processing_mode' },
    csSaveNotifications:         { m: 'POST',   p: '/{tenant}/settings/notifications',            api: 'set_notifications' },

    // ── Settings / github ──
    csRenderSetupGithub:         { m: 'GET',    p: '/{tenant}/settings/github',                  api: 'get_github' },
    csSaveGithub:                { m: 'POST',   p: '/{tenant}/settings/github',                  api: 'set_github' },
    csClearGithub:               { m: 'DELETE', p: '/{tenant}/settings/github',                  api: 'clear_github' },

    // ── Settings / security ──
    csRenderSetupSecurity:       { m: 'GET',    p: '/{tenant}/settings/security',                api: 'get_security' },
    csSaveSecurity:              { m: 'POST',   p: '/{tenant}/settings/security',                api: 'set_security' },

    // ── Settings / troubleshooting ──
    csRenderSetupTroubleshooting:{ m: 'GET',    p: '/{tenant}/troubleshooting',                  api: 'get_troubleshooting' },

    // ── PSK (onboarding-psk; used by Setup + Spoke Mgmt cards) ──
    csPskCard:                   { m: 'GET',    p: '/tenant/{tenant}/onboarding-psk',            api: 'get_psks' },
    csGenPsk:                    { m: 'POST',   p: '/tenant/{tenant}/onboarding-psk',            api: 'gen_psk' },
    csRevokePsk:                 { m: 'DELETE', p: '/tenant/{tenant}/onboarding-psk',            api: 'revoke_psk' },
    csSpokeMgmtPskCard:          { m: 'GET',    p: '/tenant/{tenant}/onboarding-psk',            api: 'get_psks' },
    csSpokeMgmtGenPsk:           { m: 'POST',   p: '/tenant/{tenant}/onboarding-psk',            api: 'gen_psk' },
    csSpokeMgmtRevokePsk:        { m: 'DELETE', p: '/tenant/{tenant}/onboarding-psk',            api: 'revoke_psk' },

    // ── USB (provisioning status + VID/PID allow/deny) ──
    csSetupAutoProvCard:         { m: 'GET',    p: '/{tenant}/usb-provisioning-status',          api: 'cs_usb_provisioning_status' },
    csRefreshAutoProvStatus:     { m: 'GET',    p: '/{tenant}/usb-provisioning-status',          api: 'cs_usb_provisioning_status' },
    csUsbVidpid:                 { m: 'POST',   p: '/{tenant}/usb-vidpids',                      api: 'cs_usb_vidpids' },

    // ── Fleet (reclone / auto-provision toggle / update-all) ──
    csFleetReclone:              { m: 'POST',   p: '/{tenant}/fleet-reclone',                    api: 'cs_fleet_reclone' },
    csToggleAutoProvision:       { m: 'POST',   p: '/{tenant}/toggle-auto-provision',            api: 'cs_toggle_auto_provision' },
    csUpdateAll:                 { m: 'POST',   p: '/{tenant}/update-all',                       api: 'cs_update_all' },

    // ── VM actions (per-spoke proxmox-command + proxmx command queue) ──
    csVmAction:                  { m: 'POST',   p: '/{tenant}/spokes/{spoke_id}/proxmox-command',api: 'cs_spoke_proxmox_command' },
    csVmBulk:                    { m: 'POST',   p: '/{tenant}/spokes/{spoke_id}/proxmox-command',api: 'cs_spoke_proxmox_command' },
    csRenderVmServerQueue:       { m: 'GET',    p: '/{tenant}/proxmx/commands',                  api: 'cs_list_commands' },
    csSendCommand:               { m: 'POST',   p: '/{tenant}/proxmx/command',                   api: 'cs_enqueue_command' },
    csClearCommands:             { m: 'DELETE', p: '/{tenant}/proxmx/commands',                  api: 'cs_clear_commands' },

    // ── Spoke management ──
    csRenderSpokeManagement:     { m: 'GET',    p: '/spokes',                                    api: 'get_spokes_list' },
    csSpokeApprove:              { m: 'POST',   p: '/{tenant}/spokes/{spoke_id}/approve',        api: 'cs_spoke_approve' },
    csSpokeEditLabel:            { m: 'PATCH',  p: '/{tenant}/spokes/{spoke_id}/label',          api: 'cs_spoke_set_label' },
    csSpokePatchConfig:          { m: 'PATCH',  p: '/{tenant}/spokes/{spoke_id}/config',         api: 'cs_spoke_patch_config' },
    csSpokeDiag:                 { m: 'GET',    p: '/{tenant}/spokes/{spoke_id}/config-diag',    api: 'cs_spoke_config_diag' },
    csSpokeDelete:               { m: 'DELETE', p: '/spokes/{spoke_id}',                         api: 'cs_spoke_delete' },
    csClaimSpoke:                { m: 'POST',   p: '/tenant/{tenant}/spokes/{spoke_id}/claim',   api: 'claim_spoke' },
};

function csLoading(label) {
    csSetToolbar('');
    csSet(`<div class="py-16 text-center text-slate-400 italic">${csEscape(label || 'Loading…')}</div>`);
}

function csEmpty(msg, hint) {
    return `<div class="py-16 text-center">
      <p class="text-slate-500 text-sm">${csEscape(msg)}</p>
      ${hint ? `<p class="text-slate-400 text-xs mt-2">${csEscape(hint)}</p>` : ''}
    </div>`;
}

function csErrorBox(label, err) {
    const msg = (err && err.message) ? err.message : String(err);
    const stub = /404|Not implemented/i.test(msg);
    return `<div class="py-10 text-center">
      <p class="text-sm font-semibold text-slate-600">${csEscape(label)}</p>
      <p class="text-xs mt-2 ${stub ? 'text-slate-400' : 'text-red-500'}">${csEscape(msg)}${stub ? ' — this endpoint is not wired in the backend yet (UI-first phase).' : ''}</p>
    </div>`;
}

function csOnlineBadge(online) {
    return online
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-green-100 text-green-700 text-[10px] font-bold uppercase tracking-wider"><span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>Online</span>`
        : `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-bold uppercase tracking-wider"><span class="w-1.5 h-1.5 rounded-full bg-slate-400"></span>Offline</span>`;
}

function csStatusBadge(status) {
    const s = String(status || 'unknown').toLowerCase();
    const map = {
        pass: 'bg-green-100 text-green-700', ok: 'bg-green-100 text-green-700', functional: 'bg-green-100 text-green-700',
        fail: 'bg-red-100 text-red-700', failed: 'bg-red-100 text-red-700',
        warning: 'bg-amber-100 text-amber-700', degraded: 'bg-amber-100 text-amber-700',
        no_data: 'bg-slate-100 text-slate-500', unknown: 'bg-slate-100 text-slate-500'
    };
    const cls = map[s] || 'bg-slate-100 text-slate-500';
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cls}">${csEscape(s)}</span>`;
}

function csTable(headers, rowsHtml, opts = {}) {
    const ths = headers.map(h => `<th class="px-4 py-2 text-left font-semibold">${csEscape(h)}</th>`).join('');
    return `<div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="bg-slate-50 text-slate-500 uppercase text-xs tracking-wider">${ths}</thead>
        <tbody class="divide-y divide-slate-100">${rowsHtml || `<tr><td class="px-4 py-8 text-center text-slate-400 italic" colspan="${headers.length}">No data.</td></tr>`}</tbody>
      </table>
    </div>`;
}

function csJsonDump(obj) {
    return `<pre class="text-xs bg-slate-50 border border-slate-200 rounded-md p-3 overflow-auto max-h-64 mt-2">${csEscape(JSON.stringify(obj, null, 2))}</pre>`;
}

/* ---------------------------------------------------------------------------
 * Telemetry WebSocket (mirror of the CS app's connectHubWebSocket)
 * ------------------------------------------------------------------------- */

let csWs = null, csWsReconnect = null, csWsRefreshTimer = null;

function connectCSWebSocket() {
    if (typeof currentView === 'undefined' || currentView !== 'cs') return;
    if (csWs && (csWs.readyState === WebSocket.OPEN || csWs.readyState === WebSocket.CONNECTING)) return;
    try {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        csWs = new WebSocket(`${proto}//${location.host}/sim/ws`);
        csWs.onmessage = (ev) => {
            let m; try { m = JSON.parse(ev.data); } catch (e) { console.error('connectCSWebSocket: non-JSON telemetry frame ignored', e); return; }
            if (m && (m.type === 'telemetry' || m.type === 'aruba_update')) csWsRefresh();
        };
        csWs.onclose = () => { csWs = null; scheduleCSReconnect(); };
        csWs.onerror = () => { try { csWs && csWs.close(); } catch (e) { console.error('connectCSWebSocket: error closing ws on onerror', e); } };
    } catch (e) { console.error('connectCSWebSocket: ws open failed, scheduling reconnect', e); csWs = null; scheduleCSReconnect(); }
}

function scheduleCSReconnect() {
    if (csWsReconnect) return;
    csWsReconnect = setTimeout(() => {
        csWsReconnect = null;
        if (typeof currentView !== 'undefined' && currentView === 'cs') connectCSWebSocket();
    }, 5000);
}

function disconnectCSWebSocket() {
    if (csWsReconnect) { clearTimeout(csWsReconnect); csWsReconnect = null; }
    if (csWsRefreshTimer) { clearTimeout(csWsRefreshTimer); csWsRefreshTimer = null; }
    if (csWs) { try { csWs.close(); } catch (e) { console.error('disconnectCSWebSocket: error closing ws', e); } csWs = null; }
}

function csWsRefresh() {
    if (typeof currentView === 'undefined' || currentView !== 'cs') return;
    if (csWsRefreshTimer) return; // debounce
    csWsRefreshTimer = setTimeout(() => {
        csWsRefreshTimer = null;
        loadCSData(currentSubView, currentSubChild, true);
    }, 1500);
}

/* ---------------------------------------------------------------------------
 * Dispatcher — called from main.js setSubView / initView + the Refresh button
 * ------------------------------------------------------------------------- */

async function loadCSData(subMenu, child, force) {
    const menu = subMenu || (typeof currentSubView !== 'undefined' ? currentSubView : 'Dashboard');
    // Resolve the active child for two-tier primaries. A primary with no
    // children (per VIEW_CHILDREN) ignores child entirely and renders its
    // primary view; a primary WITH children defaults to its first child.
    const kids = (typeof VIEW_CHILDREN !== 'undefined' && VIEW_CHILDREN.cs && VIEW_CHILDREN.cs[menu]) || null;
    let c = (child !== undefined && child !== null && child !== '') ? child
            : (typeof currentSubChild !== 'undefined' ? currentSubChild : '');
    if (!kids) c = '';
    else if (!c) c = kids[0];

    csLoading(`Loading ${menu}${c ? ' · ' + c : ''}…`);
    try {
        // Registered child renderer (waves register these as they land).
        const r = window.CS_CHILD_RENDERERS && CS_CHILD_RENDERERS[menu + '::' + c];
        if (c && r) {
            await r(force);
        } else if (c && kids && c !== kids[0]) {
            // A non-default child that hasn't been ported yet — show a clear
            // "in progress" card instead of silently re-rendering the primary.
            csChildPlaceholder(menu, c);
        } else {
            switch (menu) {
                case 'Dashboard': await csRenderSimulations(force); break;
                case 'Clients':     await csRenderClients(force); break;
                case 'Central':     await csRenderCentral(force); break;
                case 'API Server':  await csRenderApiServer(force); break;
                case 'Config':      await csRenderConfig(force); break;
                case 'Setup':       await csRenderSetup(force); break;
                case 'VM Server':   await csRenderVmServer(force); break;
                case 'Spoke Management': await csRenderSpokeManagement(force); break;
                default:            csSet(csEmpty('Unknown Simulations view.'));
            }
        }
    } catch (err) {
        console.error(`loadCSData: could not load ${menu}:`, err);
        csSet(csErrorBox(`Could not load ${menu}`, err));
    }
    connectCSWebSocket();
}

// Per-child render registry. Waves populate this as each child view is ported:
//   CS_CHILD_RENDERERS['VM Server::VMs'] = csRenderVmServerVms;
// Keys are `${primary}::${child}`. An unregistered child falls back to the
// primary renderer (default child) or a placeholder (non-default child) above.
window.CS_CHILD_RENDERERS = window.CS_CHILD_RENDERERS || {};

// Placeholder for a child tab whose port is scheduled in a later wave. Keeps
// the two-tier nav structure fully visible without breaking working primaries.
function csChildPlaceholder(primary, child) {
    csSetToolbar('');
    csSet(`<div class="max-w-2xl mx-auto mt-10">
        <div class="hpe-card rounded-lg p-8 shadow-sm text-center">
            <div class="text-3xl mb-3">🚧</div>
            <h3 class="text-lg font-bold text-slate-700 mb-1">${csEscape(primary)} · ${csEscape(child)}</h3>
            <p class="text-sm text-slate-500">This section is part of the ongoing webui-hub → cs module port and will be populated in a coming wave. The structure is in place so the navigation matches the original.</p>
        </div>
    </div>`);
}
// Exposed globally (main.js / onclick refer to loadCSData).
window.loadCSData = loadCSData;
window.connectCSWebSocket = connectCSWebSocket;
window.disconnectCSWebSocket = disconnectCSWebSocket;

/* ===========================================================================
 * 1. Simulations — checks / hardware / client-count
 *    GET /sim/api/aggregate/central?tenant_id={T}
 * ========================================================================= */

// Simulations → default child is 'Checks'. Children: Checks / Hardware / Client Count.
// All three read aggregate/central and render one dimension across spokes.
async function csSimLoadCentral() {
    try { return await csFetch(`/aggregate/central?tenant_id=${csTenant()}`) || {}; }
    catch (e) { console.error('csSimLoadCentral: aggregate/central fetch failed (likely 404/stub)', e); csSetToolbar(''); csSet(csEmpty('No simulation data yet.',
        'The /sim/api/aggregate/central endpoint is not wired in the backend yet (UI-first phase).')); return null; }
}

function csSimSpokes(data) {
    const spokes = (data && data.spokes) || [];
    if (spokes.length === 0) {
        csSetToolbar(''); csSet(csEmpty('No spokes reporting simulation data yet.',
            'Once spokes check in, their sim checks, hardware alerts, and client counts will appear here.'));
        return null;
    }
    return spokes;
}

function csCheckBuckets(st) {
    // st ∈ {'OK','ERROR','WARN','UNKNOWN',...} → bucket label
    const s = String(st || '').toUpperCase();
    if (s === 'OK' || s === 'PASS' || s === 'FUNCTIONAL') return 'functional';
    if (s === 'ERROR' || s === 'FAIL' || s === 'CRITICAL') return 'failing';
    if (s === 'WARN' || s === 'WARNING') return 'warning';
    return 'unknown';
}

async function csRenderSimulations() {
    // Simulations → Checks child (default).
    csSetToolbar('');
    const data = await csSimLoadCentral();
    const spokes = csSimSpokes(data);
    if (!spokes) return;
    // Collect the universe of check ids + per-bucket counts.
    const checkIds = new Set();
    let bf = 0, bw = 0, bo = 0;
    spokes.forEach(s => {
        const sm = (s.central_status && s.central_status.status) || {};
        Object.keys(sm).forEach(w => Object.keys(sm[w]).forEach(c => {
            checkIds.add(c);
            const b = csCheckBuckets(sm[w][c] && sm[w][c].status);
            if (b === 'failing') bf++; else if (b === 'warning') bw++; else if (b === 'functional') bo++;
        }));
    });
    const ids = Array.from(checkIds).sort();
    csSetToolbar(`<input id="cs-sim-q" oninput="csSimChecksFilter()" placeholder="Filter by site or check…" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-72">
      <select id="cs-sim-bucket" onchange="csSimChecksFilter()" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500">
        <option value="">All buckets</option><option value="failing">Failing</option><option value="warning">Warning</option><option value="functional">Functional</option><option value="unknown">Unknown</option>
      </select>`);
    const pills = csSummaryRow([[spokes.length, 'Spokes'], [ids.length, 'Checks'], [bf, 'Failing'], [bw, 'Warning']]);
    // Build a flat row per (spoke, site, check) for filtering.
    window._csSimCheckRows = [];
    spokes.forEach(s => {
        const sm = (s.central_status && s.central_status.status) || {};
        const name = s.spoke_name || s.spoke_id;
        Object.keys(sm).forEach(w => Object.keys(sm[w]).forEach(c => {
            const cell = sm[w][c];
            window._csSimCheckRows.push({ spoke: name, site: w, check: c, status: cell && cell.status, detail: cell });
        }));
    });
    csSet(`<div class="space-y-4">${pills}<div id="cs-sim-checks-body"></div></div>`);
    csSimChecksFilter();
}

window.csSimChecksFilter = function () {
    const q = (csEl('cs-sim-q') && csEl('cs-sim-q').value || '').toLowerCase();
    const bucket = csEl('cs-sim-bucket') && csEl('cs-sim-bucket').value;
    const rows = (window._csSimCheckRows || []).filter(r => {
        if (bucket && csCheckBuckets(r.status) !== bucket) return false;
        if (!q) return true;
        return (r.spoke + ' ' + r.site + ' ' + r.check).toLowerCase().includes(q);
    });
    const body = csEl('cs-sim-checks-body');
    if (!rows.length) { body.innerHTML = csEmpty('No checks match.', 'Adjust the filter above.'); return; }
    const rh = rows.map(r => `<tr>
      <td class="px-3 py-2 text-sm">${csEscape(r.spoke)}</td>
      <td class="px-3 py-2 font-mono text-xs text-slate-600">${csEscape(r.site)}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(r.check)}</td>
      <td class="px-3 py-2">${csStatusBadge(r.status)}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${csEscape((r.detail && (r.detail.message || r.detail.last_error)) || '—')}</td>
    </tr>`).join('');
    body.innerHTML = csTable(['Spoke', 'Site', 'Check', 'Status', 'Detail'], rh);
};

async function csRenderSimHardware() {
    csSetToolbar('');
    const data = await csSimLoadCentral();
    const spokes = csSimSpokes(data);
    if (!spokes) return;
    let total = 0;
    spokes.forEach(s => { (((s.central_status || {}).hardware_alerts) || []).forEach(a => { total += a.total || 0; }); });
    const pills = csSummaryRow([[spokes.length, 'Spokes'], [total, 'Alerts'], [data.mode || '—', 'Mode']]);
    const cards = spokes.map(s => {
        const hw = ((s.central_status || {}).hardware_alerts) || [];
        let html;
        if (!hw.length) html = `<p class="text-xs text-slate-400 italic">No hardware alerts.</p>`;
        else {
            const rows = hw.map(a => `<tr>
              <td class="px-3 py-2">${csEscape(a.name || a.id)}</td>
              <td class="px-3 py-2">${csEscape(a.device_type || '—')}</td>
              <td class="px-3 py-2 font-bold ${a.total > 0 ? 'text-amber-600' : 'text-slate-500'}">${csEscape(a.total || 0)}</td>
            </tr>`).join('');
            html = csTable(['Check', 'Type', 'Alerts'], rows);
        }
        return `<details class="hpe-card rounded-lg p-0 shadow-sm overflow-hidden">
          <summary class="flex items-center justify-between px-5 py-3 cursor-pointer hover:bg-slate-50">
            <span class="font-bold text-slate-700">${csEscape(s.spoke_name || s.spoke_id)}</span>${csOnlineBadge(s.spoke_online)}
          </summary>
          <div class="px-5 pb-5 border-t border-slate-100">${html}</div>
        </details>`;
    }).join('');
    csSet(`<div class="space-y-4">${pills}${cards}</div>`);
}

async function csRenderSimClientCount() {
    csSetToolbar('');
    const data = await csSimLoadCentral();
    const spokes = csSimSpokes(data);
    if (!spokes) return;
    let sites = 0, cur = 0;
    spokes.forEach(s => {
        const cc = (s.central_status && s.central_status.client_count_status) || {};
        Object.keys(cc).forEach(w => { sites++; cur += (cc[w] && cc[w].current) || 0; });
    });
    const pills = csSummaryRow([[spokes.length, 'Spokes'], [sites, 'Sites'], [cur, 'Current Clients'], [data.mode || '—', 'Mode']]);
    const cards = spokes.map(s => {
        const cc = (s.central_status && s.central_status.client_count_status) || {};
        const ccSites = Object.keys(cc);
        let html;
        if (!ccSites.length) html = `<p class="text-xs text-slate-400 italic">No client-count data.</p>`;
        else {
            const rows = ccSites.map(w => {
                const c = cc[w] || {};
                return `<tr>
                  <td class="px-3 py-2 font-mono text-xs text-slate-600">${csEscape(c.site_name || w)}</td>
                  <td class="px-3 py-2">${csStatusBadge(c.status)}</td>
                  <td class="px-3 py-2 font-bold text-slate-700">${csEscape(c.current || 0)}</td>
                  <td class="px-3 py-2 text-slate-500">${csEscape(c.hourly_avg != null ? c.hourly_avg : '—')}</td>
                  <td class="px-3 py-2 ${c.drop_pct > 0 ? 'text-amber-600' : 'text-slate-500'}">${csEscape(c.drop_pct != null ? c.drop_pct + '%' : '—')}</td>
                </tr>`;
            }).join('');
            html = csTable(['Site', 'Status', 'Current', 'Hourly Avg', 'Drop %'], rows);
        }
        return `<details class="hpe-card rounded-lg p-0 shadow-sm overflow-hidden">
          <summary class="flex items-center justify-between px-5 py-3 cursor-pointer hover:bg-slate-50">
            <span class="font-bold text-slate-700">${csEscape(s.spoke_name || s.spoke_id)}</span>${csOnlineBadge(s.spoke_online)}
          </summary>
          <div class="px-5 pb-5 border-t border-slate-100">${html}</div>
        </details>`;
    }).join('');
    csSet(`<div class="space-y-4">${pills}${cards}</div>`);
}

function csStat(label, value) {
    return `<div class="bg-slate-50 rounded-lg p-3 text-center">
      <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest">${csEscape(label)}</p>
      <div class="text-xl font-bold text-slate-700 mt-1">${csEscape(value)}</div>
    </div>`;
}

// USB dongle count for a host — the number of physical dongles, NOT the number
// of distinct VID:PID types. The pxmx agent's cs_usb_telemetry scans
// /sys/bus/usb/devices and emits one entry PER PHYSICAL DEVICE under
// proxmox.present_usb (certified) and proxmox.unknown_usb (uncertified) — keyed
// by bus_path, NOT deduped by vidpid — and drops ignored vidpids entirely. So
// present_usb.length + unknown_usb.length IS the physical dongle count (ignored
// dongles excluded). proxmox.usb_state is only the ASSIGNED-dongle subset (built
// from bus_to_vmid), so it undercounts and must not be used for totals. This
// matches VM Server/USB (csRenderVmServerUsb), which the user confirmed correct.
function csUsbCount(h) {
    const px = (h && h.proxmox) || {};
    return (Array.isArray(px.present_usb) ? px.present_usb.length : 0)
         + (Array.isArray(px.unknown_usb) ? px.unknown_usb.length : 0);
}

// Trim a Proxmox version string to just the version number (e.g. "8.1.4"),
// dropping the "pve-manager" prefix and the build id the cs spoke appends
// (e.g. "pve-manager: 8.1.4/abc12345" → "8.1.4").
function csPveVersion(v) {
    const s = String(v || '').trim();
    if (!s || s === '—') return '—';
    const m = s.match(/\d+(?:\.\d+)+/);
    return m ? m[0] : s;
}

// Compact inline stat row — "<b>N</b> Label <b>N</b> Label …" — the overview
// header style used by VM Server, Spoke Management, Clients, and the Simulations
// sub-views. `items` is a list of [value, label] pairs.
function csSummaryRow(items) {
    return `<div class="flex flex-wrap items-center gap-x-4 gap-y-1 mb-3 text-xs text-slate-500">
      ${items.map(([v, label]) => `<span><b class="text-sm text-slate-700">${csEscape(v)}</b> ${csEscape(label)}</span>`).join('')}
    </div>`;
}

function csSimSpokeCard(s) {
    const cs = s.central_status || {};
    const statusMap = cs.status || {};
    const hwAlerts = cs.hardware_alerts || [];
    const ccStatus = cs.client_count_status || {};
    const name = s.spoke_name || s.spoke_id || 'spoke';

    // Checks: site × check status table
    const sites = Object.keys(statusMap);
    let checksHtml;
    if (sites.length === 0) {
        checksHtml = `<p class="text-xs text-slate-400 italic">No check status reported.</p>`;
    } else {
        const allChecks = new Set();
        sites.forEach(w => Object.keys(statusMap[w]).forEach(c => allChecks.add(c)));
        const checkIds = Array.from(allChecks);
        const header = ['Site', ...checkIds].map(h => `<th class="px-3 py-2 text-left">${csEscape(h)}</th>`).join('');
        const rows = sites.map(w => {
            const cells = checkIds.map(c => {
                const st = statusMap[w][c];
                return `<td class="px-3 py-2">${st ? csStatusBadge(st.status) : '<span class="text-slate-300">—</span>'}</td>`;
            }).join('');
            return `<tr><td class="px-3 py-2 font-mono text-xs text-slate-600">${csEscape(w)}</td>${cells}</tr>`;
        }).join('');
        checksHtml = csTable(['Site', ...checkIds], rows);
    }

    // Hardware alerts
    let hwHtml;
    if (hwAlerts.length === 0) {
        hwHtml = `<p class="text-xs text-slate-400 italic">No hardware alerts.</p>`;
    } else {
        const rows = hwAlerts.map(a => `<tr>
          <td class="px-3 py-2">${csEscape(a.name || a.id)}</td>
          <td class="px-3 py-2">${csEscape(a.device_type || '—')}</td>
          <td class="px-3 py-2 font-bold ${a.total > 0 ? 'text-amber-600' : 'text-slate-500'}">${csEscape(a.total || 0)}</td>
        </tr>`).join('');
        hwHtml = csTable(['Check', 'Type', 'Alerts'], rows);
    }

    // Client count
    let ccHtml;
    const ccSites = Object.keys(ccStatus);
    if (ccSites.length === 0) {
        ccHtml = `<p class="text-xs text-slate-400 italic">No client-count data.</p>`;
    } else {
        const rows = ccSites.map(w => {
            const c = ccStatus[w] || {};
            return `<tr>
              <td class="px-3 py-2 font-mono text-xs text-slate-600">${csEscape(c.site_name || w)}</td>
              <td class="px-3 py-2">${csStatusBadge(c.status)}</td>
              <td class="px-3 py-2 font-bold text-slate-700">${csEscape(c.current || 0)}</td>
              <td class="px-3 py-2 text-slate-500">${csEscape(c.hourly_avg != null ? c.hourly_avg : '—')}</td>
              <td class="px-3 py-2 ${c.drop_pct > 0 ? 'text-amber-600' : 'text-slate-500'}">${csEscape(c.drop_pct != null ? c.drop_pct + '%' : '—')}</td>
            </tr>`;
        }).join('');
        ccHtml = csTable(['Site', 'Status', 'Current', 'Hourly Avg', 'Drop %'], rows);
    }

    return `<details class="hpe-card rounded-lg p-0 shadow-sm overflow-hidden" open>
      <summary class="flex items-center justify-between px-5 py-3 cursor-pointer hover:bg-slate-50">
        <span class="font-bold text-slate-700">${csEscape(name)}</span>
        ${csOnlineBadge(s.spoke_online)}
      </summary>
      <div class="px-5 pb-5 space-y-4 border-t border-slate-100">
        <div><p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Checks</p>${checksHtml}</div>
        <div><p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Hardware Alerts</p>${hwHtml}</div>
        <div><p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Client Count</p>${ccHtml}</div>
      </div>
    </details>`;
}

/* ===========================================================================
 * 2. Clients — filterable table
 *    GET /sim/api/aggregate/clients?tenant_id={T}
 * ========================================================================= */

let csClientCache = [];
let csClientTier = 'all'; // 'all' | 't1' | 't2'

// T1 = no USB passthrough; T2 = USB dongle passthrough (reclone bus / has_usb).
// Mirrors webui-hub classifyClient (app.js:2275). Falls back to t1 when no signal.
function csClassifyClient(c) {
    if (!c) return 't1';
    if (c.tier === 't2' || c.tier === 't1') return c.tier;
    if (c.has_usb === true) return 't2';
    if (c.has_usb === false) return 't1';
    if (c.vm_type === 't2' || c.client_type === 't2') return 't2';
    if (c.reclone_bus_path || c.bus_path) return 't2';
    return 't1';
}

async function csRenderClients(tier) {
    // tier may come in as a boolean `force` arg from the legacy primary-switch
    // fallback; only accept real tier strings.
    if (tier === 't1' || tier === 't2' || tier === 'all') csClientTier = tier;
    csSetToolbar(`<input id="cs-client-search" oninput="csClientFilter()" placeholder="Search clients…" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-64">
      <select id="cs-client-status" onchange="csClientFilter()" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500">
        <option value="">All</option><option value="online">Online</option><option value="offline">Offline</option>
      </select>`);
    const data = await csFetch(`/aggregate/clients?tenant_id=${csTenant()}`);
    const rows = csNormalizeClients(data);
    csClientCache = rows;
    const all = rows.length;
    const t1 = rows.filter(c => csClassifyClient(c) === 't1').length;
    const t2 = rows.filter(c => csClassifyClient(c) === 't2').length;
    const online = rows.filter(c => c.online).length;
    const pills = csSummaryRow([[all, 'Clients'], [t1, 'T1'], [t2, 'T2'], [online, 'Online']]);
    csSet(`<div class="space-y-4">${pills}<div id="cs-client-body"></div></div>`);
    csClientFilter();
}

function csNormalizeClients(data) {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.clients)) return data.clients;
    if (Array.isArray(data.rows)) return data.rows;
    return [];
}

function csRenderClientRows(rows) {
    const body = csEl('cs-client-body') || csEl('cs-content');
    if (!rows || rows.length === 0) {
        body.innerHTML = csEmpty('No clients reported.',
            'Connected client simulators will appear here once spokes check in.');
        return;
    }
    const rowHtml = rows.map(c => {
        const sims = Array.isArray(c.active_simulations) ? c.active_simulations.join(', ') : (c.simulation_id || '—');
        const t = csClassifyClient(c);
        return `<tr>
          <td class="px-4 py-2 text-slate-600">${csEscape(c.spoke_name || c.spoke_id || '—')}</td>
          <td class="px-4 py-2 font-mono text-xs">${csEscape(c.hostname || c.id || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.platform || c.hw_type || '—')}</td>
          <td class="px-4 py-2">${csOnlineBadge(c.online)}</td>
          <td class="px-4 py-2"><span class="text-[10px] font-bold px-2 py-0.5 rounded ${t === 't2' ? 'bg-purple-100 text-purple-700' : 'bg-slate-100 text-slate-600'}">${t.toUpperCase()}</span></td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.connected_ssid || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(sims)}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.last_seen || '—')}</td>
          <td class="px-4 py-2 ${c.error_count > 0 ? 'text-amber-600 font-bold' : 'text-slate-400'}">${csEscape(c.error_count || 0)}</td>
        </tr>`;
    }).join('');
    body.innerHTML = csTable(
        ['Spoke', 'Hostname', 'Platform', 'Status', 'Tier', 'SSID', 'Simulations', 'Last Seen', 'Errors'],
        rowHtml
    );
}

window.csClientFilter = function () {
    const q = (csEl('cs-client-search') && csEl('cs-client-search').value || '').toLowerCase();
    const st = csEl('cs-client-status') && csEl('cs-client-status').value;
    const filtered = csClientCache.filter(c => {
        if (csClientTier !== 'all' && csClassifyClient(c) !== csClientTier) return false;
        if (st === 'online' && !c.online) return false;
        if (st === 'offline' && c.online) return false;
        if (!q) return true;
        const hay = [c.spoke_name, c.spoke_id, c.hostname, c.id, c.connected_ssid, c.simulation_id, c.platform]
            .filter(Boolean).join(' ').toLowerCase();
        return hay.includes(q);
    });
    csRenderClientRows(filtered);
};

/* ===========================================================================
 * 3. Central — sites / alerts / clients + save form
 *    GET /sim/api/aggregate/central-status?tenant_id={T}
 *    POST /sim/api/aggregate/central  {mode, hub_central_config}
 * ========================================================================= */

async function csRenderCentral() {
    // Central → Sites child (default). Config form moved to Setup → Central API.
    csSetToolbar('');
    let data = {};
    try { data = await csFetch(`/aggregate/central-status?tenant_id=${csTenant()}`); } catch (e) { console.error('csRenderCentral: aggregate/central-status fetch failed (may be 404/stub)', e); }
    const spokes = (data && data.spokes) || [];
    const mode = data.mode || '—';
    const tokenValid = data.token_valid;
    const banner = `<div class="flex items-center gap-3 mb-4">
      <span class="text-xs text-slate-500">Mode: <b class="text-slate-700">${csEscape(mode)}</b></span>
      <span class="text-xs text-slate-500">Token: ${tokenValid === undefined ? '<span class="text-slate-400">unknown</span>' : (tokenValid ? '<span class="text-green-600 font-bold">valid</span>' : '<span class="text-red-500 font-bold">invalid</span>')}</span>
    </div>`;
    let sitesHtml;
    if (spokes.length === 0) {
        sitesHtml = csEmpty('No central site data yet.', 'Configure Central API in Setup → Central API and spokes will report site status.');
    } else {
        sitesHtml = spokes.map(sp => {
            const sites = sp.sites || [];
            const rows = sites.map(st => `<tr>
              <td class="px-3 py-2 font-mono text-xs">${csEscape(st.wsite)}</td>
              <td class="px-3 py-2 text-slate-500">${csEscape(st.central_site || '—')}</td>
              <td class="px-3 py-2 text-green-600">${csEscape(st.check_ok || 0)}</td>
              <td class="px-3 py-2 text-red-500">${csEscape(st.check_fail || 0)}</td>
              <td class="px-3 py-2 text-slate-400">${csEscape(st.check_unknown || 0)}</td>
              <td class="px-3 py-2 font-bold text-slate-700">${csEscape(st.wireless_clients || 0)}</td>
            </tr>`).join('');
            return `<div class="hpe-card rounded-lg p-4 shadow-sm">
              <div class="flex justify-between items-center mb-2"><span class="font-bold text-slate-700">${csEscape(sp.spoke_name || sp.spoke_id)}</span>${csOnlineBadge(sp.spoke_online)}</div>
              ${csTable(['Site', 'Central Site', 'OK', 'Fail', 'Unknown', 'Clients'], rows)}
            </div>`;
        }).join('');
    }
    csSet(`<div class="space-y-4">${banner}${sitesHtml}</div>`);
}

// ── Central → Alerts ─────────────────────────────────────────────────────────
async function csRenderCentralAlerts() {
    csSetToolbar('');
    let data = {};
    try { data = await csFetch(`/aggregate/central?tenant_id=${csTenant()}`); } catch (e) { console.error('csRenderCentralAlerts: aggregate/central fetch failed', e); }
    const spokes = (data && data.spokes) || [];
    if (!spokes.length) { csSet(csEmpty('No central alert data yet.')); return; }
    const cards = spokes.map(sp => {
        const c = sp.central_status || sp.central || {};
        const alerts = c.central_alerts || c.hardware_alerts || [];
        const rows = alerts.map(a => `<tr>
          <td class="px-3 py-2 text-sm">${csEscape(a.site || a.name || '—')}</td>
          <td class="px-3 py-2">${csStatusBadge(a.severity || a.level || 'warning')}</td>
          <td class="px-3 py-2 text-slate-500 text-xs">${csEscape(a.message || a.detail || '—')}</td>
        </tr>`).join('');
        return `<div class="hpe-card rounded-lg p-4 shadow-sm">
          <div class="flex justify-between items-center mb-2"><span class="font-bold text-slate-700">${csEscape(sp.spoke_name || sp.spoke_id)}</span><span class="text-xs text-slate-400">${csEscape((alerts.length))} alert(s)</span></div>
          ${csTable(['Site', 'Severity', 'Message'], rows)}
        </div>`;
    }).join('');
    csSet(`<div class="space-y-4">${cards}</div>`);
}

// ── Central → Clients ────────────────────────────────────────────────────────
async function csRenderCentralClients() {
    csSetToolbar('');
    let data = {};
    try { data = await csFetch(`/aggregate/central?tenant_id=${csTenant()}`); } catch (e) { console.error('csRenderCentralClients: aggregate/central fetch failed', e); }
    const spokes = (data && data.spokes) || [];
    if (!spokes.length) { csSet(csEmpty('No central client data yet.')); return; }
    const cards = spokes.map(sp => {
        const c = sp.central_status || sp.central || {};
        const clients = c.central_clients || [];
        const rows = clients.map(cl => `<tr>
          <td class="px-3 py-2 text-sm">${csEscape(cl.name || cl.hostname || cl.mac || '—')}</td>
          <td class="px-3 py-2 font-mono text-xs">${csEscape(cl.ip || cl.ipaddr || '—')}</td>
          <td class="px-3 py-2 text-slate-500">${csEscape(cl.site || '—')}</td>
          <td class="px-3 py-2">${csStatusBadge(cl.status || 'unknown')}</td>
        </tr>`).join('');
        return `<div class="hpe-card rounded-lg p-4 shadow-sm">
          <div class="flex justify-between items-center mb-2"><span class="font-bold text-slate-700">${csEscape(sp.spoke_name || sp.spoke_id)}</span><span class="text-xs text-slate-400">${csEscape(c.wireless_clients || 0)} wireless</span></div>
          ${csTable(['Client', 'IP', 'Site', 'Status'], rows)}
        </div>`;
    }).join('');
    csSet(`<div class="space-y-4">${cards}</div>`);
}

window.CS_CHILD_RENDERERS['Central::Sites']  = csRenderCentral;
window.CS_CHILD_RENDERERS['Central::Alerts'] = csRenderCentralAlerts;
window.CS_CHILD_RENDERERS['Central::Clients'] = csRenderCentralClients;

/* ===========================================================================
 * 4. API Server — read-only per-spoke cards
 *    GET /sim/api/aggregate/api-server?tenant_id={T}
 * ========================================================================= */

async function csRenderApiServer() {
    csSetToolbar('');
    let data = null;
    try { data = await csFetch(`/aggregate/api-server?tenant_id=${csTenant()}`); }
    catch (e) { console.error('csRenderApiServer: aggregate/api-server fetch failed', e); csSet(csEmpty('No API server data yet.',
        'The /sim/api/aggregate/api-server endpoint is not wired in the backend yet (UI-first phase).')); return; }
    const spokes = (data && data.spokes) || [];
    if (spokes.length === 0) { csSet(csEmpty('No API server data yet.')); return; }
    const cards = spokes.map(sp => {
        const a = sp.api_server || {};
        const h = a.health || {};
        const services = a.services || {};
        const svcRows = Object.keys(services).map(k => `<tr>
          <td class="px-3 py-1.5 font-mono text-xs">${csEscape(k)}</td>
          <td class="px-3 py-1.5">${csStatusBadge(typeof services[k] === 'string' ? services[k] : (services[k] && services[k].status) || 'unknown')}</td>
        </tr>`).join('');
        return `<details class="hpe-card rounded-lg p-0 shadow-sm overflow-hidden">
          <summary class="flex items-center justify-between px-5 py-3 cursor-pointer hover:bg-slate-50">
            <span class="font-bold text-slate-700">${csEscape(sp.spoke_name || sp.spoke_hostname || sp.spoke_id)}</span>
            <span class="flex items-center gap-2">${csOnlineBadge(sp.spoke_online)}<span class="text-xs text-slate-400">${csEscape(h.version || a.version || '—')}</span></span>
          </summary>
          <div class="px-5 pb-5 border-t border-slate-100 space-y-3">
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3">
              ${csStat('Status', h.status || a.status || '—')}${csStat('Clients', h.clients != null ? h.clients : '—')}
              ${csStat('Repo Synced', h.repo_synced === undefined ? '—' : (h.repo_synced ? 'Yes' : 'No'))}${csStat('Version', h.version || a.version || '—')}
            </div>
            ${h.repo_error ? `<p class="text-xs text-red-500">Repo error: ${csEscape(h.repo_error)}</p>` : ''}
            <div><p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">Services</p>${csTable(['Service', 'Status'], svcRows)}</div>
            <details class="text-xs"><summary class="cursor-pointer text-slate-400">Raw payload</summary>${csJsonDump(sp)}</details>
          </div>
        </details>`;
    }).join('');
    csSet(`<div class="space-y-3">${cards}</div>`);
}

/* ===========================================================================
 * 5. Config — config-push + simulation-conf editor + hub-config
 * ========================================================================= */

async function csRenderConfig() {
    // Config → API child (default): config-push JSON editor + per-spoke state.
    csSetToolbar('');
    const pushCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">API Config Push</h3>
      <p class="text-xs text-slate-400 mb-2">Paste a JSON config object to push to all spokes (unwrapped at the spoke's <code>_apply_hub_config</code>).</p>
      <textarea id="cs-configpush" rows="10" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-xs font-mono outline-none focus:ring-2 focus:ring-green-500" placeholder='{ "key": "value" }'></textarea>
      <button onclick="csSaveConfigPush()" class="mt-3 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Push Config</button>
      <span id="cs-configpush-msg" class="ml-3 text-xs"></span>
    </div>`;

    // per-spoke config state (desired vs applied) — best-effort read from cache.
    let stateCard = '';
    try {
        const px = await csFetch(`/aggregate/proxmox?tenant_id=${csTenant()}`);
        const hosts = (px && px.hosts) || [];
        const rows = hosts.map(h => `<tr>
          <td class="px-3 py-2 text-sm">${csEscape(h.spoke_name || h.spoke_id)}</td>
          <td class="px-3 py-2">${csOnlineBadge(h.spoke_online)}</td>
          <td class="px-3 py-2 font-mono text-xs text-slate-500">${csEscape(h.sim_conf_read_error || '—')}</td>
          <td class="px-3 py-2 text-xs text-slate-400">${csEscape(h.hub_last_checkin ? new Date(h.hub_last_checkin * 1000).toLocaleString() : '—')}</td>
        </tr>`).join('');
        stateCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Per-Spoke Config State</h3>
          ${csTable(['Spoke', 'Online', 'Conf Read Error', 'Last Check-in'], rows)}
        </div>`;
    } catch (e) { console.error('csRenderConfig: per-spoke config state load failed, hiding card', e); stateCard = ''; }

    csSet(`<div class="space-y-4">${pushCard}${stateCard}</div>`);
}

window.csSaveConfigPush = async function () {
    const msg = csEl('cs-configpush-msg');
    const raw = csEl('cs-configpush').value;
    let cfg;
    try { cfg = raw.trim() ? JSON.parse(raw) : {}; } catch (e) {
        console.error('csSaveConfigPush: invalid JSON config', e);
        if (msg) { msg.textContent = 'Invalid JSON: ' + e.message; msg.className = 'ml-3 text-xs text-red-500'; }
        return;
    }
    try {
        await csFetch('/aggregate/config-push', { method: 'POST', body: JSON.stringify({ config: cfg }) });
        if (msg) { msg.textContent = 'Pushed.'; msg.className = 'ml-3 text-xs text-green-600'; }
    } catch (e) {
        console.error('csSaveConfigPush: config push failed', e);
        if (msg) { msg.textContent = e.message; msg.className = 'ml-3 text-xs text-red-500'; }
    }
};

// ── Config → Simulation (structured INI editor + hub-config) ─────────────────
function csIniSplit(content) {
    // Split INI into [{section, body}] blocks. Lines before the first [section]
    // form a preamble section named ''.
    const lines = String(content || '').split('\n');
    const blocks = [];
    let cur = { section: '', body: [] };
    blocks.push(cur);
    for (const ln of lines) {
        const m = /^\s*\[([^\]]*)\]\s*$/.exec(ln);
        if (m) { cur = { section: m[1], body: [] }; blocks.push(cur); }
        else cur.body.push(ln);
    }
    return blocks;
}

async function csRenderConfigSimulation() {
    csSetToolbar('');
    let simCard = '';
    try {
        const sc = await csFetch(`/${csTenant()}/config/simulation-conf`);
        const content = (sc && sc.content) || '';
        const blocks = csIniSplit(content);
        const sections = blocks.map((b, i) => {
            const label = b.section ? `[${csEscape(b.section)}]` : '(preamble)';
            const body = b.body.join('\n');
            return `<details class="border border-slate-200 rounded-md mb-2" ${i === 0 ? 'open' : ''}>
              <summary class="px-3 py-2 cursor-pointer bg-slate-50 font-mono text-xs text-slate-600">${label} <span class="text-slate-400">(${b.body.length} lines)</span></summary>
              <textarea data-cs-ini-section="${csEscape(b.section)}" rows="${Math.min(12, Math.max(3, b.body.length + 1))}" class="w-full bg-white border-0 px-3 py-2 text-xs font-mono outline-none focus:ring-1 focus:ring-green-400">${csEscape(body)}</textarea>
            </details>`;
        }).join('');
        simCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
          <div class="flex justify-between items-center mb-2">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Simulation Config (structured)</h3>
            <span class="text-[10px] text-slate-400 font-mono">${csEscape((sc && sc.sha) || '')}</span>
          </div>
          <p class="text-xs text-slate-400 mb-3">Edit each [section] independently. Saved as <code>sim_conf_override</code> INI and pushed to the spoke.</p>
          <div id="cs-ini-sections">${sections || '<p class="text-xs text-slate-400 italic">No simulation.conf relayed yet.</p>'}</div>
          <button onclick="csSaveSimConfStructured()" class="mt-3 bg-[#01A982] hover:bg-[#018a6c] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Simulation Config</button>
          <span id="cs-simconf-msg" class="ml-3 text-xs"></span>
        </div>`;
    } catch (e) {
        console.error('csRenderConfigSimulation: simulation-conf load failed', e);
        simCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Simulation Config', e).replace('py-10', 'py-6')}</div>`;
    }
    let hubCard = '';
    try { hubCard = await csHubConfigCard('/tenant/' + csTenant() + '/hub-config'); }
    catch (e) { console.error('csRenderConfigSimulation: hub-config load failed', e); hubCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Hub Config', e).replace('py-10', 'py-6')}</div>`; }
    csSet(`<div class="space-y-4">${simCard}${hubCard}</div>`);
}

window.csSaveSimConfStructured = async function () {
    const msg = csEl('cs-simconf-msg');
    // Re-serialize: walk the section textareas in DOM order, emitting [section]
    // headers (skipping the preamble) before each body.
    const tas = Array.from(document.querySelectorAll('[data-cs-ini-section]'));
    let out = '';
    for (const ta of tas) {
        const section = ta.getAttribute('data-cs-ini-section');
        const body = ta.value.replace(/^\s*\n+/, '').replace(/\s+$/,'');
        if (section) out += `\n[${section}]\n`;
        if (body) out += body + '\n';
    }
    try {
        const r = await csFetch(`/${csTenant()}/config/simulation-conf`, { method: 'PUT', body: JSON.stringify({ content: out.trim() }) });
        if (msg) { msg.textContent = 'Saved (' + ((r && r.synced_spokes) != null ? r.synced_spokes + ' spokes' : 'ok') + ').'; msg.className = 'ml-3 text-xs text-green-600'; }
    } catch (e) {
        console.error('csSaveSimConfStructured: save failed', e);
        if (msg) { msg.textContent = e.message; msg.className = 'ml-3 text-xs text-red-500'; }
    }
};

window.CS_CHILD_RENDERERS['Config::API'] = csRenderConfig;
window.CS_CHILD_RENDERERS['Config::Simulation'] = csRenderConfigSimulation;

/* Shared hub-config card used by Config → Simulation + Setup → Proxmox.
 * Mirrors webui-hub's HUB_CONFIG_FIELDS panel (app.js:16485 + templates/index.html:954):
 * the hub IS the source of truth, so every owned provisioning knob is exposed
 * here. Saving pushes the full snapshot — the spoke clears any owned key that
 * is absent, so all knobs must be sent (empty fields are omitted, as in webui-hub). */
const CS_HUB_CONFIG_FIELDS = [
    { key: 'repo_branch',                 label: 'Repo Branch',                type: 'text' },
    { key: 'reclone_schedule_enabled',    label: 'Reclone Schedule',           type: 'onoff' },
    { key: 'reclone_schedule_cron',       label: 'Reclone Cron',               type: 'text',   ph: 'sunday 02:00' },
    { key: 'reclone_concurrency',         label: 'Reclone Concurrency',        type: 'number', min: 1, max: 10 },
    { key: 'vm_image_1_template_id',      label: 'VM Image 1 Template ID',     type: 'text',   ph: '100' },
    { key: 'vm_image_2_template_id',      label: 'VM Image 2 Template ID',     type: 'text',   ph: '200' },
    { key: 'vm_image_1_pct',              label: 'VM Image 1 %',               type: 'number', min: 0, max: 100 },
    { key: 'usb_auto_provision',          label: 'USB Auto Provision',         type: 'onoff' },
    { key: 'usb_missing_timeout',         label: 'USB Missing Timeout (s)',    type: 'number', ph: '60' },
    { key: 'usb_max_slots',               label: 'USB Max Slots',              type: 'number', ph: '8' },
    { key: 'vm_silent_timeout',           label: 'VM Silent Timeout (h)',      type: 'number', ph: '24' },
    { key: 'l1_vlan_start',               label: 'L1 VLAN Start',              type: 'text',   ph: '100' },
    { key: 'l1_vlan_end',                 label: 'L1 VLAN End',                type: 'text',   ph: '199' },
    { key: 'usb_vidpids',                 label: 'USB Certified VID:PIDs (JSON array of {vidpid,type,label})',  type: 'json',   ph: '[{"vidpid":"1a2b:3c4d","type":"wireless","label":"1a2b:3c4d"}]', full: true },
    { key: 'usb_ignored_vidpids',         label: 'USB Ignored VID:PIDs (JSON array of "vid:pid")', type: 'json', ph: '["1a2b:3c4d"]', full: true },
    { key: 'ignored_hostnames',           label: 'Ignored Hostnames (JSON array)', type: 'json', ph: '["sim-rpi-0000"]', full: true },
];

function _csHcOnOff(key, val) {
    const on = String(val || 'off').toLowerCase() === 'on' || val === true;
    return `<select id="cs-hc-${key}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
      <option value="off" ${!on ? 'selected' : ''}>Off</option>
      <option value="on"  ${on ? 'selected' : ''}>On</option>
    </select>`;
}

async function csHubConfigCard(path) {
    const data = await csFetch(path);
    const enabled = !!(data && data.hub_config_enabled);
    const hc = (data && data.hub_config) || {};
    const fields = CS_HUB_CONFIG_FIELDS.map(col => {
        const valRaw = hc[col.key];
        const valStr = (valRaw != null && typeof valRaw !== 'object') ? String(valRaw)
                     : (typeof valRaw === 'object' && valRaw != null) ? JSON.stringify(valRaw) : '';
        const label = `<label class="text-xs text-slate-500 ${col.full ? 'md:col-span-3' : ''}">${csEscape(col.label)}`;
        let input;
        if (col.type === 'onoff') input = _csHcOnOff(col.key, valRaw);
        else if (col.type === 'number') input = `<input id="cs-hc-${col.key}" type="number" value="${csEscape(valStr)}" ${col.min != null ? `min="${col.min}"` : ''} ${col.max != null ? `max="${col.max}"` : ''} placeholder="${csEscape(col.ph || '')}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        else input = `<input id="cs-hc-${col.key}" type="text" value="${csEscape(valStr)}" placeholder="${csEscape(col.ph || '')}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        return `${label}${input}</label>`;
    }).join('');
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Hub Config</h3>
      <label class="flex items-center gap-2 text-xs text-slate-600 mb-3"><input id="cs-hc-enabled" type="checkbox" ${enabled ? 'checked' : ''}> Enable hub as source of truth</label>
      <div id="cs-hc-fields" class="${enabled ? '' : 'hidden'} grid grid-cols-1 md:grid-cols-3 gap-3">
        ${fields}
      </div>
      <button onclick="csSaveHubConfig()" class="mt-4 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save &amp; Push to All Spokes</button>
      <span id="cs-hc-msg" class="ml-3 text-xs"></span>
    </div>`;
}

window.csSaveHubConfig = async function () {
    const msg = csEl('cs-hc-msg');
    // Mirror webui-hub saveHubConfig: skip empty fields; parse JSON-array keys;
    // scalars (incl. numbers) are sent as strings — the spoke stores them as-is
    // and normalizes the on/off keys via _normalize_relay_enabled.
    const config = {};
    CS_HUB_CONFIG_FIELDS.forEach(col => {
        const el = csEl('cs-hc-' + col.key);
        if (!el) return;
        const v = (el.value || '').trim();
        if (!v) return;
        if (col.type === 'json') {
            try { config[col.key] = JSON.parse(v); } catch (e) { console.error('csSaveHubConfig: JSON field parse failed, sending raw string', e); config[col.key] = v; }
        } else {
            config[col.key] = v;
        }
    });
    const body = {
        hub_config_enabled: !!(csEl('cs-hc-enabled') && csEl('cs-hc-enabled').checked),
        hub_config: config
    };
    try {
        const r = await csFetch('/tenant/' + csTenant() + '/hub-config', { method: 'PUT', body: JSON.stringify(body) });
        if (msg) { msg.textContent = '✅ Saved. Pushed to ' + ((r && r.pushed_to_spokes) != null ? r.pushed_to_spokes : 0) + ' spoke(s).'; msg.className = 'ml-3 text-xs text-green-600'; }
    } catch (e) {
        console.error('csSaveHubConfig: hub-config push failed', e);
        if (msg) { msg.textContent = '❌ ' + e.message; msg.className = 'ml-3 text-xs text-red-500'; }
    }
};

/* ===========================================================================
 * 6. Setup — onboarding PSK + hub-config + processing-modes + notifications
 * ========================================================================= */

async function csRenderSetup() {
    csSetToolbar('');
    let pskCard = '';
    try { pskCard = await csPskCard(); } catch (e) { console.error('csRenderSetup: psk card load failed', e); pskCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Onboarding PSK', e).replace('py-10', 'py-6')}</div>`; }
    let modesCard = '';
    try { modesCard = await csProcessingModesCard(); } catch (e) { console.error('csRenderSetup: processing-modes card load failed', e); modesCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Processing Modes', e).replace('py-10', 'py-6')}</div>`; }
    csSet(`<div class="space-y-4">${pskCard}${modesCard}</div>`);
}

async function csPskCard() {
    const data = await csFetch('/tenant/' + csTenant() + '/onboarding-psk');
    const psks = (data && data.psks) || [];
    const rows = psks.map(p => `<tr>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(p)}</td>
      <td class="px-3 py-2 text-right"><button onclick="csRevokePsk('${csEscape(p)}')" class="text-xs text-red-500 hover:underline">Revoke</button></td>
    </tr>`).join('');
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex justify-between items-center mb-3">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Onboarding PSK</h3>
        <button onclick="csGenPsk()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-1.5 rounded-md text-xs font-bold shadow-sm">+ Generate</button>
      </div>
      ${psks.length ? csTable(['PSK', ''], rows) : '<p class="text-xs text-slate-400 italic py-4 text-center">No PSKs issued.</p>'}
      <span id="cs-psk-msg" class="text-xs"></span>
    </div>`;
}

window.csGenPsk = async function () {
    const msg = csEl('cs-psk-msg');
    try { await csFetch('/tenant/' + csTenant() + '/onboarding-psk', { method: 'POST', body: '{}' }); await csRenderSetup(); }
    catch (e) { console.error('csGenPsk: psk generate failed', e); if (msg) { msg.textContent = e.message; msg.className = 'text-xs text-red-500'; } }
};

window.csRevokePsk = async function (psk) {
    const msg = csEl('cs-psk-msg');
    try { await csFetch('/tenant/' + csTenant() + '/onboarding-psk', { method: 'DELETE', body: JSON.stringify({ psk }) }); await csRenderSetup(); }
    catch (e) { console.error('csRevokePsk: psk revoke failed', e); if (msg) { msg.textContent = e.message; msg.className = 'text-xs text-red-500'; } }
};

async function csProcessingModesCard() {
    const data = await csFetch('/' + csTenant() + '/settings');
    const modes = (data && data.processing_modes) || {};
    const features = [['central_api', 'Central API'], ['teams', 'Teams'], ['email', 'Email']];
    const opts = (cur) => ['centralized', 'distributed'].map(v =>
        `<option value="${v}" ${cur === v ? 'selected' : ''}>${v.charAt(0).toUpperCase() + v.slice(1)}</option>`).join('');
    const fields = features.map(([k, label]) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <select id="cs-pm-${k}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">${opts(modes[k])}</select>
    </label>`).join('');
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Processing Modes</h3>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">${fields}</div>
      <button onclick="csSaveProcessingModes()" class="mt-4 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Modes</button>
      <span id="cs-pm-msg" class="ml-3 text-xs"></span>
    </div>`;
}

window.csSaveProcessingModes = async function () {
    const msg = csEl('cs-pm-msg');
    const features = ['central_api', 'teams', 'email'];
    try {
        for (const k of features) {
            const v = csEl('cs-pm-' + k) && csEl('cs-pm-' + k).value;
            if (v) await csFetch('/hub/tenants/' + csTenant() + '/processing-modes', { method: 'PATCH', body: JSON.stringify({ [k]: v }) });
        }
        if (msg) { msg.textContent = 'Saved.'; msg.className = 'ml-3 text-xs text-green-600'; }
    } catch (e) { console.error('csSaveProcessingModes: save failed', e); if (msg) { msg.textContent = e.message; msg.className = 'ml-3 text-xs text-red-500'; } }
};

async function csNotificationsCard() {
    const data = await csFetch('/' + csTenant() + '/settings');
    const n = (data && data.notifications) || {};
    const f = (id, label, val, type) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <input id="${id}" ${type === 'checkbox' ? 'type="checkbox" ' + (val ? 'checked' : '') : `value="${csEscape(val != null ? val : '')}"`} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
    </label>`;
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Notifications</h3>
      <label class="flex items-center gap-2 text-xs text-slate-600 mb-3"><input id="cs-notif-enabled" type="checkbox" ${n.enabled ? 'checked' : ''}> Notifications enabled</label>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        ${f('cs-notif-host', 'SMTP Host', n.smtp_host)}${f('cs-notif-port', 'SMTP Port', n.smtp_port, 'number')}
        ${f('cs-notif-user', 'SMTP User', n.smtp_user)}${f('cs-notif-pass', 'SMTP Password (new)', '', 'password')}
        ${f('cs-notif-teams', 'Teams Webhook URL (new)', '', 'password')}
        ${f('cs-notif-emails', 'To Emails (comma-separated)', Array.isArray(n.to_emails) ? n.to_emails.join(', ') : (n.to_emails || ''))}
      </div>
      <button onclick="csSaveNotifications()" class="mt-4 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Notifications</button>
      <span id="cs-notif-msg" class="ml-3 text-xs"></span>
    </div>`;
}

window.csSaveNotifications = async function () {
    const msg = csEl('cs-notif-msg');
    const body = {
        enabled: !!(csEl('cs-notif-enabled') && csEl('cs-notif-enabled').checked),
        smtp_host: csEl('cs-notif-host') && csEl('cs-notif-host').value,
        smtp_port: parseInt((csEl('cs-notif-port') && csEl('cs-notif-port').value) || '0', 10),
        smtp_user: csEl('cs-notif-user') && csEl('cs-notif-user').value,
        to_emails: csEl('cs-notif-emails') && csEl('cs-notif-emails').value
    };
    const pass = csEl('cs-notif-pass') && csEl('cs-notif-pass').value;
    const teams = csEl('cs-notif-teams') && csEl('cs-notif-teams').value;
    if (pass) body.smtp_pass = pass;
    if (teams) body.teams_webhook_url = teams;
    try {
        await csFetch('/' + csTenant() + '/settings/notifications', { method: 'POST', body: JSON.stringify(body) });
        if (msg) { msg.textContent = 'Saved.'; msg.className = 'ml-3 text-xs text-green-600'; }
    } catch (e) { console.error('csSaveNotifications: save failed', e); if (msg) { msg.textContent = e.message; msg.className = 'ml-3 text-xs text-red-500'; } }
};

/* ===========================================================================
 * 6b. Setup sub-tabs (Wave 2) — Central API / Proxmox / GitHub / Security /
 *     Notifications / Troubleshooting. The 'General' overview child is
 *     csRenderSetup above; the rest are registered below.
 * ========================================================================= */

async function csSetupAutoProvCard() {
    let on = false, present = 0, unknown = 0;
    try {
        const s = await csFetch(`/${csTenant()}/usb-provisioning-status?tenant_id=${csTenant()}`);
        on = String(s.usb_auto_provision || 'off').toLowerCase() === 'on';
        const sp = (s.spokes || [])[0] || {};
        present = sp.present_usb || 0; unknown = sp.unknown_usb || 0;
    } catch (e) { console.error('csSetupAutoProvCard: usb-provisioning-status fetch failed, defaulting to off/0', e); }
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Dongle / Auto-Provisioning</h3>
      <div class="grid grid-cols-3 gap-3 mb-3">${csStat('Auto-Provision', on ? 'On' : 'Off')}${csStat('Present USB', present)}${csStat('Unknown USB', unknown)}</div>
      <label class="flex items-center gap-2 text-sm text-slate-600">
        <input id="cs-setup-autoprov" type="checkbox" ${on ? 'checked' : ''} onchange="csToggleAutoProvision(this.checked)"/>
        Provision unassigned dongles automatically
      </label>
    </div>`;
}

// ── Central API ─────────────────────────────────────────────────────────────
async function csRenderSetupCentralApi() {
    csSetToolbar('');
    // Connection creds + mode live in central_config (surfaced via the
    // central-status aggregate); sites/checks live in central_sites_config.
    let conn = {}, sites = {};
    try { conn = await csFetch(`/aggregate/central-status?tenant_id=${csTenant()}`); } catch (e) { console.error('csRenderSetupCentralApi: central-status fetch failed, defaulting to {}', e); conn = {}; }
    try { sites = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`); } catch (e) { console.error('csRenderSetupCentralApi: central-sites-config fetch failed, defaulting to {}', e); sites = {}; }
    conn = conn || {}; sites = sites || {};
    const hc = conn.hub_central_config || {};
    const mode = conn.mode || (hc.api_version === 'new_central' ? 'central' : 'classic');
    const sm = (sites.site_mappings && typeof sites.site_mappings === 'object') ? sites.site_mappings : {};
    const mc = Array.isArray(sites.monitored_checks) ? sites.monitored_checks : [];
    const hw = Array.isArray(sites.hardware_checks) ? sites.hardware_checks : [];
    window._csCscMonitoredChecks = mc.map(c => ({ type: c.type || 'alert', id: c.id, name: c.name || c.id }));
    window._csCscCatalog = null;

    const val = id => (csEl(id) && csEl(id).value) || '';
    const f = (id, label, v, type) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <input id="${id}" ${type === 'password' ? 'type="password"' : 'type="text"'} value="${csEscape(v != null ? v : '')}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></label>`;
    const modeSel = `<select id="cs-csc-mode" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
      <option value="classic" ${mode === 'classic' ? 'selected' : ''}>Classic (access token)</option>
      <option value="central" ${mode === 'central' ? 'selected' : ''}>Central (OAuth client)</option>
    </select>`;

    const connCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Central API Connection</h3>
      <p class="text-xs text-slate-400 mb-3">Aruba Central cluster credentials. Pushed to the spoke as <code>central_config</code>; the spoke sentinel-merges them — secrets only overwrite when non-empty.</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label class="text-xs text-slate-500">Mode${modeSel}</label>
        ${f('cs-csc-cluster', 'Cluster URL', hc.cluster_url)}
        ${f('cs-csc-clientid', 'Client ID', hc.client_id)}
        ${f('cs-csc-customerid', 'Customer ID', hc.customer_id)}
        ${f('cs-csc-clientsecret', 'Client Secret', hc.client_secret, 'password')}
        ${f('cs-csc-accesstoken', 'Access Token (classic)', hc.access_token, 'password')}
        ${f('cs-csc-refreshtoken', 'Refresh Token (classic)', hc.refresh_token, 'password')}
      </div>
      <div class="flex gap-2 mt-4">
        <button onclick="csSaveCentralConn()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save Connection</button>
        <button onclick="csTestCentral()" class="bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-bold">Test Central</button>
        <span id="cs-csc-conn-msg" class="text-xs self-center"></span>
      </div>
      <div id="cs-csc-test" class="mt-3 text-xs text-slate-500"></div>
    </div>`;

    const smRows = Object.keys(sm).map(w => csCscSmRow(w, sm[w])).join('');
    const hwRows = hw.map(h => csCscHwRow(h.id, h.name, h.device_type)).join('');
    const mcList = (mc && mc.length) ? mc.map(c => `<div class="text-xs text-slate-600">• ${csEscape(c.name || c.id)} <span class="text-slate-400 font-mono">(${csEscape(c.type || 'alert')}/${csEscape(c.id)})</span></div>`).join('')
        : '<p class="text-xs text-slate-400 italic">None configured. Load the available-checks catalog to pick Aruba Central alerts/insights.</p>';

    const sitesCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Sites &amp; Checks</h3>
      <p class="text-xs text-slate-400 mb-3">Hub-owned site mappings + Aruba Central sim/hardware monitors. Pushed to the spoke as <code>central_sites_config</code> and applied to the spoke's runtime monitoring when hub-managed.</p>

      <div class="flex items-center gap-2 mb-2">
        <button onclick="csLoadCentralAvailable()" class="bg-slate-200 text-slate-700 px-3 py-1.5 rounded-md text-xs font-bold">Load available checks</button>
        <span id="cs-csc-catalog-msg" class="text-xs text-slate-400"></span>
      </div>

      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-4 mb-1">Site Mappings (wireless site → Central site)</p>
      <div id="cs-csc-sm-rows" class="space-y-2">${smRows || '<p class="text-xs text-slate-400 italic">No site mappings.</p>'}</div>
      <button onclick="csCscAddSm()" class="mt-2 text-xs text-[#01A982] font-bold hover:underline">+ Add mapping</button>

      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-4 mb-1">Monitored Checks</p>
      <div id="cs-csc-monitored">${mcList}</div>

      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-4 mb-1">Hardware Checks</p>
      <div id="cs-csc-hw-rows" class="space-y-2">${hwRows || '<p class="text-xs text-slate-400 italic">No hardware checks.</p>'}</div>
      <button onclick="csCscAddHw()" class="mt-2 text-xs text-[#01A982] font-bold hover:underline">+ Add hardware check</button>

      <div class="flex gap-2 mt-4">
        <button onclick="csSaveCentralSites()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save Sites &amp; Checks</button>
        <span id="cs-csc-msg" class="text-xs self-center"></span>
      </div>
    </div>`;

    csSet(`<div class="max-w-4xl space-y-4">${connCard}${sitesCard}</div>`);
}

function csCscSmRow(w, c) {
    return `<div class="cs-csc-sm-row flex gap-2 items-center">
      <input data-cs-sm-w value="${csEscape(w != null ? w : '')}" placeholder="wireless site" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs font-mono">
      <span class="text-slate-400">→</span>
      <input data-cs-sm-c value="${csEscape(c != null ? c : '')}" placeholder="Central site" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs font-mono">
      <button onclick="csCscRemoveRow(this)" class="text-red-500 text-xs px-2" title="Remove">✕</button>
    </div>`;
}

function csCscHwRow(id, name, dt) {
    return `<div class="cs-csc-hw-row flex gap-2 items-center">
      <input data-cs-hw-id value="${csEscape(id != null ? id : '')}" placeholder="id (AP_DOWN)" class="w-36 bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs font-mono">
      <input data-cs-hw-name value="${csEscape(name != null ? name : '')}" placeholder="name" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs">
      <input data-cs-hw-dt value="${csEscape(dt != null ? dt : '')}" placeholder="device type (ap/gateway/switch)" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs">
      <button onclick="csCscRemoveRow(this)" class="text-red-500 text-xs px-2" title="Remove">✕</button>
    </div>`;
}

window.csCscRemoveRow = function (btn) {
    const row = btn && btn.closest('.cs-csc-sm-row, .cs-csc-hw-row');
    if (row) row.remove();
};

window.csCscAddSm = function () {
    const c = csEl('cs-csc-sm-rows'); if (!c) return;
    const empty = c.querySelector('p.italic'); if (empty) empty.remove();
    const wrap = document.createElement('div'); wrap.innerHTML = csCscSmRow('', '');
    c.appendChild(wrap.firstElementChild);
};

window.csCscAddHw = function () {
    const c = csEl('cs-csc-hw-rows'); if (!c) return;
    const empty = c.querySelector('p.italic'); if (empty) empty.remove();
    const wrap = document.createElement('div'); wrap.innerHTML = csCscHwRow('', '', '');
    c.appendChild(wrap.firstElementChild);
};

window.csLoadCentralAvailable = async function () {
    const msg = csEl('cs-csc-catalog-msg');
    if (msg) { msg.textContent = 'Loading…'; msg.className = 'text-xs text-slate-400'; }
    try {
        const cat = await csFetch(`/${csTenant()}/central/available?tenant_id=${csTenant()}`) || {};
        window._csCscCatalog = cat;
        const alerts = cat.alerts || [], insights = cat.insights || [];
        const ids = new Set((window._csCscMonitoredChecks || []).map(c => c.id));
        const toggle = (c, type) => `<label class="flex items-center gap-2 text-xs text-slate-600 py-0.5">
          <input type="checkbox" data-cs-mon-type="${csEscape(type)}" data-cs-mon-id="${csEscape(c.id)}" data-cs-mon-name="${csEscape(c.name || c.id)}" ${ids.has(c.id) ? 'checked' : ''} onchange="csCscMonToggle()">
          <span>${csEscape(c.name || c.id)}</span><span class="text-slate-400 font-mono">(${csEscape(c.id)})</span>
        </label>`;
        csEl('cs-csc-monitored').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1">
          <div><p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Alerts</p>${alerts.map(a => toggle(a, 'alert')).join('') || '<p class="text-xs text-slate-400 italic">None.</p>'}</div>
          <div><p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Insights</p>${insights.map(a => toggle(a, 'insight')).join('') || '<p class="text-xs text-slate-400 italic">None.</p>'}</div>
        </div>`;
        csCscMonSync();
        if (msg) { msg.textContent = (alerts.length + insights.length) + ' checks loaded' + (cat.warning ? ' — ' + cat.warning : ''); }
    } catch (e) {
        console.error('csLoadCentralAvailable: available-checks catalog load failed', e);
        if (msg) { msg.textContent = 'Failed: ' + (e.message || e); msg.className = 'text-xs text-red-500'; }
    }
};

window.csCscMonToggle = function () { csCscMonSync(); };
window.csCscMonSync = function () {
    const checks = [];
    document.querySelectorAll('#cs-csc-monitored input[type=checkbox]').forEach(cb => {
        if (cb.checked) checks.push({ type: cb.getAttribute('data-cs-mon-type'), id: cb.getAttribute('data-cs-mon-id'), name: cb.getAttribute('data-cs-mon-name') });
    });
    window._csCscMonitoredChecks = checks;
};

window.csSaveCentralConn = async function () {
    const msg = csEl('cs-csc-conn-msg');
    const v = id => (csEl(id) && csEl(id).value) || '';
    const mode = v('cs-csc-mode');
    const hub_central_config = {
        cluster_url: v('cs-csc-cluster'),
        client_id: v('cs-csc-clientid'),
        customer_id: v('cs-csc-customerid'),
        api_version: mode === 'central' ? 'new_central' : 'classic',
    };
    // Secrets: include only when non-empty so the spoke's sentinel merge
    // doesn't wipe an existing credential with a blank field.
    if (v('cs-csc-clientsecret')) hub_central_config.client_secret = v('cs-csc-clientsecret');
    if (v('cs-csc-accesstoken'))  hub_central_config.access_token  = v('cs-csc-accesstoken');
    if (v('cs-csc-refreshtoken')) hub_central_config.refresh_token = v('cs-csc-refreshtoken');
    try {
        const r = await csFetch('/aggregate/central', { method: 'POST', body: JSON.stringify({ mode, hub_central_config }) });
        if (msg) { msg.textContent = '✅ Saved. Pushed to ' + ((r && r.pushed_to_spokes) != null ? r.pushed_to_spokes : 0) + ' spoke(s).'; msg.className = 'text-xs text-green-600'; }
    } catch (e) { console.error('csSaveCentralConn: central connection save failed', e); if (msg) { msg.textContent = '❌ ' + e.message; msg.className = 'text-xs text-red-500'; } }
};

window.csSaveCentralSites = async function () {
    const msg = csEl('cs-csc-msg');
    const site_mappings = {};
    document.querySelectorAll('#cs-csc-sm-rows .cs-csc-sm-row').forEach(row => {
        const w = (row.querySelector('[data-cs-sm-w]').value || '').trim();
        const c = (row.querySelector('[data-cs-sm-c]').value || '').trim();
        if (w) site_mappings[w] = c;
    });
    const hardware_checks = [];
    document.querySelectorAll('#cs-csc-hw-rows .cs-csc-hw-row').forEach(row => {
        const id = (row.querySelector('[data-cs-hw-id]').value || '').trim();
        if (!id) return;
        hardware_checks.push({ id, name: (row.querySelector('[data-cs-hw-name]').value || '').trim() || id, device_type: (row.querySelector('[data-cs-hw-dt]').value || '').trim() });
    });
    const cfg = { site_mappings, monitored_checks: window._csCscMonitoredChecks || [], hardware_checks };
    try {
        const r = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(cfg) });
        if (msg) { msg.textContent = '✅ Saved. Pushed to ' + ((r && r.pushed_to_spokes) != null ? r.pushed_to_spokes : 0) + ' spoke(s).'; msg.className = 'text-xs text-green-600'; }
    } catch (e) { console.error('csSaveCentralSites: central sites save failed', e); if (msg) { msg.textContent = '❌ ' + e.message; msg.className = 'text-xs text-red-500'; } }
};

window.csTestCentral = async function () {
    const out = csEl('cs-csc-test');
    try {
        const r = await csFetch(`/${csTenant()}/test-central?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify({}) });
        const rows = (r.spokes || []).map(s => `<div>${csEscape(s.spoke_name)}: token=${csEscape(s.token_state || '—')} valid=${csEscape(s.token_valid)} status=${csEscape(s.status || '—')}</div>`).join('');
        if (out) out.innerHTML = rows || '<i>No spokes reporting central state.</i>';
    } catch (e) { console.error('csTestCentral: test-central failed', e); if (out) out.textContent = 'Test failed: ' + (e.message || e); }
};

// ── Proxmox (full HUB_CONFIG editor) ────────────────────────────────────────
async function csRenderSetupProxmox() {
    csSetToolbar('');
    try {
        const card = await csHubConfigCard('/tenant/' + csTenant() + '/hub-config');
        let dongle = '';
        try { dongle = await csSetupAutoProvCard(); } catch (e) { console.error('csRenderSetupProxmox: dongle card load failed', e); dongle = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Dongle Allocation', e).replace('py-10', 'py-6')}</div>`; }
        csSet(`<div class="space-y-4"><div class="hpe-card rounded-lg p-5 shadow-sm">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Proxmox / VM Auto-Provisioning</h3>
          <p class="text-xs text-slate-400 mb-3">Hub-owned provisioning knobs (templates, VLANs, USB timeouts, reclone schedule, USB VID/PID lists). Pushed to the spoke on save.</p>
        </div>${dongle}${card}</div>`);
    } catch (e) { console.error('csRenderSetupProxmox: proxmox config load failed', e); csSet(csErrorBox('Could not load Proxmox config', e)); }
}

// ── GitHub ──────────────────────────────────────────────────────────────────
async function csRenderSetupGithub() {
    csSetToolbar('');
    let cfg = {};
    try { cfg = await csFetch(`/${csTenant()}/settings/github?tenant_id=${csTenant()}`); }
    catch (e) { console.error('csRenderSetupGithub: github config load failed', e); csSet(csErrorBox('Could not load GitHub config', e)); return; }
    cfg = cfg || {};
    const f = (id, label, val, type) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <input id="${id}" ${type === 'password' ? 'type="password"' : `value="${csEscape(val != null ? val : '')}"`} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></label>`;
    csSet(`<div class="max-w-2xl space-y-4">
      <div class="hpe-card rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">GitHub</h3>
        <div class="grid grid-cols-1 gap-3">
          ${f('cs-gh-url', 'Repo URL', cfg.repo_url)}${f('cs-gh-branch', 'Repo Branch', cfg.repo_branch)}
          ${f('cs-gh-token', 'GitHub Token ' + (cfg.has_token ? '(set — leave blank to keep)' : '(new)'), '', 'password')}
        </div>
        <div class="flex gap-2 mt-4">
          <button onclick="csSaveGithub()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save</button>
          <button onclick="csClearGithub()" class="bg-red-100 text-red-700 px-4 py-2 rounded-md text-sm font-bold">Clear</button>
          <span id="cs-gh-msg" class="text-xs self-center"></span>
        </div>
      </div></div>`);
}

window.csSaveGithub = async function () {
    const msg = csEl('cs-gh-msg');
    const body = {
        repo_url: csEl('cs-gh-url') && csEl('cs-gh-url').value,
        repo_branch: csEl('cs-gh-branch') && csEl('cs-gh-branch').value,
    };
    const tok = csEl('cs-gh-token') && csEl('cs-gh-token').value;
    if (tok) body.github_token = tok;
    try {
        await csFetch(`/${csTenant()}/settings/github?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        if (msg) { msg.textContent = 'Saved.'; msg.className = 'text-xs text-green-600'; }
        csRenderSetupGithub();
    } catch (e) { console.error('csSaveGithub: save failed', e); if (msg) { msg.textContent = e.message; msg.className = 'text-xs text-red-500'; } }
};

window.csClearGithub = async function () {
    if (!confirm('Clear GitHub config (removes repo + token from the spoke)?')) return;
    try { await csFetch(`/${csTenant()}/settings/github?tenant_id=${csTenant()}`, { method: 'DELETE' }); csRenderSetupGithub(); }
    catch (e) { console.error('csClearGithub: clear failed', e); alert('Clear failed: ' + (e.message || e)); }
};

// ── Security ─────────────────────────────────────────────────────────────────
async function csRenderSetupSecurity() {
    csSetToolbar('');
    let cfg = {};
    try { cfg = await csFetch(`/${csTenant()}/settings/security?tenant_id=${csTenant()}`); }
    catch (e) { console.error('csRenderSetupSecurity: security config load failed', e); csSet(csErrorBox('Could not load Security config', e)); return; }
    cfg = cfg || {};
    const f = (id, label, val) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <input id="${id}" value="${csEscape(val != null ? val : '')}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></label>`;
    csSet(`<div class="max-w-2xl space-y-4">
      <div class="hpe-card rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Security</h3>
        <p class="text-xs text-slate-400 mb-3">Governs the spoke's local dashboard auth. LM hub auth is managed separately in LM settings.</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          ${f('cs-sec-timeout', 'Session Timeout (minutes)', cfg.session_timeout_minutes)}
          ${f('cs-sec-provider', 'Auth Provider', cfg.auth_provider)}
        </div>
        <button onclick="csSaveSecurity()" class="mt-4 bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save</button>
        <span id="cs-sec-msg" class="ml-3 text-xs"></span>
      </div></div>`);
}

window.csSaveSecurity = async function () {
    const msg = csEl('cs-sec-msg');
    const body = {
        session_timeout_minutes: csEl('cs-sec-timeout') && csEl('cs-sec-timeout').value,
        auth_provider: csEl('cs-sec-provider') && csEl('cs-sec-provider').value,
    };
    try {
        await csFetch(`/${csTenant()}/settings/security?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        if (msg) { msg.textContent = 'Saved.'; msg.className = 'text-xs text-green-600'; }
    } catch (e) { console.error('csSaveSecurity: save failed', e); if (msg) { msg.textContent = e.message; msg.className = 'text-xs text-red-500'; } }
};

// ── Notifications (reuses the existing card) ─────────────────────────────────
async function csRenderSetupNotifications() {
    csSetToolbar('');
    try { csSet(`<div class="space-y-4">${await csNotificationsCard()}</div>`); }
    catch (e) { console.error('csRenderSetupNotifications: notifications load failed', e); csSet(csErrorBox('Could not load Notifications', e)); }
}

// ── Troubleshooting ──────────────────────────────────────────────────────────
async function csRenderSetupTroubleshooting() {
    csSetToolbar('');
    let data = {};
    try { data = await csFetch(`/${csTenant()}/troubleshooting?tenant_id=${csTenant()}`); }
    catch (e) { console.error('csRenderSetupTroubleshooting: troubleshooting load failed', e); csSet(csErrorBox('Could not load troubleshooting', e)); return; }
    const spokes = (data && data.spokes) || [];
    const cards = spokes.map(s => {
        const h = s.api_health || {};
        const rs = s.reclone_state || {};
        const rows = Object.entries(h).map(([k, v]) => `<tr><td class="px-3 py-2 font-mono text-xs text-slate-500">${csEscape(k)}</td><td class="px-3 py-2 text-sm">${csEscape(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`).join('');
        return `<div class="hpe-card rounded-lg p-5 shadow-sm">
          <div class="flex items-center justify-between mb-2">
            <span class="font-bold text-slate-700">${csEscape(s.spoke_name)}</span>
            <span class="text-xs text-slate-400">reclone: ${csEscape(rs.status || 'idle')}</span>
          </div>
          ${csTable(['Key', 'Value'], rows)}
          <div class="flex gap-2 mt-3">
            <button onclick="csUpdateAll()" class="bg-slate-700 text-white px-3 py-1.5 rounded-md text-xs font-bold">Trigger Update</button>
            <button onclick="csClearCommands()" class="bg-red-100 text-red-700 px-3 py-1.5 rounded-md text-xs font-bold">Clear Queue</button>
          </div>
        </div>`;
    }).join('');
    csSet(`<div class="space-y-4">${cards || csEmpty('No spokes reporting.')}</div>`);
}

// ── Register Setup children ────────────────────────────────────────────────
window.CS_CHILD_RENDERERS['Setup::General']        = csRenderSetup;
// Backward-compat alias: a client with stale localStorage may still request
// the old "Setup" child label before it re-persists as "General".
window.CS_CHILD_RENDERERS['Setup::Setup']           = csRenderSetup;
window.CS_CHILD_RENDERERS['Setup::Central API']    = csRenderSetupCentralApi;
window.CS_CHILD_RENDERERS['Setup::Proxmox']        = csRenderSetupProxmox;
window.CS_CHILD_RENDERERS['Setup::GitHub']         = csRenderSetupGithub;
window.CS_CHILD_RENDERERS['Setup::Security']       = csRenderSetupSecurity;
window.CS_CHILD_RENDERERS['Setup::Notifications']  = csRenderSetupNotifications;
window.CS_CHILD_RENDERERS['Setup::Troubleshooting'] = csRenderSetupTroubleshooting;

/* ===========================================================================
 * 1. VM Server — fleet overview + per-spoke drill-in children
 *    GET/DELETE /sim/api/{T}/proxmx/commands          (command queue)
 *    POST /sim/api/{T}/usb-vidpids                    (certify/ignore USB)
 * ========================================================================= */

let csVmHosts = [];
let csVmSelectedSpoke = '';

async function csVmLoad() {
    const data = await csFetch(`/aggregate/proxmox?tenant_id=${csTenant()}`);
    csVmHosts = (data && data.hosts) || [];
    // Admin-only sidecar from the hub describing where USB data lives in each
    // cached cs spoke payload (keys + lengths, no values). Surfaced in the USB
    // tab when no dongles are found, so a missing USB count can be diagnosed
    // in-place instead of hunting logs.
    window._csUsbDebug = (data && data._usb_debug) || null;
    return csVmHosts;
}

function csVmSelectedHost() {
    let h = csVmHosts.find(x => x.spoke_id === csVmSelectedSpoke);
    if (!h) h = csVmHosts.find(x => x.spoke_online) || csVmHosts[0] || null;
    if (h) csVmSelectedSpoke = h.spoke_id;
    return h;
}

/** Host-selector banner shown atop every drill-in child (VMs … API Server). */
function csVmHostBanner() {
    if (!csVmHosts.length) return '';
    const pills = csVmHosts.map(h => {
        const active = h.spoke_id === csVmSelectedSpoke;
        const cls = active ? 'bg-[#01A982] text-white border-[#01A982]'
                           : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50';
        return `<button onclick="csVmSelectHost('${csEscape(h.spoke_id)}')"
            class="px-3 py-1 rounded-full text-xs font-semibold border ${cls}">${csOnlineDot(h.spoke_online)} ${csEscape(h.spoke_name || h.spoke_id)}</button>`;
    }).join('');
    return `<div class="flex flex-wrap items-center gap-2 mb-4">
      <span class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mr-1">Host</span>${pills}
    </div>`;
}

function csOnlineDot(online) {
    return online ? '<span class="w-1.5 h-1.5 rounded-full bg-green-500 inline-block mr-1.5 align-middle"></span>'
                  : '<span class="w-1.5 h-1.5 rounded-full bg-slate-300 inline-block mr-1.5 align-middle"></span>';
}

// ── Overview (fleet) ────────────────────────────────────────────────────────
async function csRenderVmServer() {
    csSetToolbar('');
    let hosts;
    try { hosts = await csVmLoad(); }
    catch (e) { console.error('csRenderVmServer: fleet load failed', e); csSet(csErrorBox('Could not load VM Server fleet', e)); return; }
    if (!hosts.length) { csSet(csEmpty('No VM servers reporting yet.')); return; }
    const online = hosts.filter(h => h.spoke_online).length;
    const vms = hosts.reduce((n, h) => n + (h.vm_count || (h.proxmox_vms ? h.proxmox_vms.length : 0)), 0);
    const usbs = hosts.reduce((n, h) => n + csUsbCount(h), 0);
    const recloneRunning = hosts.filter(h => h.reclone_state && h.reclone_state.status === 'running').length;
    const summary = `<div class="flex flex-wrap items-center gap-x-4 gap-y-1 mb-3 text-xs text-slate-500">
      <span><b class="text-sm text-slate-700">${hosts.length}</b> Hosts</span>
      <span><b class="text-sm text-slate-700">${online}</b> Online</span>
      <span><b class="text-sm text-slate-700">${vms}</b> VMs</span>
      <span><b class="text-sm text-slate-700">${usbs}</b> USB</span>
      <span><b class="text-sm text-slate-700">${recloneRunning}</b> Recloning</span>
    </div>`;

    const fleetCards = `<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
      <div class="hpe-card rounded-lg p-4 shadow-sm">
        <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Fleet Reclone</p>
        <div class="flex items-center gap-2">
          <input id="cs-fleet-conc" type="number" min="1" value="1" class="w-16 border border-slate-200 rounded-md px-2 py-1 text-sm"/>
          <button onclick="csFleetReclone()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-3 py-1.5 rounded-md text-xs font-bold">Reclone All</button>
        </div>
        <p class="text-[10px] text-slate-400 mt-2">Concurrency controls how many guests reclone in parallel.</p>
      </div>
      <div class="hpe-card rounded-lg p-4 shadow-sm">
        <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Auto-Provisioning</p>
        <label class="flex items-center gap-2 text-sm text-slate-600">
          <input id="cs-autoprov-toggle" type="checkbox" onchange="csToggleAutoProvision(this.checked)" class="rounded"/>
          Provision unassigned dongles automatically
        </label>
        <p class="text-[10px] text-slate-400 mt-2" id="cs-autoprov-status">Status: loading…</p>
      </div>
    </div>`;

    // Per-server rows as a table — mirrors the pxmx Nodes page (border-b
    // border-slate-100, clickable, hover:bg-slate-50, selected row highlighted
    // with bg-green-50 ring-1 ring-green-300). A table also aligns the stat
    // columns vertically across rows.
    const sel = csVmSelectedSpoke;
    const rows = hosts.map(h => {
        const px = h.proxmox || {};
        const vmN = h.vm_count || (h.proxmox_vms ? h.proxmox_vms.length : 0);
        const usbN = csUsbCount(h);
        const selCls = h.spoke_id === sel ? 'bg-green-50 ring-1 ring-green-300' : 'hover:bg-slate-50';
        return `<tr class="border-b border-slate-100 cursor-pointer ${selCls}" onclick="csVmSelectHost('${csEscape(h.spoke_id)}','VMs')">
          <td class="px-4 py-2"><span class="font-medium text-slate-700">${csEscape(h.spoke_name || h.spoke_hostname || h.spoke_id)}</span></td>
          <td class="px-4 py-2 text-center">${csOnlineBadge(h.spoke_online)}</td>
          <td class="px-4 py-2 text-center">${vmN}</td>
          <td class="px-4 py-2 text-center">${usbN}</td>
          <td class="px-4 py-2 text-xs text-slate-600">${csEscape(px.agent_version || '—')}</td>
          <td class="px-4 py-2 text-xs text-slate-600">${csEscape(csPveVersion(px.pve_version))}</td>
        </tr>`;
    }).join('');
    const ths = ['Host', 'Online', 'VMs', 'USB', 'Agent', 'PVE']
        .map((c, i) => `<th class="px-4 py-2 ${i === 1 || i === 2 || i === 3 ? 'text-center' : 'text-left'} font-medium">${c}</th>`).join('');
    const table = `<div class="overflow-x-auto"><table class="w-full text-sm">
      <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${ths}</tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;

    csSet(`<div class="space-y-4">${summary}${fleetCards}${table}</div>`);
    // populate auto-provision status
    csRefreshAutoProvStatus();
}

async function csRefreshAutoProvStatus() {
    try {
        const s = await csFetch(`/${csTenant()}/usb-provisioning-status?tenant_id=${csTenant()}`);
        const on = String(s.usb_auto_provision || 'off').toLowerCase() === 'on';
        const el = csEl('cs-autoprov-toggle'); if (el) el.checked = on;
        const st = csEl('cs-autoprov-status');
        if (st) st.textContent = `Status: ${on ? 'enabled' : 'disabled'} · ${csEscape(s.usb_auto_provision || 'off')}`;
    } catch (e) { console.error('csRefreshAutoProvStatus: usb-provisioning-status fetch failed (best-effort)', e); }
}

window.csVmSelectHost = function (spokeId, child) {
    csVmSelectedSpoke = spokeId;
    if (child) { setSubChild(child); }
    else loadCSData('VM Server', currentSubChild || 'VMs', true);
};

window.csFleetReclone = async function () {
    const conc = csEl('cs-fleet-conc') ? parseInt(csEl('cs-fleet-conc').value, 10) || 1 : 1;
    try {
        await csFetch(`/${csTenant()}/fleet-reclone?tenant_id=${csTenant()}`, {
            method: 'POST', body: JSON.stringify({ concurrency: conc }) });
        alert('Fleet reclone started.');
        csRenderVmServer();
    } catch (e) { console.error('csFleetReclone: fleet reclone failed', e); alert('Fleet reclone failed: ' + (e.message || e)); }
};

window.csToggleAutoProvision = async function (enabled) {
    try {
        await csFetch(`/${csTenant()}/toggle-auto-provision?tenant_id=${csTenant()}`, {
            method: 'POST', body: JSON.stringify({ enabled }) });
        csRefreshAutoProvStatus();
    } catch (e) { console.error('csToggleAutoProvision: toggle failed', e); alert('Toggle failed: ' + (e.message || e)); }
};

window.csUpdateAll = async function () {
    try {
        await csFetch(`/${csTenant()}/update-all?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify({}) });
        alert('Agent update queued.');
    } catch (e) { console.error('csUpdateAll: update-all failed', e); alert('Update All failed: ' + (e.message || e)); }
};

// ── VMs (per-host) ──────────────────────────────────────────────────────────
function csVmCategory(v) {
    const t = String(v.type || '').toLowerCase();
    const name = String(v.name || '').toLowerCase();
    if (t === 'template' || name.includes('template')) return 'Templates';
    if (t === 'lxc' || t === 'container') return 'Containers';
    if (name.startsWith('sim-') || name.includes('client')) return 'Simulation Clients';
    return 'Other';
}

async function csRenderVmServerVms() {
    csSetToolbar('');
    let hosts;
    try { hosts = await csVmLoad(); }
    catch (e) { console.error('csRenderVmServerVms: vm load failed', e); csSet(csErrorBox('Could not load VMs', e)); return; }
    const h = csVmSelectedHost();
    if (!h) { csSet(csEmpty('No host selected.')); return; }
    const vms = h.proxmox_vms || [];
    const cats = ['Simulation Clients', 'Other', 'Containers', 'Templates'];
    const grouped = {};
    cats.forEach(c => grouped[c] = vms.filter(v => csVmCategory(v) === c));
    const tabs = cats.map((c, i) => `<button onclick="csVmVmsTab('${c}')" id="cs-vmtab-${csEscape(c)}" class="px-3 py-1.5 rounded-md text-xs font-bold ${i === 0 ? 'bg-[#01A982] text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}">${csEscape(c)} <span class="opacity-60">(${grouped[c].length})</span></button>`).join('');
    const rows = (grouped['Simulation Clients'] || []).map(csVmRow).join('');
    csSet(`<div>${csVmHostBanner()}${tabs}
      <div class="flex items-center gap-2 my-3 text-xs text-slate-500">
        <button onclick="csVmBulk('start_vm')" class="bg-green-100 text-green-700 px-2 py-1 rounded font-bold">Start</button>
        <button onclick="csVmBulk('stop_vm')" class="bg-amber-100 text-amber-700 px-2 py-1 rounded font-bold">Stop</button>
        <button onclick="csVmBulk('reboot_vm')" class="bg-slate-200 text-slate-700 px-2 py-1 rounded font-bold">Reboot</button>
        <button onclick="csVmBulk('reclone_vm')" class="bg-blue-100 text-blue-700 px-2 py-1 rounded font-bold">Reclone</button>
        <button onclick="csVmBulk('delete_vm')" class="bg-red-100 text-red-700 px-2 py-1 rounded font-bold">Delete</button>
        <span id="cs-vm-bulk-msg" class="text-slate-400 ml-2"></span>
      </div>
      <div id="cs-vm-list">${csTable(['VMID', 'Name', 'Type', 'Status', 'Actions'], rows, {id:'cs-vm-table'})}</div>
    </div>`);
    window._csVmGrouped = grouped;
    window._csVmByVmid = {};
    vms.forEach(v => { window._csVmByVmid[v.vmid] = v; });
}

function csVmRow(v) {
    const vid = csEscape(v.vmid);
    const act = (label, action, cls) => `<button onclick="csVmAction(${v.vmid},'${action}')" class="px-2 py-0.5 rounded text-[10px] font-bold ${cls}">${label}</button>`;
    return `<tr>
      <td class="px-3 py-2 font-mono text-xs"><input type="checkbox" class="cs-vm-sel" data-vmid="${vid}"/> ${vid}</td>
      <td class="px-3 py-2 text-sm">${csEscape(v.name || '—')}</td>
      <td class="px-3 py-2 text-slate-500">${csEscape(v.type || '—')}</td>
      <td class="px-3 py-2">${csStatusBadge(v.status || (v.pending_checkin ? 'pending' : 'unknown'))}</td>
      <td class="px-3 py-2"><div class="flex flex-wrap gap-1">
        ${act('Start','start_vm','bg-green-100 text-green-700')}
        ${act('Stop','stop_vm','bg-amber-100 text-amber-700')}
        ${act('Reboot','reboot_vm','bg-slate-200 text-slate-700')}
        ${act('Snapshot','snapshot_vm','bg-blue-100 text-blue-700')}
        ${act('Reclone','reclone_vm','bg-indigo-100 text-indigo-700')}
        ${act('Delete','delete_vm','bg-red-100 text-red-700')}
      </div></td>
    </tr>`;
}

window.csVmVmsTab = function (cat) {
    const rows = (window._csVmGrouped && window._csVmGrouped[cat] || []).map(csVmRow).join('');
    const list = csEl('cs-vm-list');
    if (list) list.innerHTML = csTable(['VMID', 'Name', 'Type', 'Status', 'Actions'], rows, {id:'cs-vm-table'});
    ['Simulation Clients','Other','Containers','Templates'].forEach(c => {
        const b = csEl('cs-vmtab-' + c);
        if (b) b.className = 'px-3 py-1.5 rounded-md text-xs font-bold ' + (c === cat ? 'bg-[#01A982] text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200');
    });
};

window.csVmAction = async function (vmid, action) {
    const v = (window._csVmByVmid && window._csVmByVmid[vmid]) || {};
    const args = { vmid: Number(vmid) };
    if (v.type) args.vm_type = v.type;
    const sid = encodeURIComponent(csVmSelectedSpoke);
    try {
        await csFetch(`/${csTenant()}/spokes/${sid}/proxmox-command?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ action, args }) });
        csVmFlash(action + ' queued');
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 800);
    } catch (e) { console.error('csVmAction: ' + action + ' failed', e); alert(action + ' failed: ' + (e.message || e)); }
};

window.csVmBulk = async function (action) {
    const ids = Array.from(document.querySelectorAll('.cs-vm-sel:checked')).map(c => c.dataset.vmid);
    if (!ids.length) { alert('Select one or more VMs first.'); return; }
    try {
        for (const vmid of ids) {
            const v = (window._csVmByVmid && window._csVmByVmid[vmid]) || {};
            const args = { vmid: Number(vmid) };
            if (v.type) args.vm_type = v.type;
            await csFetch(`/${csTenant()}/spokes/${encodeURIComponent(csVmSelectedSpoke)}/proxmox-command?tenant_id=${csTenant()}`,
                { method: 'POST', body: JSON.stringify({ action, args }) });
        }
        csVmFlash(`${action} queued for ${ids.length} VM(s)`);
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 1000);
    } catch (e) { console.error('csVmBulk: ' + action + ' bulk failed', e); alert(action + ' bulk failed: ' + (e.message || e)); }
};

function csVmFlash(msg) {
    const el = csEl('cs-vm-bulk-msg'); if (el) { el.textContent = msg; setTimeout(() => { if (el) el.textContent = ''; }, 2500); }
}

// ── Console / Terminal (Phase-5 stubs, faithful to current LM state) ───────
function csRenderVmServerConsoleStub(label, kind) {
    csSetToolbar('');
    csSet(`<div>${csVmHostBanner()}
      <div class="hpe-card rounded-lg p-10 shadow-sm text-center">
        <div class="text-3xl mb-3">${kind === 'console' ? '🖥️' : '⌨️'}</div>
        <h3 class="text-lg font-bold text-slate-700 mb-1">${csEscape(label)}</h3>
        <p class="text-sm text-slate-500 max-w-md mx-auto">${csEscape(label)} requires a ${kind === 'console' ? 'noVNC' : 'xterm.js'} WebSocket proxied through the LM hub. This is wired in Phase 5; the rest of the VM Server port is live now.</p>
      </div></div>`);
}
function csRenderVmServerConsole() { return csRenderVmServerConsoleStub('VM Console (noVNC)', 'console'); }
function csRenderVmServerTerminal() { return csRenderVmServerConsoleStub('Spoke Shell (xterm)', 'terminal'); }

// ── USB (certified / uncertified + certify-ignore) ───────────────────────────
// The cs-spoke relay payload carries each dongle as {vidpid:"vid:pid", name|product,
// type, bus_path, vmid, prov_status, missing_since} — NOT pre-split vid/pid and
// NOT with active_vms/missing booleans. The source webui-hub frontend derives
// those client-side; we mirror that here so the tables render correctly.
async function csRenderVmServerUsb() {
    csSetToolbar('');
    let hosts;
    try { hosts = await csVmLoad(); } catch (e) { console.error('csRenderVmServerUsb: vm load failed', e); csSet(csErrorBox('Could not load USB', e)); return; }
    const h = csVmSelectedHost();
    if (!h) { csSet(csEmpty('No host selected.')); return; }
    const px = h.proxmox || {};
    const present = px.present_usb || [];
    const unknown = px.unknown_usb || [];
    const usbState = px.usb_state || [];
    // Index assigned-dongle state by bus_path (then vidpid) to derive active_vms
    // and missing status for each certified dongle.
    const stateByBus = {}, stateByVp = {};
    usbState.forEach(e => {
        if (!e || typeof e !== 'object') return;
        if (e.bus_path) stateByBus[e.bus_path] = e;
        if (e.vidpid) stateByVp[e.vidpid] = e;
    });
    const splitVp = u => {
        if (u.vid != null && u.pid != null) return [String(u.vid), String(u.pid)];
        const vp = String(u.vidpid || '');
        const i = vp.indexOf(':');
        return i > 0 ? [vp.slice(0, i), vp.slice(i + 1)] : [vp, ''];
    };
    const activeVms = u => {
        const e = (u.bus_path && stateByBus[u.bus_path]) || (u.vidpid && stateByVp[u.vidpid]) || {};
        const v = e.vmid;
        return (v != null && v !== '') ? [String(v)] : [];
    };
    const isMissing = u => {
        const e = (u.bus_path && stateByBus[u.bus_path]) || (u.vidpid && stateByVp[u.vidpid]) || {};
        return e.prov_status === 'missing' || e.missing_since != null;
    };
    // Approval-scope badge: the hub tags each certified device with
    // approval_scope (global / local / global+local) so the tenant can see how a
    // dongle was approved.
    const scopeBadge = s => {
        if (s === 'global+local') return '<span class="bg-green-100 text-green-700 px-1.5 py-0.5 rounded text-[10px] font-bold mr-1">Global</span><span class="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded text-[10px] font-bold">Local</span>';
        if (s === 'global') return '<span class="bg-green-100 text-green-700 px-1.5 py-0.5 rounded text-[10px] font-bold">Global</span>';
        if (s === 'local') return '<span class="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded text-[10px] font-bold">Local</span>';
        return '<span class="bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded text-[10px] font-bold">Certified</span>';
    };
    const sc = u => u.approval_scope || '';
    const g = present.filter(u => sc(u) === 'global').length;
    const l = present.filter(u => sc(u) === 'local').length;
    const b = present.filter(u => sc(u) === 'global+local').length;
    const total = present.length + unknown.length;
    // Fleet-wide total across every host on this cs server (the per-host
    // `total` above is just the selected host). csUsbCount sums present+unknown
    // per host; usb_state is deliberately excluded (assigned-only subset).
    const fleetTotal = (hosts || []).reduce((n, hh) => n + csUsbCount(hh), 0);
    const summary = `<div class="mb-3 text-xs text-slate-500 flex flex-wrap items-center gap-x-4 gap-y-1">
      <span><b class="text-sm text-slate-700">${fleetTotal}</b> total on cs server</span>
      <span class="text-slate-300">|</span>
      <span><b class="text-sm text-slate-700">${total}</b> on this host</span>
      <span><b class="text-sm text-slate-700">${present.length}</b> certified</span>
      ${g ? `<span><b class="text-sm text-slate-700">${g}</b> global</span>` : ''}
      ${l ? `<span><b class="text-sm text-slate-700">${l}</b> local</span>` : ''}
      ${b ? `<span><b class="text-sm text-slate-700">${b}</b> global+local</span>` : ''}
      <span><b class="text-sm text-slate-700">${unknown.length}</b> uncertified</span>
    </div>`;
    // Type options for the per-row dropdown. A certified dongle that hasn't
    // been classified yet shows a "—" placeholder (selected) so the operator
    // must pick wired/wireless to assign it; picking it re-certifies (the
    // backend updates type on re-certify). Non-standard stored types are kept.
    const typeOpts = cur => {
        const std = ['wireless', 'wired'];
        let opts = '';
        if (!cur) opts += '<option value="" selected>—</option>';
        if (cur && !std.includes(cur)) opts += `<option value="${csEscape(cur)}" selected>${csEscape(cur)}</option>`;
        for (const t of std) opts += `<option value="${t}"${cur === t ? ' selected' : ''}>${t}</option>`;
        return opts;
    };
    // Group physical dongles by vid:pid — one row per device MODEL with a Count
    // of how many physical instances exist (10 dongles of obda:c811 → one row,
    // count 10), not a row per dongle. Type/Approved are per-vid:pid (assigned
    // at certify time, shared by every instance of that vid:pid); Active-VMs and
    // Status are merged across the instances of that vid:pid. The summary totals
    // above stay physical (present.length/unknown.length) so "10 of one type"
    // still counts as 10 dongles.
    const groupByVp = arr => {
        const m = new Map();
        for (const u of (arr || [])) {
            const [vid, pid] = splitVp(u);
            const key = `${vid}:${pid}`;
            let g = m.get(key);
            if (!g) {
                g = { vid, pid, vidpid: key, items: [], name: '', type: u.type || '', scope: '' };
                m.set(key, g);
            }
            g.items.push(u);
            const nm = u.name || u.product || u.vidpid || '';
            if (nm && (g.name === '' || g.name === '—')) g.name = nm;
            const ssc = sc(u);
            if (ssc && !g.scope) g.scope = ssc;
            if (!g.type && u.type) g.type = u.type;
        }
        return [...m.values()];
    };
    const certGroups = groupByVp(present);
    const unGroups = groupByVp(unknown);
    const certRows = certGroups.map(g => {
        const vms = [...new Set(g.items.flatMap(activeVms))].filter(Boolean);
        const anyMissing = g.items.some(isMissing);
        return `<tr>
      <td class="px-3 py-2 text-sm">${csEscape(g.name || '—')}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(g.vid)}:${csEscape(g.pid)}</td>
      <td class="px-3 py-2"><select onchange="csUsbVidpid('${csEscape(g.vid)}','${csEscape(g.pid)}','certify', this.value)" class="text-[11px] border border-slate-200 rounded px-1 py-0.5 bg-white">${typeOpts(g.type)}</select></td>
      <td class="px-3 py-2">${scopeBadge(g.scope)}</td>
      <td class="px-3 py-2 text-center text-sm font-bold text-slate-700">${g.items.length}</td>
      <td class="px-3 py-2 text-slate-500">${csEscape(vms.join(', ') || '—')}</td>
      <td class="px-3 py-2">${csStatusBadge(anyMissing ? 'warning' : 'ok')}</td>
    </tr>`;
    }).join('');
    const unRows = unGroups.map(g => { return `<tr>
      <td class="px-3 py-2 text-sm">${csEscape(g.name || '—')}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(g.vid)}:${csEscape(g.pid)}</td>
      <td class="px-3 py-2 text-center text-sm font-bold text-slate-700">${g.items.length}</td>
      <td class="px-3 py-2"><div class="flex gap-1 items-center">
        <select class="cs-usb-row-type text-[11px] border border-slate-200 rounded px-1 py-0.5 bg-white"><option value="">—</option><option value="wireless">wireless</option><option value="wired">wired</option></select>
        <button onclick="csUsbCertifyRow(this, '${csEscape(g.vid)}','${csEscape(g.pid)}')" class="bg-green-100 text-green-700 px-2 py-0.5 rounded text-[10px] font-bold">Certify</button>
        <button onclick="csUsbVidpid('${csEscape(g.vid)}','${csEscape(g.pid)}','ignore')" class="bg-slate-200 text-slate-600 px-2 py-0.5 rounded text-[10px] font-bold">Ignore</button>
      </div></td>
    </tr>`; }).join('');
    // Diagnostic: when no dongles are present, show where the cs spoke put
    // USB data (admin-only sidecar from the hub) so a missing count can be
    // diagnosed without leaving the page.
    const dbg = window._csUsbDebug;
    const showDbg = (present.length + unknown.length === 0) && dbg && dbg.length;
    const dbgBox = showDbg ? `<details class="mb-3 border border-amber-200 bg-amber-50 rounded p-3">
      <summary class="text-[11px] font-bold text-amber-700 cursor-pointer">No USB dongles received — raw telemetry structure (admin)</summary>
      <pre class="text-[10px] text-slate-600 mt-2 whitespace-pre-wrap">${csEscape(JSON.stringify(dbg, null, 2))}</pre>
      <p class="text-[10px] text-amber-700 mt-2">If <code>proxmox.usb</code>/<code>top.usb</code> show no <code>present_usb</code>/<code>usb_devices</code>, the cs spoke isn't aggregating USB into its telemetry. If they appear under <code>top.usb</code> but not <code>proxmox.usb</code>, it's a hub shape-mapping gap.</p>
    </details>` : '';
    csSet(`<div>${csVmHostBanner()}
      ${dbgBox}
      ${summary}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Certified USB (${certGroups.length} type${certGroups.length === 1 ? '' : 's'} · ${present.length} dongle${present.length === 1 ? '' : 's'})</p>
      ${csTable(['Device', 'VID:PID', 'Type', 'Approved', 'Count', 'Active VMs', 'Status'], certRows)}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-5 mb-2">Uncertified / Unknown (${unGroups.length} type${unGroups.length === 1 ? '' : 's'} · ${unknown.length} dongle${unknown.length === 1 ? '' : 's'}) — pick a type, then Certify</p>
      ${csTable(['Device', 'VID:PID', 'Count', 'Type & Actions'], unRows)}
    </div>`);
}

window.csUsbVidpid = async function (vid, pid, action, type) {
    try {
        const body = { vid, pid, action };
        if (action === 'certify') {
            // Require an explicit wired/wireless (or storage/other) type — the
            // per-row dropdown's empty "—" must not certify a typeless dongle.
            // The backend updates type on re-certify, so changing a certified
            // dongle's dropdown just re-certifies with the new type.
            const t = String(type || '').trim().toLowerCase();
            if (t !== 'wireless' && t !== 'wired' && t !== 'storage' && t !== 'other') {
                alert('Select a type (wired or wireless) before certifying.');
                return;
            }
            body.type = t;
        }
        await csFetch(`/${csTenant()}/usb-vidpids?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        csVmFlash(action + ' queued for ' + vid + ':' + pid);
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 800);
    } catch (e) { console.error('csUsbVidpid: usb action failed', e); alert('USB action failed: ' + (e.message || e)); }
};

// Per-row Certify from the Uncertified table: reads the row's type <select>
// (empty "—" → block with an alert) and forwards to csUsbVidpid.
window.csUsbCertifyRow = async function (btn, vid, pid) {
    const cell = btn.closest('td');
    const sel = cell && cell.querySelector('.cs-usb-row-type');
    const type = sel ? sel.value : '';
    if (!type) { alert('Select a type (wired or wireless) before certifying.'); return; }
    await csUsbVidpid(vid, pid, 'certify', type);
};

// ── IoT (T3) — faithful "coming soon" placeholder ─────────────────────────────
function csRenderVmServerIot() {
    csSetToolbar('');
    const h = csVmSelectedHost() || (csVmHosts.length ? csVmHosts[0] : null);
    const px = (h && h.proxmox) || {};
    const t3 = px.t3_pci_devices || [];
    csSet(`<div>${csVmHostBanner()}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">IoT / T3 PCI Devices (${t3.length})</p>
      ${t3.length ? csTable(['Device', 'Address', 'Driver'], t3.map(d => `<tr>
        <td class="px-3 py-2 text-sm">${csEscape(d.name || d.device || '—')}</td>
        <td class="px-3 py-2 font-mono text-xs">${csEscape(d.address || '—')}</td>
        <td class="px-3 py-2 text-slate-500">${csEscape(d.driver || '—')}</td></tr>`).join(''))
      : csEmpty('No IoT/T3 PCI devices reported.', 'IoT provisioning surfaces here once the spoke relays T3 device state.')}
    </div>`);
}

// ── VirtualHere — status + device table (data not in relay yet) ─────────────
async function csRenderVmServerVh() {
    csSetToolbar('');
    await csVmLoad().catch((e) => { console.error('csRenderVmServerVh: csVmLoad failed (non-fatal, placeholder view)', e); });
    csSet(`<div>${csVmHostBanner()}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">VirtualHere</p>
      ${csEmpty('VirtualHere server/device state is not part of the CS telemetry relay yet.',
                'Once the spoke exposes vh_devices in its telemetry, the grouped device table renders here.')}
    </div>`);
}

// ── Command Queue ───────────────────────────────────────────────────────────
async function csRenderVmServerQueue() {
    csSetToolbar('');
    let cmds = [];
    try {
        const data = await csFetch(`/${csTenant()}/proxmx/commands?tenant_id=${csTenant()}`);
        cmds = (data && data.commands) || [];
    } catch (e) { console.error('csRenderVmServerQueue: command queue load failed', e); csSet(csErrorBox('Could not load command queue', e)); return; }
    const rows = cmds.map(c => `<tr>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(c.id ? c.id.slice(0,8) : '—')}</td>
      <td class="px-3 py-2 text-sm">${csEscape(c.action || '—')}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(c.target || '—')}</td>
      <td class="px-3 py-2">${csStatusBadge(c.status || 'pending')}</td>
      <td class="px-3 py-2 text-slate-400 text-xs">${csEscape(c.age_secs != null ? c.age_secs + 's' : '—')}</td>
      <td class="px-3 py-2 text-slate-500 text-xs">${csEscape(c.message || '—')}</td>
    </tr>`).join('');
    const sendForm = `<div class="hpe-card rounded-lg p-4 shadow-sm mb-4">
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Send Proxmox Command</p>
      <div class="flex flex-wrap gap-2 items-end text-sm">
        <div><label class="text-xs text-slate-400">Action</label>
          <select id="cs-cmd-action" class="border border-slate-200 rounded-md px-2 py-1">
            ${['start_vm','stop_vm','reboot_vm','snapshot_vm','reclone_vm','delete_vm','update_agent','unlock_template','proxmox_reclone_all'].map(a => `<option>${a}</option>`).join('')}
          </select></div>
        <div><label class="text-xs text-slate-400">Target (hostname)</label>
          <input id="cs-cmd-target" class="border border-slate-200 rounded-md px-2 py-1 w-40" placeholder="proxmox"/></div>
        <div><label class="text-xs text-slate-400">Args JSON</label>
          <input id="cs-cmd-args" class="border border-slate-200 rounded-md px-2 py-1 w-56" placeholder='{"vmid":90050}'/></div>
        <button onclick="csSendCommand()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-3 py-1.5 rounded-md text-xs font-bold">Send</button>
        <button onclick="csClearCommands()" class="bg-red-100 text-red-700 px-3 py-1.5 rounded-md text-xs font-bold">Clear Queue</button>
      </div></div>`;
    csSet(`<div>${sendForm}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Queue (${cmds.length})</p>
      ${csTable(['ID', 'Action', 'Target', 'Status', 'Age', 'Message'], rows)}
    </div>`);
}

window.csSendCommand = async function () {
    const action = csEl('cs-cmd-action') ? csEl('cs-cmd-action').value : '';
    const target = csEl('cs-cmd-target') ? csEl('cs-cmd-target').value.trim() : 'proxmox';
    let args = {};
    try { args = JSON.parse(csEl('cs-cmd-args').value || '{}'); } catch (e) { console.error('csSendCommand: args JSON parse failed, defaulting to {}', e); args = {}; }
    const type = action.startsWith('proxmox_') || action === 'unlock_template' || action === 'update_agent' ? action : null;
    try {
        await csFetch(`/${csTenant()}/proxmx/command?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify({ action, target, args, type }) });
        csRenderVmServerQueue();
    } catch (e) { console.error('csSendCommand: send failed', e); alert('Send failed: ' + (e.message || e)); }
};

window.csClearCommands = async function () {
    if (!confirm('Clear all pending/delivered commands?')) return;
    try {
        await csFetch(`/${csTenant()}/proxmx/commands?tenant_id=${csTenant()}`, { method: 'DELETE' });
        csRenderVmServerQueue();
    } catch (e) { console.error('csClearCommands: clear failed', e); alert('Clear failed: ' + (e.message || e)); }
};

// ── Details (node header + telemetry table + raw dump) ─────────────────────
async function csRenderVmServerDetails() {
    csSetToolbar('');
    try { await csVmLoad(); } catch (e) { console.error('csRenderVmServerDetails: vm load failed', e); csSet(csErrorBox('Could not load details', e)); return; }
    const h = csVmSelectedHost();
    if (!h) { csSet(csEmpty('No host selected.')); return; }
    const px = h.proxmox || {};
    const node = px.node || {};
    const kv = Object.entries(px).filter(([k]) => !['vms','usb_state','present_usb','unknown_usb','node'].includes(k))
        .map(([k, v]) => `<tr><td class="px-3 py-2 font-mono text-xs text-slate-500">${csEscape(k)}</td><td class="px-3 py-2 text-sm">${csEscape(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`).join('');
    csSet(`<div>${csVmHostBanner()}
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        ${csStat('Node', node.hostname || '—')}${csStat('CPU 1h', px.cpu_1h_avg || '—')}
        ${csStat('Mem 1h', px.mem_1h_avg || '—')}${csStat('Agent', px.agent_version || '—')}
      </div>
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Telemetry</p>
      ${csTable(['Key', 'Value'], kv)}
      <details class="mt-4 text-xs"><summary class="cursor-pointer text-slate-400">Raw payload</summary>${csJsonDump(h)}</details>
    </div>`);
}

// ── Clients / Central / API Server (per-spoke, from the aggregate reads) ────
async function csRenderVmServerClients() {
    csSetToolbar('');
    try { await csVmLoad(); } catch (e) { console.error('csRenderVmServerClients: vm load failed', e); csSet(csErrorBox('Could not load', e)); return; }
    const h = csVmSelectedHost();
    let clients = [];
    try {
        const data = await csFetch(`/aggregate/clients?tenant_id=${csTenant()}`);
        const row = (data && data.clients || []).find(c => c.spoke_id === (h && h.spoke_id));
        clients = row ? (row.clients || []) : [];
    } catch (e) { console.error('csRenderVmServerClients: per-host clients fetch failed', e); }
    const rows = clients.map(c => `<tr>
      <td class="px-3 py-2 text-sm">${csEscape(c.hostname || c.id || '—')}</td>
      <td class="px-3 py-2 text-slate-500">${csEscape(c.platform || c.hw_type || '—')}</td>
      <td class="px-3 py-2">${csOnlineBadge(c.online)}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(c.simulation_id || '—')}</td>
    </tr>`).join('');
    csSet(`<div>${csVmHostBanner()}${csTable(['Client', 'Platform', 'Online', 'Simulation'], rows)}</div>`);
}

async function csRenderVmServerCentral() {
    csSetToolbar('');
    try { await csVmLoad(); } catch (e) { console.error('csRenderVmServerCentral: vm load failed', e); csSet(csErrorBox('Could not load', e)); return; }
    const h = csVmSelectedHost();
    let central = {};
    try {
        const data = await csFetch(`/aggregate/central?tenant_id=${csTenant()}`);
        const row = (data && data.spokes || []).find(s => s.spoke_id === (h && h.spoke_id));
        central = (row && row.central_status) || {};
    } catch (e) { console.error('csRenderVmServerCentral: per-host central fetch failed', e); }
    const status = central.status || central.token_state || 'unknown';
    const wc = central.wireless_clients || 0;
    const ha = central.hardware_alerts || 0;
    csSet(`<div>${csVmHostBanner()}
      <div class="grid grid-cols-3 gap-3 mb-4">${csStat('Status', status)}${csStat('Wireless', wc)}${csStat('Alerts', ha)}</div>
      <details class="text-xs"><summary class="cursor-pointer text-slate-400">Raw central payload</summary>${csJsonDump(central)}</details>
    </div>`);
}

async function csRenderVmServerApiServer() {
    csSetToolbar('');
    try { await csVmLoad(); } catch (e) { console.error('csRenderVmServerApiServer: vm load failed', e); csSet(csErrorBox('Could not load', e)); return; }
    const h = csVmSelectedHost();
    const api = (h && h.api_server) || {};
    const health = api.health || {};
    const rows = Object.entries(health).map(([k, v]) => `<tr><td class="px-3 py-2 font-mono text-xs text-slate-500">${csEscape(k)}</td><td class="px-3 py-2 text-sm">${csEscape(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`).join('');
    csSet(`<div>${csVmHostBanner()}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">API Server Health</p>
      ${csTable(['Key', 'Value'], rows)}
      <details class="mt-4 text-xs"><summary class="cursor-pointer text-slate-400">Raw payload</summary>${csJsonDump(api)}</details>
    </div>`);
}

// ── Register all VM Server children ─────────────────────────────────────────
window.CS_CHILD_RENDERERS['VM Server::Overview']     = csRenderVmServer;
window.CS_CHILD_RENDERERS['VM Server::VMs']          = csRenderVmServerVms;
window.CS_CHILD_RENDERERS['VM Server::Console']      = csRenderVmServerConsole;
window.CS_CHILD_RENDERERS['VM Server::Terminal']     = csRenderVmServerTerminal;
window.CS_CHILD_RENDERERS['VM Server::USB']           = csRenderVmServerUsb;
window.CS_CHILD_RENDERERS['VM Server::IoT']           = csRenderVmServerIot;
window.CS_CHILD_RENDERERS['VM Server::VirtualHere']   = csRenderVmServerVh;
window.CS_CHILD_RENDERERS['VM Server::Command Queue'] = csRenderVmServerQueue;
window.CS_CHILD_RENDERERS['VM Server::Details']       = csRenderVmServerDetails;
// VM Server :: Clients / Central / API Server children removed from the nav
// (those surfaces live in their own top-level Simulations tabs). The render
// fns (csRenderVmServerClients/Central/ApiServer) are left as inert dead code.

window.CS_CHILD_RENDERERS['Dashboard::Checks']       = csRenderSimulations;
window.CS_CHILD_RENDERERS['Dashboard::Hardware']     = csRenderSimHardware;
window.CS_CHILD_RENDERERS['Dashboard::Client Count'] = csRenderSimClientCount;

window.CS_CHILD_RENDERERS['Clients::All'] = function () { return csRenderClients('all'); };
window.CS_CHILD_RENDERERS['Clients::T1']  = function () { return csRenderClients('t1'); };
window.CS_CHILD_RENDERERS['Clients::T2']  = function () { return csRenderClients('t2'); };

window.csOpenVmConsole = function (spokeId) {
    alert(`VM console for ${spokeId} is wired in Phase 5 (noVNC over /sim/ws/console/{sessionId}).`);
};
window.csOpenSpokeShell = function (spokeId) {
    alert(`Spoke shell for ${spokeId} is wired in Phase 5 (xterm.js over /sim/api/{tenant}/spokes/{spoke}/shell).`);
};

/* ===========================================================================
 * 8. Spoke Management — list spokes, admin assign/rebind, PSK self-provision
 *    GET  /sim/api/spokes?tenant_id={T}                  (scoped to caller)
 *    POST /sim/api/tenant/{T}/spokes/{id}/claim           (PSK claim)
 *    GET/POST/DELETE /sim/api/tenant/{T}/onboarding-psk   (PSK mint/revoke)
 * =========================================================================== */

async function csRenderSpokeManagement() {
    const admin = (typeof isAdmin === 'function') ? isAdmin() : false;
    const tenant = csTenantRaw();
    let spokes = [];
    try {
        const data = await csFetch(`/spokes?tenant_id=${csTenant()}`);
        spokes = (data && data.spokes) || [];
    } catch (e) { console.error('csRenderSpokeManagement: spokes load failed', e); csSetToolbar(''); csSet(csErrorBox('Could not load spokes', e)); return; }

    // Attach assigned_site / label from module metadata if the list didn't
    // already include them (the aggregate list may omit metadata-only fields).
    window._csSpokeRows = spokes;
    const total = spokes.length;
    const online = spokes.filter(s => s.connected).length;
    const pending = spokes.filter(s => !s.approved).length;
    const unbound = spokes.filter(s => !s.tenant_id).length;

    csSetToolbar(`<input id="cs-spoke-q" oninput="csSpokeFilter()" placeholder="Search spokes…" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-64">
      <button onclick="csSpokeExpandAll(true)" class="ml-2 text-xs text-slate-500 hover:text-slate-700">Expand all</button>
      <button onclick="csSpokeExpandAll(false)" class="ml-1 text-xs text-slate-500 hover:text-slate-700">Collapse all</button>
      <button onclick="csRenderSpokeManagement()" class="ml-2 text-xs text-[#01A982] font-bold hover:underline">Refresh</button>`);

    const banner = (admin && (pending || unbound))
        ? `<div class="hpe-card rounded-lg p-4 shadow-sm border-l-4 border-amber-400 bg-amber-50">
             <p class="text-sm text-amber-700"><b>${pending}</b> pending, <b>${unbound}</b> unbound — assign/approve below so their telemetry reaches a tenant's VM Server.</p>
           </div>`
        : '';

    const summary = csSummaryRow([[total, 'Spokes'], [online, 'Online'], [pending, 'Pending'], [unbound, 'Unbound']]);

    const typeBadge = (t) => {
        const s = String(t || '').toLowerCase();
        const cls = (s === 'simulation' || s === 'client-sim' || s === 'cs')
            ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
        return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cls}">${csEscape(t || '—')}</span>`;
    };
    const tenantCell = (t) => t ? csEscape(t) : `<span class="text-amber-600 font-semibold">unbound</span>`;

    window._csSpokeRowHtml = function (s) {
        const isPending = !s.approved;
        const assignBtn = admin
            ? `<button onclick="openSpokeAssignModal('${csEscape(s.spoke_id)}','${csEscape(s.tenant_id || '')}')" class="text-xs text-[#01A982] font-bold hover:underline mr-2">${!s.tenant_id ? 'Assign' : 'Rebind'}</button>`
            : '';
        const approveBtn = admin
            ? `<button onclick="csSpokeApprove('${csEscape(s.spoke_id)}',${isPending ? 'true' : 'false'})" class="text-xs ${isPending ? 'text-green-600 font-bold' : 'text-amber-600'} hover:underline mr-2">${isPending ? 'Approve' : 'Revoke'}</button>`
            : '';
        const labelBtn = admin
            ? `<button onclick="csSpokeEditLabel('${csEscape(s.spoke_id)}','${csEscape((s.display_name || s.spoke_id || '').replace(/'/g, "\\'"))}')" class="text-xs text-slate-500 hover:underline mr-2">Label</button>`
            : '';
        const cfgBtn = admin
            ? `<button onclick="csSpokePatchConfig('${csEscape(s.spoke_id)}')" class="text-xs text-slate-500 hover:underline mr-2">Config</button>`
            : '';
        const diagBtn = admin
            ? `<button onclick="csSpokeDiag('${csEscape(s.spoke_id)}')" class="text-xs text-slate-500 hover:underline mr-2">Diag</button>`
            : '';
        const delBtn = admin
            ? `<button onclick="csSpokeDelete('${csEscape(s.spoke_id)}')" class="text-xs text-red-500 hover:underline">Delete</button>`
            : '';
        const actions = admin ? (assignBtn + approveBtn + labelBtn + cfgBtn + diagBtn + delBtn) : '<span class="text-slate-300">—</span>';
        return `<tr class="cs-spoke-row" data-cs-spoke="${csEscape(s.spoke_id).toLowerCase()}" data-cs-name="${csEscape((s.display_name || s.spoke_id || '').toLowerCase())}">
          <td class="px-3 py-2 font-mono text-xs">${csEscape(s.spoke_id)}</td>
          <td class="px-3 py-2 text-sm">${csEscape(s.display_name || s.spoke_id)}</td>
          <td class="px-3 py-2">${typeBadge(s.module_type)}</td>
          <td class="px-3 py-2">${csOnlineBadge(s.connected)}</td>
          <td class="px-3 py-2">${s.approved ? '<span class="text-green-600 text-xs font-bold">Approved</span>' : '<span class="text-amber-600 text-xs font-bold">Pending</span>'}</td>
          <td class="px-3 py-2 text-xs">${tenantCell(s.tenant_id)}</td>
          <td class="px-3 py-2 text-xs text-slate-500">${(s.vm_count != null) ? s.vm_count : '—'}</td>
          <td class="px-3 py-2 whitespace-nowrap">${actions}</td>
        </tr>`;
    };

    const rows = spokes.map(window._csSpokeRowHtml).join('');
    const spokesCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex justify-between items-center mb-3">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spokes</h3>
        <span class="text-xs text-slate-400">${admin ? 'All tenants (admin)' : 'Tenant: ' + csEscape(tenant)}</span>
      </div>
      ${csTable(['Spoke ID', 'Name', 'Type', 'State', 'Approval', 'Tenant', 'VMs', 'Actions'], rows)}
    </div>`;

    const claimCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Claim a Pending Simulation Spoke</h3>
      <p class="text-[11px] text-slate-400 mb-3">If a <b>Simulation</b> spoke connected <em>without</em> a PSK it lands as pending. Enter its Spoke ID and this tenant's onboarding PSK to approve + bind it to <span class="font-mono">${csEscape(tenant)}</span>. Only Simulation (Client-Sim) spokes can be claimed here.</p>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <input id="cs-claim-id" placeholder="spoke-id" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono">
        <input id="cs-claim-psk" placeholder="onboarding PSK" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono">
        <button onclick="csClaimSpoke()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold shadow-sm">Claim</button>
      </div>
      <span id="cs-claim-msg" class="text-xs block mt-2"></span>
    </div>`;

    let pskCard = '';
    try { pskCard = await csSpokeMgmtPskCard(); } catch (e) { console.error('csRenderSpokeManagement: psk card load failed', e); pskCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Onboarding PSK', e).replace('py-10', 'py-6')}</div>`; }

    csSet(`<div class="space-y-4">${banner}${summary}${spokesCard}${claimCard}${pskCard}</div>`);
}

window.csSpokeFilter = function () {
    const q = (csEl('cs-spoke-q') && csEl('cs-spoke-q').value || '').toLowerCase();
    document.querySelectorAll('.cs-spoke-row').forEach(tr => {
        const hay = (tr.getAttribute('data-cs-spoke') || '') + ' ' + (tr.getAttribute('data-cs-name') || '');
        tr.classList.toggle('hidden', q && !hay.includes(q));
    });
};

window.csSpokeExpandAll = function (open) {
    // No per-row expandable detail in this view (actions are inline buttons);
    // this collapses/expands the whole spokes card for a focused list view.
    const card = document.querySelector('#cs-content .hpe-card');
    if (!card) return;
    card.querySelectorAll('details').forEach(d => { d.open = !!open; });
};

window.csSpokeApprove = async function (spokeId, isPending) {
    const action = isPending ? 'approve' : 'unapprove';
    if (!confirm(`${isPending ? 'Approve' : 'Revoke'} spoke ${spokeId}?`)) return;
    try {
        await csFetch(`/${csTenant()}/spokes/${encodeURIComponent(spokeId)}/approve`, { method: 'POST', body: JSON.stringify({ action }) });
        if (typeof showToast === 'function') showToast(`Spoke ${action}d`, 'success');
        await csRenderSpokeManagement();
    } catch (e) { console.error('csSpokeApprove: approve/unapprove failed', e); if (typeof showToast === 'function') showToast(e.message, 'error'); }
};

window.csSpokeEditLabel = async function (spokeId, current) {
    const label = prompt(`Label for ${spokeId}:`, current);
    if (label === null) return;
    try {
        await csFetch(`/${csTenant()}/spokes/${encodeURIComponent(spokeId)}/label`, { method: 'PATCH', body: JSON.stringify({ label }) });
        if (typeof showToast === 'function') showToast('Label saved', 'success');
        await csRenderSpokeManagement();
    } catch (e) { console.error('csSpokeEditLabel: label save failed', e); if (typeof showToast === 'function') showToast(e.message, 'error'); }
};

window.csSpokePatchConfig = async function (spokeId) {
    const raw = prompt(`Config JSON to push to ${spokeId} (applied via CS_CONFIG_UPDATE):`, '{\n  \n}');
    if (raw === null) return;
    let cfg;
    try { cfg = JSON.parse(raw); } catch (e) { console.error('csSpokePatchConfig: invalid JSON', e); if (typeof showToast === 'function') showToast('Invalid JSON: ' + e.message, 'error'); return; }
    try {
        const r = await csFetch(`/${csTenant()}/spokes/${encodeURIComponent(spokeId)}/config`, { method: 'PATCH', body: JSON.stringify({ config: cfg }) });
        if (typeof showToast === 'function') showToast(`Config pushed to ${r.pushed_to_spokes || 0} spoke(s)`, 'success');
    } catch (e) { console.error('csSpokePatchConfig: config push failed', e); if (typeof showToast === 'function') showToast(e.message, 'error'); }
};

window.csSpokeDiag = async function (spokeId) {
    try {
        const d = await csFetch(`/${csTenant()}/spokes/${encodeURIComponent(spokeId)}/config-diag`);
        alert(`Spoke ${spokeId} config-diag:\n\n` +
              `last_seen: ${d.last_seen || '—'}\n` +
              `applied_error: ${d.applied_error || 'none'}\n` +
              `telemetry_keys: ${(d.telemetry_keys || []).join(', ') || '—'}\n\n` +
              `applied_config:\n${JSON.stringify(d.applied_config, null, 2)}`);
    } catch (e) { console.error('csSpokeDiag: config-diag failed', e); if (typeof showToast === 'function') showToast(e.message, 'error'); }
};

window.csSpokeDelete = async function (spokeId) {
    if (!confirm(`Permanently delete spoke ${spokeId}? This closes its connection and wipes its registration + keys. It must fully re-onboard to return.`)) return;
    try {
        await csFetch(`/spokes/${encodeURIComponent(spokeId)}?tenant_id=${csTenant()}`, { method: 'DELETE' });
        if (typeof showToast === 'function') showToast('Spoke deleted', 'success');
        await csRenderSpokeManagement();
    } catch (e) { console.error('csSpokeDelete: delete failed', e); if (typeof showToast === 'function') showToast(e.message, 'error'); }
};

async function csSpokeMgmtPskCard() {
    const data = await csFetch('/tenant/' + csTenant() + '/onboarding-psk');
    const psks = (data && data.psks) || [];
    const tenant = csTenantRaw();
    const rows = psks.map(p => `<tr>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(p)}</td>
      <td class="px-3 py-2 text-right"><button onclick="csSpokeMgmtRevokePsk('${csEscape(p)}')" class="text-xs text-red-500 hover:underline">Revoke</button></td>
    </tr>`).join('');
    const deploy = psks.length
        ? `<div class="mt-3 text-[11px] text-slate-500 bg-slate-50 border border-slate-200 rounded-md p-3">
             <p class="font-bold text-slate-600 mb-1">Self-provision a spoke (auto-bind to ${csEscape(tenant)}):</p>
             <p class="font-mono">LM_ONBOARDING_PSK=&lt;psk&gt; LM_TENANT_ID_HINT=${csEscape(tenant)}</p>
             <p class="mt-1 text-slate-400">Set these env vars (or <span class="font-mono">--onboarding-psk</span> / <span class="font-mono">--tenant-id-hint</span>) on the spoke and restart — it auto-approves + binds on connect.</p>
           </div>`
        : '<p class="text-[11px] text-slate-400 mt-2">Generate a PSK to reveal the self-provision deploy snippet.</p>';
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex justify-between items-center mb-3">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Onboarding PSK <span class="text-slate-400 normal-case font-normal">· tenant ${csEscape(tenant)}</span></h3>
        <button onclick="csSpokeMgmtGenPsk()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-1.5 rounded-md text-xs font-bold shadow-sm">+ Generate</button>
      </div>
      ${psks.length ? csTable(['PSK', ''], rows) : '<p class="text-xs text-slate-400 italic py-4 text-center">No PSKs issued.</p>'}
      <span id="cs-psk-mgmt-msg" class="text-xs"></span>
      ${deploy}
    </div>`;
}

window.csSpokeMgmtGenPsk = async function () {
    const msg = csEl('cs-psk-mgmt-msg');
    try { await csFetch('/tenant/' + csTenant() + '/onboarding-psk', { method: 'POST', body: '{}' }); await csRenderSpokeManagement(); }
    catch (e) { console.error('csSpokeMgmtGenPsk: psk generate failed', e); if (msg) { msg.textContent = e.message; msg.className = 'text-xs text-red-500'; } }
};

window.csSpokeMgmtRevokePsk = async function (psk) {
    const msg = csEl('cs-psk-mgmt-msg');
    try { await csFetch('/tenant/' + csTenant() + '/onboarding-psk', { method: 'DELETE', body: JSON.stringify({ psk }) }); await csRenderSpokeManagement(); }
    catch (e) { console.error('csSpokeMgmtRevokePsk: psk revoke failed', e); if (msg) { msg.textContent = e.message; msg.className = 'text-xs text-red-500'; } }
};

window.csClaimSpoke = async function () {
    const msg = csEl('cs-claim-msg');
    const spokeId = ((csEl('cs-claim-id') && csEl('cs-claim-id').value) || '').trim();
    const psk = ((csEl('cs-claim-psk') && csEl('cs-claim-psk').value) || '').trim();
    if (!spokeId || !psk) {
        if (msg) { msg.textContent = 'Spoke ID and PSK are required.'; msg.className = 'text-xs text-red-500'; }
        return;
    }
    try {
        await csFetch('/tenant/' + csTenant() + '/spokes/' + encodeURIComponent(spokeId) + '/claim?tenant_id=' + csTenant(),
            { method: 'POST', body: JSON.stringify({ onboarding_psk: psk }) });
        if (msg) { msg.textContent = 'Claimed — spoke approved + bound.'; msg.className = 'text-xs text-green-600'; }
        if (typeof showToast === 'function') showToast('Spoke claimed', 'success');
        await csRenderSpokeManagement();
    } catch (e) {
        console.error('csClaimSpoke: claim failed', e);
        const m = (e && e.message) ? e.message : String(e);
        if (msg) { msg.textContent = m; msg.className = 'text-xs text-red-500'; }
        if (typeof showToast === 'function') showToast('Claim failed: ' + m, 'error');
    }
};

})();