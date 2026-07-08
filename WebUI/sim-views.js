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

// Debounce a keystroke-driven filter so a fast typist doesn't re-render the
// whole list (csRenderClientRows / cs-sim-checks table) on every keypress.
// The select-driven filters (onchange) keep calling the immediate function —
// a single dropdown change should apply instantly, not on a 200ms delay.
function csDebounce(fn, wait) {
    let t = null;
    return function () {
        clearTimeout(t);
        const ctx = this, args = arguments;
        t = setTimeout(() => fn.apply(ctx, args), wait);
    };
}

function csSet(html) {
    // Auto-refresh chokepoint: while a telemetry-driven refresh cycle is in
    // flight (csRefreshInFlight, set only by csWsRefresh) AND the user is
    // actively editing a form control anywhere on the page, refuse to replace
    // #cs-content's innerHTML — that would wipe the field's value + focus/
    // cursor out from under an in-progress edit. The pre-fetch guard in
    // csWsRefresh can't see a user who focuses a field DURING an awaited
    // csFetch/csVmLoad inside a renderer (e.g. csRenderSetupCentralApi's two
    // fetches before this csSet); this gate closes that race for EVERY
    // renderer in one place. The next telemetry pulse (~10s, debounced)
    // retries once the user is done. Explicit renders (tab switch, Save/Test
    // buttons, post-action reloads) never set csRefreshInFlight, so they are
    // never blocked here.
    if (csRefreshInFlight && csUserIsEditing()) return;
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
 *                         '/aggregate/clients?tenant_id=default'). csFetch
 *                         appends ?tenant_id=<csTenant()> automatically if
 *                         the path doesn't already carry one (see below) —
 *                         you don't need to add it yourself, though existing
 *                         call sites that already do are left alone.
 * @param {RequestInit} [opts] Standard fetch options; `headers` are merged with
 *                         the default JSON Content-Type header.
 * @returns {Promise<any>} Parsed JSON (object/array) when the response is
 *                         JSON, otherwise a string (response text).
 * @throws {Error} On 401 (session expired), 404 (not implemented), or any
 *                         non-ok status with the server's detail surfaced.
 */
async function csFetch(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    // The backend's get_tenant_id() dependency (core/src/simulations/routes.py)
    // resolves the tenant ONLY from the query string (?tenant_id= / ?tenant=)
    // — it never reads a {tenant} PATH segment, even though most routes have
    // one. Around two dozen call sites in this file built paths like
    // '/tenant/' + csTenant() + '/hub-config' with no query param at all,
    // so those requests silently fell back to whatever the admin's session
    // resolves to instead of the tenant actually selected in the UI —
    // causing e.g. the VM Server auto-provisioning toggle (whose call DID
    // append ?tenant_id=) and Setup/Proxmox's same setting (whose call did
    // NOT) to permanently read/write two different tenant buckets. Fixed
    // once here instead of auditing every call site: append tenant_id
    // unless the caller already put one in the query string.
    let url = '/sim/api' + path;
    if (!/[?&](tenant_id|tenant)=/.test(url)) {
        url += (url.includes('?') ? '&' : '?') + 'tenant_id=' + csTenant();
    }
    const res = await fetch(url, { ...opts, headers });
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
    csResetHubConfig:            { m: 'POST',   p: '/tenant/{tenant}/hub-config/reset',          api: 'reset_hub_config' },

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

    // ── PSK (onboarding-psk; used by the Spoke Mgmt card — Setup/General's
    //    duplicate copy was removed since Spoke Management already owns PSKs) ──
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
    csKillSwitchGet:             { m: 'GET',    p: '/{tenant}/kill-switch',                       api: 'cs_get_kill_switch' },
    csKillSwitchSet:             { m: 'POST',   p: '/{tenant}/kill-switch',                       api: 'cs_set_kill_switch' },
    csDemoActive:                { m: 'GET',    p: '/{tenant}/demo/active',                       api: 'cs_demo_active' },
    csDemoScenarios:             { m: 'GET',    p: '/{tenant}/demo/scenarios',                    api: 'cs_demo_scenarios' },
    csDemoTrigger:               { m: 'POST',   p: '/{tenant}/demo/client/{hostname}/scenario',   api: 'cs_demo_set_scenario' },
    csDemoClear:                 { m: 'DELETE', p: '/{tenant}/demo/client/{hostname}/scenario',   api: 'cs_demo_clear_scenario' },
    // ── per-client override Control Panel (persisted registry overrides) ──
    csGetClientControl:          { m: 'GET',    p: '/{tenant}/clients/{hostname}/control',        api: 'cs_get_client_control' },
    csSetClientControl:          { m: 'POST',   p: '/{tenant}/clients/{hostname}/control',        api: 'cs_set_client_control' },
    csClearClientControl:        { m: 'DELETE', p: '/{tenant}/clients/{hostname}/control',        api: 'cs_clear_client_control' },
    csControlAll:                { m: 'POST',   p: '/{tenant}/clients/control-all',               api: 'cs_control_all' },
    csVmAction:                  { m: 'POST',   p: '/{tenant}/spokes/{spoke_id}/proxmox-command',api: 'cs_spoke_proxmox_command' },
    csVmBulk:                    { m: 'POST',   p: '/{tenant}/spokes/{spoke_id}/proxmox-command',api: 'cs_spoke_proxmox_command' },
    csRenderVmServerQueue:       { m: 'GET',    p: '/{tenant}/proxmx/commands',                  api: 'cs_list_commands' },
    csSendCommand:               { m: 'POST',   p: '/{tenant}/proxmx/command',                   api: 'cs_enqueue_command' },
    csClearCommands:             { m: 'DELETE', p: '/{tenant}/proxmx/commands',                  api: 'cs_clear_commands' },
    csDeleteCommand:             { m: 'DELETE', p: '/{tenant}/proxmx/commands/{cmd_id}',          api: 'cs_delete_command' },
    csExpirePending:             { m: 'DELETE', p: '/{tenant}/proxmx/commands/pending',           api: 'cs_expire_pending' },

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

// Shared toast for every "Save & Push to Spokes"-style route (they all
// return {pushed_to_spokes, queued}). The spoke may be approved+bound but
// momentarily unreachable (self-update restart, brief reconnect blip) — in
// that case push_or_queue_to_spoke (core/src/main.py) queues the change via
// the Mailbox instead of dropping it, so it applies the moment the spoke
// reconnects rather than being lost. Surface that as a distinct amber toast
// instead of claiming the change already landed.
function csPushToast(r, verb) {
    verb = verb || 'Saved';
    const n = (r && r.pushed_to_spokes != null) ? r.pushed_to_spokes : 0;
    if (r && r.queued) {
        showToast(`${verb} — spoke temporarily unreachable, queued for delivery on reconnect.`, 'info');
    } else {
        showToast(`${verb}. Pushed to ${n} spoke(s).`, 'success');
    }
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
    // opts.headerHtml: optional array (same length as headers) of raw HTML to
    // use for a given column's <th> instead of the escaped header text — used
    // by the VM Server VMs table to put a "select all" checkbox in the header.
    const rawHeaders = opts.headerHtml || [];
    const ths = headers.map((h, i) => `<th class="px-4 py-2 text-left font-semibold">${rawHeaders[i] || csEscape(h)}</th>`).join('');
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
// True only while a telemetry-driven refresh cycle (csWsRefresh → loadCSData →
// renderer → csSet) is in flight. Gates csSet's innerHTML replace so a user who
// focuses a field DURING a renderer's awaited fetch doesn't get stomped — see
// csSet. Explicit loadCSData calls (Save/post-action reloads) leave this false.
let csRefreshInFlight = false;

// Pages that telemetry must NEVER auto-refresh, even when the user is idle.
// These are form-heavy / config pages where a silent innerHTML replace is
// disruptive (wipes un-saved local state, re-mounts widgets, drops scroll
// position) and the data is either static or has its own explicit Refresh
// button. Keyed by `${currentSubView}::${currentSubChild}` (matches the
// CS_CHILD_RENDERERS registry). Only the telemetry-driven csWsRefresh path
// honors this — explicit loadCSData calls (tab switch, Save, post-action
// reload, the Refresh button) always render.
const CS_NO_REFRESH = new Set([
    'Setup::Proxmox',   // Proxmox hypervisor config — manual Refresh only
    'Config::API',      // Config → API
    'Config::Simulation', // Config → Simulation (form-heavy)
]);

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

// True while the user is actively focused on a form control anywhere on the
// page (typing in a text/number field, mid-interaction with a checkbox/select/
// textarea just clicked). loadCSData's re-render replaces the ENTIRE current
// view's innerHTML (csSet), which would otherwise wipe both the field's value
// AND focus/cursor position out from under an in-progress edit — matching
// what the original client-sim UI's per-field ``!input.matches(':focus')``
// guards prevented, but applied once at the render chokepoint instead of
// needing every render function to remember to add its own guard.
function csUserIsEditing() {
    const el = document.activeElement;
    if (el) {
        const tag = el.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    }
    // VM Server bulk-select: focus alone isn't enough here. Checking boxes
    // then moving toward Start/Stop/Delete shifts focus off any checkbox
    // (and off the page entirely once the mouse is down on the button) well
    // before the click lands, so a refresh landing in that gap wiped the
    // whole selection out from under the user even though they were still
    // actively mid-action. A checked box is a timing-independent signal that
    // the user has a pending selection, regardless of what currently has
    // focus — don't refresh (and rebuild the table from scratch) while one
    // exists.
    return !!document.querySelector('.cs-vm-sel:checked');
}

function csWsRefresh() {
    if (typeof currentView === 'undefined' || currentView !== 'cs') return;
    if (csWsRefreshTimer) return; // debounce
    csWsRefreshTimer = setTimeout(() => {
        csWsRefreshTimer = null;
        // Page-level denylist: never auto-refresh these even when idle.
        // Explicit renders (tab switch / Save / Refresh button) bypass this.
        const childKey = (typeof currentSubChild !== 'undefined' ? currentSubChild : '');
        if (CS_NO_REFRESH.has(currentSubView + '::' + childKey)) return;
        // Don't stomp an in-progress edit on ANY page (Config, Auto-
        // Provisioning, Central API Setup, or a search box on a live-data
        // page) — skip this cycle and let the next telemetry pulse (~10s
        // later, debounced above) retry once the user is done.
        if (csUserIsEditing()) return;
        // Mark the refresh cycle in flight so csSet's innerHTML replace also
        // bails if the user focuses a field DURING a renderer's awaited fetch
        // (the pre-check above can't see that). Cleared in finally so a
        // thrown renderer still resets the gate.
        csRefreshInFlight = true;
        loadCSData(currentSubView, currentSubChild, true).finally(
            () => { csRefreshInFlight = false; });
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
            <h3 class="text-lg font-bold text-slate-700 mb-1">${csEscape(primary)} · ${csEscape(child)} ${helpIcon('cs', null, 'Simulations help')}</h3>
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

// ── Kill switch (global sim emergency stop) ─────────────────────────────────
// Ports the legacy cs webui-spoke's prominent always-visible kill-switch
// banner. The spoke's engine.set_kill_switch persists kill_switch.txt and
// short-circuits every sim iteration to KILLED. Prepended to the Dashboard +
// Clients views so the emergency stop is one click away wherever the operator
// lands. Reads via GET /kill-switch; toggles via POST /kill-switch.
async function csKillSwitchBanner() {
    let ks = null, connected = false;
    try {
        const r = await csFetch(`/${csTenant()}/kill-switch?tenant_id=${csTenant()}`);
        ks = r && r.kill_switch; connected = !!(r && r.spoke_connected);
    } catch (e) { console.warn('csKillSwitchBanner: read failed', e); }
    if (ks === true) {
        return `<div class="rounded-lg border-2 border-red-500 bg-red-50 p-3 flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="text-2xl">⛔</span>
            <div><p class="text-sm font-bold text-red-700">SIMULATIONS HALTED — Kill switch active</p>
            <p class="text-xs text-red-600">All sim iterations are short-circuited to KILLED on this tenant's cs spoke.</p></div>
          </div>
          <button onclick="csToggleKillSwitch(false)" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-bold">▶ Resume Sims</button>
        </div>`;
    }
    if (ks === false) {
        return `<div class="rounded-lg border border-amber-300 bg-amber-50 p-3 flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="text-xl">🟢</span>
            <p class="text-sm font-bold text-amber-700">Kill switch: OFF — simulations running</p>
          </div>
          <button onclick="csToggleKillSwitch(true)" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-bold">⛔ Emergency Stop</button>
        </div>`;
    }
    return `<div class="rounded-lg border border-slate-200 bg-slate-50 p-3 flex items-center justify-between">
      <div class="flex items-center gap-3"><span class="text-xl">⚪</span>
      <p class="text-sm text-slate-500">Kill switch: ${connected ? 'unknown' : 'spoke offline'}</p></div>
      <button disabled class="bg-slate-200 text-slate-400 px-4 py-2 rounded-md text-sm font-bold cursor-not-allowed">Emergency Stop</button>
    </div>`;
}

window.csToggleKillSwitch = async function (on) {
    if (on && !confirm("EMERGENCY STOP: halt all simulations on this tenant's cs spoke?")) return;
    try {
        await csFetch(`/${csTenant()}/kill-switch?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ on }) });
        if (typeof showToast === 'function') showToast(on ? 'Kill switch ON — sims halted' : 'Kill switch OFF — sims resumed', on ? 'error' : 'success');
        loadCSData(currentSubView, currentSubChild, true);
        if (typeof window.csKillSwitchMountChip === 'function') window.csKillSwitchMountChip('cs-ks-chip');
    } catch (e) { console.error('csToggleKillSwitch: toggle failed', e); if (typeof showToast === 'function') showToast('Kill-switch toggle failed: ' + (e.message || e), 'error'); }
};

// Compact kill-switch control mounted into the Clients child strip (All/T1/T2),
// pinned far right by renderSecondaryNav. Reads the same GET /kill-switch state
// as the banner and toggles via csToggleKillSwitch. Spoke-offline → a muted label.
window.csKillSwitchMountChip = async function (elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    let ks = false, connected = false;
    try {
        const r = await csFetch(`/${csTenant()}/kill-switch?tenant_id=${csTenant()}`);
        ks = r && r.kill_switch; connected = !!(r && r.spoke_connected);
    } catch (e) { console.warn('csKillSwitchMountChip: read failed', e); }
    if (!connected) {
        el.innerHTML = `<span class="text-[10px] normal-case tracking-normal text-slate-400">Kill switch: spoke offline</span>`;
        return;
    }
    const ksBtn = ks
        ? `<button onclick="csToggleKillSwitch(false)" title="Simulations halted — click to resume"
             class="normal-case tracking-normal bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded-md text-xs font-bold">▶ Resume Sims</button>`
        : `<button onclick="csToggleKillSwitch(true)" title="Emergency stop all simulations on this tenant"
             class="normal-case tracking-normal bg-white hover:bg-red-50 text-red-600 border border-red-300 px-3 py-1 rounded-md text-xs font-bold">⛔ Emergency Stop</button>`;
    // Purge Clients lives next to the Emergency Stop chip in this same strip,
    // sized identically to it (px-3 py-1 rounded-md text-xs font-bold, outline
    // red). Shown only on the Clients child strip — purge is client-specific.
    // Moved here from the csRenderClients toolbar so the destructive action sits
    // with the other emergency control at the top of the view.
    const purgeBtn = (typeof currentSubView !== 'undefined' && currentSubView === 'Clients')
        ? `<button id="cs-purge-clients-btn" onclick="csPurgeClients(this)" title="Remove all client records from memory and disk"
             class="normal-case tracking-normal bg-white hover:bg-red-50 text-red-600 border border-red-300 px-3 py-1 rounded-md text-xs font-bold">🗑 Purge Clients</button>`
        : '';
    el.innerHTML = ksBtn + purgeBtn;
};

async function csRenderSimulations() {
    // Simulations → Checks child (default).
    csSetToolbar('');
    // Kill switch moved to the Checks/Hardware/Client Count child strip
    // (renderSecondaryNav → csKillSwitchMountChip), pinned far right — no longer
    // a content banner here.
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
    csSetToolbar(`<input id="cs-sim-q" oninput="csSimChecksFilterKey()" placeholder="Filter by site or check…" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-72">
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

// Keystroke-debounced entry point for the free-text filter input (the bucket
// <select> stays on the immediate onchange= above). See csDebounce.
window.csSimChecksFilterKey = csDebounce(window.csSimChecksFilter, 200);

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

// Compact key/value tile for the Details telemetry grid. Replaces the old
// full-width 2-column csTable whose Value column stretched across the entire
// content width and left a huge empty band on wide screens — tiling the
// entries into a responsive grid (csRenderVmServerDetails) packs the data
// across the available width instead. Object values are stringified; long
// values wrap (break-all) and are scroll-capped so one giant blob can't blow
// out a single tile's height.
function csKvTile(k, v) {
    const raw = (v !== null && typeof v === 'object') ? JSON.stringify(v) : String(v === null ? '' : v);
    const long = raw.length > 64;
    return `<div class="bg-slate-50 rounded-lg p-3">
      <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest break-all">${csEscape(k)}</p>
      <div class="text-sm text-slate-700 mt-1 font-mono break-all${long ? ' max-h-28 overflow-auto' : ''}">${csEscape(raw)}</div>
    </div>`;
}

// Full-width Auto-Provisioning card for the Details view. The ``provision``
// block (px.provision) is a nested object — rendering it through csKvTile
// stringifies the whole thing into one tile with heavy word-wrapping and no
// structure. Instead this formats the diagnostic fields readably (mirrors
// csRefreshAutoProvStatus) and spans the full content width so the reason
// string and config snapshot have room. Rendered LAST in the Details layout
// (after the telemetry grid), full-width via col-span-all.
function csProvisionCard(px) {
    const prov = (px && px.provision) || {};
    if (!Object.keys(prov).length) {
        return `<div class="bg-slate-50 rounded-lg p-3 col-span-1 sm:col-span-2 lg:col-span-3 xl:col-span-4">
      <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest mb-1">Auto-Provisioning</p>
      <div class="text-sm text-slate-500">No provision diagnostic reported by this host's agent.</div>
    </div>`;
    }
    const cfg = prov.config || {};
    const reason = prov.reason ? csEscape(String(prov.reason)) : '—';
    const loopOn = !!prov.loop_running;
    const csOn = !!prov.cs_enabled;
    const autoOn = !!prov.auto_provision_on;
    const vidpids = (cfg.dongle_vidpids != null) ? csEscape(String(cfg.dongle_vidpids)) : '—';
    const img1 = cfg.image1_template_id ? 'yes' : (cfg.image1_template_id === false ? 'no' : '—');
    const img2 = cfg.image2_template_id ? 'yes' : (cfg.image2_template_id === false ? 'no' : '—');
    const maxSlots = (cfg.max_slots != null) ? csEscape(String(cfg.max_slots)) : '—';
    const vr = cfg.vmid_range || {};
    const vrStr = (vr && (vr.start || vr.end)) ? `${csEscape(String(vr.start))}–${csEscape(String(vr.end))}` : '—';
    const active = (cfg.active_usb_vms != null) ? csEscape(String(cfg.active_usb_vms)) : '—';
    // provision_halt is an OBJECT {halted,reason,cpu_pct,cpu_threshold,...} —
    // format it; String()'ing it yielded "Halt: [object Object]".
    const h = prov.halt || null;
    const halt = (h && h.halted)
        ? `${csEscape(String(h.reason || 'load'))} — CPU ${h.cpu_pct}% ≥ ${h.cpu_threshold}%, Mem ${h.mem_pct}% ≥ ${h.mem_threshold}%`
        : '';
    // Delete-gate decision trace + the 1h averages the gate actually acts on
    // (distinct from the display CPU 1H) — so you can see WHAT auto-prov decides
    // on and WHY it did/didn't shed a VM.
    const dg = (px && px.delete_gate) || {};
    const ga = (px && px.gate_averages) || {};
    let dgLine = '';
    if (dg && dg.reason) {
        const cd = dg.cooldown_remaining_s ? ` · cooldown ${dg.cooldown_remaining_s}s` : '';
        const cand = (dg.eligible_candidates != null) ? ` · ${dg.eligible_candidates} eligible` : '';
        const shed = (dg.last_torn_down && dg.last_torn_down.length);
        dgLine = `<div class="${shed ? 'text-emerald-700' : 'text-slate-700'}"><b>Delete gate:</b> ${csEscape(String(dg.reason))}${cand}${cd}</div>`;
    }
    let gaLine = '';
    if (ga && (ga.cpu_1h_avg != null || ga.mem_1h_avg != null)) {
        const f = v => (v != null ? v + '%' : '—');
        gaLine = `<div class="text-[11px] text-slate-500"><b>Gate uses (1h avg):</b> CPU ${f(ga.cpu_1h_avg)} · Mem ${f(ga.mem_1h_avg)}</div>`;
    }
    // Status chips: CS-enabled, loop-running, auto-provision-on. Amber when a
    // gate is closed (the most common "enabled but nothing provisions" causes).
    const chip = (label, ok) => `<span class="inline-block rounded-full px-2 py-0.5 text-[10px] font-bold ${ok ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}">${csEscape(label)}</span>`;
    let html = `<div class="bg-slate-50 rounded-lg p-3 col-span-1 sm:col-span-2 lg:col-span-3 xl:col-span-4">
      <div class="flex items-center gap-2 mb-2">
        <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Auto-Provisioning</p>
        ${chip('CS-enabled', csOn)}${chip('loop running', loopOn)}${chip('auto-provision on', autoOn)}
      </div>
      <div class="text-sm text-slate-700 space-y-1">
        <div><b>Last pass:</b> ${reason}${loopOn ? '' : ' <span class="text-amber-600">(provision loop not running — check the pxmx agent log)</span>'}</div>
        ${halt ? `<div class="text-amber-600"><b>Halt:</b> ${halt}</div>` : ''}
        ${dgLine}
        ${gaLine}
        <div><b>Config:</b> dongle_vidpids=${vidpids} · image1=${img1} · image2=${img2} · max_slots=${maxSlots} · vmid_range=${vrStr} · active_usb_vms=${active}</div>
      </div>
    </div>`;
    return html;
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
// Present/unknown components of csUsbCount — same source (proxmox.present_usb /
// proxmox.unknown_usb arrays), split out so Setup/Proxmox "Present USB" and
// "Unknown USB" match the Overview/USB-view totals instead of reading the stale
// proxmox.usb_count field (the assigned-dongle subset) or a different endpoint.
function csPresentUsbCount(h) {
    const px = (h && h.proxmox) || {};
    return Array.isArray(px.present_usb) ? px.present_usb.length : 0;
}
function csUnknownUsbCount(h) {
    const px = (h && h.proxmox) || {};
    return Array.isArray(px.unknown_usb) ? px.unknown_usb.length : 0;
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

// Human-readable formatter for last_seen values. The Clients table (and any
// last_seen telemetry tile) receives a fractional epoch-seconds float
// (heartbeat.py time.time()) or occasionally an ISO string; rendering it raw
// shows "1751400000.123", which is unreadable. This normalizes either form to a
// local "YYYY-MM-DD HH:MM:SS" string. Values >= 1e11 are treated as already-ms.
// Returns a RAW (unescaped) string — callers wrap in csEscape / csKvTile, the
// same convention as csPveVersion. Unknown formats fall back to String(v).
function csLastSeen(v) {
    if (v == null || v === '' || v === '—') return '—';
    let ms = NaN;
    if (typeof v === 'number') ms = v;
    else {
        const s = String(v).trim();
        ms = /^[\d.]+$/.test(s) ? Number(s) : Date.parse(s);
    }
    if (isNaN(ms)) return String(v);
    if (ms < 1e11) ms *= 1000;            // epoch seconds → ms
    const d = new Date(ms);
    if (isNaN(d.getTime())) return String(v);
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
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
    // Tier by PASSTHROUGH (authoritative, from the agent's compute_vm_tiers):
    // T2 = USB dongle; T1/T3 = PCI passthrough. Prefer the agent-computed
    // c.tier; fall back to has_usb (T2/T1) when the VM wasn't classified.
    if (c.tier === 't1' || c.tier === 't2' || c.tier === 't3') return c.tier;
    if (c.has_usb === true) return 't2';
    if (c.has_usb === false) return 't1';
    if (c.vm_type === 't2' || c.client_type === 't2') return 't2';
    if (c.reclone_bus_path || c.bus_path) return 't2';
    return 't1';
}

async function csRenderClients(tier) {
    // tier may come in as a boolean `force` arg from the legacy primary-switch
    // fallback; only accept real tier strings.
    if (tier === 't1' || tier === 't2' || tier === 't3' || tier === 'all') csClientTier = tier;
    csSetToolbar(`<input id="cs-client-search" oninput="csClientFilterKey()" placeholder="Search clients…" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-64">
      <select id="cs-client-status" onchange="csClientFilter()" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500">
        <option value="">All</option><option value="online">Online</option><option value="offline">Offline</option>
      </select>`);
    // Initial load: fan out the clients fetch and the demo card together.
    // /aggregate/clients is a fast hub cache read, but csDemoCard() does two
    // relay round-trips to the spoke (/demo/active + /demo/scenarios) — running
    // them serially after the cache read made the page feel slow on first
    // access. Parallelizing cuts initial paint to max(fast read, relay) instead
    // of their sum.
    const [data, demoCard] = await Promise.all([
        csFetch(`/aggregate/clients?tenant_id=${csTenant()}`),
        csDemoCard(),
    ]);
    const rows = csNormalizeClients(data);
    csClientCache = rows;
    const all = rows.length;
    const t1 = rows.filter(c => csClassifyClient(c) === 't1').length;
    const t2 = rows.filter(c => csClassifyClient(c) === 't2').length;
    const t3 = rows.filter(c => csClassifyClient(c) === 't3').length;
    const online = rows.filter(c => c.online).length;
    const pills = csSummaryRow([[all, 'Clients'], [t1, 'T1'], [t2, 'T2'], [t3, 'T3'], [online, 'Online']]);
    // Kill switch moved to the All/T1/T2 child strip (renderSecondaryNav →
    // csKillSwitchMountChip), pinned far right — no longer a content banner here.
    csSet(`<div class="space-y-4">${demoCard}${pills}<div id="cs-client-body"></div></div>`);
    csClientFilter();
}

// "Purge Clients" — ports the original solutions-hpe cs-webui button
// (DELETE /api/clients/history → clients_purged WS). Clears every client
// record from the spoke's registry (memory + clients.json on disk). Hits the
// tenant's cs spoke via the hub relay DELETE /sim/api/{tenant}/clients (or the
// spoke's own local_ui_routes equivalent when run from the cs standalone
// dashboard — same /sim/api/* contract). The hub also drops its cached
// `clients` for the spoke, so re-rendering shows empty immediately.
window.csPurgeClients = async function (btn) {
    if (!confirm('Clear all client history? Records on disk will also be deleted. This cannot be undone.'))
        return;
    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = '⏳ Purging…';
    try {
        const r = await csFetch(`/${csTenant()}/clients`, { method: 'DELETE' });
        const n = (r && r.purged != null) ? r.purged : '?';
        if (typeof showToast === 'function') showToast(`Purged ${n} client record(s)`, 'success');
        // Re-render the Clients tab so the now-empty list shows immediately.
        await csRenderClients(csClientTier);
        // The Purge button now lives in the kill-switch chip (secondary nav),
        // which csRenderClients doesn't touch — re-mount it so the button
        // resets from its disabled "⏳ Purging…" state.
        if (typeof window.csKillSwitchMountChip === 'function') window.csKillSwitchMountChip('cs-ks-chip');
    } catch (e) {
        console.error('csPurgeClients: purge failed', e);
        if (typeof showToast === 'function') showToast('Purge failed: ' + (e.message || e), 'error');
        btn.disabled = false;
        btn.textContent = orig;
    }
};

function csNormalizeClients(data) {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.clients)) return data.clients;
    if (Array.isArray(data.rows)) return data.rows;
    return [];
}

// Clients render as TWO rows each (ported from webui-hub's client + control-row
// pair): a data row — no Spoke column — plus a second "sim bar" row of clickable
// per-simulation override buttons. The original hid the override panel behind a
// "Control" button; here the sim buttons are always visible inline on line 2,
// each showing whether that sim is currently running and toggling a per-client
// override on click. Columns: Hostname, Platform, Status, Tier, SSID, Last Seen,
// Errors, Demo.
const CS_CLIENT_COLS = 11;
function csRenderClientRows(rows) {
    const body = csEl('cs-client-body') || csEl('cs-content');
    if (!rows || rows.length === 0) {
        body.innerHTML = csEmpty('No clients reported.',
            'Connected client simulators will appear here once spokes check in.');
        return;
    }
    const rowHtml = rows.map(c => {
        const t = csClassifyClient(c);
        const host = c.hostname || c.id || '';
        const cfg = c.config || {};
        const line1 = `<tr class="border-t border-slate-100">
          <td class="px-4 py-2 font-mono text-xs">${csEscape(host || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(cfg.wsite || '—')}</td>
          <td class="px-4 py-2 font-mono text-xs text-slate-500">${csEscape(c.simulation_id || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(cfg.sim_phy || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.platform || c.hw_type || '—')}</td>
          <td class="px-4 py-2">${csOnlineBadge(c.online)}</td>
          <td class="px-4 py-2"><span class="text-[10px] font-bold px-2 py-0.5 rounded ${t === 't2' ? 'bg-purple-100 text-purple-700' : t === 't3' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'}">${t.toUpperCase()}</span></td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.connected_ssid || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(csLastSeen(c.last_seen))}</td>
          <td class="px-4 py-2 ${c.error_count > 0 ? 'text-amber-600 font-bold' : 'text-slate-400'}">${csEscape(c.error_count || 0)}</td>
          ${host ? csDemoCell(host) : '<td class="px-4 py-2 text-slate-300">—</td>'}
        </tr>`;
        const line2 = host ? `<tr>
          <td colspan="${CS_CLIENT_COLS}" class="px-4 pb-3 pt-0">${csClientSimBar(c, host)}</td>
        </tr>` : '';
        return line1 + line2;
    }).join('');
    body.innerHTML = csTable(
        ['Hostname', 'Site', 'Sim-ID', 'PHY', 'Platform', 'Status', 'Tier', 'SSID', 'Last Seen', 'Errors', 'Demo'],
        rowHtml
    );
}

// The second line under each client: one clickable button per simulation (the
// original webui-hub FLAG_ORDER set). A button is highlighted when that sim is
// currently on (in the client's active_simulations or effective config).
// Clicking toggles a per-client override; the server REPLACES the whole override
// map, so csSimToggle sends every flag for the host with the clicked one flipped
// (POST /clients/{host}/control {overrides:{flag:on/off}} — same endpoint the
// original Apply used). "Clear" removes all overrides for the client.
function csSimBtnClass(on) {
    return 'px-2 py-0.5 rounded-md text-[11px] font-bold border transition-colors ' +
        (on ? 'bg-purple-100 text-purple-700 border-purple-300'
            : 'bg-white text-slate-400 border-slate-200 hover:bg-slate-100');
}

function csClientSimBar(c, host) {
    const active = new Set((Array.isArray(c.active_simulations) ? c.active_simulations : [])
        .map(s => String(s).toLowerCase()));
    const cfg = c.effective_config || c.config || {};
    const ov = c.overrides || {};
    // A per-client override WINS (so a set override reflects + stays across
    // refreshes); otherwise fall back to what the client is actually running.
    const isOn = f => {
        if (Object.prototype.hasOwnProperty.call(ov, f))
            return ['on', 'true', '1'].includes(String(ov[f]).toLowerCase());
        return active.has(f) ||
            ['on', 'true', '1'].includes(String(cfg[f] == null ? '' : cfg[f]).toLowerCase());
    };
    const btns = CS_CONTROL_FLAGS.map(f => {
        const on = isOn(f);
        return `<button data-cs-sim-host="${csEscape(host)}" data-cs-sim-flag="${csEscape(f)}" data-cs-sim-on="${on ? '1' : '0'}"
          onclick="csSimToggle(this)" title="Click to ${on ? 'disable' : 'enable'} ${csEscape(f)} on ${csEscape(host)}"
          class="${csSimBtnClass(on)}">${csEscape(f)}</button>`;
    }).join('');
    return `<div class="flex flex-wrap items-center gap-1.5">
      ${btns}
      <button data-cs-ctl-host="${csEscape(host)}" onclick="csCtlClear(this)"
        class="ml-2 px-2 py-0.5 rounded-md text-[11px] font-bold bg-red-50 text-red-600 hover:bg-red-100 border border-red-200">Clear</button>
      <span id="${csEscape(csCtlId(host, 'msg'))}" class="text-[11px] text-slate-400 ml-1"></span>
    </div>`;
}

// Persist a single flag override into the [username] section of
// user-overrides.conf (mirrors csCtlSaveUO for one flag) so Config/Simulations
// "User Overrides" reflects the same change. Best-effort: a failure here must
// NOT undo the runtime registry toggle already sent, so it logs + toasts and
// never throws.
async function csPersistFlagToUserOverrides(host, flag, value) {
    const user = String(host || '').split('-')[0] || host;
    if (!user) return;
    try {
        const cur = await csFetch(`/${csTenant()}/config/user-overrides-conf`);
        const state = csParseIni((cur && cur.content) || '');
        const merged = Object.assign({}, state[user] || {});
        merged[flag] = value;
        state[user] = merged;
        let text = '';
        for (const [u, kv] of Object.entries(state)) {
            text += `[${u}]\n`;
            for (const [k, v] of Object.entries(kv)) {
                if (v === '' || v === null || v === undefined) continue;
                text += `${k}=${v}\n`;
            }
            text += '\n';
        }
        await csFetch(`/${csTenant()}/config/user-overrides-conf`,
            { method: 'PUT', body: JSON.stringify({ content: text.trim() }) });
    } catch (e) {
        console.error('csPersistFlagToUserOverrides failed', e);
        if (typeof showToast === 'function') showToast(`user-overrides save failed: ${e.message || 'error'}`, 'error');
    }
}

window.csSimToggle = async function (btn) {
    const host = btn.dataset.csSimHost, flag = btn.dataset.csSimFlag;
    if (!host || !flag) return;
    const next = btn.dataset.csSimOn === '1' ? 'off' : 'on';
    // Set just THIS flag's override — the endpoint merges it into the client's
    // persisted overrides (registry.set_overrides), so toggling one sim doesn't
    // disturb the others. Also mirror the flag into user-overrides.conf so the
    // Config/Simulations "User Overrides" card stays in sync. "Clear" drops all
    // overrides for the client.
    csCtlMsg(host, `${next === 'on' ? 'Enabling' : 'Disabling'} ${flag}…`, true);
    try {
        await csFetch(`/${csTenant()}/clients/${encodeURIComponent(host)}/control?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ overrides: { [flag]: next } }) });
        await csPersistFlagToUserOverrides(host, flag, next);
        btn.dataset.csSimOn = next === 'on' ? '1' : '0';
        btn.className = csSimBtnClass(next === 'on');
        btn.title = `Click to ${next === 'on' ? 'disable' : 'enable'} ${flag} on ${host}`;
        csCtlMsg(host, `${flag} ${next}`, true);
        if (typeof showToast === 'function') showToast(`${flag} ${next} on ${host}`, 'success');
    } catch (e) { console.error('csSimToggle failed', e); csCtlMsg(host, e.message || 'failed', false); }
};

// ── Demo scenarios (named per-client failure presets, 120-min TTL) ───────────
// Ports the legacy cs webui-spoke demo system. Trigger a named failure on one
// client for 2h, or 'normal' to clear. The override is ephemeral on the spoke
// (layered on top of persisted overrides at config delivery). The active-demos
// card + per-row Demo column live on the Clients tab.
window._csDemoActive = {};      // hostname → {scenario, minutes_remaining, ...}
window._csDemoScenarios = {};   // scenario name → {flag: on/off}

async function csDemoLoad() {
    try {
        const a = await csFetch(`/${csTenant()}/demo/active?tenant_id=${csTenant()}`);
        const active = (a && a.active) || [];
        window._csDemoActive = {};
        active.forEach(d => { window._csDemoActive[d.hostname] = d; });
    } catch (e) { console.warn('csDemoLoad: active read failed', e); window._csDemoActive = {}; }
    if (window._csDemoScenarios && Object.keys(window._csDemoScenarios).length) return;
    try {
        const s = await csFetch(`/${csTenant()}/demo/scenarios?tenant_id=${csTenant()}`);
        window._csDemoScenarios = (s && s.scenarios) || {};
    } catch (e) { console.warn('csDemoLoad: scenarios read failed', e); window._csDemoScenarios = {}; }
}

function csDemoOptions(activeScenario) {
    const names = Object.keys(window._csDemoScenarios || {});
    if (!names.length) names.push('normal', 'dns_fail', 'dhcp_fail', 'assoc_fail', 'auth_fail', 'ssidpw_fail', 'port_flap');
    return names.map(n => `<option value="${csEscape(n)}" ${n === activeScenario ? 'selected' : ''}>${csEscape(n)}</option>`).join('');
}

function csDemoCell(hostname) {
    const a = window._csDemoActive[hostname];
    const badge = a ? `<span class="inline-block bg-amber-100 text-amber-700 rounded px-1.5 py-0.5 text-[10px] font-bold mr-1">${csEscape(a.scenario)} ${csEscape(a.minutes_remaining != null ? a.minutes_remaining + 'm' : '')}</span>` : '';
    return `<td class="px-4 py-2 whitespace-nowrap">
      ${badge}
      <select id="cs-demo-${csEscape(hostname)}" class="border border-slate-200 rounded-md px-1 py-0.5 text-[11px]">
        ${csDemoOptions(a ? a.scenario : 'normal')}
      </select>
      <button data-cs-demo-host="${csEscape(hostname)}" onclick="csDemoTrigger(this)"
        class="bg-blue-100 hover:bg-blue-200 text-blue-700 px-1.5 py-0.5 rounded-md text-[11px] font-bold">Go</button>
    </td>`;
}

async function csDemoCard() {
    await csDemoLoad();
    const active = Object.values(window._csDemoActive || {});
    if (!active.length) return '';
    const rows = active.map(a => `<div class="flex items-center justify-between py-1">
      <span class="text-sm"><span class="font-mono text-xs font-bold">${csEscape(a.hostname)}</span>
        <span class="ml-2 inline-block bg-amber-100 text-amber-700 rounded px-1.5 py-0.5 text-[10px] font-bold">${csEscape(a.scenario)}</span>
        <span class="ml-2 text-xs text-slate-400">${csEscape(a.minutes_remaining)}m remaining</span></span>
      <button data-cs-demo-host="${csEscape(a.hostname)}" onclick="csDemoClear(this)"
        class="bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded-md text-[11px] font-bold">Clear</button>
    </div>`).join('');
    return `<div class="hpe-card rounded-lg p-4 shadow-sm">
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Active Demo Scenarios (${active.length})</p>
      ${rows}
    </div>`;
}

window.csDemoTrigger = async function (btn) {
    const host = btn.dataset.csDemoHost;
    const sel = csEl('cs-demo-' + host);
    const scenario = sel ? sel.value : 'normal';
    try {
        await csFetch(`/${csTenant()}/demo/client/${encodeURIComponent(host)}/scenario?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ scenario }) });
        if (typeof showToast === 'function') showToast(`Demo '${scenario}' triggered on ${host}`, 'success');
        loadCSData('Clients', currentSubChild, true);
    } catch (e) { console.error('csDemoTrigger: trigger failed', e); if (typeof showToast === 'function') showToast('Demo trigger failed: ' + (e.message || e), 'error'); }
};

window.csDemoClear = async function (btn) {
    const host = btn.dataset.csDemoHost;
    try {
        await csFetch(`/${csTenant()}/demo/client/${encodeURIComponent(host)}/scenario?tenant_id=${csTenant()}`, { method: 'DELETE' });
        if (typeof showToast === 'function') showToast(`Demo cleared on ${host}`, 'success');
        loadCSData('Clients', currentSubChild, true);
    } catch (e) { console.error('csDemoClear: clear failed', e); if (typeof showToast === 'function') showToast('Demo clear failed: ' + (e.message || e), 'error'); }
};

// ── per-client override Control Panel (ports the legacy cs webui-spoke) ──────
// Live sim-flag toggles per client + Apply / Clear / Apply-to-ALL / Save-to-
// user-overrides. Unlike the ephemeral demo flags, these write the spoke's
// PERSISTED registry overrides (sticky across reconnects/reboots). The panel
// is an expandable row beneath each client; opening it fetches the host's
// current overrides and seeds the toggles.
const CS_CONTROL_FLAGS = ['kill_switch', 'dns_fail', 'iperf', 'download',
    'www_traffic', 'ping_test', 'ssidpw_fail', 'auth_fail', 'dhcp_fail',
    'port_flap', 'assoc_fail'];
const CS_CONTROL_COLS = 11;  // Clients-table column count (panel colspan)

function csCtlId(host, flag) {
    const h = String(host || '').replace(/[^a-zA-Z0-9_-]/g, '_');
    return `cs-ctl-${h}-${flag}`;
}

function csControlCell(hostname) {
    return `<td class="px-4 py-2 whitespace-nowrap">
      <button data-cs-ctl-host="${csEscape(hostname)}" onclick="csCtlToggle(this)"
        class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-2 py-1 rounded-md text-[11px] font-bold">⚙ Control</button>
    </td>`;
}

// The flag toggles + action buttons. Selects default to 'off' and are re-seeded
// from the spoke's current overrides when the panel is opened (csCtlToggle).
function csControlPanel(hostname) {
    const flags = CS_CONTROL_FLAGS.map(f => {
        const id = csCtlId(hostname, f);
        return `<label class="flex items-center gap-1 text-xs text-slate-600">
          <span class="w-24 truncate" title="${csEscape(f)}">${csEscape(f)}</span>
          <select id="${csEscape(id)}" data-cs-ctl-host="${csEscape(hostname)}" data-cs-ctl-flag="${csEscape(f)}"
            class="border border-slate-200 rounded-md px-1 py-0.5 text-[11px]">
            <option value="off">off</option><option value="on">on</option>
          </select>
        </label>`;
    }).join('');
    return `<div class="bg-slate-50 border border-slate-200 rounded-lg p-3">
      <div class="flex items-center justify-between mb-2">
        <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Live Overrides — ${csEscape(hostname)}</p>
        <p class="text-[10px] text-slate-400">Persisted to the spoke registry (survives reconnect/reboot). Demo flags layer on top at delivery.</p>
      </div>
      <div class="grid grid-cols-4 gap-2 mb-3">${flags}</div>
      <div class="flex flex-wrap gap-2">
        <button data-cs-ctl-host="${csEscape(hostname)}" onclick="csCtlApply(this)"
          class="bg-[#01A982] hover:bg-[#018a6c] text-white px-3 py-1.5 rounded-md text-xs font-bold">Apply</button>
        <button data-cs-ctl-host="${csEscape(hostname)}" onclick="csCtlClear(this)"
          class="bg-red-100 hover:bg-red-200 text-red-700 px-3 py-1.5 rounded-md text-xs font-bold">Clear Overrides</button>
        <button data-cs-ctl-host="${csEscape(hostname)}" onclick="csCtlAll(this)"
          class="bg-amber-100 hover:bg-amber-200 text-amber-700 px-3 py-1.5 rounded-md text-xs font-bold">Apply to ALL</button>
        <button data-cs-ctl-host="${csEscape(hostname)}" onclick="csCtlSaveUO(this)"
          class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-3 py-1.5 rounded-md text-xs font-bold">Save to user-overrides</button>
        <span id="${csEscape(csCtlId(hostname, 'msg'))}" class="text-xs text-slate-400 self-center"></span>
      </div>
    </div>`;
}

function csControlPanelRow(hostname) {
    // Hidden by default; csCtlToggle shows it + seeds the toggles from the
    // spoke's current overrides.
    return `<tr id="${csEscape('cs-ctl-panel-' + String(hostname).replace(/[^a-zA-Z0-9_-]/g, '_'))}" style="display:none">
      <td colspan="${CS_CONTROL_COLS}" class="px-4 py-2 bg-slate-50">${csControlPanel(hostname)}</td>
    </tr>`;
}

// Read the 11 toggles for a host into {flag: on/off}.
function csCtlCollect(hostname) {
    const out = {};
    for (const f of CS_CONTROL_FLAGS) {
        const el = csEl(csCtlId(hostname, f));
        out[f] = el ? el.value : 'off';
    }
    return out;
}

function csCtlMsg(hostname, text, ok) {
    const m = csEl(csCtlId(hostname, 'msg'));
    if (m) { m.textContent = text; m.className = 'text-xs ' + (ok ? 'text-green-600' : 'text-red-500'); }
}

window.csCtlToggle = async function (btn) {
    const host = btn.dataset.csCtlHost;
    if (!host) return;
    const panel = csEl('cs-ctl-panel-' + String(host).replace(/[^a-zA-Z0-9_-]/g, '_'));
    if (!panel) return;
    if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }
    // Open: seed toggles from the spoke's current persisted overrides.
    try {
        const r = await csFetch(`/${csTenant()}/clients/${encodeURIComponent(host)}/control?tenant_id=${csTenant()}`);
        const ov = (r && r.overrides) || {};
        for (const f of CS_CONTROL_FLAGS) {
            const el = csEl(csCtlId(host, f));
            if (el) {
                const v = String(ov[f] == null ? 'off' : ov[f]).toLowerCase();
                el.value = (v === 'on' || v === 'true' || v === '1') ? 'on' : 'off';
            }
        }
    } catch (e) { console.warn('csCtlToggle: override read failed, showing defaults', e); }
    panel.style.display = '';
};

window.csCtlApply = async function (btn) {
    const host = btn.dataset.csCtlHost;
    const flags = csCtlCollect(host);
    csCtlMsg(host, 'Applying…', true);
    try {
        await csFetch(`/${csTenant()}/clients/${encodeURIComponent(host)}/control?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ overrides: flags }) });
        csCtlMsg(host, 'Applied.', true);
        if (typeof showToast === 'function') showToast(`Overrides applied to ${host}`, 'success');
    } catch (e) { console.error('csCtlApply: apply failed', e); csCtlMsg(host, e.message || 'failed', false); }
};

window.csCtlClear = async function (btn) {
    const host = btn.dataset.csCtlHost;
    csCtlMsg(host, 'Clearing…', true);
    try {
        await csFetch(`/${csTenant()}/clients/${encodeURIComponent(host)}/control?tenant_id=${csTenant()}`, { method: 'DELETE' });
        // Reset toggles to 'off' to reflect the cleared state.
        for (const f of CS_CONTROL_FLAGS) {
            const el = csEl(csCtlId(host, f));
            if (el) el.value = 'off';
        }
        csCtlMsg(host, 'Cleared.', true);
        if (typeof showToast === 'function') showToast(`Overrides cleared on ${host}`, 'success');
    } catch (e) { console.error('csCtlClear: clear failed', e); csCtlMsg(host, e.message || 'failed', false); }
};

window.csCtlAll = async function (btn) {
    const host = btn.dataset.csCtlHost;
    const flags = csCtlCollect(host);
    csCtlMsg(host, 'Applying to ALL…', true);
    try {
        const r = await csFetch(`/${csTenant()}/clients/control-all?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ overrides: flags }) });
        const n = (r && r.applied != null) ? r.applied : '?';
        csCtlMsg(host, `Applied to ${n} clients.`, true);
        if (typeof showToast === 'function') showToast(`Overrides applied to ${n} clients`, 'success');
    } catch (e) { console.error('csCtlAll: apply-all failed', e); csCtlMsg(host, e.message || 'failed', false); }
};

// Persist the current toggles into the [username] section of user-overrides.conf
// (username = hostname prefix, mirroring sim_config.username_for). Merges with
// any non-flag keys already pinned for that user; never drops other users.
window.csCtlSaveUO = async function (btn) {
    const host = btn.dataset.csCtlHost;
    const flags = csCtlCollect(host);
    const user = String(host || '').split('-')[0] || host;
    if (!user) { csCtlMsg(host, 'no username', false); return; }
    csCtlMsg(host, 'Saving to user-overrides…', true);
    try {
        const cur = await csFetch(`/${csTenant()}/config/user-overrides-conf`);
        const state = csParseIni((cur && cur.content) || '');
        const existing = state[user] || {};
        // Merge: keep existing non-flag keys, overwrite the 11 control flags.
        const merged = Object.assign({}, existing);
        for (const f of CS_CONTROL_FLAGS) merged[f] = flags[f];
        state[user] = merged;
        let text = '';
        for (const [u, kv] of Object.entries(state)) {
            text += `[${u}]\n`;
            for (const [k, v] of Object.entries(kv)) {
                if (v === '' || v === null || v === undefined) continue;
                text += `${k}=${v}\n`;
            }
            text += '\n';
        }
        await csFetch(`/${csTenant()}/config/user-overrides-conf`,
            { method: 'PUT', body: JSON.stringify({ content: text.trim() }) });
        csCtlMsg(host, `Saved to [${user}].`, true);
        if (typeof showToast === 'function') showToast(`Saved to user-overrides [${user}]`, 'success');
    } catch (e) { console.error('csCtlSaveUO: save failed', e); csCtlMsg(host, e.message || 'failed', false); }
};

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

// Keystroke-debounced entry point for the free-text search input (the status
// <select> stays on the immediate onchange= above). See csDebounce.
window.csClientFilterKey = csDebounce(window.csClientFilter, 200);

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
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">API Config Push ${helpIcon('cs', null, 'Simulations help')}</h3>
      <p class="text-xs text-slate-400 mb-2">Paste a JSON config object to push to all spokes (unwrapped at the spoke's <code>_apply_hub_config</code>).</p>
      <textarea id="cs-configpush" rows="10" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-xs font-mono outline-none focus:ring-2 focus:ring-green-500" placeholder='{ "key": "value" }'></textarea>
      <button onclick="csSaveConfigPush()" class="mt-3 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Push Config</button>
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
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Per-Spoke Config State ${helpIcon('cs', null, 'Simulations help')}</h3>
          ${csTable(['Spoke', 'Online', 'Conf Read Error', 'Last Check-in'], rows)}
        </div>`;
    } catch (e) { console.error('csRenderConfig: per-spoke config state load failed, hiding card', e); stateCard = ''; }

    csSet(`<div class="space-y-4">${pushCard}${stateCard}</div>`);
}

window.csSaveConfigPush = async function () {
    const raw = csEl('cs-configpush').value;
    let cfg;
    try { cfg = raw.trim() ? JSON.parse(raw) : {}; } catch (e) {
        console.error('csSaveConfigPush: invalid JSON config', e);
        showToast('Invalid JSON: ' + e.message, 'error');
        return;
    }
    try {
        await csFetch('/aggregate/config-push', { method: 'POST', body: JSON.stringify({ config: cfg }) });
        showToast('Pushed.', 'success');
    } catch (e) {
        console.error('csSaveConfigPush: config push failed', e);
        showToast(e.message, 'error');
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

// ── Simulations Config tab (legacy solutions-hpe/client-sim port) ─────────────
// Structured editor for configs/simulation.conf + configs/user-overrides.conf.
// The hub is the source of truth for hub-owned config: edits save as the
// hub-managed override (sim_conf_override / user_conf_override INI text →
// CS_CONFIG_UPDATE → spoke writes configs/hub-*-overrides.conf, merged on top
// of the repo base files by sim_config.load_configs). The spoke's CS_GET_CONFIG
// returns the MERGED effective config, which is what the editor loads on Refresh
// (so the UI shows what's actually in effect). Mirrors the legacy "Hub-managed
// override (no GitHub API key)" tab.

// Keys whose value is an on/off flag → rendered as a toggle select (on/off).
// (allow_offline and l1 use yes/no in the canon; they stay text inputs so the
// exact value is preserved losslessly.)
const CS_ONOFF_KEYS = new Set([
    'kill_switch', 'rapid_update', 'github_repo', 'smb_repo', 'site_based_ssid',
    'ssidpw_fail', 'auth_fail', 'syslog', 'web_server',
    'dhcp_fail', 'dns_fail', 'assoc_fail', 'port_flap', 'ping_test',
    'download', 'www_traffic', 'iperf',
]);

// Ordered field schema per section → [{key, label}]. Drives the labeled-input
// editor (the legacy tab showed named fields, not raw INI). Keys not in the
// schema for a section are still rendered as generic key=value rows so edits
// are never lost (and any extra section falls back to a raw textarea).
const CS_SIM_SECTION_FIELDS = {
    simulation: [
        ['sim_load', 'Sim Load'], ['repo_location', 'Repo Location'],
        ['repo_branch', 'Repo Branch'], ['reboot_schedule', 'Reboot Schedule'],
        ['dot1x_password', 'Dot1x Password'], ['dot1x_eap', 'Dot1x Eap'],
        ['iperf_bw', 'Iperf Bw'], ['kill_switch', 'Kill Switch'],
        ['rapid_update', 'Rapid Update'], ['github_repo', 'Github Repo'],
        ['smb_repo', 'Smb Repo'], ['site_based_ssid', 'Site Based Ssid'],
        ['allow_offline', 'Allow Offline'], ['ssidpw_fail', 'Ssidpw Fail'],
        ['auth_fail', 'Auth Fail'], ['syslog', 'Syslog'],
        ['web_server', 'Web Server'],
    ],
    server: [['server_url', 'Server Url']],
    address: [
        ['smb_address', 'Smb Address'], ['ping_address', 'Ping Address'],
        ['dns_latency_1', 'Dns Latency 1'], ['dns_latency_2', 'Dns Latency 2'],
        ['dns_latency_3', 'Dns Latency 3'],
        ['dns_bad_ip_1', 'Dns Bad Ip 1'], ['dns_bad_ip_2', 'Dns Bad Ip 2'],
        ['dns_bad_ip_3', 'Dns Bad Ip 3'],
        ['dns_bad_record_1', 'Dns Bad Record 1'], ['dns_bad_record_2', 'Dns Bad Record 2'],
        ['dns_bad_record_3', 'Dns Bad Record 3'],
        ['iperf_server', 'Iperf Server'], ['syslog_server', 'Syslog Server'],
    ],
};
// Per-bucket [s0]–[s9] field schema (identical for each bucket).
const CS_SIM_BUCKET_FIELDS = [
    ['wsite', 'Wsite'], ['ssid', 'Ssid'], ['ssidpw', 'Ssidpw'],
    ['dhcp_fail', 'Dhcp Fail'], ['dns_fail', 'Dns Fail'],
    ['assoc_fail', 'Assoc Fail'], ['port_flap', 'Port Flap'],
    ['ping_test', 'Ping Test'], ['download', 'Download'],
    ['www_traffic', 'Www Traffic'], ['iperf', 'Iperf'],
    ['sim_phy', 'Sim Phy'], ['l1', 'L1'],
];
const CS_SIM_BUCKETS = ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9'];

// Parse raw INI text → {section: {key: value}}. Lines before the first [section]
// are dropped (the canon has none). Comments (#/;) and blank lines are skipped.
// Used client-side for the user-overrides editor (the sim-conf editor uses the
// server's parsed view, but user-overrides round-trips as raw text).
function csParseIni(text) {
    const out = {};
    let cur = null;
    for (const ln of String(text || '').split('\n')) {
        const sm = /^\s*\[([^\]]*)\]\s*$/.exec(ln);
        if (sm) { cur = sm[1]; out[cur] = {}; continue; }
        if (cur === null) continue;  // preamble — skip
        const km = /^\s*([^=#;\s][^=]*?)\s*=\s*(.*)$/.exec(ln);
        if (km) out[cur][km[1].trim()] = km[2].trim();
    }
    return out;
}

// Render one labeled field for a section. on/off keys → a select; others → text
// input. Each input carries data-cs-section + data-cs-key so the serializer can
// walk them regardless of which section card they live in.
function csSimField(section, key, label, value) {
    const id = `cs-sim-${csEscape(section)}-${csEscape(key)}`;
    const v = (value === undefined || value === null) ? '' : String(value);
    if (CS_ONOFF_KEYS.has(key)) {
        const on = v.toLowerCase() === 'on';
        return `<div class="flex flex-col gap-1">
          <label class="text-[10px] text-slate-500 uppercase font-bold tracking-wider">${csEscape(label)}</label>
          <select id="${id}" data-cs-section="${csEscape(section)}" data-cs-key="${csEscape(key)}"
                  class="border border-slate-200 rounded-md px-2 py-1.5 text-sm ${on ? 'text-emerald-700 font-semibold' : 'text-slate-600'}">
            <option value="on" ${on ? 'selected' : ''}>on</option>
            <option value="off" ${!on ? 'selected' : ''}>off</option>
          </select></div>`;
    }
    return `<div class="flex flex-col gap-1">
      <label class="text-[10px] text-slate-500 uppercase font-bold tracking-wider">${csEscape(label)}</label>
      <input id="${id}" data-cs-section="${csEscape(section)}" data-cs-key="${csEscape(key)}"
             value="${csEscape(v)}" class="border border-slate-200 rounded-md px-2 py-1.5 text-sm font-mono">
    </div>`;
}

// Generic key=value row for keys the schema doesn't name (so an extra key a fork
// added isn't silently dropped on save). Rendered as a labeled text input.
function csSimExtraField(section, key, value) {
    return csSimField(section, key, key, value);
}

// Render a section's fields from its schema + any extra keys present in `kv`.
function csSimSectionFields(section, schema, kv) {
    kv = kv || {};
    const seen = new Set();
    const fields = schema.map(([key, label]) => {
        seen.add(key);
        return csSimField(section, key, label, kv[key]);
    }).join('');
    // Extra keys not in the schema → generic rows so they survive a save.
    const extras = Object.keys(kv).filter(k => !seen.has(k))
        .map(k => csSimExtraField(section, k, kv[k])).join('');
    return fields + extras;
}

async function csRenderConfigSimulation() {
    csSetToolbar('');
    // Load the MERGED effective simulation.conf (parsed) + user-overrides.conf
    // (raw) from the spoke via the hub. source='spoke' when the spoke is online;
    // 'stored-override' when it fell back to the hub's stored override text.
    let sim = null, uo = null, simErr = null, uoErr = null;
    try { sim = await csFetch(`/${csTenant()}/config/simulation-conf-parsed`); }
    catch (e) { console.error('csRenderConfigSimulation: simulation-conf-parsed load failed', e); simErr = e; }
    try { uo = await csFetch(`/${csTenant()}/config/user-overrides-conf`); }
    catch (e) { console.error('csRenderConfigSimulation: user-overrides-conf load failed', e); uoErr = e; }

    const fetchedSim = (sim && sim.fetched_at) ? csFmtFetched(sim.fetched_at) : '—';
    const simSource = (sim && sim.source) || 'spoke';
    const simConnected = !!(sim && sim.spoke_connected);
    const sections = (sim && sim.sections) || {};
    const raw = (sim && sim.raw) || '';

    // ── Simulation Config card ──────────────────────────────────────────────
    let simBody;
    if (simErr) {
        simBody = csErrorBox('Simulation Config', simErr).replace('py-10', 'py-6');
    } else {
        // Known sections rendered as labeled field grids; unknown sections fall
        // back to raw textareas so a fork's extra sections aren't dropped.
        const simFields = csSimSectionFields('simulation', CS_SIM_SECTION_FIELDS.simulation, sections.simulation);
        const serverFields = csSimSectionFields('server', CS_SIM_SECTION_FIELDS.server, sections.server);
        const addressFields = csSimSectionFields('address', CS_SIM_SECTION_FIELDS.address, sections.address);
        const known = new Set(['simulation', 'server', 'address', ...CS_SIM_BUCKETS]);
        const extras = Object.keys(sections).filter(s => !known.has(s));
        const extraBlocks = extras.map(s => {
            // Re-emit the extra section's key=value lines as a raw textarea.
            const body = Object.entries(sections[s]).map(([k, v]) => `${k}=${v}`).join('\n');
            return `<details class="border border-slate-200 rounded-md mb-2">
              <summary class="px-3 py-2 cursor-pointer bg-slate-50 font-mono text-xs text-slate-600">[${csEscape(s)}] <span class="text-slate-400">(extra)</span></summary>
              <textarea data-cs-ini-section="${csEscape(s)}" rows="6" class="w-full bg-white border-0 px-3 py-2 text-xs font-mono outline-none focus:ring-1 focus:ring-green-400">${csEscape(body)}</textarea>
            </details>`;
        }).join('');
        // [s0]–[s9] buckets — collapsible, s0 open by default.
        const bucketCards = CS_SIM_BUCKETS.map((b, i) => {
            const fields = csSimSectionFields(b, CS_SIM_BUCKET_FIELDS, sections[b]);
            return `<details class="border border-slate-200 rounded-md mb-2" ${i === 0 ? 'open' : ''}>
              <summary class="px-3 py-2 cursor-pointer bg-slate-50 font-mono text-xs text-slate-600">Simulation ${b.toUpperCase()} <span class="text-slate-400">(${Object.keys(sections[b] || {}).length})</span></summary>
              <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 p-3">${fields || '<p class="text-xs text-slate-400 italic col-span-full">No values set.</p>'}</div>
            </details>`;
        }).join('');
        simBody = `
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="border border-slate-200 rounded-lg p-3">
              <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest mb-2">[simulation]</p>
              <div class="grid grid-cols-2 md:grid-cols-3 gap-3">${simFields}</div>
            </div>
            <div class="border border-slate-200 rounded-lg p-3">
              <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest mb-2">[server] / [address]</p>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">${serverFields}${addressFields}</div>
            </div>
          </div>
          <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Per-bucket profiles [s0]–[s9]</p>
          ${bucketCards}
          ${extras.length ? `<p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-3 mb-2">Extra sections</p>${extraBlocks}` : ''}
          <details class="mt-3 text-xs"><summary class="cursor-pointer text-slate-400">Raw merged simulation.conf</summary><pre class="mt-2 p-2 bg-slate-50 rounded font-mono text-[11px] whitespace-pre-wrap break-all">${csEscape(raw)}</pre></details>`;
    }
    const simCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex flex-wrap justify-between items-center mb-3 gap-2">
        <div class="flex items-center gap-2">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Simulation Config ${helpIcon('cs', null, 'Simulations help')}</h3>
          <span class="inline-block bg-slate-100 text-slate-500 rounded-full px-2 py-0.5 text-[10px] font-bold">Hub-managed override (no GitHub API key)</span>
          ${simSource === 'spoke' ? '' : (simConnected
            ? '<span class="inline-block bg-amber-100 text-amber-700 rounded-full px-2 py-0.5 text-[10px] font-bold">spoke online — live config fetch timed out, showing stored override</span>'
            : '<span class="inline-block bg-amber-100 text-amber-700 rounded-full px-2 py-0.5 text-[10px] font-bold">spoke offline — showing stored override</span>')}
        </div>
        <span class="text-[10px] text-slate-400">Last fetched: ${csEscape(fetchedSim)}</span>
      </div>
      <p class="text-xs text-slate-400 mb-3">Edit the labeled fields. Saved as the hub-managed <code>sim_conf_override</code> INI and pushed to the spoke (merged on top of the repo's simulation.conf). Clearing a field reverts it to the repo default.</p>
      <div id="cs-ini-sections">${simBody}</div>
      <div class="flex items-center gap-3 mt-4">
        <button onclick="csSaveSimConfStructured()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save</button>
        <button onclick="csRenderConfigSimulation()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-4 py-2 rounded-md text-sm font-bold">Refresh</button>
      </div>
    </div>`;

    // ── User overrides card ─────────────────────────────────────────────────
    const uoCard = csRenderUserOverridesCard(uo, uoErr);

    // ── Hub config card (kept at the bottom) ────────────────────────────────
    let hubCard = '';
    try { hubCard = await csHubConfigCard('/tenant/' + csTenant() + '/hub-config'); }
    catch (e) { console.error('csRenderConfigSimulation: hub-config load failed', e); hubCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Hub Config', e).replace('py-10', 'py-6')}</div>`; }
    csSet(`<div class="space-y-4">${simCard}${uoCard}${hubCard}</div>`);
}

// Serialize the labeled sim-conf inputs (+ extra-section textareas) back into
// INI text. Walk [data-cs-section]/[data-cs-key] inputs; empty values are
// skipped so clearing a field drops it from the override (revert to repo base).
// Then [data-cs-ini-section] raw textareas (extra sections) are appended verbatim.
function csSerializeSimConf() {
    const bySection = {};
    document.querySelectorAll('[data-cs-section][data-cs-key]').forEach(el => {
        const s = el.getAttribute('data-cs-section');
        const k = el.getAttribute('data-cs-key');
        const v = el.value;
        if (v === '' || v === null || v === undefined) return;  // empty → revert
        bySection[s] = bySection[s] || {};
        bySection[s][k] = v;
    });
    const extras = [];
    document.querySelectorAll('[data-cs-ini-section]').forEach(ta => {
        const s = ta.getAttribute('data-cs-ini-section');
        if (!s) return;
        extras.push([s, ta.value]);
    });
    const order = ['simulation', 'server', 'address', ...CS_SIM_BUCKETS];
    const emitted = new Set();
    let out = '';
    for (const s of order) {
        if (bySection[s] && Object.keys(bySection[s]).length) {
            emitted.add(s);
            out += `[${s}]\n`;
            for (const [k, v] of Object.entries(bySection[s])) out += `${k}=${v}\n`;
            out += '\n';
        }
    }
    for (const s of Object.keys(bySection)) {
        if (emitted.has(s) || order.includes(s)) continue;
        out += `[${s}]\n`;
        for (const [k, v] of Object.entries(bySection[s])) out += `${k}=${v}\n`;
        out += '\n';
    }
    for (const [s, body] of extras) {
        out += `[${s}]\n${String(body).replace(/^\s*\n+/, '').replace(/\s+$/, '')}\n\n`;
    }
    return out.trim();
}

window.csSaveSimConfStructured = async function () {
    try {
        const content = csSerializeSimConf();
        const r = await csFetch(`/${csTenant()}/config/simulation-conf`,
            { method: 'PUT', body: JSON.stringify({ content }) });
        showToast('Saved (' + ((r && r.synced_spokes) != null ? r.synced_spokes + ' spokes' : 'ok') + ').', 'success');
        // Re-load the merged view so the UI reflects the now-effective config.
        csRenderConfigSimulation();
    } catch (e) {
        console.error('csSaveSimConfStructured: save failed', e);
        showToast(e.message, 'error');
    }
};

// ── User overrides editor ────────────────────────────────────────────────────
// Per-user simulation override sections ([username] in user-overrides.conf).
// State is the source of truth (csUserOverridesState = {user: {key: value}});
// field inputs update it live, add/remove re-render from it, save serializes it.
let csUserOverridesState = {};
let csUserOverridesFetched = '—';

// Label map for known sim keys (so user-override fields get the same labels as
// the sim-conf editor). Built once from the section + bucket schemas.
const CS_SIM_LABELS = (() => {
    const m = {};
    for (const fields of Object.values(CS_SIM_SECTION_FIELDS))
        for (const [k, lbl] of fields) m[k] = lbl;
    for (const [k, lbl] of CS_SIM_BUCKET_FIELDS) m[k] = lbl;
    return m;
})();

function csUOField(user, key, value) {
    const label = CS_SIM_LABELS[key] || key;
    const v = (value === undefined || value === null) ? '' : String(value);
    const attrs = `data-cs-uo-user="${csEscape(user)}" data-cs-uo-key="${csEscape(key)}"`;
    if (CS_ONOFF_KEYS.has(key)) {
        const on = v.toLowerCase() === 'on';
        return `<div class="flex flex-col gap-1">
          <label class="text-[10px] text-slate-500 uppercase font-bold tracking-wider">${csEscape(label)}</label>
          <select ${attrs} onchange="csUOSet(this)"
                  class="border border-slate-200 rounded-md px-2 py-1.5 text-sm ${on ? 'text-emerald-700 font-semibold' : 'text-slate-600'}">
            <option value="on" ${on ? 'selected' : ''}>on</option>
            <option value="off" ${!on ? 'selected' : ''}>off</option>
          </select></div>`;
    }
    return `<div class="flex flex-col gap-1">
      <label class="text-[10px] text-slate-500 uppercase font-bold tracking-wider">${csEscape(label)}</label>
      <input ${attrs} value="${csEscape(v)}" oninput="csUOSet(this)"
             class="border border-slate-200 rounded-md px-2 py-1.5 text-sm font-mono">
    </div>`;
}

// Render all per-user cards from csUserOverridesState.
function csUORenderCards() {
    const users = Object.keys(csUserOverridesState);
    if (!users.length) {
        return '<p class="text-xs text-slate-400 italic">No per-user overrides. Click ＋ Add User to pin a hostname to a custom sim profile.</p>';
    }
    return users.map(u => {
        const kv = csUserOverridesState[u] || {};
        const fields = Object.keys(kv).map(k => csUOField(u, k, kv[k])).join('');
        const cnt = Object.keys(kv).length;
        return `<div class="border border-slate-200 rounded-lg p-3 mb-3">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-bold text-slate-700">👤 ${csEscape(u)}</span>
            <div class="flex gap-2">
              <button data-uo-user="${csEscape(u)}" onclick="csUODownload(this)"
                      class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-2 py-1 rounded-md text-[11px] font-bold">Download</button>
              <button data-uo-user="${csEscape(u)}" onclick="csUORemove(this)"
                      class="bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded-md text-[11px] font-bold">✕ Remove</button>
            </div>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">${fields || '<p class="text-xs text-slate-400 italic col-span-full">No fields found in this override.</p>'}</div>
        </div>`;
    }).join('');
}

function csRenderUserOverridesCard(uo, uoErr) {
    if (uoErr) {
        return `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('User Overrides', uoErr).replace('py-10', 'py-6')}</div>`;
    }
    const content = (uo && uo.content) || '';
    csUserOverridesState = csParseIni(content);
    csUserOverridesFetched = (uo && uo.fetched_at) ? csFmtFetched(uo.fetched_at) : '—';
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex flex-wrap justify-between items-center mb-2 gap-2">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">User Overrides ${helpIcon('cs', null, 'Simulations help')}</h3>
        <span class="text-[10px] text-slate-400">Last fetched: ${csEscape(csUserOverridesFetched)}</span>
      </div>
      <p class="text-xs text-slate-400 mb-3">Per-user simulation overrides — pin a hostname to specific sim settings (a <code>[username]</code> section overrides the bucket profile for that user).</p>
      <div class="flex items-center gap-3 mb-3">
        <button onclick="csUOAdd()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-1.5 rounded-md text-sm font-bold">＋ Add User</button>
        <button onclick="csRenderConfigSimulation()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-3 py-1.5 rounded-md text-sm font-bold">Refresh</button>
        <button onclick="csUOSave()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-1.5 rounded-md text-sm font-bold">Save</button>
      </div>
      <div id="cs-uo-cards">${csUORenderCards()}</div>
    </div>`;
}

window.csUOSet = function (el) {
    const u = el.dataset.csUoUser, k = el.dataset.csUoKey;
    if (!u || !k) return;
    csUserOverridesState[u] = csUserOverridesState[u] || {};
    csUserOverridesState[u][k] = el.value;
};

// Build the default field template for a newly-added user override, mirroring
// the legacy getSpokeUserOverrideTemplate: union of keys across existing
// sections (so a new card shows the same fields siblings already track), with
// boolean flags defaulted to 'off' and sim_load to '100'. Falls back to a
// sensible default set when no sections exist yet.
function csUOTemplate() {
    const seen = new Set();
    const order = [];
    const sample = {};
    for (const kv of Object.values(csUserOverridesState)) {
        for (const k of Object.keys(kv)) {
            if (seen.has(k)) continue;
            seen.add(k); order.push(k); sample[k] = kv[k];
        }
    }
    if (!order.length) {
        for (const k of ['wsite', 'ssid', 'ssidpw', 'dhcp_fail', 'kill_switch', 'sim_load']) {
            seen.add(k); order.push(k);
        }
        sample.dhcp_fail = 'off'; sample.kill_switch = 'off'; sample.sim_load = '100';
    }
    const values = {};
    for (const k of order) {
        const s = sample[k];
        if (csIsBoolVal(s) || k === 'dhcp_fail' || k === 'kill_switch' || CS_ONOFF_KEYS.has(k)) values[k] = 'off';
        else if (k === 'sim_load') values[k] = s ? String(s) : '100';
        else values[k] = '';
    }
    return values;
}

// True for values the legacy treated as boolean toggles (on/off/true/false).
function csIsBoolVal(v) {
    if (v === true || v === false) return true;
    const s = String(v == null ? '' : v).trim().toLowerCase();
    return s === 'on' || s === 'off';
}

window.csUOAdd = function () {
    const u = prompt('Username to pin (hostname prefix, e.g. jsmith):');
    if (!u) return;
    const user = u.trim();
    if (!user || /[\r\n\[\]]/.test(user)) { if (typeof showToast === 'function') showToast('Invalid username.', 'error'); return; }
    if (csUserOverridesState[user]) { if (typeof showToast === 'function') showToast('User already exists.', 'error'); return; }
    csUserOverridesState[user] = csUOTemplate();
    const c = csEl('cs-uo-cards');
    if (c) c.innerHTML = csUORenderCards();
};

window.csUORemove = function (btn) {
    const u = btn.dataset.uoUser;
    if (!u) return;
    if (!confirm(`Remove override for ${u}?`)) return;
    delete csUserOverridesState[u];
    const c = csEl('cs-uo-cards');
    if (c) c.innerHTML = csUORenderCards();
};

window.csUODownload = function (btn) {
    const u = btn.dataset.uoUser;
    const kv = csUserOverridesState[u] || {};
    let text = `[${u}]\n`;
    for (const [k, v] of Object.entries(kv)) text += `${k}=${v}\n`;
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${u}.conf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
};

window.csUOSave = async function () {
    let text = '';
    for (const [u, kv] of Object.entries(csUserOverridesState)) {
        text += `[${u}]\n`;
        for (const [k, v] of Object.entries(kv)) {
            if (v === '' || v === null || v === undefined) continue;  // empty → drop
            text += `${k}=${v}\n`;
        }
        text += '\n';
    }
    try {
        const r = await csFetch(`/${csTenant()}/config/user-overrides-conf`,
            { method: 'PUT', body: JSON.stringify({ content: text.trim() }) });
        showToast('Saved (' + ((r && r.synced_spokes) != null ? r.synced_spokes + ' spokes' : 'ok') + ').', 'success');
    } catch (e) {
        console.error('csUOSave: save failed', e);
        showToast(e.message, 'error');
    }
};

// Human-readable "Last fetched" stamp from the hub's ISO-8601 fetched_at.
function csFmtFetched(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleString();
    } catch (e) { return iso; }
}

window.CS_CHILD_RENDERERS['Config::API'] = csRenderConfig;
window.CS_CHILD_RENDERERS['Config::Simulation'] = csRenderConfigSimulation;

/* Shared hub-config card used by Config → Simulation + Setup → Proxmox.
 * Mirrors webui-hub's HUB_CONFIG_FIELDS panel (app.js:16485 + templates/index.html:954):
 * the hub IS the source of truth, so the remaining owned knobs (schedules, VLANs,
 * watchdog group, VID/PID lists, VMID range, use_all_dongles) are exposed here.
 * The provisioning-behavior / template / threshold / protected-VMID knobs live in
 * the structured VM Auto-Provisioning card (CS_AUTOPROV_FIELDS). Because
 * store.set_hub_config REPLACES (not merges), csSaveHubConfig does GET-merge-PUT
 * so saving this card does not wipe the Auto-Provisioning card's keys (and vice
 * versa). Empty fields are omitted from the collected patch (as in webui-hub). */
const CS_HUB_CONFIG_FIELDS = [
    { key: 'repo_branch',                 label: 'Repo Branch',                type: 'branch', repo: 'pxmx' },
    { key: 'reclone_schedule_enabled',    label: 'Reclone Schedule',           type: 'onoff' },
    { key: 'reclone_schedule_cron',       label: 'Reclone Cron',               type: 'text',   ph: 'sunday 02:00' },
    // NOTE: the provisioning-behavior knobs (usb_auto_provision, usb_missing_timeout,
    // usb_max_slots, reclone_concurrency), the clone-source templates
    // (vm_image_1/2_template_id, vm_image_1_pct), the resource thresholds, and
    // protected_vmids are owned by the structured "VM Auto-Provisioning" card
    // (CS_AUTOPROV_FIELDS / csSetupAutoProvConfigCard) — NOT this flat grid — so
    // they render grouped + with help text and don't collide here.
    // VMID allocation range for NEW sim VMs. The clone-source templates (owned by
    // the VM Auto-Provisioning card) are excluded from this pool by the agent —
    // keep them OUTSIDE the range (the agent enforces it regardless, but
    // configuring them outside avoids wasted scans). Defaults 90000-99999
    // (Proxmox's high VMID band), cluster-consistent. The cs speak emits these as
    // usb_config vmid_start/vmid_end (flat), which the agent reads.
    { key: 'vmid_start',                  label: 'VMID Range Start',           type: 'number', ph: '90000', min: 100 },
    { key: 'vmid_end',                    label: 'VMID Range End',             type: 'number', ph: '99999', min: 100 },
    { key: 'use_all_dongles',             label: 'Use All Dongles',            type: 'onoff' },
    { key: 'vm_silent_timeout',           label: 'VM Silent Timeout (h)',      type: 'number', ph: '24' },
    { key: 'l1_vlan_start',               label: 'L1 VLAN Start',              type: 'text',   ph: '100' },
    { key: 'l1_vlan_end',                 label: 'L1 VLAN End',                type: 'text',   ph: '199' },
    // ── Guest-agent watchdog (hub-owned; cs spoke → agent usb_config). Ported
    // from the original solutions-hpe/client-sim Setup/Proxmox (HUB_CONFIG_OWNED_KEYS:
    // guest_agent_* + watchdog_reboot_enabled). The agent (watchdogs.py) reads
    // these from the cs-speak usb_config blob; env vars still override.
    { key: 'guest_agent_watchdog_enabled',          label: 'Guest-Agent Watchdog',     type: 'onoff' },
    { key: 'guest_agent_grace_minutes',             label: 'GA Grace (min)',          type: 'number', ph: '20', min: 1 },
    { key: 'guest_agent_check_interval_minutes',    label: 'GA Check Interval (min)', type: 'number', ph: '10', min: 1 },
    { key: 'guest_agent_reboot_after_minutes',      label: 'GA Reboot After (min)',   type: 'number', ph: '10', min: 1 },
    { key: 'guest_agent_reclone_after_minutes',     label: 'GA Reclone After (min)',  type: 'number', ph: '30', min: 1 },
    { key: 'watchdog_reboot_enabled',               label: 'Watchdog Reboot',         type: 'onoff' },
    { key: 'usb_vidpids',                 label: 'USB Certified VID:PIDs (JSON array of {vidpid,type,label})',  type: 'json',   ph: '[{"vidpid":"1a2b:3c4d","type":"wireless","label":"1a2b:3c4d"}]', full: true },
    { key: 'usb_ignored_vidpids',         label: 'USB Ignored VID:PIDs (JSON array of "vid:pid")', type: 'json', ph: '["1a2b:3c4d"]', full: true },
    { key: 't1_pci_vidpids',              label: 'T1 PCI VID:PIDs (JSON array of "vid:pid" — VM whose PCI passthrough matches → T1)', type: 'json', ph: '["1912:0015"]', full: true },
    { key: 't3_pci_vidpids',              label: 'T3 PCI VID:PIDs (JSON array of "vid:pid" — VM whose PCI passthrough matches → T3)', type: 'json', ph: '["168c:0034"]', full: true },
    { key: 'ignored_hostnames',           label: 'Ignored Hostnames (JSON array)', type: 'json', ph: '["sim-rpi-0000"]', full: true },
];

function _csHcOnOff(id, val, onChangeFn) {
    const on = String(val || 'off').toLowerCase() === 'on' || val === true;
    const onchange = onChangeFn ? ` onchange="${onChangeFn}()"` : '';
    return `<select id="${id}"${onchange} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
      <option value="off" ${!on ? 'selected' : ''}>Off</option>
      <option value="on"  ${on ? 'selected' : ''}>On</option>
    </select>`;
}

// Fetch the branch list for a repo (module key like 'pxmx'/'cs', an
// "owner/name", or a full git URL) from the hub's git-ls-remote endpoint.
// Returns an array of branch names, or null on any failure — the caller then
// falls back to a plain text input so a branch can still be typed (and so the
// cs standalone dashboard, which has no hub /setup route, degrades cleanly).
async function csFetchBranches(repo) {
    if (!repo) return null;
    // Client-side timeout so a slow/unreachable remote can't block the card
    // render for the backend's full git-ls-remote budget — fall back to a text
    // input quickly instead.
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 9000);
    try {
        const res = await fetch('/setup/repo-branches?repo=' + encodeURIComponent(repo),
                                { headers: { 'Content-Type': 'application/json' }, signal: ctrl.signal });
        if (!res.ok) return null;
        const data = await res.json();
        return Array.isArray(data.branches) && data.branches.length ? data.branches : null;
    } catch (e) {
        console.warn('csFetchBranches: could not list branches for', repo, e);
        return null;
    } finally {
        clearTimeout(t);
    }
}

// Render a branch picker: a <select> of the fetched branches when available,
// else a plain text input (so nothing is lost when GitHub/the remote is
// unreachable). The current value is always preserved as a selectable option
// even if it isn't in the fetched list (a custom/feature branch, or a typo the
// admin still wants to see) so saving never silently drops it.
function _csBranchSelect(id, currentVal, branches, onChangeFn) {
    const cur = currentVal != null ? String(currentVal) : '';
    // onChangeFn is optional: cards that auto-save (Hub Config) pass their save
    // fn; cards with an explicit Save button (GitHub) omit it so the picker
    // just holds its value until the user clicks Save.
    if (!branches) {
        const onblur = onChangeFn ? ` onblur="${onChangeFn}()"` : '';
        return `<input id="${id}" type="text" value="${csEscape(cur)}" placeholder="main"${onblur} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
    }
    const onchange = onChangeFn ? ` onchange="${onChangeFn}()"` : '';
    const list = branches.includes(cur) || !cur ? branches.slice() : [cur, ...branches];
    const opts = list.map(b =>
        `<option value="${csEscape(b)}" ${b === cur ? 'selected' : ''}>${csEscape(b)}</option>`).join('');
    return `<select id="${id}"${onchange} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">${opts}</select>`;
}

async function csHubConfigCard(path) {
    const data = await csFetch(path);
    const enabled = !!(data && data.hub_config_enabled);
    const hc = (data && data.hub_config) || {};
    // Pre-fetch branch lists once per distinct repo for any 'branch' fields, so
    // the synchronous field map below can build a populated <select> (falls
    // back to a text input per-field when a repo's branches can't be listed).
    const branchRepos = [...new Set(CS_HUB_CONFIG_FIELDS
        .filter(c => c.type === 'branch').map(c => c.repo))];
    const branchMap = {};
    await Promise.all(branchRepos.map(async r => { branchMap[r] = await csFetchBranches(r); }));
    const fields = CS_HUB_CONFIG_FIELDS.map(col => {
        const valRaw = hc[col.key];
        const valStr = (valRaw != null && typeof valRaw !== 'object') ? String(valRaw)
                     : (typeof valRaw === 'object' && valRaw != null) ? JSON.stringify(valRaw) : '';
        const label = `<label class="text-xs text-slate-500 ${col.full ? 'md:col-span-3' : ''}">${csEscape(col.label)}`;
        let input;
        if (col.type === 'onoff') input = _csHcOnOff('cs-hc-' + col.key, valRaw, 'csSaveHubConfig');
        else if (col.type === 'branch') input = _csBranchSelect('cs-hc-' + col.key, valStr, branchMap[col.repo], 'csSaveHubConfig');
        else if (col.type === 'number') input = `<input id="cs-hc-${col.key}" type="number" value="${csEscape(valStr)}" ${col.min != null ? `min="${col.min}"` : ''} ${col.max != null ? `max="${col.max}"` : ''} placeholder="${csEscape(col.ph || '')}" onblur="csSaveHubConfig()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        else input = `<input id="cs-hc-${col.key}" type="text" value="${csEscape(valStr)}" placeholder="${csEscape(col.ph || '')}" onblur="csSaveHubConfig()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        return `${label}${input}</label>`;
    }).join('');
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Hub Config ${helpIcon('cs', null, 'Simulations help')}</h3>
      <p class="text-xs text-slate-400 mb-3">Changes save automatically — a select/checkbox saves on change, a text/number field saves when you click or tab away from it.</p>
      <label class="flex items-center gap-2 text-xs text-slate-600 mb-3"><input id="cs-hc-enabled" type="checkbox" ${enabled ? 'checked' : ''} onchange="csHcToggleEnabled(this.checked)"> Enable hub as source of truth</label>
      <div id="cs-hc-fields" class="${enabled ? '' : 'hidden'} grid grid-cols-1 md:grid-cols-3 gap-3">
        ${fields}
      </div>
    </div>`;
}

window.csHcToggleEnabled = function (checked) {
    const fields = csEl('cs-hc-fields');
    if (fields) fields.classList.toggle('hidden', !checked);
    csSaveHubConfig();
};

window.csSaveHubConfig = async function () {
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
    try {
        // store.set_hub_config REPLACES (not merges), so two cards that each own a
        // subset of hub_config keys would wipe each other on save. GET the current
        // snapshot, merge our collected fields over it, then PUT the full merged
        // hub_config — the VM Auto-Provisioning card's keys are preserved.
        const cur = await csFetch('/tenant/' + csTenant() + '/hub-config');
        const merged = Object.assign({}, (cur && cur.hub_config) || {}, config);
        const body = {
            hub_config_enabled: !!(csEl('cs-hc-enabled') && csEl('cs-hc-enabled').checked),
            hub_config: merged
        };
        const r = await csFetch('/tenant/' + csTenant() + '/hub-config', { method: 'PUT', body: JSON.stringify(body) });
        csPushToast(r, 'Saved');
    } catch (e) {
        console.error('csSaveHubConfig: hub-config push failed', e);
        showToast(e.message, 'error');
    }
};

/* ===========================================================================
 * 6. Setup — hub-config + processing-modes + notifications
 *    (Onboarding PSK lives in Spoke Management now — removed from here to
 *    avoid the duplicate copy.)
 * ========================================================================= */

/* Structured "VM Auto-Provisioning" card — the grouped, source-repo-faithful
 * port of the original solutions-hpe/client-sim Setup/Proxmox panel
 * (.scratch-shpe/cs-webui/templates/index.html:490, ts-proxmox), extended with
 * Resource Thresholds + Protected VMIDs (the original card's siblings the user
 * surfaced). Owns the provisioning-behavior / template / threshold /
 * protected-VMID knobs; the rest stay in the flat Hub Config card. A `section`
 * row renders a divider (+ optional help text); every other row is a field.
 * Element ids use the cs-ap- prefix (distinct from the Hub Config card's
 * cs-hc-) so the two cards' saves never cross-read. Save is GET-merge-PUT — see
 * csSaveHubConfig for why (store.set_hub_config REPLACES, not merges). */
const CS_AUTOPROV_FIELDS = [
    { section: 'Provisioning Behavior' },
    { key: 'usb_auto_provision',   label: 'Auto-Provision VMs',            type: 'onoff' },
    { key: 'usb_missing_timeout',  label: 'Destroy after missing (minutes)', type: 'number', ph: '60', min: 1 },
    { key: 'usb_max_slots',        label: 'Max VMs per host',              type: 'number', ph: '24', min: 1, max: 256 },
    // Resource thresholds act on the 1-hour rolling average (pxmx agent records
    // cpu_samples/mem_samples rings). Above the provision threshold → no new
    // VMs; above the delete threshold → newest sim VM is removed (one/cycle).
    // Stored as % (0-100); the cs speak clamps + threads them into usb_config.
    { section: 'Resource Thresholds (1-hour average)',
      help: 'When the 1-hour rolling average exceeds the provision threshold no new VMs are spun up. When it exceeds the delete threshold the newest sim VM is removed (one per cycle). Values apply only after a full hour of telemetry data is available.' },
    { key: 'cpu_provision_threshold', label: 'CPU — Block provisioning above (%)', type: 'number', ph: '80', min: 0, max: 100 },
    { key: 'cpu_delete_threshold',    label: 'CPU — Delete VM above (%)',        type: 'number', ph: '90', min: 0, max: 100 },
    { key: 'mem_provision_threshold', label: 'Memory — Block provisioning above (%)', type: 'number', ph: '80', min: 0, max: 100 },
    { key: 'mem_delete_threshold',    label: 'Memory — Delete VM above (%)',        type: 'number', ph: '90', min: 0, max: 100 },
    // Clone-source templates (clone FROM these VMIDs). The agent excludes them
    // from the VMID allocation pool; keep them OUTSIDE vmid_start/vmid_end and
    // cluster-consistent. Hub key vm_image_* is remapped to image*_template_id
    // by the cs speak (_HUB_KEY_REMAP) before landing in settings + usb_config.
    { section: 'VM Templates' },
    { key: 'vm_image_1_template_id', label: 'VM Image 1 Template VMID', type: 'number', ph: '100', min: 1 },
    { key: 'vm_image_2_template_id', label: 'VM Image 2 Template VMID', type: 'number', ph: '200', min: 1 },
    { key: 'vm_image_1_pct',          label: 'VM Image 1 % target',     type: 'number', ph: '50',  min: 0, max: 100 },
    { section: 'Parallel Provisioning' },
    { key: 'reclone_concurrency', label: 'Max parallel operations', type: 'number', ph: '1', min: 1, max: 20 },
    // Comma-separated ints AND ranges ("9000, 9005-9007"). VM 1001 is always
    // protected regardless — the cs speak merges it into the emitted list.
    { section: 'Protected VMIDs',
      help: 'Comma-separated VMIDs that cannot be started, stopped, recloned, or deleted. VM 1001 is always protected.' },
    { key: 'protected_vmids', label: 'Protected VMIDs', type: 'text', ph: '9000, 9005-9007', full: true },
];

async function csSetupAutoProvConfigCard() {
    let hc = {}, enabled = false;
    try {
        const data = await csFetch('/tenant/' + csTenant() + '/hub-config');
        enabled = !!(data && data.hub_config_enabled);
        hc = (data && data.hub_config) || {};
    } catch (e) { console.error('csSetupAutoProvConfigCard: hub-config fetch failed', e); }
    const rows = CS_AUTOPROV_FIELDS.map(col => {
        if (col.section) {
            const help = col.help ? `<p class="text-[11px] text-slate-400 mt-1 mb-1 leading-snug">${csEscape(col.help)}</p>` : '';
            return `<div class="md:col-span-3 mt-2"><p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">${csEscape(col.section)}</p>${help}</div>`;
        }
        const valRaw = hc[col.key];
        const valStr = (valRaw != null && typeof valRaw !== 'object') ? String(valRaw)
                     : (typeof valRaw === 'object' && valRaw != null) ? JSON.stringify(valRaw) : '';
        const label = `<label class="text-xs text-slate-500 ${col.full ? 'md:col-span-3' : ''}">${csEscape(col.label)}`;
        let input;
        if (col.type === 'onoff') input = _csHcOnOff('cs-ap-' + col.key, valRaw, 'csSaveAutoProvConfig');
        else if (col.type === 'number') input = `<input id="cs-ap-${col.key}" type="number" value="${csEscape(valStr)}" ${col.min != null ? `min="${col.min}"` : ''} ${col.max != null ? `max="${col.max}"` : ''} placeholder="${csEscape(col.ph || '')}" onblur="csSaveAutoProvConfig()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        else input = `<input id="cs-ap-${col.key}" type="text" value="${csEscape(valStr)}" placeholder="${csEscape(col.ph || '')}" onblur="csSaveAutoProvConfig()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        return `${label}${input}</label>`;
    }).join('');
    const note = enabled ? '<span class="text-slate-400">Hub-owned knobs; saved automatically as you edit (a select/checkbox on change, a text/number field when you click or tab away). Turning Auto-Provision VMs On also enables hub config (mirrors the Overview/USB toggle).</span>'
        : '<span class="text-amber-600">Hub config is not enabled — auto-save pushes to spokes only when Auto-Provision VMs is On (which enables hub config) or after you enable it in the Hub Config card below.</span>';
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">VM Auto-Provisioning ${helpIcon('cs', null, 'Simulations help')}</h3>
      <p class="text-xs text-slate-400 mb-3">${note}</p>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">${rows}</div>
    </div>`;
}

window.csSaveAutoProvConfig = async function () {
    // Collect only this card's fields (cs-ap- prefix). Numbers/scalars are sent
    // as strings — the cs speak stores + normalizes them (usb_missing_timeout
    // minutes→seconds, protected_vmids parsed + 1001 merged, thresholds clamped).
    const config = {};
    CS_AUTOPROV_FIELDS.forEach(col => {
        if (col.section) return;
        const el = csEl('cs-ap-' + col.key);
        if (!el) return;
        const v = (el.value || '').trim();
        if (!v) return;
        config[col.key] = v;
    });
    try {
        // store.set_hub_config REPLACES (not merges) → GET-merge-PUT so saving
        // this card does not wipe the Hub Config card's keys (VID/PID lists,
        // watchdog group, VLANs, VMID range, …).
        const cur = await csFetch('/tenant/' + csTenant() + '/hub-config');
        const merged = Object.assign({}, (cur && cur.hub_config) || {}, config);
        // Mirror the Overview toggle's semantics (POST /toggle-auto-provision,
        // routes.py): turning Auto-Provision VMs On must also enable hub_config
        // so the set_hub_config route actually pushes to spokes (it only pushes
        // `if enabled`, routes.py:996). Without this, saving On here wrote the
        // key but never pushed it → the Overview checkbox showed On yet the
        // provision loop never started (the Setup dropdown looked "not linked"
        // to the real auto-provision the Overview checkbox controls).
        const autoProvOn = String(merged.usb_auto_provision || '').toLowerCase() === 'on';
        const hcEnabled = !!(cur && cur.hub_config_enabled) || autoProvOn;
        const body = {
            hub_config_enabled: hcEnabled,
            hub_config: merged
        };
        const r = await csFetch('/tenant/' + csTenant() + '/hub-config', { method: 'PUT', body: JSON.stringify(body) });
        csPushToast(r, 'Saved');
        // Keep the Overview/USB auto-provision checkbox + status in sync with
        // this save (same underlying key) so the two controls never drift.
        try { if (typeof csRefreshAutoProvStatus === 'function') csRefreshAutoProvStatus(); } catch (_) {}
    } catch (e) {
        console.error('csSaveAutoProvConfig: hub-config push failed', e);
        showToast(e.message, 'error');
    }
};

async function csRenderSetup() {
    csSetToolbar('');
    let modesCard = '';
    try { modesCard = await csProcessingModesCard(); } catch (e) { console.error('csRenderSetup: processing-modes card load failed', e); modesCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Processing Modes', e).replace('py-10', 'py-6')}</div>`; }
    csSet(`<div class="space-y-4">${modesCard}</div>`);
}

async function csProcessingModesCard() {
    const data = await csFetch('/' + csTenant() + '/settings');
    const modes = (data && data.processing_modes) || {};
    const features = [['central_api', 'Central API'], ['teams', 'Teams'], ['email', 'Email']];
    // Unset == distributed at runtime (routes.py test_central: `modes.get("central_api") == "centralized"`
    // is False when unset → distributed branch). Show that truth in the dropdown instead of letting the
    // browser default-display the first option ("Centralized"), which misleads operators into thinking
    // centralized is active when nothing has been persisted.
    const opts = (cur) => {
        if (!cur) cur = 'distributed';
        return ['centralized', 'distributed'].map(v =>
            `<option value="${v}" ${cur === v ? 'selected' : ''}>${v.charAt(0).toUpperCase() + v.slice(1)}</option>`).join('');
    };
    const fields = features.map(([k, label]) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <select id="cs-pm-${k}" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">${opts(modes[k])}</select>
    </label>`).join('');
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Processing Modes ${helpIcon('cs', null, 'Simulations help')}</h3>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">${fields}</div>
      <button onclick="csSaveProcessingModes()" class="mt-4 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Modes</button>
    </div>`;
}

window.csSaveProcessingModes = async function () {
    const features = ['central_api', 'teams', 'email'];
    try {
        for (const k of features) {
            const v = csEl('cs-pm-' + k) && csEl('cs-pm-' + k).value;
            if (v) await csFetch('/hub/tenants/' + csTenant() + '/processing-modes', { method: 'PATCH', body: JSON.stringify({ [k]: v }) });
        }
        showToast('Saved.', 'success');
    } catch (e) { console.error('csSaveProcessingModes: save failed', e); showToast(e.message, 'error'); }
};

async function csNotificationsCard() {
    const data = await csFetch('/' + csTenant() + '/settings');
    const n = (data && data.notifications) || {};
    const f = (id, label, val, type) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <input id="${id}" ${type === 'checkbox' ? 'type="checkbox" ' + (val ? 'checked' : '') : `value="${csEscape(val != null ? val : '')}"`} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
    </label>`;
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Notifications ${helpIcon('cs', null, 'Simulations help')}</h3>
      <label class="flex items-center gap-2 text-xs text-slate-600 mb-3"><input id="cs-notif-enabled" type="checkbox" ${n.enabled ? 'checked' : ''}> Notifications enabled</label>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        ${f('cs-notif-host', 'SMTP Host', n.smtp_host)}${f('cs-notif-port', 'SMTP Port', n.smtp_port, 'number')}
        ${f('cs-notif-user', 'SMTP User', n.smtp_user)}${f('cs-notif-pass', 'SMTP Password (new)', '', 'password')}
        ${f('cs-notif-teams', 'Teams Webhook URL (new)', '', 'password')}
        ${f('cs-notif-emails', 'To Emails (comma-separated)', Array.isArray(n.to_emails) ? n.to_emails.join(', ') : (n.to_emails || ''))}
      </div>
      <button onclick="csSaveNotifications()" class="mt-4 bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Notifications</button>
    </div>`;
}

window.csSaveNotifications = async function () {
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
        showToast('Saved.', 'success');
    } catch (e) { console.error('csSaveNotifications: save failed', e); showToast(e.message, 'error'); }
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
    } catch (e) { console.error('csSetupAutoProvCard: usb-provisioning-status fetch failed, defaulting to off', e); }
    // Present/Unknown USB come from the SAME source the VM Server Overview and
    // USB views use (csVmLoad → per-host proxmox.present_usb/unknown_usb arrays,
    // summed across the fleet), so the Setup counts always match Overview/USB
    // instead of reading 0 from a separate endpoint's spoke-level field when the
    // shape differs or a spoke isn't relaying.
    try {
        const hosts = await csVmLoad();
        present = (hosts || []).reduce((n, h) => n + csPresentUsbCount(h), 0);
        unknown = (hosts || []).reduce((n, h) => n + csUnknownUsbCount(h), 0);
    } catch (e) { console.error('csSetupAutoProvCard: vm load for USB counts failed, defaulting to 0', e); }
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Dongle / Auto-Provisioning ${helpIcon('cs', null, 'Simulations help')}</h3>
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

    // Known Aruba Central API regional gateways (new Central platform). Rendered as a
    // <datalist> so Cluster URL is a dropdown of known clusters AND still accepts a typed
    // custom URL (private clusters, classic /oauth2/token hosts, future regions).
    // Source: developer.arubanetworks.com new-central docs "Making API Calls".
    const CENTRAL_CLUSTERS = [
        ['US-1 (prod)', 'https://us1.api.central.arubanetworks.com'],
        ['US-2', 'https://us2.api.central.arubanetworks.com'],
        ['US-West-4', 'https://us4.api.central.arubanetworks.com'],
        ['US-West-5', 'https://us5.api.central.arubanetworks.com'],
        ['US-East-1', 'https://us6.api.central.arubanetworks.com'],
        ['Canada-1', 'https://ca1.api.central.arubanetworks.com'],
        ['EU-1', 'https://de1.api.central.arubanetworks.com'],
        ['EU-Central-2', 'https://de2.api.central.arubanetworks.com'],
        ['EU-Central-3', 'https://de3.api.central.arubanetworks.com'],
        ['UK', 'https://gb1.api.central.arubanetworks.com'],
        ['APAC-1 (India)', 'https://in1.api.central.arubanetworks.com'],
        ['APAC-East-1 (Japan)', 'https://jp1.api.central.arubanetworks.com'],
        ['APAC-South-1 (Australia)', 'https://au1.api.central.arubanetworks.com'],
        ['UAE-North-1', 'https://ae1.api.central.arubanetworks.com'],
        ['China', 'https://cn1.api.central.arubanetworks.com.cn'],
        ['Internal', 'https://internal.api.central.arubanetworks.com'],
    ];
    const clusterField = `<label class="text-xs text-slate-500">Cluster URL
      <input id="cs-csc-cluster" list="cs-central-clusters" value="${csEscape(hc.cluster_url || '')}" placeholder="select a known cluster or type a custom URL" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
      <datalist id="cs-central-clusters">${CENTRAL_CLUSTERS.map(([region, url]) => `<option value="${url}" label="${csEscape(region)}">`).join('')}</datalist>
    </label>`;

    const connCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Central API Connection ${helpIcon('cs', null, 'Simulations help')}</h3>
      <p class="text-xs text-slate-400 mb-3">Aruba Central cluster credentials. Pushed to the spoke as <code>central_config</code>; the spoke sentinel-merges them — secrets only overwrite when non-empty.</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label class="text-xs text-slate-500">Mode${modeSel}</label>
        ${clusterField}
        ${f('cs-csc-clientid', 'Client ID', hc.client_id)}
        ${f('cs-csc-customerid', 'Customer ID', hc.customer_id)}
        ${f('cs-csc-clientsecret', 'Client Secret', hc.client_secret, 'password')}
        ${f('cs-csc-accesstoken', 'Access Token (classic)', hc.access_token, 'password')}
        ${f('cs-csc-refreshtoken', 'Refresh Token (classic)', hc.refresh_token, 'password')}
      </div>
      <div class="flex gap-2 mt-4">
        <button onclick="csSaveCentralConn()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save Connection</button>
        <button onclick="csTestCentral()" class="bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-bold">Test Central</button>
      </div>
      <div id="cs-csc-test" class="mt-3 text-xs text-slate-500"></div>
    </div>`;

    const smRows = Object.keys(sm).map(w => csCscSmRow(w, sm[w])).join('');
    const hwRows = hw.map(h => csCscHwRow(h.id, h.name, h.device_type)).join('');
    const mcList = (mc && mc.length) ? mc.map(c => `<div class="text-xs text-slate-600">• ${csEscape(c.name || c.id)} <span class="text-slate-400 font-mono">(${csEscape(c.type || 'alert')}/${csEscape(c.id)})</span></div>`).join('')
        : '<p class="text-xs text-slate-400 italic">None configured. Load the available-checks catalog to pick Aruba Central alerts/insights.</p>';

    const sitesCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Sites &amp; Checks ${helpIcon('cs', null, 'Simulations help')}</h3>
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
        csPushToast(r, 'Saved');
    } catch (e) { console.error('csSaveCentralConn: central connection save failed', e); showToast(e.message, 'error'); }
};

window.csSaveCentralSites = async function () {
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
        csPushToast(r, 'Saved');
    } catch (e) { console.error('csSaveCentralSites: central sites save failed', e); showToast(e.message, 'error'); }
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
        // VM Auto-Provisioning (structured config, at top) → Hub Config (remaining
        // knobs). The old "Dongle / Auto-Provisioning" status card that used to
        // sit here was removed — it duplicated the new structured card's
        // Auto-Provision on/off (now the "Auto-Provision VMs" select, saved with
        // the rest of the knobs via GET-merge-PUT). Live dongle counts + the
        // provision-loop status live on the Overview/USB page card
        // (cs-autoprov-toggle / csRefreshAutoProvStatus), unchanged. Both Setup
        // cards save via GET-merge-PUT against the same /tenant/{t}/hub-config,
        // so neither wipes the other's keys.
        let autoProv = '';
        try { autoProv = await csSetupAutoProvConfigCard(); } catch (e) { console.error('csRenderSetupProxmox: auto-prov card load failed', e); autoProv = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('VM Auto-Provisioning', e).replace('py-10', 'py-6')}</div>`; }
        const card = await csHubConfigCard('/tenant/' + csTenant() + '/hub-config');
        const resetBar = `<div class="hpe-card rounded-lg p-4 shadow-sm flex items-center justify-between gap-3">
          <p class="text-xs text-slate-500">Reset every knob on this page to factory defaults. Certified/ignored USB devices + ignored hostnames are preserved (manage those on the USB page).</p>
          <button onclick="csResetHubConfig()" class="shrink-0 bg-red-100 hover:bg-red-200 text-red-700 px-4 py-2 rounded-md text-sm font-bold">Reset to Default</button>
        </div>`;
        csSet(`<div class="space-y-4">${autoProv}<div class="hpe-card rounded-lg p-5 shadow-sm">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Hub Config ${helpIcon('cs', null, 'Simulations help')}</h3>
          <p class="text-xs text-slate-400 mb-3">Remaining hub-owned knobs (reclone schedule, VMID range, VLANs, USB VID/PID lists, watchdog group). Pushed to the spoke on save.</p>
        </div>${card}${resetBar}</div>`);
    } catch (e) { console.error('csRenderSetupProxmox: proxmox config load failed', e); csSet(csErrorBox('Could not load Proxmox config', e)); }
}

window.csResetHubConfig = async function () {
    if (!confirm('Reset all Simulations/Setup/Proxmox knobs to factory defaults for this tenant? Certified/ignored USB devices are preserved. This pushes the reset config to the spoke.')) return;
    try {
        const r = await csFetch('/tenant/' + csTenant() + '/hub-config/reset', { method: 'POST', body: JSON.stringify({}) });
        // Re-render so both cards reflect the reset values (csSetupAutoProvConfigCard
        // + csHubConfigCard reload from /hub-config, which now returns the defaults).
        await csRenderSetupProxmox();
        csPushToast(r, 'Reset to defaults');
    } catch (e) {
        console.error('csResetHubConfig: reset failed', e);
        if (typeof showToast === 'function') showToast('Reset failed: ' + (e.message || e), 'error');
    }
};

// ── GitHub ──────────────────────────────────────────────────────────────────
async function csRenderSetupGithub() {
    csSetToolbar('');
    let cfg = {};
    try { cfg = await csFetch(`/${csTenant()}/settings/github?tenant_id=${csTenant()}`); }
    catch (e) { console.error('csRenderSetupGithub: github config load failed', e); csSet(csErrorBox('Could not load GitHub config', e)); return; }
    cfg = cfg || {};
    const f = (id, label, val, type) => `<label class="text-xs text-slate-500">${csEscape(label)}
      <input id="${id}" ${type === 'password' ? 'type="password"' : `value="${csEscape(val != null ? val : '')}"`} class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></label>`;
    // List branches for the actually-configured repo URL (falls back to the
    // 'cs' module key when no URL is set yet), so the Repo Branch field is a
    // dropdown; degrades to a text field when the remote can't be listed.
    const branches = await csFetchBranches(cfg.repo_url || 'cs');
    const branchField = `<label class="text-xs text-slate-500">Repo Branch${
        _csBranchSelect('cs-gh-branch', cfg.repo_branch, branches, null)}</label>`;
    csSet(`<div class="max-w-2xl space-y-4">
      <div class="hpe-card rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">GitHub ${helpIcon('cs', null, 'Simulations help')}</h3>
        <div class="grid grid-cols-1 gap-3">
          ${f('cs-gh-url', 'Repo URL', cfg.repo_url)}${branchField}
          ${f('cs-gh-token', 'GitHub Token ' + (cfg.has_token ? '(set — leave blank to keep)' : '(new)'), '', 'password')}
        </div>
        <div class="flex gap-2 mt-4">
          <button onclick="csSaveGithub()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save</button>
          <button onclick="csClearGithub()" class="bg-red-100 text-red-700 px-4 py-2 rounded-md text-sm font-bold">Clear</button>
        </div>
      </div></div>`);
}

window.csSaveGithub = async function () {
    const body = {
        repo_url: csEl('cs-gh-url') && csEl('cs-gh-url').value,
        repo_branch: csEl('cs-gh-branch') && csEl('cs-gh-branch').value,
    };
    const tok = csEl('cs-gh-token') && csEl('cs-gh-token').value;
    if (tok) body.github_token = tok;
    try {
        await csFetch(`/${csTenant()}/settings/github?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        showToast('Saved.', 'success');
        csRenderSetupGithub();
    } catch (e) { console.error('csSaveGithub: save failed', e); showToast(e.message, 'error'); }
};

window.csClearGithub = async function () {
    if (!confirm('Clear GitHub config (removes repo + token from the spoke)?')) return;
    try { await csFetch(`/${csTenant()}/settings/github?tenant_id=${csTenant()}`, { method: 'DELETE' }); csRenderSetupGithub(); }
    catch (e) { console.error('csClearGithub: clear failed', e); if (typeof showToast === 'function') showToast('Clear failed: ' + (e.message || e), 'error'); }
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
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Security ${helpIcon('cs', null, 'Simulations help')}</h3>
        <p class="text-xs text-slate-400 mb-3">Governs the spoke's local dashboard auth. LM hub auth is managed separately in LM settings.</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          ${f('cs-sec-timeout', 'Session Timeout (minutes)', cfg.session_timeout_minutes)}
          ${f('cs-sec-provider', 'Auth Provider', cfg.auth_provider)}
        </div>
        <button onclick="csSaveSecurity()" class="mt-4 bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-2 rounded-md text-sm font-bold">Save</button>
      </div></div>`);
}

window.csSaveSecurity = async function () {
    const body = {
        session_timeout_minutes: csEl('cs-sec-timeout') && csEl('cs-sec-timeout').value,
        auth_provider: csEl('cs-sec-provider') && csEl('cs-sec-provider').value,
    };
    try {
        await csFetch(`/${csTenant()}/settings/security?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        showToast('Saved.', 'success');
    } catch (e) { console.error('csSaveSecurity: save failed', e); showToast(e.message, 'error'); }
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
let csVmSelectedSpoke = '';       // spoke_id of the selected host (command routing)
let csVmSelectedHostId = '';      // UNIQUE per-host key for selection — see csVmHostId
// Unique id for a host ROW/pill. Several pxmx agents relayed by ONE cs spoke
// share the same spoke_id, so selecting by spoke_id always resolved to the
// first host (Overview link + Host pills appeared dead / stuck on one host).
// Key on the agent hostname instead (falls back to spoke_id for the legacy
// single-host-per-spoke shape, where spoke_id is already unique).
function csVmHostId(h) {
    return (h && (h.hostname || h.spoke_hostname || h.spoke_id)) || '';
}

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
    let h = csVmHosts.find(x => csVmHostId(x) === csVmSelectedHostId);
    if (!h) h = csVmHosts.find(x => x.spoke_online) || csVmHosts[0] || null;
    if (h) { csVmSelectedHostId = csVmHostId(h); csVmSelectedSpoke = h.spoke_id; }
    return h;
}

/** Host-selector banner shown atop every drill-in child (VMs … API Server). */
function csVmHostBanner() {
    if (!csVmHosts.length) return '';
    const pills = csVmHosts.map(h => {
        const active = csVmHostId(h) === csVmSelectedHostId;
        const cls = active ? 'bg-[#01A982] text-white border-[#01A982]'
                           : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50';
        return `<button onclick="csVmSelectHost('${csEscape(csVmHostId(h))}')"
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
// Rolling 1h CPU/Mem average cell (px.cpu_1h_avg / px.mem_1h_avg) — mirrors the
// original webui server list: value.toFixed(1)% or "—" before samples exist.
// Colored red past 90% / amber past 75% so a loaded host reads at a glance.
function csPctCell(v) {
    if (v == null || v === '') return '<span class="text-slate-400">—</span>';
    const n = Number(v);
    if (!isFinite(n)) return '<span class="text-slate-400">—</span>';
    const cls = n >= 90 ? 'text-red-600 font-semibold'
              : n >= 75 ? 'text-amber-600 font-medium' : 'text-slate-600';
    return `<span class="${cls}" style="font-variant-numeric:tabular-nums">${n.toFixed(1)}%</span>`;
}

// Auto-provisioning status badge for a host, from px.provision (the pxmx agent's
// diagnostic). Shows the throttle + WHAT throttled it (provision_halt.reason +
// the cpu/mem pct vs threshold, or CPU pacing) — copied from the original
// webui's provision_halt badge — else Active / Idle / Off.
function csProvThrottleBadge(px) {
    const prov = (px && px.provision) || {};
    const halt = prov.halt || {};
    const pill = (cls, txt, title) =>
        `<span title="${csEscape(title || '')}" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${cls}">${csEscape(txt)}</span>`;
    // No provision telemetry (a row with no proxmox/agent data) → neutral "—",
    // not a misleading "Active". Active/Idle/Off/throttled are only meaningful
    // once the pxmx agent has actually reported a provision block.
    if (!prov || Object.keys(prov).length === 0)
        return '<span class="text-slate-400">—</span>';
    if (halt.halted) {
        const r = String(halt.reason || '').toLowerCase();
        const n = v => (v == null ? '?' : Number(v).toFixed(0));
        let detail;
        if (r === 'cpu') detail = `CPU ${n(halt.cpu_pct)}% ≥ ${n(halt.cpu_threshold)}%`;
        else if (r === 'mem') detail = `Mem ${n(halt.mem_pct)}% ≥ ${n(halt.mem_threshold)}%`;
        else if (r === 'pacing') detail = `CPU pacing ${n(halt.cpu_pct)}% ≥ ${n(halt.cpu_threshold)}%`;
        else detail = r || 'throttled';
        return pill('bg-red-100 text-red-700', `⏸ ${detail}`, 'Auto-provisioning throttled: ' + detail);
    }
    if (prov.auto_provision_on === false)
        return pill('bg-slate-200 text-slate-500', 'Off', 'Auto-provisioning disabled');
    if (prov.cs_enabled === false)
        return pill('bg-slate-200 text-slate-500', 'No sim', 'Client-simulation mode not enabled on this agent');
    if (prov.loop_running === false)
        return pill('bg-amber-100 text-amber-700', 'Idle', prov.reason || 'Provision loop not running');
    return pill('bg-green-100 text-green-700', 'Active', prov.reason || 'Provisioning active');
}

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
        <div id="cs-autoprov-status" class="mt-2 text-[10px] text-slate-500 space-y-1">Status: loading…</div>
      </div>
    </div>`;

    // Per-server rows as a table — mirrors the pxmx Nodes page (border-b
    // border-slate-100, clickable, hover:bg-slate-50, selected row highlighted
    // with bg-green-50 ring-1 ring-green-300). A table also aligns the stat
    // columns vertically across rows.
    const sel = csVmSelectedHostId;
    // Sort hosts by display name (numeric-aware so …svr-02/-03/-10 order
    // naturally, not lexically). Copy first — don't mutate the loaded array.
    const _hname = h => (h.spoke_name || h.spoke_hostname || h.spoke_id || '');
    const rows = hosts.slice()
        .sort((a, b) => _hname(a).localeCompare(_hname(b), undefined, { numeric: true, sensitivity: 'base' }))
        .map(h => {
        const px = h.proxmox || {};
        const vmN = h.vm_count || (h.proxmox_vms ? h.proxmox_vms.length : 0);
        const usbN = csUsbCount(h);
        const selCls = csVmHostId(h) === sel ? 'bg-green-50 ring-1 ring-green-300' : 'hover:bg-slate-50';
        return `<tr class="border-b border-slate-100 cursor-pointer ${selCls}" onclick="csVmSelectHost('${csEscape(csVmHostId(h))}','VMs')">
          <td class="px-4 py-2"><span class="font-medium text-slate-700">${csEscape(h.spoke_name || h.spoke_hostname || h.spoke_id)}</span></td>
          <td class="px-4 py-2 text-center">${csOnlineBadge(h.spoke_online)}</td>
          <td class="px-4 py-2 text-center">${vmN}</td>
          <td class="px-4 py-2 text-center">${usbN}</td>
          <td class="px-4 py-2 text-center text-xs">${csPctCell(px.cpu_1h_avg)}</td>
          <td class="px-4 py-2 text-center text-xs">${csPctCell(px.mem_1h_avg)}</td>
          <td class="px-4 py-2 text-center">${csProvThrottleBadge(px)}</td>
          <td class="px-4 py-2 text-xs text-slate-600">${csEscape(px.agent_version || '—')}</td>
          <td class="px-4 py-2 text-xs text-slate-600">${csEscape(csPveVersion(px.pve_version))}</td>
        </tr>`;
    }).join('');
    // Header alignment: center the numeric/badge columns (Online…Auto-Prov),
    // left-align Host + the version columns.
    const ths = ['Host', 'Online', 'VMs', 'USB', 'CPU 1h', 'Mem 1h', 'Auto-Prov', 'Agent', 'PVE']
        .map((c, i) => `<th class="px-4 py-2 ${i >= 1 && i <= 6 ? 'text-center' : 'text-left'} font-medium">${c}</th>`).join('');
    const table = `<div class="overflow-x-auto"><table class="w-full text-sm">
      <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${ths}</tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;

    csSet(`<div class="space-y-4">${summary}${fleetCards}${table}</div>`);
    // populate auto-provision status
    csRefreshAutoProvStatus();
}

async function csRefreshAutoProvStatus() {
    const st = csEl('cs-autoprov-status');
    try {
        const s = await csFetch(`/${csTenant()}/usb-provisioning-status?tenant_id=${csTenant()}`);
        const on = String(s.usb_auto_provision || 'off').toLowerCase() === 'on';
        const el = csEl('cs-autoprov-toggle'); if (el) el.checked = on;
        if (!st) return;
        const csCount = Number(s.cs_enabled_agent_count || 0);
        // Primary (freshest host) provision diagnostic — WHY the last pass
        // provisioned nothing (or did), plus the loop liveness heartbeat and the
        // config snapshot so a missing certification/template is visible at a
        // glance instead of grepping the pxmx agent log.
        const sp = (s.spokes || [])[0] || {};
        const prov = (sp && sp.provision) || {};
        const reason = prov.reason ? csEscape(String(prov.reason)) : '—';
        const loopOn = !!prov.loop_running;
        let html = `<div><b>Status:</b> ${on ? 'enabled' : 'disabled'} · ${csEscape(s.usb_auto_provision || 'off')}</div>`;
        html += `<div><b>CS-enabled agents:</b> ${csCount}</div>`;
        // Most common cause of "I enabled Auto-Provisioning but nothing happens":
        // the per-agent Client Simulation flag was never set, so the provision
        // loop never spawns. Surface it explicitly.
        if (on && csCount === 0) {
            html += `<div class="text-amber-600 font-semibold">⚠ Auto-Provisioning is on but no hypervisor agent has Client Simulation mode enabled — enable it on the Hypervisors page (host → "Enable Client Simulation mode on this host").</div>`;
        }
        html += `<div><b>Last pass:</b> ${reason}${loopOn ? '' : ' <span class="text-amber-600">(provision loop not running — check the pxmx agent log)</span>'}</div>`;
        st.innerHTML = html;
    } catch (e) {
        console.error('csRefreshAutoProvStatus: usb-provisioning-status fetch failed (best-effort)', e);
        if (st) st.textContent = 'Status: unavailable';
    }
}

window.csVmSelectHost = function (hostId, child) {
    csVmSelectedHostId = hostId;
    // Derive the spoke_id of the picked host for command routing (several hosts
    // can share one spoke_id; the picked host disambiguates which one is viewed).
    const h = csVmHosts.find(x => csVmHostId(x) === hostId);
    if (h) csVmSelectedSpoke = h.spoke_id;
    if (child) { setSubChild(child); }
    else loadCSData('VM Server', currentSubChild || 'VMs', true);
};

window.csFleetReclone = async function () {
    const conc = csEl('cs-fleet-conc') ? parseInt(csEl('cs-fleet-conc').value, 10) || 1 : 1;
    try {
        await csFetch(`/${csTenant()}/fleet-reclone?tenant_id=${csTenant()}`, {
            method: 'POST', body: JSON.stringify({ concurrency: conc }) });
        if (typeof showToast === 'function') showToast('Fleet reclone started.', 'success');
        csRenderVmServer();
    } catch (e) { console.error('csFleetReclone: fleet reclone failed', e); if (typeof showToast === 'function') showToast('Fleet reclone failed: ' + (e.message || e), 'error'); }
};

window.csToggleAutoProvision = async function (enabled) {
    try {
        const r = await csFetch(`/${csTenant()}/toggle-auto-provision?tenant_id=${csTenant()}`, {
            method: 'POST', body: JSON.stringify({ enabled }) });
        csPushToast(r, enabled ? 'Auto-provisioning enabled' : 'Auto-provisioning disabled');
        csRefreshAutoProvStatus();
    } catch (e) { console.error('csToggleAutoProvision: toggle failed', e); if (typeof showToast === 'function') showToast('Toggle failed: ' + (e.message || e), 'error'); }
};

window.csUpdateAll = async function () {
    try {
        await csFetch(`/${csTenant()}/update-all?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify({}) });
        if (typeof showToast === 'function') showToast('Agent update queued.', 'success');
    } catch (e) { console.error('csUpdateAll: update-all failed', e); if (typeof showToast === 'function') showToast('Update All failed: ' + (e.message || e), 'error'); }
};

// ── VMs (per-host) ──────────────────────────────────────────────────────────
function csVmCategory(v) {
    // The agent stamps is_template (Proxmox ``template: 1`` flag / name / tag
    // heuristics) on every VM; a template's ``type`` is still ``qemu``, so
    // checking type alone misfiles templates as 'Other'. Honor the flag first.
    if (v.is_template) return 'Templates';
    const t = String(v.type || '').toLowerCase();
    const name = String(v.name || '').toLowerCase();
    if (t === 'template' || name.includes('template')) return 'Templates';
    if (t === 'lxc' || t === 'container') return 'Containers';
    // Prefer VMID over the display name: the auto-provisioning "realistic
    // hostname" feature (vm_names.json, e.g. vmid 90025 -> "kbell") means a
    // sim-managed VM's name often does NOT start with "sim-" or contain
    // "client" at all, so a name-only check misfiled every custom-named sim
    // client into 'Other'. 90000 is the sim-managed floor used everywhere
    // else in the stack (pxmx cs_guard.SIM_VMIN / assert_sim_vm), so treat
    // it as the primary signal and keep the name check only as a fallback
    // for anything below that floor.
    const vmid = parseInt(v.vmid, 10);
    if ((!isNaN(vmid) && vmid >= 90000) || name.startsWith('sim-') || name.includes('client')) {
        return 'Simulation Clients';
    }
    return 'Other';
}

async function csRenderVmServerVms() {
    csSetToolbar('');
    let hosts;
    try { hosts = await csVmLoad(); }
    catch (e) { console.error('csRenderVmServerVms: vm load failed', e); csSet(csErrorBox('Could not load VMs', e)); return; }
    // csVmLoad() above is the slow part of a refresh cycle. csWsRefresh's own
    // csUserIsEditing() guard only runs BEFORE this fetch starts, so a
    // checkbox checked WHILE it's in flight still slips through and gets
    // wiped when the table below replaces the DOM. Re-check right after the
    // await, before touching anything, so a race here bails out the same way
    // the pre-fetch guard does — the next telemetry pulse retries once the
    // user is done (matches csWsRefresh's own comment).
    if (csUserIsEditing()) return;
    const h = csVmSelectedHost();
    if (!h) { csSet(csEmpty('No host selected.')); return; }
    const vms = h.proxmox_vms || [];
    // Join the missing-dongle shed deadline (proxmox.usb_state[].shed_at) onto
    // each VM by vmid so the row's status badge can show a live "Sheds in
    // MM:SS" countdown for a VM whose dongle was removed (teardown pending).
    const _usbState = (h.proxmox && h.proxmox.usb_state) || h.usb_state || [];
    const _shedByVmid = {};
    _usbState.forEach(u => { if (u && u.shed_at && u.vmid != null) _shedByVmid[String(u.vmid)] = u.shed_at; });
    vms.forEach(v => { v._shed_at = _shedByVmid[String(v.vmid)] || null; });
    csStartShedTicker();
    const cats = ['Simulation Clients', 'Other', 'Containers', 'Templates'];
    const grouped = {};
    cats.forEach(c => grouped[c] = vms.filter(v => csVmCategory(v) === c));
    const tabs = cats.map((c, i) => `<button onclick="csVmVmsTab('${c}')" id="cs-vmtab-${csEscape(c)}" class="px-3 py-1.5 rounded-md text-xs font-bold ${i === 0 ? 'bg-[#01A982] text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}">${csEscape(c)} <span class="opacity-60">(${grouped[c].length})</span></button>`).join('');
    const rows = (grouped['Simulation Clients'] || []).map(csVmRow).join('');
    csSet(`<div>${csVmHostBanner()}${csAutoProvPanel(h)}${tabs}
      <div class="flex items-center gap-2 my-3 text-xs text-slate-500">
        <button onclick="csVmBulk('start_vm')" class="bg-green-100 text-green-700 px-2 py-1 rounded font-bold">Start</button>
        <button onclick="csVmBulk('stop_vm')" class="bg-amber-100 text-amber-700 px-2 py-1 rounded font-bold">Stop</button>
        <button onclick="csVmBulk('reboot_vm')" class="bg-slate-200 text-slate-700 px-2 py-1 rounded font-bold">Reboot</button>
        <button onclick="csVmBulk('reclone_vm')" class="bg-blue-100 text-blue-700 px-2 py-1 rounded font-bold">Reclone</button>
        <button onclick="csVmBulk('delete_vm')" class="bg-red-100 text-red-700 px-2 py-1 rounded font-bold">Delete</button>
      </div>
      <div id="cs-vm-list">${csVmTable(rows)}</div>
    </div>`);
    window._csVmGrouped = grouped;
    window._csVmByVmid = {};
    vms.forEach(v => { window._csVmByVmid[v.vmid] = v; });
}

const CS_VM_TABLE_HEADERS = ['VMID', 'Name', 'Type', 'Status', 'Actions'];
const CS_VM_TABLE_HEADER_HTML = [
    '<label class="inline-flex items-center gap-1.5 cursor-pointer"><input type="checkbox" id="cs-vm-selectall" onchange="csVmSelectAll(this.checked)"/> VMID</label>',
];
function csVmTable(rows) {
    return csTable(CS_VM_TABLE_HEADERS, rows, {id: 'cs-vm-table', headerHtml: CS_VM_TABLE_HEADER_HTML});
}

// Toggles every visible row checkbox (the current category tab only — matches
// what the bulk actions above already operate on) and keeps its own state in
// sync when a row is (de)selected individually.
window.csVmSelectAll = function (checked) {
    document.querySelectorAll('.cs-vm-sel').forEach(cb => { cb.checked = checked; });
};
window.csVmSelUpdateHeader = function () {
    const boxes = Array.from(document.querySelectorAll('.cs-vm-sel'));
    const header = csEl('cs-vm-selectall');
    if (header) header.checked = boxes.length > 0 && boxes.every(cb => cb.checked);
};

// ── Live auto-provisioning status (ported from solutions-hpe/cs-webui) ───────
// Per-VM transient state for the VM list: the pxmx agent stamps prov_status
// ('provisioning'/'tearing_down') + pending_checkin onto each VM (relayed via
// the cs spoke ingest). 🔴 deleting wins over 🔵 provisioning wins over the
// steady running/paused/stopped state.
// Format a seconds duration as "Hh Mm" (>=1h) or "M:SS" for the shed countdown.
function csFmtDuration(s) {
    s = Math.max(0, Math.round(Number(s) || 0));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h > 0 ? `${h}h ${m}m` : `${m}:${String(sec).padStart(2, '0')}`;
}

// Single 1s ticker that updates every .cs-shed-countdown span from its absolute
// data-shed-at (agent epoch; assumes NTP-synced clocks). Idempotent — the VM
// list re-renders on each telemetry pulse with fresh spans; the ticker keeps
// counting them down between pulses so the timer is live, not stepwise.
function csStartShedTicker() {
    if (window._csShedTicker) return;
    window._csShedTicker = setInterval(() => {
        const now = Date.now() / 1000;
        document.querySelectorAll('.cs-shed-countdown').forEach(el => {
            const at = Number(el.getAttribute('data-shed-at'));
            const secs = at - now;
            el.textContent = secs <= 0 ? 'now' : csFmtDuration(secs);
        });
    }, 1000);
}

// Badge for a VM whose dongle was removed and is counting down to teardown.
function csShedBadge(v) {
    if (!v || !v._shed_at) return '';
    const secs = Number(v._shed_at) - Date.now() / 1000;
    if (secs <= 0) return '';
    return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-orange-100 text-orange-700" title="Dongle removed — VM will be shed when the missing-dongle timer expires">`
        + `<span class="w-1.5 h-1.5 rounded-full bg-orange-500 animate-pulse"></span>🔌 Sheds in `
        + `<span class="cs-shed-countdown" data-shed-at="${Number(v._shed_at)}">${csFmtDuration(secs)}</span></span>`;
}

function csVmStatusBadge(v) {
    const ps = String(v.prov_status || '').toLowerCase();
    if (ps === 'tearing_down') {
        return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700"><span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>Deleting…</span>`;
    }
    // Missing-dongle shed countdown wins over the steady status (it's imminent).
    const shed = csShedBadge(v);
    if (shed) return shed;
    if (ps === 'provisioning' || v.pending_checkin === true) {
        const label = (String(v.status || '').toLowerCase() === 'running') ? 'Configuring' : 'Provisioning';
        return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-sky-100 text-sky-700"><span class="w-1.5 h-1.5 rounded-full bg-sky-500 animate-pulse"></span>${label}</span>`;
    }
    return csStatusBadge(v.status || 'unknown');
}

function csAutoProvPhaseMeta(status) {
    switch (String(status || '').toLowerCase()) {
        case 'cloning':
        case 'provisioning':    return { label: 'Cloning', cls: 'bg-sky-100 text-sky-700' };
        case 'configuring':     return { label: 'Configuring', cls: 'bg-cyan-100 text-cyan-700' };
        case 'pending_checkin': return { label: 'Waiting for check-in', cls: 'bg-cyan-100 text-cyan-700' };
        case 'done':            return { label: 'Done', cls: 'bg-green-100 text-green-700' };
        case 'failed':          return { label: 'Failed', cls: 'bg-red-100 text-red-700' };
        default:                return { label: 'Pending', cls: 'bg-slate-100 text-slate-500' };
    }
}

// Normalize the live run into {running,total,completed,failed,items[]}. Prefer
// the authoritative prov_run the agent emits; otherwise derive it from per-VM
// prov_status/pending_checkin (so the feed still works on older agents).
function csAutoProvRunState(px, vms) {
    const run = px && px.prov_run;
    if (run && Array.isArray(run.items) && run.items.length) {
        const items = run.items
            .filter(it => it && it.vmid != null)
            .map(it => ({ vmid: it.vmid, vm_name: it.vm_name || null, bus: it.bus || null,
                          status: String(it.status || 'pending').toLowerCase() }));
        return {
            running: Boolean(run.running),
            total: Number.isFinite(+run.total) ? +run.total : items.length,
            completed: Number.isFinite(+run.completed) ? +run.completed : items.filter(i => i.status === 'done').length,
            failed: Number.isFinite(+run.failed) ? +run.failed : items.filter(i => i.status === 'failed').length,
            startedAt: run.started_at || null,
            items,
        };
    }
    const provItems = (vms || [])
        .filter(v => String(v.prov_status || '').toLowerCase() === 'provisioning')
        .map(v => ({ vmid: v.vmid, vm_name: v.name || null, bus: null,
                     status: String(v.status || '').toLowerCase() === 'running' ? 'configuring' : 'cloning' }));
    const pendItems = (vms || [])
        .filter(v => v.pending_checkin === true && String(v.prov_status || '').toLowerCase() !== 'provisioning')
        .map(v => ({ vmid: v.vmid, vm_name: v.name || null, bus: null, status: 'pending_checkin' }));
    const items = [...provItems, ...pendItems];
    return { running: items.length > 0, total: items.length, completed: 0, failed: 0, startedAt: null, items };
}

// The live status tile mounted above the VM list — a status pill (Off / Idle /
// Provisioning… X/Y / Deleting N), a progress bar, and a per-VM phase feed.
function csAutoProvPanel(h) {
    const px = (h && h.proxmox) || {};
    const vms = (h && h.proxmox_vms) || [];
    const prov = px.provision || {};
    const autoOn = prov.auto_provision_on === true || String(prov.auto_provision_on || '').toLowerCase() === 'on';
    const run = csAutoProvRunState(px, vms);
    const deleting = vms.filter(v => String(v.prov_status || '').toLowerCase() === 'tearing_down');
    const active = run.running && run.total > 0;
    const halt = prov.halt || null;

    let pill;
    if (deleting.length) {
        pill = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-50 text-red-700 text-xs font-bold"><span class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>Deleting ${deleting.length} VM${deleting.length > 1 ? 's' : ''}…</span>`;
    } else if (active) {
        const bits = [`Provisioning… ${Math.min(run.completed, run.total)}/${run.total}`];
        if (run.failed) bits.push(`${run.failed} failed`);
        pill = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-50 text-sky-700 text-xs font-bold"><span class="animate-spin w-3 h-3 rounded-full border-2 border-sky-500 border-t-transparent"></span>${bits.join(' · ')}</span>`;
    } else if (!autoOn) {
        pill = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 text-slate-500 text-xs font-bold"><span class="w-2 h-2 rounded-full bg-slate-400"></span>Auto-Provisioning: Off</span>`;
    } else {
        pill = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 text-xs font-bold"><span class="w-2 h-2 rounded-full bg-slate-400"></span>Auto-Provisioning: Idle</span>`;
    }

    // Idle + nothing deleting → compact pill + last-pass reason only.
    if (!active && !deleting.length) {
        const reason = prov.reason ? `<span class="text-xs text-slate-400 truncate">${csEscape(prov.reason)}</span>` : '';
        return `<div class="hpe-card rounded-lg p-3 mb-3 flex items-center justify-between gap-3">${pill}${reason}</div>`;
    }

    const pct = run.total > 0 ? Math.round((Math.min(run.completed, run.total) / run.total) * 100) : 0;
    const feedItems = [
        ...deleting.map(v => ({ vmid: v.vmid, vm_name: v.name, bus: null, status: 'deleting' })),
        ...run.items.filter(i => i.status !== 'done'),
    ];
    const feed = feedItems.map(it => {
        const meta = it.status === 'deleting'
            ? { label: 'Deleting', cls: 'bg-red-100 text-red-700' }
            : csAutoProvPhaseMeta(it.status);
        const name = it.vm_name || (it.vmid != null ? `VM ${it.vmid}` : (it.bus ? `Bus ${it.bus}` : 'Slot —'));
        return `<div class="flex items-center justify-between gap-2 py-1 border-b border-slate-100 last:border-0">
            <span class="text-xs font-mono text-slate-600 truncate">${csEscape(name)}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${meta.cls}">${meta.label}</span>
        </div>`;
    }).join('') || `<div class="text-xs text-slate-400 py-1">No active items.</div>`;

    const haltLine = (halt && halt.reason)
        ? `<div class="text-[11px] text-amber-600 mt-2">⏸ Paused — ${csEscape(halt.reason)} (CPU ${halt.cpu_pct}% ≥ ${halt.cpu_threshold}%, Mem ${halt.mem_pct}% ≥ ${halt.mem_threshold}%)</div>`
        : '';

    return `<div class="hpe-card rounded-lg p-4 mb-3">
        <div class="flex items-center justify-between gap-3 mb-2">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">VM Auto-Provisioning</h3>
            ${pill}
        </div>
        ${active ? `<div class="flex items-center justify-between text-xs text-slate-500 mb-1"><span>${Math.min(run.completed, run.total)} of ${run.total} complete${run.failed ? ` · ${run.failed} failed` : ''}</span><span>${pct}%</span></div>
        <div class="h-2 rounded-full bg-slate-100 overflow-hidden mb-2"><div class="h-full bg-gradient-to-r from-[#01A982] to-sky-400" style="width:${pct}%"></div></div>` : ''}
        <div class="max-h-48 overflow-y-auto">${feed}</div>
        ${haltLine}
    </div>`;
}

function csVmRow(v) {
    const vid = csEscape(v.vmid);
    // Disable actions on a VM that's being torn down — it's about to vanish.
    const busy = String(v.prov_status || '').toLowerCase() === 'tearing_down';
    const act = (label, action, cls) => busy
        ? `<button disabled title="VM is being deleted" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-300 cursor-not-allowed">${label}</button>`
        : `<button onclick="csVmAction(${v.vmid},'${action}')" class="px-2 py-0.5 rounded text-[10px] font-bold ${cls}">${label}</button>`;
    return `<tr>
      <td class="px-3 py-2 font-mono text-xs"><input type="checkbox" class="cs-vm-sel" data-vmid="${vid}" onchange="csVmSelUpdateHeader()"/> ${vid}</td>
      <td class="px-3 py-2 text-sm">${csEscape(v.name || '—')}</td>
      <td class="px-3 py-2 text-slate-500">${csEscape(v.is_template ? 'template' : (v.type || '—'))}</td>
      <td class="px-3 py-2">${csVmStatusBadge(v)}</td>
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
    if (list) list.innerHTML = csVmTable(rows);
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
    // Before destroying a VM, expire in-flight commands for its host so a
    // queued start/reclone doesn't fire against a gone VM (best-effort).
    if (action === 'delete_vm') await csExpirePendingForTarget();
    try {
        await csFetch(`/${csTenant()}/spokes/${sid}/proxmox-command?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ action, args }) });
        csVmFlash(action + ' queued');
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 800);
    } catch (e) { console.error('csVmAction: ' + action + ' failed', e); if (typeof showToast === 'function') showToast(action + ' failed: ' + (e.message || e), 'error'); }
};

window.csVmBulk = async function (action) {
    const ids = Array.from(document.querySelectorAll('.cs-vm-sel:checked')).map(c => c.dataset.vmid);
    if (!ids.length) { if (typeof showToast === 'function') showToast('Select one or more VMs first.', 'info'); return; }
    if (action === 'delete_vm') await csExpirePendingForTarget();
    try {
        // Bounded concurrency (4 at a time) instead of a sequential await per
        // VM — a 24-VM bulk action previously issued 24 back-to-back round
        // trips; chunked Promise.all keeps the same fail-fast semantics
        // (first error rejects the chunk) while cutting wall-clock to ~N/4.
        const buildReq = (vmid) => {
            const v = (window._csVmByVmid && window._csVmByVmid[vmid]) || {};
            const args = { vmid: Number(vmid) };
            if (v.type) args.vm_type = v.type;
            return csFetch(`/${csTenant()}/spokes/${encodeURIComponent(csVmSelectedSpoke)}/proxmox-command?tenant_id=${csTenant()}`,
                { method: 'POST', body: JSON.stringify({ action, args }) });
        };
        const CHUNK = 4;
        for (let i = 0; i < ids.length; i += CHUNK) {
            await Promise.all(ids.slice(i, i + CHUNK).map(buildReq));
        }
        csVmFlash(`${action} queued for ${ids.length} VM(s)`);
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 1000);
    } catch (e) { console.error('csVmBulk: ' + action + ' bulk failed', e); if (typeof showToast === 'function') showToast(action + ' bulk failed: ' + (e.message || e), 'error'); }
};

// Best-effort expiry of in-flight commands for the selected proxmox host before
// a VM teardown. Swallowed on failure — the delete still proceeds.
async function csExpirePendingForTarget() {
    const host = (typeof csVmSelectedHost === 'function' && csVmSelectedHost()) || 'proxmox';
    try {
        await csFetch(`/${csTenant()}/proxmx/commands/pending?target=${encodeURIComponent(host)}&tenant_id=${csTenant()}`,
            { method: 'DELETE' });
    } catch (e) { console.warn('csExpirePendingForTarget: best-effort expiry failed', e); }
}

function csVmFlash(msg) {
    if (typeof showToast === 'function') showToast(msg, 'success');
}

// ── Console / Terminal (Phase-5 stubs, faithful to current LM state) ───────
function csRenderVmServerConsoleStub(label, kind) {
    csSetToolbar('');
    csSet(`<div>${csVmHostBanner()}
      <div class="hpe-card rounded-lg p-10 shadow-sm text-center">
        <div class="text-3xl mb-3">${kind === 'console' ? '🖥️' : '⌨️'}</div>
        <h3 class="text-lg font-bold text-slate-700 mb-1">${csEscape(label)} ${helpIcon('cs', null, 'Simulations help')}</h3>
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
                if (typeof showToast === 'function') showToast('Select a type (wired or wireless) before certifying.', 'info');
                return;
            }
            body.type = t;
        }
        await csFetch(`/${csTenant()}/usb-vidpids?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        csVmFlash(action + ' queued for ' + vid + ':' + pid);
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 800);
    } catch (e) { console.error('csUsbVidpid: usb action failed', e); if (typeof showToast === 'function') showToast('USB action failed: ' + (e.message || e), 'error'); }
};

// Per-row Certify from the Uncertified table: reads the row's type <select>
// (empty "—" → block with an alert) and forwards to csUsbVidpid.
window.csUsbCertifyRow = async function (btn, vid, pid) {
    const cell = btn.closest('td');
    const sel = cell && cell.querySelector('.cs-usb-row-type');
    const type = sel ? sel.value : '';
    if (!type) { if (typeof showToast === 'function') showToast('Select a type (wired or wireless) before certifying.', 'info'); return; }
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
      <td class="px-3 py-2"><button data-cs-cmd-id="${csEscape(c.id || '')}" onclick="csCmdDelete(this)"
        class="bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded-md text-[11px] font-bold">Delete</button></td>
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
      ${csTable(['ID', 'Action', 'Target', 'Status', 'Age', 'Message', 'Actions'], rows)}
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
    } catch (e) { console.error('csSendCommand: send failed', e); if (typeof showToast === 'function') showToast('Send failed: ' + (e.message || e), 'error'); }
};

window.csClearCommands = async function () {
    if (!confirm('Clear all pending/delivered commands?')) return;
    try {
        await csFetch(`/${csTenant()}/proxmx/commands?tenant_id=${csTenant()}`, { method: 'DELETE' });
        csRenderVmServerQueue();
    } catch (e) { console.error('csClearCommands: clear failed', e); if (typeof showToast === 'function') showToast('Clear failed: ' + (e.message || e), 'error'); }
};

window.csCmdDelete = async function (btn) {
    const id = btn.dataset.csCmdId;
    if (!id) return;
    if (!confirm('Delete this command?')) return;
    try {
        await csFetch(`/${csTenant()}/proxmx/commands/${encodeURIComponent(id)}?tenant_id=${csTenant()}`, { method: 'DELETE' });
        csRenderVmServerQueue();
    } catch (e) { console.error('csCmdDelete: delete failed', e); if (typeof showToast === 'function') showToast('Delete failed: ' + (e.message || e), 'error'); }
};

// ── Details (node header + headline stats + telemetry tile grid + raw dump) ─
async function csRenderVmServerDetails() {
    csSetToolbar('');
    try { await csVmLoad(); } catch (e) { console.error('csRenderVmServerDetails: vm load failed', e); csSet(csErrorBox('Could not load details', e)); return; }
    const h = csVmSelectedHost();
    if (!h) { csSet(csEmpty('No host selected.')); return; }
    const px = h.proxmox || {};
    const node = px.node || {};
    // usb_count is the ASSIGNED-dongle subset (len(usb_state)) — it undercounts
    // and reads 0 when no dongle is assigned, so hide it from the telemetry grid.
    // The headline USB stat below uses csUsbCount (present+unknown = physical
    // dongles), the same source as the Overview per-host row + USB view.
    // `provision` is pulled out of the generic grid and rendered LAST as its
    // own full-width card (csProvisionCard) — it's a nested object that wraps
    // badly as a raw csKvTile and deserves a readable layout.
    const skip = ['vms','usb_state','present_usb','unknown_usb','node','usb_count','provision'];
    const entries = Object.entries(px).filter(([k]) => !skip.includes(k));
    // Pretty-print a few well-known keys instead of their raw form: pve_version
    // arrives as "pve-manager/9.2.3/abc123" (strip to 9.2.3 via csPveVersion) and
    // last_seen as a fractional epoch (→ local datetime via csLastSeen).
    const fmt = (k, v) => {
        if (k === 'pve_version') return csKvTile(k, csPveVersion(v));
        if (k === 'last_seen') return csKvTile(k, csLastSeen(v));
        return csKvTile(k, v);
    };
    const tiles = entries.map(([k, v]) => fmt(k, v)).join('');
    csSet(`<div>${csVmHostBanner()}
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
        ${csStat('Node', node.hostname || '—')}${csStat('USB', csUsbCount(h))}
        ${csStat('CPU 1h', px.cpu_1h_avg || '—')}${csStat('Mem 1h', px.mem_1h_avg || '—')}
        ${csStat('Agent', px.agent_version || '—')}
      </div>
      <div class="flex items-center justify-between mb-2">
        <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Telemetry</p>
        <span class="text-[10px] text-slate-400">${entries.length} field${entries.length === 1 ? '' : 's'}</span>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">${tiles}</div>
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-4 mb-2">Auto-Provisioning</p>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">${csProvisionCard(px)}</div>
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
window.CS_CHILD_RENDERERS['Clients::T3']  = function () { return csRenderClients('t3'); };

window.csOpenVmConsole = function (spokeId) {
    if (typeof showToast === 'function') showToast(`VM console for ${spokeId} is wired in Phase 5 (noVNC over /sim/ws/console/{sessionId}).`, 'info');
};
window.csOpenSpokeShell = function (spokeId) {
    if (typeof showToast === 'function') showToast(`Spoke shell for ${spokeId} is wired in Phase 5 (xterm.js over /sim/api/{tenant}/spokes/{spoke}/shell).`, 'info');
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

    // Two <tr>s per spoke (data row + a full-width actions row underneath) so
    // the 6 admin action buttons get their own line instead of being crammed
    // into a narrow trailing "Actions" cell, which forced them to wrap. Both
    // rows share the same class + data-cs-* attributes so csSpokeFilter's
    // search hides/shows the pair together.
    window._csSpokeRowHtml = function (s) {
        const isPending = !s.approved;
        const assignBtn = admin
            ? `<button onclick="openSpokeAssignModal('${csEscape(s.spoke_id)}','${csEscape(s.tenant_id || '')}')" class="text-xs text-[#01A982] font-bold hover:underline whitespace-nowrap">${!s.tenant_id ? 'Assign' : 'Rebind'}</button>`
            : '';
        const approveBtn = admin
            ? `<button onclick="csSpokeApprove('${csEscape(s.spoke_id)}',${isPending ? 'true' : 'false'})" class="text-xs ${isPending ? 'text-green-600 font-bold' : 'text-amber-600'} hover:underline whitespace-nowrap">${isPending ? 'Approve' : 'Revoke'}</button>`
            : '';
        const labelBtn = admin
            ? `<button onclick="csSpokeEditLabel('${csEscape(s.spoke_id)}','${csEscape((s.display_name || s.spoke_id || '').replace(/'/g, "\\'"))}')" class="text-xs text-slate-500 hover:underline whitespace-nowrap">Label</button>`
            : '';
        const cfgBtn = admin
            ? `<button onclick="csSpokePatchConfig('${csEscape(s.spoke_id)}')" class="text-xs text-slate-500 hover:underline whitespace-nowrap">Config</button>`
            : '';
        const diagBtn = admin
            ? `<button onclick="csSpokeDiag('${csEscape(s.spoke_id)}')" class="text-xs text-slate-500 hover:underline whitespace-nowrap">Diag</button>`
            : '';
        const delBtn = admin
            ? `<button onclick="csSpokeDelete('${csEscape(s.spoke_id)}')" class="text-xs text-red-500 hover:underline whitespace-nowrap">Delete</button>`
            : '';
        const actions = admin
            ? `<div class="flex flex-wrap items-center gap-4">${assignBtn}${approveBtn}${labelBtn}${cfgBtn}${diagBtn}${delBtn}</div>`
            : '<span class="text-slate-300">—</span>';
        const dataAttrs = `data-cs-spoke="${csEscape(s.spoke_id).toLowerCase()}" data-cs-name="${csEscape((s.display_name || s.spoke_id || '').toLowerCase())}"`;
        return `<tr class="cs-spoke-row" ${dataAttrs}>
          <td class="px-3 pt-2 pb-1 font-mono text-xs whitespace-nowrap">${csEscape(s.spoke_id)}</td>
          <td class="px-3 pt-2 pb-1 text-sm whitespace-nowrap">${csEscape(s.display_name || s.spoke_id)}</td>
          <td class="px-3 pt-2 pb-1 whitespace-nowrap">${typeBadge(s.module_type)}</td>
          <td class="px-3 pt-2 pb-1 whitespace-nowrap">${csOnlineBadge(s.connected)}</td>
          <td class="px-3 pt-2 pb-1 whitespace-nowrap">${s.approved ? '<span class="text-green-600 text-xs font-bold">Approved</span>' : '<span class="text-amber-600 text-xs font-bold">Pending</span>'}</td>
          <td class="px-3 pt-2 pb-1 text-xs whitespace-nowrap">${tenantCell(s.tenant_id)}</td>
          <td class="px-3 pt-2 pb-1 text-xs text-slate-500 whitespace-nowrap">${(s.vm_count != null) ? s.vm_count : '—'}</td>
        </tr>
        <tr class="cs-spoke-row" ${dataAttrs}>
          <td class="px-3 pt-0 pb-2.5" colspan="7">${actions}</td>
        </tr>`;
    };

    const rows = spokes.map(window._csSpokeRowHtml).join('');
    const spokesCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex justify-between items-center mb-3">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spokes ${helpIcon('cs', null, 'Simulations help')}</h3>
        <span class="text-xs text-slate-400">${admin ? 'All tenants (admin)' : 'Tenant: ' + csEscape(tenant)}</span>
      </div>
      ${csTable(['Spoke ID', 'Name', 'Type', 'State', 'Approval', 'Tenant', 'VMs'], rows)}
    </div>`;

    const claimCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Claim a Pending Simulation Spoke ${helpIcon('cs', null, 'Simulations help')}</h3>
      <p class="text-[11px] text-slate-400 mb-3">If a <b>Simulation</b> spoke connected <em>without</em> a PSK it lands as pending. Enter its Spoke ID and this tenant's onboarding PSK to approve + bind it to <span class="font-mono">${csEscape(tenant)}</span>. Only Simulation (Client-Sim) spokes can be claimed here.</p>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <input id="cs-claim-id" placeholder="spoke-id" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono">
        <input id="cs-claim-psk" placeholder="onboarding PSK" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono">
        <button onclick="csClaimSpoke()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold shadow-sm">Claim</button>
      </div>
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
        csPushToast(r, 'Config pushed');
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
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Onboarding PSK <span class="text-slate-400 normal-case font-normal">· tenant ${csEscape(tenant)}</span> ${helpIcon('cs', null, 'Simulations help')}</h3>
        <button onclick="csSpokeMgmtGenPsk()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-1.5 rounded-md text-xs font-bold shadow-sm">+ Generate</button>
      </div>
      ${psks.length ? csTable(['PSK', ''], rows) : '<p class="text-xs text-slate-400 italic py-4 text-center">No PSKs issued.</p>'}
      ${deploy}
    </div>`;
}

window.csSpokeMgmtGenPsk = async function () {
    try { await csFetch('/tenant/' + csTenant() + '/onboarding-psk', { method: 'POST', body: '{}' }); await csRenderSpokeManagement(); }
    catch (e) { console.error('csSpokeMgmtGenPsk: psk generate failed', e); showToast(e.message, 'error'); }
};

window.csSpokeMgmtRevokePsk = async function (psk) {
    try { await csFetch('/tenant/' + csTenant() + '/onboarding-psk', { method: 'DELETE', body: JSON.stringify({ psk }) }); await csRenderSpokeManagement(); }
    catch (e) { console.error('csSpokeMgmtRevokePsk: psk revoke failed', e); showToast(e.message, 'error'); }
};

window.csClaimSpoke = async function () {
    const spokeId = ((csEl('cs-claim-id') && csEl('cs-claim-id').value) || '').trim();
    const psk = ((csEl('cs-claim-psk') && csEl('cs-claim-psk').value) || '').trim();
    if (!spokeId || !psk) {
        showToast('Spoke ID and PSK are required.', 'error');
        return;
    }
    try {
        await csFetch('/tenant/' + csTenant() + '/spokes/' + encodeURIComponent(spokeId) + '/claim?tenant_id=' + csTenant(),
            { method: 'POST', body: JSON.stringify({ onboarding_psk: psk }) });
        showToast('Claimed — spoke approved + bound.', 'success');
        await csRenderSpokeManagement();
    } catch (e) {
        console.error('csClaimSpoke: claim failed', e);
        const m = (e && e.message) ? e.message : String(e);
        showToast('Claim failed: ' + m, 'error');
    }
};

})();