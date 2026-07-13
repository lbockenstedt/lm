/* ============================================================================
 * sim-views.js — Native Client-Sim (Simulations) views for the LM hub.
 *
 * Replaces the former <iframe src="/sim"> integration. The 7 Simulations
 * sub-nav tabs (Simulations / Clients / Central / VM Server /
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
// Last-good cache of successful GET reads (url -> response), so a protect-shed
// 503 serves stale data instead of blanking the Simulations view.
const _csLastGood = {};
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
    // Hub PROTECTING (503, /sim + /aggregate are shed under protect): serve the
    // last-good cached response for this GET so the Simulations view shows STALE
    // data instead of blanking with a "backing off" error. Reads only — a
    // mutation still surfaces the 503 so the operator knows it didn't apply.
    const _method = (opts.method || 'GET').toUpperCase();
    if (res.status === 503 && _method === 'GET' && _csLastGood[url] !== undefined) {
        window.__csServingStale = true;
        return _csLastGood[url];
    }
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
    const _data = ct.includes('application/json') ? await res.json() : await res.text();
    // Cache successful GET reads so a subsequent protect-shed (503) can serve the
    // last-good instead of blanking the view. Bounded by the (small) set of sim URLs.
    if (_method === 'GET') { _csLastGood[url] = _data; window.__csServingStale = false; }
    return _data;
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

// Backpressure badge for a spoke tile (and, contextually, the clients it owns).
// Reads the hub's per-spoke throttle level from the shared status metrics stash
// (window.__lmHubMetrics, populated by main.js updateStatus). Defensive: returns
// '' when metrics aren't present (e.g. the standalone cs spoke WebUI) or the
// spoke isn't throttled. level 1 = offending, 2 = fleet-throttled.
function csThrottleBadge(spokeId) {
    try {
        const bp = (window.__lmHubMetrics || {}).backpressure || {};
        const lvl = (bp.spoke_levels || {})[spokeId] || 0;
        if (lvl === 1) return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-100 text-red-700 text-[10px] font-bold uppercase tracking-wider animate-pulse" title="Offending — over its message rate; coalescing updates locally at the hub's request">⚠ Offending</span>`;
        if (lvl >= 2) return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-orange-100 text-orange-700 text-[10px] font-bold uppercase tracking-wider" title="Throttled — fleet-wide slow-down active; coalescing updates locally">⏳ Throttled</span>`;
    } catch (e) { /* metrics not available — no badge */ }
    return '';
}

function csStatusBadge(status) {
    const s = String(status || 'unknown').toLowerCase();
    const map = {
        pass: 'bg-green-100 text-green-700', ok: 'bg-green-100 text-green-700', functional: 'bg-green-100 text-green-700',
        fail: 'bg-red-100 text-red-700', failed: 'bg-red-100 text-red-700',
        error: 'bg-red-100 text-red-700', critical: 'bg-red-100 text-red-700', down: 'bg-red-100 text-red-700',
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
    // opts.colWidths: optional array (same length as headers) of CSS widths
    // (e.g. '180px' / '7rem') emitted as a <colgroup> so wide tables (the
    // 11-column Clients table) get tunable per-column widths instead of auto.
    const rawHeaders = opts.headerHtml || [];
    const ths = headers.map((h, i) => `<th class="px-4 py-2 text-left font-semibold">${rawHeaders[i] || csEscape(h)}</th>`).join('');
    const colWidths = opts.colWidths;
    const colgroup = (Array.isArray(colWidths) && colWidths.length)
        ? `<colgroup>${colWidths.map(w => `<col style="width:${csEscape(String(w))}">`).join('')}</colgroup>`
        : '';
    return `<div class="overflow-x-auto">
      <table class="w-full text-sm">
        ${colgroup}
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

// Auto-refresh throttle knob — the minimum gap (seconds) between telemetry-
// driven re-renders. csWsRefresh fires on EVERY telemetry/aruba frame the cs
// WebSocket receives; with multiple cs spokes each relaying ~10-15s plus aruba
// updates, frames arrive every few seconds, so without a throttle the page
// re-renders far faster than the "15s" the per-spoke relay cadence implies.
// This gate coalesces that frame storm to at most one re-render per gap.
//   -1 = auto-refresh OFF (manual Refresh / tab switch only)
//    0 = no throttle (refresh on every debounced pulse — the legacy behavior)
//   >0 = min seconds between telemetry-driven re-renders
// Persisted in localStorage (cs_auto_refresh_gap_s) so it survives reloads.
// Default OFF (-1): telemetry-driven auto-refresh is opt-in. The cs WebSocket
// pushes a frame every few seconds (multi-spoke + aruba), so a default-on
// refresh re-renders the page out from under the user far too often. Users
// who want live updates pick a gap from the Auto-refresh select; the manual
// ↻ Refresh button always works regardless.
const CS_AUTOREFRESH_KEY = 'cs_auto_refresh_gap_s';
const CS_AUTOREFRESH_DEFAULT = -1;
let csAutoRefreshGapS = CS_AUTOREFRESH_DEFAULT;
let csLastAutoRefreshAt = 0;
try {
    const _v = parseInt(localStorage.getItem(CS_AUTOREFRESH_KEY), 10);
    if (!isNaN(_v)) csAutoRefreshGapS = _v;
} catch (e) { /* localStorage unavailable — keep default */ }
function csAutoRefreshOpts() {
    return [['-1', 'Off'], ['5', '5s'], ['15', '15s'],
            ['30', '30s'], ['60', '60s'], ['0', 'No throttle']];
}
function csSetAutoRefreshGap(v) {
    csAutoRefreshGapS = parseInt(v, 10);
    if (isNaN(csAutoRefreshGapS)) csAutoRefreshGapS = CS_AUTOREFRESH_DEFAULT;
    try { localStorage.setItem(CS_AUTOREFRESH_KEY, String(csAutoRefreshGapS)); } catch (e) {}
    // Reset so the next pulse after a change can fire promptly (e.g. switching
    // from a long gap back to 5s shouldn't wait out the old remainder).
    csLastAutoRefreshAt = 0;
}
// The <select> rendered next to the manual Refresh button (main.js cs shell).
function csAutoRefreshControl() {
    const opts = csAutoRefreshOpts()
        .map(([v, lbl]) => `<option value="${v}"${Number(v) === csAutoRefreshGapS ? ' selected' : ''}>${csEscape(lbl)}</option>`)
        .join('');
    return `<label class="text-[10px] text-slate-400 uppercase tracking-wider mr-1">Auto-refresh</label>`
        + `<select onchange="csSetAutoRefreshGap(this.value)" class="text-xs border border-slate-200 rounded-md px-2 py-1 bg-white text-slate-600" title="Throttle telemetry-driven page refreshes. Off = manual Refresh only.">`
        + opts + `</select>`;
}

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
    // Config form editors are manual-refresh only (a telemetry-driven rebuild
    // would stomp a half-edited form). Listed per child so Config::Quota State
    // — a live ledger view, not a form — is NOT here and auto-refreshes.
    'Config::Sim Quotas',    // Sim Quotas editor — manual Refresh only
    'Config::PXMX Sites',    // PXMX site assignments — manual Refresh only
    'Config::Config Editor', // raw config editor — manual Refresh only
    'VM Server::Command Queue', // loads serve from the cached CS_TELEMETRY
                                // command_queue (instant); kept manual-refresh so
                                // a busy spoke's live=1 re-fetch after a mutation
                                // can't loop the telemetry auto-refresh.
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
        // Match `primary::child` (a specific sub-tab) OR a bare `primary` (a
        // childless primary like Config — currentSubChild may also hold a stale
        // value from a prior primary, so the bare form is the reliable match).
        if (CS_NO_REFRESH.has(currentSubView + '::' + childKey) ||
            CS_NO_REFRESH.has(currentSubView)) return;
        // Auto-refresh throttle knob: -1 = OFF (manual Refresh only); >0 = skip
        // this pulse if less than the configured gap has elapsed since the last
        // telemetry-driven re-render (the next pulse retries, so a multi-spoke
        // frame storm coalesces to ~one refresh per gap). 0 = no throttle.
        if (csAutoRefreshGapS < 0) return;
        if (csAutoRefreshGapS > 0 && Date.now() - csLastAutoRefreshAt < csAutoRefreshGapS * 1000) return;
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
        csLastAutoRefreshAt = Date.now();
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
                case 'Config':      await csRenderConfigSimulation(force); break;
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
        <option value="">All statuses</option><option value="failing">Failing</option><option value="warning">Warning</option><option value="functional">Functional</option><option value="unknown">Unknown</option>
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
            <span class="font-bold text-slate-700">${csEscape(s.spoke_name || s.spoke_id)}</span>${csOnlineBadge(s.spoke_online)}${csThrottleBadge(s.spoke_id)}
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
            <span class="font-bold text-slate-700">${csEscape(s.spoke_name || s.spoke_id)}</span>${csOnlineBadge(s.spoke_online)}${csThrottleBadge(s.spoke_id)}
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

// Relative "minutes ago" for the Clients Last Seen column + the age in minutes
// so the cell can turn red past 30 min. Falls back to the raw value when
// unparseable. Same timestamp parsing as csLastSeen (epoch s/ms or ISO string).
function csLastSeenAgo(v) {
    if (v == null || v === '' || v === '—') return { text: '—', mins: null };
    let ms = NaN;
    if (typeof v === 'number') ms = v;
    else { const s = String(v).trim(); ms = /^[\d.]+$/.test(s) ? Number(s) : Date.parse(s); }
    if (isNaN(ms)) return { text: String(v), mins: null };
    if (ms < 1e11) ms *= 1000;
    const mins = Math.max(0, Math.floor((Date.now() - ms) / 60000));
    // Decimal hours (can be < 1, e.g. "0.23 hrs"); red when > 0.5 h (mins > 30).
    const hrs = Math.max(0, (Date.now() - ms) / 3600000);
    return { text: `${hrs.toFixed(2)} hrs`, mins };
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

// ── Faceted Clients drill-down (scales to thousands) ─────────────────────────
// Instead of one flat table of every client, the Clients tab summarizes by
// Simulation, then drills Simulation → Tier → Site → the client list, with a
// name/IP/MAC search that works at any level. Each facet is a chip row whose
// counts reflect the OTHER active facets (standard faceted counting).
let csFacet = { sim: null, tier: null, site: null };
// Client-list paging: 10 per page by default; the user can pick up to 100 from
// a selector at the bottom of the table. Capping the page size at 100 also keeps
// the DOM bounded no matter how large the match set is.
let csClientPage = 1;
let csClientPageSize = 10;
const CS_CLIENT_PAGE_SIZES = [10, 25, 50, 100];

// Reset to page 1 + re-render — called whenever the filter set changes (facet,
// search, or status) so the user isn't stranded on a now-empty page.
window.csClientResetPage = function () { csClientPage = 1; csRenderClientsFaceted(); };
window.csClientGoPage = function (delta) { csClientPage += Number(delta) || 0; csRenderClientsFaceted(); };
window.csClientSetPageSize = function (size) {
    csClientPageSize = Math.max(1, Math.min(100, Number(size) || 10));
    csClientPage = 1;
    csRenderClientsFaceted();
};

// Active simulation flags for a client — a per-client override WINS, else its
// active_simulations / effective config. Mirrors csClientSimBar's isOn.
function csClientActiveSims(c) {
    const active = new Set((Array.isArray(c.active_simulations) ? c.active_simulations : [])
        .map(s => String(s).toLowerCase()));
    const cfg = c.effective_config || c.config || {};
    const ov = c.overrides || {};
    return CS_CONTROL_FLAGS.filter(f => {
        if (Object.prototype.hasOwnProperty.call(ov, f))
            return ['on', 'true', '1'].includes(String(ov[f]).toLowerCase());
        // "Enabled" reflects the resolved CONFIG (per-client override wins, else
        // the bucket/user-overrides effective config) — NOT active_simulations
        // (what the client is momentarily running), so a cleared override drops
        // off immediately instead of lingering until the client stops the sim.
        return ['on', 'true', '1'].includes(String(cfg[f] == null ? '' : cfg[f]).toLowerCase());
    });
}
function csClientSite(c) { return (c.config && c.config.wsite) || c.wsite || '—'; }
function csClientSearchHay(c) {
    return [c.hostname, c.id, c.connected_ssid, c.simulation_id, c.platform,
            c.ip, c.mac, c.address, c.config && c.config.address, c.config && c.config.ip]
        .filter(Boolean).join(' ').toLowerCase();
}
// Passes the active facets? `skip` omits one dimension (used for facet counts so
// a facet's own selection doesn't collapse its counts to the chosen value).
function csClientPass(c, skip) {
    const st = csEl('cs-client-status') && csEl('cs-client-status').value;
    const q = ((csEl('cs-client-search') && csEl('cs-client-search').value) || '').trim().toLowerCase();
    if (skip !== 'status') {
        if (st === 'online' && !c.online) return false;
        if (st === 'offline' && c.online) return false;
    }
    if (skip !== 'search' && q && !csClientSearchHay(c).includes(q)) return false;
    if (skip !== 'sim' && csFacet.sim && csClientActiveSims(c).indexOf(csFacet.sim) === -1) return false;
    if (skip !== 'tier' && csFacet.tier && csClassifyClient(c) !== csFacet.tier) return false;
    if (skip !== 'site' && csFacet.site && csClientSite(c) !== csFacet.site) return false;
    return true;
}
window.csFacetSelect = function (dim, val) {
    csFacet[dim] = val || null;   // '' (the All option) clears the facet
    if (dim === 'tier') csClientTier = csFacet.tier || 'all';
    csClientPage = 1;             // a new filter set → back to page 1
    csRenderClientsFaceted();
};
window.csFacetReset = function () {
    csFacet = { sim: null, tier: null, site: null };
    csClientTier = 'all';
    csClientPage = 1;
    if (csEl('cs-client-search')) csEl('cs-client-search').value = '';
    if (csEl('cs-client-status')) csEl('cs-client-status').value = '';
    csRenderClientsFaceted();
};

// Render the facet chip bar + either the summary hint (no facet/search) or the
// filtered, PAGED client list (10/page default, up to 100; pager at the bottom).
// Cheap: O(clients × facets), and only one page of rows ever hits the DOM.
function csRenderClientsFaceted() {
    const facetsEl = csEl('cs-facets');
    const bodyEl = csEl('cs-client-body') || csEl('cs-content');
    if (!facetsEl || !bodyEl) return;
    const q = ((csEl('cs-client-search') && csEl('cs-client-search').value) || '').trim();

    const simCounts = {};
    CS_CONTROL_FLAGS.forEach(f => { simCounts[f] = 0; });
    const tierCounts = { t1: 0, t2: 0, t3: 0 };
    const siteCounts = {};
    csClientCache.forEach(c => {
        if (csClientPass(c, 'sim')) csClientActiveSims(c).forEach(f => { if (f in simCounts) simCounts[f]++; });
        if (csClientPass(c, 'tier')) { const t = csClassifyClient(c); if (t in tierCounts) tierCounts[t]++; }
        if (csClientPass(c, 'site')) { const s = csClientSite(c); siteCounts[s] = (siteCounts[s] || 0) + 1; }
    });

    // Compact <select> dropdowns (Simulation / Tier / Site) — all available from
    // the start, so there can be many simulations/sites without overflowing.
    // Option labels carry the (other-facet-scoped) counts; the value is passed at
    // runtime via this.value (no interpolation into the handler → injection-safe).
    const selCls = 'bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const lblCls = 'text-[11px] font-bold text-slate-400 uppercase tracking-wider';
    const opt = (v, label, count, cur) =>
        `<option value="${csEscape(v)}"${v === cur ? ' selected' : ''}>${csEscape(label)}${count != null ? ` (${count})` : ''}</option>`;
    const dropdown = (dim, allLabel, opts, cur) =>
        `<select onchange="csFacetSelect('${dim}', this.value)" class="${selCls}"><option value="">${csEscape(allLabel)}</option>${opts.join('')}</select>`;

    const simOpts = CS_CONTROL_FLAGS.filter(f => simCounts[f] > 0 || csFacet.sim === f)
        .map(f => opt(f, f, simCounts[f], csFacet.sim));
    const tierOpts = ['t1', 't2', 't3'].map(t => opt(t, t.toUpperCase(), tierCounts[t], csFacet.tier));
    const siteOpts = Object.keys(siteCounts).sort().map(s => opt(s, s, siteCounts[s], csFacet.site));

    // Any facet OR search lists clients (Simulation, Tier, and Site are all entry
    // points); nothing selected → the summary hint.
    const showList = !!(csFacet.sim || csFacet.tier || csFacet.site || q);
    const total = csClientCache.length;
    facetsEl.innerHTML = `
      <div class="flex flex-wrap items-center gap-x-2 gap-y-2 mb-3">
        <span class="${lblCls}">Simulation</span>${dropdown('sim', `All Simulations (${total})`, simOpts, csFacet.sim)}
        <span class="${lblCls} ml-2">Tier</span>${dropdown('tier', 'All Tiers', tierOpts, csFacet.tier)}
        <span class="${lblCls} ml-2">Site</span>${dropdown('site', 'All Sites', siteOpts, csFacet.site)}
        ${showList ? `<button onclick="csFacetReset()" class="text-xs text-slate-400 hover:text-slate-600 underline ml-2">Clear</button>` : ''}
      </div>`;

    if (!showList) {
        bodyEl.innerHTML = `<div class="text-center text-slate-400 text-sm py-10 border border-dashed border-slate-200 rounded-lg">${total.toLocaleString()} client(s). Pick a <span class="font-semibold text-slate-600">Simulation</span>, <span class="font-semibold text-slate-600">Tier</span>, or <span class="font-semibold text-slate-600">Site</span> above — or search by name / IP / MAC — to list clients.</div>`;
        return;
    }
    const matches = csClientCache.filter(c => csClientPass(c))
        .sort((a, b) => String(a.hostname || a.id || '')
            .localeCompare(String(b.hostname || b.id || ''), undefined, { numeric: true, sensitivity: 'base' }));
    // Paginate.
    const pageSize = csClientPageSize;
    const totalPages = Math.max(1, Math.ceil(matches.length / pageSize));
    if (csClientPage > totalPages) csClientPage = totalPages;
    if (csClientPage < 1) csClientPage = 1;
    const start = (csClientPage - 1) * pageSize;
    const shown = matches.slice(start, start + pageSize);
    const first = matches.length ? start + 1 : 0;
    const last = Math.min(start + pageSize, matches.length);

    const sizeOpts = CS_CLIENT_PAGE_SIZES.map(n =>
        `<option value="${n}"${n === pageSize ? ' selected' : ''}>${n}</option>`).join('');
    const btn = (label, delta, disabled) =>
        `<button onclick="csClientGoPage(${delta})" ${disabled ? 'disabled' : ''} class="px-2 py-0.5 rounded border ${disabled ? 'border-slate-100 text-slate-300 cursor-not-allowed' : 'border-slate-200 text-slate-600 hover:bg-slate-50'}">${label}</button>`;
    // Pager sits at the BOTTOM of the table.
    const pager = `<div class="flex flex-wrap items-center justify-between gap-2 mt-3 text-xs text-slate-500">
        <span>Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${matches.length.toLocaleString()}</span>
        <div class="flex items-center gap-2">
          ${btn('‹ Prev', -1, csClientPage <= 1)}
          <span>Page ${csClientPage} of ${totalPages}</span>
          ${btn('Next ›', 1, csClientPage >= totalPages)}
          <span class="ml-2">Per page</span>
          <select onchange="csClientSetPageSize(this.value)" class="bg-white border border-slate-200 rounded px-2 py-0.5 text-xs">${sizeOpts}</select>
        </div>
      </div>`;
    bodyEl.innerHTML = `<div class="text-xs text-slate-400 mb-2">${matches.length.toLocaleString()} client(s)</div><div id="cs-client-rows"></div>${pager}`;
    csRenderClientRows(shown, 'cs-client-rows');
}

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
    // fallback; only accept real tier strings. The Clients::T1/T2/T3 sub-nav tabs
    // pre-seed the Tier facet (drill still goes Simulation → Tier → Site).
    if (tier === 't1' || tier === 't2' || tier === 't3' || tier === 'all') {
        csClientTier = tier;
        csFacet.tier = (tier === 'all') ? null : tier;
    }
    csSetToolbar(`<input id="cs-client-search" oninput="csClientFilterKey()" placeholder="Search name / IP / MAC…" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-64">
      <select id="cs-client-status" onchange="csClientResetPage()" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500">
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
    csClientCache = csNormalizeClients(data);
    // Faceted drill-down: the demo card, then the Simulation/Tier/Site facet bar,
    // then the (drill-gated, capped) client list, then a static legend. Kill
    // switch stays in the secondary-nav chip (renderSecondaryNav → csKillSwitchMountChip).
    csSet(`<div class="space-y-4">${demoCard}<div id="cs-facets"></div><div id="cs-client-body"></div>${csClientsLegend()}</div>`);
    csRenderClientsFaceted();
}

// Static legend under the Clients view — what the sim-bar button colors, the
// demo mark, the red last-seen, and the tier badges mean. Swatch classes mirror
// csSimBtnClass / the row renderer so the samples match the live UI exactly.
function csClientsLegend() {
    const sw = cls => `<span class="${cls} px-2 py-0.5 rounded-md text-[11px] font-bold">sim</span>`;
    const tier = (cls, t) => `<span class="font-bold text-slate-600">${t}</span>`;
    const lbl = t => `<span class="font-bold uppercase tracking-wider text-slate-400 mr-1">${t}</span>`;
    return `<div class="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500">
      <span class="font-bold uppercase tracking-wider text-slate-400">Legend</span>
      <div class="mt-2 space-y-1.5">
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Status')}
          <span class="flex items-center gap-1.5"><span class="inline-block w-2 h-2 rounded-full bg-green-500"></span> Online</span>
          <span class="flex items-center gap-1.5"><span class="inline-block w-2 h-2 rounded-full bg-amber-400"></span> Offline &lt; 30 min</span>
          <span class="flex items-center gap-1.5"><span class="inline-block w-2 h-2 rounded-full bg-red-500"></span> Offline &gt; 30 min</span>
          <span class="flex items-center gap-1.5"><span class="text-red-600 font-bold">0.75 hrs</span> Last Seen over 30 min ago</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Sim')}
          <span class="flex items-center gap-1.5">${sw('bg-[#263040]/10 text-[#263040] border border-[#263040]')} SID default ON</span>
          <span class="flex items-center gap-1.5">${sw('bg-white text-slate-400 border border-slate-200')} SID default OFF</span>
          <span class="flex items-center gap-1.5">${sw('bg-white text-[#263040] border-2 border-[#263040]')} Override ON</span>
          <span class="flex items-center gap-1.5">${sw('bg-[#263040]/5 text-[#263040]/60 border border-[#263040]/40')} Override OFF</span>
          <span class="flex items-center gap-1.5"><span class="bolt text-amber-600 font-bold">⚡</span> Demo scenario active (auto-reverts in 2h)</span>
          <span class="flex items-center gap-1.5"><span class="bg-amber-50 border border-amber-200 px-1.5 rounded">row</span> highlighted while a demo runs</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Tier')}
          <span class="flex items-center gap-1.5">${tier('', 'T1')} Physical Hardware · ${tier('', 'T2')} USB dongle · ${tier('', 'T3')} PCI passthrough</span>
        </div>
      </div>
    </div>`;
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
// per-simulation override buttons. Columns: Hostname (with a status dot), Site,
// SID, PHY, OS, Tier, SSID, Last Seen, Errors, Demo.
const CS_CLIENT_COLS = 10;

// Status dot shown next to the hostname (replaces the Status column):
//   green  = online
//   yellow = offline, last seen < 30 min ago (just dropped)
//   red    = offline, last seen > 30 min ago (stale)
function csClientStatusDot(c) {
    const ls = csLastSeenAgo(c.last_seen);
    let color, label;
    if (c.online) { color = 'bg-green-500'; label = 'Online'; }
    else if (ls.mins != null && ls.mins > 30) { color = 'bg-red-500'; label = 'Offline > 30 min'; }
    else { color = 'bg-amber-400'; label = 'Offline < 30 min'; }
    return `<span class="inline-block w-2 h-2 rounded-full ${color} mr-1.5 align-middle" title="${csEscape(label)}"></span>`;
}
function csRenderClientRows(rows, targetId) {
    const body = (targetId && csEl(targetId)) || csEl('cs-client-body') || csEl('cs-content');
    if (!rows || rows.length === 0) {
        body.innerHTML = csEmpty('No clients reported.',
            'Connected client simulators will appear here once spokes check in.');
        return;
    }
    const rowHtml = rows.map(c => {
        const t = csClassifyClient(c);
        const host = c.hostname || c.id || '';
        const cfg = c.config || {};
        const _demoOn = window._csDemoActive && window._csDemoActive[host];
        const _ls = csLastSeenAgo(c.last_seen);
        const line1 = `<tr class="border-t border-slate-100 ${_demoOn ? 'bg-amber-50' : ''}">
          <td class="px-4 py-2 font-mono text-xs whitespace-nowrap">${csClientStatusDot(c)}${csEscape(host || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(cfg.wsite || '—')}</td>
          <td class="px-4 py-2 font-mono text-xs text-slate-500">${csEscape(c.simulation_id || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(cfg.sim_phy || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.platform || c.hw_type || '—')}</td>
          <td class="px-4 py-2 text-xs font-semibold text-slate-600">${t.toUpperCase()}</td>
          <td class="px-4 py-2 text-slate-500">${csEscape(c.connected_ssid || '—')}</td>
          <td class="px-4 py-2 ${_ls.mins != null && _ls.mins > 30 ? 'text-red-600 font-bold' : 'text-slate-500'}" title="${csEscape(csLastSeen(c.last_seen))}">${csEscape(_ls.text)}</td>
          <td class="px-4 py-2 ${c.error_count > 0 ? 'text-amber-600 font-bold' : 'text-slate-400'}">${csEscape(c.error_count || 0)}</td>
          ${host ? csDemoCell(host) : '<td class="px-4 py-2 text-slate-300">—</td>'}
        </tr>`;
        const line2 = host ? `<tr>
          <td colspan="${CS_CLIENT_COLS}" class="px-4 pb-3 pt-0">${csClientSimBar(c, host)}</td>
        </tr>` : '';
        return line1 + line2;
    }).join('');
    body.innerHTML = csTable(
        ['Name', 'Site', 'SID', 'PHY', 'OS', 'Tier', 'SSID', 'Last Seen', 'Err', 'Demo'],
        rowHtml,
        // Column widths (10 cols — Status column dropped; status is now a dot by
        // the hostname). Tunable: adjust these and the header order as needed.
        { colWidths: ['200px', '90px', '70px', '80px', '90px', '60px',
                      '216px', '132px', '35px', '300px'] }
    );
    csDemoStartTicker();
}

// The second line under each client: one clickable button per simulation (the
// original webui-hub FLAG_ORDER set). A button is highlighted when that sim is
// currently on (in the client's active_simulations or effective config).
// Clicking toggles a per-client override; the server REPLACES the whole override
// map, so csSimToggle sends every flag for the host with the clicked one flipped
// (POST /clients/{host}/control {overrides:{flag:on/off}} — same endpoint the
// original Apply used). "Clear" removes all overrides for the client.
function csSimBtnClass(on, isOverride) {
    // isOverride (truthy) → border-ONLY purple, same color family as the filled
    // bucket-default-on button, so an operator can tell a per-client override
    // apart from the bucket default at a glance. Filled purple = bucket-on;
    // slate border = bucket-off; purple border = override (on = bold, off =
    // faint). The override object is pruned server-side when it matches the
    // bucket default (see ClientRegistry.set_overrides), so an override button
    // only appears for a REAL deviation from the bucket.
    // HPE-navy (#263040) with a light fill + solid navy border (the "gradient"
    // treatment, same as the left-menu active items): filled light-navy = default
    // ON; navy border = override (bold=on / faint=off); slate = default OFF.
    if (isOverride) {
        return 'px-[0.152rem] py-[0.051rem] rounded text-[12px] font-bold border transition-colors ' +
            (on ? 'bg-white text-[#263040] border-2 border-[#263040] hover:bg-[#263040]/5'
                : 'bg-[#263040]/5 text-[#263040]/60 border-[#263040]/40 hover:bg-[#263040]/10');
    }
    return 'px-[0.152rem] py-[0.051rem] rounded text-[12px] font-bold border transition-colors ' +
        (on ? 'bg-[#263040]/10 text-[#263040] border-[#263040]'
            : 'bg-white text-slate-400 border-slate-200 hover:bg-slate-100');
}

function csClientSimBar(c, host) {
    const cfg = c.effective_config || c.config || {};
    // Model A: a button is "on" iff the client's RESOLVED config has the flag on.
    // Per-user overrides (user-overrides.conf [username]) and the 2h demo are
    // already folded into that resolved config by the spoke, so this single
    // source matches exactly what the client is configured to run — a cleared
    // override drops off as soon as the next telemetry frame lands. There is no
    // separate registry-override layer to style anymore (isOv = false).
    const isOn = f =>
        ['on', 'true', '1'].includes(String(cfg[f] == null ? '' : cfg[f]).toLowerCase());
    const btns = CS_CONTROL_FLAGS.map(f => {
        const on = isOn(f);
        const ovFlag = false;
        return `<button data-cs-sim-host="${csEscape(host)}" data-cs-sim-flag="${csEscape(f)}" data-cs-sim-on="${on ? '1' : '0'}" data-cs-sim-ov="${ovFlag ? '1' : '0'}"
          onclick="csSimToggle(this)" title="${ovFlag ? 'Override' : 'SID'}: ${csEscape(f)} ${on ? 'on' : 'off'} on ${csEscape(host)} — click to ${on ? 'disable' : 'enable'}"
          class="${csSimBtnClass(on, ovFlag)} w-full text-center">${csEscape(f)}</button>`;
    }).join('');
    // Uniform-size sim knobs laid out in a 2-ROW grid (columns = half the flag
    // count, rounded up) so every button is the same width and the set stays
    // tidy as more simulations are added (it grows into more columns, still 2
    // rows; overflow-x-auto scrolls if it ever gets very wide). Clear + status
    // message sit on their own line below.
    const _simCols = Math.max(1, Math.ceil(CS_CONTROL_FLAGS.length / 2));
    return `<div class="space-y-1.5">
      <div class="grid gap-1 overflow-x-auto pb-0.5" style="grid-template-columns: repeat(${_simCols}, minmax(46px, 1fr));">${btns}</div>
      <div class="flex items-center gap-1.5">
        <span id="${csEscape(csCtlId(host, 'msg'))}" class="text-[11px] text-slate-400"></span>
      </div>
    </div>`;
}

// ── Per-client sim toggle (model A: per-USER override in user-overrides.conf) ─
// A single click toggles one sim for the client's USER (username = host minus
// the trailing -N). The HUB owns the write: cs_set_client_control edits the
// [username] section of user-overrides.conf, pushes it through the source-of-
// truth flow, commits+pushes to GitHub when a token is configured, and clears
// any legacy per-client registry override. No client-side user-overrides mirror
// is needed here — the dashboard just flips the button and lets the next
// telemetry frame confirm the resolved config.
window.csSimToggle = async function (btn) {
    const host = btn.dataset.csSimHost, flag = btn.dataset.csSimFlag;
    if (!host || !flag) return;
    const next = btn.dataset.csSimOn === '1' ? 'off' : 'on';
    const user = String(host || '').split('-')[0] || host;
    csCtlMsg(host, `${next === 'on' ? 'Enabling' : 'Disabling'} ${flag}…`, true);
    // Optimistic flip; cs_set_client_control patches the hub cache so the next
    // render already reflects it, and the ~10s telemetry frame is authoritative.
    const on = (next === 'on');
    const prevOn = btn.dataset.csSimOn;
    btn.dataset.csSimOn = on ? '1' : '0';
    btn.className = csSimBtnClass(on, false) + ' w-full text-center';
    try {
        await csFetch(`/${csTenant()}/clients/${encodeURIComponent(host)}/control?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ overrides: { [flag]: next } }) });
        btn.title = `${flag} ${on ? 'on' : 'off'} for ${user} — click to ${on ? 'disable' : 'enable'}`;
        csCtlMsg(host, `${flag} ${next} (user override)`, true);
        if (typeof showToast === 'function') showToast(`${flag} ${next} for ${user} (user override)`, 'success');
    } catch (e) {
        // Revert the optimistic flip so the button matches the true state.
        btn.dataset.csSimOn = prevOn;
        btn.className = csSimBtnClass(prevOn === '1', false) + ' w-full text-center';
        console.error('csSimToggle failed', e);
        csCtlMsg(host, e.message || 'failed', false);
        if (typeof showToast === 'function') showToast(`toggle failed: ${e.message || 'error'}`, 'error');
    }
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

// Live countdown ticker for active demo scenarios — a ⚡ pill + H:MM:SS that
// ticks every second from the scenario's expires_at (epoch). Mirrors the source
// project's active-simulation visual (colored + lightning bolt + countdown).
function _csFmtCountdown(secs) {
    secs = Math.max(0, Math.floor(secs));
    const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60;
    const pad = n => String(n).padStart(2, '0');
    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}
let _csDemoTicker = null;
function csDemoStartTicker() {
    if (_csDemoTicker) return;
    _csDemoTicker = setInterval(csDemoTickCountdowns, 1000);
    csDemoTickCountdowns();
}
function csDemoTickCountdowns() {
    const spans = document.querySelectorAll('.cs-demo-countdown[data-demo-expires]');
    if (!spans.length) { if (_csDemoTicker) { clearInterval(_csDemoTicker); _csDemoTicker = null; } return; }
    const now = Date.now() / 1000;
    spans.forEach(el => {
        const exp = parseFloat(el.getAttribute('data-demo-expires')) || 0;
        const rem = exp - now;
        el.textContent = rem <= 0 ? 'expired' : _csFmtCountdown(rem);
    });
}

function csDemoCell(hostname) {
    const a = window._csDemoActive[hostname];
    const exp = a && a.expires_at != null ? a.expires_at : '';
    const badge = a ? `<span class="inline-flex items-center gap-1 bg-amber-100 text-amber-800 border border-amber-300 rounded px-1.5 py-0.5 text-[10px] font-bold mr-1 animate-pulse" title="Simulation '${csEscape(a.scenario)}' active">⚡ ${csEscape(a.scenario)} <span class="cs-demo-countdown font-mono" data-demo-expires="${csEscape(String(exp))}">${csEscape(a.minutes_remaining != null ? Math.round(a.minutes_remaining) + 'm' : '')}</span></span>` : '';
    return `<td class="px-4 py-2 whitespace-nowrap ${a ? 'bg-amber-50' : ''}">
      ${badge}
      <select id="cs-demo-${csEscape(hostname)}" class="border border-slate-200 rounded-md px-1 py-0.5 text-[11px]">
        ${csDemoOptions(a ? a.scenario : 'normal')}
      </select>
      <button data-cs-demo-host="${csEscape(hostname)}" onclick="csDemoTrigger(this)"
        class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-1.5 py-0.5 rounded-md text-[11px] font-bold">Go</button>
      <button data-cs-ctl-host="${csEscape(hostname)}" onclick="csCtlClear(this)"
        class="bg-red-50 hover:bg-red-100 text-red-600 border border-red-200 px-1.5 py-0.5 rounded-md text-[11px] font-bold" title="Clear this client's sim overrides">Clear</button>
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
// Alphabetical so the sim knobs + the Simulation facet dropdown list in order.
const CS_CONTROL_FLAGS = ['assoc_fail', 'auth_fail', 'dhcp_fail', 'dns_fail',
    'download', 'iperf', 'kill_switch', 'ping_test', 'port_flap',
    'ssidpw_fail', 'www_traffic'];
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
          class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold">Apply</button>
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

// Back-compat alias — the faceted renderer is the single filter path now
// (search + status + Simulation/Tier/Site facets). Any external caller still
// invoking csClientFilter() gets a faceted re-render.
window.csClientFilter = function () { csRenderClientsFaceted(); };

// Keystroke-debounced entry point for the search input (the status <select>
// re-renders immediately via its onchange=). Search matches name / IP / MAC /
// SSID / Sim-ID and works at any drill level. Resets to page 1. See csDebounce.
window.csClientFilterKey = csDebounce(function () { csClientResetPage(); }, 200);

/* ===========================================================================
 * 3. Central — sites / alerts / clients + save form
 *    GET /sim/api/aggregate/central-status?tenant_id={T}
 *    POST /sim/api/aggregate/central  {mode, hub_central_config}
 * ========================================================================= */

// The Central Sites/Alerts/Clients tabs now pull the FULL Central inventory via
// /aggregate/central-browse (hub forwards CS_CENTRAL_BROWSE → spoke browse_all),
// independent of site_mappings. Shared fetch with a short in-memory cache so
// switching tabs doesn't re-hit Central each time.
let _csCentralBrowseCache = null, _csCentralBrowseAt = 0, _csCentralBrowseTenant = null;
async function csCentralBrowse() {
    const t = csTenant();
    if (_csCentralBrowseCache && _csCentralBrowseTenant === t && (Date.now() - _csCentralBrowseAt) < 60000) {
        return _csCentralBrowseCache;
    }
    let data = {};
    try { data = await csFetch(`/aggregate/central-browse?tenant_id=${t}`) || {}; }
    catch (e) { console.error('csCentralBrowse: /aggregate/central-browse failed', e); data = { warning: String(e && e.message || e) }; }
    _csCentralBrowseCache = data; _csCentralBrowseAt = Date.now(); _csCentralBrowseTenant = t;
    return data;
}
function _csCentralWarn(data) {
    return data && data.warning ? `<div class="text-xs text-amber-600 mb-3">${csEscape(data.warning)}</div>` : '';
}

// ── Central shared table: clickable column sort + Monitored on/off filter ────
// The five Central tabs (Sites/Alerts/Insights/Clients/Hardware) each render a
// table with a per-row Monitor toggle. This wrapper gives them click-to-sort on
// any column header (▲/▼ marks the active column; click toggles asc/desc) and a
// quick All / On / Off filter above the table for the Monitored flag (when
// opts.monitorOf is supplied). Sort + filter state is kept per table-id across
// re-renders, so toggling a Monitor button (which re-fetches + re-renders the
// tab) preserves the user's sort/filter. Re-sorting/re-filtering is LOCAL — it
// rebuilds only the table slot from the cached rows in _csCentralTbl[id], never
// re-hitting Central.
const _csCentralTbl = {};   // id -> {columns, rows, opts, sort:{col,dir}|null, filter:'all'|'mon'|'unmon'}

function csCentralTable(id, columns, rows, opts = {}) {
    // columns: [{label, render(row)->html, sort(row)->comparable, width?}]
    // opts.monitorOf: (row)->bool  — enables the Monitored All/On/Off filter
    // opts.caption:   small grey caption rendered under the filter row
    const st = _csCentralTbl[id] || (_csCentralTbl[id] = { sort: null, filter: 'all' });
    st.columns = columns; st.rows = rows; st.opts = opts;
    return `<div id="cs-central-table-${csEscape(id)}">${_csCentralTableBuild(id)}</div>`;
}

function _csCentralTableBuild(id) {
    const st = _csCentralTbl[id]; if (!st) return '';
    const { columns, rows, opts, sort, filter } = st;
    const monOf = opts.monitorOf || null;
    let view = rows;
    if (monOf && filter !== 'all') view = rows.filter(r => filter === 'mon' ? !!monOf(r) : !monOf(r));
    if (sort && columns[sort.col] && typeof columns[sort.col].sort === 'function') {
        const ci = sort.col, dir = sort.dir, acc = columns[ci].sort;
        view = view.slice().sort((a, b) => {
            const av = acc(a), bv = acc(b);
            let cmp;
            if (typeof av === 'number' && typeof bv === 'number') cmp = av - bv;
            else {
                const as = String(av == null ? '' : av).toLowerCase();
                const bs = String(bv == null ? '' : bv).toLowerCase();
                cmp = as < bs ? -1 : as > bs ? 1 : 0;
            }
            return dir === 'desc' ? -cmp : cmp;
        });
    }
    const ths = columns.map((c, i) => {
        const active = sort && sort.col === i;
        const arrow = active ? (sort.dir === 'desc' ? ' ▼' : ' ▲') : '';
        const w = c.width ? ` style="width:${csEscape(String(c.width))}"` : '';
        return `<th${w} class="px-3 py-2 text-left font-semibold cursor-pointer select-none hover:text-slate-700" onclick="csCentralSort('${csEscape(id)}', ${i})" title="Sort by ${csEscape(c.label)}">${csEscape(c.label)}${active ? `<span class="text-slate-400">${arrow}</span>` : ''}</th>`;
    }).join('');
    const body = view.length
        ? view.map(r => `<tr>${columns.map(c => `<td class="px-3 py-2">${c.render(r)}</td>`).join('')}</tr>`).join('')
        : `<tr><td class="px-3 py-8 text-center text-slate-400 italic" colspan="${columns.length}">No data.</td></tr>`;
    let bar = '';
    if (monOf) {
        const nMon = rows.filter(r => monOf(r)).length;
        const mk = (val, label) => `<button onclick="csCentralFilter('${csEscape(id)}','${val}')" class="px-2.5 py-1 rounded-md text-xs font-bold border ${filter === val ? 'bg-[#263040]/10 text-[#263040] border-[#263040]' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'}">${label}</button>`;
        bar = `<div class="flex items-center gap-2 mb-3">
            <span class="text-xs text-slate-500 font-semibold uppercase tracking-wider">Monitored:</span>
            ${mk('all', `All (${rows.length})`)}${mk('mon', `On (${nMon})`)}${mk('unmon', `Off (${rows.length - nMon})`)}
        </div>`;
    }
    const caption = opts.caption ? `<div class="text-xs text-slate-400 mb-2">${csEscape(opts.caption)}</div>` : '';
    return `${bar}${caption}<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-slate-50 text-slate-500 uppercase text-xs tracking-wider">${ths}</thead><tbody class="divide-y divide-slate-100">${body}</tbody></table></div>`;
}

// Click handlers — local re-render from the cached rows (NO Central refetch).
window.csCentralSort = function (id, col) {
    const st = _csCentralTbl[id]; if (!st) return;
    if (st.sort && st.sort.col === col) st.sort.dir = st.sort.dir === 'asc' ? 'desc' : 'asc';
    else st.sort = { col, dir: 'asc' };
    const wrap = document.getElementById(`cs-central-table-${id}`);
    if (wrap) wrap.innerHTML = _csCentralTableBuild(id);
};
window.csCentralFilter = function (id, val) {
    const st = _csCentralTbl[id]; if (!st) return;
    st.filter = val;
    const wrap = document.getElementById(`cs-central-table-${id}`);
    if (wrap) wrap.innerHTML = _csCentralTableBuild(id);
};

async function csRenderCentral() {
    csSetToolbar('');
    // Browse (full site inventory) + the monitoring config, so each row shows a
    // Monitor toggle reflecting whether the site is already enrolled.
    const [data, sitesCfg] = await Promise.all([
        csCentralBrowse(),
        csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`).catch(() => ({})),
    ]);
    const sites = (data && data.sites) || [];
    const warn = _csCentralWarn(data);
    if (!sites.length) { csSet(`${warn}${csEmpty('No Central sites returned.', 'Verify the Central API token/mode in Setup → Central API and that the account has sites.')}`); return; }
    const sm = (sitesCfg && sitesCfg.site_mappings && typeof sitesCfg.site_mappings === 'object') ? sitesCfg.site_mappings : {};
    const monitored = new Set(Object.values(sm).map(v => String(v)));  // Central-site names enrolled
    // Per-site alert/insight counts from the browse data. Insights tagged
    // "All Sites" (global) count toward every site.
    const alertsBySite = {}, insightsBySite = {}; let globalInsights = 0;
    ((data && data.alerts) || []).forEach(a => { const s = a.site || '—'; alertsBySite[s] = (alertsBySite[s] || 0) + 1; });
    ((data && data.insights) || []).forEach(i => { const s = i.site || '—'; if (s === 'All Sites') globalInsights++; else insightsBySite[s] = (insightsBySite[s] || 0) + 1; });
    const rows = sites.map(st => {
        const name = st.name || '';
        const isMon = monitored.has(String(name));
        const nAlerts = alertsBySite[name] || 0;
        const nInsights = (insightsBySite[name] || 0) + globalInsights;
        const btn = isMon
            ? `<button onclick="csToggleMonitorSite(${csEscape(JSON.stringify(name))}, false)" class="bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-emerald-100" title="Stop monitoring this site's client count">✓ Monitored</button>`
            : `<button onclick="csToggleMonitorSite(${csEscape(JSON.stringify(name))}, true)" class="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-slate-200" title="Monitor this site's client count for change (shows on the dashboard)">Monitor</button>`;
        return { name, health: st.health_score, clients: st.wireless_clients != null ? st.wireless_clients : 0,
                 alerts: nAlerts, insights: nInsights, monitored: isMon, btn: name ? btn : '' };
    });
    const siteCols = [
        { label: 'Site',     render: r => `<span class="font-medium text-slate-700">${csEscape(r.name || '—')}</span>`, sort: r => r.name || '' },
        { label: 'Health',   render: r => r.health != null && r.health !== '' ? csEscape(r.health) : '—', sort: r => (r.health == null || r.health === '' ? -1 : Number(r.health) || 0) },
        { label: 'Clients',  render: r => `<span class="font-bold text-slate-700">${csEscape(r.clients)}</span>`, sort: r => r.clients },
        { label: 'Alerts',   render: r => `<span class="${r.alerts ? 'text-amber-600 font-bold' : 'text-slate-400'}">${r.alerts}</span>`, sort: r => r.alerts },
        { label: 'Insights', render: r => `<span class="${r.insights ? 'text-slate-600' : 'text-slate-400'}">${r.insights}</span>`, sort: r => r.insights },
        { label: 'Monitor',  render: r => r.btn, sort: r => r.monitored ? 1 : 0 },
    ];
    csSet(`<div class="space-y-4">${warn}<div class="hpe-card rounded-lg p-4 shadow-sm">${csCentralTable('central-sites', siteCols, rows, { monitorOf: r => r.monitored, caption: `${sites.length} site(s) — Monitor a site to track its client count for change on the dashboard` })}</div></div>`);
}

// Enroll / un-enroll a Central site for client-count monitoring by toggling it in
// central_sites_config.site_mappings (key=value=Central site name), preserving the
// monitored alert/insight + hardware checks. Once enrolled the hub/spoke poller
// tracks its client count (7-day baseline) and it appears on the dashboard.
window.csToggleMonitorSite = async function (siteName, monitor, rerender) {
    try {
        const cfg = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`) || {};
        const sm = (cfg.site_mappings && typeof cfg.site_mappings === 'object') ? { ...cfg.site_mappings } : {};
        if (monitor) {
            sm[siteName] = siteName;
        } else {
            Object.keys(sm).forEach(k => { if (String(sm[k]) === String(siteName) || k === siteName) delete sm[k]; });
        }
        const body = {
            site_mappings: sm,
            monitored_checks: Array.isArray(cfg.monitored_checks) ? cfg.monitored_checks : [],
            hardware_checks: Array.isArray(cfg.hardware_checks) ? cfg.hardware_checks : [],
        };
        const r = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        if (typeof csPushToast === 'function') csPushToast(r, monitor ? `Monitoring ${siteName}` : `Stopped monitoring ${siteName}`);
        else if (typeof showToast === 'function') showToast(monitor ? `Monitoring ${siteName}` : `Stopped monitoring ${siteName}`, 'success');
        (rerender === 'clients' ? csRenderCentralClients : csRenderCentral)();
    } catch (e) {
        console.error('csToggleMonitorSite failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
};

// ── Central → Alerts (live active alerts from Central) ───────────────────────
// Displays the live active alerts Central returns (/network-notifications/v1/
// alerts, status Active) — the same data the source browse view shows. Alert
// CHECK-TYPE monitoring (the fixed new_central alert types) lives in Setup ->
// Central API; new_central does not expose insights as monitorable checks
// (the poller never counts them), so these are inventory views like Clients.
async function csRenderCentralAlerts() {
    csSetToolbar('');
    const [data, sitesCfg] = await Promise.all([
        csCentralBrowse(),
        csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`).catch(() => ({})),
    ]);
    const alerts = (data && data.alerts) || [];
    const warn = _csCentralWarn(data);
    if (!alerts.length) { csSet(`${warn}${csEmpty('No active Central alerts.', 'Active alerts come from Central /network-notifications/v1/alerts.')}`); return; }
    const monSet = new Set((Array.isArray(sitesCfg && sitesCfg.monitored_checks) ? sitesCfg.monitored_checks : [])
        .filter(c => c && c.type === 'alert').map(c => `${c.id}::${c.site || ''}`));
    const _sevRank = { critical: 4, error: 3, fail: 3, failed: 3, warning: 2, degraded: 2, info: 1, unknown: 0 };
    const rows = alerts.map(a => {
        const id = String((a.name || a.category) || '').trim();
        const name = a.name || a.category || id;
        const site = (a.site && a.site !== '—') ? a.site : '';
        const isMon = id && monSet.has(`${id}::${site}`);
        const btn = !id ? '—' : (isMon
            ? `<button onclick="csToggleMonitorCheck('alert', ${csEscape(JSON.stringify(id))}, ${csEscape(JSON.stringify(name))}, false, ${csEscape(JSON.stringify(site))})" class="bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-emerald-100" title="Stop monitoring this alert at ${csEscape(site || 'all sites')}">✓ Monitored</button>`
            : `<button onclick="csToggleMonitorCheck('alert', ${csEscape(JSON.stringify(id))}, ${csEscape(JSON.stringify(name))}, true, ${csEscape(JSON.stringify(site))})" class="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-slate-200" title="Monitor this alert at ${csEscape(site || 'all sites')}">Monitor</button>`);
        return { name: a.name || '—', site: a.site || '—', severity: a.severity || 'warning',
                 category: a.category || '—', monitored: !!isMon, btn };
    });
    const alertCols = [
        { label: 'Alert',    render: r => `<span class="text-sm">${csEscape(r.name)}</span>`, sort: r => r.name },
        { label: 'Site',     render: r => `<span class="text-slate-500">${csEscape(r.site)}</span>`, sort: r => r.site },
        { label: 'Severity', render: r => csStatusBadge(r.severity), sort: r => _sevRank[String(r.severity).toLowerCase()] || 0 },
        { label: 'Category', render: r => `<span class="text-slate-500 text-xs">${csEscape(r.category)}</span>`, sort: r => r.category },
        { label: 'Monitor',  render: r => r.btn, sort: r => r.monitored ? 1 : 0 },
    ];
    csSet(`<div class="space-y-4">${warn}<div class="hpe-card rounded-lg p-4 shadow-sm">${csCentralTable('central-alerts', alertCols, rows, { monitorOf: r => r.monitored, caption: `${alerts.length} active alert(s)` })}</div></div>`);
}

// ── Central → Insights (live AI insights, with Monitor toggle) ───────────────
// Displays live insights (/network-notifications/v1/insights) with a Monitor
// toggle per row. Monitoring adds {type:'insight', id:name||category, name} to
// central_sites_config.monitored_checks; the new_central poller counts insights
// per site by that same key so the enrolled insight's status shows on the
// dashboard Checks tab.
async function csRenderCentralInsights() {
    csSetToolbar('');
    const [data, sitesCfg] = await Promise.all([
        csCentralBrowse(),
        csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`).catch(() => ({})),
    ]);
    const insights = (data && data.insights) || [];
    const warn = _csCentralWarn(data);
    if (!insights.length) { csSet(`${warn}${csEmpty('No Central insights.', 'AI insights come from Central /network-notifications/v1/insights.')}`); return; }
    const monSet = new Set((Array.isArray(sitesCfg && sitesCfg.monitored_checks) ? sitesCfg.monitored_checks : [])
        .filter(c => c && c.type === 'insight').map(c => `${c.id}::${c.site || ''}`));
    const rows = insights.map(i => {
        const id = String((i.name || i.category) || '').trim();
        const name = i.name || i.category || id;
        const site = i.site || '';
        const isMon = id && monSet.has(`${id}::${site}`);
        const btn = !id ? '—' : (isMon
            ? `<button onclick="csToggleMonitorCheck('insight', ${csEscape(JSON.stringify(id))}, ${csEscape(JSON.stringify(name))}, false, ${csEscape(JSON.stringify(site))})" class="bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-emerald-100" title="Stop monitoring this insight at ${csEscape(site || 'all sites')}">✓ Monitored</button>`
            : `<button onclick="csToggleMonitorCheck('insight', ${csEscape(JSON.stringify(id))}, ${csEscape(JSON.stringify(name))}, true, ${csEscape(JSON.stringify(site))})" class="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-slate-200" title="Monitor this insight at ${csEscape(site || 'all sites')}">Monitor</button>`);
        return { name: i.name || '—', category: i.category || '—', site: i.site || '—',
                 monitored: !!isMon, btn };
    });
    const insightCols = [
        { label: 'Insight',  render: r => `<span class="text-sm">${csEscape(r.name)}</span>`, sort: r => r.name },
        { label: 'Category', render: r => `<span class="text-slate-500">${csEscape(r.category)}</span>`, sort: r => r.category },
        { label: 'Site',     render: r => `<span class="text-slate-500">${csEscape(r.site)}</span>`, sort: r => r.site },
        { label: 'Monitor',  render: r => r.btn, sort: r => r.monitored ? 1 : 0 },
    ];
    csSet(`<div class="space-y-4">${warn}<div class="hpe-card rounded-lg p-4 shadow-sm">${csCentralTable('central-insights', insightCols, rows, { monitorOf: r => r.monitored, caption: `${insights.length} insight(s)` })}</div></div>`);
}

// Toggle an insight (or alert) TYPE in central_sites_config.monitored_checks
// (keyed type:id), preserving site_mappings + hardware_checks.
window.csToggleMonitorCheck = async function (type, id, name, monitor, site) {
    try {
        const cfg = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`) || {};
        site = site || '';
        const key = `${type}:${id}:${site}`;
        let checks = (Array.isArray(cfg.monitored_checks) ? cfg.monitored_checks : []).filter(c => `${c.type}:${c.id}:${c.site || ''}` !== key);
        if (monitor) checks.push({ type, id, name, site });
        const body = {
            site_mappings: (cfg.site_mappings && typeof cfg.site_mappings === 'object') ? cfg.site_mappings : {},
            monitored_checks: checks,
            hardware_checks: Array.isArray(cfg.hardware_checks) ? cfg.hardware_checks : [],
        };
        const r = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        if (typeof csPushToast === 'function') csPushToast(r, monitor ? `Monitoring ${name}` : `Stopped monitoring ${name}`);
        else if (typeof showToast === 'function') showToast(monitor ? `Monitoring ${name}` : `Stopped monitoring ${name}`, 'success');
        (type === 'alert' ? csRenderCentralAlerts : csRenderCentralInsights)();
    } catch (e) {
        console.error('csToggleMonitorCheck failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
};

// ── Central → Clients ────────────────────────────────────────────────────────
async function csRenderCentralClients() {
    csSetToolbar('');
    const [data, sitesCfg] = await Promise.all([
        csCentralBrowse(),
        csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`).catch(() => ({})),
    ]);
    const clients = (data && data.clients) || [];
    const warn = _csCentralWarn(data);
    if (!clients.length) { csSet(`${warn}${csEmpty('No Central clients returned.')}`); return; }
    const sm = (sitesCfg && sitesCfg.site_mappings && typeof sitesCfg.site_mappings === 'object') ? sitesCfg.site_mappings : {};
    const monitored = new Set(Object.values(sm).map(v => String(v)));
    const rows = clients.map(cl => {
        const site = cl.site || '';
        const isMon = site && monitored.has(String(site));
        const btn = !site ? '—' : (isMon
            ? `<button onclick="csToggleMonitorSite(${csEscape(JSON.stringify(site))}, false, 'clients')" class="bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-emerald-100" title="Stop monitoring this client's site">✓ Site monitored</button>`
            : `<button onclick="csToggleMonitorSite(${csEscape(JSON.stringify(site))}, true, 'clients')" class="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-slate-200" title="Monitor this client's site (client-count on the dashboard)">Monitor</button>`);
        return { host: cl.hostname || cl.mac || '—', ip: cl.ip || '—', mac: cl.mac || '—',
                 site: cl.site || '—', status: cl.status || 'unknown', monitored: !!isMon, btn };
    });
    const clientCols = [
        { label: 'Client',  render: r => `<span class="text-sm">${csEscape(r.host)}</span>`, sort: r => r.host },
        { label: 'IP',      render: r => `<span class="font-mono text-xs">${csEscape(r.ip)}</span>`, sort: r => r.ip },
        { label: 'MAC',     render: r => `<span class="font-mono text-xs">${csEscape(r.mac)}</span>`, sort: r => r.mac },
        { label: 'Site',    render: r => `<span class="text-slate-500">${csEscape(r.site)}</span>`, sort: r => r.site },
        { label: 'Status',  render: r => csStatusBadge(r.status), sort: r => String(r.status || '') },
        { label: 'Monitor', render: r => r.btn, sort: r => r.monitored ? 1 : 0 },
    ];
    csSet(`<div class="space-y-4">${warn}<div class="hpe-card rounded-lg p-4 shadow-sm">${csCentralTable('central-clients', clientCols, rows, { monitorOf: r => r.monitored, caption: `${clients.length} client(s)` })}</div></div>`);
}

// ── Central → Hardware (device-down check types) ─────────────────────────────
// Lists the monitorable hardware checks (AP/Switch/Gateway Down) from the
// available-checks catalog with a Monitor toggle -> central_sites_config
// .hardware_checks (SEPARATE from monitored_checks). The poller consumes
// hardware_checks to produce the dashboard Hardware alerts.
let _csCentralAvailCache = null, _csCentralAvailAt = 0, _csCentralAvailTenant = null;
async function csCentralAvailable() {
    const t = csTenant();
    if (_csCentralAvailCache && _csCentralAvailTenant === t && (Date.now() - _csCentralAvailAt) < 60000) return _csCentralAvailCache;
    let cat;
    try { cat = await csFetch(`/${t}/central/available?tenant_id=${t}`) || {}; }
    catch (e) { console.error('csCentralAvailable: fetch failed', e); cat = { warning: String(e && e.message || e) }; }
    _csCentralAvailCache = cat; _csCentralAvailAt = Date.now(); _csCentralAvailTenant = t;
    return cat;
}

async function csRenderCentralHardware() {
    csSetToolbar('');
    const [data, sitesCfg] = await Promise.all([
        csCentralBrowse(),
        csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`).catch(() => ({})),
    ]);
    // Pull ALL hardware devices (APs / switches / gateways) from the browse
    // inventory, flattened across sites.
    const dbs = (data && data.devices_by_site) || {};
    const devices = [];
    Object.keys(dbs).forEach(site => (dbs[site] || []).forEach(d => devices.push(Object.assign({ site }, d))));
    const warn = _csCentralWarn(data);
    if (!devices.length) { csSet(`${warn}${csEmpty('No Central hardware devices returned.', 'Devices (APs, switches, gateways) come from Central for your monitored account.')}`); return; }
    const monSet = new Set((Array.isArray(sitesCfg && sitesCfg.hardware_checks) ? sitesCfg.hardware_checks : []).map(c => `${c.id}::${c.site || ''}`));
    const rows = devices.map(d => {
        const id = String((d.serial || d.name) || '').trim();
        const name = d.name || d.serial || id;
        const dt = d.type || '';
        const site = d.site || '';
        const isMon = id && monSet.has(`${id}::${site}`);
        const btn = !id ? '—' : (isMon
            ? `<button onclick="csToggleMonitorHardware(${csEscape(JSON.stringify(id))}, ${csEscape(JSON.stringify(name))}, ${csEscape(JSON.stringify(dt))}, ${csEscape(JSON.stringify(site))}, false)" class="bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-emerald-100" title="Stop monitoring this device">✓ Monitored</button>`
            : `<button onclick="csToggleMonitorHardware(${csEscape(JSON.stringify(id))}, ${csEscape(JSON.stringify(name))}, ${csEscape(JSON.stringify(dt))}, ${csEscape(JSON.stringify(site))}, true)" class="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-bold hover:bg-slate-200" title="Monitor this device (alerts on the dashboard when it goes down)">Monitor</button>`);
        return { name, type: dt || '—', model: d.model || '—', site: site || '—',
                 status: d.status || 'unknown', monitored: !!isMon, btn };
    });
    const hwCols = [
        { label: 'Device',  render: r => `<span class="text-sm text-slate-700">${csEscape(r.name)}</span>`, sort: r => r.name },
        { label: 'Type',    render: r => `<span class="text-slate-500">${csEscape(r.type)}</span>`, sort: r => r.type },
        { label: 'Model',   render: r => `<span class="text-slate-500 text-xs">${csEscape(r.model)}</span>`, sort: r => r.model },
        { label: 'Site',    render: r => `<span class="text-slate-500">${csEscape(r.site)}</span>`, sort: r => r.site },
        { label: 'Status',  render: r => csStatusBadge(r.status), sort: r => String(r.status || '') },
        { label: 'Monitor', render: r => r.btn, sort: r => r.monitored ? 1 : 0 },
    ];
    csSet(`<div class="space-y-4">${warn}<div class="hpe-card rounded-lg p-4 shadow-sm">${csCentralTable('central-hardware', hwCols, rows, { monitorOf: r => r.monitored, caption: `${devices.length} device(s) — Monitor a switch / AP / gateway to track it on the dashboard` })}</div></div>`);
}

// Toggle a hardware check in central_sites_config.hardware_checks (keyed by id),
// preserving site_mappings + monitored_checks.
window.csToggleMonitorHardware = async function (id, name, deviceType, site, monitor) {
    try {
        const cfg = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`) || {};
        site = site || '';
        const key = `${id}::${site}`;
        let hw = (Array.isArray(cfg.hardware_checks) ? cfg.hardware_checks : []).filter(c => `${c.id}::${c.site || ''}` !== key);
        if (monitor) hw.push({ id, name, device_type: deviceType, site });
        const body = {
            site_mappings: (cfg.site_mappings && typeof cfg.site_mappings === 'object') ? cfg.site_mappings : {},
            monitored_checks: Array.isArray(cfg.monitored_checks) ? cfg.monitored_checks : [],
            hardware_checks: hw,
        };
        const r = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        if (typeof csPushToast === 'function') csPushToast(r, monitor ? `Monitoring ${name}` : `Stopped monitoring ${name}`);
        else if (typeof showToast === 'function') showToast(monitor ? `Monitoring ${name}` : `Stopped monitoring ${name}`, 'success');
        csRenderCentralHardware();
    } catch (e) {
        console.error('csToggleMonitorHardware failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
};

window.CS_CHILD_RENDERERS['Central::Sites']    = csRenderCentral;
window.CS_CHILD_RENDERERS['Central::Alerts']   = csRenderCentralAlerts;
window.CS_CHILD_RENDERERS['Central::Insights'] = csRenderCentralInsights;
window.CS_CHILD_RENDERERS['Central::Clients']  = csRenderCentralClients;
window.CS_CHILD_RENDERERS['Central::Hardware'] = csRenderCentralHardware;

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
      <button onclick="csSaveConfigPush()" class="mt-3 bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-5 py-2 rounded-md text-sm font-bold shadow-sm">Push Config</button>
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
    // Config Source of Truth (Hub vs GitHub) — drives the toggle + read-only gate.
    let srcCfg = null;
    try { srcCfg = await csFetch(`/${csTenant()}/config/source`); }
    catch (e) { srcCfg = { source: 'github', has_token: false, writable: true }; }
    const cfgSource = (srcCfg && srcCfg.source) || 'github';
    const cfgWritable = !!(srcCfg && srcCfg.writable);

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
          <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Per-simulation profiles [s0]–[s9]</p>
          ${bucketCards}
          ${extras.length ? `<p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-3 mb-2">Extra sections</p>${extraBlocks}` : ''}
          <details class="mt-3 text-xs"><summary class="cursor-pointer text-slate-400">Raw merged simulation.conf</summary><pre class="mt-2 p-2 bg-slate-50 rounded font-mono text-[11px] whitespace-pre-wrap break-all">${csEscape(raw)}</pre></details>`;
    }
    const simCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex flex-wrap justify-between items-center mb-3 gap-2">
        <div class="flex items-center gap-2">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Simulation Config ${helpIcon('cs', null, 'Simulations help')}</h3>
          ${cfgSource === 'hub'
            ? '<span class="inline-block bg-emerald-100 text-emerald-700 rounded-full px-2 py-0.5 text-[10px] font-bold">Hub-owned (GitHub sync ignored)</span>'
            : (cfgWritable
              ? '<span class="inline-block bg-[#01A982]/10 text-[#01A982] border border-[#01A982] rounded-full px-2 py-0.5 text-[10px] font-bold">GitHub-managed (commits on save)</span>'
              : '<span class="inline-block bg-amber-100 text-amber-700 rounded-full px-2 py-0.5 text-[10px] font-bold">GitHub-managed — READ-ONLY (no API key)</span>')}
          ${simSource === 'spoke' ? '' : (simConnected
            ? '<span class="inline-block bg-amber-100 text-amber-700 rounded-full px-2 py-0.5 text-[10px] font-bold">spoke online — live config fetch timed out, showing stored override</span>'
            : '<span class="inline-block bg-amber-100 text-amber-700 rounded-full px-2 py-0.5 text-[10px] font-bold">spoke offline — showing stored override</span>')}
        </div>
        <span class="text-[10px] text-slate-400">Last fetched: ${csEscape(fetchedSim)}</span>
      </div>
      <p class="text-xs text-slate-400 mb-3">Edit the labeled fields. Saved as the hub-managed <code>sim_conf_override</code> INI and pushed to the spoke (merged on top of the repo's simulation.conf). Clearing a field reverts it to the repo default.</p>
      <div id="cs-ini-sections">${simBody}</div>
      <div class="flex justify-end items-center gap-3 mt-4">
        <button onclick="csSaveSimConfStructured()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save</button>
        <button onclick="csRenderConfigSimulation()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-4 py-2 rounded-md text-sm font-bold">Refresh</button>
      </div>
    </div>`;

    // ── User overrides card ─────────────────────────────────────────────────
    const uoCard = csRenderUserOverridesCard(uo, uoErr);

    // ── Hub config card (kept at the bottom) ────────────────────────────────
    let hubCard = '';
    try { hubCard = await csHubConfigCard('/tenant/' + csTenant() + '/hub-config'); }
    catch (e) { console.error('csRenderConfigSimulation: hub-config load failed', e); hubCard = `<div class="hpe-card rounded-lg p-5 shadow-sm">${csErrorBox('Hub Config', e).replace('py-10', 'py-6')}</div>`; }
    // Source of Truth toggle (top) + read-only wrapper for the conf editors when
    // GitHub-managed with no API key. The Hub Config card stays editable (it's
    // central/notification config, not the simulation.conf files).
    const sotCard = csConfigSourceCard(cfgSource, srcCfg);
    const roBanner = cfgWritable ? '' :
        `<div class="rounded-lg border border-amber-200 bg-amber-50 text-amber-800 text-xs px-4 py-2">GitHub is the source of truth and no API key is configured — the config below is read-only. Add a GitHub API key (Setup → GitHub) or switch Source of Truth to Hub.</div>`;
    const roWrap = cfgWritable ? '' : 'pointer-events-none opacity-60 select-none';
    csSet(`<div class="space-y-4">${sotCard}${roBanner}<div class="${roWrap} space-y-4">${simCard}${uoCard}</div>${hubCard}</div>`);
}

// ── Config → Sim Quotas sub-tab ────────────────────────────────────────────
// Declares alert/insight → simulation linkage + the per-site client quota
// the SimQuotaEngine (Chunk 2) keeps filled from the online pool. Renders
// against the cs spoke's /sim-quota-catalog (sims + sites derived from this
// tenant's simulation.conf + the global suggested linkage). Save is a
// GET-merge-POST on central-sites-config so site_mappings / monitored_checks /
// hardware_checks are preserved (mirrors csToggleMonitorCheck). The server
// re-validates + dedups and returns the cleaned rows, which we adopt.
let csSimQuotaCatalog = null;       // {sims, sites, suggested, meta}
let csSimQuotaRows = [];            // working set of quota rows
let csSimQuotaMonitored = [];       // monitored_checks → {type,id,name,site} for the ID dropdown

async function csRenderConfigSimQuotas() {
    csSetToolbar('');
    try {
        const [cat, cfg] = await Promise.all([
            csFetch(`/${csTenant()}/sim-quota-catalog?tenant_id=${csTenant()}`).catch(() => null),
            csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`).catch(() => ({})),
        ]);
        csSimQuotaCatalog = cat || { sims: [], sites: [], suggested: {}, meta: {} };
        // Monitored alerts/insights (Central → Alerts/Insights → Monitor) are the
        // source for the row's Alert / Insight ID dropdown — a quota is linked to
        // an alert/insight the tenant actually monitors.
        csSimQuotaMonitored = Array.isArray(cfg && cfg.monitored_checks)
            ? cfg.monitored_checks.filter(c => c && c.id).map(c => ({
                  type: c.type || 'alert', id: String(c.id),
                  name: c.name || c.id, site: c.site || '',
              })) : [];
        const quotas = Array.isArray(cfg && cfg.sim_quotas) ? cfg.sim_quotas : [];
        csSimQuotaRows = quotas.map(csSimQuotaRowFromServer);
        csRenderSimQuotaEditor();
    } catch (e) {
        console.error('csRenderConfigSimQuotas: load failed', e);
        csSet(csErrorBox('Could not load Sim Quotas', e));
    }
}

function csSimQuotaRowFromServer(q) {
    return {
        alert_type: q.alert_type || 'alert',
        alert_id: q.alert_id || '',
        sim_id: q.sim_id || '',
        count: q.count != null ? q.count : 10,
        site: q.site || '',
        multi_capable: !!q.multi_capable,
        rehome: !!q.rehome,
        enabled: !!q.enabled,
    };
}

function csSimQuotaSelect(selected, items, placeholder) {
    return `<option value="">${csEscape(placeholder)}</option>` +
        items.map(it => `<option value="${csEscape(it)}" ${it === selected ? 'selected' : ''}>${csEscape(it)}</option>`).join('');
}

// Simulation dropdown options for a quota row: a leading "(Clients Associated)"
// PRESENCE option (value "") — homes N clients to the site, runs no sim — then
// the runnable sim primitives. Selecting presence hides the row's Type / Alert
// ID (a presence quota has no alert) and forces multi-capable (a homed-but-
// sim-less client is still a free runner other sims may stack onto).
function csSimQuotaSimOptions(selected, simIds) {
    const pres = '<option value=""' + (selected === '' ? ' selected' : '') +
        '>Clients Associated (no sim)</option>';
    return pres + simIds.map(it =>
        `<option value="${csEscape(it)}" ${it === selected ? 'selected' : ''}>${csEscape(it)}</option>`).join('');
}

// Alert / Insight ID dropdown options for a row: the monitored checks matching
// the row's alert_type (alert vs insight), labeled "name — id". A saved
// alert_id that's no longer monitored is kept as a trailing option so it isn't
// silently dropped on re-render.
function csSimQuotaAlertIdOptions(alertType, selectedId) {
    const opts = [];
    const seen = new Set();
    (csSimQuotaMonitored || []).forEach(c => {
        if (c.type !== alertType || !c.id || seen.has(c.id)) return;
        seen.add(c.id);
        const label = c.name && c.name !== c.id ? `${c.name} — ${c.id}` : c.id;
        opts.push({ id: c.id, label, selected: c.id === selectedId });
    });
    if (selectedId && !seen.has(selectedId)) {
        opts.push({ id: selectedId, label: `${selectedId} (not monitored)`, selected: true });
    }
    const ph = opts.length ? '— select alert/insight —' : '— monitor an alert/insight first —';
    return `<option value="">${csEscape(ph)}</option>` +
        opts.map(o => `<option value="${csEscape(o.id)}" ${o.selected ? 'selected' : ''}>${csEscape(o.label)}</option>`).join('');
}

function csRenderSimQuotaEditor() {
    const cat = csSimQuotaCatalog || { sims: [], sites: [], suggested: {}, meta: {} };
    const simIds = (cat.sims || []).map(s => s.sim_id);
    const sites = cat.sites || [];
    const meta = cat.meta || {};
    const suggested = cat.suggested || {};
    const rowHtml = csSimQuotaRows.map((r, i) => {
        const isPresence = !r.sim_id;
        const simOpts = csSimQuotaSimOptions(r.sim_id, simIds);
        const siteOpts = csSimQuotaSelect(r.site, sites, '— all sites —');
        const idOpts = csSimQuotaAlertIdOptions(r.alert_type, r.alert_id);
        const alertCell = isPresence
            ? `<label class="text-xs text-slate-500" data-cs-sq-presence-note>Presence
                <div class="text-[11px] text-slate-400 italic mt-1 leading-tight">Homes N clients to the site — no sim. They stay free for stackable sims.</div>
              </label>`
            : `<label class="text-xs text-slate-500">Type
                <select data-cs-sq="alert_type" onchange="csSimQuotaOnTypeChange(this)" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm mt-1">
                  <option value="alert" ${r.alert_type === 'alert' ? 'selected' : ''}>Alert</option>
                  <option value="insight" ${r.alert_type === 'insight' ? 'selected' : ''}>Insight</option>
                </select>
              </label>`;
        const idCell = isPresence
            ? `<label class="text-xs text-slate-500">Alert / Insight ID
                <div class="text-[11px] text-slate-400 italic mt-1 leading-tight">— none (presence) —</div>
              </label>`
            : `<label class="text-xs text-slate-500">Alert / Insight ID
                <select data-cs-sq="alert_id" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm mt-1">${idOpts}</select>
              </label>`;
        return `<div class="grid grid-cols-1 md:grid-cols-7 gap-2 items-end bg-white border border-slate-200 rounded-md p-2" data-cs-sqrow="${i}">
          ${alertCell}
          ${idCell}
          <label class="text-xs text-slate-500">Simulation
            <select data-cs-sq="sim_id" onchange="csSimQuotaOnSimChange(this)" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm mt-1">${simOpts}</select>
          </label>
          <label class="text-xs text-slate-500">Clients
            <input data-cs-sq="count" type="number" min="1" value="${csEscape(String(r.count))}" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm mt-1">
          </label>
          <label class="text-xs text-slate-500">Site
            <select data-cs-sq="site" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm mt-1">${siteOpts}</select>
          </label>
          <label class="text-xs text-slate-500 flex flex-col gap-1">
            <span class="flex items-center gap-1"><input data-cs-sq="multi_capable" type="checkbox" ${isPresence ? 'checked disabled' : (r.multi_capable ? 'checked' : '')}> Multi-capable</span>
            <span class="flex items-center gap-1"><input data-cs-sq="rehome" type="checkbox" ${r.rehome ? 'checked' : ''}> Re-home</span>
            <span class="flex items-center gap-1"><input data-cs-sq="enabled" type="checkbox" ${r.enabled ? 'checked' : ''}> Enabled</span>
          </label>
          <button onclick="csSimQuotaDel(${i})" class="text-red-600 hover:text-red-800 text-xs font-bold py-1">Remove</button>
        </div>`;
    }).join('');
    const suggestHtml = Object.keys(suggested).length ? `
        <details class="text-xs text-slate-500 mt-2">
          <summary class="cursor-pointer">Suggested alert → sim linkage</summary>
          <ul class="mt-1 list-disc list-inside space-y-0.5">
            ${Object.entries(suggested).map(([a, s]) => `<li><span class="font-mono">${csEscape(a)}</span> → <span class="font-mono">${csEscape(s)}</span> <button onclick="csSimQuotaAddSuggested('${csEscape(a)}','${csEscape(s)}')" class="text-[#01A982] hover:underline ml-1">add</button></li>`).join('')}
          </ul>
        </details>` : '';
    csSet(`<div class="space-y-4">
      <div class="hpe-card rounded-lg p-5 shadow-sm">
        <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Sim Quotas ${helpIcon('cs', null, 'Simulations help')}</h3>
          <div class="flex gap-2">
            <button onclick="csSimQuotaAdd()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold shadow-sm">+ Add Quota</button>
            <button onclick="csSimQuotaSave()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold shadow-sm">Save Quotas</button>
          </div>
        </div>
        <p class="text-xs text-slate-500 mb-2">Link a monitored alert or insight (Central → Alerts/Insights → Monitor) to the simulation that produces it, then set how many online clients the engine keeps running that sim in the chosen site. The engine auto-selects from the online pool and self-heals when a runner dies. <span class="font-semibold">Re-home</span> lets it borrow runners from other sites (re-homing their <span class="font-mono">wsite</span>) when this site's pool can't fill the count. Sims + sites come from this tenant's <span class="font-semibold">Config Editor</span> (simulation.conf) and Central site mappings.</p>
        ${suggestHtml}
        <div class="space-y-2 mt-2" id="cs-sq-rows">${rowHtml || '<div class="text-xs text-slate-400 italic">No quotas defined. Add one or pick a suggested linkage above.</div>'}</div>
      </div>
    </div>`);
}

// Read the working rows back from the DOM so Add/Remove/Suggest keep current
// edits without forcing a save first.
function csSimQuotaSyncFromDom() {
    const rows = [];
    document.querySelectorAll('[data-cs-sqrow]').forEach(el => {
        const g = (k) => el.querySelector(`[data-cs-sq="${k}"]`);
        // A presence row (Clients Associated) has no Type / Alert ID controls
        // (they're replaced by static labels) — nullish-guard so the sync
        // doesn't throw and preserves alert_type/alert_id defaults.
        rows.push({
            alert_type: (g('alert_type') || {}).value || 'alert',
            alert_id: ((g('alert_id') || {}).value || '').trim(),
            sim_id: g('sim_id').value,
            count: parseInt(g('count').value || '1', 10) || 1,
            site: g('site').value,
            multi_capable: !!g('multi_capable').checked,
            rehome: !!g('rehome').checked,
            enabled: !!g('enabled').checked,
        });
    });
    csSimQuotaRows = rows;
    return rows;
}

window.csSimQuotaAdd = function (preset) {
    csSimQuotaSyncFromDom();
    const p = preset || {};
    csSimQuotaRows.push({
        alert_type: p.alert_type || 'alert',
        alert_id: p.alert_id || '',
        sim_id: p.sim_id || '',
        count: p.count != null ? p.count : 10,
        site: p.site || '',
        multi_capable: p.multi_capable != null ? !!p.multi_capable : false,
        rehome: p.rehome != null ? !!p.rehome : false,
        enabled: p.enabled != null ? !!p.enabled : false,
    });
    csRenderSimQuotaEditor();
};

// Repopulate the Alert / Insight ID dropdown when the row's Type flips between
// alert and insight (the monitored-check list is type-scoped). Preserves the
// current selection if it's still valid for the new type.
window.csSimQuotaOnTypeChange = function (typeSel) {
    const row = typeSel.closest('[data-cs-sqrow]');
    if (!row) return;
    const idSel = row.querySelector('[data-cs-sq="alert_id"]');
    if (!idSel) return;
    const cur = idSel.value;
    idSel.innerHTML = csSimQuotaAlertIdOptions(typeSel.value, cur);
};

// Toggling the Simulation dropdown between a real sim and "(Clients
// Associated)" (presence) flips the row's Type / Alert ID visibility and
// forces multi-capable for presence. Re-renders the editor (current edits are
// synced from the DOM first so nothing is lost).
window.csSimQuotaOnSimChange = function (simSel) {
    csSimQuotaSyncFromDom();
    csRenderSimQuotaEditor();
};

window.csSimQuotaAddSuggested = function (alertId, simId) {
    csSimQuotaAdd({ alert_id: alertId, sim_id: simId, count: 10 });
};

window.csSimQuotaDel = function (i) {
    csSimQuotaSyncFromDom();
    csSimQuotaRows.splice(i, 1);
    csRenderSimQuotaEditor();
};

window.csSimQuotaSave = async function () {
    const rows = csSimQuotaSyncFromDom();
    try {
        const cfg = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`) || {};
        const body = {
            site_mappings: (cfg.site_mappings && typeof cfg.site_mappings === 'object') ? cfg.site_mappings : {},
            monitored_checks: Array.isArray(cfg.monitored_checks) ? cfg.monitored_checks : [],
            hardware_checks: Array.isArray(cfg.hardware_checks) ? cfg.hardware_checks : [],
            sim_quotas: rows,
        };
        const r = await csFetch(`/${csTenant()}/central-sites-config?tenant_id=${csTenant()}`, { method: 'POST', body: JSON.stringify(body) });
        // Server re-validates + dedups; adopt its cleaned rows so the UI matches.
        const clean = Array.isArray(r && r.sim_quotas) ? r.sim_quotas : rows;
        const errs = Array.isArray(r && r.sim_quota_errors) ? r.sim_quota_errors : [];
        csSimQuotaRows = clean.map(csSimQuotaRowFromServer);
        csRenderSimQuotaEditor();
        if (errs.length) showToast(`Saved with ${errs.length} issue(s): ${errs.join('; ')}`, 'error');
        else showToast('Sim quotas saved.', 'success');
    } catch (e) {
        console.error('csSimQuotaSave: save failed', e);
        showToast(e.message, 'error');
    }
};

// ── Quota State: live SimQuotaEngine ledger (Config → Quota State) ──────────
// Read-only view of which clients the engine currently has assigned to each
// effective quota, the target vs. assigned count, and the multi_capable /
// rehome flags. Manual-refresh under Config (shares the Config primary's
// no-auto-refresh). Mirrored in both sim-views.js copies (hub + spoke).
async function csRenderSimQuotaState() {
    csSetToolbar('');
    try {
        const st = await csFetch(`/${csTenant()}/sim-quota-state?tenant_id=${csTenant()}`) || {};
        if (st.warning) {
            csSet(`<div class="hpe-card p-5 shadow-sm"><p class="text-xs text-slate-500">${csEscape(st.warning)}</p></div>`);
            return;
        }
        const eff = Array.isArray(st.effective) ? st.effective : [];
        const ledger = (st.ledger && typeof st.ledger === 'object') ? st.ledger : {};
        // Mirrors the engine's _quota_key / sim_quota.quota_dedup_key: a
        // presence quota (sim_id empty — "Clients Associated") is keyed by site
        // alone (presence::MIA), not alert_type:alert_id:site, so it joins the
        // ledger's presence entry instead of a phantom alert row.
        const keyOf = (q) => !q.sim_id
            ? `presence::${q.site || ''}`
            : `${q.alert_type || 'alert'}:${q.alert_id || ''}:${q.site || ''}`;
        // Join alert/insight IDs to their friendly names via the monitored_checks
        // slice the spoke returns alongside the ledger (a quota row stores only
        // the bare id). Falls back to the id when no monitored check matches.
        const mc = Array.isArray(st.monitored_checks) ? st.monitored_checks : [];
        const nameOf = (type, id) => {
            const t = type || 'alert', i = String(id || '');
            const hit = mc.find(c => c && String(c.id) === i && (c.type || 'alert') === t);
            return hit && hit.name ? hit.name : '';
        };
        const chips = (hosts) => (hosts || []).map(h =>
            `<span class="inline-block bg-slate-100 text-slate-700 rounded px-1.5 py-0.5 mr-1 mb-1 font-mono text-[11px]">${csEscape(h)}</span>`).join('');
        const rows = eff.map(q => {
            const k = keyOf(q);
            const e = ledger[k] || {};
            const clients = Array.isArray(e.clients) ? e.clients : [];
            const target = q.count != null ? q.count : 0;
            const fill = clients.length >= target
                ? `<span class="text-[#01A982] font-semibold">${clients.length}/${target}</span>`
                : `<span class="text-amber-600 font-semibold">${clients.length}/${target}</span>`;
            const fname = nameOf(q.alert_type, q.alert_id);
            const isPresence = !q.sim_id;
            const idCell = isPresence
                ? `<span class="text-slate-700 italic">Clients Associated</span>`
                : (fname
                    ? `<span class="text-slate-700">${csEscape(fname)}</span> <span class="font-mono text-slate-400 text-[11px]">${csEscape(q.alert_id || '')}</span>`
                    : `<span class="font-mono">${csEscape(q.alert_id || '')}</span>`);
            const typeCell = isPresence ? 'presence' : (q.alert_type || 'alert');
            const simCell = isPresence
                ? `<span class="italic text-slate-400">— none —</span>`
                : `<span class="font-mono">${csEscape(q.sim_id || '')}</span>`;
            return `<tr class="border-t border-slate-100">
              <td class="px-2 py-1.5 text-xs capitalize">${csEscape(typeCell)}</td>
              <td class="px-2 py-1.5 text-xs">${idCell}</td>
              <td class="px-2 py-1.5 text-xs">${simCell}</td>
              <td class="px-2 py-1.5 text-xs">${csEscape(q.site || '<all>')}</td>
              <td class="px-2 py-1.5 text-xs text-center">${fill}</td>
              <td class="px-2 py-1.5 text-xs text-center">${q.multi_capable ? '✓' : '—'}</td>
              <td class="px-2 py-1.5 text-xs text-center">${q.rehome ? '✓' : '—'}</td>
              <td class="px-2 py-1.5 text-xs">${chips(clients) || '<span class="text-slate-400 italic">none</span>'}</td>
            </tr>`;
        }).join('');
        // Ledger entries no longer in the effective set (quota removed but
        // clients not yet released) — surfaced so they're not invisible.
        const effKeys = new Set(eff.map(keyOf));
        const orphans = Object.entries(ledger).filter(([k]) => !effKeys.has(k));
        const orphanHtml = orphans.length ? `
            <div class="mt-4">
              <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Releasing (no longer effective)</p>
              ${orphans.map(([k, e]) => {
                  const parts = k.split(':');
                  const on = nameOf(parts[0], parts[1]);
                  const lbl = on ? `${csEscape(on)} <span class="font-mono text-slate-400">(${csEscape(k)})</span>` : `<span class="font-mono">${csEscape(k)}</span>`;
                  return `<p class="text-xs text-slate-500 mb-1">${lbl} → ${chips(e.clients)}</p>`;
              }).join('')}
            </div>` : '';
        csSet(`<div class="space-y-4">
          <div class="hpe-card rounded-lg p-5 shadow-sm">
            <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
              <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Quota State ${helpIcon('cs', null, 'Simulations help')}</h3>
              <button onclick="csRenderSimQuotaState()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-sm font-bold shadow-sm">↻ Refresh</button>
            </div>
            <p class="text-xs text-slate-500 mb-3">Live SimQuotaEngine ledger — which clients are currently assigned to each effective quota. The engine tops up to the target count from the online pool each 60s sweep; amber = under-filled.</p>
            ${eff.length ? `<table class="w-full text-left">
              <thead><tr class="text-[11px] text-slate-400 uppercase tracking-wider">
                <th class="px-2 py-1">Type</th><th class="px-2 py-1">Alert / Insight ID</th>
                <th class="px-2 py-1">Sim</th><th class="px-2 py-1">Site</th>
                <th class="px-2 py-1 text-center">Assigned</th><th class="px-2 py-1 text-center">Multi</th>
                <th class="px-2 py-1 text-center">Re-home</th><th class="px-2 py-1">Clients</th>
              </tr></thead>
              <tbody>${rows}</tbody>
            </table>` : '<p class="text-xs text-slate-400 italic">No effective sim quotas. Define some in Config → Sim Quotas.</p>'}
            ${orphanHtml}
          </div>
        </div>`);
    } catch (e) {
        console.error('csRenderSimQuotaState: load failed', e);
        csSet(csErrorBox('Could not load Quota State', e));
    }
}

// ── PXMX Sites: assign each connected pxmx server (agent host) to a site ──────
// The SimQuotaEngine resolves a client's site via its hosting server's entry
// here (after a per-client wsite override, before the bucket-default wsite), so
// a site-specific quota ("10 DNS-fail in MIA") fills from clients whose hosting
// server is in MIA. Mirrored in both sim-views.js copies (hub + spoke).
let csPxmxSiteMap = {};
let csPxmxAgents = [];
let csPxmxSites = [];

async function csRenderPxmxSiteMap() {
    csSetToolbar('');
    try {
        const [mapRes, cat] = await Promise.all([
            csFetch(`/${csTenant()}/pxmx-site-map?tenant_id=${csTenant()}`).catch(() => null),
            csFetch(`/${csTenant()}/sim-quota-catalog?tenant_id=${csTenant()}`).catch(() => null),
        ]);
        csPxmxSiteMap = (mapRes && mapRes.pxmx_site_map) || {};
        csPxmxAgents = Array.isArray(mapRes && mapRes.agents) ? mapRes.agents : [];
        csPxmxSites = (cat && cat.sites) || [];
        csRenderPxmxSiteMapEditor();
    } catch (e) {
        console.error('csRenderPxmxSiteMap: load failed', e);
        csSet(csErrorBox('Could not load PXMX site assignments', e));
    }
}

function csRenderPxmxSiteMapEditor() {
    // Rows = every connected agent (so the operator can assign a newly-joined
    // server) PLUS any mapped host not currently connected (so a temporarily-
    // offline server keeps its assignment and is flagged).
    const seen = new Set();
    const rows = [];
    csPxmxAgents.forEach(a => {
        const h = a.agent_id || a.hostname;
        if (!h || seen.has(h)) return;
        seen.add(h);
        rows.push({ host: h, connected: true, last_seen: a.last_seen || 0 });
    });
    Object.keys(csPxmxSiteMap).forEach(h => {
        if (!seen.has(h)) rows.push({ host: h, connected: false, last_seen: 0 });
    });
    rows.sort((a, b) => a.host.localeCompare(b.host));
    const siteOpts = (sel) =>
        `<option value="" ${(!sel) ? 'selected' : ''}>— unassigned —</option>` +
        csPxmxSites.map(s => `<option value="${csEscape(s)}" ${s === sel ? 'selected' : ''}>${csEscape(s)}</option>`).join('');
    const rowHtml = rows.map((r, i) => {
        const sel = csPxmxSiteMap[r.host] || '';
        const badge = r.connected
            ? '<span class="text-emerald-600 text-[10px] font-bold uppercase">connected</span>'
            : '<span class="text-amber-600 text-[10px] font-bold uppercase">offline</span>';
        return `<div class="grid grid-cols-1 md:grid-cols-3 gap-2 items-center bg-white border border-slate-200 rounded-md p-2" data-cs-pxrow="${i}">
          <label class="text-xs text-slate-600 font-mono">${csEscape(r.host)} ${badge}</label>
          <select data-cs-px="site" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm">${siteOpts(sel)}</select>
          <button onclick="csPxmxSiteClear('${csEscape(r.host)}')" class="text-red-600 hover:text-red-800 text-xs font-bold py-1 justify-self-end">Clear</button>
        </div>`;
    }).join('');
    csSet(`<div class="space-y-4">
      <div class="hpe-card rounded-lg p-5 shadow-sm">
        <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">PXMX Site Assignments ${helpIcon('cs', null, 'Simulations help')}</h3>
          <button onclick="csPxmxSiteSave()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold shadow-sm">Save Assignments</button>
        </div>
        <p class="text-xs text-slate-500 mb-2">Assign each pxmx server (the agent host) to a site. The Sim Quota engine fills a site-specific quota from clients whose <span class="font-semibold">hosting server</span> is in that site — e.g. a "MIA" quota draws from clients on MIA-assigned servers. A client's own wsite override still wins; the bucket-default wsite is the fallback. Sites come from <span class="font-semibold">Config Editor</span> (simulation.conf) and Central site mappings.</p>
        <div class="space-y-2 mt-2" id="cs-px-rows">${rowHtml || '<div class="text-xs text-slate-400 italic">No pxmx servers connected and no assignments saved. A server appears here once its agent connects to this spoke.</div>'}</div>
      </div>
    </div>`);
}

window.csPxmxSiteClear = function (host) {
    // Reflect the clear in the DOM select so the subsequent save picks it up.
    document.querySelectorAll('[data-cs-pxrow]').forEach(el => {
        const lbl = el.querySelector('label');
        if (lbl && lbl.textContent.trim().startsWith(host)) {
            const sel = el.querySelector('[data-cs-px="site"]');
            if (sel) sel.value = '';
        }
    });
};

window.csPxmxSiteSave = async function () {
    const map = {};
    document.querySelectorAll('[data-cs-pxrow]').forEach(el => {
        const lbl = el.querySelector('label');
        const sel = el.querySelector('[data-cs-px="site"]');
        if (!lbl || !sel) return;
        // The host is the label's leading text (before the badge span).
        const host = lbl.textContent.trim().split(/\s+/)[0];
        const site = sel.value.trim();
        if (host) map[host] = site;
    });
    try {
        const r = await csFetch(`/${csTenant()}/pxmx-site-map?tenant_id=${csTenant()}`, {
            method: 'POST', body: JSON.stringify({ pxmx_site_map: map }),
        });
        csPxmxSiteMap = (r && r.pxmx_site_map) || map;
        const errs = Array.isArray(r && r.errors) ? r.errors : [];
        csRenderPxmxSiteMapEditor();
        if (errs.length) showToast(`Saved with ${errs.length} issue(s): ${errs.join('; ')}`, 'error');
        else showToast('PXMX site assignments saved.', 'success');
    } catch (e) {
        console.error('csPxmxSiteSave: save failed', e);
        showToast(e.message, 'error');
    }
};

// Source of Truth toggle card (top of the Config screen).
function csConfigSourceCard(source, cfg) {
    cfg = cfg || {};
    const isHub = source === 'hub';
    const hasToken = !!cfg.has_token;
    const repo = cfg.repo_url || '';
    const branch = cfg.repo_branch || 'main';
    const btn = (val, label, active) =>
        `<button onclick="csSetConfigSource('${val}')" class="px-3 py-1.5 rounded-md text-sm font-bold border transition-colors ${active ? 'bg-[#01A982]/10 text-[#01A982] border-[#01A982]' : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50'}">${label}</button>`;
    let status;
    if (isHub) {
        status = '<span class="text-emerald-700">Hub-owned — the GitHub sync is ignored; your edits are authoritative and are never reverted by a repo pull.</span>';
    } else if (hasToken) {
        status = `<span class="text-slate-500">GitHub-managed — edits commit + push to <span class="font-mono">${csEscape(repo || 'the configured repo')}</span> @ <span class="font-mono">${csEscape(branch)}</span>.</span>`;
    } else {
        status = '<span class="text-amber-700 font-semibold">GitHub-managed, no API key — the config is READ-ONLY. Add a key (Setup → GitHub) or switch to Hub.</span>';
    }
    return `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex flex-wrap items-center gap-3">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Source of Truth</h3>
        <div class="flex gap-2">${btn('hub', 'Hub', isHub)}${btn('github', 'GitHub', !isHub)}</div>
      </div>
      <p class="text-xs mt-2">${status}</p>
    </div>`;
}
window.csSetConfigSource = async function (val) {
    try {
        await csFetch(`/${csTenant()}/config/source`, { method: 'POST', body: JSON.stringify({ source: val }) });
        if (typeof showToast === 'function') showToast(`Source of Truth: ${val === 'hub' ? 'Hub' : 'GitHub'}`, 'success');
        csRenderConfigSimulation();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Failed to set source: ' + (e.message || e), 'error');
    }
};

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
        // Collapsible per-user card (the list gets long) — click the header to
        // expand/collapse; default collapsed so the page stays compact. The
        // action buttons stopPropagation so clicking them doesn't toggle.
        return `<div class="border border-slate-200 rounded-lg mb-3">
          <div class="flex items-center justify-between p-3 cursor-pointer select-none" onclick="csUOToggle(this)">
            <span class="text-sm font-bold text-slate-700 flex items-center gap-1.5">
              <span class="cs-uo-chev text-slate-400 inline-block w-3">▸</span>👤 ${csEscape(u)}
              <span class="text-[10px] font-normal text-slate-400">(${cnt} override${cnt === 1 ? '' : 's'})</span>
            </span>
            <div class="flex gap-2" onclick="event.stopPropagation()">
              <button data-uo-user="${csEscape(u)}" onclick="csUODownload(this)"
                      class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-2 py-1 rounded-md text-[11px] font-bold">Download</button>
              <button data-uo-user="${csEscape(u)}" onclick="csUORemove(this)"
                      class="bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded-md text-[11px] font-bold">✕ Remove</button>
            </div>
          </div>
          <div class="cs-uo-body hidden px-3 pb-3">
            <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">${fields || '<p class="text-xs text-slate-400 italic col-span-full">No fields found in this override.</p>'}</div>
          </div>
        </div>`;
    }).join('');
}

// Toggle a per-user override card open/closed (collapsible list).
window.csUOToggle = function (headerEl) {
    const body = headerEl.nextElementSibling;
    if (!body) return;
    body.classList.toggle('hidden');
    const chev = headerEl.querySelector('.cs-uo-chev');
    if (chev) chev.textContent = body.classList.contains('hidden') ? '▸' : '▾';
};

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
      <p class="text-xs text-slate-400 mb-3">Per-user simulation overrides — pin a hostname to specific sim settings (a <code>[username]</code> section overrides the simulation profile for that user).</p>
      <div class="flex items-center gap-3 mb-3">
        <button onclick="csUOAdd()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold">＋ Add User</button>
        <button onclick="csUOSave()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold">Save</button>
      </div>
      <div id="cs-uo-cards">${csUORenderCards()}</div>
      <div class="flex justify-end mt-3">
        <button onclick="csRenderConfigSimulation()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-3 py-1.5 rounded-md text-sm font-bold">Refresh</button>
      </div>
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

// Config has no sub-tabs now (the former "Simulation" tab is the Config root,
// rendered by `case 'Config'` → csRenderConfigSimulation; the "API" tab was
// dropped). csRenderConfig (the old API-tab content) is retained but no longer
// registered as a child renderer.

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
    // ── List fields: comma- or space-delimited in the UI; the hub normalizes
    // to a list before storing/pushing (see normalize_hub_config_lists in
    // core/src/simulations/routes.py). No raw JSON to paste. usb_vidpids is a
    // list of {vidpid,type,label}; only the vidpid is needed here — type/label
    // already stored for a vidpid are preserved on save.
    { key: 'usb_vidpids',                 label: 'USB Certified VID:PIDs',  type: 'list', obj: true, ph: '1a2b:3c4d, 5678:9abc  (comma or space separated)', full: true },
    { key: 'usb_ignored_vidpids',         label: 'USB Ignored VID:PIDs', type: 'list', ph: '1a2b:3c4d, 5678:9abc  (comma or space separated)', full: true },
    { key: 't1_pci_vidpids',              label: 'T1 PCI VID:PIDs (VM whose PCI passthrough matches → T1)', type: 'list', ph: '1912:0015, 168c:0034  (comma or space separated)', full: true },
    { key: 't3_pci_vidpids',              label: 'T3 PCI VID:PIDs (VM whose PCI passthrough matches → T3)', type: 'list', ph: '168c:0034  (comma or space separated)', full: true },
    { key: 'ignored_hostnames',           label: 'Ignored Hostnames', type: 'list', ph: 'sim-rpi-0000, sim-rpi-0001  (comma or space separated)', full: true },
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

// Render a stored list field (array OR JSON-array string OR legacy delimited
// string) as a comma-separated display string for the Setup/Proxmox list inputs.
// usb_vidpids (obj=true) is a list of {vidpid,type,label} — only vidpid is shown
// (type/label are preserved on save by the backend). The user edits the
// comma/space-delimited text; the hub normalizes it back to a list.
function _csListDisplay(valRaw, isObj) {
    let arr = valRaw;
    if (typeof valRaw === 'string') {
        const s = valRaw.trim();
        if (!s) return '';
        if (s.startsWith('[')) {
            try { arr = JSON.parse(s); } catch (e) { arr = null; }
        } else {
            return s;   // already a delimited string
        }
    }
    if (!Array.isArray(arr) || !arr.length) return '';
    if (isObj) {
        return arr.map(it => (it && typeof it === 'object') ? (it.vidpid || '') : String(it))
                   .filter(Boolean).join(', ');
    }
    return arr.map(it => String(it)).join(', ');
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
        else if (col.type === 'list') {
            // Comma/space-delimited text; backend normalize_hub_config_lists converts to a list.
            const disp = _csListDisplay(valRaw, !!col.obj);
            input = `<input id="cs-hc-${col.key}" type="text" value="${csEscape(disp)}" placeholder="${csEscape(col.ph || '')}" onblur="csSaveHubConfig()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
        } else input = `<input id="cs-hc-${col.key}" type="text" value="${csEscape(valStr)}" placeholder="${csEscape(col.ph || '')}" onblur="csSaveHubConfig()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">`;
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
    // Mirror webui-hub saveHubConfig: skip empty fields; list fields are sent as
    // the raw comma/space-delimited string and the hub normalizes them to lists
    // (normalize_hub_config_lists); scalars (incl. numbers) are sent as strings —
    // the spoke stores them as-is and normalizes the on/off keys via
    // _normalize_relay_enabled.
    const config = {};
    CS_HUB_CONFIG_FIELDS.forEach(col => {
        const el = csEl('cs-hc-' + col.key);
        if (!el) return;
        const v = (el.value || '').trim();
        if (!v) return;
        if (col.type === 'list') {
            config[col.key] = v;   // delimited string — backend converts to a list
        } else if (col.type === 'json') {
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
      <div class="flex justify-end mt-4"><button onclick="csSaveProcessingModes()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Modes</button></div>
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
      <button onclick="csSaveNotifications()" class="mt-4 bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-5 py-2 rounded-md text-sm font-bold shadow-sm">Save Notifications</button>
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
 *     Notifications. The 'General' overview child is
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
    // Site-mapping <select>s seed SYNCHRONOUSLY from the existing mappings so the
    // form renders instantly (no blocking on the slow Central browse). The full
    // option lists (discovered Central sites + simulated wireless sites) are
    // refreshed in place AFTER render by _csRefreshSiteSelects — no re-render,
    // so an open dropdown doesn't flash/close and each row keeps its selection.
    const _wirelessSites = Object.keys(sm);
    const _discoveredSites = Array.from(new Set(Object.values(sm).filter(Boolean)));
    window._csWirelessSites = _wirelessSites.slice();
    window._csCentralSites = _discoveredSites.slice();
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
      <div class="flex justify-end gap-2 mt-4">
        <button onclick="csSaveCentralConn()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Save Connection</button>
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
      ${_discoveredSites.length ? `<p class="text-[10px] text-slate-400 mb-1">${_discoveredSites.length} Central site(s) discovered — pick from the dropdown (refreshes as more are found).</p>` : '<p class="text-[10px] text-slate-400 mb-1">No Central sites discovered yet (check the connection); the dropdown lists discovered sites once loaded.</p>'}
      <div id="cs-csc-sm-rows" class="space-y-2">${smRows || '<p class="text-xs text-slate-400 italic">No site mappings.</p>'}</div>
      <button onclick="csCscAddSm()" class="mt-2 text-xs text-[#01A982] font-bold hover:underline">+ Add mapping</button>

      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-4 mb-1">Monitored Checks</p>
      <div id="cs-csc-monitored">${mcList}</div>

      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-4 mb-1">Hardware Checks</p>
      <div id="cs-csc-hw-rows" class="space-y-2">${hwRows || '<p class="text-xs text-slate-400 italic">No hardware checks.</p>'}</div>
      <button onclick="csCscAddHw()" class="mt-2 text-xs text-[#01A982] font-bold hover:underline">+ Add hardware check</button>

      <div class="flex justify-end gap-2 mt-4">
        <button onclick="csSaveCentralSites()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Save Sites &amp; Checks</button>
      </div>
    </div>`;

    csSet(`<div class="max-w-4xl space-y-4">${connCard}${sitesCard}</div>`);
    // Refresh the site-mapping <select> options AFTER the form is on screen —
    // rewrites each row's options in place (no re-render), so a dropdown stays
    // open and each row keeps its selection. Fire-and-forget; the slow Central
    // browse can't block the tab.
    _csRefreshSiteSelects();
}

// Build <option> markup for a site <select>: a blank "— select —" first, then
// every known site, with `current` always present and selected (so an existing
// mapping to a site not in the discovered list still shows). Sorted for stable
// display.
function _csSiteOptions(list, current) {
    const set = new Set((list || []).filter(Boolean));
    if (current) set.add(current);
    const opts = Array.from(set).sort();
    const cur = current || '';
    return [`<option value=""${cur === '' ? ' selected' : ''}>— select —</option>`]
        .concat(opts.map(o => `<option value="${csEscape(o)}"${o === cur ? ' selected' : ''}>${csEscape(o)}</option>`))
        .join('');
}

// Refresh the site-mapping <select> options AFTER render: fetch the full
// wireless + Central site lists, merge into the window globals, then rewrite
// each row's <select> options in place (preserving its current selection). No
// re-render, so an open dropdown doesn't flash/close.
async function _csRefreshSiteSelects() {
    // Wireless sites (fast, local): connected clients' config.wsite.
    try {
        const cl = await csFetch(`/aggregate/clients?tenant_id=${csTenant()}`) || {};
        const rows = cl.clients || cl.rows || [];
        const found = rows.map(c => (c.config && c.config.wsite) || c.wsite).filter(Boolean);
        window._csWirelessSites = Array.from(new Set((window._csWirelessSites || []).concat(found))).sort();
    } catch (e) { /* clients optional */ }
    // Central sites (slower: forwards to the spoke's Central browse).
    try {
        const b = await csCentralBrowse();
        const found = ((b && b.sites) || []).map(s => s && s.name).filter(Boolean);
        window._csCentralSites = Array.from(new Set((window._csCentralSites || []).concat(found))).sort();
    } catch (e) { /* browse optional */ }
    document.querySelectorAll('#cs-csc-sm-rows .cs-csc-sm-row').forEach(row => {
        const wSel = row.querySelector('[data-cs-sm-w]');
        const cSel = row.querySelector('[data-cs-sm-c]');
        if (wSel) { const cur = wSel.value; wSel.innerHTML = _csSiteOptions(window._csWirelessSites, cur); wSel.value = cur; }
        if (cSel) { const cur = cSel.value; cSel.innerHTML = _csSiteOptions(window._csCentralSites, cur); cSel.value = cur; }
    });
}

function csCscSmRow(w, c) {
    const selCls = 'flex-1 bg-white border border-slate-300 rounded-md px-2 py-1.5 text-xs text-slate-700 outline-none focus:ring-2 focus:ring-green-500';
    return `<div class="cs-csc-sm-row flex gap-2 items-center">
      <select data-cs-sm-w class="${selCls}">${_csSiteOptions(window._csWirelessSites, w)}</select>
      <span class="text-slate-400">→</span>
      <select data-cs-sm-c class="${selCls}">${_csSiteOptions(window._csCentralSites, c)}</select>
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
        <div class="flex justify-end gap-2 mt-4">
          <button onclick="csSaveGithub()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Save</button>
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
        <button onclick="csSaveSecurity()" class="mt-4 bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Save</button>
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

// ── Register Config children ───────────────────────────────────────────────
// Config is now two sub-tabs: "Sim Quotas" (alert→sim linkage + per-site
// client quotas the engine keeps filled) and "Config Editor" (the former flat
// Config view — Source of Truth + simulation.conf + user-overrides + hub
// config). VIEW_CHILDREN.cs.Config (main.js) lists both; the existing
// case 'Config' dispatch is the no-children fallback and stays as a safety net.
window.CS_CHILD_RENDERERS['Config::Sim Quotas']    = csRenderConfigSimQuotas;
window.CS_CHILD_RENDERERS['Config::PXMX Sites']    = csRenderPxmxSiteMap;
window.CS_CHILD_RENDERERS['Config::Quota State']   = csRenderSimQuotaState;
window.CS_CHILD_RENDERERS['Config::Config Editor']    = csRenderConfigSimulation;

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
window.CS_CHILD_RENDERERS['Setup::Diagnostics']    = csRenderSetupDiagnostics;

/* ===========================================================================
 * 1. VM Server — fleet overview + per-spoke drill-in children
 *    GET/DELETE /sim/api/{T}/proxmx/commands          (command queue)
 *    POST /sim/api/{T}/usb-vidpids                    (certify/ignore USB)
 * ========================================================================= */

let csVmHosts = [];
// Auto-Provisioning on/off mirror of the hub flag (set by
// csRefreshAutoProvStatus from usb-provisioning-status). Drives the ENABLE
// button label/state on the Auto-Provisioning tile.
let csAutoProvOn = false;
let csVmSelectedSpoke = '';       // spoke_id of the FIRST in-scope host (single-host children)
let csVmSelectedHostId = '';      // FIRST in-scope host id (single-host children)
// Multi-host selection for VMS + Command Queue. Empty array = ALL hosts. The
// searchable panel (csVmHostBanner) toggles entries here; single-host children
// (USB / API / Console / Auto-prov) fall back to the first via csVmSelectedHost().
let csVmSelectedHostIds = [];
let _csHostPanelOpen = false;
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

// Hosts currently in scope: the multi-selection, or ALL hosts when empty.
// Numeric-aware sort so pxmx-cs-svr-02/-03/-04 order naturally.
function csVmSelectedHosts() {
    const _hn = h => (h.spoke_name || h.spoke_hostname || h.spoke_id || '');
    const all = csVmHosts.slice().sort((a, b) =>
        _hn(a).localeCompare(_hn(b), undefined, { numeric: true, sensitivity: 'base' }));
    if (!csVmSelectedHostIds.length) return all;               // empty = ALL
    const sel = new Set(csVmSelectedHostIds);
    const picked = all.filter(h => sel.has(csVmHostId(h)));
    return picked.length ? picked : all;                       // stale ids → all
}

// First in-scope host — for single-host children (USB / API / Console / Auto-
// prov) that still operate on one host. Keeps csVmSelectedHostId/Spoke in sync.
function csVmSelectedHost() {
    const hosts = csVmSelectedHosts();
    let h = hosts.find(x => csVmHostId(x) === csVmSelectedHostId)
         || hosts.find(x => x.spoke_online) || hosts[0] || null;
    if (h) { csVmSelectedHostId = csVmHostId(h); csVmSelectedSpoke = h.spoke_id; }
    return h;
}

// Owning host's command-routing target (hostname) + spoke for a tagged VM.
function csVmKey(v) { return (v._spoke || '') + '|' + (v._host || '') + '|' + v.vmid; }

/** Searchable multi-select host filter shown atop every VM Server child.
 * Replaces the old pill row (which didn't scale past ~15 hosts). Empty
 * selection = All hosts; pick one or many. Scales via search + scroll. */
function csVmHostBanner() {
    if (!csVmHosts.length) return '';
    const _hname = h => (h.spoke_name || h.spoke_hostname || h.spoke_id || '');
    const sorted = csVmHosts.slice().sort((a, b) =>
        _hname(a).localeCompare(_hname(b), undefined, { numeric: true, sensitivity: 'base' }));
    const sel = new Set(csVmSelectedHostIds);
    const nSel = csVmSelectedHostIds.length;
    const summary = nSel === 0 ? `All hosts (${sorted.length})`
                  : nSel === 1 ? (_hname(sorted.find(h => sel.has(csVmHostId(h))) || {}) || '1 host')
                  : `${nSel} hosts selected`;
    const rows = sorted.map(h => {
        const id = csVmHostId(h);
        const on = sel.has(id);
        return `<label data-cs-host-name="${csEscape(_hname(h).toLowerCase())}"
             class="flex items-center gap-2 px-3 py-1.5 text-xs cursor-pointer hover:bg-slate-50 ${on ? 'bg-green-50' : ''}">
             <input type="checkbox" ${on ? 'checked' : ''} onchange="csVmHostToggle('${csEscape(id)}')"/>
             ${csOnlineDot(h.spoke_online)}<span class="flex-1">${csEscape(_hname(h))}</span>
             <span class="text-slate-400">${(h.proxmox_vms || []).length} VM</span></label>`;
    }).join('');
    return `<div class="mb-4 relative" style="max-width:28rem">
      <div class="flex items-center gap-2">
        <span class="text-[10px] font-bold uppercase tracking-widest text-slate-400">Host</span>
        <button onclick="csVmHostPanelToggle()" class="flex-1 text-left px-3 py-1.5 rounded-md border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 flex items-center justify-between">
          <span>${csEscape(summary)}</span><span class="text-slate-400">▾</span></button>
        ${nSel ? `<button onclick="csVmHostAll()" class="text-[11px] text-slate-400 hover:text-slate-600 underline">clear</button>` : ''}
      </div>
      <div id="cs-host-panel" class="${_csHostPanelOpen ? '' : 'hidden'} absolute z-20 mt-1 w-full bg-white border border-slate-200 rounded-md shadow-lg">
        <div class="p-2 border-b border-slate-100">
          <input id="cs-host-search" type="text" placeholder="Search hosts…" oninput="csVmHostSearch(this.value)"
                 class="w-full px-2 py-1 text-xs border border-slate-200 rounded"/></div>
        <label class="flex items-center gap-2 px-3 py-1.5 text-xs cursor-pointer hover:bg-slate-50 border-b border-slate-100 font-semibold">
          <input type="checkbox" ${nSel === 0 ? 'checked' : ''} onchange="csVmHostAll()"/>All hosts</label>
        <div class="max-h-64 overflow-y-auto">${rows}</div>
      </div>
    </div>`;
}

// Host-filter interactions. A toggle re-renders the view (VM list depends on the
// selection); we blur first so csRenderVmServerVms' csUserIsEditing() guard —
// which blocks background telemetry re-renders — doesn't also block THIS
// explicit re-render. _csHostPanelOpen persists so the panel stays open across it.
window.csVmHostPanelToggle = function () {
    _csHostPanelOpen = !_csHostPanelOpen;
    const p = document.getElementById('cs-host-panel');
    if (p) p.classList.toggle('hidden', !_csHostPanelOpen);
    if (_csHostPanelOpen) { const s = document.getElementById('cs-host-search'); if (s) s.focus(); }
};
window.csVmHostSearch = function (term) {
    const t = (term || '').trim().toLowerCase();
    document.querySelectorAll('#cs-host-panel [data-cs-host-name]').forEach(el => {
        el.classList.toggle('hidden', !!t && !el.getAttribute('data-cs-host-name').includes(t));
    });
};
window.csVmHostToggle = function (id) {
    const i = csVmSelectedHostIds.indexOf(id);
    if (i >= 0) csVmSelectedHostIds.splice(i, 1); else csVmSelectedHostIds.push(id);
    _csHostPanelOpen = true;
    if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
    loadCSData('VM Server', currentSubChild || 'VMs', true);
};
window.csVmHostAll = function () {
    csVmSelectedHostIds = [];
    _csHostPanelOpen = false;
    if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
    loadCSData('VM Server', currentSubChild || 'VMs', true);
};

// Dismiss the host panel on an outside click. It is a MULTI-select — ticking a
// host (csVmHostToggle) deliberately keeps it open so you can pick several — so
// clicking anywhere outside it is the clear way to close it (there was none:
// no ✕, and only re-clicking the Host button or "All hosts" closed it). Bound
// once at module load; keys off #cs-host-panel so it survives re-renders.
if (!window._csHostPanelOutsideBound) {
    window._csHostPanelOutsideBound = true;
    document.addEventListener('click', function (e) {
        if (!_csHostPanelOpen) return;
        const panel = document.getElementById('cs-host-panel');
        const wrap = panel && panel.closest('.relative');
        // Clicks on the toggle button, the search box, or a host row live inside
        // the wrapper and manage their own state; only an OUTSIDE click closes.
        if (wrap && !wrap.contains(e.target)) {
            _csHostPanelOpen = false;
            panel.classList.add('hidden');
        }
    });
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
    const vms = hosts.reduce((n, h) => n + csSimVmCount(h), 0);
    const usbs = hosts.reduce((n, h) => n + csUsbCount(h), 0);
    // Count VMs the agents report as actively recloning (prov_status stamped
    // from reclone_vmids) — the reclone_state placeholder was always empty.
    const recloneRunning = hosts.reduce((n, h) =>
        n + ((h.proxmox_vms || []).filter(v => String(v.prov_status || '').toLowerCase() === 'recloning').length), 0);
    const summary = `<div class="flex flex-wrap items-center gap-x-4 gap-y-1 mb-3 text-xs text-slate-500">
      <span><b class="text-sm text-slate-700">${hosts.length}</b> Hosts</span>
      <span><b class="text-sm text-slate-700">${online}</b> Online</span>
      <span><b class="text-sm text-slate-700">${recloneRunning}</b> Recloning</span>
      <span><b class="text-sm text-slate-700">${usbs}</b> USB</span>
      <span><b class="text-sm text-slate-700">${vms}</b> VMs</span>
    </div>`;

    const fleetCards = `<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
      <div class="hpe-card rounded-lg p-4 shadow-sm">
        <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Fleet Reclone</p>
        <div class="flex items-center gap-2">
          <input id="cs-fleet-conc" type="number" min="1" value="1" class="w-16 border border-slate-200 rounded-md px-2 py-1 text-sm"/>
          <button onclick="csFleetReclone()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold">Reclone All</button>
        </div>
        <p class="text-[10px] text-slate-400 mt-2">Concurrency controls how many guests reclone in parallel.</p>
        <div id="cs-fleet-reclone-progress" class="mt-2 text-[11px] text-slate-500 space-y-1">No reclone in progress.</div>
      </div>
      <div class="hpe-card rounded-lg p-4 shadow-sm">
        <div class="flex items-center justify-between mb-2">
          <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Auto-Provisioning</p>
          <button id="cs-autoprov-enable-btn" onclick="csToggleAutoProvision(!csAutoProvOn)" class="px-3 py-1 rounded-md text-xs font-bold border">Enable</button>
        </div>
        <div class="flex gap-4">
          <div class="flex-1 min-w-0">
            <div id="cs-autoprov-status" class="text-[10px] text-slate-500 space-y-1">Status: loading…</div>
          </div>
          <div class="flex-1 min-w-0 border-l border-slate-100 pl-3">
            <div class="text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">Provisioning now</div>
            <div id="cs-autoprov-live" class="text-[11px] text-slate-500 space-y-1">loading…</div>
          </div>
        </div>
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
        const vmN = csSimVmCount(h);
        const usbN = csUsbCount(h);
        // Quarantined-dongle pill for the USB cell: surfaces dmesg-quarantined
        // dongles at the fleet level (count + tooltip of bus-id: reason). The
        // per-dongle live-recovery badges live on the USB detail card.
        const qtList = (px.quarantine || []).filter(q => q && q.bus_path);
        const qtPill = qtList.length ? `<span class="ml-1 inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-red-100 text-red-700 text-[9px] font-bold uppercase tracking-wider" title="${csEscape(qtList.map(q => q.bus_path + ': ' + (q.reason || '')).join('; '))}">🚫 ${qtList.length} QT</span>` : '';
        const selCls = csVmHostId(h) === sel ? 'bg-green-50 ring-1 ring-green-300' : 'hover:bg-slate-50';
        return `<tr class="border-b border-slate-100 cursor-pointer ${selCls}" onclick="csVmSelectHost('${csEscape(csVmHostId(h))}','VMs')">
          <td class="px-4 py-2 text-center" onclick="event.stopPropagation()"><input type="checkbox" class="cs-host-sel" data-spoke="${csEscape(h.spoke_id || '')}" data-name="${csEscape(h.spoke_name || h.spoke_hostname || h.spoke_id || '')}"></td>
          <td class="px-4 py-2"><span class="font-medium text-slate-700">${csEscape(h.spoke_name || h.spoke_hostname || h.spoke_id)}</span></td>
          <td class="px-4 py-2 text-center">${csOnlineBadge(h.spoke_online)}</td>
          <td class="px-4 py-2 text-center">${vmN}</td>
          <td class="px-4 py-2 text-center">${usbN}${qtPill}</td>
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
    const selTh = `<th class="px-4 py-2 text-center"><input type="checkbox" onclick="csFleetSelectAll(this)" title="Select all hosts"></th>`;
    const table = `<div class="overflow-x-auto"><table class="w-full text-sm">
      <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${selTh}${ths}</tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;

    // Fleet template refresh — pick one/some/all hosts and refresh each host's
    // template from its stored backup. Tenant-admin (own hosts) + Global Admin.
    const _canRefresh = (typeof isAdmin === 'function' && isAdmin())
        || (typeof isTenantAdmin === 'function' && isTenantAdmin());
    const bulkBar = _canRefresh
        ? `<div class="flex items-center gap-2 flex-wrap">
             <button onclick="csFleetRefreshTemplates()" class="bg-amber-100 hover:bg-amber-200 text-amber-800 border border-amber-300 px-3 py-1.5 rounded-md text-xs font-bold" title="Refresh the template on the selected host(s): pause auto-provisioning, delete the sim VMs + template, restore the stored backup, then resume auto-provisioning.">↻ Refresh Template(s)</button>
             <span class="text-[11px] text-slate-400">Select host(s) above, then refresh from their stored template backup. This wipes the host's sim VMs.</span>
           </div>`
        : '';

    csSet(`<div class="space-y-4">${summary}${fleetCards}${bulkBar}${table}</div>`);
    // populate auto-provision status + the live panels (host data from csVmLoad).
    csRefreshAutoProvStatus();
    csAutoProvLivePanel();
    csFleetRecloneProgress();
}

// ── Fleet Reclone / Auto-Provisioning live progress panels ───────────────────
// Modeled on the first-version webui-spoke ``renderRecloneStatus`` +
// ``renderAutoProvisionStatus``: a per-host progress bar (done/total VMs) for an
// active fleet reclone, and an in-flight VM list for auto-provisioning. Both
// read data that already rides the per-host relay payload (reclone_state /
// usb_devices[].prov_status), so they refresh with the VM Server auto-refresh.

function csFleetRecloneProgress() {
    const el = csEl('cs-fleet-reclone-progress');
    if (!el) return;
    // Per-host reclone_state; only hosts with a non-idle/non-empty state are "running".
    const active = (csVmHosts || []).map(h => ({ h, rs: h.reclone_state || {} }))
        .filter(x => x.rs.status === 'running' || (x.rs.status && x.rs.status !== 'idle' && Object.keys(x.rs).length));
    if (!active.length) { el.textContent = 'No reclone in progress.'; return; }
    el.innerHTML = active.map(({ h, rs }) => {
        const total = Number(rs.total || 0);
        const done = Number(rs.completed || 0) + Number(rs.failed || 0);
        const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
        const host = csEscape(h.spoke_name || h.spoke_hostname || h.spoke_id || '');
        const cur = rs.current_vm ? ` · recloning VM ${csEscape(String(rs.current_vm))}` : '';
        const ph = rs.phase ? ` (${csEscape(rs.phase)})` : '';
        const bar = total
            ? `<div class="w-full bg-slate-100 rounded-full h-1.5 my-1"><div class="bg-[#01A982] h-1.5 rounded-full" style="width:${pct}%"></div></div>
               <div class="text-[10px] text-slate-400">${done} / ${total} VMs (${pct}%)${cur}${ph}</div>`
            : `<div class="text-[10px] text-slate-400">starting${cur}${ph}</div>`;
        const log = (rs.log || []).slice(-4).reverse().map(e => {
            const ic = e.status === 'completed' ? '✅' : e.status === 'failed' ? '❌'
                : e.status === 'in_progress' ? '⏳' : '🕐';
            return `<div class="text-[10px] text-slate-400">${ic} VM ${csEscape(String(e.vmid ?? '—'))} · ${csEscape(e.status || '')}</div>`;
        }).join('');
        return `<div class="border-t border-slate-100 pt-1 first:border-0 first:pt-0">
            <div class="text-[10px] font-bold text-slate-600">${host}</div>${bar}${log}</div>`;
    }).join('');
}

function csAutoProvLivePanel() {
    const el = csEl('cs-autoprov-live');
    if (!el) return;
    // Aggregate in-flight USB entries across hosts (the per-VM "provisioning /
    // tearing_down / missing / starting-up" states that already ride usb_devices).
    // Mirrors renderAutoProvisionStatus: a present-but-VM-not-running dongle is
    // "starting up". Cross-reference each host's proxmox_vms running set.
    const flight = [];
    (csVmHosts || []).forEach(h => {
        const runningVmids = new Set((h.proxmox_vms || [])
            .filter(v => String(v.status || '').toLowerCase() === 'running')
            .map(v => Number(v.vmid)));
        (h.usb_devices || []).forEach(u => {
            const ps = String(u.prov_status || '').toLowerCase();
            if (ps === 'provisioning' || ps === 'tearing_down' || ps === 'missing'
                || (ps === 'active' && u.vmid != null && !runningVmids.has(Number(u.vmid)))) {
                flight.push({ host: h.spoke_name || h.spoke_hostname || h.spoke_id || '', u });
            }
        });
    });
    if (!csAutoProvOn) {
        el.innerHTML = `<div class="text-slate-400">Auto-Provisioning is off.</div>`;
        return;
    }
    if (!flight.length) {
        el.innerHTML = `<div class="text-slate-400">No active provisioning work.</div>`;
        return;
    }
    el.innerHTML = flight.map(({ host, u }) => {
        const ps = String(u.prov_status || '').toLowerCase();
        const ic = ps === 'provisioning' ? '⏳' : ps === 'tearing_down' ? '🗑️'
            : ps === 'missing' ? '⚠️' : '🔄';
        const lbl = ps === 'provisioning' ? 'Cloning' : ps === 'tearing_down' ? 'Tearing Down'
            : ps === 'missing' ? 'USB Missing' : 'Starting Up';
        return `<div><span>${ic}</span> <b>VM ${csEscape(String(u.vmid ?? '—'))}</b>
            <span class="text-slate-400">${csEscape(lbl)}</span>
            <span class="text-slate-300">${csEscape(host)}</span></div>`;
    }).join('');
}

window.csFleetSelectAll = function (cb) {
    document.querySelectorAll('.cs-host-sel').forEach(x => { x.checked = cb.checked; });
};

// Fleet template refresh — refresh the selected hosts' templates from their
// stored backups. Destructive: each host's sim VMs + template are wiped and the
// backup restored (the agent pauses/resumes auto-prov around it).
window.csFleetRefreshTemplates = async function () {
    const boxes = Array.from(document.querySelectorAll('.cs-host-sel:checked'));
    const spokeIds = boxes.map(b => b.getAttribute('data-spoke')).filter(Boolean);
    const names = boxes.map(b => b.getAttribute('data-name') || b.getAttribute('data-spoke'));
    if (!spokeIds.length) { if (typeof showToast === 'function') showToast('Select one or more hosts first', 'error'); return; }
    if (!window.confirm(`Refresh the template on ${spokeIds.length} host(s):\n${names.join(', ')}\n\nThis PAUSES auto-provisioning, DELETES the sim VMs + template on each host, restores the stored backup, then resumes auto-provisioning. Existing sim clients will be wiped.`)) return;
    try {
        const r = await fetch('/tenant/templates/refresh-hosts', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_ids: spokeIds })
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { if (typeof showToast === 'function') showToast(d.detail || 'Refresh failed', 'error'); return; }
        // Surface per-host skips/errors, then a summary.
        (d.results || []).filter(x => x.status !== 'SUCCESS').forEach(x => {
            if (typeof showToast === 'function') showToast(`${x.name || x.spoke_id}: ${x.message || x.status}`, 'error');
        });
        const ok = d.refreshed || 0, total = d.total || spokeIds.length;
        if (typeof showToast === 'function') showToast(`Refresh queued on ${ok}/${total} host(s).`, ok ? 'success' : 'error');
        csRenderVmServer();
    } catch (e) { if (typeof showToast === 'function') showToast('Refresh failed: ' + (e.message || e), 'error'); }
};

async function csRefreshAutoProvStatus() {
    const st = csEl('cs-autoprov-status');
    try {
        const s = await csFetch(`/${csTenant()}/usb-provisioning-status?tenant_id=${csTenant()}`);
        const on = String(s.usb_auto_provision || 'off').toLowerCase() === 'on';
        csAutoProvOn = on;
        // ENABLE button reflects on/off (green when enabled, grey when disabled).
        const btn = csEl('cs-autoprov-enable-btn');
        if (btn) {
            btn.textContent = on ? 'Enabled' : 'Enable';
            btn.className = on
                ? 'px-3 py-1 rounded-md text-xs font-bold border bg-[#01A982]/10 text-[#01A982] border-[#01A982]'
                : 'px-3 py-1 rounded-md text-xs font-bold border bg-slate-100 text-slate-500 border-slate-300';
        }
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
        // csAutoProvOn is now fresh → re-render the live in-flight panel.
        csAutoProvLivePanel();
    } catch (e) {
        console.error('csRefreshAutoProvStatus: usb-provisioning-status fetch failed (best-effort)', e);
        if (st) st.textContent = 'Status: unavailable';
    }
}

window.csVmSelectHost = function (hostId, child) {
    // Overview → VMs link / legacy single-host pick: narrow the multi-selection
    // to just this host (empty = all; [hostId] = only it).
    csVmSelectedHostIds = hostId ? [hostId] : [];
    csVmSelectedHostId = hostId;
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

// Count only simulation-client VMs for a host — the same bucket the VMs tab's
// 'Simulation Clients' category shows (vmid >= 90000 / sim-* / *client*,
// excluding templates and LXC containers). The overview's VMs column and the
// fleet table used h.vm_count, which includes templates + containers. Falls
// back to vm_count only when the full VM list isn't present (best-effort).
function csSimVmCount(h) {
    const list = h && h.proxmox_vms;
    if (Array.isArray(list)) return list.filter(v => csVmCategory(v) === 'Simulation Clients').length;
    return (h && h.vm_count) || 0;
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
    const scope = csVmSelectedHosts();
    if (!scope.length) { csSet(csEmpty('No hosts.')); return; }
    const single = scope.length === 1 ? scope[0] : null;
    csVmSelectedHost();   // keep csVmSelectedHostId/Spoke in sync for children
    // Flatten VMs across the selected hosts, tagging each with its owning
    // spoke/host so actions route correctly (VMIDs can collide across hosts).
    // Join the per-host missing-dongle shed deadline (usb_state[].shed_at).
    const vms = [];
    scope.forEach(hh => {
        const hn = hh.hostname || hh.spoke_hostname || hh.spoke_id;
        const usb = (hh.proxmox && hh.proxmox.usb_state) || hh.usb_state || [];
        const shed = {};
        usb.forEach(u => { if (u && u.shed_at && u.vmid != null) shed[String(u.vmid)] = u.shed_at; });
        (hh.proxmox_vms || []).forEach(v => {
            const vv = Object.assign({}, v);
            vv._spoke = hh.spoke_id;
            vv._host = hn;
            vv._hostlabel = hh.spoke_name || hn;
            vv._shed_at = shed[String(v.vmid)] || null;
            vv._key = csVmKey(vv);
            vms.push(vv);
        });
    });
    csStartShedTicker();
    const cats = ['Simulation Clients', 'Other', 'Containers', 'Templates'];
    const grouped = {};
    cats.forEach(c => grouped[c] = vms.filter(v => csVmCategory(v) === c));
    const tabs = cats.map((c, i) => `<button onclick="csVmVmsTab('${c}')" id="cs-vmtab-${csEscape(c)}" class="px-3 py-1.5 rounded-md text-xs font-bold ${i === 0 ? 'bg-[#01A982]/10 text-[#01A982] border border-[#01A982]' : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50'}">${csEscape(c)} <span class="opacity-60">(${grouped[c].length})</span></button>`).join('');
    const rows = csVmRenderRows(grouped['Simulation Clients'] || []);
    // Auto-prov panel is per-host — only when exactly one host is in scope.
    const apPanel = single ? csAutoProvPanel(single) : '';
    csSet(`<div>${csVmHostBanner()}${apPanel}${tabs}
      <div class="flex items-center gap-2 my-3 text-xs text-slate-500">
        <button onclick="csVmBulk('start_vm')" class="bg-green-100 text-green-700 px-2 py-1 rounded font-bold">Start</button>
        <button onclick="csVmBulk('stop_vm')" class="bg-amber-100 text-amber-700 px-2 py-1 rounded font-bold">Stop</button>
        <button onclick="csVmBulk('reboot_vm')" class="bg-slate-200 text-slate-700 px-2 py-1 rounded font-bold">Reboot</button>
        <button onclick="csVmBulk('reclone_vm')" class="bg-blue-100 text-blue-700 px-2 py-1 rounded font-bold">Reclone</button>
        <button onclick="csVmBulk('delete_vm')" class="bg-red-100 text-red-700 px-2 py-1 rounded font-bold">Delete</button>
      </div>
      <div id="cs-vm-list">${csVmTable(rows)}</div>
      ${csVmStatusLegend()}
    </div>`);
    window._csVmGrouped = grouped;
    window._csVmByKey = {};
    window._csVmByVmid = {};
    vms.forEach(v => { window._csVmByKey[v._key] = v; window._csVmByVmid[v.vmid] = v; });
}

const CS_VM_TABLE_HEADERS = ['VMID', 'Name', 'OS', 'Status', 'Host', 'Actions'];

// Friendly OS label from the agent's cached Proxmox ostype (l26 → Linux, win* →
// Windows, etc.); falls back to the qemu/lxc type when ostype is unknown.
function csVmOs(v) {
    const t = String(v.ostype || v.os || '').toLowerCase();
    if (!t) return v.is_template ? 'template' : (v.type === 'lxc' ? 'Linux (CT)' : '—');
    if (t.startsWith('win')) return 'Windows';
    if (t === 'l26' || t === 'l24' || t.startsWith('linux')) return 'Linux';
    if (t.includes('solaris')) return 'Solaris';
    if (t.includes('other')) return 'Other';
    return v.ostype || v.os;
}
const CS_VM_TABLE_HEADER_HTML = [
    '<label class="inline-flex items-center gap-1.5 cursor-pointer"><input type="checkbox" id="cs-vm-selectall" onchange="csVmSelectAll(this.checked)"/> VMID</label>',
];
function csVmTable(rows) {
    return csTable(CS_VM_TABLE_HEADERS, rows, {id: 'cs-vm-table', headerHtml: CS_VM_TABLE_HEADER_HTML});
}

// Legend for the VM STATUS column — explains each transient-operation + steady
// badge so an operator can read the list at a glance. Keep the swatch colors in
// sync with csVmStatusBadge / csStatusBadge / csShedBadge.
function csVmStatusLegend() {
    const item = (cls, label, desc) =>
        `<span class="inline-flex items-center gap-1.5" title="${csEscape(desc)}">
           <span class="w-2.5 h-2.5 rounded-full ${cls}"></span>
           <span class="text-slate-600">${csEscape(label)}</span>
           <span class="text-slate-400">— ${csEscape(desc)}</span>
         </span>`;
    const items = [
        ['bg-green-500', 'Running', 'VM is powered on'],
        ['bg-slate-400', 'Stopped', 'VM is powered off'],
        ['bg-indigo-500', 'Recloning', 'being destroyed + re-cloned from template (in progress)'],
        ['bg-sky-500', 'Provisioning / Configuring', 'auto-provision: cloning then configuring a new sim VM'],
        ['bg-amber-500', 'Shedding', 'countdown to teardown — its USB dongle is missing'],
        ['bg-red-500', 'Deleting', 'being torn down (destroy in progress)'],
    ];
    return `<div class="mt-3 px-1">
      <p class="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">Status legend</p>
      <div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">${items.map(i => item(i[0], i[1], i[2])).join('')}</div>
    </div>`;
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
        // Quarantine-recovery countdown — same absolute-epoch pattern as the
        // shed countdown (data-qt-at = agent since + 1h QUARANTINE_RECOVERY_S).
        document.querySelectorAll('.cs-qt-countdown').forEach(el => {
            const at = Number(el.getAttribute('data-qt-at'));
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
    return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700" title="Dongle removed — VM will be shed when the missing-dongle timer expires">`
        + `<span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>🗑️ Sheds in `
        + `<span class="cs-shed-countdown" data-shed-at="${Number(v._shed_at)}">${csFmtDuration(secs)}</span></span>`;
}

// Number of quarantined dongles on a host (px.quarantine list, dmesg-only).
function csQtCount(h) {
    const q = (h && h.proxmox && h.proxmox.quarantine) || [];
    return Array.isArray(q) ? q.length : 0;
}

// Badge for a dongle quarantined by kernel USB (dmesg) errors — the ONLY
// quarantine path. Shows the bus-id + reason + a live countdown to the 1h
// auto-recovery that clears it (a still-plugged dongle gets retried; if the
// kernel errors persist it re-quarantines next pass). A failed clone NEVER
// quarantines the dongle, so this is the sole "sidelined dongle" signal.
function csQtBadge(q) {
    if (!q || !q.bus_path) return '';
    const at = Number(q.recovers_at);
    const secs = isFinite(at) ? at - Date.now() / 1000 : NaN;
    const reason = String(q.reason || 'quarantined');
    const present = q.present === false ? ' (absent)' : '';
    const title = `Quarantined — ${reason}${present}. Auto-recovers after 1h; re-quarantines if kernel USB errors persist.`;
    const cnt = (isFinite(secs) && secs > 0)
        ? `<span class="cs-qt-countdown" data-qt-at="${at}">${csFmtDuration(secs)}</span>`
        : 'now';
    return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700" title="${csEscape(title)}">`
        + `<span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>🚫 QT ${csEscape(q.bus_path)} · ${csEscape(reason)} · clears in ${cnt}</span>`;
}

function csVmStatusBadge(v) {
    const ps = String(v.prov_status || '').toLowerCase();
    if (ps === 'tearing_down') {
        return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700"><span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>Deleting…</span>`;
    }
    // An active reclone (destroy + clone + boot + guest-agent wait) wins over the
    // steady status — the agent stamps prov_status="recloning" for its duration.
    if (ps === 'recloning') {
        return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-indigo-100 text-indigo-700"><span class="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse"></span>Recloning…</span>`;
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
    const key = csEscape(v._key != null ? v._key : csVmKey(v));
    // Disable actions on a VM that's being torn down — it's about to vanish.
    const busy = String(v.prov_status || '').toLowerCase() === 'tearing_down';
    // Route by composite key (spoke|host|vmid) — VMIDs can collide across hosts.
    const act = (label, action, cls) => busy
        ? `<button disabled title="VM is being deleted" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-300 cursor-not-allowed">${label}</button>`
        : `<button onclick="csVmAction('${key}','${action}')" class="px-2 py-0.5 rounded text-[10px] font-bold ${cls}">${label}</button>`;
    return `<tr>
      <td class="px-3 py-2 font-mono text-xs"><input type="checkbox" class="cs-vm-sel" data-vmkey="${key}" data-vmid="${vid}" onchange="csVmSelUpdateHeader()"/> ${vid}</td>
      <td class="px-3 py-2 text-sm">${csEscape(v.name || '—')}</td>
      <td class="px-3 py-2 text-slate-500">${csEscape(csVmOs(v))}</td>
      <td class="px-3 py-2">${csVmStatusBadge(v)}</td>
      <td class="px-3 py-2 text-xs text-slate-500">${csEscape(v._hostlabel || v._host || '—')}</td>
      <td class="px-3 py-2"><div class="flex flex-wrap gap-1">
        ${act('Start','start_vm','bg-green-100 text-green-700')}
        ${act('Stop','stop_vm','bg-amber-100 text-amber-700')}
        ${act('Reboot','reboot_vm','bg-slate-200 text-slate-700')}
        ${act('Reclone','reclone_vm','bg-indigo-100 text-indigo-700')}
        ${act('Delete','delete_vm','bg-red-100 text-red-700')}
      </div></td>
    </tr>`;
}

// Render a category's rows, capped for scale (100s of hosts × VMs). Beyond the
// cap, prompt to narrow the Host filter rather than DOM tens of thousands of rows.
const CS_VM_ROW_CAP = 400;
function csVmRenderRows(list) {
    const shown = (list || []).slice(0, CS_VM_ROW_CAP);
    let html = shown.map(csVmRow).join('');
    if ((list || []).length > CS_VM_ROW_CAP) {
        html += `<tr><td colspan="6" class="px-3 py-2 text-xs text-amber-700 bg-amber-50">Showing ${CS_VM_ROW_CAP} of ${list.length} VMs — narrow the Host filter to see the rest.</td></tr>`;
    }
    return html;
}

window.csVmVmsTab = function (cat) {
    const rows = csVmRenderRows((window._csVmGrouped && window._csVmGrouped[cat]) || []);
    const list = csEl('cs-vm-list');
    if (list) list.innerHTML = csVmTable(rows);
    ['Simulation Clients','Other','Containers','Templates'].forEach(c => {
        const b = csEl('cs-vmtab-' + c);
        if (b) b.className = 'px-3 py-1.5 rounded-md text-xs font-bold ' + (c === cat ? 'bg-[#01A982]/10 text-[#01A982] border border-[#01A982]' : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-50');
    });
};

// The proxmox-command `target` = the host the action runs on. Without it the hub
// defaults to the spoke's PRIMARY host, so an action on a multi-host spoke can
// hit the wrong host — e.g. a delete "succeeds" (destroy_vm finds the VM
// already-gone there) while the real VM survives on the SELECTED host. Pin it to
// the selected host so every action lands where the VM actually lives.
function csVmTarget() {
    const h = (typeof csVmSelectedHost === 'function' && csVmSelectedHost()) || {};
    return h.hostname || h.spoke_hostname || undefined;
}

// Present-tense label for a VM action, for immediate "…" feedback toasts.
const CS_VM_ACTION_LABEL = {
    delete_vm: 'Deleting', start_vm: 'Starting', stop_vm: 'Stopping',
    reboot_vm: 'Rebooting', reclone_vm: 'Recloning', snapshot_vm: 'Snapshotting',
};
function csVmActionLabel(a) { return CS_VM_ACTION_LABEL[a] || a; }

window.csVmAction = async function (key, action) {
    // key is the composite spoke|host|vmid (routes to the VM's OWN host); tolerate
    // a bare vmid for any legacy caller.
    const v = (window._csVmByKey && window._csVmByKey[key])
           || (window._csVmByVmid && window._csVmByVmid[key]) || {};
    const vmid = v.vmid != null ? v.vmid : key;
    const args = { vmid: Number(vmid) };
    if (v.type) args.vm_type = v.type;
    const sid = encodeURIComponent(v._spoke || csVmSelectedSpoke);
    const target = v._host || csVmTarget();
    if (typeof showToast === 'function') showToast(`${csVmActionLabel(action)} VM ${vmid}…`, 'info');
    if (action === 'delete_vm') await csExpirePendingForTarget(target);
    try {
        await csFetch(`/${csTenant()}/spokes/${sid}/proxmox-command?tenant_id=${csTenant()}`,
            { method: 'POST', body: JSON.stringify({ action, args, target }) });
        csVmFlash(action + ' queued');
        setTimeout(() => loadCSData('VM Server', currentSubChild, true), 800);
    } catch (e) { console.error('csVmAction: ' + action + ' failed', e); if (typeof showToast === 'function') showToast(action + ' failed: ' + (e.message || e), 'error'); }
};

window.csVmBulk = async function (action) {
    const keys = Array.from(document.querySelectorAll('.cs-vm-sel:checked')).map(c => c.dataset.vmkey);
    if (!keys.length) { if (typeof showToast === 'function') showToast('Select one or more VMs first.', 'info'); return; }
    // Resolve each selected VM to its OWNING host/spoke — VMIDs collide across
    // hosts, so a cross-host bulk must route each VM to its own host, not the
    // one selected host (the bug where delete only hit host 04).
    const items = keys.map(k => window._csVmByKey && window._csVmByKey[k]).filter(Boolean);
    if (!items.length) return;
    const byHost = {};
    items.forEach(v => { const hl = v._hostlabel || v._host || '?'; byHost[hl] = (byHost[hl] || 0) + 1; });
    const hostList = Object.keys(byHost);
    // Destructive + cross-host → confirm with the per-host breakdown.
    if (action === 'delete_vm') {
        const bd = hostList.map(h => `${h} (${byHost[h]})`).join(', ');
        if (!confirm(`Delete ${items.length} VM(s) across ${hostList.length} host(s)?\n\n${bd}`)) return;
    }
    if (typeof showToast === 'function') showToast(`${csVmActionLabel(action)} ${items.length} VM(s) across ${hostList.length} host(s)…`, 'info');
    if (action === 'delete_vm') {
        for (const hh of new Set(items.map(v => v._host))) { await csExpirePendingForTarget(hh); }
    }
    // Sequential paced enqueue — a burst floods the cs spoke's queue/WS
    // ("connection closed mid-send"); the 250ms gap paces the ENQUEUE while the
    // agent's own 2-slot semaphore bounds execution. Per-item errors tolerated
    // so one failure doesn't abort the batch. Each VM routes to its own spoke.
    let ok = 0, fail = 0;
    for (let i = 0; i < items.length; i++) {
        const v = items[i];
        try {
            const args = { vmid: Number(v.vmid) };
            if (v.type) args.vm_type = v.type;
            await csFetch(`/${csTenant()}/spokes/${encodeURIComponent(v._spoke)}/proxmox-command?tenant_id=${csTenant()}`,
                { method: 'POST', body: JSON.stringify({ action, args, target: v._host }) });
            ok++;
        } catch (e) { console.error('csVmBulk item ' + (v && v.vmid) + ' failed', e); fail++; }
        if (typeof showToast === 'function' && items.length > 4 && (i + 1) % 5 === 0)
            showToast(`${csVmActionLabel(action)}… ${i + 1}/${items.length}`, 'info');
        await new Promise(r => setTimeout(r, 250));
    }
    if (typeof showToast === 'function') {
        if (fail) showToast(`${action}: ${ok} queued, ${fail} failed`, 'error');
        else csVmFlash(`${action} queued for ${ok} VM(s)`);
    }
    setTimeout(() => loadCSData('VM Server', currentSubChild, true), 1000);
};

// Best-effort expiry of in-flight commands for the selected proxmox host before
// a VM teardown. Swallowed on failure — the delete still proceeds.
async function csExpirePendingForTarget(target) {
    const host = target || csVmTarget() || 'proxmox';
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
    // Summary pills kept in alphabetical order by label.
    const summary = `<div class="mb-3 text-xs text-slate-500 flex flex-wrap items-center gap-x-4 gap-y-1">
      <span><b class="text-sm text-slate-700">${present.length}</b> certified</span>
      ${g ? `<span><b class="text-sm text-slate-700">${g}</b> global</span>` : ''}
      ${b ? `<span><b class="text-sm text-slate-700">${b}</b> global+local</span>` : ''}
      ${l ? `<span><b class="text-sm text-slate-700">${l}</b> local</span>` : ''}
      <span><b class="text-sm text-slate-700">${total}</b> on this host</span>
      <span><b class="text-sm text-slate-700">${fleetTotal}</b> total on cs server</span>
      <span><b class="text-sm text-slate-700">${unknown.length}</b> uncertified</span>
    </div>`;
    // Quarantined dongles (dmesg kernel USB errors — the only quarantine path).
    // One red badge per bus: bus-id + reason + live countdown to the 1h
    // auto-recovery. Surfaced here (the dongle-management surface) so an admin
    // sees WHY a dongle is sidelined and that it self-clears.
    const qt = (px.quarantine || []).filter(q => q && q.bus_path);
    const qtBox = qt.length ? `<div class="mb-4 border border-red-200 bg-red-50 rounded-lg p-3">
      <p class="text-[11px] font-bold text-red-700 uppercase tracking-wider mb-2">Quarantined dongles (${qt.length}) — sidelined by kernel USB errors</p>
      <div class="flex flex-wrap gap-2">${qt.map(csQtBadge).join('')}</div>
      <p class="text-[10px] text-red-600/80 mt-2">Each auto-recovers after 1h and gets retried; re-quarantines if the kernel errors persist. A failed clone never quarantines a dongle.</p>
    </div>` : '';
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
    // Start the live countdown ticker so the QT badges' "clears in" timer ticks
    // between telemetry pulses (idempotent — one interval for the whole page).
    csStartShedTicker();
    csSet(`<div>${csVmHostBanner()}
      ${dbgBox}
      ${summary}
      ${qtBox}
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
async function csRenderVmServerQueue(live) {
    csSetToolbar('');
    await csVmLoad().catch(() => {});   // populate csVmHosts for the host filter
    let cmds = [];
    try {
        // Default (live falsy) serves from the hub's cached CS_TELEMETRY
        // (instant). After a Send/Delete/Clear we pass live=true so the page
        // reflects the mutation immediately (the spoke just responded to the
        // action, so the round-trip is fast).
        const liveQs = live ? '&live=1' : '';
        const data = await csFetch(`/${csTenant()}/proxmx/commands?tenant_id=${csTenant()}${liveQs}`);
        cmds = (data && data.commands) || [];
    } catch (e) { console.error('csRenderVmServerQueue: command queue load failed', e); csSet(csErrorBox('Could not load command queue', e)); return; }
    // Filter the queue to the selected host(s); empty selection = all hosts.
    const _scope = csVmSelectedHosts();
    const _scopeHosts = new Set(_scope.map(h => h.hostname || h.spoke_hostname || h.spoke_id));
    const _filtered = csVmSelectedHostIds.length ? cmds.filter(c => _scopeHosts.has(c.target)) : cmds;
    // Newest on top: sort by created_at desc (fall back to age_secs asc when
    // created_at is absent — smaller age = newer). A mass-delete dump is far
    // easier to triage when the freshest commands (the ones still running /
    // just failed) sit at the top instead of scrolling past 30 stale rows.
    const shown = _filtered.slice().sort((a, b) => {
        const ca = Number(a.created_at || 0), cb = Number(b.created_at || 0);
        if (ca && cb) return cb - ca;
        const aa = Number(a.age_secs != null ? a.age_secs : 1e18);
        const ab = Number(b.age_secs != null ? b.age_secs : 1e18);
        return aa - ab;
    });
    const rows = shown.map(c => {
        // Second row: the command string (action + args JSON) so an operator
        // can see WHAT a queued command will do without cross-referencing the
        // Send form — e.g. `delete_vm {"vmid":90075}`. Collapsed under the row.
        const _argsStr = (() => { try { return c.args ? JSON.stringify(c.args) : ''; } catch (e) { return ''; } })();
        const _cmdStr = `${c.action || ''}${_argsStr ? ' ' + _argsStr : ''}`;
        return `<tr>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(c.id ? c.id.slice(0,8) : '—')}</td>
      <td class="px-3 py-2 text-sm">${csEscape(c.action || '—')}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(c.target || '—')}</td>
      <td class="px-3 py-2">${csStatusBadge(c.status || 'pending')}</td>
      <td class="px-3 py-2 text-slate-400 text-xs">${csEscape(c.age_secs != null ? c.age_secs + 's' : '—')}</td>
      <td class="px-3 py-2 text-slate-500 text-xs">${csEscape(c.message || '—')}</td>
      <td class="px-3 py-2"><button data-cs-cmd-id="${csEscape(c.id || '')}" onclick="csCmdDelete(this)"
        class="bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded-md text-[11px] font-bold">Delete</button></td>
    </tr><tr class="bg-slate-50/60">
      <td colspan="7" class="px-3 pb-2 pt-0 font-mono text-[11px] text-slate-500 break-all">${csEscape(_cmdStr || '—')}</td>
    </tr>`;
    }).join('');
    const sendForm = `<div class="hpe-card rounded-lg p-4 shadow-sm mb-4">
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Send Proxmox Command</p>
      <div class="flex flex-wrap gap-2 items-end text-sm">
        <div><label class="text-xs text-slate-400">Action</label>
          <select id="cs-cmd-action" class="border border-slate-200 rounded-md px-2 py-1">
            ${['start_vm','stop_vm','reboot_vm','snapshot_vm','reclone_vm','delete_vm','update_agent','unlock_template','proxmox_reclone_all'].map(a => `<option>${a}</option>`).join('')}
          </select></div>
        <div><label class="text-xs text-slate-400">Target (hostname)</label>
          <input id="cs-cmd-target" value="${csVmSelectedHostIds.length === 1 ? csEscape([..._scopeHosts][0] || '') : ''}" class="border border-slate-200 rounded-md px-2 py-1 w-40" placeholder="proxmox"/></div>
        <div><label class="text-xs text-slate-400">Args JSON</label>
          <input id="cs-cmd-args" class="border border-slate-200 rounded-md px-2 py-1 w-56" placeholder='{"vmid":90050}'/></div>
        <button onclick="csSendCommand()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold">Send</button>
        <button onclick="csClearCommands()" class="bg-red-100 text-red-700 px-3 py-1.5 rounded-md text-xs font-bold">Clear Queue</button>
      </div></div>`;
    csSet(`<div>${csVmHostBanner()}${sendForm}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Queue (${shown.length}${csVmSelectedHostIds.length ? ' of ' + cmds.length : ''})</p>
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
        csRenderVmServerQueue(true);
    } catch (e) { console.error('csSendCommand: send failed', e); if (typeof showToast === 'function') showToast('Send failed: ' + (e.message || e), 'error'); }
};

window.csClearCommands = async function () {
    if (!confirm('Clear all pending/delivered commands?')) return;
    try {
        await csFetch(`/${csTenant()}/proxmx/commands?tenant_id=${csTenant()}`, { method: 'DELETE' });
        csRenderVmServerQueue(true);
    } catch (e) { console.error('csClearCommands: clear failed', e); if (typeof showToast === 'function') showToast('Clear failed: ' + (e.message || e), 'error'); }
};

window.csCmdDelete = async function (btn) {
    const id = btn.dataset.csCmdId;
    if (!id) return;
    if (!confirm('Delete this command?')) return;
    try {
        await csFetch(`/${csTenant()}/proxmx/commands/${encodeURIComponent(id)}?tenant_id=${csTenant()}`, { method: 'DELETE' });
        csRenderVmServerQueue(true);
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

// ── Clients / Central (per-spoke, from the aggregate reads) ────
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

// ── Setup → Diagnostics: CS Bridge Status (hub-side relay state per agent) ───
// Lets an Azure-hub operator diagnose "why isn't svr-02 deleting?" without SSH:
// per agent, the bridge decision (ACTIVE / SKIP not-enabled / SKIP no-cs-spoke)
// + relay outcome counters (accepted / re-queued / gave-up / completed / failed)
// + the last outcome ts. The same data is in the hub log (WebUI Logs →
// Simulations) as greppable [cs-bridge] lines; this panel surfaces it structured.
// Read-only; refreshes on render. Global across the tenant's agents — that's
// why it lives under Setup/Diagnostics, not under a host-scoped VM Server tab.
async function csRenderSetupDiagnostics() {
    csSetToolbar('');
    let snap = null;
    try {
        snap = await csFetch(`/${csTenant()}/cs-bridge-status?tenant_id=${csTenant()}`);
    } catch (e) { console.error('csRenderSetupDiagnostics: load failed', e); csSet(csErrorBox('Could not load CS bridge status', e)); return; }
    if (!snap || !snap.available) {
        csSet(`<div>
          <p class="text-sm text-slate-500">CS bridge not started on this hub yet. The bridge poller runs on the hub; status appears here once it completes its first cycle (a few seconds after hub boot).</p>
        </div>`);
        return;
    }
    const agents = snap.agents || [];
    // Collapse CS-disabled (SKIP not-enabled) agents out of the table per the
    // "hide non-CS everywhere in the cs app" rule — their host + VMs are already
    // hidden in VM Server; the Diagnostics panel keeps a one-line count so the
    // "why isn't svr-02 deleting" diagnostic the panel exists for still surfaces
    // *that* an agent is disabled, without listing the disabled agent/VMs.
    const _disabled = agents.filter(a => (a.decision || '').startsWith('SKIP not-enabled'));
    const _shown = agents.filter(a => !(a.decision || '').startsWith('SKIP not-enabled'));
    const _cfgFast = snap.configured_fast_s != null ? `${snap.configured_fast_s}s` : '15s (default)';
    const _cfgLong = snap.configured_long_s != null ? `${snap.configured_long_s}s` : '60s (default)';
    const cfg = `<div class="hpe-card rounded-lg p-3 shadow-sm mb-3 text-xs text-slate-500 flex flex-wrap gap-x-4 gap-y-1">
      <span><b class="text-slate-600">max retries:</b> ${csEscape(String(snap.max_retries ?? '—'))}</span>
      <span><b class="text-slate-600">spoke→agent (configured):</b> fast ${csEscape(_cfgFast)} / long ${csEscape(_cfgLong)}</span>
      <span><b class="text-slate-600">hub→spoke (actual):</b> fast ${csEscape(String(snap.relay_timeout_s ?? '—'))}s / long ${csEscape(String(snap.relay_timeout_long_s ?? '—'))}s</span>
      <span><b class="text-slate-600">cycle:</b> ${csEscape(snap.cycle || '—')}</span>
    </div>
    <p class="text-[11px] text-slate-400 mb-3">Set the spoke→agent windows in <b>Setup → General → Agent Relay Timeouts</b>. The hub→spoke window tracks the configured long/fast value +5s (never below the env default) so the hub doesn't pre-empt the spoke's wait. If hub→spoke shows the env defaults (16s/65s) here after you saved General, the save didn't reach global_config — re-save.</p>`;
    const head = ['Agent', 'Hostname', 'Via (host spoke)', 'Decision', 'Inbox', 'Accepted', 'Re-queued', 'Gave up', 'Completed', 'Failed', 'Last outcome'];
    const body = _shown.map(a => {
        const _decClass = (a.decision || '').startsWith('ACTIVE') ? 'text-emerald-600' :
                         (a.decision || '').startsWith('SKIP') ? 'text-amber-600' : 'text-slate-500';
        return `<tr>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(a.agent_id || '—')}</td>
      <td class="px-3 py-2 font-mono text-xs">${csEscape(a.hostname || '—')}</td>
      <td class="px-3 py-2 font-mono text-xs text-slate-500">${csEscape(a.host_spoke || '—')}</td>
      <td class="px-3 py-2 text-xs ${_decClass}">${csEscape(a.decision || '—')}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${csEscape(String(a.last_inbox_count ?? 0))}</td>
      <td class="px-3 py-2 text-xs text-emerald-600">${csEscape(String(a.accepted || 0))}</td>
      <td class="px-3 py-2 text-xs text-amber-600">${csEscape(String(a.requeued || 0))}</td>
      <td class="px-3 py-2 text-xs text-red-600">${csEscape(String(a.gave_up || 0))}</td>
      <td class="px-3 py-2 text-xs text-slate-600">${csEscape(String(a.completed || 0))}</td>
      <td class="px-3 py-2 text-xs text-red-600">${csEscape(String(a.failed || 0))}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${csEscape(a.last_outcome ? (a.last_outcome + ' @ ' + (a.last_ts_iso || '')) : '—')}</td>
    </tr>`;
    }).join('');
    const _disabledLine = _disabled.length
      ? `<p class="text-[11px] text-amber-600 mb-2">${csEscape(String(_disabled.length))} agent(s) hidden (CS disabled) — enable in Agent Config to manage their VMs.</p>`
      : '';
    csSet(`<div>${cfg}
      <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">CS Bridge — per-agent relay status (${_shown.length} shown${_disabled.length ? ', ' + _disabled.length + ' hidden' : ''})</p>
      ${_disabledLine}
      <p class="text-[11px] text-slate-400 mb-3">ACTIVE = the bridge is polling + relaying this agent's queue. <b>Via</b> = the spoke the agent is actually connected to (commands are delivered through it); <b>cs_spoke</b> in the Decision is the tenant's queue broker (one per tenant — every lrb agent shares it). <b>Inbox</b> = commands found in the agent's inbox on the cs spoke last poll (0 with 0 Accepted = nothing queued / hostname-key mismatch; &gt;0 with 0 Accepted = relay path issue). SKIP no-cs-spoke = no client-sim spoke bound to the tenant. Re-queued climbing = agent too busy to ACK (transient, retried up to max retries). Gave up / Failed = retries exhausted or a genuine rejection. The same data streams to <b>WebUI Logs → Simulations</b> as <code>[cs-bridge]</code> lines.</p>
      ${_shown.length ? csTable(head, body) : '<p class="text-sm text-slate-500">No active agents seen yet.</p>'}
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
        <button onclick="csClaimSpoke()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold shadow-sm">Claim</button>
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
        <button onclick="csSpokeMgmtGenPsk()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-xs font-bold shadow-sm">+ Generate</button>
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