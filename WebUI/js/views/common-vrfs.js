// System → General → Common VRFs (Global Admin only; lm#1992). Shared
// infrastructure (the shared DNS, DHCP, firewall, Proxmox and ClearPass) serves
// NetBox's global table and the common VRFs; when the hub filters that shared
// data down to a tenant, the tenant's prefixes in any other VRF are left out.
// With nothing ticked the hub infers the common VRFs (a VRF two or more tenants
// have prefixes in); ticking VRFs names exactly the common ones instead.
// An ES module: _renderSetupGeneralTile (settings.js) calls
// lmViews.commonVrfs(containerId); nothing here is a window global. Reads and
// saves GET/PUT /admin/common-vrfs (core/src/routes/setup_misc.py). The VRFs
// listed come from the hub's NetBox cache, so the card never waits on NetBox.
import { safeHtml, rawHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

const HOW = "A change applies the next time the hub filters shared data, with no restart. "
    + "The VRFs listed are those a tenant has a prefix in, from the hub's NetBox cache "
    + '(refreshed every 5 minutes), plus any saved VRF no longer in it. '
    + 'NetBox views are not filtered this way.';

// Card state. `seq` counts loads, so an older load or save never redraws over
// a newer one; `data` is the last GET/PUT reply, `picked` the ticked VRF ids,
// and `saving` is true while this card's save runs (Save and the checkboxes
// are disabled, so the ticks stay what is being saved).
const state = { seq: 0, data: null, picked: new Set(), saving: false, error: '' };
let view = null;
// The PUT the hub has not answered yet, if any. It outlives its card: a card
// drawn meanwhile (System reopened) waits for it before reading, so it shows
// what the hub stored last and cannot send a second save that lands first.
let inflight = null;

// The VRF ids in `ids` as strings in numeric order (shorter first, then by text).
function sortedIds(ids) {
    return [...ids].map(String).sort((a, b) => a.length - b.length || (a < b ? -1 : a > b ? 1 : 0));
}

// True when the ticked VRFs are not the saved ones.
function isChanged(data, picked) {
    return sortedIds(picked).join() !== sortedIds(data.vrf_ids || []).join();
}

// A VRF's label: its name. One that shares its name with another listed VRF,
// or has no name in the cache, also shows its NetBox id, so the two can be
// told apart (NetBox does not require VRF names to be unique).
function vrfLabel(v, dupNames) {
    if (!v.name) return `Unknown VRF (NetBox id ${v.id})`;
    return dupNames.has(v.name.toLowerCase()) ? `${v.name} (NetBox id ${v.id})` : v.name;
}

// One VRF's checkbox, with a badge when the VRF is common right now. The
// checkbox is disabled while a save runs.
function vrfRow(v, ticked, common, auto, dupNames, saving) {
    const id = String(v.id);
    const why = auto ? 'Two or more tenants have prefixes in this VRF' : 'This VRF is in the saved list';
    const badge = common.has(id)
        ? safeHtml`<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800" title="${why}">common now</span>`
        : '';
    const tip = v.name ? '' : safeHtml` title="The hub's NetBox cache has no name for this VRF"`;
    return safeHtml`<label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer whitespace-nowrap"${tip}>
        <input type="checkbox" data-action="pick" value="${id}" ${ticked.has(id) ? 'checked' : ''} ${saving ? 'disabled' : ''} class="rounded border-slate-300 text-primary-text focus:ring-green-500">
        ${vrfLabel(v, dupNames)} ${badge}</label>`;
}

// The card for `data` (the GET /admin/common-vrfs reply) with the VRF ids in
// `picked` ticked. Without data it shows "Loading…", or `error` if the load failed.
export function commonVrfsHtml(data, picked = [], { saving = false, error = '' } = {}) {
    // The heading and what the setting does, in every state.
    const help = typeof helpIcon === 'function' ? rawHtml(helpIcon('lm-hub', 'How to use it', 'Hub help')) : '';
    const head = safeHtml`<h3 class="text-sm font-bold text-slate-500">Common VRFs ${help}</h3>
        <p class="text-xs text-slate-500" title="${HOW}">The NetBox VRFs that shared infrastructure (such as the shared DNS, DHCP, firewall, Proxmox and ClearPass) serves besides NetBox's global table. A tenant's prefixes in any other VRF are left out when the hub filters that shared data for the tenant. This applies to every tenant.</p>`;
    const err = error ? safeHtml`<p class="text-xs text-red-500">${error}</p>` : '';
    if (!data) return safeHtml`${head}${err || safeHtml`<p class="text-xs text-slate-500 italic animate-pulse">Loading…</p>`}`;
    // What is ticked and common now, and which names more than one VRF has.
    const ticked = new Set([...picked].map(String));
    const common = new Set((data.common || []).map(String));
    const vrfs = Array.isArray(data.vrfs) ? data.vrfs : [];
    const seen = {};
    vrfs.forEach(v => { const k = String(v.name || '').toLowerCase(); if (k) seen[k] = (seen[k] || 0) + 1; });
    const dupNames = new Set(Object.keys(seen).filter(k => seen[k] > 1));
    const auto = data.mode !== 'configured';
    // The mode line, the checkboxes (or why there are none), and Save on the right.
    const mode = auto
        ? safeHtml`<p class="text-xs text-slate-600"><b>Automatic:</b> a VRF two or more tenants have prefixes in is common. Tick VRFs and save to name exactly the common ones instead.</p>`
        : safeHtml`<p class="text-xs text-slate-600"><b>Set by a Global Admin:</b> only the ticked VRFs are common, however many tenants use them. Untick them all and save to go back to automatic.</p>`;
    const list = vrfs.length
        ? safeHtml`<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-10 gap-y-1">${vrfs.map(v => vrfRow(v, ticked, common, auto, dupNames, saving))}</div>`
        : safeHtml`<p class="text-xs text-slate-500 italic">No VRFs in the hub's NetBox cache: no tenant has a prefix in a VRF yet, so only NetBox's global table is common.</p>`;
    const can = isChanged(data, ticked) && !saving;
    const btn = (typeof _SETUP_CLS !== 'undefined' ? _SETUP_CLS.btnCls : '') + ' disabled:opacity-50 disabled:cursor-not-allowed';
    return safeHtml`${head}${mode}${list}${err}
        <div class="flex justify-end"><button type="button" data-action="save" class="${btn}" ${can ? '' : 'disabled'} title="Save the ticked VRFs; with none ticked the hub infers them">${saving ? 'Saving…' : 'Save'}</button></div>`;
}

// True while load `seq` is the newest and System is still open.
function isCurrent(seq) {
    return seq === state.seq && (typeof currentView === 'undefined' || currentView === 'settings');
}

// A checkbox changed: update the ticked set and redraw (Save enables on a change).
function pick(el) {
    if (el.checked) state.picked.add(el.value); else state.picked.delete(el.value);
    view.refresh();
}

// Save the ticked VRFs (none ticked = automatic), one save at a time. The
// reply must hold exactly what was sent; the card then redraws from it.
async function saveCommonVrfs(seq) {
    if (!state.data || inflight) return;
    const ids = sortedIds(state.picked);
    Object.assign(state, { saving: true, error: '' });
    view.refresh();
    try {
        inflight = apiJson('/admin/common-vrfs', { method: 'PUT', body: JSON.stringify({ vrf_ids: ids }) });
        const res = await inflight;
        const stored = sortedIds(res.vrf_ids || []);
        if (stored.join() !== ids.join()) throw new Error('the hub did not store the ticked VRFs');
        if (seq === state.seq) Object.assign(state, { data: res, picked: new Set(stored) });
        showToast(ids.length ? 'Common VRFs saved' : 'Common VRFs cleared: the hub infers them again', 'success');
    } catch (e) {
        if (seq === state.seq) state.error = `Could not save: ${e.message || e}`;
        showToast(`Could not save the common VRFs: ${e.message || e}`, 'error');
    } finally {
        inflight = null;
    }
    if (seq === state.seq) { state.saving = false; view.refresh(); }
}

// Entry point from _renderSetupGeneralTile: draw the card into `containerId`
// from GET /admin/common-vrfs, starting from the saved selection.
async function renderCommonVrfs(containerId) {
    // A fresh card each visit; an older load still running is ignored.
    const seq = ++state.seq;
    Object.assign(state, { data: null, picked: new Set(), saving: false, error: '' });
    const root = document.getElementById(containerId);
    if (!root) return;
    view = createView({ el: root, state, render: s => commonVrfsHtml(s.data, s.picked, s) });
    delegate(root, { pick, save: () => saveCommonVrfs(seq) });
    view.refresh();
    // An earlier card's save still running: wait for it (that card reports a
    // failure), so this card reads what the hub stored and offers no Save meanwhile.
    if (inflight) {
        await inflight.catch(() => {});
        if (!isCurrent(seq)) return;
    }
    // Load the setting and the VRFs to pick from (the hub answers from its cache).
    try {
        const data = await apiJson('/admin/common-vrfs');
        if (!isCurrent(seq)) return;
        Object.assign(state, { data, picked: new Set((data.vrf_ids || []).map(String)) });
    } catch (e) {
        if (!isCurrent(seq)) return;
        state.error = `Could not load the common VRFs: ${e.message || e}`;
    }
    view.refresh();
}

lmViews.commonVrfs = renderCommonVrfs;
