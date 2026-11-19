// OS Updates page (left nav). An ES module: classic code opens it through the
// lmViews registry in main.js (lmViews.osupdates(contentEl)); nothing here is a
// window global. Uses the React-lite helpers: safeHtml markup, createView for
// the parts that re-render, delegate() for every button and field.
import { safeHtml, rawHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';
import { html as phtml, render, useState, useEffect } from '../../assets/preact-htm.module.js';

// ── OS Updates (left-nav view, Global-Admin) ────────────────────────────────
// Fleet OS package updates. The HUB is the module: it collects pending-update
// state from every spoke and agent and, on explicit approval, sends the apply
// commands. Nodes never update themselves.
// Rolling one node at a time, hub last; a manual deploy never reboots (see
// hub_os_updates.py). Deploy everything, or only selected nodes / packages /
// security updates; reboot is a separate per-node action, or Auto-reboot on an
// auto-patch node. Nodes LM cannot patch (appliances, unsupported OS) are left
// out by the hub; the Nodes card shows how many were hidden.
let _osuPoll = null;

// Every button and field on the page; wired by delegate() (js/core/view.js).
const _osuActions = {
    saveAutoCheck: () => osuSaveAutoCheck(),
    setAutoPatchSecurity: el => osuSetAutoPatchSecurity(el.value === 'security'),
    saveAutoPatchExclude: () => osuSaveAutoPatchExclude(),
    saveWindow: () => osuSaveWindow(),
    saveSnapshot: () => osuSaveSnapshot(),
    check: () => osuCheck(),
    applySelected: () => osuApplySelected(),
    apply: () => osuApply(),
    cancel: () => osuCancel(),
    toggleNode: el => osuToggleNode(el.dataset.node, el.checked),
    toggleGroup: el => osuToggleGroup(el.dataset.tenant, el.dataset.state, el.checked),
    setSort: el => osuSetSort(el.value),
    pickTenant: el => osuPick('tenant', el.dataset.pick),
    pickState: el => osuPick('state', el.dataset.pick),
    togglePkg: el => osuTogglePkg(el.dataset.node, el.dataset.pkg, el.checked),
    reboot: el => osuReboot(el.dataset.node),
    fixAccess: el => osuFixAccess(el.dataset.node),
    toggleAutoPatch: el => osuToggleAutoPatch(el.dataset.node, el.checked, el),
    toggleAutoReboot: el => osuToggleAutoReboot(el.dataset.node, el.checked, el),
};

function renderOsUpdatesView(content) {
    // A fresh visit starts from the default order (the dropdown below is new
    // too), with nothing picked and nothing ticked.
    _osuUi.sort = 'attention';
    _osuUi.pick = { tenant: null, state: null };
    _osuClearSel();
    // Fleet-wide settings are Global Admin only; a Tenant Admin sees just their nodes.
    const osuFleetCls = isAdmin() ? '' : 'hidden';
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    const sub = 'border border-slate-200 rounded-md p-4 space-y-3';
    const subTitle = 'text-xs font-bold text-slate-500';
    const h3 = 'text-sm font-bold text-slate-500';
    content.innerHTML = safeHtml`
        <div class="${card}">
            <div class="flex items-center justify-between">
                <h3 class="${h3}">OS Updates ${rawHtml(helpIcon('lm-hub', null, 'Hub help'))} <span class="cursor-help normal-case font-normal text-slate-500" title="Operating-system package updates (apt dist-upgrade) for every spoke and agent. Global Admin only; every approval is audit-logged.
• Deploy every listed node, only selected nodes/packages, or only security updates.
• A manual deploy never reboots; a host that needs one gets a Reboot… button. Proxmox cluster nodes are the exception (below).
• Auto-patch is approved per node and runs only in the maintenance window, minus packages under &quot;Never auto-install&quot;.
• Auto-reboot (on by default for auto-patch nodes) reboots nodes that installed something once the run is done, hub last.
• Proxmox cluster nodes reboot only when needed, in HA maintenance mode (guests move off first), one node at a time.
• Nodes update one at a time; the hub goes last (this page restarts).
• Nothing is listed until you pick a tenant or a state (needs attention, patching, updates pending, not checked yet, up to date) in the bar above the list; click a picked one again to clear it. Changing the pick unticks every node.
• The picked nodes are grouped by tenant, then by state; each group has a Select all and the Sort box orders them.
• Ticks, Approve &amp; deploy listed and Select fixes (Who is affected?) cover only the listed nodes. The summary of failed nodes names the listed ones, plus any whose spoke is offline (they drop out of the list, so even a lone one is named) while no tenant and no state other than needs attention is picked, and always when no node reports at all.
• Separate from LM code updates.">ⓘ</span></h3>
                <span class="flex items-center gap-3"><span id="osu-status" class="text-xs text-slate-500"></span><span id="osu-checked" class="text-xs text-slate-500"></span></span>
            </div>
            <div id="osu-summary" class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3"></div>
            <div class="flex flex-wrap items-center gap-2">
                <button data-action="check" class="${btnSecCls}">↻ Check for updates</button>
                <button id="osu-apply-selected" data-action="applySelected" class="${btnCls}" disabled>Deploy selected (0)</button>
                <button id="osu-apply" data-action="apply" class="${btnSecCls}" disabled title="Every listed node that has pending updates, never a node the list hides. Pick a tenant or a state to list nodes.">Approve &amp; deploy listed (0)</button>
                <label class="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer ml-1" title="Nodes without picked packages get only their pending security updates"><input type="checkbox" id="osu-security-only" class="w-4 h-4 rounded">Security updates only</label>
                <button id="osu-cancel" data-action="cancel" class="${btnSecCls} hidden">Cancel run</button>
                <span id="osu-run" class="text-xs text-slate-500 ml-auto"></span>
            </div>
        </div>
        <div class="${card} mt-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
                <h3 class="${h3}">Nodes</h3>
                <span class="flex items-center gap-3">
                    <span id="osu-hidden" class="text-xs text-slate-500"></span>
                    <label class="flex items-center gap-1.5 text-xs text-slate-500" for="osu-sort">Sort
                        <select id="osu-sort" class="${inputCls} w-48" data-action="setSort" title="Tenants and the nodes inside each state group">
                            <option value="attention">Needs attention first</option>
                            <option value="name">Name (A–Z)</option>
                            <option value="updates">Most updates first</option>
                        </select>
                    </label>
                </span>
            </div>
            <div id="osu-body"><p class="text-xs text-slate-500 italic">Loading…</p></div>
        </div>
        <div class="${card} mt-4">
            <h3 class="${h3}">Who is affected?</h3>
            <div id="osu-cve" class="space-y-3"></div>
        </div>
        <div class="${card} mt-4 ${osuFleetCls}">
            <h3 class="${h3}">Automation</h3>
            <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <div class="${sub}">
                    <div class="${subTitle}">Auto-check</div>
                    <div class="flex flex-wrap items-center gap-3">
                        <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="osu-autocheck-enabled" class="w-4 h-4 text-green-600 rounded">Check the fleet every</label>
                        <input type="number" id="osu-autocheck-hours" min="1" step="1" value="6" class="${inputCls} w-20">
                        <span class="text-xs text-slate-500">hour(s)</span>
                        <span id="osu-autocheck-status" class="text-xs text-slate-500"></span>
                        <button data-action="saveAutoCheck" class="${btnSecCls} ml-auto">Save</button>
                    </div>
                </div>
                <div class="${sub}">
                    <div class="${subTitle}" title="Auto-patch and auto-reboot only run in this window (once per window). Same start and end = any time.">Maintenance window</div>
                    <div class="flex flex-wrap items-end gap-3">
                        <div class="space-y-1"><label class="${labelCls}">From</label><input type="time" id="osu-window-start" class="${inputCls} w-32" value="01:00"></div>
                        <div class="space-y-1"><label class="${labelCls}">To</label><input type="time" id="osu-window-end" class="${inputCls} w-32" value="05:00"></div>
                        <div class="space-y-1 flex-1 min-w-[10rem]"><label class="${labelCls}">Timezone</label><input type="text" id="osu-window-tz" class="${inputCls}" placeholder="e.g. America/Chicago"></div>
                        <button data-action="saveWindow" class="${btnSecCls}">Save</button>
                    </div>
                </div>
                <div class="${sub}">
                    <div class="flex items-center justify-between"><span class="${subTitle}">Auto-patch</span><span id="osu-autopatch-count" class="text-xs text-slate-500"></span></div>
                    <p class="text-xs text-slate-500">Only nodes ticked <b>Auto-patch</b> in the Nodes list are patched, inside the maintenance window.</p>
                    <div class="flex flex-wrap items-end gap-3">
                        <div class="space-y-1">
                            <label class="${labelCls}">Install</label>
                            <select id="osu-autopatch-security" class="${inputCls} w-48" data-action="setAutoPatchSecurity">
                                <option value="security">Security updates only</option>
                                <option value="all">All updates</option>
                            </select>
                        </div>
                        <div class="space-y-1 flex-1 min-w-[12rem]">
                            <label class="${labelCls}" title="Package names or globs, comma-separated. Auto-patch never installs these; manual deploys are unaffected.">Never auto-install</label>
                            <input type="text" id="osu-autopatch-exclude" class="${inputCls}" placeholder="e.g. linux-image-*, docker-ce, proxmox-*">
                        </div>
                        <button data-action="saveAutoPatchExclude" class="${btnSecCls}">Save</button>
                    </div>
                </div>
                <div class="${sub}">
                    <div class="${subTitle}">Pre-patch VM snapshots</div>
                    <div class="flex flex-wrap items-center gap-3">
                        <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer" title="Before patching a node that runs in a Proxmox VM, LM snapshots that VM (manual deploys and auto-patch). If the snapshot fails the node is not patched; a VM that cannot be snapshotted at all (storage without snapshot support, or a spoke without VM-action support) is patched with a warning. Proxmox hosts themselves (bare metal) are patched without a snapshot."><input type="checkbox" id="osu-snap-enabled" class="w-4 h-4 text-green-600 rounded" checked>Snapshot VMs before patching, keep</label>
                        <input type="number" id="osu-snap-keep" min="1" max="20" step="1" value="2" class="${inputCls} w-20" title="Older pre-patch snapshots (lm-prepatch-*) beyond this count are deleted">
                        <button data-action="saveSnapshot" class="${btnSecCls} ml-auto">Save</button>
                    </div>
                </div>
            </div>
        </div>`;
    delegate(content, _osuActions);
    osuLoad();
    osuLoadAutoCheck();
    osuLoadAutoPatch();
    render(phtml`<${CveLookup} />`, document.getElementById('osu-cve'));
}

// Footer "Pending Reboot" alert: during the maintenance window, lists the
// nodes auto-reboot is about to restart (hover for the list). Admins (a
// Tenant Admin sees their own nodes), like the rest of OS Updates; refreshed every minute.
async function osuRefreshRebootTray() {
    const tray = document.getElementById('reboot-tray');
    if (!tray) return;
    let data = { nodes: [] };
    if (typeof isAdmin === 'function' && (isAdmin() || isTenantAdmin())) {
        try { data = await apiJson('/api/os-updates/pending-reboots'); } catch (e) { /* keep hidden */ }
    }
    const nodes = data.in_window ? (data.nodes || []) : [];
    tray.classList.toggle('hidden', !nodes.length);
    tray.classList.toggle('flex', nodes.length > 0);
    if (!nodes.length) return;
    const w = data.window || {};
    document.getElementById('reboot-tray-tooltip').innerHTML = safeHtml`
        <div class="font-bold mb-1">${nodes.length} system(s) will be rebooted</div>
        ${nodes.map(n => safeHtml`<div class="flex justify-between gap-4 py-0.5"><span>${n.label}</span><span class="opacity-60">${n.note}</span></div>`)}
        <div class="opacity-60 mt-1">Maintenance window ${w.start}–${w.end} ${w.tz}</div>`;
}
setTimeout(osuRefreshRebootTray, 5000);
setInterval(osuRefreshRebootTray, 60000);



async function osuLoadAutoPatch() {
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch');
        document.getElementById('osu-autopatch-security').value = cfg.security_only !== false ? 'security' : 'all';
        document.getElementById('osu-autopatch-exclude').value = (cfg.exclude || []).join(', ');
        osuShowWindow(cfg.window);
        osuShowSnapshot(cfg.snapshot);
    } catch (e) { /* best-effort */ }
}

function osuShowSnapshot(snap) {
    if (!snap) return;
    document.getElementById('osu-snap-enabled').checked = !!snap.enabled;
    document.getElementById('osu-snap-keep').value = snap.keep;
}

async function osuSaveSnapshot() {
    const snapshot = {
        enabled: document.getElementById('osu-snap-enabled').checked,
        keep: parseInt(document.getElementById('osu-snap-keep').value, 10),
    };
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ snapshot }) });
        osuShowSnapshot(cfg.snapshot);
        showToast(cfg.snapshot.enabled
            ? `VMs are snapshotted before patching (keeping ${cfg.snapshot.keep}).`
            : 'Pre-patch snapshots turned off.', 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}

function osuShowWindow(w) {
    if (!w) return;
    document.getElementById('osu-window-start').value = w.start;
    document.getElementById('osu-window-end').value = w.end;
    document.getElementById('osu-window-tz').value = w.tz;
}

async function osuSaveWindow() {
    const window_ = {
        start: document.getElementById('osu-window-start').value,
        end: document.getElementById('osu-window-end').value,
        // Default to this browser's timezone so "01:00" means the operator's 1 AM.
        tz: document.getElementById('osu-window-tz').value.trim()
            || Intl.DateTimeFormat().resolvedOptions().timeZone,
    };
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ window: window_ }) });
        osuShowWindow(cfg.window);
        const w = cfg.window;
        showToast(w.start === w.end
            ? `Auto-patch may run at any time (${w.tz}).`
            : `Auto-patch runs between ${w.start} and ${w.end} (${w.tz}).`, 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function osuSaveAutoPatchExclude() {
    const exclude = document.getElementById('osu-autopatch-exclude').value
        .split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ exclude }) });
        document.getElementById('osu-autopatch-exclude').value = (cfg.exclude || []).join(', ');
        showToast(cfg.exclude && cfg.exclude.length
            ? `Auto-patch will never install: ${cfg.exclude.join(', ')}.`
            : 'Auto-patch exclusions cleared.', 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function osuSetAutoPatchSecurity(on) {
    try {
        await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ security_only: on }) });
        showToast(on ? 'Auto-patch: security updates only.' : 'Auto-patch: all updates.', 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function osuToggleAutoPatch(key, on, el) {
    const n = _osuNode(key);
    const label = n ? n.label : key;
    const hubNote = n && n.kind === 'hub' ? '\n\nThis is the HUB — patching it restarts LM services, and Auto-reboot reboots it last.' : '';
    if (on && !confirm(`Approve ${label} for auto-patching?\n\nIn each maintenance window its pending updates are installed automatically, then the node is rebooted (Auto-reboot — untick it to keep the node up).${hubNote}`)) {
        if (el) el.checked = false;
        return;
    }
    try {
        await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ node: key, enabled: on }) });
        showToast(`${label}: auto-patch ${on ? 'approved' : 'off'}.`, 'success');
        osuLoad();
    } catch (e) { if (el) el.checked = !on; showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function osuToggleAutoReboot(key, on, el) {
    const n = _osuNode(key);
    const label = n ? n.label : key;
    try {
        await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ node: key, auto_reboot: on }) });
        showToast(`${label}: auto-reboot ${on ? 'on' : 'off'}.`, 'success');
        osuLoad();
    } catch (e) { if (el) el.checked = !on; showToast('Save failed: ' + (e.message || e), 'error'); }
}

// One-time login for a node blocked by missing privileges. The password goes
// to that node once to install its update helper; LM never stores it.
function osuFixAccess(key) {
    const n = _osuNode(key);
    if (!n) return;
    const inp = 'w-full px-3 py-2 border border-slate-200 rounded-md text-sm';
    const modal = openModal('osu-fix-modal', safeHtml`
      <h3 class="text-lg font-bold text-navy">Fix update access — ${n.label}</h3>
      <p class="text-sm text-slate-500">Enter the root password (or a user that can sudo) for this node, one time. It is used once to install LM's update helper and is <b>never stored</b>.</p>
      <input id="osu-fix-user" type="text" value="root" autocomplete="off" placeholder="username" class="${inp}">
      <input id="osu-fix-pw" type="password" autocomplete="off" placeholder="password" class="${inp}">
      <div class="flex justify-end gap-2 pt-2">
        <button data-action="close" class="px-4 py-1.5 text-sm rounded-full border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button id="osu-fix-go" data-action="fix" class="px-4 py-1.5 text-sm rounded-full bg-primary text-white font-bold hover:bg-primary-hover">Fix access</button>
      </div>`, { backdropClose: true });
    delegate(modal, { close: () => modal.remove(), fix: () => osuDoFixAccess(key) });
    document.getElementById('osu-fix-pw')?.focus();
}

async function osuDoFixAccess(key) {
    const pwEl = document.getElementById('osu-fix-pw');
    const username = (document.getElementById('osu-fix-user')?.value || 'root').trim();
    const password = pwEl?.value || '';
    if (!password) { showToast('Enter the password.', 'info'); return; }
    const btn = document.getElementById('osu-fix-go');
    if (btn) { btn.disabled = true; btn.textContent = 'Fixing…'; }
    try {
        const r = await apiJson('/api/os-updates/fix-access', { method: 'POST', body: JSON.stringify({ node: key, username, password }) });
        document.getElementById('osu-fix-modal')?.remove();
        showToast(r.message || 'Access fixed.', 'success');
        osuLoad();
    } catch (e) {
        if (pwEl) pwEl.value = '';
        if (btn) { btn.disabled = false; btn.textContent = 'Fix access'; }
        showToast('Fix failed: ' + (e.message || e), 'error');
    }
}

async function osuLoadAutoCheck() {
    try {
        const cfg = await apiJson('/api/os-updates/auto-check');
        const chk = document.getElementById('osu-autocheck-enabled');
        const hrs = document.getElementById('osu-autocheck-hours');
        if (chk) chk.checked = cfg.enabled !== false;
        if (hrs) hrs.value = cfg.interval_hours ?? 6;
    } catch (e) { /* best-effort — the manual Check button still works */ }
}

async function osuSaveAutoCheck() {
    const enabled = !!document.getElementById('osu-autocheck-enabled')?.checked;
    const hours = Math.max(1, parseInt(document.getElementById('osu-autocheck-hours')?.value, 10) || 6);
    const st = document.getElementById('osu-autocheck-status');
    try {
        const cfg = await apiJson('/api/os-updates/auto-check', {
            method: 'POST', body: JSON.stringify({ enabled, interval_hours: hours }),
        });
        document.getElementById('osu-autocheck-hours').value = cfg.interval_hours;
        showToast(cfg.enabled ? `Auto-check enabled — every ${cfg.interval_hours}h.` : 'Auto-check disabled.', 'success');
        if (st) { st.textContent = 'saved'; setTimeout(() => { if (st) st.textContent = ''; }, 2000); }
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function osuLoad() {
    try { _osuRender(await apiJson('/api/os-updates')); }
    catch (e) { const b = document.getElementById('osu-body'); if (b) b.innerHTML = safeHtml`<p class="text-xs text-red-500">${e.message || e}</p>`; }
}

async function osuCheck() {
    const st = document.getElementById('osu-status');
    if (st) st.textContent = 'checking every node…';
    try { _osuRender(await apiJson('/api/os-updates/check', { method: 'POST', body: JSON.stringify({ refresh: true }) })); showToast('Update check complete.', 'success'); }
    catch (e) { showToast('Check failed: ' + (e.message || e), 'error'); }
    finally { if (st) st.textContent = ''; }
}

// Selection survives the 5s progress re-render: node keys picked whole, and
// per-node package picks (a node with package picks applies only those). A
// package pick never selects the whole node — clearing the last pick must not
// leave a full dist-upgrade selected.
const _osuSel = { nodes: new Set(), pkgs: {} };

// How the node list is ordered ('attention' | 'name' | 'updates'), and the
// drill-down picks. Nothing is listed until a tenant or a state is picked
// (owner request: never open on every node and then filter). null = not
// picked; a tenant pick is a group key from _osuTenantKey(), a state pick an
// _OSU_STATES id. Not saved: leaving the tab and coming back resets both
// (renderOsUpdatesView).
const _osuUi = { sort: 'attention', pick: { tenant: null, state: null } };

// The node list is a view (js/core/view.js): a re-render morphs the page, so
// open package lists stay open while polling.
const _osuView = createView({ el: 'osu-body', state: { data: {} }, render: _osuBodyHtml });
function _osuNode(key) { return (_osuView.state.data.nodes || []).find(x => `${x.kind}:${x.id}` === key); }

function _osuSelectedKeys() { return [...new Set([..._osuSel.nodes, ...Object.keys(_osuSel.pkgs)])]; }

function _osuBusy() { const r = _osuView.state.data.run; return !!(r && r.status === 'running'); }

function osuToggleNode(key, on) {
    _osuSel.nodes[on ? 'add' : 'delete'](key);
    delete _osuSel.pkgs[key];
    _osuRender(_osuView.state.data);
}

function osuTogglePkg(key, pkg, on) {
    const set = _osuSel.pkgs[key] || (_osuSel.pkgs[key] = new Set());
    if (on) { set.add(pkg); _osuSel.nodes.delete(key); } else set.delete(pkg);
    if (!set.size) delete _osuSel.pkgs[key];
    _osuRender(_osuView.state.data);
}

// A group's "Select all": tick (or untick) every deployable node in that
// tenant + state group. Like a single node tick, it drops that node's package picks.
function osuToggleGroup(tenantKey, state, on) {
    const d = _osuView.state.data;
    const busy = _osuBusy();
    (d.nodes || []).map(n => _osuClassify(n, d.run, busy))
        .filter(c => c.tenantKey === tenantKey && c.group === state && _osuSelectable(c.n, busy))
        .forEach(c => { _osuSel.nodes[on ? 'add' : 'delete'](c.key); delete _osuSel.pkgs[c.key]; });
    _osuRender(d);
}

// Sort dropdown changed: redraw the list from the data already loaded.
function osuSetSort(sort) {
    _osuUi.sort = sort;
    _osuView.refresh();
}

// Untick every node and package.
function _osuClearSel() {
    _osuSel.nodes.clear();
    Object.keys(_osuSel.pkgs).forEach(k => delete _osuSel.pkgs[k]);
}

// A drill-down chip was clicked ('tenant' or 'state' row): pick it, or clear
// the pick when it is already picked. Every tick is cleared too, so none is
// left on a node the new pick hides. The list is redrawn from scratch: a new
// pick is a new view, so its groups open as the defaults say rather than as
// the user left them under the old pick.
function osuPick(row, value) {
    _osuUi.pick[row] = _osuUi.pick[row] === value ? null : value;
    _osuClearSel();
    const body = document.getElementById('osu-body');
    if (body) body.innerHTML = '';
    _osuRender(_osuView.state.data);
}

// What "Select fixes" can tick for a CVE lookup: the pending upgrades of the
// vulnerable packages on each affected node whose packages can be picked.
// `listed` holds the [node key, package] pairs on nodes the list shows under
// the current picks; `hidden` counts those on nodes it hides. Only the listed
// ones are ticked: a tick on a hidden node could not be seen or cleared before
// "Deploy selected". A package that two CVEs share counts once.
function _osuCveFixes(d) {
    const data = _osuView.state.data;
    const busy = _osuBusy();
    const nodes = (data.nodes || []).map(n => _osuClassify(n, data.run, busy));
    const shown = new Set((_osuListed(nodes) || []).map(c => c.key));
    const pending = new Map(nodes.filter(c => _osuCanPick(c.n, busy))
        .map(c => [c.key, new Set((c.n.packages || []).map(p => p.package))]));
    const fixes = new Map();  // node key -> its fix packages
    (d.results || []).forEach(r => r.affected.forEach(a => {
        const avail = pending.get(a.node);
        if (avail) a.binaries.filter(b => avail.has(b)).forEach(b => fixes.set(a.node, (fixes.get(a.node) || new Set()).add(b)));
    }));
    const pairs = [...fixes].flatMap(([key, pkgs]) => [...pkgs].map(p => [key, p]));
    return { listed: pairs.filter(([key]) => shown.has(key)), hidden: pairs.filter(([key]) => !shown.has(key)).length };
}

// "Select fixes": tick the CVE's fixes on the listed nodes (_osuCveFixes).
function osuCveSelectFixes(d) {
    const picks = _osuCveFixes(d).listed;
    picks.forEach(([key, pkg]) => {
        (_osuSel.pkgs[key] || (_osuSel.pkgs[key] = new Set())).add(pkg);
        _osuSel.nodes.delete(key);
    });
    _osuRender(_osuView.state.data);
    showToast(`${picks.length} package update(s) selected — review, then "Deploy selected".`, 'success');
}

// "Who is affected?" — a Preact component (React-lite phase 6). Search a CVE
// id or a package name; the hub answers from the last check's installed
// packages and Debian's security tracker. phtml`` escapes every value.
function CveLookup() {
    const [q, setQ] = useState('');
    const [fleet, setFleet] = useState([]);
    const [result, setResult] = useState({ data: null, loading: false, error: '' });

    // Suggestions: only the CVEs that affect at least one node.
    useEffect(() => { apiJson('/api/os-updates/cves/fleet').then(setFleet, () => {}); }, []);

    async function search(query) {
        query = query.trim();
        if (!query) return;
        setResult({ data: null, loading: true, error: '' });
        try {
            setResult({ data: await apiJson('/api/os-updates/cves?q=' + encodeURIComponent(query)), loading: false, error: '' });
        } catch (e) {
            setResult({ data: null, loading: false, error: e.message || String(e) });
        }
    }

    function typed(value) {
        setQ(value);
        if (fleet.some(c => c.cve === value)) search(value);  // picked a suggestion
    }

    const { inputCls, labelCls, btnSecCls } = _SETUP_CLS;
    return phtml`
        <form class="flex flex-wrap items-end gap-3" onSubmit=${e => { e.preventDefault(); search(q); }}>
            <div class="space-y-1 flex-1 min-w-[16rem]">
                <label class=${labelCls} title="Matches each node's installed packages (reported at the last check) against Debian's security tracker">CVE id or package</label>
                <input type="text" id="osu-cve-q" list="osu-cve-list" autocomplete="off" class=${inputCls}
                    placeholder="e.g. CVE-2026-1234 or php" value=${q} onInput=${e => typed(e.target.value)}
                    title=${fleet.length ? `${fleet.length} CVE(s) affect the fleet — start typing to pick one` : ''} />
                <datalist id="osu-cve-list">
                    ${fleet.map(c => phtml`<option value=${c.cve} label=${`${c.urgency ? c.urgency + ' · ' : ''}${c.nodes} node(s) · ${c.description}`} />`)}
                </datalist>
            </div>
            <button type="submit" class=${btnSecCls}>Look up</button>
        </form>
        <div id="osu-cve-body">
            ${result.loading ? phtml`<p class="text-xs text-slate-500 italic">Looking up…</p>`
                : result.error ? phtml`<p class="text-xs text-red-600">${result.error}</p>`
                : result.data ? phtml`<${CveResult} d=${result.data} />` : null}
        </div>`;
}

function Badge({ text, color, title }) {
    return phtml`<span class="text-xs font-bold ${_OSU_BADGE_CLS[color]} border rounded-full px-2 py-0.5" title=${title || ''}>${text}</span>`;
}

function CveNodeRow({ a, patched }) {
    const status = patched ? phtml`<${Badge} text="patched" color="emerald" />`
        : a.update_pending ? phtml`<${Badge} text="update pending" color="amber" title="An update for this package is waiting — deploy it from this page" />`
        : a.fix_available ? phtml`<${Badge} text="fixed in Debian — not yet installable here" color="amber" title='Run "Check for updates"; the node may lack the security repo' />`
        : phtml`<${Badge} text="no fix yet" color="red" title="Debian has not released a fix for this release" />`;
    return phtml`<div class="flex flex-wrap items-center justify-between gap-2 py-0.5">
        <span><b class="text-slate-700">${a.label}</b> <span class="text-slate-500">debian ${a.release}</span> — ${a.package} <span class="text-slate-500">${a.version} (${a.binaries.join(', ')})</span></span>
        ${status}</div>`;
}

function CveCard({ r }) {
    const flags = [r.urgency ? `${r.urgency} urgency` : '', r.remote ? 'remote' : ''].filter(Boolean).join(' · ');
    const patched = r.patched || [];
    return phtml`<div class="border border-slate-200 rounded-md p-2 bg-white text-xs">
        <div class="flex flex-wrap items-center gap-2">
            <a href=${'https://security-tracker.debian.org/tracker/' + encodeURIComponent(r.cve)} target="_blank" rel="noopener" class="font-bold text-slate-700 underline">${r.cve}</a>
            <span class="text-slate-500">${flags}</span>
            ${r.affected.length ? phtml`<${Badge} text=${`${r.affected.length} affected`} color="red" />` : phtml`<${Badge} text="no node affected" color="emerald" />`}
        </div>
        <div class="text-slate-500 mt-0.5">${r.description || ''}</div>
        ${r.affected.map(a => phtml`<${CveNodeRow} a=${a} />`)}
        ${patched.length ? phtml`<details class="mt-1"><summary class="cursor-pointer text-xs text-slate-500">${patched.length} node(s) have the package and are patched</summary>
            ${patched.map(a => phtml`<${CveNodeRow} a=${a} patched />`)}</details>` : null}
    </div>`;
}

function CveResult({ d }) {
    const note = (cls, text) => phtml`<p class="text-xs ${cls}">${text}</p>`;
    let body;
    if (!Object.keys(d.feeds || {}).length) {
        body = note('text-amber-700', 'No Debian security data yet — run "Check for updates" so nodes report their installed packages and the hub fetches the tracker feed.');
    } else if (d.kind === 'cve' && !d.known) {
        body = note('text-slate-500', `${d.query} is not in Debian's security tracker for the release(s) in this fleet — it may not affect Debian packages, or not be published yet.`);
    } else if (!(d.results || []).length) {
        body = note('text-slate-500', `No open CVEs match "${d.query}" on any checked node.`);
    } else {
        const fixes = _osuCveFixes(d);
        body = phtml`<div class="flex flex-wrap items-center gap-2 text-xs">
                <b class=${d.affected_nodes ? 'text-red-700' : 'text-emerald-700'}>${d.affected_nodes} of ${d.checked_nodes} checked node(s) affected</b>
                ${fixes.listed.length ? phtml`<button type="button" onClick=${() => osuCveSelectFixes(d)} class="text-xs font-bold text-emerald-800 border border-emerald-300 rounded px-2 py-0.5 hover:bg-emerald-50" title="Pick the pending updates of the vulnerable packages on the affected nodes listed under Nodes">Select fixes (${fixes.listed.length})</button>` : null}
                ${fixes.hidden ? phtml`<span class="text-slate-500" title="Select fixes ticks only nodes listed under Nodes">${fixes.hidden} fix(es) on nodes not listed above: pick their tenant or state to select them</span>` : null}
                ${d.truncated ? phtml`<span class="text-slate-500">showing the first 200 CVEs — narrow the search</span>` : null}</div>
            ${d.results.map(r => phtml`<${CveCard} r=${r} />`)}`;
    }
    const unknown = d.unknown || [];
    const feeds = Object.entries(d.feeds || {}).map(([c, f]) =>
        `${c}${f.fetched_at ? ' ' + new Date(f.fetched_at * 1000).toLocaleString() : ''}${f.error ? ' (refresh failed: ' + f.error + ')' : ''}`).join(', ');
    return phtml`<div class="space-y-2">
        ${body}
        ${unknown.length ? phtml`<details><summary class="cursor-pointer text-xs text-amber-700">${unknown.length} node(s) could not be assessed</summary>
            ${unknown.map(u => phtml`<div class="text-xs text-slate-500"><b>${u.label}</b> — ${u.reason}</div>`)}</details>` : null}
        <p class="text-xs text-slate-500">Installed packages as of the last check · Debian security tracker data: ${feeds || 'none available'}</p>
    </div>`;
}

async function _osuDeploy(body, summary) {
    const secOnly = !!document.getElementById('osu-security-only')?.checked;
    body.security_only = secOnly;
    // Deliberate friction: this changes packages on real hosts.
    if (!confirm(`Approve and deploy OS updates?\n\n${summary}\n\n` +
                 `• ${secOnly ? 'security updates only (unless packages were picked)' : 'apt dist-upgrade, or just the picked packages'}\n` +
                 `• one node at a time, hub last\n` +
                 `• nothing is rebooted automatically — you'll get a badge instead`)) return;
    try {
        const r = await apiJson('/api/os-updates/apply', { method: 'POST', body: JSON.stringify(body) });
        showToast(`Deploying to ${r.queued} node(s) — one at a time.`, 'success');
        _osuClearSel();
        _osuStartPoll();
    } catch (e) { showToast('Apply failed: ' + (e.message || e), 'error'); }
}

// What "Approve & deploy listed" deploys and counts: the nodes the list shows
// under the current picks (_osuListed) that a group's Select all would tick.
// None while the list asks for a pick, so it never deploys a node the list
// hides (fleet rule 7.5: select-all covers only the current view).
function _osuDeployable(d, busy) {
    return (_osuListed((d.nodes || []).map(n => _osuClassify(n, d.run, busy))) || []).filter(c => _osuSelectable(c.n, busy));
}

// "Approve & deploy listed": send the listed deployable nodes by key, so the
// hub patches only those (an empty body would mean every node in scope).
async function osuApply() {
    const rows = _osuDeployable(_osuView.state.data, _osuBusy());
    if (!rows.length) { showToast('No listed node has pending updates.', 'info'); return; }
    _osuDeploy({ nodes: rows.map(c => c.key) }, `All ${rows.length} listed node(s) with pending updates.`);
}

async function osuApplySelected() {
    const keys = _osuSelectedKeys();
    if (!keys.length) { showToast('Select at least one node or package.', 'info'); return; }
    const labels = Object.fromEntries((_osuView.state.data.nodes || []).map(n => [`${n.kind}:${n.id}`, n.label]));
    const packages = {};
    const lines = keys.map(k => {
        const picked = _osuSel.pkgs[k];
        if (picked && picked.size) { packages[k] = [...picked]; return `• ${labels[k] || k}: ${picked.size} package(s)`; }
        return `• ${labels[k] || k}: all pending`;
    });
    const nodes = keys.filter(k => !packages[k]);
    _osuDeploy({ nodes, packages }, lines.join('\n'));
}

async function osuCancel() {
    if (!confirm('Cancel the update run?\n\nThe node currently updating will finish (apt cannot be safely interrupted); queued nodes are skipped.')) return;
    try { const r = await apiJson('/api/os-updates/cancel', { method: 'POST', body: '{}' }); showToast(r.message || 'Cancelling…', 'success'); }
    catch (e) { showToast('Cancel failed: ' + (e.message || e), 'error'); }
}

async function osuReboot(key) {
    const n = _osuNode(key);
    if (!n) return;
    const warn = n.kind === 'hub' ? '\n\nThis is the HUB — the WebUI and every spoke connection drop until it is back.'
        : (n.flavor === 'proxmox' ? '\n\nThis is a Proxmox host — every VM on it goes down with it.' : '');
    if (!confirm(`Reboot ${n.label} in 1 minute?${warn}\n\n(Cancel on the host with: shutdown -c)`)) return;
    try {
        const r = await apiJson('/api/os-updates/reboot', { method: 'POST', body: JSON.stringify({ node: key }) });
        showToast(`${n.label}: ${r.message || 'reboot scheduled'}`, 'success');
        osuLoad();
    } catch (e) { showToast('Reboot failed: ' + (e.message || e), 'error'); }
}

function _osuStartPoll() {
    if (_osuPoll) clearInterval(_osuPoll);
    // A dist-upgrade takes minutes; poll the snapshot so the roll's progress is
    // visible without the operator refreshing.
    _osuPoll = setInterval(async () => {
        try {
            const d = await apiJson('/api/os-updates');
            _osuRender(d);
            if (!d.run || d.run.status !== 'running') { clearInterval(_osuPoll); _osuPoll = null; }
        } catch (e) { clearInterval(_osuPoll); _osuPoll = null; }
    }, 5000);
}

// Literal class strings: Tailwind is precompiled, so built-up names wouldn't exist.
const _OSU_BADGE_CLS = {
    blue: 'text-blue-700 bg-blue-50 border-blue-200',
    red: 'text-red-700 bg-red-50 border-red-200',
    emerald: 'text-emerald-700 bg-emerald-50 border-emerald-200',
    amber: 'text-amber-800 bg-amber-50 border-amber-200',
    slate: 'text-slate-500 bg-slate-100 border-slate-300',
};
const _osuBadge = (text, color, title) => safeHtml`<span class="text-xs font-bold ${_OSU_BADGE_CLS[color]} border rounded-full px-2 py-0.5" title="${title || ''}">${text}</span>`;

function _osuVmLabel(n) {
    if (n.vm) return safeHtml` · <span title="Snapshotted before patching">VM ${n.vm.name} (${n.vm.vmid}@${n.vm.node})</span>`;
    return n.vm_note ? safeHtml` · <span title="Not snapshotted before patching">${n.vm_note}</span>` : '';
}

// New data from the hub: update the toolbar around the list, then the list.
function _osuRender(d) {
    _osuView.state.data = d;
    if (!document.getElementById('osu-body')) return;
    const run = d.run;
    const busy = _osuBusy();
    // A picked tenant that no longer has a node (its spokes went away) falls
    // back to "not picked", with its ticks: its chip could not be drawn to
    // clear it. A state pick is kept even when empty: nodes move between
    // states during a run, and its chip is drawn while any node reports. With
    // no node at all there is no bar, so it falls back too: nodes that report
    // again are not listed under a pick the page no longer shows.
    const pick = _osuUi.pick;
    if (pick.tenant !== null && !(d.nodes || []).some(n => _osuTenantKey(n) === pick.tenant)) {
        pick.tenant = null;
        _osuClearSel();
    }
    if (!(d.nodes || []).length) pick.state = null;
    // A re-check or a run can move a ticked node out of the picked tenant or
    // state: its tick goes too, so "Deploy selected" never counts a node the
    // list hides.
    const listed = new Set((_osuListed((d.nodes || []).map(n => _osuClassify(n, run, busy))) || []).map(c => c.key));
    _osuSelectedKeys().filter(k => !listed.has(k)).forEach(k => { _osuSel.nodes.delete(k); delete _osuSel.pkgs[k]; });
    const runEl = document.getElementById('osu-run');
    if (runEl) {
        const label = { finished: 'complete', cancelled: 'cancelled', interrupted: 'interrupted by a hub restart' };
        runEl.textContent = busy
            ? `deploying ${run.done}/${run.total} — current: ${run.current || '…'}${run.cancel_requested ? ' (cancelling after this node)' : ''}`
            : (run && label[run.status] ? `last run${run.actor === 'auto-patch' ? ' (auto-patch)' : ''}: ${run.done}/${run.total} ${label[run.status]}` : '');
    }
    const nSel = _osuSelectedKeys().length;
    const nAll = _osuDeployable(d, busy).length;
    const btn = document.getElementById('osu-apply');
    if (btn) { btn.disabled = !nAll; btn.textContent = `Approve & deploy listed (${nAll})`; }
    const selBtn = document.getElementById('osu-apply-selected');
    if (selBtn) { selBtn.disabled = busy || !nSel; selBtn.textContent = `Deploy selected (${nSel})`; }
    const cancelBtn = document.getElementById('osu-cancel');
    if (cancelBtn) cancelBtn.classList.toggle('hidden', !busy);
    const apCount = document.getElementById('osu-autopatch-count');
    if (apCount) { const k = (d.nodes || []).filter(n => n.auto_patch).length; apCount.textContent = k ? `${k} node(s) approved` : 'no nodes approved'; }
    const t = d.totals || {};
    const tile = (label, val, cls) => safeHtml`<div class="rounded border border-slate-200 px-4 py-3"><div class="text-xs text-slate-500">${label}</div><div class="text-2xl font-semibold ${cls || 'text-slate-700'}">${val || 0}</div></div>`;
    const sumEl = document.getElementById('osu-summary');
    if (sumEl) sumEl.innerHTML = safeHtml`${tile('Nodes', t.nodes)}${tile('With updates', t.with_updates, t.with_updates && 'text-amber-600')}${tile('Packages', t.packages)}${tile('Security', t.security, t.security && 'text-red-600')}${tile('Need reboot', t.reboot_required, t.reboot_required && 'text-amber-600')}${tile('Unreachable', t.unreachable, t.unreachable && 'text-red-600')}`;
    const notes = [];
    if (t.blocked) notes.push(`${t.blocked} blocked`);
    if (t.not_checked) notes.push(`${t.not_checked} not checked yet`);
    if (t.unmanaged) notes.push(`${t.unmanaged} appliance/unsupported node(s) hidden`);
    const hiddenEl = document.getElementById('osu-hidden');
    if (hiddenEl) hiddenEl.textContent = notes.join(' · ');
    const checkedEl = document.getElementById('osu-checked');
    if (checkedEl) checkedEl.textContent = 'Last checked: ' + (d.checked_at ? new Date(d.checked_at * 1000).toLocaleString() : 'never');
    _osuView.refresh();
    // The CVE card's "Select fixes" count follows the picks and the data. Same
    // component at the same root: Preact keeps its search and result.
    const cveEl = document.getElementById('osu-cve');
    if (cveEl) render(phtml`<${CveLookup} />`, cveEl);
    if (busy && !_osuPoll) _osuStartPoll();
}

// Failed nodes of the last run that share a cause (e.g. one offline spoke),
// shown once with the nodes it took down. It names only nodes the picks cover:
// those listed (`listed`, from _osuListed: null while the list asks for a
// pick), and failed nodes the hub no longer reports. An offline spoke and its
// agents drop out of `nodes` (every classified node), so they have no row,
// tenant or chip and this is the only place they show: they count as needing
// attention with no tenant, named unless a tenant or another state is picked,
// and their cause shows even when it took down only them. With no node
// reported there is no drill-down bar, so no pick hides them.
function _osuFailureGroups(run, nodes, listed) {
    const pick = _osuUi.pick;
    const reported = new Set(nodes.map(c => c.key));
    const shown = new Set((listed || []).map(c => c.key));
    const gone = !nodes.length || (pick.tenant === null && (pick.state === null || pick.state === 'attention'));
    const groups = new Map();
    (run && run.items || []).filter(i => i.status === 'failed' && (shown.has(i.key) || (gone && !reported.has(i.key)))).forEach(i => {
        const cause = i.cause || i.message || 'failed';
        if (!groups.has(cause)) groups.set(cause, { labels: [], unreported: false });
        const g = groups.get(cause);
        g.labels.push(i.label || i.key);
        g.unreported = g.unreported || !reported.has(i.key);
    });
    // A listed node's row shows its own failure, so a cause is named once it
    // took down two nodes, or any node that has no row.
    const banners = [...groups].filter(([, g]) => g.labels.length > 1 || g.unreported);
    if (!banners.length) return '';
    return safeHtml`<div class="space-y-2 mb-3">${banners.map(([cause, { labels }]) => safeHtml`
        <div class="rounded border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
            <div class="font-bold">${labels.length} ${labels.length === 1 ? 'node' : 'nodes'} not patched — ${cause}</div>
            <div class="mt-1 text-red-600">${labels.join(', ')}</div>
        </div>`)}</div>`;
}

// Display order, labels and drill-down chip tooltips of the state groups
// inside a tenant, worst first. The tooltips list what _osuClassify puts in each.
const _OSU_STATES = [
    { id: 'attention', label: 'Needs attention', title: 'Failed, interrupted or skipped patches, unreachable nodes, blocked deploys, and reboots that are due or did not finish cleanly' },
    { id: 'patching', label: 'Patching', title: 'Queued, snapshotting, installing or rebooting in the current run' },
    { id: 'pending', label: 'Updates pending', title: 'Updates waiting to be deployed' },
    { id: 'unchecked', label: 'Not checked yet', title: 'Not checked for updates yet' },
    { id: 'current', label: 'Up to date', title: 'Patched: nothing left to install' },
];

// A reboot was scheduled in the last 15 minutes (the node is about to restart).
function _osuRebootScheduled(n) {
    return !!(n.reboot_scheduled_at && (Date.now() / 1000 - n.reboot_scheduled_at) < 900);
}

// A node that needs a reboot nobody has scheduled yet.
function _osuNeedsReboot(n) { return !!n.reboot_required && !_osuRebootScheduled(n); }

// How the node's automatic reboot ended when it did not end cleanly, as the hub reports it
// (reboot_state): the node was never rebooted, the reboot failed, the command went out but no answer
// came back (the node may be rebooting), or the node is left in HA maintenance mode (rebooted or
// not). Each needs a different follow-up, so each has its own badge.
const _OSU_REBOOT_BADGES = {
    not_started: 'not rebooted', failed: 'reboot failed',
    unconfirmed: 'reboot not confirmed', drained: 'left in maintenance',
};
function _osuRebootProblem(item) {
    const s = item && item.reboot_state;
    return _OSU_REBOOT_BADGES[s] ? s : '';
}

// Node can be ticked for "Deploy selected" (and by a group's select-all).
function _osuSelectable(n, busy) { return !!(n.eligible && n.count && !n.apply_blocker && !busy); }

// Node's packages can be ticked one by one: its LM reports the 'packages' feature.
function _osuCanPick(n, busy) { return _osuSelectable(n, busy) && (n.features || []).includes('packages'); }

// The tenant group a node is listed under. Grouped by the tenant's key, never
// its name: two tenants may share a name. Real keys are prefixed, so no tenant
// id (any text is a valid id) can equal the "hub" or "none" keys and merge
// into those groups.
function _osuTenantKey(n) {
    return n.kind === 'hub' ? 'hub' : (n.tenant_key ? `tenant-${n.tenant_key}` : 'none');
}

// Where a node sits on the page: its run item, the tenant group (a name, never
// an id), the state group and the state badge. One place decides all of it, so
// the row badge and the group it is listed under can never disagree.
function _osuClassify(n, run, busy) {
    const key = `${n.kind}:${n.id}`;
    const item = run && (run.items || []).find(i => i.key === key);
    // An in-flight status left in a run that is no longer going (the hub restarted mid-run, or the
    // saved run predates the hub's own cleanup) was cut off: show it as the hub marks it on restart,
    // never as a node that is still patching.
    let st = item && item.status;
    if (!busy) st = { applying: 'interrupted', rebooting: 'interrupted', queued: 'skipped', snapshotting: 'skipped' }[st] || st;
    const tenantKey = _osuTenantKey(n);
    const tenant = n.tenant || (n.kind === 'hub' ? 'Hub' : 'Unassigned');
    let group, badge;
    // While a run is going the cached inventory is stale: a node it just finished is shown
    // with the run item's own result (what is left, whether it now needs a reboot), so its
    // group, badge, counts, sort and package list all agree and none shows pre-deploy data.
    // A failed apply that got as far as re-listing (apt exited part-way) has the same result, and
    // so does a node that was patched and is now rebooting; one that never reached apt reports no
    // count, so its cached state still stands. A node being rebooted no longer needs one.
    if (busy && item && (st === 'done' || Number.isInteger(item.remaining))) {
        n = { ...n, count: item.remaining || 0, packages: [], security_count: 0, reboot_required: st !== 'rebooting' && !!item.reboot_required };
    } else if (busy && st === 'rebooting') {
        // The one-node Reboot button: its item reports no package count, so the cached one stands.
        n = { ...n, reboot_required: false };
    }
    if (st === 'snapshotting' || st === 'applying' || st === 'rebooting') { group = 'patching'; badge = _osuBadge(`${st}…`, 'blue'); }
    // The node's automatic reboot did not end cleanly (see _OSU_REBOOT_BADGES): a person has to look,
    // even when the patch itself worked and no reboot is still due.
    else if ((st === 'done' || st === 'failed') && _osuRebootProblem(item)) { group = 'attention'; badge = _osuBadge(_OSU_REBOOT_BADGES[item.reboot_state], 'red'); }
    else if (st === 'failed' || st === 'interrupted') { group = 'attention'; badge = _osuBadge(st, 'red'); }
    else if (st === 'queued') { group = 'patching'; badge = _osuBadge('queued', 'slate'); }
    // Never patched this run (cancelled, or the window ended): still pending, and the user asked for it.
    else if (st === 'skipped') { group = 'attention'; badge = _osuBadge('skipped', 'slate'); }
    // A package-by-package deploy can leave others pending, so only "nothing remains" is up to date.
    else if (st === 'done' && busy) {
        group = _osuNeedsReboot(n) ? 'attention' : (n.count ? 'pending' : 'current');
        badge = n.count ? _osuBadge(`updated, ${n.count} left`, 'amber') : _osuBadge('updated', 'emerald');
    }
    else if (n.unreachable) { group = 'attention'; badge = _osuBadge('unreachable', 'red'); }
    else if (n.checked === false) { group = 'unchecked'; badge = _osuBadge('not checked yet', 'slate'); }
    else if (!n.count) { group = _osuNeedsReboot(n) ? 'attention' : 'current'; badge = _osuBadge('up to date', 'emerald'); }
    // Pending updates still need attention when a deploy is blocked or a reboot nobody scheduled is due.
    else { group = (n.apply_blocker || _osuNeedsReboot(n)) ? 'attention' : 'pending'; badge = _osuBadge(`${n.count} pending`, 'amber'); }
    return { n, key, item, tenantKey, tenant, group, badge };
}

// Nodes of one state group, in the chosen order (default: by name).
function _osuSortNodes(rows, sort) {
    const byName = (a, b) => String(a.n.label).localeCompare(String(b.n.label));
    return [...rows].sort(sort === 'updates' ? (a, b) => (b.n.count || 0) - (a.n.count || 0) || byName(a, b) : byName);
}

// Per-tenant numbers for the group header and the sort order.
function _osuTenantStats(key, items) {
    return {
        key, name: items[0].tenant, items,
        attention: items.filter(c => c.group === 'attention').length,
        packages: items.reduce((sum, c) => sum + (c.n.count || 0), 0),
        reboot: items.filter(c => _osuNeedsReboot(c.n)).length,
    };
}

// Tenants in the chosen order: worst first by default, A–Z, or most packages first.
function _osuSortTenants(tenants, sort) {
    const byName = (a, b) => a.name.localeCompare(b.name);
    const order = {
        attention: (a, b) => b.attention - a.attention || b.packages - a.packages || byName(a, b),
        updates: (a, b) => b.packages - a.packages || byName(a, b),
    };
    return [...tenants].sort(order[sort] || byName);
}

// One state group of a tenant: a collapsible list of node rows, with a
// select-all for the nodes in it that can be deployed.
function _osuStateHtml(t, s, rows, open, busy) {
    const selectable = rows.filter(c => _osuSelectable(c.n, busy));
    const selectAll = selectable.length
        ? safeHtml`<label class="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer py-1" title="Tick every node in this group that has updates to deploy"><input type="checkbox" class="w-4 h-4 rounded" ${selectable.every(c => _osuSel.nodes.has(c.key)) ? 'checked' : ''} data-action="toggleGroup" data-tenant="${t.key}" data-state="${s.id}">Select all ${selectable.length}</label>` : '';
    // "osu-s-" vs the tenant card's "osu-t-": a tenant named "a-pending" can't take the id of tenant "a"'s pending group.
    return safeHtml`<details id="osu-s-${encodeURIComponent(t.key)}-${s.id}" ${open ? 'open' : ''} class="mt-2">
        <summary class="cursor-pointer text-xs font-bold text-slate-500 py-1">${s.label} (${rows.length})</summary>
        ${selectAll}
        <div class="divide-y divide-slate-100">${rows.map(c => _osuRowHtml(c, busy))}</div>
    </details>`;
}

// One tenant: a collapsible card whose header counts what needs doing in the
// whole tenant, then its state groups: only the picked state's, when one is
// picked (`state`), so the header can count nodes that are not listed.
function _osuTenantHtml(t, sort, busy, state) {
    const states = _OSU_STATES
        .map(s => ({ s, rows: _osuSortNodes(t.items.filter(c => c.group === s.id), sort) }))
        .filter(x => x.rows.length);
    const shown = states.filter(x => state === null || x.s.id === state);
    // Up to date is collapsed unless it is all there is to show.
    const groups = shown.map(({ s, rows }) => _osuStateHtml(t, s, rows, s.id !== 'current' || shown.length === 1, busy));
    const listed = shown.reduce((sum, x) => sum + x.rows.length, 0);
    const badges = [
        t.attention ? _osuBadge(`${t.attention} need attention`, 'red') : '',
        t.packages ? _osuBadge(`${t.packages} package(s) pending`, 'amber') : '',
        t.reboot ? _osuBadge(`${t.reboot} need reboot`, 'amber') : '',
        states.length === 1 && states[0].s.id === 'current' ? _osuBadge('all up to date', 'emerald') : '',
    ];
    return safeHtml`<details id="osu-t-${encodeURIComponent(t.key)}" open class="border border-slate-200 rounded-md mb-3">
        <summary class="cursor-pointer px-3 py-2 flex flex-wrap items-center gap-2 bg-slate-50 rounded-md">
            <span class="text-sm font-bold text-slate-700">${t.name}</span>
            <span class="text-xs text-slate-500">${listed === t.items.length ? '' : `${listed} of `}${t.items.length} node(s)</span>
            ${badges}
        </summary>
        <div class="px-3 pb-2">${groups}</div>
    </details>`;
}

// The drill-down bar above the list: a Tenant row and a State row, each drawn
// when it offers a real choice (2+ tenants or states) or holds a pick, and has
// a chip to show. A row's chips are the groups that have a node under the other
// row's pick, plus its own picked chip so a pick never hides itself; counts say
// what a click would list. A state pick left with no node (a run moved them on)
// therefore hides an unpicked Tenant row: no tenant has a node to list. Same
// idiom as Setup → Module Management → Managed Devices (.sub-nav-item.active =
// HPE-green underline).
function _osuDrillHtml(tenants, nodes, offered) {
    const pick = _osuUi.pick;
    const chip = (action, value, active, label, count, title) => safeHtml`<button type="button" data-action="${action}" data-pick="${value}" title="${active ? 'Click again to clear this pick' : title}" class="sub-nav-item ${active ? 'active' : ''} px-2 py-1 text-xs tracking-normal select-none">${label}<span class="ml-1 text-xs text-slate-500 normal-case">${count}</span></button>`;
    const row = (label, chips) => (chips.length ? safeHtml`<div class="flex flex-wrap items-center gap-1"><span class="text-xs font-bold text-slate-500 mr-1">${label}</span>${chips}</div>` : '');
    const rows = [];
    if (offered.tenant || pick.tenant !== null) {
        // Tenants A–Z, then the hub, then nodes with no tenant.
        const rank = t => (t.key === 'hub' ? 1 : t.key === 'none' ? 2 : 0);
        const chips = [...tenants].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name))
            .map(t => ({ t, count: t.items.filter(c => pick.state === null || c.group === pick.state).length }))
            .filter(x => x.count || x.t.key === pick.tenant)
            .map(({ t, count }) => chip('pickTenant', t.key, t.key === pick.tenant, t.name, count, "List only this tenant's nodes"));
        rows.push(row('Tenant', chips));
    }
    if (offered.state || pick.state !== null) {
        const chips = _OSU_STATES
            .map(s => ({ s, count: nodes.filter(c => c.group === s.id && (pick.tenant === null || c.tenantKey === pick.tenant)).length }))
            .filter(x => x.count || x.s.id === pick.state)
            .map(({ s, count }) => chip('pickState', s.id, s.id === pick.state, s.label, count, s.title));
        rows.push(row('State', chips));
    }
    const drawn = rows.filter(Boolean);
    return drawn.length ? safeHtml`<div class="space-y-1 border-b border-slate-100 pb-2 mb-3">${drawn}</div>` : '';
}

// Which drill-down rows offer a real choice: 2+ tenants, 2+ states.
function _osuOffered(nodes) {
    return { tenant: new Set(nodes.map(c => c.tenantKey)).size > 1, state: new Set(nodes.map(c => c.group)).size > 1 };
}

// The nodes the list shows under the current picks, from the classified
// `nodes` (_osuClassify): null while it asks for a pick instead (a row offers a
// choice and nothing is picked), else those in the picked tenant and state.
// The list, the ticks, the failure banner and the CVE "Select fixes" all use
// it, so none of them reaches a node the list hides.
function _osuListed(nodes) {
    const pick = _osuUi.pick;
    const offered = _osuOffered(nodes);
    if (pick.tenant === null && pick.state === null && (offered.tenant || offered.state)) return null;
    return nodes.filter(c => (pick.tenant === null || c.tenantKey === pick.tenant) && (pick.state === null || c.group === pick.state));
}

// The Nodes card: the drill-down bar, then the picked nodes grouped by tenant,
// then by state. While a row offers a choice and nothing is picked, it asks for
// a pick instead of listing every node.
function _osuBodyHtml({ data: d }) {
    const run = d.run;
    const busy = _osuBusy();
    const nodes = (d.nodes || []).map(n => _osuClassify(n, run, busy));
    if (!nodes.length) return safeHtml`${_osuFailureGroups(run, nodes, [])}<p class="text-xs text-slate-500 italic">No nodes reporting.</p>`;
    const byTenant = new Map();
    nodes.forEach(c => byTenant.set(c.tenantKey, [...(byTenant.get(c.tenantKey) || []), c]));
    const tenants = [...byTenant].map(([key, items]) => _osuTenantStats(key, items));
    const offered = _osuOffered(nodes);
    const bar = _osuDrillHtml(tenants, nodes, offered);
    const listed = _osuListed(nodes);
    const failures = _osuFailureGroups(run, nodes, listed);
    if (!listed) {
        const what = [offered.tenant && 'a tenant', offered.state && 'a state'].filter(Boolean).join(' or ');
        return safeHtml`${failures}${bar}<p class="text-xs text-slate-500 italic">${nodes.length} nodes. Pick ${what} above to list them.</p>`;
    }
    const shown = tenants.filter(t => listed.some(c => c.tenantKey === t.key));
    if (!shown.length) return safeHtml`${failures}${bar}<p class="text-xs text-slate-500 italic">No nodes are in this state right now.</p>`;
    return safeHtml`${failures}${bar}${_osuSortTenants(shown, _osuUi.sort).map(t => _osuTenantHtml(t, _osuUi.sort, busy, _osuUi.pick.state))}`;
}

// One node row: name, state badge, pending packages, reboot and auto-patch controls.
function _osuRowHtml(c, busy) {
    const { n, key, item, badge: state } = c;
    const feats = n.features || [];
    const scheduled = _osuRebootScheduled(n);
    const reboot = scheduled ? _osuBadge('reboot scheduled', 'blue')
        : (n.reboot_required ? _osuBadge('reboot required', 'amber', 'A kernel/PVE update needs a reboot. Nothing reboots automatically — do it deliberately.') : '');
    const canReboot = n.eligible && n.reboot_required && !scheduled && feats.includes('reboot') && !busy;
    const rebootBtn = canReboot ? safeHtml`<button data-action="reboot" data-node="${key}" class="text-xs font-bold text-amber-800 border border-amber-300 rounded-full px-2 py-0.5 hover:bg-amber-100">Reboot…</button>` : '';
    const selectable = _osuSelectable(n, busy);
    const nodeBox = selectable
        ? safeHtml`<input type="checkbox" class="w-4 h-4 rounded" ${_osuSel.nodes.has(key) ? 'checked' : ''} data-action="toggleNode" data-node="${key}" title="Upgrade everything pending on this node">`
        : '';
    const canPick = _osuCanPick(n, busy);
    const picked = _osuSel.pkgs[key] || new Set();
    const pkgs = (n.packages || []).map(p => {
        const label = safeHtml`${p.package} <span class="text-slate-500">${p.current}→${p.candidate}</span>`;
        const cls = p.security ? 'text-red-700' : 'text-slate-500';
        if (!canPick) return safeHtml`<span class="inline-block mr-2 ${cls}">${label}</span>`;
        return safeHtml`<label class="inline-flex items-center gap-1 mr-3 ${cls} cursor-pointer"><input type="checkbox" class="w-3 h-3" ${picked.has(p.package) ? 'checked' : ''} data-action="togglePkg" data-node="${key}" data-pkg="${p.package}">${label}</label>`;
    });
    const pickNote = selectable && !feats.includes('packages')
        ? safeHtml`<div class="text-xs text-slate-500 mt-1">Update LM on this node to pick individual packages — it can only be updated whole.</div>` : '';
    const pickHint = canPick ? safeHtml`<div class="text-xs text-slate-500 mb-1">${picked.size ? `${picked.size} picked — only these will be upgraded on this node.` : 'Pick packages to upgrade only those, or tick the node to upgrade everything.'}</div>` : '';
    const detail = n.reason
        ? safeHtml`<div class="text-xs text-slate-500 mt-1">${n.reason}</div>`
        : (n.count ? safeHtml`<details class="osu-pkgs mt-1"><summary class="cursor-pointer text-xs text-slate-500">${n.count} package(s)${n.security_count ? ` · ${n.security_count} security` : ''}</summary><div class="text-xs mt-1 leading-relaxed">${pickHint}${pkgs}</div></details>${pickNote}` : '');
    const fixBtn = n.apply_blocker && feats.includes('fix_access') && !busy
        ? safeHtml` <button data-action="fixAccess" data-node="${key}" class="ml-1 text-xs font-bold text-amber-800 border border-amber-300 rounded-full px-2 py-0.5 hover:bg-amber-100">Fix access…</button>` : '';
    const autoBox = n.eligible
        ? safeHtml`<label class="flex items-center gap-1 text-xs font-bold ${n.auto_patch ? 'text-emerald-700' : 'text-slate-500'} cursor-pointer" title="Install this node's updates automatically in the maintenance window"><input type="checkbox" class="w-3 h-3" ${n.auto_patch ? 'checked' : ''} data-action="toggleAutoPatch" data-node="${key}">Auto-patch</label>` : '';
    const rebootBox = n.eligible && n.auto_patch
        ? safeHtml`<label class="flex items-center gap-1 text-xs font-bold ${n.auto_reboot ? 'text-emerald-700' : 'text-slate-500'} cursor-pointer" title="Reboot this node after auto-patch installs something"><input type="checkbox" class="w-3 h-3" ${n.auto_reboot ? 'checked' : ''} data-action="toggleAutoReboot" data-node="${key}">Auto-reboot</label>` : '';
    const blocker = n.apply_blocker ? safeHtml`<div class="text-xs text-amber-700 mt-1">Can't apply: ${n.apply_blocker}${fixBtn}</div>` : '';
    const msg = [];
    if (item && item.message) msg.push(safeHtml`<div class="text-xs ${item.status === 'done' ? 'text-slate-500' : 'text-red-600'} mt-1">${item.message}</div>`);
    else if (item && item.status === 'done' && item.mode === 'packages') msg.push(safeHtml`<div class="text-xs text-slate-500 mt-1">upgraded ${(item.packages || []).join(', ')}</div>`);
    if (item && item.snapshot) msg.push(safeHtml`<div class="text-xs text-slate-500 mt-1">snapshot: ${item.snapshot}</div>`);
    if (item && item.auto_reboot) msg.push(safeHtml`<div class="text-xs ${_osuRebootProblem(item) || item.auto_reboot.startsWith('failed') ? 'text-red-600' : 'text-slate-500'} mt-1">reboot: ${item.auto_reboot}</div>`);
    const meta = [n.kind, n.flavor, n.pve_cluster && n.pve_cluster.name ? 'PVE cluster ' + n.pve_cluster.name : ''].filter(Boolean).join(' · ');
    return safeHtml`<div id="osu-node-${key}" class="py-3 flex flex-wrap items-start gap-x-4 gap-y-2">
        <div class="w-5 pt-0.5">${nodeBox}</div>
        <div class="flex-1 min-w-[16rem]">
            <div class="text-sm font-medium text-slate-700">${n.label}</div>
            <div class="text-xs text-slate-500">${meta}${_osuVmLabel(n)}</div>
            ${detail}${blocker}${msg}
        </div>
        <div class="flex flex-wrap items-center justify-end gap-1.5">${state}${reboot}${rebootBtn}</div>
        <div class="flex flex-col gap-1 w-28">${autoBox}${rebootBox}</div>
    </div>`;
}

lmViews.osupdates = renderOsUpdatesView;

