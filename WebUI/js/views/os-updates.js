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
    togglePkg: el => osuTogglePkg(el.dataset.node, el.dataset.pkg, el.checked),
    reboot: el => osuReboot(el.dataset.node),
    fixAccess: el => osuFixAccess(el.dataset.node),
    toggleAutoPatch: el => osuToggleAutoPatch(el.dataset.node, el.checked, el),
    toggleAutoReboot: el => osuToggleAutoReboot(el.dataset.node, el.checked, el),
};

function renderOsUpdatesView(content) {
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
• Deploy everything, only selected nodes/packages, or only security updates.
• A manual deploy never reboots; a host that needs one gets a Reboot… button. Proxmox cluster nodes are the exception (below).
• Auto-patch is approved per node and runs only in the maintenance window, minus packages under &quot;Never auto-install&quot;.
• Auto-reboot (on by default for auto-patch nodes) reboots nodes that installed something once the run is done, hub last.
• Proxmox cluster nodes reboot only when needed, in HA maintenance mode (guests move off first), one node at a time.
• Nodes update one at a time; the hub goes last (this page restarts).
• Separate from LM code updates.">ⓘ</span></h3>
                <span class="flex items-center gap-3"><span id="osu-status" class="text-xs text-slate-500"></span><span id="osu-checked" class="text-xs text-slate-500"></span></span>
            </div>
            <div id="osu-summary" class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3"></div>
            <div class="flex flex-wrap items-center gap-2">
                <button data-action="check" class="${btnSecCls}">↻ Check for updates</button>
                <button id="osu-apply-selected" data-action="applySelected" class="${btnCls}" disabled>Deploy selected (0)</button>
                <button id="osu-apply" data-action="apply" class="${btnSecCls}">Approve &amp; deploy all</button>
                <label class="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer ml-1" title="Nodes without picked packages get only their pending security updates"><input type="checkbox" id="osu-security-only" class="w-4 h-4 rounded">Security updates only</label>
                <button id="osu-cancel" data-action="cancel" class="${btnSecCls} hidden">Cancel run</button>
                <span id="osu-run" class="text-xs text-slate-500 ml-auto"></span>
            </div>
        </div>
        <div class="${card} mt-4">
            <div class="flex items-center justify-between">
                <h3 class="${h3}">Nodes</h3>
                <span id="osu-hidden" class="text-xs text-slate-500"></span>
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
                        <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer" title="Before patching a node that runs in a Proxmox VM, LM snapshots that VM (manual deploys and auto-patch). If the snapshot fails the node is not patched. Proxmox hosts themselves (bare metal) are patched without a snapshot."><input type="checkbox" id="osu-snap-enabled" class="w-4 h-4 text-green-600 rounded" checked>Snapshot VMs before patching, keep</label>
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
        <button data-action="close" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button id="osu-fix-go" data-action="fix" class="px-4 py-1.5 text-sm rounded-md bg-primary text-white font-bold hover:bg-primary-hover">Fix access</button>
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

// Pending upgrades on each affected node that belong to the vulnerable packages.
function _osuCveFixes(d) {
    const nodes = {};
    (_osuView.state.data.nodes || []).forEach(n => { nodes[`${n.kind}:${n.id}`] = n; });
    const picks = [];
    (d.results || []).forEach(r => r.affected.forEach(a => {
        const pending = new Set(((nodes[a.node] || {}).packages || []).map(p => p.package));
        a.binaries.filter(b => pending.has(b)).forEach(b => picks.push([a.node, b]));
    }));
    return picks;
}

function osuCveSelectFixes(d) {
    const picks = _osuCveFixes(d);
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
        const fixes = _osuCveFixes(d).length;
        body = phtml`<div class="flex flex-wrap items-center gap-2 text-xs">
                <b class=${d.affected_nodes ? 'text-red-700' : 'text-emerald-700'}>${d.affected_nodes} of ${d.checked_nodes} checked node(s) affected</b>
                ${fixes ? phtml`<button type="button" onClick=${() => osuCveSelectFixes(d)} class="text-xs font-bold text-emerald-800 border border-emerald-300 rounded px-2 py-0.5 hover:bg-emerald-50" title="Pick the pending updates of the vulnerable packages on affected nodes">Select fixes (${fixes})</button>` : null}
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
        _osuSel.nodes.clear(); Object.keys(_osuSel.pkgs).forEach(k => delete _osuSel.pkgs[k]);
        _osuStartPoll();
    } catch (e) { showToast('Apply failed: ' + (e.message || e), 'error'); }
}

async function osuApply() {
    const n = (_osuView.state.data.totals || {}).with_updates || 0;
    if (!n) { showToast('No nodes have pending updates.', 'info'); return; }
    _osuDeploy({}, `All ${n} node(s) with pending updates.`);
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
    const runEl = document.getElementById('osu-run');
    if (runEl) {
        const label = { finished: 'complete', cancelled: 'cancelled', interrupted: 'interrupted by a hub restart' };
        runEl.textContent = busy
            ? `deploying ${run.done}/${run.total} — current: ${run.current || '…'}${run.cancel_requested ? ' (cancelling after this node)' : ''}`
            : (run && label[run.status] ? `last run${run.actor === 'auto-patch' ? ' (auto-patch)' : ''}: ${run.done}/${run.total} ${label[run.status]}` : '');
    }
    const nSel = _osuSelectedKeys().length;
    const btn = document.getElementById('osu-apply');
    if (btn) btn.disabled = busy;
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
    if (busy && !_osuPoll) _osuStartPoll();
}

// Failed nodes of the last run that share a cause (e.g. one offline spoke),
// shown once with the nodes it took down instead of N identical row errors.
function _osuFailureGroups(run) {
    const groups = new Map();
    (run && run.items || []).filter(i => i.status === 'failed').forEach(i => {
        const cause = i.cause || i.message || 'failed';
        if (!groups.has(cause)) groups.set(cause, []);
        groups.get(cause).push(i.label || i.key);
    });
    const shared = [...groups].filter(([, labels]) => labels.length > 1);
    if (!shared.length) return '';
    return safeHtml`<div class="space-y-2 mb-3">${shared.map(([cause, labels]) => safeHtml`
        <div class="rounded border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
            <div class="font-bold">${labels.length} nodes not patched — ${cause}</div>
            <div class="mt-1 text-red-600">${labels.join(', ')}</div>
        </div>`)}</div>`;
}

function _osuBodyHtml({ data: d }) {
    const run = d.run;
    const busy = _osuBusy();
    const rows = (d.nodes || []).map(n => {
        const key = `${n.kind}:${n.id}`;
        const feats = n.features || [];
        const item = run && (run.items || []).find(i => i.key === key);
        let state;
        if (item && item.status === 'snapshotting') state = _osuBadge('snapshotting…', 'blue');
        else if (item && item.status === 'applying') state = _osuBadge('applying…', 'blue');
        else if (item && item.status === 'rebooting') state = _osuBadge('rebooting…', 'blue');
        else if (item && item.status === 'failed') state = _osuBadge('failed', 'red');
        else if (item && item.status === 'interrupted') state = _osuBadge('interrupted', 'red');
        else if (item && item.status === 'queued') state = _osuBadge('queued', 'slate');
        else if (item && item.status === 'done' && busy) state = _osuBadge('updated', 'emerald');
        else if (n.unreachable) state = _osuBadge('unreachable', 'red');
        else if (n.checked === false) state = _osuBadge('not checked yet', 'slate');
        else if (!n.count) state = _osuBadge('up to date', 'emerald');
        else state = _osuBadge(`${n.count} pending`, 'amber');
        const scheduled = n.reboot_scheduled_at && (Date.now() / 1000 - n.reboot_scheduled_at) < 900;
        const reboot = scheduled ? _osuBadge('reboot scheduled', 'blue')
            : (n.reboot_required ? _osuBadge('reboot required', 'amber', 'A kernel/PVE update needs a reboot. Nothing reboots automatically — do it deliberately.') : '');
        const canReboot = n.eligible && n.reboot_required && !scheduled && feats.includes('reboot') && !busy;
        const rebootBtn = canReboot ? safeHtml`<button data-action="reboot" data-node="${key}" class="text-xs font-bold text-amber-800 border border-amber-300 rounded px-2 py-0.5 hover:bg-amber-100">Reboot…</button>` : '';
        const selectable = n.eligible && n.count && !n.apply_blocker && !busy;
        const nodeBox = selectable
            ? safeHtml`<input type="checkbox" class="w-4 h-4 rounded" ${_osuSel.nodes.has(key) ? 'checked' : ''} data-action="toggleNode" data-node="${key}" title="Upgrade everything pending on this node">`
            : '';
        const canPick = selectable && feats.includes('packages');
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
            : (n.count ? safeHtml`<details class="mt-1"><summary class="cursor-pointer text-xs text-slate-500">${n.count} package(s)${n.security_count ? ` · ${n.security_count} security` : ''}</summary><div class="text-xs mt-1 leading-relaxed">${pickHint}${pkgs}</div></details>${pickNote}` : '');
        const fixBtn = n.apply_blocker && feats.includes('fix_access') && !busy
            ? safeHtml` <button data-action="fixAccess" data-node="${key}" class="ml-1 text-xs font-bold text-amber-800 border border-amber-300 rounded px-2 py-0.5 hover:bg-amber-100">Fix access…</button>` : '';
        const autoBox = n.eligible
            ? safeHtml`<label class="flex items-center gap-1 text-xs font-bold ${n.auto_patch ? 'text-emerald-700' : 'text-slate-500'} cursor-pointer" title="Install this node's updates automatically in the maintenance window"><input type="checkbox" class="w-3 h-3" ${n.auto_patch ? 'checked' : ''} data-action="toggleAutoPatch" data-node="${key}">Auto-patch</label>` : '';
        const rebootBox = n.eligible && n.auto_patch
            ? safeHtml`<label class="flex items-center gap-1 text-xs font-bold ${n.auto_reboot ? 'text-emerald-700' : 'text-slate-500'} cursor-pointer" title="Reboot this node after auto-patch installs something"><input type="checkbox" class="w-3 h-3" ${n.auto_reboot ? 'checked' : ''} data-action="toggleAutoReboot" data-node="${key}">Auto-reboot</label>` : '';
        const blocker = n.apply_blocker ? safeHtml`<div class="text-xs text-amber-700 mt-1">Can't apply: ${n.apply_blocker}${fixBtn}</div>` : '';
        const msg = [];
        if (item && item.message) msg.push(safeHtml`<div class="text-xs ${item.status === 'done' ? 'text-slate-500' : 'text-red-600'} mt-1">${item.message}</div>`);
        else if (item && item.status === 'done' && item.mode === 'packages') msg.push(safeHtml`<div class="text-xs text-slate-500 mt-1">upgraded ${(item.packages || []).join(', ')}</div>`);
        if (item && item.snapshot) msg.push(safeHtml`<div class="text-xs text-slate-500 mt-1">snapshot: ${item.snapshot}</div>`);
        if (item && item.auto_reboot) msg.push(safeHtml`<div class="text-xs ${item.auto_reboot.startsWith('failed') ? 'text-red-600' : 'text-slate-500'} mt-1">reboot: ${item.auto_reboot}</div>`);
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
    });
    return rows.length
        ? safeHtml`${_osuFailureGroups(run)}<div class="divide-y divide-slate-100">${rows}</div>`
        : safeHtml`<p class="text-xs text-slate-500 italic">No nodes reporting.</p>`;
}

lmViews.osupdates = renderOsUpdatesView;

