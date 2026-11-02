// pxmx-console.js — Proxmox (PXMX), console ports and serial sessions.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── PXMX / Proxmox ──────────────────────────────────────────────────────────

// Stable key tying a node to the VMs that run on it: "<cluster>::<node>".
// VMs expose the same cluster/node fields, so this scopes a node's VMs.
function pxmxNodeKey(cluster, node) {
    return `${cluster || ''}::${node || ''}`;
}

// Shared table scaffolding — horizontal-scroll wrapper + uppercase header row.
// Used by the PXMX, NetBox, DNS, DHCP, LE and CPPM views (was six byte-identical
// local th/tw copies).
function tableWrap(html) {
    return `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;
}

function tableHead(cols) {
    return `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
}

// VM table — shared by the node-detail view and the no-nodes fallback.
// Each VM is a 2-line entry: line 1 = identity (Cluster/Host, VMID, Name, IP,
// Clone action); line 2 = metadata (Type, Status, CPU, Memory, Pool). Cluster
// and Host(node) are merged into one "Cluster / Host" column as "<cluster>/<node>".
// Shared VM lifecycle button spec — the inline per-row action buttons AND the
// bulk-action bar render from this SAME list so the two always match (icon,
// label, color, hover). Inline rows call pxmxVmAction('<uid>','<action>'); the
// bulk bar calls pxmxBulkAction('<action>'). Add/change an action here once
// and both surfaces update together.
const PXMX_VM_ACTIONS = [
    { action: 'start',    label: '▶ Start',     cls: 'bg-green-100 text-green-700 hover:bg-green-200' },
    { action: 'stop',     label: '■ Stop',      cls: 'bg-red-600 text-white hover:bg-red-700' },
    { action: 'reboot',   label: '↺ Restart',   cls: 'bg-amber-100 text-amber-700 hover:bg-amber-200' },
    { action: 'snapshot', label: '📷 Snapshot', cls: 'bg-slate-200 text-slate-700 hover:bg-slate-300' },
    { action: 'backup',   label: '💾 Backup',    cls: 'bg-sky-100 text-sky-700 hover:bg-sky-200' },
    { action: 'destroy',  label: '🗑 Delete',    cls: 'bg-red-800 text-white hover:bg-red-900' },
];

// Friendly OS label from the agent's cached Proxmox ostype (l26 → Linux, win*
// → Windows, etc.); falls back to the qemu/lxc type when ostype is unknown.
// Mirrors csVmOs (sim-views.js) so the Hypervisor VM list reads the same as the
// cs VM Server list.
function pxmxOs(v) {
    const t = String(v.ostype || v.os || '').toLowerCase();
    if (!t) return v.template ? 'template' : (v.type === 'lxc' ? 'Linux (CT)' : '—');
    if (t.startsWith('win')) return 'Windows';
    if (t === 'l26' || t === 'l24' || t.startsWith('linux')) return 'Linux';
    if (t.includes('solaris')) return 'Solaris';
    if (t.includes('other')) return 'Other';
    return v.ostype || v.os;
}

// Steady-state status pill for a pxmx VM (mirrors csVmStatusBadge's plain tail
// ── Optimistic in-flight VM state (click-driven) ─────────────────────────────
// Telemetry can MISS a fast transition (a VM destroyed between two frames goes
// present→gone with no intermediate frame). The operator's click IS the signal:
// the moment an action is dispatched we mark the VM in-flight so its row shows
// the operation immediately, then telemetry reconciles it on the next refresh.
// Keyed by unique_id (fallback vmid). This view has no prov_run (a Simulations
// concept), so it's click-driven only — no auto-prov provisioning placeholders.
const _pxmxVmInflight = new Map();   // key -> {op, ts}
const _PXMX_ACTION_OP = { start: 'starting', stop: 'stopping', reboot: 'rebooting', restart: 'rebooting', destroy: 'deleting', delete: 'deleting' };
const _PXMX_INFLIGHT_META = {
    deleting:  { label: 'deleting…',  cls: 'bg-red-100 text-red-700' },
    stopping:  { label: 'stopping…',  cls: 'bg-amber-100 text-amber-700' },
    starting:  { label: 'starting…',  cls: 'bg-green-100 text-green-700' },
    rebooting: { label: 'rebooting…', cls: 'bg-blue-100 text-blue-700' },
    cloning:   { label: 'cloning…',   cls: 'bg-blue-100 text-blue-700' },
};
function pxmxVmKey(v) { return String((v && (v.unique_id || v.vmid)) != null ? (v.unique_id || v.vmid) : ''); }
function pxmxInflightBadge(op) {
    const m = _PXMX_INFLIGHT_META[op] || { label: op + '…', cls: 'bg-amber-100 text-amber-700' };
    return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${m.cls}" title="Operation in progress — waiting for telemetry to confirm"><span class="animate-spin inline-block w-2.5 h-2.5 rounded-full border-2 border-current border-t-transparent"></span>⏳ ${escapeHtml(m.label)}</span>`;
}
// Reconcile the in-flight map against a fresh telemetry VM list: drop confirmed
// deletes (VM gone), clear ops whose target state telemetry now reflects, and
// time out any entry older than 120s so a lost/failed op can't stick forever.
// Runs BEFORE the rows are built on each load.
function pxmxReconcileVmInflight(freshVms) {
    if (!_pxmxVmInflight.size) return;
    const now = Date.now();
    const byKey = new Map();
    (freshVms || []).forEach(v => { if (v) byKey.set(pxmxVmKey(v), v); });
    for (const [key, ent] of Array.from(_pxmxVmInflight.entries())) {
        if (now - (ent && ent.ts || 0) > 120000) { _pxmxVmInflight.delete(key); continue; }
        const v = byKey.get(key);
        if (!v) { if (ent.op === 'deleting') _pxmxVmInflight.delete(key); continue; }
        const st = String(v.status || '').toLowerCase();
        if (ent.op === 'stopping' && st === 'stopped') _pxmxVmInflight.delete(key);
        else if ((ent.op === 'starting' || ent.op === 'rebooting') && st === 'running') _pxmxVmInflight.delete(key);
    }
}
// Re-render just the VM list table (when mounted) so an optimistic badge shows
// instantly, before the next telemetry refresh. No-op off the VM list view.
// Per-server tab filter for the flat "Virtual Machines" list — null/'' means
// "All" (the default on first load, since this starts unset). Persists for
// the session, including across pxmxRerenderVmList's optimistic in-flight
// re-renders (action clicks) and the post-bulk-action loadPxmxData refresh —
// switching tabs shouldn't get silently undone by an unrelated background
// refresh. A full page reload naturally resets it back to "All".
window._pxmxVmTabFilter = window._pxmxVmTabFilter || null;
function pxmxFilteredVms() {
    const all = window._pxmxVms || [];
    const key = window._pxmxVmTabFilter;
    return key ? all.filter(v => pxmxNodeKey(v.cluster, v.node) === key) : all;
}
function pxmxRerenderVmList() {
    try {
        const el = document.getElementById('pxmx-vm-list');
        if (el) el.innerHTML = pxmxVmTableHtml(pxmxFilteredVms());
    } catch (e) { console.warn('pxmxRerenderVmList failed', e); }
}

// branch — pxmx VMs don't carry prov_status/shed/reclone state like cs sim
// clients do, so a simple running/stopped/other pill is the right shape here).
function pxmxVmStatusBadge(v) {
    const _inf = _pxmxVmInflight.get(pxmxVmKey(v));
    if (_inf) return pxmxInflightBadge(_inf.op);
    const st = String(v.status || 'unknown').toLowerCase();
    const cls = st === 'running' ? 'bg-green-100 text-green-700'
              : st === 'stopped' ? 'bg-slate-100 text-slate-500'
              : 'bg-amber-100 text-amber-700';
    return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${escapeHtml(v.status || '—')}</span>`;
}

// Hypervisor VM list — ported to the cs VM Server VMs list format: single-line
// rows, columns [VMID, Name, OS, Status, Host, Actions], inline per-row action
// buttons (cs-style) PLUS a row click → openVmDetail for the richer ops the cs
// list doesn't have (Backup-to-Hub, Clone, storage picker). No category tabs
// (the cs tabs are sim-client-specific). Bulk-select checkbox stays in the VMID
// cell (cs shape) and feeds the existing pxmxBulkBar/pxmxBulkAction path.
// Shared floating menu for the per-row "Actions ▾" button — Start/Stop/
// Restart/Snapshot/Backup live here now (Delete + Console stay as standalone
// buttons, matching the delete-protection/console-availability treatment they
// already have). One menu element reused across every row (created lazily,
// repositioned + repopulated per open) rather than one hidden menu per row —
// keeps the DOM light on a long VM list. Click-toggle + outside-click closes,
// same convention as toggleTenantPicker/closeTenantPicker.
function _pxmxVmActionMenuEl() {
    let menu = document.getElementById('pxmx-vm-action-menu');
    if (!menu) {
        menu = document.createElement('div');
        menu.id = 'pxmx-vm-action-menu';
        menu.className = 'hidden fixed z-50 bg-white border border-slate-200 rounded-md shadow-lg py-1 text-xs min-w-[140px]';
        document.body.appendChild(menu);
        document.addEventListener('click', () => menu.classList.add('hidden'));
    }
    return menu;
}
window.pxmxToggleVmActionMenu = function (evt, uid, isTpl) {
    evt.stopPropagation();
    const menu = _pxmxVmActionMenuEl();
    const wasOpenForThisRow = menu.dataset.forUid === uid && !menu.classList.contains('hidden');
    menu.classList.add('hidden');
    if (wasOpenForThisRow) return;
    // Templates aren't runnable (no start/stop/reboot/snapshot) — only Backup
    // applies, mirroring the prior per-row button filtering for templates.
    const specs = PXMX_VM_ACTIONS.filter(s => s.action !== 'destroy' && (!isTpl || s.action === 'backup'));
    menu.innerHTML = specs.map(s =>
        `<button onclick="event.stopPropagation(); document.getElementById('pxmx-vm-action-menu').classList.add('hidden'); pxmxVmAction('${uid}','${s.action}')" class="w-full text-left px-3 py-1.5 hover:bg-slate-50 font-medium text-slate-700 flex items-center gap-1.5" title="${s.label} virtual machine">${s.label}</button>`
    ).join('');
    const r = evt.currentTarget.getBoundingClientRect();
    menu.style.top = (r.bottom + 4) + 'px';
    menu.style.left = r.left + 'px';
    menu.dataset.forUid = uid;
    menu.classList.remove('hidden');
};

function pxmxVmTableHtml(vms) {
    // Header must have exactly as many columns as the row below renders —
    // the checkbox + VMID share ONE <td> in each row (see below), so they
    // share one <th> here too. A separate 'VMID' header for the same 7-col
    // count as the row's 6 <td>s shifted every column after it by one (OS
    // showing Status's value, Host showing Actions, etc. — the reported bug).
    const cols = ['<input type="checkbox" onclick="pxmxBulkSelectAll(this.checked)" title="Select all"/> VMID', 'Name', 'OS', 'Status', 'Host', 'Actions'];
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const tplPools = window._pxmxTemplatePools || [];
    const isTemplate = vm => !!(vm.template || (vm.pool && tplPools.includes(String(vm.pool).toLowerCase())));
    const canAct = canEdit();   // VM control is write-tier; view users see no actions
    const rows = vms.map(vm => {
        const uid = escJs(vm.unique_id || '');
        const isLxc = String(vm.type || '').toLowerCase() === 'lxc';
        const tpl = isTemplate(vm);
        // Cluster/Host merged: Proxmox node is the host, shown as "<cluster>/<node>".
        const host = escapeHtml(`${vm.cluster || '—'}/${vm.node || '—'}`);
        // act() renders a single action button from a PXMX_VM_ACTIONS spec —
        // used here only for Delete (Start/Stop/Reboot/Snapshot/Backup moved
        // into the "Actions ▾" menu below, same spec list, same pxmxVmAction
        // call). Also the bulk bar's per-button renderer, so styling stays in
        // sync there. All actions route through pxmxVmAction (which confirms
        // destructive ops per Hypervisors → Settings). Gated by canEdit() —
        // view users get a read-only list. Clone + Backup-to-Hub stay in the
        // click-through detail panel (they need the storage picker / template-
        // pool affordance).
        const act = (spec) => {
            if (!canAct) return '';
            // Delete-protection safeguard: a protected VM's Delete button is
            // disabled + locked. The hub enforces this too (403), so this is
            // UX, not the security boundary.
            if (spec.action === 'destroy' && vm.protected) {
                return `<button disabled title="Protected from deletion — remove the safeguard in Setup → Hypervisors" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-400 cursor-not-allowed">🔒 Delete</button>`;
            }
            return `<button onclick="event.stopPropagation(); pxmxVmAction('${uid}','${spec.action}')" class="px-2 py-0.5 rounded text-[10px] font-bold ${spec.cls}" title="${spec.label} this virtual machine">${spec.label}</button>`;
        };
        const consoleBtn = !canAct ? ''
            : (isLxc || tpl)
                ? `<button disabled title="${isLxc ? 'Containers have no VNC console' : 'Templates have no console'}" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-300 cursor-not-allowed">🖥 Console</button>`
                : `<button onclick="event.stopPropagation(); pxmxOpenConsole('${uid}')" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-100 hover:bg-slate-700" title="Open a noVNC console to this VM">🖥 Console</button>`;
        // Start/Stop/Restart/Snapshot/Backup live behind one "Actions ▾" menu
        // (pxmxToggleVmActionMenu) — Delete and Console stay as standalone
        // buttons (delete-protection and console-availability need their own
        // always-visible state, not a menu item you might miss).
        const destroySpec = PXMX_VM_ACTIONS.find(s => s.action === 'destroy');
        const menuBtn = !canAct ? '' : `<button onclick="event.stopPropagation(); pxmxToggleVmActionMenu(event, '${uid}', ${tpl})" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 hover:bg-slate-200" title="Open VM actions menu">⋯ Actions ▾</button>`;
        const actions = `<div class="flex flex-wrap gap-1 justify-end">
            ${consoleBtn}
            ${menuBtn}
            ${act(destroySpec)}
        </div>`;
        return `<tr class="border-b border-slate-100 hover:bg-slate-50 cursor-pointer" data-unique-id="${escapeHtml(vm.unique_id || '')}" onclick="openVmDetail('${uid}')">
            <td class="px-4 py-2 font-mono text-xs font-bold" onclick="event.stopPropagation()"><input type="checkbox" class="pxmx-vm-sel" value="${escapeHtml(vm.unique_id || '')}" title="Select VM ${escapeHtml(vm.name || vm.vmid)} for bulk operations"/> ${escapeHtml(vm.vmid)}</td>
            <td class="px-4 py-2 text-sm font-medium">${escapeHtml(vm.name || '—')}</td>
            <td class="px-4 py-2 text-slate-500">${escapeHtml(pxmxOs(vm))}</td>
            <td class="px-4 py-2">${pxmxVmStatusBadge(vm)}</td>
            <td class="px-4 py-2 text-xs text-slate-500 font-mono">${host}</td>
            <td class="px-4 py-2" onclick="event.stopPropagation()">${actions}</td>
        </tr>`;
    }).join('');
    return pxmxBulkBar() + tableWrap(tableHead(cols) + rows);
}

// "Virtual Machines" tab strip — All (default) + one tab per server (node),
// numeric-aware sort so …svr-2/-3/-10 order naturally (mirrors the Overview
// sort). Switching tabs is a pure client-side filter over the already-loaded
// window._pxmxVms/_pxmxNodes — no re-fetch. Counts help spot an empty/
// offline host at a glance. Separate from the existing Overview → click-a-
// node → scoped node-detail-card flow (openNodeVms/pxmxNodeDetailHtml),
// which stays as-is; this is the flat "Virtual Machines" landing view.
function pxmxVmTabsHtml() {
    const nodes = window._pxmxNodes || [];
    const allVms = window._pxmxVms || [];
    const activeKey = window._pxmxVmTabFilter || null;
    const _cmp = (a, b) => String(a || '').localeCompare(String(b || ''), undefined,
        { numeric: true, sensitivity: 'base' });
    const sortedNodes = nodes.slice().sort((a, b) => _cmp(a.cluster, b.cluster) || _cmp(a.node, b.node));
    const tabBtn = (key, label, count, active) =>
        `<button onclick="pxmxSelectVmTab('${escJsAttr(key || '')}')" class="px-3 py-1.5 rounded-md text-xs font-bold transition-colors ${active ? 'bg-[#01A982]/10 text-[#01A982] border border-[#01A982]' : 'text-slate-500 hover:bg-slate-100 border border-transparent'}" title="Filter virtual machines by server ${escapeHtml(label)}">${escapeHtml(label)} <span class="opacity-60">(${count})</span></button>`;
    const countFor = key => allVms.filter(v => pxmxNodeKey(v.cluster, v.node) === key).length;
    return `<div class="flex flex-wrap gap-1.5 mb-3">
        ${tabBtn('', 'All', allVms.length, !activeKey)}
        ${sortedNodes.map(n => tabBtn(pxmxNodeKey(n.cluster, n.node), n.node, countFor(pxmxNodeKey(n.cluster, n.node)), activeKey === pxmxNodeKey(n.cluster, n.node))).join('')}
    </div>`;
}
window.pxmxSelectVmTab = function (key) {
    window._pxmxVmTabFilter = key || null;
    const wrap = document.getElementById('pxmx-vm-section');
    if (wrap) wrap.innerHTML = pxmxVmSectionHtml();
};
// Full section (header + tabs + table) — one shared builder so a fresh page
// load and a tab click render identically.
function pxmxVmSectionHtml() {
    const nodes = window._pxmxNodes || [];
    const activeKey = window._pxmxVmTabFilter || null;
    const vms = pxmxFilteredVms();
    const countLabel = activeKey ? `${vms.length} on ${escapeHtml((activeKey.split('::')[1] || activeKey))}` : `${vms.length} total`;
    const buildBtn = nodes.length
        ? `<button onclick="pxmxOpenCreateVm()" class="mb-3 ml-2 px-3 py-1.5 rounded-md text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors" title="Create a new virtual machine from an ISO installer">＋ Build VM from ISO</button>`
        : '';
    return `<div class="flex items-center justify-between mb-1 px-1">
            <h3 class="text-base font-semibold text-[#263040]">Virtual Machines &amp; Containers
                <span class="text-xs text-slate-400 font-normal">(${countLabel})</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>
            ${buildBtn}
        </div>`
        + pxmxVmTabsHtml()
        + `<div id="pxmx-vm-list">${vms.length > 0 ? pxmxVmTableHtml(vms)
           : '<p class="p-4 text-slate-400 italic text-sm">No VMs on this server.</p>'}</div>`;
}

// Bulk VM actions — operate on the checked rows. Reuses /api/pxmx/vm-action per
// VM (so Backup gets the same Hypervisors-config injection), confirming ONCE for
// the batch when confirm_destructive is on.
function pxmxBulkBar() {
    if (!canEdit()) return '';   // VM control is write-tier; view users see none
    // Render from the shared PXMX_VM_ACTIONS spec so the bulk buttons match the
    // inline per-row buttons exactly (icon, label, color, hover, sizing).
    const btns = PXMX_VM_ACTIONS.map(s =>
        `<button onclick="pxmxBulkAction('${s.action}')" class="px-2 py-0.5 rounded text-[10px] font-bold ${s.cls}" title="Execute ${s.label} on all selected VMs">${s.label}</button>`).join('');
    return `<div class="flex flex-wrap items-center gap-2 mb-3 text-xs">
      <span class="text-slate-400 font-medium mr-1">Bulk (selected):</span>
      ${btns}
      <span id="pxmx-bulk-status" class="text-slate-400"></span>
    </div>`;
}

window.pxmxBulkSelectAll = function (checked) {
    document.querySelectorAll('.pxmx-vm-sel').forEach(cb => { cb.checked = checked; });
};

window.pxmxBulkAction = async function (action) {
    const sel = Array.from(document.querySelectorAll('.pxmx-vm-sel:checked')).map(cb => cb.value);
    if (!sel.length) { showToast('No VMs selected', 'info'); return; }
    if (['destroy', 'delete'].includes(action)) {
        if (!window.confirm(`DELETE ${sel.length} selected VM(s)?\n\nThis DESTROYS each VM and its disks (--purge) — IRREVERSIBLE. (VMs protected in Setup → Hypervisors are skipped.)`)) return;
    } else if (['stop', 'reboot', 'restart'].includes(action)) {
        const cfg = await pxmxHvConfig();
        if (cfg.confirm_destructive !== false &&
            !window.confirm(`${action.toUpperCase()} ${sel.length} selected VM(s)?`)) return;
    }
    // Backup skips the confirm dialog — non-destructive (snapshot mode); go
    // straight to the batched action and toast the per-VM results.
    const statusEl = document.getElementById('pxmx-bulk-status');
    // One batched request — the hub authorizes + relays each VM server-side
    // (bounded-concurrent) instead of the browser firing one POST per VM. Each
    // item keeps its own node so VMs route to their own host.
    const items = sel.map(uid => (window._pxmxVms || []).find(v => v.unique_id === uid))
                     .filter(Boolean)
                     .map(vm => ({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type }));
    const missing = sel.length - items.length;
    if (statusEl) statusEl.textContent = `${action}… ${items.length} VM(s)`;
    // Optimistic in-flight: mark every selected VM the moment we dispatch (before
    // awaiting), then re-render so their rows show the operation immediately.
    const _op = _PXMX_ACTION_OP[action];
    if (_op) { items.forEach(it => _pxmxVmInflight.set(String((it.unique_id || it.vmid) != null ? (it.unique_id || it.vmid) : ''), { op: _op, ts: Date.now() })); pxmxRerenderVmList(); }
    let ok = 0, fail = missing;
    try {
        const r = await setupFetch('/api/pxmx/vm-action-bulk', {
            method: 'POST',
            body: JSON.stringify({ action, items, tenant: currentTenant }),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d && Array.isArray(d.results)) {
            ok = d.results.filter(x => x && x.ok).length;
            fail += d.results.filter(x => x && !x.ok).length;
        } else { fail += items.length; }
    } catch (e) { fail += items.length; }
    showToast(`Bulk ${action}: ${ok} ok${fail ? `, ${fail} failed` : ''}`, fail ? 'error' : 'success');
    if (statusEl) statusEl.textContent = `${ok} ok${fail ? `, ${fail} failed` : ''}`;
    setTimeout(() => loadPxmxData('Virtual Machines'), 1500);
};

// Clicking a VM row opens a details panel with Start/Stop/Restart/Snapshot
// controls (VNC Console wired up in the VNC increment). Back returns to the
// cached VM list. Actions POST /api/pxmx/vm-action (admin-only) which routes to
// the pxmx spoke's PXMX_VM_ACTION (unguarded — any vmid, not just the sim floor).
function openVmDetail(uniqueId) {
    const vms = window._pxmxVms || [];
    const vm = vms.find(v => v.unique_id === uniqueId);
    const container = document.getElementById('pxmx-content');
    if (!vm || !container) return;
    const memGb  = ((vm.mem_bytes || 0) / 1073741824).toFixed(1);
    const ipList = Array.isArray(vm.ips) ? vm.ips : [];
    const runCls  = vm.status === 'running' ? 'bg-green-100 text-green-700'
                 : vm.status === 'stopped' ? 'bg-slate-100 text-slate-500' : 'bg-amber-100 text-amber-700';
    const typeCls = vm.type === 'lxc' ? 'bg-blue-50 text-blue-600' : 'bg-[#263040]/10 text-[#263040]';
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const uid = escJs(vm.unique_id);
    container.innerHTML = `
        <button onclick="loadPxmxData('Virtual Machines')" class="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-[#01A982] font-medium transition-colors" title="Return to virtual machines list">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
            Back to VM list
        </button>
        <div class="rounded-lg border border-slate-200 bg-slate-50/50 p-4 mb-4">
            <h3 class="text-base font-semibold text-[#263040]">${escapeHtml(vm.name || '—')}
                <span class="text-xs text-slate-400 font-normal font-mono">VMID ${vm.vmid} · ${escapeHtml((vm.cluster || '') + '/' + (vm.node || ''))}</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>
            <p class="text-xs text-slate-500 mt-1">Status
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${runCls}">${vm.status}</span>
                · <span class="px-2 py-0.5 rounded-full text-xs font-medium ${typeCls}">${vm.type || 'vm'}</span>
                · CPU ${vm.cpu ?? '—'}% · RAM ${memGb} GB
                · IP ${ipList.length ? escapeHtml(ipList.join(', ')) : '—'}
                · Pool ${vm.pool ? escapeHtml(vm.pool) : '—'}</p>
        </div>
        <div class="flex flex-wrap items-center gap-2 mb-4"${canEdit() ? '' : ' style="display:none"'}>
            <button onclick="pxmxVmAction('${uid}','start')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-green-600 hover:bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] transition-colors" title="Power on this virtual machine">▶ Start</button>
            <button onclick="pxmxVmAction('${uid}','stop')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-red-600 hover:bg-red-700 text-white transition-colors" title="Gracefully shut down or force-stop this VM">■ Stop</button>
            <button onclick="pxmxVmAction('${uid}','reboot')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-amber-600 hover:bg-amber-700 text-white transition-colors" title="Reboot this virtual machine">↺ Restart</button>
            <button onclick="pxmxVmAction('${uid}','snapshot')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-600 hover:bg-slate-700 text-white transition-colors" title="Take an instantaneous snapshot of this VM">📷 Snapshot</button>
            ${isAdmin() ? `<button onclick="pxmxOpenVmSnapSchedule('${uid}')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 transition-colors" title="View or set how often this VM is snapshotted">🕒 Schedule…</button>` : ''}
            <button onclick="pxmxVmAction('${uid}','backup')" title="vzdump backup to the storage configured in Setup → Hypervisors" class="px-3 py-1.5 rounded-md text-xs font-bold bg-sky-600 hover:bg-sky-700 text-white transition-colors">💾 Backup</button>
            <button id="pxmx-backup-hub-btn" onclick="pxmxBackupToHub('${uid}')" title="vzdump this template and store a copy in the hub's Template Repo (Template Repo page). The archive is deleted from the chosen storage after streaming." class="px-3 py-1.5 rounded-md text-xs font-bold bg-sky-100 hover:bg-sky-200 text-sky-700 border border-sky-300 transition-colors">⬆ Back up to Hub</button>
            <select id="pxmx-backup-hub-storage" title="vzdump storage target for THIS backup (file-based only — PBS excluded; vzdump-to-PBS isn't a single streamable file). The archive is deleted from here after it streams to the hub." class="px-2 py-1.5 rounded-md text-xs border border-slate-300 bg-white max-w-[12rem]"><option value="">loading storages…</option></select>
            <button id="pxmx-vm-console-btn" onclick="pxmxOpenConsole('${uid}')" title="Open VNC console (noVNC)" class="px-3 py-1.5 rounded-md text-xs font-bold bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] transition-colors">🖥 Console</button>
            ${vm.protected
                ? `<button disabled title="Protected from deletion — remove the safeguard in Setup → Hypervisors" class="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-200 text-slate-400 cursor-not-allowed">🔒 Delete</button>`
                : `<button onclick="pxmxVmAction('${uid}','destroy')" title="Destroy this VM and its disks (--purge) — IRREVERSIBLE" class="px-3 py-1.5 rounded-md text-xs font-bold bg-red-800 hover:bg-red-900 text-white transition-colors">🗑 Delete</button>`}
            ${(() => { const tp = (window._pxmxTemplatePools||[]); return (vm.pool && tp.includes(String(vm.pool).toLowerCase())) ? `<button onclick="pxmxCloneVm('${uid}')" title="Clone this template to a new VM" class="px-3 py-1.5 rounded-md text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors">⧉ Clone</button><button onclick="pxmxDeploySpoke('${uid}')" title="One-click spoke deploy: clone this golden spoke template, auto-name it CS-SVR-0N, and start it so it DHCPs and self-onboards" class="px-3 py-1.5 rounded-md text-xs font-bold bg-emerald-600 hover:bg-emerald-700 text-white transition-colors">🚀 Deploy Spoke</button>` : ''; })()}
            <span id="pxmx-vm-action-status" class="text-xs text-slate-400"></span>
        </div>
        <div id="pxmx-vm-snap-sched" class="hidden rounded-lg border border-slate-200 bg-white p-4 mb-4"></div>`;
    // Populate the "Back up to Hub" storage dropdown with this host's
    // file-based backup storages (PBS excluded). Default = the host's
    // configured backup_storage (per-host override, else global).
    pxmxPopulateBackupHubStorage(vm.node || '');
}

// Hypervisor → Settings tab: backup (storage/mode/keep) + snapshot (keep/prefix)
// + confirm-destructive + per-host overrides. Reads GET /hypervisors-config and
// the live per-host storage list (GET /hypervisor-storages, which fans
// PXMX_LIST_STORAGE to each host). Saves via PUT. Governs the VM action panel.
async function renderPxmxSettings(container) {
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading Hypervisor settings…</p>';
    let cfg = {}, storages = { hosts: [] }, vms = [];
    try {
        const [cR, sR, vR] = await Promise.all([
            setupFetch(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`),
            setupFetch(`/sim/api/tenant/${currentTenant}/hypervisor-storages?tenant_id=${encodeURIComponent(currentTenant)}`),
            setupFetch(`/api/pxmx/vms?tenant=${encodeURIComponent(currentTenant)}`),
        ]);
        cfg = (await cR.json()).hypervisors_config || {};
        storages = await sR.json() || { hosts: [] };
        const _vd = await vR.json().catch(() => ({}));
        vms = (Array.isArray(_vd.vms) ? _vd.vms : []).filter(v => v && v.unique_id);
    } catch (e) {
        container.innerHTML = `<div class="p-4 text-sm text-red-600">Could not load Hypervisor settings: ${escapeHtml(String(e.message || e))}</div>`;
        return;
    }
    window._pxmxHvConfig = cfg; // refresh the cache the VM actions read
    const allStorages = [...new Set((storages.hosts || []).flatMap(h => h.storages || []))].sort();
    const optList = (arr, sel, blank) => `<option value="">${blank}</option>` +
        arr.map(s => `<option value="${escapeHtml(s)}"${s === sel ? ' selected' : ''}>${escapeHtml(s)}</option>`).join('');
    const modeSel = (sel, blank) => (blank ? `<option value="">${blank}</option>` : '') +
        ['snapshot', 'suspend', 'stop'].map(m => `<option value="${m}"${m === sel ? ' selected' : ''}>${m}</option>`).join('');
    const perHost = cfg.per_host || {};
    const hostRows = (storages.hosts || []).map(h => {
        const ph = perHost[h.hostname] || {};
        return `<tr data-host="${escapeHtml(h.hostname)}" class="border-b border-slate-50">
          <td class="px-3 py-2 text-sm font-medium text-slate-700">${escapeHtml(h.hostname)}</td>
          <td class="px-3 py-2"><select class="ph-storage border border-slate-200 rounded px-2 py-1 text-xs bg-white">${optList(h.storages || [], ph.backup_storage, '(use global)')}</select></td>
          <td class="px-3 py-2"><select class="ph-mode border border-slate-200 rounded px-2 py-1 text-xs bg-white">${modeSel(ph.backup_mode, '(global)')}</select></td>
          <td class="px-3 py-2"><input type="number" min="0" class="ph-keep border border-slate-200 rounded px-2 py-1 text-xs w-20" value="${ph.backup_keep ?? ''}" placeholder="global"/></td>
        </tr>`;
    }).join('') || `<tr><td colspan="4" class="px-3 py-3 text-xs text-slate-400 italic">No hosts reporting storages yet (agents fan PXMX_LIST_STORAGE on connect).</td></tr>`;
    const inp = 'border border-slate-200 rounded-md px-3 py-1.5 text-sm w-full';
    const lbl = 'block text-xs font-bold text-slate-500 uppercase tracking-wider mb-2';
    // Delete-protection safeguard (Global Admin only): a checkbox per visible VM
    // so the admin can mark which VMs can't be deleted. Stored as this tenant's
    // ``protected_vms`` (unique_id list); enforced globally as the union across
    // all tenants. Pre-check the already-protected VMs.
    const protectedVms = new Set((cfg.protected_vms || []).map(String));
    const protectRows = vms.length ? vms.map(v => {
        const uid = escapeHtml(v.unique_id);
        const checked = protectedVms.has(v.unique_id) ? 'checked' : '';
        return `<label class="flex items-center gap-2 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 cursor-pointer">
            <input type="checkbox" class="pxmx-protect-cb rounded" value="${uid}" ${checked} title="Lock VM to prevent deletion"/>
            <span class="font-medium">${escapeHtml(v.name || '—')}</span>
            <span class="text-slate-400 font-mono">VMID ${escapeHtml(v.vmid)} · ${escapeHtml((v.cluster || '') + '/' + (v.node || ''))}</span>
        </label>`;
    }).join('') : `<div class="px-3 py-3 text-xs text-slate-400 italic">No VMs visible for this tenant.</div>`;
    container.innerHTML = `
      <div class="space-y-5 max-w-3xl">
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-3">Backup (vzdump) ${helpIcon('pxmx', null, 'Hypervisor help')}</p>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div><label class="${lbl}">Default storage</label><select id="hv-backup-storage" class="${inp}" title="Default storage destination for VM backups">${optList(allStorages, cfg.backup_storage, '— select —')}</select></div>
            <div><label class="${lbl}">Mode</label><select id="hv-backup-mode" class="${inp}" title="Backup mode (snapshot, suspend, or stop)">${modeSel(cfg.backup_mode || 'snapshot', '')}</select></div>
            <div><label class="${lbl}">Keep last (0 = no prune)</label><input id="hv-backup-keep" type="number" min="0" value="${cfg.backup_keep ?? 3}" class="${inp}" title="Number of backup archives to keep per VM"/></div>
          </div>
          <p class="text-[11px] text-slate-400 mt-2">Snapshot mode = no downtime. Storage list is pulled live from each host; per-host overrides below win over the default.</p>
        </div>
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-3">Snapshot</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div><label class="${lbl}">Keep last</label><input id="hv-snap-keep" type="number" min="0" value="${cfg.snapshot_keep ?? 5}" class="${inp}" title="Number of snapshots to retain"/></div>
            <div><label class="${lbl}">Name prefix</label><input id="hv-snap-prefix" type="text" value="${escapeHtml(cfg.snapshot_prefix || 'lm')}" class="${inp}" title="Prefix string for automated snapshot names"/></div>
          </div>
        </div>
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-3">Per-host overrides</p>
          <div class="overflow-x-auto"><table class="w-full text-sm" id="pxmx-perhost-rows">
            <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr><th class="px-3 py-2 text-left font-medium">Host</th><th class="px-3 py-2 text-left font-medium">Backup storage</th><th class="px-3 py-2 text-left font-medium">Mode</th><th class="px-3 py-2 text-left font-medium">Keep</th></tr></thead>
            <tbody>${hostRows}</tbody>
          </table></div>
        </div>
        <div class="hpe-card rounded-lg p-5 shadow-sm space-y-3">
          <label class="flex items-center gap-2 text-sm text-slate-700"><input id="hv-confirm" type="checkbox" ${cfg.confirm_destructive !== false ? 'checked' : ''} class="rounded" title="Require confirmation for destructive operations"/> Confirm before destructive VM actions (stop / restart / reboot)</label>
          ${isAdmin() ? `<label class="flex items-start gap-2 text-sm text-slate-700"><input id="hv-host-shell" type="checkbox" ${cfg.host_shell_enabled ? 'checked' : ''} class="rounded mt-0.5" title="Enable root PTY shell on hypervisor host"/> <span>Enable <b>host terminal</b> (root shell on the Proxmox host via VM Server → Terminal). <span class="text-amber-600">Off by default</span> — a live root shell on this tenant's hypervisor. Global Admin (any host) + Tenant Admin (own tenant). Every session is audited.</span></label>` : ''}
          ${isAdmin() ? `<label class="flex items-start gap-2 text-sm text-slate-700"><input id="hv-tenant-console" type="checkbox" ${cfg.tenant_console_enabled ? 'checked' : ''} class="rounded mt-0.5" title="Allow Tenant Admins to open VM consoles"/> <span>Allow <b>Tenant Admins</b> to open VM consoles &amp; lifecycle actions on this hypervisor. <span class="text-amber-600">Off by default</span> — turn on for a hypervisor dedicated to one tenant (or a flat lab) whose VMs aren't tagged or subnet-scoped. On a <b>shared</b> hypervisor leave OFF: tenant admins are then limited to VMs attributable to their tenant by Proxmox tag or subnet. (Enabling host terminal above also grants console.)</span></label>` : ''}
        </div>
        ${isAdmin() ? `<div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-1">Delete protection ${helpIcon('pxmx', null, 'Hypervisor help')}</p>
          <p class="text-[11px] text-slate-400 mb-3">Checked VMs cannot be deleted from anywhere — the list is enforced globally across all tenants. Managed by Global Admin.</p>
          <div class="max-h-64 overflow-y-auto border border-slate-200 rounded-md divide-y divide-slate-50">${protectRows}</div>
        </div>` : ''}
        ${isAdmin() ? `<div class="hpe-card rounded-lg p-5 shadow-sm" id="pxmx-snap-schedules"></div>` : ''}
        <div class="flex justify-end items-center gap-3">
          <button onclick="savePxmxSettings()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-5 py-2 rounded-md text-sm font-bold" title="Save hypervisor backup and console settings">Save</button>
          <span id="pxmx-settings-status" class="text-xs text-slate-400"></span>
        </div>
      </div>`;
    if (isAdmin()) pxmxLoadSnapSchedules();
}

// ── VM snapshot schedules (Global Admin) ─────────────────────────────────────
// Shared hub service (/api/vm-snapshots): snapshot picked VMs, or every VM with
// a tag / in a pool, every N hours, keeping the last K. Schedules belong to the
// tenant being viewed and only see that tenant's VMs. Managed here (Settings)
// and per VM from the VM detail view (pxmxOpenVmSnapSchedule).
function _snapUrl(path = '') {
    return `/api/vm-snapshots/schedules${path}?tenant=${encodeURIComponent(currentTenant || '')}`;
}

// Refresh whichever schedule view is open (Settings list or a VM's panel).
function _pxmxSnapRefresh() {
    if (document.getElementById('pxmx-snap-schedules')) pxmxLoadSnapSchedules();
    const vmBox = document.getElementById('pxmx-vm-snap-sched');
    if (vmBox && vmBox.dataset.uid) pxmxOpenVmSnapSchedule(vmBox.dataset.uid);
}

function _vmTags(vm) {
    const t = vm.tags || [];
    return Array.isArray(t) ? t : String(t).split(/[;,\s]+/).filter(Boolean);
}

function _pxmxSnapLastRun(s) {
    const r = s.last_result;
    if (s.running) return '<span class="text-blue-600">running…</span>';
    if (!r) return '<span class="text-slate-400">never run</span>';
    return `<span class="${r.errors.length ? 'text-red-600' : 'text-emerald-700'}" title="${escapeHtml(r.errors.join('\n'))}">${escapeHtml(new Date(r.at * 1000).toLocaleString())}: ${r.ok} ok${r.failed ? `, ${r.failed} failed` : ''}${r.errors.length && !r.failed ? ' — ' + escapeHtml(r.errors[0]) : ''}</span>`;
}

function _ownSchedule(schedules, uid) {
    return schedules.find(s => s.vms.length === 1 && s.vms[0] === uid && !s.tags.length && !s.pools.length);
}

// VM detail → "Schedule…": the schedules that snapshot this VM, and a quick
// form for this VM's own schedule (one that targets just this VM).
async function pxmxOpenVmSnapSchedule(uid) {
    const box = document.getElementById('pxmx-vm-snap-sched');
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uid);
    if (!box || !vm) return;
    box.dataset.uid = uid;
    box.classList.remove('hidden');
    let d;
    try { d = await apiJson(_snapUrl()); }
    catch (e) { box.innerHTML = `<p class="text-sm text-red-600">Could not load snapshot schedules: ${escapeHtml(String(e.message || e))}</p>`; return; }
    const tags = _vmTags(vm);
    const own = _ownSchedule(d.schedules, uid);
    const via = s => [
        s.vms.includes(uid) ? 'this VM' : '',
        ...s.tags.filter(t => tags.includes(t)).map(t => 'tag ' + t),
        ...s.pools.filter(p => p === vm.pool).map(p => 'pool ' + p),
    ].filter(Boolean);
    const others = d.schedules.filter(s => s !== own && via(s).length);
    const inScope = d.vms.some(v => v.unique_id === uid);
    const btn = 'text-[11px] font-bold border border-slate-300 rounded px-2 py-0.5 hover:bg-slate-100';
    const inp = 'border border-slate-200 rounded-md px-2 py-1 text-sm w-20';
    const otherRows = others.map(s => `<li class="text-xs text-slate-600">${escapeHtml(s.name)}${s.enabled ? '' : ' (paused)'} — every ${s.every_hours}h, keep ${s.keep}, via ${escapeHtml(via(s).join(', '))} · ${_pxmxSnapLastRun(s)}</li>`).join('');
    const sid = own ? escapeHtml(JSON.stringify(own.id)) : '';
    box.innerHTML = `
      <div class="flex items-center justify-between mb-2">
        <p class="text-sm font-bold text-[#263040]">Snapshot schedule <span class="cursor-help font-normal text-slate-400" title="Snapshots this VM every N hours and deletes the oldest of this schedule's snapshots beyond Keep. Schedules that cover many VMs (by tag or pool) are managed in Hypervisors → Settings.">ⓘ</span></p>
        <button class="text-slate-400 hover:text-slate-600 text-sm" onclick="document.getElementById('pxmx-vm-snap-sched').classList.add('hidden')" title="Close">✕</button>
      </div>
      ${inScope ? '' : '<p class="text-xs text-amber-700 mb-2">This VM is not in the current tenant\'s VM list, so a schedule here would not snapshot it.</p>'}
      <div class="flex flex-wrap items-end gap-3">
        <label class="flex items-center gap-2 text-sm text-slate-700 self-center"><input id="vm-snap-enabled" type="checkbox" class="rounded" ${!own || own.enabled ? 'checked' : ''}/> Snapshot this VM</label>
        <div><label class="block text-[10px] font-bold text-slate-500 uppercase">Every (hours)</label><input id="vm-snap-every" type="number" min="1" max="8760" class="${inp}" value="${own ? own.every_hours : 24}"/></div>
        <div><label class="block text-[10px] font-bold text-slate-500 uppercase">Keep last</label><input id="vm-snap-keep" type="number" min="1" max="100" class="${inp}" value="${own ? own.keep : 7}"/></div>
        <button class="bg-[#01A982] hover:bg-[#018a6c] text-white px-3 py-1 rounded-md text-xs font-bold" onclick="pxmxSaveVmSnapSchedule(${escapeHtml(JSON.stringify(uid))})">${own ? 'Save' : 'Create schedule'}</button>
        ${own ? `<button class="${btn}" onclick="pxmxRunSnapSchedule(${sid})" ${own.running ? 'disabled' : ''}>Run now</button>
        <button class="${btn} text-red-700" onclick="pxmxDeleteSnapSchedule(${sid})">Delete</button>` : ''}
      </div>
      ${own ? `<p class="text-xs mt-2">Last run: ${_pxmxSnapLastRun(own)}</p>` : ''}
      ${otherRows ? `<p class="text-xs font-bold text-slate-500 mt-3">Also covered by</p><ul class="list-disc pl-5 mt-1 space-y-0.5">${otherRows}</ul>` : ''}`;
}

async function pxmxSaveVmSnapSchedule(uid) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uid) || {};
    const body = {
        enabled: document.getElementById('vm-snap-enabled').checked,
        every_hours: parseFloat(document.getElementById('vm-snap-every').value),
        keep: parseInt(document.getElementById('vm-snap-keep').value, 10),
        vms: [uid], tags: [], pools: [],
    };
    try {
        const own = _ownSchedule((await apiJson(_snapUrl())).schedules, uid);
        body.name = own ? own.name : `VM ${vm.name || vm.vmid}`;
        await apiJson(_snapUrl(own ? '/' + encodeURIComponent(own.id) : ''),
            { method: own ? 'PUT' : 'POST', body: JSON.stringify(body) });
        showToast('Snapshot schedule saved', 'success');
        pxmxOpenVmSnapSchedule(uid);
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}
async function pxmxLoadSnapSchedules(editId) {
    const box = document.getElementById('pxmx-snap-schedules');
    if (!box) return;
    let d;
    try { d = await apiJson(_snapUrl()); }
    catch (e) { box.innerHTML = `<p class="text-sm text-red-600">Could not load snapshot schedules: ${escapeHtml(String(e.message || e))}</p>`; return; }
    window._pxmxSnapData = d;
    const btn = 'text-[11px] font-bold border border-slate-300 rounded px-2 py-0.5 hover:bg-slate-100';
    const rows = d.schedules.map(s => {
        const targets = [
            s.vms.length ? `${s.vms.length} VM(s)` : '',
            s.tags.length ? 'tags: ' + s.tags.join(', ') : '',
            s.pools.length ? 'pools: ' + s.pools.join(', ') : '',
        ].filter(Boolean).join(' · ');
        const last = _pxmxSnapLastRun(s);
        const id = escapeHtml(JSON.stringify(s.id));
        return `<tr class="border-b border-slate-50 text-xs">
          <td class="px-3 py-2 font-medium text-slate-700">${escapeHtml(s.name)}${s.enabled ? '' : ' <span class="text-slate-400">(paused)</span>'}</td>
          <td class="px-3 py-2 text-slate-600">${escapeHtml(targets)} <span class="text-slate-400">= ${s.vm_count} VM(s)</span></td>
          <td class="px-3 py-2 text-slate-600">every ${s.every_hours}h · keep ${s.keep}</td>
          <td class="px-3 py-2">${last}</td>
          <td class="px-3 py-2 whitespace-nowrap text-right">
            <button class="${btn}" onclick="pxmxRunSnapSchedule(${id})" ${s.running ? 'disabled' : ''}>Run now</button>
            <button class="${btn}" onclick="pxmxLoadSnapSchedules(${id})">Edit</button>
            <button class="${btn} text-red-700" onclick="pxmxDeleteSnapSchedule(${id})">Delete</button>
          </td></tr>`;
    }).join('') || '<tr><td colspan="5" class="px-3 py-3 text-xs text-slate-400 italic">No schedules yet.</td></tr>';
    box.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <p class="text-sm font-bold text-[#263040]">Snapshot schedules <span class="cursor-help font-normal text-slate-400" title="Snapshots the chosen VMs — and every VM carrying a chosen Proxmox tag or in a chosen pool — every N hours, deleting the oldest of that schedule's snapshots beyond Keep. Checked every 5 minutes; VMs are snapshotted one at a time. Deleting a schedule keeps its snapshots. Global Admin only.">ⓘ</span></p>
        <button class="${btn}" onclick="pxmxLoadSnapSchedules('new')">+ Add schedule</button>
      </div>
      <div class="overflow-x-auto"><table class="w-full"><tbody>${rows}</tbody></table></div>
      ${editId ? _pxmxSnapForm(d, d.schedules.find(s => s.id === editId)) : ''}`;
}

function _pxmxSnapForm(d, s) {
    s = s || { id: '', name: '', enabled: true, vms: [], tags: [], pools: [], every_hours: 24, keep: 7 };
    const inp = 'border border-slate-200 rounded-md px-3 py-1.5 text-sm w-full';
    const lbl = 'block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1';
    const boxes = (cls, items, picked, label) => items.length
        ? items.map(v => `<label class="flex items-center gap-2 px-3 py-1 text-xs text-slate-700 hover:bg-slate-50 cursor-pointer"><input type="checkbox" class="${cls} rounded" value="${escapeHtml(label ? v.unique_id : v)}" ${picked.includes(label ? v.unique_id : v) ? 'checked' : ''}/>${label ? label(v) : escapeHtml(v)}</label>`).join('')
        : '<div class="px-3 py-2 text-xs text-slate-400 italic">none</div>';
    const vmLabel = v => `<span class="font-medium">${escapeHtml(v.name || '—')}</span> <span class="text-slate-400 font-mono">VMID ${escapeHtml(String(v.vmid))} · ${escapeHtml(v.node || '')}</span>`;
    return `
      <div class="mt-4 border border-slate-200 rounded-md p-4 space-y-3 bg-slate-50" id="pxmx-snap-form" data-id="${escapeHtml(s.id)}">
        <p class="text-xs font-bold text-slate-600">${s.id ? 'Edit schedule' : 'New schedule'}</p>
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <div class="sm:col-span-2"><label class="${lbl}">Name</label><input id="snap-name" class="${inp}" value="${escapeHtml(s.name)}"/></div>
          <div><label class="${lbl}">Every (hours)</label><input id="snap-every" type="number" min="1" max="8760" class="${inp}" value="${s.every_hours}"/></div>
          <div><label class="${lbl}">Keep last</label><input id="snap-keep" type="number" min="1" max="100" class="${inp}" value="${s.keep}"/></div>
        </div>
        <label class="flex items-center gap-2 text-sm text-slate-700"><input id="snap-enabled" type="checkbox" class="rounded" ${s.enabled ? 'checked' : ''}/> Enabled</label>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div class="sm:col-span-2"><label class="${lbl}">VMs</label><div class="max-h-56 overflow-y-auto border border-slate-200 rounded-md bg-white">${boxes('snap-vm', d.vms, s.vms, vmLabel)}</div></div>
          <div class="space-y-3">
            <div><label class="${lbl}" title="Every VM with one of these Proxmox tags, including VMs added later">Tags</label><div class="max-h-24 overflow-y-auto border border-slate-200 rounded-md bg-white">${boxes('snap-tag', d.tags, s.tags)}</div></div>
            <div><label class="${lbl}" title="Every VM in one of these Proxmox pools, including VMs added later">Pools</label><div class="max-h-24 overflow-y-auto border border-slate-200 rounded-md bg-white">${boxes('snap-pool', d.pools, s.pools)}</div></div>
          </div>
        </div>
        <div class="flex justify-end gap-2">
          <button class="text-sm border border-slate-300 rounded-md px-4 py-1.5" onclick="pxmxLoadSnapSchedules()">Cancel</button>
          <button class="bg-[#01A982] hover:bg-[#018a6c] text-white px-4 py-1.5 rounded-md text-sm font-bold" onclick="pxmxSaveSnapSchedule()">Save schedule</button>
        </div>
      </div>`;
}

async function pxmxSaveSnapSchedule() {
    const form = document.getElementById('pxmx-snap-form');
    const picked = cls => Array.from(form.querySelectorAll('.' + cls)).filter(cb => cb.checked).map(cb => cb.value);
    const body = {
        name: document.getElementById('snap-name').value.trim(),
        enabled: document.getElementById('snap-enabled').checked,
        every_hours: parseFloat(document.getElementById('snap-every').value),
        keep: parseInt(document.getElementById('snap-keep').value, 10),
        vms: picked('snap-vm'), tags: picked('snap-tag'), pools: picked('snap-pool'),
    };
    const id = form.dataset.id;
    try {
        await apiJson(_snapUrl(id ? '/' + encodeURIComponent(id) : ''),
            { method: id ? 'PUT' : 'POST', body: JSON.stringify(body) });
        showToast('Snapshot schedule saved', 'success');
        pxmxLoadSnapSchedules();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function pxmxRunSnapSchedule(id) {
    try {
        await apiJson(_snapUrl(`/${encodeURIComponent(id)}/run`), { method: 'POST' });
        showToast('Snapshotting started — the result shows under Last run', 'success');
        _pxmxSnapRefresh();
        setTimeout(_pxmxSnapRefresh, 15000);
    } catch (e) { showToast('Run failed: ' + (e.message || e), 'error'); }
}

async function pxmxDeleteSnapSchedule(id) {
    if (!confirm('Delete this snapshot schedule? Snapshots it already took are kept.')) return;
    try {
        await apiJson(_snapUrl('/' + encodeURIComponent(id)), { method: 'DELETE' });
        _pxmxSnapRefresh();
    } catch (e) { showToast('Delete failed: ' + (e.message || e), 'error'); }
}

async function savePxmxSettings() {
    const val = id => (document.getElementById(id) || {}).value;
    const perHost = {};
    document.querySelectorAll('#pxmx-perhost-rows tr[data-host]').forEach(tr => {
        const host = tr.getAttribute('data-host');
        const st = (tr.querySelector('.ph-storage') || {}).value || '';
        const md = (tr.querySelector('.ph-mode') || {}).value || '';
        const kp = (tr.querySelector('.ph-keep') || {}).value;
        const o = {};
        if (st) o.backup_storage = st;
        if (md) o.backup_mode = md;
        if (kp !== '' && kp != null) o.backup_keep = parseInt(kp, 10);
        if (Object.keys(o).length) perHost[host] = o;
    });
    const cfg = {
        backup_storage: val('hv-backup-storage') || '',
        backup_mode: val('hv-backup-mode') || 'snapshot',
        backup_keep: parseInt(val('hv-backup-keep') || '0', 10) || 0,
        snapshot_keep: parseInt(val('hv-snap-keep') || '0', 10) || 0,
        snapshot_prefix: val('hv-snap-prefix') || 'lm',
        confirm_destructive: (document.getElementById('hv-confirm') || {}).checked !== false,
        per_host: perHost,
    };
    const _hostShellEl = document.getElementById('hv-host-shell');
    if (_hostShellEl) cfg.host_shell_enabled = !!_hostShellEl.checked;
    else if (window._pxmxHvConfig) cfg.host_shell_enabled = !!window._pxmxHvConfig.host_shell_enabled;  // preserve for non-admins
    const _tenantConsoleEl = document.getElementById('hv-tenant-console');
    if (_tenantConsoleEl) cfg.tenant_console_enabled = !!_tenantConsoleEl.checked;
    else if (window._pxmxHvConfig) cfg.tenant_console_enabled = !!window._pxmxHvConfig.tenant_console_enabled;  // preserve for non-admins
    // Delete-protection list (Global Admin only renders the checkboxes). Collect
    // the checked unique_ids; for non-admins (no checkboxes) preserve the
    // existing list so a non-admin Save doesn't wipe the safeguard.
    const _protectCbs = document.querySelectorAll('.pxmx-protect-cb');
    if (_protectCbs.length) {
        cfg.protected_vms = Array.from(_protectCbs).filter(cb => cb.checked).map(cb => cb.value);
    } else if (window._pxmxHvConfig) {
        cfg.protected_vms = window._pxmxHvConfig.protected_vms || [];
    }
    const st = document.getElementById('pxmx-settings-status');
    try {
        const r = await setupFetch(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`, {
            method: 'PUT', body: JSON.stringify({ hypervisors_config: cfg }),
        });
        if (r.ok) { window._pxmxHvConfig = cfg; showToast('Hypervisor settings saved', 'success'); if (st) st.textContent = 'Saved'; }
        else { const d = await r.json().catch(() => ({})); showToast('Save failed: ' + (d.detail || r.status), 'error'); if (st) st.textContent = 'Save failed'; }
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); if (st) st.textContent = 'Save failed'; }
}

// Cached Setup → Hypervisors config (confirm toggle + backup/snapshot settings).
// Fetched once per view; pass force=true to refresh after a save.
async function pxmxHvConfig(force) {
    if (!force && window._pxmxHvConfig) return window._pxmxHvConfig;
    try {
        const d = await apiJson(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`);
        window._pxmxHvConfig = (d && d.hypervisors_config) || {};
    } catch (e) { window._pxmxHvConfig = window._pxmxHvConfig || {}; }
    return window._pxmxHvConfig;
}

async function pxmxVmAction(uniqueId, action) {
    const vms = window._pxmxVms || [];
    const vm = vms.find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('VM not found in cache', 'error'); return; }
    // Delete is IRREVERSIBLE (qm/pct destroy --purge — VM + disks + backup-job
    // membership gone) so it ALWAYS confirms with the VM name, regardless of the
    // confirm_destructive toggle. Stop/reboot/restart/backup confirm only when
    // Setup → Hypervisors asks for it (default on).
    if (['destroy', 'delete'].includes(action)) {
        if (!window.confirm(`DELETE "${vm.name || vm.vmid}"?\n\nThis DESTROYS the VM and its disks (--purge) — IRREVERSIBLE.`)) return;
    } else if (['stop', 'reboot', 'restart'].includes(action)) {
        const cfg = await pxmxHvConfig();
        if (cfg.confirm_destructive !== false &&
            !window.confirm(`${action.toUpperCase()} "${vm.name || vm.vmid}"?`)) return;
    }
    // Backup skips the confirm dialog — vzdump (snapshot mode = no downtime) is
    // non-destructive, so go straight to the action and toast the result.
    const statusEl = document.getElementById('pxmx-vm-action-status');
    const setStat = (msg) => { if (statusEl) statusEl.textContent = msg; };
    setStat(`${action}…`);
    // Optimistic in-flight: mark the VM the moment we dispatch (before awaiting),
    // then re-render so its row shows the operation immediately. Telemetry
    // reconciles it on the next load (pxmxReconcileVmInflight).
    const _op = _PXMX_ACTION_OP[action];
    if (_op) { _pxmxVmInflight.set(pxmxVmKey(vm), { op: _op, ts: Date.now() }); pxmxRerenderVmList(); }
    try {
        const r = await setupFetch('/api/pxmx/vm-action', {
            method: 'POST',
            body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type, action, tenant: currentTenant })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(`${action} succeeded for ${vm.name || vm.vmid}`, 'success');
            setStat(`${action} done — refreshing`);
            setTimeout(() => loadPxmxData('Virtual Machines'), 1500);
        } else {
            showToast(`${action} failed: ${data && (data.message || data.detail) || r.status}`, 'error');
            setStat(`${action} failed`);
        }
    } catch (e) {
        showToast(`${action} failed: ${e.message || e}`, 'error');
        setStat(`${action} failed`);
    }
}

// Populate the "Back up to Hub" storage dropdown for the open VM's node.
// Lists the host's backup-capable storages EXCEPT PBS (vzdump-to-PBS pushes
// dedup chunks, not a single streamable .vma.zst we can PUT to the hub).
// Defaults to the host's configured backup_storage (per-host override, else
// the global default from Hypervisors → Settings). When no file-based storage
// is available, disables the ⬆ button so the admin can't queue a dump that
// would fall back to the node's root-disk temp dir (the space concern this
// feature exists to avoid).
let _pxmxBackupHubStorageCache = {};
async function pxmxPopulateBackupHubStorage(node) {
    const sel = document.getElementById('pxmx-backup-hub-storage');
    const btn = document.getElementById('pxmx-backup-hub-btn');
    if (!sel) return;
    if (!node) {
        sel.innerHTML = '<option value="">(no node)</option>';
        if (btn) { btn.disabled = true; btn.title = 'No node for this VM — cannot pick a storage.'; }
        return;
    }
    try {
        const [sR, cR] = await Promise.all([
            setupFetch(`/sim/api/tenant/${currentTenant}/hypervisor-storages?tenant_id=${encodeURIComponent(currentTenant)}`),
            setupFetch(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`),
        ]);
        const sdata = await sR.json() || { hosts: [] };
        const cdata = await cR.json().catch(() => ({}));
        const cfg = (cdata && cdata.hypervisors_config) || {};
        const host = (sdata.hosts || []).find(h =>
            String(h.hostname || '').toLowerCase() === String(node).toLowerCase());
        const types = (host && host.storage_types) || {};
        const all = (host && host.storages) || [];
        const fileBased = all.filter(s => types[s] !== 'pbs');
        const def = (cfg.per_host && cfg.per_host[node] && cfg.per_host[node].backup_storage)
            || cfg.backup_storage || '';
        _pxmxBackupHubStorageCache[node] = { storages: fileBased, default: def };
        if (!fileBased.length) {
            sel.innerHTML = '<option value="">no file-based storage</option>';
            sel.disabled = true;
            if (btn) { btn.disabled = true; btn.title = `No file-based backup storage on ${node} (only PBS / none). Configure one in Setup → Hypervisors first.`; }
            return;
        }
        sel.disabled = false;
        if (btn) { btn.disabled = false; btn.title = "vzdump this template and store a copy in the hub's Template Repo (Template Repo page). The archive is deleted from the chosen storage after streaming."; }
        const opts = fileBased.map(s => `<option value="${escapeHtml(s)}"${s === def ? ' selected' : ''}>${escapeHtml(s)}${types[s] ? ' (' + escapeHtml(types[s]) + ')' : ''}</option>`).join('');
        sel.innerHTML = `<option value="">— select storage —</option>${opts}`;
        if (def && fileBased.includes(def)) sel.value = def;
    } catch (e) {
        sel.innerHTML = '<option value="">(load failed)</option>';
        if (btn) btn.title = `Could not load storages: ${escapeHtml(String(e.message || e))}`;
    }
}

// Back up a Proxmox template to the hub's Template Repo. Sends the VM's unique_id
// (the hub resolves the owning agent + vmid + node) + the chosen vzdump storage
// target; the agent runs vzdump --storage <X> and streams the archive up, then
// deletes it from the storage. Long-running — the trigger just queues it.
async function pxmxBackupToHub(uniqueId) {
    const vms = window._pxmxVms || [];
    const vm = vms.find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('VM not found in cache', 'error'); return; }
    const sel = document.getElementById('pxmx-backup-hub-storage');
    const storage = sel ? String(sel.value || '').trim() : '';
    if (!storage) {
        showToast('Pick a vzdump storage target for this host first (file-based only — PBS excluded).', 'error');
        return;
    }
    if (!window.confirm(`Run vzdump on "${vm.name || vm.vmid}" to storage "${storage}" and stream a copy to the hub Template Repo?\n\nThe archive is deleted from ${storage} after streaming. This can take several minutes for a large template.`)) return;
    const statusEl = document.getElementById('pxmx-vm-action-status');
    if (statusEl) statusEl.textContent = `Backing up to hub (${storage})…`;
    try {
        const r = await setupFetch('/setup/templates/backup', {
            method: 'POST',
            body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, name: vm.name || '', storage })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(data.message || 'Backup queued — check the Template Repo in a few minutes.', 'success');
            if (statusEl) statusEl.textContent = 'Backup queued — see Template Repo';
        } else {
            showToast(`Backup failed: ${(data && (data.message || data.detail)) || r.status}`, 'error');
            if (statusEl) statusEl.textContent = 'Backup failed';
        }
    } catch (e) { showToast(`Backup failed: ${e.message || e}`, 'error'); }
}

// ── Template Repo (admin) — Proxmox template backups stored on the hub ────────
let _templateRepoTimer = null;
function _tplBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(1) + ' ' + u[i];
}
// Legend for the Template Repo Status column (swatches match _tplStatusBadge).
function _templateRepoLegend() {
    const item = (cls, label, desc) =>
        `<span class="inline-flex items-center gap-1.5" title="${escJsAttr(desc)}"><span class="w-2.5 h-2.5 rounded-full ${cls}"></span><span class="text-slate-600">${label}</span> <span class="text-slate-400">— ${desc}</span></span>`;
    const items = [
        ['bg-green-500', 'Complete', 'backup stored on the hub, ready to restore'],
        ['bg-sky-500', 'In progress', 'vzdump running on the node, or uploading to the hub (shows %)'],
        ['bg-red-500', 'Failed', 'backup did not complete — hover the badge for the error'],
    ];
    return `<div class="mt-3 px-1"><p class="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">Status legend</p><div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">${items.map(i => item(i[0], i[1], i[2])).join('')}</div></div>`;
}
function _tplStatusBadge(t) {
    const s = String(t.status || '').toLowerCase();
    if (s === 'complete') return '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">Complete</span>';
    if (s === 'failed') return `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-red-100 text-red-700" title="${escJsAttr(t.error || '')}">Failed</span>`;
    const label = s === 'dumping' ? 'Dumping' : (s === 'uploading' ? 'Uploading' : 'Pending');
    const pct = Math.max(0, Math.min(100, Number(t.progress) || 0));
    return `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-sky-100 text-sky-700"><span class="animate-spin inline-block w-2.5 h-2.5 rounded-full border-2 border-sky-500 border-t-transparent align-middle mr-1"></span>${label} ${pct}%</span>`;
}
async function renderTemplateRepo() {
    const host = document.getElementById('template-repo-content');
    if (!host) return;
    let templates = [];
    try {
        const r = await setupFetch('/setup/templates');
        const d = await r.json().catch(() => ({}));
        templates = (d && d.templates) || [];
    } catch (e) {
        host.innerHTML = `<div class="hpe-card rounded-lg p-5 text-red-600">Could not load templates: ${escapeHtml(e.message || String(e))}</div>`;
        return;
    }
    window._templateRepo = templates;
    const anyBusy = templates.some(t => !['complete', 'failed'].includes(String(t.status || '').toLowerCase()));
    // The repo is tenant-driven, per PXMX host: group by the tenant derived from
    // the source host, and order within a tenant by host (source_node) then name
    // so a host's templates cluster together.
    let rows;
    if (!templates.length) {
        rows = `<tr><td colspan="8" class="px-4 py-6 text-center text-sm text-slate-400 italic">No templates yet — use “⬆ Back up to Hub” on a Proxmox template VM (Hypervisors → open a template).</td></tr>`;
    } else {
        const groups = {};
        templates.forEach(t => { const k = t.tenant || '— Unassigned —'; (groups[k] = groups[k] || []).push(t); });
        rows = Object.keys(groups).sort((a, b) => a.localeCompare(b)).map(tenant => {
            const items = groups[tenant].sort((a, b) =>
                String(a.source_node || '').localeCompare(String(b.source_node || '')) ||
                String(a.name || '').localeCompare(String(b.name || '')));
            const hdr = `<tr class="bg-slate-100"><td colspan="8" class="px-4 py-1.5 text-xs font-bold text-slate-500 uppercase tracking-wider">Tenant: ${escapeHtml(tenant)} <span class="text-slate-400 font-normal normal-case">(${items.length})</span></td></tr>`;
            return hdr + items.map(_templateRepoRow).join('');
        }).join('');
    }
    host.innerHTML = `
      <div class="flex items-center justify-between">
        <div>
          <h2 class="text-lg font-bold text-[#263040]">Template Repo</h2>
          <p class="text-sm text-slate-500">Proxmox template backups (vzdump) stored on the hub. Trigger one with “⬆ Back up to Hub” on a template VM; edit each template’s metadata here.</p>
        </div>
        <button onclick="renderTemplateRepo()" class="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200">↻ Refresh</button>
      </div>
      <div class="hpe-card rounded-lg overflow-hidden">
        <div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>
            <th class="px-4 py-2 text-left font-medium">Name</th>
            <th class="px-4 py-2 text-left font-medium">OS</th>
            <th class="px-4 py-2 text-left font-medium">Version</th>
            <th class="px-4 py-2 text-left font-medium">Purpose</th>
            <th class="px-4 py-2 text-left font-medium">Source (host · vmid)</th>
            <th class="px-4 py-2 text-right font-medium">Size</th>
            <th class="px-4 py-2 text-left font-medium">Status</th>
            <th class="px-4 py-2 text-right font-medium">Actions</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </div>
      ${_templateRepoLegend()}`;
    if (_templateRepoTimer) { clearTimeout(_templateRepoTimer); _templateRepoTimer = null; }
    if (anyBusy && document.getElementById('template-repo-content')) {
        _templateRepoTimer = setTimeout(() => { if (document.getElementById('template-repo-content')) renderTemplateRepo(); }, 5000);
    }
}
function _templateRepoRow(t) {
    const id = escJsAttr(t.id);
    const src = `${escapeHtml(t.source_node || '—')} · vmid ${escapeHtml(String(t.source_vmid == null ? '—' : t.source_vmid))}`;
    const when = t.created_at ? new Date(t.created_at).toLocaleString() : '';
    return `<tr class="border-t border-slate-100 hover:bg-slate-50">
      <td class="px-4 py-2 font-medium text-slate-700">${escapeHtml(t.name || '—')}<div class="text-[11px] text-slate-400">${escapeHtml(when)}</div></td>
      <td class="px-4 py-2 text-slate-600">${escapeHtml(t.os || '—')}</td>
      <td class="px-4 py-2 text-slate-600">${escapeHtml(t.version || '—')}</td>
      <td class="px-4 py-2 text-slate-600">${escapeHtml(t.purpose || '—')}</td>
      <td class="px-4 py-2 text-xs text-slate-500">${src}</td>
      <td class="px-4 py-2 text-right text-slate-600">${t.size ? _tplBytes(t.size) : '—'}</td>
      <td class="px-4 py-2">${_tplStatusBadge(t)}</td>
      <td class="px-4 py-2 text-right whitespace-nowrap">
        <button onclick="templateRepoEdit('${id}')" class="px-2 py-1 rounded text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-600">Edit</button>
        <button onclick="templateRepoDelete('${id}')" class="px-2 py-1 rounded text-xs font-bold bg-red-100 hover:bg-red-200 text-red-700" title="Delete this template backup from the hub repository (irreversible)">Delete</button>
      </td>
    </tr>`;
}
function templateRepoEdit(id) {
    const t = (window._templateRepo || []).find(x => x.id === id);
    if (!t) return;
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const modal = document.createElement('div');
    modal.id = 'template-edit-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
      <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Edit template metadata</h3>
          <button onclick="this.closest('#template-edit-modal').remove()" class="text-slate-400 hover:text-slate-600">✕</button>
        </div>
        <div class="p-6 space-y-3">
          <div class="text-[11px] text-slate-400 font-mono">${esc(t.source_node)}/vmid ${esc(t.source_vmid)} · sha256 ${esc((t.sha256 || '').slice(0, 12))} · ${t.size ? _tplBytes(t.size) : '—'}</div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">Tenant</label><div class="w-full bg-slate-50 border border-slate-200 rounded-md px-3 py-2 text-sm text-slate-500">${esc(t.tenant) || '— Unassigned —'} <span class="text-[11px] text-slate-400">(derived from the PXMX host — not editable)</span></div></div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">Name</label><input id="tpl-edit-name" value="${esc(t.name)}" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm"></div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">OS</label><input id="tpl-edit-os" value="${esc(t.os)}" placeholder="Debian 12, Windows 11…" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm"></div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">Version</label><input id="tpl-edit-version" value="${esc(t.version)}" placeholder="v3, 2026-07 golden…" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm"></div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">Purpose</label><textarea id="tpl-edit-purpose" rows="2" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm">${esc(t.purpose)}</textarea></div>
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#template-edit-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="templateRepoSaveMeta('${escJsAttr(id)}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">Save</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
}
async function templateRepoSaveMeta(id) {
    const g = i => (document.getElementById(i) || {}).value || '';
    try {
        const r = await setupFetch(`/setup/templates/${encodeURIComponent(id)}`, {
            method: 'PATCH',
            body: JSON.stringify({ name: g('tpl-edit-name'), os: g('tpl-edit-os'), version: g('tpl-edit-version'), purpose: g('tpl-edit-purpose') })
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.status === 'SUCCESS') { showToast('Template metadata saved', 'success'); document.getElementById('template-edit-modal')?.remove(); renderTemplateRepo(); }
        else showToast(d.detail || 'Save failed', 'error');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
}
async function templateRepoDelete(id) {
    const t = (window._templateRepo || []).find(x => x.id === id);
    if (!window.confirm(`Delete template "${t ? (t.name || id) : id}" from the hub repo? This removes the stored archive.`)) return;
    try {
        const r = await setupFetch(`/setup/templates/${encodeURIComponent(id)}`, { method: 'DELETE' });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.status === 'SUCCESS') { showToast('Template deleted', 'success'); renderTemplateRepo(); }
        else showToast(d.detail || 'Delete failed', 'error');
    } catch (e) { showToast('Delete failed: ' + (e.message || e), 'error'); }
}

// Clone-from-template: opens a small modal prompting for the new VM's name (a
// free VMID is auto-assigned by the agent when left blank), then POSTs
// /api/pxmx/clone with the template unique_id. Templates are shared — any admin
// acting as a tenant may clone; the new VM is tagged with the acting tenant's
// proxmox_tag and shows up after the list refresh + VM sync. The hub enforces
// the template-pool membership server-side (UI affordance mirrors it).
async function pxmxCloneVm(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('Template not found in cache', 'error'); return; }
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const baseName = `${(vm.name || 'vm').replace(/[^a-zA-Z0-9-]/g, '').toLowerCase().slice(0, 12) || 'vm'}-clone`;
    // Fetch the Proxmox resource pools so the user can place the new VM in one.
    let pools = [];
    try {
        const r = await fetch('/api/pxmx/pools');
        const d = r.ok ? await r.json() : {};
        pools = d.pools || [];
    } catch (e) { /* dropdown just stays empty */ }
    const poolOpts = ['<option value="">— no pool —</option>']
        .concat(pools.map(p => `<option value="${escapeHtml(p.poolid)}">${escapeHtml(p.poolid)}${p.cluster ? ' (' + escapeHtml(p.cluster) + ')' : ''}</option>`))
        .join('');
    const tpl = `<div id="pxmx-clone-modal" class="fixed inset-0 z-[60] flex items-center justify-center bg-black/40">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-md p-5 space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold text-[#263040]">Clone template</h3>
                <button onclick="document.getElementById('pxmx-clone-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none" title="Close clone dialog">×</button>
            </div>
            <p class="text-xs text-slate-500">Cloning <span class="font-mono">${escapeHtml(vm.name || '')}</span> (VMID ${vm.vmid}, pool ${escapeHtml(vm.pool || '—')}). The new VM is tagged with the current tenant name and starts stopped.</p>
            <label class="block text-xs font-medium text-slate-600">New VM name
                <input id="pxmx-clone-name" value="${escapeHtml(baseName)}" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" title="Name for the newly cloned virtual machine" />
            </label>
            <label class="block text-xs font-medium text-slate-600">New VMID (optional — blank = auto-assign)
                <input id="pxmx-clone-vmid" placeholder="auto" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" title="Optional custom VMID (leave blank to auto-assign)" />
            </label>
            <label class="block text-xs font-medium text-slate-600">Destination pool (optional)
                <select id="pxmx-clone-pool" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Select target resource pool">${poolOpts}</select>
            </label>
            <div class="flex justify-end gap-2 pt-1">
                <button onclick="document.getElementById('pxmx-clone-modal').remove()" class="px-3 py-2 rounded-md text-sm font-medium text-slate-600 hover:bg-slate-100" title="Cancel cloning">Cancel</button>
                <button id="pxmx-clone-go" onclick="pxmxCloneVmSubmit('${escJs(vm.unique_id)}')" class="px-4 py-2 rounded-md text-sm font-bold bg-indigo-600 hover:bg-indigo-700 text-white" title="Clone template to new VM">⧉ Clone</button>
            </div>
            <p id="pxmx-clone-status" class="text-xs text-slate-400"></p>
        </div>
    </div>`;
    // Remove any stale modal first, then mount at the document root so it
    // survives the pxmx-content re-render that openVmDetail replaced.
    const existing = document.getElementById('pxmx-clone-modal');
    if (existing) existing.remove();
    document.body.insertAdjacentHTML('beforeend', tpl);
    const nameInput = document.getElementById('pxmx-clone-name');
    if (nameInput) { nameInput.focus(); nameInput.select(); }
}

async function pxmxCloneVmSubmit(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('Template not found in cache', 'error'); return; }
    const name = (document.getElementById('pxmx-clone-name') || {}).value || '';
    const vmidRaw = (document.getElementById('pxmx-clone-vmid') || {}).value || '';
    const pool = (document.getElementById('pxmx-clone-pool') || {}).value || '';
    const statusEl = document.getElementById('pxmx-clone-status');
    const goBtn = document.getElementById('pxmx-clone-go');
    const cleanName = name.trim();
    if (!cleanName) { if (statusEl) statusEl.textContent = 'Name is required'; return; }
    if (goBtn) { goBtn.disabled = true; goBtn.textContent = 'Cloning…'; }
    if (statusEl) statusEl.textContent = 'Cloning — a full-disk clone can take a minute…';
    const body = { template_unique_id: vm.unique_id, name: cleanName, type: vm.type || 'qemu' };
    const nvid = parseInt(vmidRaw, 10);
    if (vmidRaw.trim() && !isNaN(nvid)) body.new_vmid = nvid;
    if (pool) body.pool = pool;
    try {
        const r = await setupFetch('/api/pxmx/clone' + _tenantQS(), { method: 'POST', body: JSON.stringify(body) });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(`Cloned to VMID ${data.vmid} (${data.name})`, 'success');
            const modal = document.getElementById('pxmx-clone-modal');
            if (modal) modal.remove();
            setTimeout(() => loadPxmxData('Virtual Machines'), 1200);
        } else {
            const msg = data && (data.detail || data.message) || r.status;
            showToast(`Clone failed: ${msg}`, 'error');
            if (statusEl) statusEl.textContent = `Failed: ${msg}`;
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = '⧉ Clone'; }
        }
    } catch (e) {
        showToast(`Clone failed: ${e.message || e}`, 'error');
        if (statusEl) statusEl.textContent = `Failed: ${e.message || e}`;
        if (goBtn) { goBtn.disabled = false; goBtn.textContent = '⧉ Clone'; }
    }
}

// One-click spoke deploy (the "easy button"). Clones a *golden spoke template*
// (a VM whose agent was installed with `install_agent.sh --clone-only
// --onboarding-psk`, service staged+enabled but STOPPED, PSK carried over),
// auto-names the clone CS-SVR-0N (next free — the hub computes it), and STARTS
// it so it DHCPs, derives its spoke id from its own hostname, auto-discovers the
// hub, presents the carried PSK, and self-approves + tenant-binds. The operator
// can override the prefix/number and toggle auto-start. POSTs /api/pxmx/deploy-spoke.
async function pxmxDeploySpoke(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('Template not found in cache', 'error'); return; }
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const tpl = `<div id="pxmx-deploy-modal" class="fixed inset-0 z-[60] flex items-center justify-center bg-black/40">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-md p-5 space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold text-[#263040]">🚀 Deploy spoke</h3>
                <button onclick="document.getElementById('pxmx-deploy-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
            </div>
            <p class="text-xs text-slate-500">Cloning golden template <span class="font-mono">${escapeHtml(vm.name || '')}</span> (VMID ${vm.vmid}). The clone is named <span class="font-mono">&lt;prefix&gt;-0N</span>, tagged for the current tenant, and started — it then DHCPs and self-onboards under its own hostname (no IP to set, no agent to register).</p>
            <div class="grid grid-cols-2 gap-3">
                <label class="block text-xs font-medium text-slate-600">Name prefix
                    <input id="pxmx-deploy-prefix" value="CS-SVR" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" />
                </label>
                <label class="block text-xs font-medium text-slate-600">Number (blank = next free)
                    <input id="pxmx-deploy-number" placeholder="auto" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" />
                </label>
            </div>
            <label class="flex items-center gap-2 text-xs font-medium text-slate-600">
                <input id="pxmx-deploy-start" type="checkbox" checked class="w-4 h-4 rounded" /> Start the clone after deploy (self-onboard)
            </label>
            <div class="flex justify-end gap-2 pt-1">
                <button onclick="document.getElementById('pxmx-deploy-modal').remove()" class="px-3 py-2 rounded-md text-sm font-medium text-slate-600 hover:bg-slate-100">Cancel</button>
                <button id="pxmx-deploy-go" onclick="pxmxDeploySpokeSubmit('${escJs(vm.unique_id)}')" class="px-4 py-2 rounded-md text-sm font-bold bg-emerald-600 hover:bg-emerald-700 text-white">🚀 Deploy</button>
            </div>
            <p id="pxmx-deploy-status" class="text-xs text-slate-400"></p>
        </div>
    </div>`;
    const existing = document.getElementById('pxmx-deploy-modal');
    if (existing) existing.remove();
    document.body.insertAdjacentHTML('beforeend', tpl);
    const pfx = document.getElementById('pxmx-deploy-prefix');
    if (pfx) { pfx.focus(); pfx.select(); }
}

async function pxmxDeploySpokeSubmit(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('Template not found in cache', 'error'); return; }
    const prefix = ((document.getElementById('pxmx-deploy-prefix') || {}).value || 'CS-SVR').trim() || 'CS-SVR';
    const numberRaw = ((document.getElementById('pxmx-deploy-number') || {}).value || '').trim();
    const start = !!(document.getElementById('pxmx-deploy-start') || {}).checked;
    const statusEl = document.getElementById('pxmx-deploy-status');
    const goBtn = document.getElementById('pxmx-deploy-go');
    const body = { template_unique_id: vm.unique_id, type: vm.type || 'qemu', name_prefix: prefix, start };
    if (numberRaw) {
        const n = parseInt(numberRaw, 10);
        if (isNaN(n)) { if (statusEl) statusEl.textContent = 'Number must be an integer'; return; }
        body.number = n;
    }
    if (goBtn) { goBtn.disabled = true; goBtn.textContent = 'Deploying…'; }
    if (statusEl) statusEl.textContent = 'Cloning the golden template — a full-disk clone can take a minute…';
    try {
        const r = await setupFetch('/api/pxmx/deploy-spoke' + _tenantQS(), { method: 'POST', body: JSON.stringify(body) });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            const startedMsg = data.started ? 'started — it will self-onboard shortly'
                : (data.start_error ? `NOT started (${data.start_error}) — boot it manually` : 'left stopped');
            showToast(`Deployed ${data.deployed_name} (VMID ${data.vmid}, spoke ${data.spoke_id}) — ${startedMsg}`, data.started || !start ? 'success' : 'error');
            const modal = document.getElementById('pxmx-deploy-modal');
            if (modal) modal.remove();
            setTimeout(() => loadPxmxData('Virtual Machines'), 1200);
        } else {
            const msg = data && (data.detail || data.message) || r.status;
            showToast(`Deploy failed: ${msg}`, 'error');
            if (statusEl) statusEl.textContent = `Failed: ${msg}`;
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = '🚀 Deploy'; }
        }
    } catch (e) {
        showToast(`Deploy failed: ${e.message || e}`, 'error');
        if (statusEl) statusEl.textContent = `Failed: ${e.message || e}`;
        if (goBtn) { goBtn.disabled = false; goBtn.textContent = '🚀 Deploy'; }
    }
}


// new qemu VM that boots a Proxmox installer ISO. The user picks a node → the
// ISO list + disk-storage list for that node load (PXMX_LIST_ISOS /
// PXMX_LIST_STORAGES via /api/pxmx/isos + /api/pxmx/storages), then sets name,
// memory, cores, disk size, and an optional destination pool (from
// /api/pxmx/pools). On submit POST /api/pxmx/create-vm; the new VM is tagged
// with the tenant name (label) + proxmox_tag (VM-sync key) and left stopped —
// the user boots it and installs via the VNC console.
function pxmxOpenCreateVm() {
    const nodes = window._pxmxNodes || [];
    if (!nodes.length) { showToast('No Proxmox nodes available', 'error'); return; }
    const nodeOpts = nodes.map(n => `<option value="${escapeHtml(n.node)}">${escapeHtml(n.node)}${n.cluster ? ' (' + escapeHtml(n.cluster) + ')' : ''}</option>`).join('');
    const tpl = `<div id="pxmx-create-vm-modal" class="fixed inset-0 z-[60] flex items-center justify-center bg-black/40">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-lg p-5 space-y-3">
            <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold text-[#263040]">Build VM from ISO</h3>
                <button onclick="document.getElementById('pxmx-create-vm-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none" title="Close create VM dialog">×</button>
            </div>
            <p class="text-xs text-slate-500">Define a new qemu VM that boots an installer ISO. The VM is tagged with the current tenant name and starts stopped — boot it from the Console button, install, then Start.</p>
            <div class="grid grid-cols-2 gap-3">
                <label class="block text-xs font-medium text-slate-600">Node
                    <select id="pxmx-cv-node" onchange="pxmxLoadNodeMedia()" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Select hypervisor host node">${nodeOpts}</select>
                </label>
                <label class="block text-xs font-medium text-slate-600">VM name
                    <input id="pxmx-cv-name" value="new-vm" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" title="Virtual machine name" />
                </label>
                <label class="block text-xs font-medium text-slate-600 col-span-2">Installer ISO
                    <select id="pxmx-cv-iso" disabled class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Select installer ISO image"><option value="">Loading ISOs…</option></select>
                </label>
                <label class="block text-xs font-medium text-slate-600">Disk storage
                    <select id="pxmx-cv-storage" disabled class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Target storage pool for root disk"><option value="">Loading…</option></select>
                </label>
                <label class="block text-xs font-medium text-slate-600">Disk size (GB)
                    <input id="pxmx-cv-disk" type="number" min="1" value="32" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Root disk size in gigabytes" />
                </label>
                <label class="block text-xs font-medium text-slate-600">Memory (MB)
                    <input id="pxmx-cv-mem" type="number" min="128" value="2048" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Memory allocation in megabytes" />
                </label>
                <label class="block text-xs font-medium text-slate-600">CPU cores
                    <input id="pxmx-cv-cores" type="number" min="1" value="2" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Virtual CPU core count" />
                </label>
                <label class="block text-xs font-medium text-slate-600 col-span-2">Destination pool (optional)
                    <select id="pxmx-cv-pool" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" title="Optional resource pool assignment"><option value="">— no pool —</option></select>
                </label>
            </div>
            <div class="flex justify-end gap-2 pt-1">
                <button onclick="document.getElementById('pxmx-create-vm-modal').remove()" class="px-3 py-2 rounded-md text-sm font-medium text-slate-600 hover:bg-slate-100" title="Cancel VM creation">Cancel</button>
                <button id="pxmx-cv-go" onclick="pxmxCreateVmSubmit()" class="px-4 py-2 rounded-md text-sm font-bold bg-indigo-600 hover:bg-indigo-700 text-white" title="Provision new virtual machine">＋ Create VM</button>
            </div>
            <p id="pxmx-cv-status" class="text-xs text-slate-400"></p>
        </div>
    </div>`;
    const existing = document.getElementById('pxmx-create-vm-modal');
    if (existing) existing.remove();
    document.body.insertAdjacentHTML('beforeend', tpl);
    // Load ISOs + storages for the preselected node, and the pool list.
    pxmxLoadNodeMedia();
    pxmxLoadCreatePools();
}

async function pxmxLoadNodeMedia() {
    const nodeSel = document.getElementById('pxmx-cv-node');
    const isoSel = document.getElementById('pxmx-cv-iso');
    const stSel = document.getElementById('pxmx-cv-storage');
    if (!nodeSel) return;
    const node = nodeSel.value;
    if (isoSel) { isoSel.disabled = true; isoSel.innerHTML = '<option value="">Loading ISOs…</option>'; }
    if (stSel) { stSel.disabled = true; stSel.innerHTML = '<option value="">Loading…</option>'; }
    try {
        const [isoR, stR] = await Promise.all([
            fetch(`/api/pxmx/isos?node=${encodeURIComponent(node)}`),
            fetch(`/api/pxmx/storages?node=${encodeURIComponent(node)}&content=images`),
        ]);
        const isoD = isoR.ok ? await isoR.json() : {};
        const stD = stR.ok ? await stR.json() : {};
        const isos = isoD.isos || [];
        const storages = stD.storages || [];
        if (isoSel) {
            isoSel.innerHTML = isos.length
                ? isos.map(i => `<option value="${escapeHtml(i.volid)}">${escapeHtml(i.name || i.volid)}</option>`).join('')
                : '<option value="">— no ISOs on this node —</option>';
            isoSel.disabled = isos.length === 0;
        }
        if (stSel) {
            stSel.innerHTML = storages.length
                ? storages.map(s => `<option value="${escapeHtml(s.storage)}">${escapeHtml(s.storage)} (${Math.round((s.avail || 0) / 1e9)} GB free)</option>`).join('')
                : '<option value="">— no image storage —</option>';
            stSel.disabled = storages.length === 0;
        }
    } catch (e) {
        if (isoSel) { isoSel.innerHTML = '<option value="">Failed to load ISOs</option>'; }
        if (stSel) { stSel.innerHTML = '<option value="">Failed to load storages</option>'; }
    }
}

async function pxmxLoadCreatePools() {
    const poolSel = document.getElementById('pxmx-cv-pool');
    if (!poolSel) return;
    try {
        const r = await fetch('/api/pxmx/pools');
        const d = r.ok ? await r.json() : {};
        const pools = d.pools || [];
        poolSel.innerHTML = '<option value="">— no pool —</option>'
            + pools.map(p => `<option value="${escapeHtml(p.poolid)}">${escapeHtml(p.poolid)}${p.cluster ? ' (' + escapeHtml(p.cluster) + ')' : ''}</option>`).join('');
    } catch (e) { /* leave default */ }
}

async function pxmxCreateVmSubmit() {
    const get = id => (document.getElementById(id) || {}).value || '';
    const body = {
        node: get('pxmx-cv-node'),
        name: get('pxmx-cv-name').trim(),
        volid: get('pxmx-cv-iso'),
        disk_storage: get('pxmx-cv-storage'),
        disk_gb: parseInt(get('pxmx-cv-disk'), 10) || 32,
        memory_mb: parseInt(get('pxmx-cv-mem'), 10) || 2048,
        cores: parseInt(get('pxmx-cv-cores'), 10) || 2,
        pool: get('pxmx-cv-pool'),
    };
    const statusEl = document.getElementById('pxmx-cv-status');
    const goBtn = document.getElementById('pxmx-cv-go');
    if (!body.name) { if (statusEl) statusEl.textContent = 'Name is required'; return; }
    if (!body.volid) { if (statusEl) statusEl.textContent = 'Pick an ISO'; return; }
    if (!body.disk_storage) { if (statusEl) statusEl.textContent = 'Pick a disk storage'; return; }
    if (goBtn) { goBtn.disabled = true; goBtn.textContent = 'Creating…'; }
    if (statusEl) statusEl.textContent = 'Creating VM (defines + tags)…';
    try {
        const r = await setupFetch('/api/pxmx/create-vm' + _tenantQS(), { method: 'POST', body: JSON.stringify(body) });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(`Created VMID ${data.vmid} (${data.name}) — boot it from Console to install`, 'success');
            const modal = document.getElementById('pxmx-create-vm-modal');
            if (modal) modal.remove();
            setTimeout(() => loadPxmxData('Virtual Machines'), 1200);
        } else {
            const msg = data && (data.detail || data.message) || r.status;
            showToast(`Create failed: ${msg}`, 'error');
            if (statusEl) statusEl.textContent = `Failed: ${msg}`;
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = '＋ Create VM'; }
        }
    } catch (e) {
        showToast(`Create failed: ${e.message || e}`, 'error');
        if (statusEl) statusEl.textContent = `Failed: ${e.message || e}`;
        if (goBtn) { goBtn.disabled = false; goBtn.textContent = '＋ Create VM'; }
    }
}

// ── Console module (serial console access) ─────────────────────────────────
// Lists every connected Console spoke's serial ports and opens an xterm.js
// terminal wired to the hub's /ws/console-serial/{session_id} byte relay. xterm
// is dynamic-imported from CDN once (mirrors how noVNC is loaded below).
let _consolePorts = [];
let _consoleSpokes = [];
let _consoleDpaSpokes = [];
let _xtermMod = null;

async function loadConsoleData() {
    const el = document.getElementById('console-container');
    if (!el) return;
    try {
        const res = await fetch(`/api/console/ports?tenant=${encodeURIComponent(currentTenant || 'default')}`, { credentials: 'same-origin' });
        if (!res.ok) {
            el.innerHTML = `<div class="py-12 text-center text-red-400 italic">${res.status === 403 ? 'Console module access required.' : 'Failed to load console ports (' + res.status + ').'}</div>`;
            return;
        }
        const data = await res.json();
        _consolePorts = data.ports || [];
        _consoleSpokes = data.consoles || [];
        _consoleDpaSpokes = data.dpa_consoles || [];
        _renderConsolePorts(el, data);
    } catch (e) {
        el.innerHTML = `<div class="py-12 text-center text-red-400 italic">Error: ${escapeHtml(e.message)}</div>`;
    }
}

// Direct Port Access endpoint for a console row: the ssh command to reach this
// serial line straight on the console server (click to copy), plus the telnet
// endpoint when that transport is on. Hidden when DPA is off for the agent.
function _consoleDpaSshCmd(p) {
    const d = p.dpa || {};
    if (!d.ssh_port) return '';
    return `ssh -p ${d.ssh_port} ${d.host || '<console-server>'}`;
}

function _consoleDpaBadge(p) {
    const d = p.dpa;
    if (!d || (!d.ssh_port && !d.telnet_port)) return '';
    const pin = '<span title="Port pinned by an operator override">📌</span>';
    const parts = [];
    if (d.ssh_port) {
        const cmd = _consoleDpaSshCmd(p);
        parts.push(`<button type="button" onclick="_consoleCopyDpa(this)" data-cmd="${escapeHtml(cmd)}" class="font-mono px-1.5 py-0.5 rounded bg-sky-50 text-sky-700 border border-sky-200 hover:bg-sky-100" title="Direct Port Access over SSH — host ${escapeHtml(String(d.host || '?'))}, port ${escapeHtml(String(d.ssh_port))}. Click to copy.">🔐 DPA ${escapeHtml(String(d.host || '?'))}:${escapeHtml(String(d.ssh_port))}${d.ssh_override ? ' ' + pin : ''}</button>`);
    }
    if (d.telnet_port) {
        const tb = String(d.bind || '127.0.0.1');
        const th = (tb === '0.0.0.0' || tb === '::') ? (d.host || tb) : tb;
        parts.push(`<span class="font-mono px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200" title="Direct Port Access over telnet (unauthenticated, unencrypted; bound to ${escapeHtml(tb)})">🔌 telnet ${escapeHtml(String(th))}:${escapeHtml(String(d.telnet_port))}${d.telnet_override ? ' ' + pin : ''}</span>`);
    }
    return `<div class="text-[11px] mt-0.5 space-x-1">${parts.join(' ')}</div>`;
}

async function _consoleCopyDpa(btn) {
    const cmd = btn.getAttribute('data-cmd') || '';
    try {
        await navigator.clipboard.writeText(cmd);
        showToast(`Copied: ${cmd}`, 'success');
    } catch (e) {
        showToast(cmd, 'info');
    }
}

function _renderConsolePorts(el, data) {
    const ports = data.ports || [];
    const consoles = data.consoles || [];
    const admin = isAdmin();
    if (consoles.length === 0) {
        el.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No Console agents connected. Load the <b>Console</b> role on an agent (Setup → Spokes &amp; Agents → Load Role).</div>`;
        return;
    }
    if (ports.length === 0) {
        el.innerHTML = `<div class="py-12 text-center text-slate-400 italic">${consoles.length} Console agent(s) connected, but no serial ports detected.</div>`;
        return;
    }
    const esc = s => (s || '').replace(/'/g, "\\'");
    const rows = ports.map(p => {
        const identHost = (p.probe && p.probe.identity && p.probe.identity.hostname) || '';
        const label = p.alias || identHost || p.product || p.device;
        const baud = (p.settings && p.settings.baud) || '—';
        const inUse = p.in_use ? ` <span class="text-[10px] px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 font-bold uppercase">In use</span>` : '';
        const staleBadge = p.stale ? ` <span title="Console agent offline — showing last-known data (names/settings restored from cache). Live status resumes when the agent reconnects." class="text-[10px] px-2 py-0.5 rounded-full bg-slate-200 text-slate-600 font-bold uppercase">offline</span>` : '';
        const disconnectedBadge = (p.present === false && !p.stale) ? ` <span title="Device not connected right now (adapter unplugged or target powered off). Its saved name is retained; the port reappears live when it reconnects." class="text-[10px] px-2 py-0.5 rounded-full bg-slate-200 text-slate-500 font-bold uppercase">disconnected</span>` : '';
        const unreachable = (p.present === false || p.stale);
        const monDot = (p.monitoring && !p.in_use)
            ? ` <span title="Passively monitoring — capturing console output while idle" class="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-bold uppercase">● monitoring</span>` : '';
        const bootBadge = _consoleBootBadge(p.boot);
        const stackBadge = _consoleStackBadge(p);
        const agentName = p.agent_name || p.spoke_id || '';
        const tenantId = p.tenant_id || 'unassigned';
        const eP = esc(p.port_id), eS = esc(p.spoke_id || ''), eT = esc(p.tenant_override || '');
        const tenantBtn = admin ? `<button onclick="openConsolePortTenantModal('${eS}','${eP}','${eT}')" class="text-[11px] px-2 py-1 rounded border border-[#01A982] text-[#01A982] hover:bg-slate-50">Tenant</button>` : '';
        const configBtn = hasConsoleWrite() ? `<button onclick="openConsoleConfigModal('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-indigo-400 text-indigo-600 hover:bg-slate-50">Config</button>` : '';
        const profileBtn = hasConsoleView() ? `<button onclick="profileDevice('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-violet-400 text-violet-600 hover:bg-slate-50" title="Profile this device: use the known fingerprint if we have one, otherwise ask the AI to identify it from its (scrubbed) console output">🔎 Profile Device</button>` : '';
        const captureBtn = (p.capture_bytes || p.monitoring || (p.probe && p.probe.banner))
            ? `<button onclick="openConsoleCaptureModal('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50" title="View recent console output captured from this port">Capture</button>` : '';
        const dpaBadge = _consoleDpaBadge(p);
        return `<tr class="hover:bg-slate-50">
            <td class="px-4 py-3"><div class="font-semibold text-slate-700">${escapeHtml(label)}${inUse}${staleBadge}${disconnectedBadge}${monDot}${bootBadge}${stackBadge}</div>
              <div class="text-xs font-mono text-slate-400" title="${escapeHtml(p.spoke_id || '')}">${escapeHtml(tenantId)}:${escapeHtml(agentName)}:${escapeHtml(p.device)}:${escapeHtml(String(baud))}</div>
              ${dpaBadge}
              ${_consoleStackLine(p)}
              ${_consoleIdentityBlock(p)}</td>
            <td class="px-4 py-3 text-right whitespace-nowrap space-x-1">
              ${unreachable
                ? `<button disabled title="Device not connected — reconnect it to open a session" class="text-[11px] px-2 py-1 rounded bg-slate-100 text-slate-400 border border-slate-200 font-bold cursor-not-allowed">🖥 Open</button>`
                : `<button onclick="openConsoleTerminal('${eS}','${eP}','${esc(label)}')" class="text-[11px] px-2 py-1 rounded bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] font-bold">🖥 Open</button>`}
              ${profileBtn}
              ${captureBtn}
              <button onclick="openConsoleSettingsModal('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50">Settings</button>
              ${configBtn}
              ${tenantBtn}
            </td></tr>`;
    }).join('');
    const profileAllBtn = hasConsoleView()
        ? `<button onclick="profileAllDevices()" class="text-[11px] px-3 py-1.5 rounded border border-violet-400 text-violet-600 hover:bg-slate-50" title="Profile every listed device at once: known fingerprints are used as-is; unknown devices are sent (scrubbed) to the AI to identify. Ports open in a session are skipped.">🔎 Profile All Devices</button>`
        : '';
    const diagBtn = hasConsoleView()
        ? `<button onclick="openConsoleDiagnosticsModal()" class="text-[11px] px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50" title="Serial connections that keep failing or disconnecting">🩺 Diagnostics</button>`
        : '';
    const dpaBtn = admin
        ? `<button onclick="openConsoleDpaModal()" class="text-[11px] px-3 py-1.5 rounded border border-sky-400 text-sky-700 hover:bg-slate-50" title="Direct Port Access: SSH (or telnet) straight to a serial port on the console server">🔌 Direct Port Access</button>`
        : '';
    const adminTools = diagBtn + dpaBtn + ((admin || isTenantAdmin())
        ? `<button onclick="openConsoleCredentialsModal()" class="text-[11px] px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50">🔑 Credentials</button>`
        : '');
    const tools = (profileAllBtn || adminTools)
        ? `<div class="flex justify-end gap-2 p-2 border-b border-slate-100">${profileAllBtn}${adminTools}</div>`
        : '';
    el.innerHTML = `${tools}<div class="p-0 overflow-hidden"><table class="w-full text-left text-sm">
        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>
          <th class="px-4 py-3">Device</th>
          <th class="px-4 py-3 text-right">Actions</th></tr></thead>
        <tbody class="divide-y divide-slate-200">${rows}</tbody></table></div>`;
}

// Profile a single device (admin): use the built-in/learned fingerprint if we
// already have one; only fall back to the AI (on scrubbed console output) when
// the device is unrecognized. Passive capture continues regardless — this is the
// explicit, on-demand profiling action.
async function profileDevice(spokeId, portId) {
    showToast('🔎 Profiling device (fingerprint first, AI only if unknown)…', 'info');
    try {
        const res = await fetch('/api/console/identify-llm', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId }),
        });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(d.detail || 'Profiling failed', 'error'); return; }
        if (d.identified && d.vendor) {
            const bits = [d.vendor, (d.identity || {}).type, (d.identity || {}).model, (d.identity || {}).serial].filter(Boolean).join(' · ');
            const via = d.source === 'fingerprint' ? ' (known fingerprint)' : (d.learned ? ' (learned)' : ' (AI)');
            showToast(`🔎 Profiled: ${bits}${via}`, 'success');
            loadConsoleData();
        } else {
            showToast(d.status === 'ERROR' ? (d.message || 'Profiling error') : '🔎 Could not profile this device yet', 'info');
        }
    } catch (e) { showToast('Profiling failed: ' + e.message, 'error'); }
}

// Profile every listed device at once (admin). Known fingerprints resolve without
// the AI; only unknown devices are sent (scrubbed) to the AI. Runs in the
// background; ports open in a session are skipped.
async function profileAllDevices() {
    const n = (_consolePorts || []).filter(p => !p.in_use).length;
    if (!n) { showToast('No idle ports to profile.', 'info'); return; }
    showToast(`🔎 Profiling ${n} device(s) — this runs in the background…`, 'info');
    try {
        const res = await fetch(`/api/console/identify-llm-all?tenant=${encodeURIComponent(currentTenant || 'default')}`, {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}',
        });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(d.detail || 'Bulk profiling failed', 'error'); return; }
        const skipped = d.skipped_in_use ? `, ${d.skipped_in_use} in-use skipped` : '';
        showToast(`🔎 Queued ${d.queued || 0} device(s)${skipped}. Results will populate as they finish.`, 'success');
        setTimeout(loadConsoleData, 8000);  // pull in early results
    } catch (e) { showToast('Bulk profiling failed: ' + e.message, 'error'); }
}

// Relative "last seen" string from an epoch-seconds timestamp (0/absent → '').
function _consoleRelTime(ts) {
    if (!ts) return '';
    const secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (secs < 60) return secs + 's ago';
    if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
    if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
    return Math.floor(secs / 86400) + 'd ago';
}

// The identity line under a port. Placeholder until anything is scraped; once the
// system gleans (passively) or verifies (active login) device info, it replaces
// the placeholder. A badge marks how the info was obtained + when last seen.
// VSF stack indicators. A stack is one logical switch spread over several
// chassis, but each chassis has its own serial line — without these badges an
// operator can't tell which cable actually reaches the conductor (the only
// member that accepts configuration), and a standby member just looks like an
// unidentifiable box called "standby".
function _consoleStackBadge(p) {
    const st = (p.probe && p.probe.stack) || null;
    if (!st || !st.is_stack) return '';
    const mbr = st.member_id ? ` ${st.member_id}` : '';
    if (st.role === 'conductor') {
        return ` <span title="VSF stack conductor — this console line configures the whole stack" class="text-[10px] px-2 py-0.5 rounded-full bg-[#01A982]/15 text-[#01A982] font-bold uppercase">\u2b22 conductor${mbr}</span>`;
    }
    if (st.role === 'standby') {
        return ` <span title="VSF stack standby member — it will take over if the conductor fails. Most commands are rejected here; configure the stack from the conductor." class="text-[10px] px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 font-bold uppercase">\u2b22 standby${mbr}</span>`;
    }
    return ` <span title="VSF stack member — configure the stack from its conductor" class="text-[10px] px-2 py-0.5 rounded-full bg-slate-200 text-slate-600 font-bold uppercase">\u2b22 member${mbr}</span>`;
}

// Second line of stack detail: image version, topology, and a jump to the
// conductor's own console port when the hub managed to correlate it.
function _consoleStackLine(p) {
    const st = (p.probe && p.probe.stack) || null;
    if (!st || !st.is_stack) return '';
    const bits = [];
    const total = (st.members || []).filter(m => m.present).length;
    if (total) bits.push(`${total} member${total === 1 ? '' : 's'}`);
    if (st.topology) bits.push(escapeHtml(String(st.topology)));
    if (st.sw_version) bits.push(`image ${escapeHtml(String(st.sw_version))}`);
    let link = '';
    if (!st.is_conductor && st.conductor_port_id) {
        const name = st.conductor_hostname || 'conductor';
        link = ` &middot; <a href="#" onclick="focusConsolePort('${(st.conductor_spoke_id || '').replace(/'/g, "\\'")}','${(st.conductor_port_id || '').replace(/'/g, "\\'")}');return false;" class="text-[#01A982] hover:underline" title="Open the console port of this stack's conductor">conductor: ${escapeHtml(String(name))}</a>`;
    } else if (!st.is_conductor && st.conductor_mac) {
        link = ` &middot; <span title="This stack's conductor MAC is ${escapeHtml(String(st.conductor_mac))} but no console port has identified it yet">conductor not on console</span>`;
    }
    return `<div class="text-[11px] text-slate-400 mt-0.5">\u2b22 VSF ${bits.join(' \u00b7 ')}${link}</div>`;
}

// Jump to another port's row (used by the stack "conductor:" link) — scroll it
// into view and flash it rather than opening a session the operator didn't ask for.
function focusConsolePort(spokeId, portId) {
    const rows = document.querySelectorAll('#console-ports-body tr, table tr');
    const target = (_consolePorts || []).find(p => p.port_id === portId && (!spokeId || p.spoke_id === spokeId));
    if (!target) { showToast('That console port is not in the current list.', 'warn'); return; }
    const label = target.alias || ((target.probe && target.probe.identity && target.probe.identity.hostname) || target.device);
    showToast(`Conductor is on ${label} (${target.device})`, 'info');
}

function _consoleBootBadge(boot) {
    if (!boot || !boot.state || boot.state === 'idle') return '';
    const relock = boot.relocked ? ' 🔒baud' : '';
    if (boot.state === 'booting') {
        return ` <span title="A boot/wake cycle is being captured${relock ? ' (re-locking baud)' : ''}" class="text-[10px] px-2 py-0.5 rounded-full bg-sky-100 text-sky-700 font-bold uppercase">⟳ booting${relock}</span>`;
    }
    if (boot.state === 'booted') {
        return ` <span title="Captured a boot cycle and reached a prompt" class="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-bold uppercase">✓ booted</span>`;
    }
    if (boot.state === 'stuck') {
        const why = boot.stuck_reason ? ` — ${escapeHtml(String(boot.stuck_reason)).slice(0, 80)}` : '';
        return ` <span title="Boot appears stuck / failed${why}. Likely a hardware or boot problem — check the console capture." class="text-[10px] px-2 py-0.5 rounded-full bg-red-100 text-red-700 font-bold uppercase">⚠ boot stuck</span>`;
    }
    return '';
}

function _consoleIdentityBlock(p) {
    const probe = p.probe || {};
    const ident = probe.identity || {};
    const summary = _consoleIdentitySummary(ident);
    const seen = p.last_activity
        ? `<span class="text-[10px] text-slate-400" title="Last console output seen">· 👂 ${_consoleRelTime(p.last_activity)}</span>` : '';
    if (probe.vendor || summary) {
        const src = probe.stale
            ? '<span class="text-[9px] px-1 py-0.5 rounded bg-amber-100 text-amber-700 font-bold uppercase" title="Last-known profile — the latest identify attempt did not re-confirm it; still retrying">last known</span>'
            : probe.source === 'active'
            ? '<span class="text-[9px] px-1 py-0.5 rounded bg-green-100 text-green-700 font-bold uppercase" title="Verified via read-only login">verified</span>'
            : (probe.source === 'passive'
                ? '<span class="text-[9px] px-1 py-0.5 rounded bg-slate-100 text-slate-500 font-bold uppercase" title="Observed passively from console output (no login)">observed</span>' : '');
        const vpill = probe.vendor
            ? `<span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 font-bold uppercase text-[9px]">${escapeHtml(probe.vendor)}</span> ` : '';
        return `<div class="text-xs mt-0.5 flex items-center gap-1.5 flex-wrap">${vpill}${summary}${src}${seen}</div>`;
    }
    // Nothing gleaned yet. An active-source probe with no identity means we tried
    // logging in with the stored credentials but the device hasn't revealed
    // anything usable yet — say so instead of pretending we're only listening.
    if (probe.source === 'active') {
        const why = probe.logged_in
            ? 'logged in, nothing identifiable yet'
            : (probe.error ? escapeHtml(String(probe.error).slice(0, 80)) : 'no response to stored logins yet');
        return `<div class="text-xs mt-0.5 text-slate-400 italic" title="Tried the stored credentials">🔑 Login attempted — ${why} ${seen}</div>`;
    }
    if (p.monitoring) {
        return `<div class="text-xs mt-0.5 text-slate-400 italic" title="Passively capturing and periodically trying the stored logins">🎧 Listening &amp; trying stored logins — nothing yet ${seen}</div>`;
    }
    return `<div class="text-xs mt-0.5 text-slate-300 italic">not yet identified</div>`;
}

function _consoleIdentitySummary(identity) {
    if (!identity) return '';
    const typePill = identity.type
        ? `<span class="px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-700 font-bold uppercase text-[9px]" title="Device role">${escapeHtml(identity.type)}</span> `
        : '';
    const parts = [];
    if (identity.model) parts.push(`<span class="font-semibold text-slate-700">${escapeHtml(identity.model)}</span>`);
    if (identity.os) parts.push(escapeHtml(identity.os));
    if (identity.serial) parts.push('SN ' + escapeHtml(identity.serial));
    if (identity.mac) parts.push(escapeHtml(identity.mac));
    if (identity.ip) parts.push(escapeHtml(identity.ip));
    const body = parts.length ? `<span class="text-slate-500">${parts.join(' · ')}</span>` : '';
    return (typePill || body) ? `${typePill}${body}` : '';
}

// Show the recent console capture (whatever the device emitted while idle) —
// the passive monitor keeps this filled even with no user connected.
async function openConsoleCaptureModal(spokeId, portId) {
    let d = {};
    try {
        const res = await fetch('/api/console/capture', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId }),
        });
        d = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(d.detail || 'Capture unavailable', 'error'); return; }
    } catch (e) { showToast('Capture failed: ' + e.message, 'error'); return; }
    const text = (d.capture || '').trim() || '(no console output captured yet)';
    const meta = `${d.monitoring ? '🎧 monitoring · ' : ''}${d.last_activity ? 'last output ' + _consoleRelTime(d.last_activity) : 'no activity'} · ${d.capture_bytes || 0} bytes seen`;
    const old = document.getElementById('console-capture-modal');
    if (old) old.remove();
    const modal = document.createElement('div');
    modal.id = 'console-capture-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-60 backdrop-blur-sm';
    modal.innerHTML = `<div class="bg-[#1e1e1e] rounded-xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col" style="height:70vh">
        <div class="px-4 py-2 flex justify-between items-center bg-[#2d2d2d] text-slate-200">
          <div class="text-sm font-mono">${escapeHtml(portId)} <span class="text-[10px] text-slate-400">${escapeHtml(meta)}</span></div>
          <button onclick="document.getElementById('console-capture-modal').remove()" class="text-slate-300 hover:text-white text-2xl leading-none">&times;</button>
        </div>
        <pre class="flex-1 m-0 p-3 overflow-auto text-xs text-slate-100 font-mono whitespace-pre-wrap">${escapeHtml(text)}</pre>
        <div class="px-4 py-2 bg-[#2d2d2d] text-right"><button class="js-capture-refresh text-[11px] px-3 py-1.5 rounded border border-slate-500 text-slate-200 hover:bg-slate-700">↻ Refresh</button></div>
      </div>`;
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
    _mountModal(modal);
    modal.querySelector('.js-capture-refresh').setAttribute(
        'onclick', `openConsoleCaptureModal('${escJsAttr(spokeId)}','${escJsAttr(portId)}')`);
}

async function openConsoleDiagnosticsModal() {
    const modal = document.createElement('div');
    modal.id = 'console-diag-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">🩺 Serial Connection Diagnostics</h3>
          <button onclick="this.closest('#console-diag-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div id="console-diag-body" class="p-6 overflow-auto text-sm text-slate-500">Loading…</div></div>`;
    document.body.appendChild(modal);
    await refreshConsoleDiagnostics();
}

async function refreshConsoleDiagnostics() {
    const body = document.getElementById('console-diag-body');
    if (!body) return;
    let data = { diagnostics: [], errors: {} };
    try {
        const res = await fetch(`/api/console/diagnostics?tenant=${encodeURIComponent(currentTenant || 'default')}`, { credentials: 'same-origin' });
        if (res.ok) data = await res.json();
        else { body.innerHTML = `<div class="text-red-500">Failed to load (${res.status})</div>`; return; }
    } catch (e) { body.innerHTML = `<div class="text-red-500">${escapeHtml(e.message)}</div>`; return; }
    window._consoleDiagLast = { ...data, _fetched_at: new Date().toISOString() };
    const rows = data.diagnostics || [];
    const errs = Object.entries(data.errors || {});
    const summaryBanner = _consoleDiagSummaryBanner(data.summaries || {});
    const debugBanner = _consoleDiagDebugBanner(data.debug);
    if (!rows.length && !errs.length) {
        body.innerHTML = `${summaryBanner}${debugBanner}<div class="text-emerald-600 flex items-center gap-2">✅ No failing or disconnecting serial connections.</div>
          <div class="pt-4 flex justify-end gap-2">${_consoleDiagFooterBtns()}</div>`;
        return;
    }
    const statusPill = (d) => {
        if (!d.present) return '<span class="px-2 py-0.5 rounded-full bg-slate-200 text-slate-600 text-[10px] font-bold uppercase">gone</span>';
        if (d.currently_failing) return '<span class="px-2 py-0.5 rounded-full bg-red-100 text-red-700 text-[10px] font-bold uppercase">failing</span>';
        if (d.recoveries > 1) return '<span class="px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 text-[10px] font-bold uppercase">flapping</span>';
        return '<span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 text-[10px] font-bold uppercase">recovered</span>';
    };
    const failRows = rows.filter(d => d.open_failures || d.disconnects || d.currently_failing);
    const identRows = rows.filter(d => (d.identify && d.identify.attempts) || (d.present && d.schedule));
    const bootRows = rows.filter(d => d.boot && d.boot.state && d.boot.state !== 'idle');
    const failTbl = failRows.length ? `<div class="text-[11px] font-bold text-slate-500 uppercase mb-1">Serial connection failures</div><table class="w-full text-left mb-5">
        <thead class="text-slate-500 uppercase text-[10px] border-b border-slate-200"><tr>
          <th class="py-2 pr-3">Port</th><th class="py-2 pr-3">Agent</th><th class="py-2 pr-3">Status</th>
          <th class="py-2 pr-3 text-center">Open fails</th><th class="py-2 pr-3 text-center">Disconnects</th>
          <th class="py-2 pr-3 text-center">Recoveries</th><th class="py-2 pr-3">Last error</th><th class="py-2 pr-3">Last event</th>
        </tr></thead><tbody>${failRows.map(d => `<tr class="border-b border-slate-50">
          <td class="py-2 pr-3 font-mono text-xs">${escapeHtml(d.alias || d.device || d.port_id)}</td>
          <td class="py-2 pr-3 text-xs">${escapeHtml(d.agent_name || d.spoke_id || '')}</td>
          <td class="py-2 pr-3">${statusPill(d)}</td>
          <td class="py-2 pr-3 text-center">${d.open_failures || 0}</td>
          <td class="py-2 pr-3 text-center">${d.disconnects || 0}</td>
          <td class="py-2 pr-3 text-center">${d.recoveries || 0}</td>
          <td class="py-2 pr-3 text-xs text-red-500 max-w-[16rem] truncate" title="${escapeHtml(d.last_error || '')}">${escapeHtml(d.last_error || '')}</td>
          <td class="py-2 pr-3 text-xs text-slate-400">${_consoleRelTime(Math.max(d.last_failure || 0, d.last_disconnect || 0, d.last_recovery || 0))}</td>
        </tr>`).join('')}</tbody></table>` : '';
    const identTbl = identRows.length ? `<div class="text-[11px] font-bold text-slate-500 uppercase mb-1">Identify / login telemetry</div><table class="w-full text-left">
        <thead class="text-slate-500 uppercase text-[10px] border-b border-slate-200"><tr>
          <th class="py-2 pr-3">Port</th><th class="py-2 pr-3">Via</th><th class="py-2 pr-3">Outcome</th>
          <th class="py-2 pr-3" title="Identified hostname, its source, and whether it is stable or flapping">Hostname</th>
          <th class="py-2 pr-2 text-center" title="Login / Password / Shell prompt detected">L·P·S</th>
          <th class="py-2 pr-2 text-center" title="credentials tried / available">Creds</th>
          <th class="py-2 pr-2 text-center">Bytes</th><th class="py-2 pr-3">Why</th><th class="py-2 pr-3">Last</th>
        </tr></thead><tbody>${identRows.map(d => _consoleIdentDiagRow(d)).join('')}</tbody></table>
        <div class="mt-2 text-[10px] text-slate-400">Tip: click a row's “Why” to see the last raw line the device emitted (control chars stripped). A <b>flapping</b> hostname changes across probes — hover it for the distinct values, their source (command output vs CLI prompt vs AI) and when each was seen. A port with <b>no attempt yet</b> shows why it isn't being logged into and when the next try is due.</div>` : '';
    const bootStatePill = (b) => {
        if (b.state === 'stuck') return '<span class="px-2 py-0.5 rounded-full bg-red-100 text-red-700 text-[10px] font-bold uppercase">stuck</span>';
        if (b.state === 'booting') return '<span class="px-2 py-0.5 rounded-full bg-sky-100 text-sky-700 text-[10px] font-bold uppercase">booting</span>';
        if (b.state === 'booted') return '<span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 text-[10px] font-bold uppercase">booted</span>';
        return escapeHtml(b.state || '');
    };
    const bootTbl = bootRows.length ? `<div class="text-[11px] font-bold text-slate-500 uppercase mb-1 mt-5">Boot / wake capture</div><table class="w-full text-left mb-2">
        <thead class="text-slate-500 uppercase text-[10px] border-b border-slate-200"><tr>
          <th class="py-2 pr-3">Port</th><th class="py-2 pr-3">State</th>
          <th class="py-2 pr-3 text-center" title="Reached a login/shell prompt">Prompt</th>
          <th class="py-2 pr-3 text-center" title="Age of this boot episode">Age</th>
          <th class="py-2 pr-3">Why</th><th class="py-2 pr-3">Last output</th>
        </tr></thead><tbody>${bootRows.map(d => { const b = d.boot; return `<tr class="border-b border-slate-50">
          <td class="py-2 pr-3 font-mono text-xs">${escapeHtml(d.alias || d.device || d.port_id)}</td>
          <td class="py-2 pr-3">${bootStatePill(b)}${b.relocked ? ' <span class="text-[9px] text-slate-400" title="Baud re-locked during this boot">🔒baud</span>' : ''}</td>
          <td class="py-2 pr-3 text-center">${b.prompt_seen ? '✅' : '—'}</td>
          <td class="py-2 pr-3 text-center text-xs text-slate-500">${b.age_s || 0}s</td>
          <td class="py-2 pr-3 text-xs ${b.state === 'stuck' ? 'text-red-600' : 'text-slate-500'} max-w-[20rem] truncate" title="${escapeHtml((b.reason || '') + (b.stuck_reason ? ' — ' + b.stuck_reason : '') + (b.transcript_tail ? '\n\n' + b.transcript_tail : ''))}">${escapeHtml(b.stuck_reason || b.reason || '')}</td>
          <td class="py-2 pr-3 text-xs text-slate-400">${b.since_output_s || 0}s ago</td>
        </tr>`; }).join('')}</tbody></table>
        <div class="mb-3 text-[10px] text-slate-400">A device that just powered on is watched until it reaches a prompt (<b>booted</b>) or its boot stalls / faults (<b>stuck</b> — likely a hardware or boot problem). Hover “Why” to see the captured boot transcript.</div>` : '';
    const errHtml = errs.length
        ? `<div class="mt-3 text-[11px] text-amber-600">Unreachable consoles: ${errs.map(([s, e]) => escapeHtml(s)).join(', ')}</div>` : '';
    body.innerHTML = `${summaryBanner}${debugBanner}<div class="text-[11px] text-slate-400 mb-2">${failRows.length} port(s) with a failure/disconnect history · ${identRows.length} with identify attempts or pending (since each agent started).</div>${failTbl}${identTbl}${bootTbl}${errHtml}
      <div class="pt-4 flex justify-end gap-2">${_consoleDiagFooterBtns()}</div>`;
}

// Spoke-level banner explaining the whole-agent reasons a console might not be
// logging in at all: auto-identify disabled, or zero operator credentials (only
// the factory-default set is tried). Green when every agent is set up to log in.
function _consoleDiagSummaryBanner(summaries) {
    const entries = Object.entries(summaries || {});
    if (!entries.length) return '';
    const warns = [];
    for (const [sid, s] of entries) {
        const who = escapeHtml(s.agent_name || sid);
        if (!s.auto_identify)
            warns.push(`<div class="text-red-700">⛔ <b>${who}</b>: auto-identify is <b>disabled</b> — it will not attempt any login (enable via the agent's <span class="font-mono">auto_identify</span> config).</div>`);
        else if (!s.login_enabled)
            warns.push(`<div class="text-red-700">⛔ <b>${who}</b>: no credentials to try (operator list empty and factory defaults off) — logins can't run.</div>`);
        else if ((s.credentials_loaded || 0) === 0)
            warns.push(`<div class="text-amber-700">⚠ <b>${who}</b>: 0 operator credentials loaded — only factory-default logins are tried. Add creds via 🔑 Credentials.</div>`);
    }
    if (!warns.length) {
        const total = entries.reduce((n, [, s]) => n + (s.credentials_loaded || 0), 0);
        return `<div class="mb-3 text-[11px] px-3 py-2 rounded bg-emerald-50 border border-emerald-100 text-emerald-700">✅ Auto-identify is on for every console agent (${total} operator credential(s) loaded); logins run on the auto-probe schedule.</div>`;
    }
    return `<div class="mb-3 text-[11px] px-3 py-2 rounded bg-amber-50 border border-amber-100 space-y-1">${warns.join('')}</div>`;
}

// Hub-side credential/seed debug banner — the authoritative "why is login
// failing" view even when a console agent's own summary is missing (stale hub /
// agent not reporting). Shows whether operator creds are SAVED on the hub, its
// code version, and per-agent whether the hub has pushed those creds (seeded).
// Counts only — never secrets.
function _consoleDiagDebugBanner(dbg) {
    if (!dbg) return '';
    const rows = [];
    const saved = dbg.hub_credentials_saved || 0;
    rows.push(`<div class="text-slate-600">🛈 Hub: <b>${saved}</b> operator credential(s) saved · source <span class="font-mono">${escapeHtml(dbg.hub_credentials_source || 'none')}</span> · version <span class="font-mono">${escapeHtml(dbg.hub_version || '?')}</span> (${escapeHtml(dbg.hub_head || '?')})</div>`);
    if (!saved)
        rows.push(`<div class="text-red-700">⛔ No operator credentials saved on the hub — every agent tries only the 9 factory defaults (<span class="font-mono">creds_tried=N/9</span>). Add them via 🔑 Credentials.</div>`);
    for (const [sid, st] of Object.entries(dbg.spokes || {})) {
        const bits = `seeded=${st.seeded} responded=${st.responded} summary=${st.summary_reported}`;
        rows.push(`<div class="text-slate-500 font-mono text-[10px]">${escapeHtml(sid)}: ${bits}</div>`);
        if (saved && !st.seeded)
            rows.push(`<div class="text-amber-700">⚠ <b>${escapeHtml(sid)}</b>: creds saved but not yet pushed to this agent — Refresh (or open Console ports) to re-seed.</div>`);
    }
    const tone = !saved ? 'bg-red-50 border-red-100' : 'bg-slate-50 border-slate-200';
    return `<div class="mb-3 text-[11px] px-3 py-2 rounded border ${tone} space-y-1">${rows.join('')}</div>`;
}

// Footer buttons shared by the diagnostics modal states: purge all collected
// telemetry (Global-Admin only — purge is infra-wide across every tenant's
// spoke) + copy/refresh (available to the whole console view tier).
function _consoleDiagFooterBtns() {
    const purgeBtn = isAdmin()
        ? `<button onclick="purgeConsoleDiagnostics()" class="text-[11px] px-3 py-1.5 rounded border border-red-200 text-red-600 hover:bg-red-50" title="Delete all collected serial-health / identify telemetry across every console agent">🗑 Purge data</button>`
        : '';
    return `<button onclick="copyConsoleDiagnostics(this)" class="text-[11px] px-3 py-1.5 rounded border border-[#01A982] text-[#01A982] hover:bg-[#01A982]/10 font-bold" title="Copy the full diagnostics — every port's login/identify telemetry, prompts, creds tried, skip reason and the last raw device line — as plain text to paste into a ticket or chat">⧉ Copy debug</button>`
         + purgeBtn
         + `<button onclick="refreshConsoleDiagnostics()" class="text-[11px] px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50">↻ Refresh</button>`;
}

// Serialize the last-fetched console diagnostics to plain text so an operator can
// paste EVERYTHING (including the hover-only bits — the raw transcript tail, the
// hostname history, the skip reason) into a ticket or a chat with support. No
// secrets: credentials are only ever reported as counts, never values.
function copyConsoleDiagnostics(btn) {
    const d = window._consoleDiagLast;
    if (!d) { showToast('Nothing to copy yet — open/refresh diagnostics first', 'error'); return; }
    const L = [`LM CONSOLE DIAGNOSTICS — captured ${d._fetched_at}`,
               '(last FETCHED data — press Refresh for live values)', ''];
    const summaries = Object.entries(d.summaries || {});
    L.push(`AGENTS (${summaries.length})`);
    if (!summaries.length) L.push('  (no console agents reported a summary)');
    summaries.forEach(([sid, s]) => {
        L.push(`  ${s.agent_name || sid} [${sid}]`);
        L.push(`    auto_identify=${s.auto_identify}  login_enabled=${s.login_enabled}` +
               `  operator_creds=${s.credentials_loaded}  factory_defaults=${s.factory_default_creds}` +
               `  monitor=${s.monitor}  ports=${s.port_count}`);
        if (!s.auto_identify) L.push('    ⛔ auto-identify DISABLED — no login is attempted on any port.');
        else if (!s.login_enabled) L.push('    ⛔ no credentials to try (operator list empty AND factory defaults off).');
        else if (!s.credentials_loaded) L.push('    ⚠ 0 operator credentials — only factory-default logins are tried.');
    });
    L.push('');
    // Hub-side credential/seed debug — the authoritative "why is login failing"
    // answer even when a console agent's own summary is missing above. Reports
    // whether operator creds are SAVED on the hub, whether the hub pushed them to
    // each agent, and the hub's own code version. Counts only, never secrets.
    const dbg = d.debug;
    if (dbg) {
        L.push('DEBUG — HUB CREDENTIAL / SEED STATE');
        L.push(`  hub_credentials_saved=${dbg.hub_credentials_saved}` +
               `  source=${dbg.hub_credentials_source}` +
               `  hub_version=${dbg.hub_version || '?'}  hub_head=${dbg.hub_head || '?'}`);
        if (!dbg.hub_credentials_saved) {
            L.push('  ⚠ NO operator credentials saved on the hub — every agent will try only the');
            L.push('    9 factory-default logins (creds_tried=N/9). Set them in Console → credentials.');
        }
        const sp = Object.entries(dbg.spokes || {});
        sp.forEach(([sid, st]) => {
            L.push(`  ${sid}: seeded=${st.seeded} responded=${st.responded}` +
                   ` summary_reported=${st.summary_reported}`);
            if (dbg.hub_credentials_saved && !st.seeded)
                L.push('    ⚠ creds saved but NOT yet pushed to this agent — open Console ports or Refresh to re-seed.');
        });
        L.push('');
    }
    const errs = Object.entries(d.errors || {});
    if (errs.length) { L.push(`UNREACHABLE CONSOLES (${errs.length})`); errs.forEach(([s, e]) => L.push(`  ${s}: ${e}`)); L.push(''); }

    const rows = d.diagnostics || [];
    const failRows = rows.filter(r => r.open_failures || r.disconnects || r.currently_failing);
    L.push(`SERIAL CONNECTION FAILURES (${failRows.length})`);
    if (!failRows.length) L.push('  (none)');
    failRows.forEach(r => {
        const st = !r.present ? 'GONE' : r.currently_failing ? 'FAILING' : r.recoveries > 1 ? 'FLAPPING' : 'RECOVERED';
        L.push(`  ${r.alias || r.device || r.port_id} [${r.agent_name || r.spoke_id || ''}] — ${st}`);
        L.push(`    open_failures=${r.open_failures || 0} disconnects=${r.disconnects || 0} recoveries=${r.recoveries || 0}` +
               ` present=${r.present} monitoring=${r.monitoring} in_use=${r.in_use}`);
        if (r.last_error) L.push(`    last_error: ${r.last_error}`);
    });
    L.push('');

    const identRows = rows.filter(r => (r.identify && r.identify.attempts) || (r.present && r.schedule));
    L.push(`IDENTIFY / LOGIN TELEMETRY (${identRows.length})`);
    if (!identRows.length) L.push('  (no ports)');
    identRows.forEach(r => {
        const t = r.identify || {};
        const sc = r.schedule || {};
        L.push(`  ${r.alias || r.device || r.port_id} [${r.agent_name || r.spoke_id || ''}]`);
        L.push(`    port_id=${r.port_id} device=${r.device || ''} present=${r.present}` +
               ` vendor=${r.vendor || t.vendor || '-'} identified=${r.identified}`);
        if (!t.attempts) {
            L.push(`    NO ATTEMPT YET — ${sc.skip_reason || 'pending'}` +
                   (sc.next_attempt_in ? ` (next in ${_consoleFmtDur(sc.next_attempt_in)})` : ''));
        } else {
            const outcome = t.logged_in ? 'LOGGED IN'
                : t.shell_prompt_seen ? 'shell, no id'
                : t.password_prompt_seen ? 'auth rejected'
                : t.login_prompt_seen ? 'login prompt (no login)'
                : t.any_output ? 'output, no prompt' : 'silent';
            L.push(`    via=${t.method === 'llm' ? 'AI (show commands)' : 'login'} outcome=${outcome}` +
                   `  logged_in=${!!t.logged_in}`);
            L.push(`    prompts: login=${!!t.login_prompt_seen} password=${!!t.password_prompt_seen} shell=${!!t.shell_prompt_seen}` +
                   `  any_output=${!!t.any_output} bytes=${t.bytes || 0}`);
            L.push(`    creds_tried=${t.creds_tried || 0}/${t.creds_available || 0}` +
                   `  schedule=${sc.skip_reason || ''}${sc.next_attempt_in ? ` (next in ${_consoleFmtDur(sc.next_attempt_in)})` : ''}` +
                   `  backoff=${sc.backoff_s || 0}s`);
            if (t.method === 'llm') L.push(`    commands_run=${(t.commands_run || []).length} rejected=${(t.rejected || []).length}`);
            if (t.reason) L.push(`    reason: ${t.reason}`);
            if (t.error) L.push(`    error: ${t.error}`);
            if (t.hostname) {
                L.push(`    hostname=${t.hostname} source=${t.hostname_source || '?'}` +
                       ` stable=${t.hostname_changes ? `NO (changed ${t.hostname_changes}x, ${t.hostname_distinct} distinct)` : 'yes'}`);
                (t.hostname_history || []).forEach(h => L.push(`      seen "${h.host}" via ${h.source || '?'} @ ${_consoleRelTime(h.ts)}`));
            }
            if (t.tail) L.push('    last raw line(s) from device:\n' + t.tail.split('\n').map(x => '      | ' + x).join('\n'));
        }
        L.push('');
    });

    const bootRows = rows.filter(r => r.boot && r.boot.state && r.boot.state !== 'idle');
    L.push(`BOOT / WAKE CAPTURE (${bootRows.length})`);
    if (!bootRows.length) L.push('  (no boot cycles observed)');
    bootRows.forEach(r => {
        const b = r.boot;
        L.push(`  ${r.alias || r.device || r.port_id} [${r.agent_name || r.spoke_id || ''}] — ${(b.state || '').toUpperCase()}`);
        L.push(`    prompt_seen=${!!b.prompt_seen} relocked_baud=${!!b.relocked}` +
               ` age=${b.age_s || 0}s since_output=${b.since_output_s || 0}s`);
        if (b.reason) L.push(`    reason: ${b.reason}`);
        if (b.stuck_reason) L.push(`    stuck_reason: ${b.stuck_reason}`);
        if (b.transcript_tail) L.push('    boot transcript tail:\n' + b.transcript_tail.split('\n').map(x => '      | ' + x).join('\n'));
        L.push('');
    });

    const txt = L.join('\n');
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(() => showToast('Diagnostics copied to clipboard', 'success'),
            () => _consoleDiagFallbackCopy(txt));
    } else { _consoleDiagFallbackCopy(txt); }
    if (btn) { const o = btn.textContent; btn.textContent = '✓ Copied'; setTimeout(() => { btn.textContent = o; }, 1500); }
}
window.copyConsoleDiagnostics = copyConsoleDiagnostics;

// Clipboard fallback (insecure context / permission denied): drop the text into
// a modal textarea the operator can select-all + copy from manually.
function _consoleDiagFallbackCopy(txt) {
    const m = document.createElement('div');
    m.className = 'fixed inset-0 z-[60] flex items-center justify-center bg-black bg-opacity-50';
    m.innerHTML = `<div class="bg-white rounded-lg shadow-2xl w-full max-w-2xl p-4">
        <div class="flex justify-between items-center mb-2"><b class="text-sm">Copy diagnostics</b>
          <button onclick="this.closest('.fixed').remove()" class="text-slate-400 text-xl leading-none">&times;</button></div>
        <textarea class="w-full h-80 border border-slate-300 rounded p-2 font-mono text-[11px]" readonly></textarea>
        <div class="text-[11px] text-slate-400 mt-1">Select all (Ctrl/Cmd+A) and copy.</div></div>`;
    m.querySelector('textarea').value = txt;
    document.body.appendChild(m);
    m.querySelector('textarea').focus();
    m.querySelector('textarea').select();
}


// Purge all collected diagnostics/identify telemetry (admin). Confirms first,
// since the accumulated failure/identify history is cleared on every console agent.
async function purgeConsoleDiagnostics() {
    if (!confirm('Purge ALL collected serial-health and identify telemetry on every console agent?\n\nThis clears accumulated failure/disconnect counts, identify attempts and captured transcript tails. Live state re-derives on the next probe.')) return;
    try {
        const res = await fetch('/api/console/diagnostics/purge', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}',
        });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(d.detail || `Purge failed (${res.status})`, 'error'); return; }
        showToast(`Purged diagnostics for ${d.purged || 0} port(s)`, 'success');
        await refreshConsoleDiagnostics();
    } catch (e) { showToast('Purge failed: ' + e.message, 'error'); }
}

// One row of the identify/login telemetry table (explains why a device is / isn't
// being identified: what prompts were seen, creds tried, and the last raw line).
function _consoleIdentDiagRow(d) {
    const t = d.identify || {};
    const sched = d.schedule || {};
    const yn = (b) => b ? '<span class="text-emerald-600 font-bold">✓</span>' : '<span class="text-slate-300">·</span>';
    let pill;
    if (!t.attempts) {
        // No login/identify attempt recorded yet — explain the state instead of
        // mislabelling it "silent". This is the "isn't trying to login" case.
        pill = sched.active_identity
            ? '<span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 text-[10px] font-bold uppercase">identified</span>'
            : '<span class="px-2 py-0.5 rounded-full bg-slate-200 text-slate-600 text-[10px] font-bold uppercase">not tried yet</span>';
    } else if (t.logged_in) pill = '<span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 text-[10px] font-bold uppercase">logged in</span>';
    else if (t.shell_prompt_seen) pill = '<span class="px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 text-[10px] font-bold uppercase">shell, no id</span>';
    else if (t.password_prompt_seen) pill = '<span class="px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 text-[10px] font-bold uppercase">auth rejected</span>';
    else if (t.login_prompt_seen) pill = '<span class="px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 text-[10px] font-bold uppercase">login prompt</span>';
    else if (t.any_output) pill = '<span class="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-[10px] font-bold uppercase">no prompt</span>';
    else pill = '<span class="px-2 py-0.5 rounded-full bg-red-100 text-red-700 text-[10px] font-bold uppercase">silent</span>';
    const via = t.method === 'llm' ? '🤖 AI' : (t.attempts ? '🔑 login' : '—');
    const cmds = (t.method === 'llm' && (t.commands_run || t.rejected))
        ? `<div class="text-[10px] text-slate-400">ran ${(t.commands_run || []).length}${(t.rejected || []).length ? ` · ${t.rejected.length} rejected` : ''}</div>` : '';
    const vend = t.vendor ? ` <span class="text-[10px] text-blue-600 font-bold uppercase">${escapeHtml(t.vendor)}</span>` : '';
    // "Why" = for attempted ports, the last reason/line the device gave; for
    // never-attempted ports, why it isn't being probed + when the next try lands.
    const nextTxt = (sched.next_attempt_in > 0)
        ? ` <span class="text-slate-400">(next in ${_consoleFmtDur(sched.next_attempt_in)})</span>` : '';
    const why = t.attempts
        ? `${escapeHtml(t.reason || '')}${sched.skip_reason ? `<div class="text-[10px] text-slate-400">${escapeHtml(sched.skip_reason)}${nextTxt}</div>` : ''}`
        : `<span class="text-slate-500">${escapeHtml(sched.skip_reason || 'pending')}${nextTxt}</span>`;
    const tail = escapeHtml(t.tail || '(no output)');
    const whyCell = t.attempts
        ? `<span class="cursor-help underline decoration-dotted" title="Last line seen from device:&#10;${tail}">${why}</span>`
        : why;
    return `<tr class="border-b border-slate-50 align-top">
      <td class="py-2 pr-3 font-mono text-xs">${escapeHtml(d.alias || d.device || d.port_id)}${vend}</td>
      <td class="py-2 pr-3 text-xs">${via}${cmds}</td>
      <td class="py-2 pr-3">${pill}</td>
      <td class="py-2 pr-3">${_consoleHostnameCell(t)}</td>
      <td class="py-2 pr-2 text-center text-xs whitespace-nowrap">${yn(t.login_prompt_seen)}·${yn(t.password_prompt_seen)}·${yn(t.shell_prompt_seen)}</td>
      <td class="py-2 pr-2 text-center text-xs">${t.creds_tried || 0}/${t.creds_available || 0}</td>
      <td class="py-2 pr-2 text-center text-xs">${t.bytes || 0}</td>
      <td class="py-2 pr-3 text-xs text-slate-500 max-w-[14rem]">${whyCell}${t.error ? `<div class="text-[10px] text-red-500">${escapeHtml(t.error)}</div>` : ''}</td>
      <td class="py-2 pr-3 text-xs text-slate-400">${t.attempts ? _consoleRelTime(t.last_attempt || 0) : '—'}</td>
    </tr>`;
}

// Compact seconds → "3m"/"1h2m" duration for the "next attempt in …" hint.
function _consoleFmtDur(s) {
    s = Math.max(0, Math.round(s || 0));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60), h = Math.floor(m / 60);
    if (h) return `${h}h${m % 60 ? (m % 60) + 'm' : ''}`;
    return `${m}m`;
}

// Hostname cell for the identify telemetry table: the current identified name,
// its source badge (command output / CLI prompt / AI), and a stability marker.
// A "flapping" name (changed across probes) is the tell-tale for a noisy line,
// an unreliable prompt-glean, or two devices sharing a cable — hover for the
// distinct values seen, each with its source and age.
function _consoleHostnameCell(t) {
    const hn = t.hostname || '';
    if (!hn) return '<span class="text-slate-300">—</span>';
    const src = t.hostname_source || '';
    const srcBadge = src ? ` <span class="text-[9px] px-1 rounded bg-slate-100 text-slate-500 uppercase" title="Where this name came from">${escapeHtml(src)}</span>` : '';
    const changes = t.hostname_changes || 0;
    const distinct = t.hostname_distinct || 1;
    const hist = t.hostname_history || [];
    const tip = hist.map(h => `${h.host}  —  ${h.source || '?'}, ${_consoleRelTime(h.ts)}`).join('&#10;');
    const mark = changes > 0
        ? `<span class="text-[10px] px-1.5 py-0.5 rounded-full bg-red-100 text-red-700 font-bold cursor-help" title="Changed ${changes}× across ${distinct} distinct value(s):&#10;${escapeHtml(tip)}">⚠ flapping ×${changes}</span>`
        : `<span class="text-[10px] text-emerald-600" title="Same name on every probe">✓ stable</span>`;
    return `<div class="font-mono text-xs">${escapeHtml(hn)}${srcBadge}</div><div class="mt-0.5">${mark}</div>`;
}

async function openConsoleCredentialsModal() {
    const modal = document.createElement('div');
    modal.id = 'console-creds-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    let existing = [];
    let vaultBacked = false;
    let source = 'hub';
    let migrateWarning = '';
    let localCreds = [];
    let tenantScope = '';
    let sharedGlobalCount = 0;
    let canManage = false;
    let bucketHasPsk = false;
    let loadFailed = false;
    try {
        const res = await fetch('/api/console/credentials' + _consoleTenantQuery(), { credentials: 'same-origin' });
        if (res.ok) {
            const j = await res.json();
            existing = j.credentials || [];
            vaultBacked = (j.read_only !== false);
            source = j.source || 'hub';
            migrateWarning = j.migrate_warning || '';
            localCreds = j.local_credentials || [];
            tenantScope = j.tenant || '';
            sharedGlobalCount = j.shared_global_count || 0;
            canManage = (j.can_manage === true);
            bucketHasPsk = (j.bucket_has_psk === true);
        } else {
            loadFailed = true;
        }
    } catch (e) { console.error(e); loadFailed = true; }
    if (loadFailed) {
        showToast('Unable to load console credentials (access denied or error).', 'error');
        return;
    }
    // Which vault accounts the scan / auto-identify sweep may use. Admin-only,
    // so a 403 here simply means "no picker for you" — never a modal failure.
    let credCandidates = [];
    let selectionActive = false;
    try {
        const cres = await fetch('/api/console/credentials/candidates' + _consoleTenantQuery(),
                                 { credentials: 'same-origin' });
        if (cres.ok) {
            const cj = await cres.json();
            credCandidates = cj.candidates || [];
            selectionActive = (cj.selection_active === true);
        }
    } catch (e) { console.error('console credential candidates fetch failed', e); }
    const selectionSection = credCandidates.length
        ? `<div class="pt-2 border-t border-slate-100">
             <p class="text-[11px] font-semibold text-slate-500 mb-1">Accounts used for scanning &amp; auto-identify</p>
             <p class="text-[11px] text-slate-400 mb-2">Every account is tried unless you narrow this list. Un-tick an account to keep the sweep from using it.</p>
             <div class="space-y-1">${credCandidates.map(c => `
               <label class="flex items-center gap-2 bg-slate-50 rounded px-2 py-1 cursor-pointer">
                 <input type="checkbox" class="console-cred-sel" data-name="${escapeHtml(c.name)}" ${c.selected ? 'checked' : ''}>
                 <span class="font-mono text-xs text-slate-600">${escapeHtml(c.username || '(no username)')}</span>
                 <span class="text-[10px] text-slate-400 ml-auto truncate max-w-[45%]" title="${escapeHtml(c.name)}">${escapeHtml(c.name)}</span>
               </label>`).join('')}</div>
             <div class="flex justify-between items-center pt-2 gap-2">
               <span class="text-[10px] ${selectionActive ? 'text-amber-600' : 'text-slate-400'}">${selectionActive
                   ? 'Selection active — only ticked accounts are used.'
                   : 'No selection — every account is tried.'}</span>
               <span class="flex gap-2 shrink-0">
                 <button onclick="clearConsoleCredentialSelection('${escJsAttr(tenantScope)}')" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50">Use all</button>
                 <button onclick="saveConsoleCredentialSelection('${escJsAttr(tenantScope)}')" class="text-[11px] px-3 py-1 rounded border border-[#01A982] text-[#01A982] hover:bg-[#01A982]/10 font-bold">Save selection</button>
               </span>
             </div>
           </div>`
        : '';
    if (vaultBacked) {
        // Creation is disabled: console logins are managed in the Credential
        // Vault (or a legacy Key Vault ref). The hub only reads them here, so
        // editing lives in the vault, not this modal. Legacy LOCAL passwords may
        // still be DELETED here to clean them up (delete-only, never add).
        const list = existing.length
            ? existing.map(c => `<li class="font-mono text-xs text-slate-600">${escapeHtml(c.username)}${c.has_password ? '' : ' <span class="text-amber-500">(no password)</span>'}</li>`).join('')
            : '<li class="text-xs text-slate-400 italic">no credentials resolved from the vault</li>';
        const srcLabel = tenantScope
            ? `the <b>Credential Vault</b> (tenant <b>${escapeHtml(tenantScope)}</b> bucket + shared global slot)`
            : source === 'cred_vault' ? 'the <b>Credential Vault</b> (Global Admin slot)'
            : source === 'keyvault' ? 'a legacy <b>Key Vault</b> reference'
            : 'the <b>hub</b> (legacy local store)';
        const warnBanner = migrateWarning
            ? `<div class="text-xs px-3 py-2 rounded bg-amber-50 text-amber-800 border border-amber-200">⚠ ${escapeHtml(migrateWarning)}</div>`
            : '';
        // Legacy local passwords still on the hub — offer per-row delete so an
        // operator can clean them up (they can't be edited, only removed).
        const localSection = localCreds.length
            ? `<div class="pt-2 border-t border-slate-100">
                 <p class="text-[11px] font-semibold text-slate-500 mb-1">Legacy local passwords (delete to clean up)</p>
                 <div class="space-y-1">${localCreds.map(c => `
                   <div class="flex items-center justify-between gap-2 bg-slate-50 rounded px-2 py-1">
                     <span class="font-mono text-xs text-slate-600">${escapeHtml(c.username)}${c.has_password ? '' : ' <span class="text-amber-500">(no password)</span>'}</span>
                     <button onclick="deleteConsoleLocalCredential('${escJsAttr(c.username)}')" class="text-[11px] px-2 py-0.5 rounded border border-red-300 text-red-600 hover:bg-red-50" title="Delete this local credential">Delete</button>
                   </div>`).join('')}</div>
               </div>`
            : '';
        const sharedNote = sharedGlobalCount
            ? `<div class="text-[11px] px-3 py-2 rounded bg-slate-50 text-slate-500 border border-slate-200">➕ ${sharedGlobalCount} shared global login${sharedGlobalCount === 1 ? '' : 's'} (managed by a Global Admin) also appl${sharedGlobalCount === 1 ? 'ies' : 'y'} to your console devices.</div>`
            : '';
        modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
              <h3 class="text-lg font-bold text-[#263040]">Console Credential Library</h3>
              <button onclick="this.closest('#console-creds-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
            </div>
            <div class="p-6 space-y-3">
              <div class="text-xs px-3 py-2 rounded bg-blue-50 text-blue-700 border border-blue-100">🔐 Resolved from ${srcLabel} (read-only here). New raw passwords can no longer be created — manage credentials in the Credential Vault.</div>
              ${warnBanner}
              <ul class="space-y-1 list-disc list-inside">${list}</ul>
              ${sharedNote}
              ${selectionSection}
              ${localSection}
              <div class="pt-3 flex justify-end"><button onclick="this.closest('#console-creds-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Close</button></div>
            </div></div>`;
        _mountModal(modal);
        return;
    }
    const rowFor = (u) => `<div class="flex gap-2 console-cred-row">
        <input class="console-cred-user flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" placeholder="username" value="${(u || '').replace(/"/g, '&quot;')}">
        <input class="console-cred-pass flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" type="password" placeholder="password (blank = keep)">
        <button onclick="this.closest('.console-cred-row').remove()" class="px-2 text-red-400 hover:text-red-600">&times;</button></div>`;
    const pskRow = bucketHasPsk
        ? `<div class="pt-1"><label class="block text-[11px] text-slate-500 mb-1">Vault pass-phrase (required to save — this bucket is PSK-protected)</label>
             <input id="console-cred-psk" type="password" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm" placeholder="bucket pass-phrase"></div>`
        : '';
    const scopeNote = tenantScope
        ? `<div class="text-xs px-3 py-2 rounded bg-blue-50 text-blue-700 border border-blue-100">🔐 These are the console scan logins for tenant <b>${escapeHtml(tenantScope)}</b>, stored in your <b>Credential Vault</b> bucket and pushed to this tenant's console agents. ${sharedGlobalCount ? `${sharedGlobalCount} shared global login${sharedGlobalCount === 1 ? '' : 's'} also appl${sharedGlobalCount === 1 ? 'ies' : 'y'} (managed by a Global Admin).` : ''}</div>`
        : '';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Console Scan Credentials</h3>
          <button onclick="this.closest('#console-creds-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-3">
          ${scopeNote}
          <p class="text-[11px] text-slate-400">Tried in order when scanning/auto-identifying serial-attached devices. Stored in the Credential Vault; passwords are never displayed back. Leave a password blank to keep the stored one. Remove all rows to clear this tenant's console logins.</p>
          <div id="console-cred-rows" class="space-y-2">${(existing.length ? existing.map(c => rowFor(c.username)).join('') : rowFor(''))}</div>
          <button onclick="document.getElementById('console-cred-rows').insertAdjacentHTML('beforeend', _consoleCredRowHtml())" class="text-[11px] px-3 py-1 rounded border border-slate-300 hover:bg-slate-50">+ Add credential</button>
          ${pskRow}
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#console-creds-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="saveConsoleVaultCredentials('${escJsAttr(tenantScope)}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">Save</button>
          </div>
        </div></div>`;
    _mountModal(modal);
}

// Persist which vault accounts the console scan / auto-identify sweep may use.
// Ticking every account clears the restriction instead of pinning today's list,
// so an account added to the vault later is picked up automatically.
async function saveConsoleCredentialSelection(tenant) {
    const boxes = Array.from(document.querySelectorAll('#console-creds-modal .console-cred-sel'));
    const selected = boxes.filter(b => b.checked).map(b => b.dataset.name);
    if (!selected.length) {
        showToast('Tick at least one account, or use "Use all" to clear the selection.', 'error');
        return;
    }
    await _postConsoleCredentialSelection(
        tenant,
        selected.length === boxes.length ? null : selected,
        selected.length === boxes.length
            ? 'Using every console account.'
            : `Console sweep limited to ${selected.length} account${selected.length === 1 ? '' : 's'}.`);
}

// Drop any restriction — every console/login secret in the bucket is tried.
async function clearConsoleCredentialSelection(tenant) {
    await _postConsoleCredentialSelection(tenant, null, 'Using every console account.');
}

async function _postConsoleCredentialSelection(tenant, selected, okMsg) {
    const body = { selected };
    if (tenant) body.tenant = tenant;
    try {
        const res = await fetch('/api/console/credentials/selection', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!res.ok) {
            const j = await res.json().catch(() => ({}));
            showToast(j.detail || 'Could not save the credential selection.', 'error');
            return;
        }
        showToast(okMsg, 'success');
        document.getElementById('console-creds-modal')?.remove();
        openConsoleCredentialsModal();
    } catch (e) {
        console.error('console credential selection save failed', e);
        showToast('Could not save the credential selection.', 'error');
    }
}

// Save the tenant's console SCAN credentials into the Credential Vault (tenant
// bucket, automation-readable) via /api/console/credentials/set. A blank
// password keeps the stored one; removing every row clears the list. Sends the
// bucket pass-phrase when the bucket is PSK-protected.
async function saveConsoleVaultCredentials(tenant) {
    const rows = Array.from(document.querySelectorAll('#console-creds-modal .console-cred-row'));
    const credentials = [];
    for (const row of rows) {
        const u = (row.querySelector('.console-cred-user')?.value || '').trim();
        const p = row.querySelector('.console-cred-pass')?.value || '';
        if (!u) continue;
        credentials.push({ username: u, password: p });
    }
    const psk = document.getElementById('console-cred-psk')?.value || '';
    try {
        const res = await fetch('/api/console/credentials/set', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant: tenant || undefined, psk, credentials }),
        });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(d.detail || 'Could not save console credentials', 'error'); return; }
        showToast(`🔑 Saved ${d.count || 0} console scan credential(s).`, 'success');
        document.getElementById('console-creds-modal')?.remove();
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

function _consoleCredRowHtml() {
    return `<div class="flex gap-2 console-cred-row">
        <input class="console-cred-user flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" placeholder="username">
        <input class="console-cred-pass flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" type="password" placeholder="password">
        <button onclick="this.closest('.console-cred-row').remove()" class="px-2 text-red-400 hover:text-red-600">&times;</button></div>`;
}

async function deleteConsoleLocalCredential(username) {
    if (!confirm(`Delete local console credential "${username}"? This removes the legacy password from the hub; it cannot be undone.`)) return;
    // Delete-only POST: re-read the current local list, drop the target, and
    // submit the remaining usernames (no passwords — the backend rejects any
    // password or new username). Creating/changing is disabled; only deletion.
    let localCreds = [];
    try {
        const res = await fetch('/api/console/credentials', { credentials: 'same-origin' });
        if (res.ok) localCreds = (await res.json()).local_credentials || [];
    } catch (e) { console.error(e); }
    const remaining = localCreds
        .filter(c => c.username !== username)
        .map(c => ({ username: c.username }));
    try {
        const res = await fetch('/api/console/credentials', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credentials: remaining }),
        });
        if (res.ok) {
            showToast('Credential deleted', 'success');
            document.getElementById('console-creds-modal')?.remove();
            openConsoleCredentialsModal();
        } else {
            const d = await res.json().catch(() => ({}));
            showToast(d.detail || 'Delete failed', 'error');
        }
    } catch (e) { showToast('Delete failed: ' + e.message, 'error'); }
}

async function saveConsoleCredentials() {
    const rows = Array.from(document.querySelectorAll('.console-cred-row'));
    const credentials = rows.map(r => ({
        username: r.querySelector('.console-cred-user').value.trim(),
        password: r.querySelector('.console-cred-pass').value,
    })).filter(c => c.username);
    try {
        const res = await fetch('/api/console/credentials', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credentials }),
        });
        if (res.ok) { showToast('Credentials saved', 'success'); document.getElementById('console-creds-modal')?.remove(); }
        else { const d = await res.json().catch(() => ({})); showToast(d.detail || 'Save failed', 'error'); }
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

async function _consoleLoadXterm() {
    if (_xtermMod) return _xtermMod;
    if (!document.getElementById('xterm-css')) {
        const link = document.createElement('link');
        link.id = 'xterm-css'; link.rel = 'stylesheet';
        link.href = 'https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css';
        document.head.appendChild(link);
    }
    try {
        _xtermMod = await import('https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/+esm');
    } catch (e) {
        console.error('xterm load failed', e);
        return null;
    }
    // Optional fit addon: lets each terminal grow to fill its body so there is
    // no dead space below/right of the console grid. Non-fatal if the CDN
    // blocks it — consoles just fall back to the default 80×24 grid.
    if (!_xtermMod.FitAddon) {
        try {
            const fitMod = await import('https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/+esm');
            _xtermMod.FitAddon = fitMod.FitAddon;
        } catch (e) { console.warn('xterm fit addon load failed (non-fatal)', e); }
    }
    return _xtermMod;
}

async function openConsoleTerminal(spokeId, portId, knownLabel) {
    const key = spokeId + '::' + portId;
    // Already open? Don't mint a second session for the same port — just surface
    // the serial dock and switch to that port's existing tab.
    if (window._serialConsoles && window._serialConsoles.has(key)) {
        serialEnsureConsoleDock();
        serialActivateConsole(key);
        const existing = window._serialConsoles.get(key);
        showToast(`Console for ${(existing && existing.label) || portId} is already open`, 'info');
        return;
    }
    const mod = await _consoleLoadXterm();
    if (!mod || !mod.Terminal) { showToast('Failed to load terminal (CDN unreachable)', 'error'); return; }
    let session;
    try {
        const res = await fetch('/api/console/open', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId, mode: 'rw' }),
        });
        session = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(session.detail || 'Open failed', 'error'); return; }
    } catch (e) { showToast('Open failed: ' + e.message, 'error'); return; }
    serialAddConsoleTab(spokeId, portId, session, mod.Terminal, knownLabel);
}

// ── Tabbed serial-console dock ──────────────────────────────────────────────
// A single in-browser window hosting EVERY open serial console as a tab, so an
// operator can keep several device consoles connected at once and switch
// between them without dropping any. Each session's xterm renders into its own
// body div; inactive bodies are hidden (display:none) but their WebSocket stays
// open, so switching tabs is instant and non-destructive. The serial spoke
// already fans one physical port to many sessions, so multiple people (and
// multiple tabs) can watch/drive the same device concurrently. Registry:
// window._serialConsoles (Map<key, {key, spokeId, portId, session, term, ws,
// bodyEl, ro, statusText, statusCls}>); window._serialActiveConsole holds the
// visible tab's key. key = `${spokeId}::${portId}`.

// Both console docks are `position: fixed` bottom drawers, so they cover the
// bottom slice of #viewport without the page knowing — the underlying list
// (port list / VM list) has no bottom padding to compensate, so its last rows
// scroll to just above the drawer's covered area and then stop: the browser
// considers the container "fully scrolled" even though a drawer-height chunk
// of it is still hidden underneath. Give #viewport bottom padding equal to
// whichever dock(s) are currently showing (minimized docks only cover their
// header bar) so scrolling all the way down actually clears the drawer.
// Create (or reveal) the shared serial-console dock shell. Idempotent — the
// list and bodies persist across opens; only wired once. Full-screen panel
// bounded by the header (top-16), footer (bottom-10), and left nav sidebar
// (left-56, index.html) — occupies the same box <main> does. A left-side
// search + scrollable list (serialRenderConsoleList) replaces the old
// horizontal tab strip, which became unusable once more than a handful of
// consoles were open (had to scroll sideways through a cramped strip).
function serialEnsureConsoleDock() {
    let modal = document.getElementById('serial-console-modal');
    if (modal) { modal.classList.remove('hidden'); serialRefreshAvailablePorts(); return modal; }
    modal = document.createElement('div');
    modal.id = 'serial-console-modal';
    modal.className = 'fixed top-16 bottom-10 left-56 right-0 z-40 flex bg-[#1e1e1e] border-t border-slate-700 shadow-2xl';
    modal.innerHTML = `
        <div id="serial-console-sidebar" class="shrink-0 flex flex-col border-r border-slate-700 bg-[#181818] overflow-hidden">
            <div class="p-2 border-b border-slate-700 space-y-2 w-72">
                <div class="flex items-center justify-between">
                    <strong class="text-sm text-slate-200">Serial Consoles</strong>
                    <div class="flex items-center gap-2">
                        <button id="serial-console-refresh" title="Refresh the list of available consoles" class="text-slate-400 hover:text-sky-400 text-sm leading-none">⟳</button>
                    </div>
                </div>
                <input id="serial-console-search" type="text" placeholder="Search consoles…"
                       class="w-full text-xs bg-[#1e1e1e] border border-slate-600 rounded px-2 py-1 text-slate-100 focus:outline-none focus:border-sky-500">
                <button id="serial-broadcast-toggle" title="Check 2 or more consoles below first" disabled
                        class="opacity-40 w-full px-2 py-1 text-xs rounded border border-sky-500 text-sky-400 hover:bg-sky-900/40">Broadcast: Off</button>
            </div>
            <div id="serial-console-list" class="flex-1 overflow-y-auto w-72"></div>
        </div>
        <div id="serial-console-resize-handle" title="Drag to resize — collapse to fit two consoles side-by-side"
             class="w-1.5 shrink-0 cursor-col-resize bg-slate-700 hover:bg-sky-500 active:bg-sky-500 relative">
            <button id="serial-console-sidebar-collapse" title="Collapse/expand the console list"
                    class="absolute top-2 -left-2 w-4 h-8 flex items-center justify-center rounded-sm bg-slate-700 hover:bg-sky-600 text-slate-300 hover:text-white text-[10px] leading-none">◂</button>
        </div>
        <div class="flex-1 flex flex-col min-w-0 min-h-0">
            <div class="flex items-center gap-3 px-4 py-2 bg-[#2d2d2d] border-b border-slate-700 text-slate-200 text-sm">
                <button id="serial-console-min" title="Minimize to the footer — keeps every session connected so you can browse the rest of the UI" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">▁ Minimize</button>
                <button id="serial-console-fs" title="Fullscreen the active console" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">Fullscreen</button>
                <button id="serial-console-takeover" title="Take over write control from the other user" class="px-2 py-0.5 text-xs rounded border border-amber-500 text-amber-400 hover:bg-amber-900/40 hidden">Take Over</button>
                <button id="serial-console-reconnect" title="Reconnect this console — resumes on the same terminal, keeping its scrollback" class="px-2 py-0.5 text-xs rounded border border-green-500 text-green-400 hover:bg-green-900/40 hidden">⟳ Reconnect</button>
                <span id="serial-console-status" class="ml-auto text-xs text-amber-400"></span>
                <button id="serial-console-closeall" title="Close all open consoles" class="text-slate-400 hover:text-red-400 text-lg leading-none">&times;</button>
            </div>
            <div id="serial-console-bodies" class="relative flex-1 min-h-0 flex bg-[#1e1e1e] overflow-hidden"></div>
            <div id="serial-broadcast-bar" class="hidden shrink-0 flex items-center gap-2 px-3 py-1.5 bg-[#2d2d2d] border-t border-slate-700">
                <span id="serial-broadcast-bar-label" class="text-xs text-sky-400 whitespace-nowrap">Broadcast to 0 consoles:</span>
                <input id="serial-broadcast-bar-input" type="text" placeholder="Type a line and press Enter to send it to every checked console…"
                       class="flex-1 text-xs font-mono bg-[#1e1e1e] border border-slate-600 rounded px-2 py-1 text-slate-100 focus:outline-none focus:border-sky-500">
            </div>
        </div>`;
    document.body.appendChild(modal);
    // Refit visible terminals when the window resizes or fullscreen toggles so
    // the console grid always fills its body (registered once).
    if (!window._serialFitHooked) {
        window.addEventListener('resize', serialFitVisibleConsoles);
        document.addEventListener('fullscreenchange', serialFitVisibleConsoles);
        window._serialFitHooked = true;
    }
    modal.querySelector('#serial-console-fs').onclick = () => {
        const c = serialActiveConsole();
        const screen = c && c.bodyEl;
        if (document.fullscreenElement) document.exitFullscreen();
        else if (screen && screen.requestFullscreen) screen.requestFullscreen().catch(() => {});
    };
    modal.querySelector('#serial-console-closeall').onclick = () => serialCloseAllConsoles();
    modal.querySelector('#serial-console-min').onclick = () => serialSetDockCollapsed(true);
    modal.querySelector('#serial-console-refresh').onclick = () => serialRefreshAvailablePorts();
    modal.querySelector('#serial-console-takeover').onclick = () => serialForceTakeover();
    modal.querySelector('#serial-console-reconnect').onclick = () => {
        const c = serialActiveConsole();
        if (c) serialReconnectConsole(c.key);
    };
    modal.querySelector('#serial-console-search').addEventListener('input', (ev) => {
        window._serialConsoleFilter = ev.target.value.trim().toLowerCase();
        serialRenderConsoleList();
    });
    modal.querySelector('#serial-broadcast-toggle').onclick = () => {
        window._serialBroadcastOn = !window._serialBroadcastOn;
        serialUpdateBroadcastBar();
        const bar = modal.querySelector('#serial-broadcast-bar');
        const input = modal.querySelector('#serial-broadcast-bar-input');
        if (window._serialBroadcastOn && bar && !bar.classList.contains('hidden') && input) input.focus();
        modal.querySelector('#serial-broadcast-toggle').textContent =
            window._serialBroadcastOn ? 'Broadcast: On' : 'Broadcast: Off';
        // Toggling Broadcast is what splits (On) or collapses (Off) the panes.
        serialReflowBodies();
    };
    modal.querySelector('#serial-broadcast-bar-input').addEventListener('keydown', (ev) => {
        if (ev.key !== 'Enter') return;
        ev.preventDefault();
        const input = ev.target;
        const text = input.value;
        if (!text) return;
        const sent = serialBroadcastSend(text);
        input.value = '';
        if (!sent) showToast('Broadcast: no writable consoles in the group', 'warning');
    });
    serialUpdateBroadcastBar();
    // Sidebar starts at its remembered width (session-only — resets on a full
    // page reload) so reopening the dock keeps the operator's preferred split
    // instead of resetting to the default every time. Collapsing it (rather
    // than closing sessions) is what makes room to view two consoles
    // side-by-side without the list eating into the split.
    modal.querySelector('#serial-console-sidebar-collapse').onclick = () =>
        serialSetSidebarCollapsed(!window._serialSidebarCollapsed);
    serialSetSidebarCollapsed(!!window._serialSidebarCollapsed);
    modal.querySelector('#serial-console-resize-handle').addEventListener('mousedown', (ev) => {
        // A mousedown on the collapse button shouldn't also start a drag.
        if (ev.target.closest('#serial-console-sidebar-collapse')) return;
        window._serialSidebarDragging = true;
        document.body.style.userSelect = 'none';
        ev.preventDefault();
    });
    _serialWireSidebarResize();
    // Populate the left menu with EVERY console the user has rights to (not just
    // the ones already open) so it acts as a click-to-open directory.
    serialRefreshAvailablePorts();
    return modal;
}

// Expand/collapse the console LIST specifically (distinct from
// serialSetDockCollapsed, which minimizes the WHOLE dock to a footer pill).
// Collapsing just hides the browse-and-search sidebar, reclaiming its width
// for the console body area — e.g. so a broadcast pair of split panes gets
// the full dock width instead of competing with the list for space. No
// sessions are affected either way.
function serialSetSidebarCollapsed(collapsed) {
    window._serialSidebarCollapsed = !!collapsed;
    const modal = document.getElementById('serial-console-modal');
    if (!modal) return;
    const sidebar = modal.querySelector('#serial-console-sidebar');
    const btn = modal.querySelector('#serial-console-sidebar-collapse');
    if (sidebar) sidebar.style.width = collapsed ? '0px' : ((window._serialSidebarWidth || 288) + 'px');
    if (btn) { btn.textContent = collapsed ? '▸' : '◂'; btn.title = collapsed ? 'Expand the console list' : 'Collapse the console list'; }
}

// Drag-to-resize wiring for the sidebar — attached to `document` ONCE (guarded
// by a flag) rather than per dock-open, since the dock's DOM (and any
// listeners bound to ITS elements) is destroyed on close; a document-level
// listener would otherwise accumulate a stale copy every reopen. Looks up the
// current dock elements by id on every move rather than closing over them, so
// it naturally no-ops once the dock (or its drag) is gone.
function _serialWireSidebarResize() {
    if (window._serialResizeWired) return;
    window._serialResizeWired = true;
    const MIN_W = 160, MAX_W = 560;
    document.addEventListener('mousemove', (ev) => {
        if (!window._serialSidebarDragging) return;
        const modal = document.getElementById('serial-console-modal');
        const sidebar = document.getElementById('serial-console-sidebar');
        if (!modal || !sidebar) return;
        const w = Math.max(MIN_W, Math.min(MAX_W, ev.clientX - modal.getBoundingClientRect().left));
        window._serialSidebarWidth = w;
        window._serialSidebarCollapsed = false;
        sidebar.style.width = w + 'px';
        const btn = document.getElementById('serial-console-sidebar-collapse');
        if (btn) { btn.textContent = '◂'; btn.title = 'Collapse the console list'; }
    });
    document.addEventListener('mouseup', () => {
        if (!window._serialSidebarDragging) return;
        window._serialSidebarDragging = false;
        document.body.style.userSelect = '';
    });
}

// Send one line to every member of the broadcast group (from the shared
// broadcast bar, NOT from typing into an individual pane — a pane always
// stays single-target, see serialAddConsoleTab). Read-only members are
// silently skipped, same as an individual pane would drop the bytes anyway.
function serialBroadcastSend(text) {
    const group = window._serialBroadcastGroup;
    if (!group || group.size < 2 || !window._serialConsoles) return 0;
    const bytes = text + '\r';
    let sent = 0;
    group.forEach(k => {
        const peer = window._serialConsoles.get(k);
        if (peer && !peer.ro && peer.ws && peer.ws.readyState === 1) { peer.ws.send(bytes); sent++; }
    });
    return sent;
}

// Show/hide the shared broadcast input bar + refresh its "N consoles" label.
// Visible only when the toggle is on AND 2+ consoles are checked in the
// group — off, or under 2 checked, each console just has its own normal
// per-pane typing (term.onData in serialAddConsoleTab), same as before this
// feature existed.
function serialUpdateBroadcastBar() {
    const modal = document.getElementById('serial-console-modal');
    if (!modal) return;
    const bar = modal.querySelector('#serial-broadcast-bar');
    const toggleBtn = modal.querySelector('#serial-broadcast-toggle');
    if (!bar || !toggleBtn) return;
    const group = window._serialBroadcastGroup;
    const groupActive = !!(group && group.size >= 2);
    const on = !!window._serialBroadcastOn && groupActive;
    bar.classList.toggle('hidden', !on);
    toggleBtn.classList.toggle('bg-sky-600', !!window._serialBroadcastOn);
    toggleBtn.classList.toggle('text-white', !!window._serialBroadcastOn);
    toggleBtn.disabled = !groupActive;
    toggleBtn.classList.toggle('opacity-40', !groupActive);
    toggleBtn.title = groupActive
        ? 'Toggle a single shared input that broadcasts to every checked console'
        : 'Check 2 or more consoles below first';
    const label = bar.querySelector('#serial-broadcast-bar-label');
    if (label) label.textContent = `Broadcast to ${group ? group.size : 0} consoles:`;
}

// Show/hide + size console bodies. With an active broadcast group (2+
// checked), every group member is shown side-by-side (flex-wrap, so any
// count lays out sanely) — PLUS whichever tab is "active" even if it isn't
// in the group, so you can still peek at another console without joining
// the broadcast. With no active group, only the active tab shows (full
// width), same as plain single-tab view. Fires a window resize event
// afterward so anything watching viewport size (noVNC elsewhere) notices.
function serialReflowBodies() {
    if (!window._serialConsoles) return;
    const activeKey = window._serialActiveConsole;
    const group = window._serialBroadcastGroup;
    // Side-by-side (split) view only when the operator has explicitly turned
    // Broadcast ON with 2+ consoles checked. Merely checking consoles no longer
    // splits the screen — otherwise the dock silently showed two panes while
    // the toggle still read "Broadcast: Off", and a second (read-only) session
    // to the same device mirrored the active pane. With Broadcast off, exactly
    // one pane shows: the active console (full height).
    const groupActive = !!(window._serialBroadcastOn && group && group.size >= 2);
    const bodies = document.getElementById('serial-console-bodies');
    if (!bodies) return;
    bodies.classList.toggle('flex-wrap', groupActive);
    // Authoritative over the ACTUAL DOM, not just the registry: walk every pane
    // currently in the bodies container and show/hide it by its own
    // data-console-key. A registry-only loop can leave a stray or duplicate
    // pane (one whose entry was replaced/removed) visible beside the active
    // one — which is exactly how a second console appeared in both slots. Here
    // any pane whose key isn't the active tab (or a broadcast-group member) is
    // forced hidden, so at most one console shows when broadcast is off.
    Array.from(bodies.children).forEach(el => {
        const k = el.getAttribute('data-console-key');
        const inGroup = groupActive && group.has(k);
        const visible = inGroup || k === activeKey;
        el.classList.toggle('hidden', !visible);
        el.classList.toggle('flex-1', visible && !inGroup);
        el.style.flex = inGroup ? '1 1 320px' : '';
    });
    try { window.dispatchEvent(new Event('resize')); } catch (err) {}
    // Refit the now-visible terminals after the browser applies the layout
    // above (an xterm only measures correctly once its body is visible + sized).
    try {
        requestAnimationFrame(() => {
            if (!window._serialConsoles) return;
            window._serialConsoles.forEach((e, k) => {
                const inGroup = groupActive && group && group.has(k);
                if (inGroup || k === activeKey) serialFitConsole(e);
            });
        });
    } catch (err) {}
}

// Resize one console's xterm to fill its (visible) body — removes the dead
// space below/right of the terminal grid — then repaint it. The repaint is
// what keeps side-by-side (broadcast) panes correct: without it, resizing or
// focusing one terminal can leave another pane showing a stale/mirrored view.
// No-op when the body is hidden (fit/measure needs a laid-out, non-zero box).
function serialFitConsole(entry) {
    if (!entry || !entry.bodyEl || !entry.term) return;
    if (entry.bodyEl.classList.contains('hidden') || !entry.bodyEl.offsetParent) return;
    try { if (entry.fitAddon) entry.fitAddon.fit(); } catch (e) {}
    // Backstop for when the fit addon is absent (its CDN module can be blocked
    // while the core xterm still loads) or no-oped before the renderer measured
    // its cell — either leaves the grid stuck at the default 80×24 so a tall
    // pane is only ~half filled. Compute the grid ourselves from the measured
    // cell size; single controller, so no oscillation with the addon.
    try { _serialManualFit(entry); } catch (e) {}
    try { entry.term.refresh(0, entry.term.rows - 1); } catch (e) {}
}

// Dependency-free fit: size the xterm grid to its body using the renderer's
// measured cell dimensions. Mirrors what the fit addon does, but without the
// external addon-fit module (which the appliance's CDN egress can block). No-op
// until the renderer has measured a cell (retried by the ResizeObserver and the
// delayed refits registered at open).
function _serialManualFit(entry) {
    const term = entry.term, el = entry.bodyEl;
    if (!term || !el) return;
    const core = term._core;
    const dims = core && core._renderService && core._renderService.dimensions;
    const cell = dims && dims.css && dims.css.cell;
    const cellW = cell && cell.width, cellH = cell && cell.height;
    if (!cellW || !cellH) return;
    const cs = getComputedStyle(el);
    const padX = (parseFloat(cs.paddingLeft) || 0) + (parseFloat(cs.paddingRight) || 0);
    const padY = (parseFloat(cs.paddingTop) || 0) + (parseFloat(cs.paddingBottom) || 0);
    const sb = (core.viewport && core.viewport.scrollBarWidth) || 14;
    const availW = el.clientWidth - padX - sb;
    const availH = el.clientHeight - padY;
    if (availW <= 0 || availH <= 0) return;
    const cols = Math.max(2, Math.floor(availW / cellW));
    const rows = Math.max(1, Math.floor(availH / cellH));
    if (cols !== term.cols || rows !== term.rows) {
        try { term.resize(cols, rows); } catch (e) {}
    }
}

// Refit every currently-visible console (window resize / fullscreen change).
function serialFitVisibleConsoles() {
    if (!window._serialConsoles) return;
    window._serialConsoles.forEach(e => serialFitConsole(e));
}

// Passive liveness watchdog. The relay sends a keepalive frame every ~20s (and
// device output resets the timer too), so an OPEN console that has received
// nothing for the stale window has a dead tunnel that no close frame reached —
// the "still looks connected but dropped" case. Flip it to Disconnected and
// close the socket so its onclose runs. Purely passive (reads timestamps, sends
// nothing) — the browser can't safely send keepalives, since anything it writes
// on the serial leg would be injected as bytes to the device.
function serialEnsureHeartbeatWatch() {
    if (window._serialHeartbeatTimer) return;
    const STALE_MS = 75000;  // 3+ missed 20s keepalives
    window._serialHeartbeatTimer = setInterval(() => {
        const reg = window._serialConsoles;
        if (!reg || reg.size === 0) return;
        const now = Date.now();
        reg.forEach(e => {
            if (!e.ws || e.ws.readyState !== 1) return;  // only live sockets
            if (now - (e._lastRx || now) <= STALE_MS) return;
            e.statusText = 'Disconnected: no heartbeat'; e.statusCls = 'text-red-400';
            try { e.ws.close(4408, 'no heartbeat'); } catch (err) {}
        });
    }, 15000);
}
function serialActiveConsole() {
    return (window._serialConsoles && window._serialActiveConsole)
        ? window._serialConsoles.get(window._serialActiveConsole) : null;
}

// Mint a serial console tab: build its body div, attach an xterm + WebSocket,
// register it, and make it the active tab.
function serialAddConsoleTab(spokeId, portId, session, Terminal, knownLabel) {
    if (!window._serialConsoles) window._serialConsoles = new Map();
    const key = spokeId + '::' + portId;
    const modal = serialEnsureConsoleDock();
    // A newly opened console always expands the dock (so it's visible), even if
    // the operator had minimized it to the footer.
    serialSetDockCollapsed(false);
    const bodies = modal.querySelector('#serial-console-bodies');
    // Never leave two panes for the same console: drop any pre-existing pane
    // for this key (a stray from a prior open/close) before adding the fresh
    // one, so the reflow can't show a duplicate beside the active tab.
    bodies.querySelectorAll('[data-console-key]').forEach(n => {
        if (n.getAttribute('data-console-key') === key) n.remove();
    });
    const bodyEl = document.createElement('div');
    bodyEl.className = 'hidden relative flex-1 min-w-0 min-h-0 p-1 overflow-hidden bg-[#1e1e1e] border-r border-slate-800';
    bodyEl.setAttribute('data-console-key', key);
    bodies.appendChild(bodyEl);
    const ro = !!session.read_only;
    // Prefer the identified hostname/alias known at open time (same
    // precedence as the port-list table: operator alias > auto-identified
    // hostname) over the raw USB-derived port_id. Snapshot-only — a hostname
    // identified WHILE this console is already open won't retroactively
    // relabel the tab (would need a new server push; close/reopen picks it
    // up via a fresh knownLabel).
    const label = knownLabel || portId;
    const entry = { key, spokeId, portId, label, session, ro, term: null, ws: null, bodyEl,
                    statusText: 'Connecting…', statusCls: 'text-amber-400' };
    window._serialConsoles.set(key, entry);
    // Make this tab active first so its body is visible when xterm lays out —
    // an xterm opened into a display:none container measures 0×0 and renders blank.
    serialActivateConsole(key);
    const term = new Terminal({ cursorBlink: true, fontSize: 13, scrollback: 5000,
                                convertEol: true,
                                theme: { background: '#1e1e1e' } });
    entry.term = term;
    // Grow the terminal grid to fill its body (no dead space below/right).
    try {
        const FitAddon = (typeof _xtermMod !== 'undefined' && _xtermMod) ? _xtermMod.FitAddon : null;
        if (FitAddon) { entry.fitAddon = new FitAddon(); term.loadAddon(entry.fitAddon); }
    } catch (e) {}
    term.open(bodyEl);
    serialFitConsole(entry);
    // The FitAddon can no-op on the very first synchronous fit (the renderer
    // hasn't measured its cell size yet), leaving the grid at the default 80×24
    // so the terminal only fills the top of a tall pane. A ResizeObserver on
    // the body refits whenever the pane actually gets (or changes) its real
    // size — the reliable way to make the grid always fill the dock, whether on
    // first open, dock resize, or the broadcast split. rAF-debounced to dodge
    // the "ResizeObserver loop" warning.
    try {
        if (typeof ResizeObserver !== 'undefined') {
            let raf = 0;
            const ro2 = new ResizeObserver(() => {
                if (raf) return;
                raf = requestAnimationFrame(() => { raf = 0; serialFitConsole(entry); });
            });
            ro2.observe(bodyEl);
            entry.resizeObserver = ro2;
        }
    } catch (e) {}
    // Belt-and-suspenders initial refits for the first paint (covers the case
    // where the observer hasn't fired yet before the pane is laid out).
    requestAnimationFrame(() => serialFitConsole(entry));
    setTimeout(() => serialFitConsole(entry), 120);
    term.focus();
    // Clicking anywhere in this console's body focuses its terminal so the
    // operator can type immediately — no need to reselect it from the left
    // menu. If it isn't the active tab (e.g. a broadcast-group pane), clicking
    // makes it active first.
    bodyEl.addEventListener('mousedown', () => {
        if (window._serialActiveConsole !== key) serialActivateConsole(key);
        try { term.focus(); } catch (e) {}
    });
    // Keystrokes always target the CURRENT socket (entry.ws), which reconnect
    // swaps out — so this handler is registered once and survives reconnects
    // (re-registering per socket would leak handlers bound to dead sockets).
    let _lastRoToast = 0;
    term.onData(d => {
        if (entry.ro) {
            const now = Date.now();
            if (now - _lastRoToast > 3000) {
                _lastRoToast = now;
                if (typeof showToast === 'function') {
                    showToast('Console is in read-only mode — click "Take Over" above to send input', 'warning');
                }
            }
            return;
        }
        if (entry.ws && entry.ws.readyState === 1) entry.ws.send(d);
    });
    serialAttachWs(entry, session);
    serialRenderConsoleList();
    serialSyncSerialHeader();
}

// Open (or re-open) the browser↔serial WebSocket for a console entry and wire
// its handlers. Factored out of serialAddConsoleTab so a dropped session can be
// reconnected onto the SAME terminal (preserving scrollback) — see
// serialReconnectConsole — instead of forcing a close/reopen.
function serialAttachWs(entry, session) {
    const term = entry.term, label = entry.label;
    entry.session = session;
    entry.ro = !!session.read_only;
    const upd = (text, cls) => { entry.statusText = text; entry.statusCls = cls; serialRenderConsoleList(); serialSyncSerialHeader(); };
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/console-serial/${session.session_id}?token=${encodeURIComponent(session.ws_token)}`);
    ws.binaryType = 'arraybuffer';
    entry.ws = ws;
    entry._lastRx = Date.now();
    ws.onopen = () => { entry._lastRx = Date.now(); upd(entry.ro ? 'Connected (read-only)' : 'Connected', 'text-green-400'); };
    ws.onmessage = (ev) => {
        // Any frame — device bytes OR a keepalive control frame — proves the
        // tunnel is alive; refresh the liveness timestamp the watchdog reads.
        entry._lastRx = Date.now();
        if (typeof ev.data === 'string') {
            let ctl = null;
            try { ctl = JSON.parse(ev.data); } catch (e) {}
            // Server keepalive ping (relay idle heartbeat) — consume it, never
            // write it to the terminal.
            if (ctl && ctl.type === 'ping') return;
            if (ctl && ctl.type === 'downgraded') {
                entry.ro = true;
                upd('Connected (read-only) — control taken over', 'text-amber-400');
                showToast(`Console control for ${label} was taken over by another user`, 'warning');
                return;
            }
            term.write(ev.data);
        }
        else term.write(new Uint8Array(ev.data));
    };
    ws.onclose = (ev) => {
        // A reconnect deliberately closes the old socket first; don't paint a
        // scary "[disconnected]" for that superseded socket.
        if (ws._superseded) return;
        try { term.write(`\r\n\x1b[33m[disconnected${ev.reason ? ': ' + ev.reason : ''}] — click Reconnect to resume\x1b[0m\r\n`); } catch (e) {}
        upd('Disconnected' + (ev.reason ? ': ' + ev.reason : ''), 'text-red-400');
    };
    serialEnsureHeartbeatWatch();
    return ws;
}

// Re-establish a dropped console onto its EXISTING terminal (keeps scrollback)
// by minting a fresh session for the same port and re-attaching the socket —
// the "Reconnect" affordance so a disconnect doesn't force a close/reopen.
async function serialReconnectConsole(key) {
    const reg = window._serialConsoles;
    const entry = reg && reg.get(key);
    if (!entry) return;
    if (entry.ws && (entry.ws.readyState === 0 || entry.ws.readyState === 1)) {
        showToast(`Console for ${entry.label || entry.portId} is still connected`, 'info');
        return;
    }
    // Retire the old socket so its onclose can't repaint "[disconnected]".
    if (entry.ws) { try { entry.ws._superseded = true; entry.ws.close(); } catch (e) {} }
    entry.statusText = 'Reconnecting…'; entry.statusCls = 'text-amber-400';
    serialRenderConsoleList(); serialSyncSerialHeader();
    let session;
    try {
        const res = await fetch('/api/console/open', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: entry.spokeId, port_id: entry.portId, mode: 'rw' }),
        });
        session = await res.json().catch(() => ({}));
        if (!res.ok) {
            entry.statusText = 'Reconnect failed: ' + (session.detail || res.status);
            entry.statusCls = 'text-red-400';
            serialRenderConsoleList(); serialSyncSerialHeader();
            showToast(session.detail || 'Reconnect failed', 'error');
            return;
        }
    } catch (e) {
        entry.statusText = 'Reconnect failed';
        entry.statusCls = 'text-red-400';
        serialRenderConsoleList(); serialSyncSerialHeader();
        showToast('Reconnect failed: ' + e.message, 'error');
        return;
    }
    try { entry.term.write('\r\n\x1b[36m[reconnecting…]\x1b[0m\r\n'); } catch (e) {}
    serialAttachWs(entry, session);
    serialFitConsole(entry);
    if (window._serialActiveConsole === key) { try { entry.term.focus(); } catch (e) {} }
}

// Show one tab's console, hide the rest (their WS stays open). Re-renders the
// tab strip + header and focuses the active terminal for keyboard input.
function serialActivateConsole(key) {
    window._serialActiveConsole = key;
    serialReflowBodies();
    serialRenderConsoleList();
    serialSyncSerialHeader();
    const c = window._serialConsoles && window._serialConsoles.get(key);
    if (c && c.term) { try { c.term.focus(); c.term.scrollToBottom(); } catch (e) {} }
}

// Build the display label for an available console port — same precedence as
// the Console port table: operator alias > auto-identified hostname > USB
// product string > raw device node.
function _serialPortLabel(p) {
    const identHost = (p.probe && p.probe.identity && p.probe.identity.hostname) || '';
    return p.alias || identHost || p.product || p.device || p.port_id || '';
}

// Pull the full set of console ports the current user has rights to (tenant-
// scoped + rights-filtered server-side) into `_consolePorts`, then repaint the
// dock's left menu. This is what lets the left menu act as a directory of
// EVERY console you can connect to — not just the ones already open. Silently
// keeps the last-known list on error (the menu still shows open sessions).
async function serialRefreshAvailablePorts() {
    try {
        const res = await fetch(`/api/console/ports?tenant=${encodeURIComponent(currentTenant || 'default')}`,
                                { credentials: 'same-origin' });
        if (res.ok) {
            const data = await res.json();
            _consolePorts = data.ports || [];
        }
    } catch (e) { /* keep last-known list */ }
    serialRenderConsoleList();
}

// Paint the left-side console menu. It lists EVERY console the user has rights
// to (from `_consolePorts`), merged with the OPEN sessions
// (window._serialConsoles) so open ones are flagged connected — colored status
// dot, RO badge, broadcast checkbox, and a close button — while the rest are
// click-to-open (a "+" affordance). Filtered by the search box, which now
// searches the whole available directory, not just what's already open.
// Replaces the old open-only strip so an operator can browse and connect to
// any authorized console from here.
function serialRenderConsoleList() {
    const modal = document.getElementById('serial-console-modal');
    if (!modal) return;
    const list = modal.querySelector('#serial-console-list');
    if (!list) return;
    const active = window._serialActiveConsole;
    const group = window._serialBroadcastGroup;
    const filter = window._serialConsoleFilter || '';
    const open = window._serialConsoles || new Map();

    // Merge available ports (the directory) with open sessions, keyed by
    // spoke::port. Available ports seed the rows; open sessions overlay their
    // live state onto the matching row (or add a row of their own if the port
    // isn't in the available list yet — e.g. ports not loaded / other tenant).
    const byKey = new Map();
    (_consolePorts || []).forEach(p => {
        const key = (p.spoke_id || '') + '::' + p.port_id;
        byKey.set(key, {
            key, spokeId: p.spoke_id || '', portId: p.port_id,
            label: _serialPortLabel(p), reachable: !(p.present === false || p.stale),
            inUse: !!p.in_use, open: false, entry: null,
        });
    });
    open.forEach((e, key) => {
        const row = byKey.get(key) || { key, spokeId: e.spokeId, portId: e.portId,
            label: e.label, reachable: true, inUse: false };
        row.open = true; row.entry = e; row.label = e.label || row.label;
        byKey.set(key, row);
    });

    let rows = Array.from(byKey.values());
    const total = rows.length;
    if (filter) rows = rows.filter(r => (r.label || r.portId || r.key || '').toLowerCase().includes(filter));
    // Connected consoles first (keep active sessions at the top), then the rest,
    // each alphabetized by label.
    rows.sort((a, b) => ((b.open ? 1 : 0) - (a.open ? 1 : 0)) || (a.label || '').localeCompare(b.label || ''));

    list.innerHTML = rows.length ? rows.map(r => {
        const e = r.entry;
        const isA = r.open && r.key === active;
        const dot = r.open
            ? (e.statusCls === 'text-green-400' ? 'bg-green-400'
               : (e.statusCls === 'text-red-400' ? 'bg-red-400' : 'bg-amber-400'))
            : (r.reachable ? 'bg-slate-500' : 'bg-slate-700');
        const rowCls = isA ? 'bg-[#1e1e1e] text-slate-100'
            : (r.open || r.reachable ? 'text-slate-400 hover:bg-[#222] hover:text-slate-200'
                                     : 'text-slate-600');
        const label = escapeHtml(r.label || r.portId || r.key);
        const kAttr = escapeHtml(r.key);
        const sAttr = escapeHtml(r.spokeId);
        const pAttr = escapeHtml(r.portId);
        const roBadge = (r.open && e.ro) ? '<span class="ml-1 px-1 rounded bg-amber-600 text-white text-[9px]">RO</span>' : '';
        const stateBadge = r.open ? ''
            : (r.reachable
                ? (r.inUse ? '<span class="ml-1 px-1 rounded bg-amber-700 text-amber-100 text-[9px]">IN USE</span>' : '')
                : '<span class="ml-1 px-1 rounded bg-slate-700 text-slate-300 text-[9px]">OFFLINE</span>');
        const inGroup = !!(group && group.has(r.key));
        const lead = r.open
            ? `<input type="checkbox" data-bcast-key="${kAttr}" ${inGroup ? 'checked' : ''} title="Include in broadcast group" onclick="event.stopPropagation()">`
            : `<span class="w-[13px] shrink-0 text-center ${r.reachable ? 'text-slate-500' : 'text-slate-700'}" title="${r.reachable ? 'Click to open' : 'Device offline'}">+</span>`;
        const closeBtn = r.open
            ? `<button data-close="${kAttr}" title="Close this console" class="text-slate-500 hover:text-red-400 text-sm leading-none shrink-0">&times;</button>`
            : '';
        // A dropped-but-still-open console gets an inline Reconnect on its row,
        // so it can be resumed without switching to it first.
        const reconnectBtn = (r.open && e.statusCls === 'text-red-400')
            ? `<button data-reconnect="${kAttr}" title="Reconnect this console (keeps scrollback)" class="text-slate-500 hover:text-green-400 text-sm leading-none shrink-0">⟳</button>`
            : '';
        const cursor = (r.open || r.reachable) ? 'cursor-pointer' : 'cursor-not-allowed';
        return `<div data-key="${kAttr}" data-open="${r.open ? '1' : '0'}" data-reachable="${r.reachable ? '1' : '0'}" data-spoke="${sAttr}" data-port="${pAttr}" data-label="${label}"
            class="serial-console-row flex items-center gap-2 px-3 py-2 border-b border-[#232323] ${cursor} text-xs ${rowCls}">
            ${lead}
            <span class="w-2 h-2 rounded-full ${dot} shrink-0"></span>
            <span class="font-mono truncate flex-1">${label}</span>${roBadge}${stateBadge}
            ${reconnectBtn}
            ${closeBtn}
        </div>`;
    }).join('') : `<div class="px-3 py-4 text-xs text-slate-500 italic">${total ? 'No consoles match your search.' : 'No consoles available.'}</div>`;

    list.querySelectorAll('.serial-console-row').forEach(el => {
        const key = el.getAttribute('data-key');
        const isOpen = el.getAttribute('data-open') === '1';
        el.onclick = (ev) => {
            if (ev.target.closest('[data-close]') || ev.target.closest('[data-reconnect]') || ev.target.matches('input[type=checkbox]')) return;
            if (isOpen) { serialActivateConsole(key); return; }
            if (el.getAttribute('data-reachable') !== '1') {
                showToast('Device not connected — reconnect it to open a session', 'warning');
                return;
            }
            openConsoleTerminal(el.getAttribute('data-spoke'), el.getAttribute('data-port'), el.getAttribute('data-label'));
        };
        const closeBtn = el.querySelector('[data-close]');
        if (closeBtn) closeBtn.onclick = (ev) => { ev.stopPropagation(); serialCloseConsole(key); };
        const reconnectBtn = el.querySelector('[data-reconnect]');
        if (reconnectBtn) reconnectBtn.onclick = (ev) => { ev.stopPropagation(); serialReconnectConsole(key); };
        const cb = el.querySelector('input[data-bcast-key]');
        if (cb) cb.onclick = (ev) => {
            ev.stopPropagation();
            if (!window._serialBroadcastGroup) window._serialBroadcastGroup = new Set();
            if (cb.checked) window._serialBroadcastGroup.add(key); else window._serialBroadcastGroup.delete(key);
            serialReflowBodies();
            serialSyncSerialHeader();
            serialUpdateBroadcastBar();
            serialRenderConsoleList();
        };
    });
}

// Sync the header status line to the active console's state.
function serialSyncSerialHeader() {
    const modal = document.getElementById('serial-console-modal');
    if (!modal) return;
    const statusEl = modal.querySelector('#serial-console-status');
    if (!statusEl) return;
    const c = serialActiveConsole();
    let txt = '';
    if (c) {
        txt = (c.label || c.portId || '') + ' — ' + c.statusText;
        if (c.session && c.session.settings && c.session.settings.baud) txt += '  @' + c.session.settings.baud;
    }
    const bgroup = window._serialBroadcastGroup;
    if (window._serialBroadcastOn && bgroup && bgroup.size >= 2) {
        txt += `  · ⇄ broadcasting to ${bgroup.size} consoles`;
    }
    statusEl.textContent = txt;
    statusEl.className = 'ml-auto text-xs ' + (c ? c.statusCls : 'text-slate-400');
    const toBtn = modal.querySelector('#serial-console-takeover');
    if (toBtn) toBtn.classList.toggle('hidden', !(c && c.ro));
    // Offer Reconnect whenever the active console's socket is closed/closing —
    // resumes on the same terminal instead of forcing a close/reopen.
    const rcBtn = modal.querySelector('#serial-console-reconnect');
    if (rcBtn) {
        const dead = !!(c && (!c.ws || c.ws.readyState === 2 || c.ws.readyState === 3));
        rcBtn.classList.toggle('hidden', !dead);
    }
    serialRenderDockPill();
}

// Force-takeover: claim the write lock for the active console's session,
// evicting whoever currently holds it. Server-gated to edit-tier regardless
// of what /api/console/open itself required.
async function serialForceTakeover() {
    const c = serialActiveConsole();
    if (!c) return;
    const btn = document.getElementById('serial-console-takeover');
    if (btn) { btn.disabled = true; btn.textContent = 'Taking over…'; }
    try {
        const res = await fetch(`/api/console/${encodeURIComponent(c.session.session_id)}/takeover`, {
            method: 'POST', credentials: 'same-origin',
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'Takeover failed', 'error'); return; }
        c.ro = false;
        c.statusText = 'Connected (you have control)';
        c.statusCls = 'text-green-400';
        showToast(`Console control taken over for ${c.label || c.portId}`, 'success');
        serialRenderConsoleList();
        serialSyncSerialHeader();
    } catch (e) {
        showToast('Takeover failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Take Over'; }
    }
}

// Collapse (minimize) or restore the whole console dock WITHOUT closing any
// session: every WebSocket + xterm stays live in the DOM, the dock is just
// hidden and replaced by a small footer pill so the operator can browse the
// rest of the UI while their consoles keep streaming. Restoring re-lays-out
// the active terminal (an xterm that was display:none can measure 0×0).
function serialSetDockCollapsed(collapsed) {
    window._serialDockCollapsed = !!collapsed;
    const modal = document.getElementById('serial-console-modal');
    if (modal) modal.classList.toggle('hidden', !!collapsed);
    serialRenderDockPill();
    if (!collapsed && modal) {
        serialReflowBodies();
        const c = serialActiveConsole();
        if (c && c.term) { try { c.term.focus(); c.term.scrollToBottom(); } catch (e) {} }
        try { window.dispatchEvent(new Event('resize')); } catch (e) {}
    }
}

// Paint (or remove) the minimized-dock pill. Shown only while the dock is
// collapsed AND at least one console is open; it surfaces the live count +
// active console + an aggregate status dot, restores the dock on click, and
// carries its own close-all affordance. Rendered inline in the footer slot
// (#footer-console-slot, between "Enterprise Edition" and the Hub Status
// icon); if that slot is missing (e.g. a stale cached index.html) it falls
// back to a floating fixed pill so the feature still works.
function serialRenderDockPill() {
    const slot = document.getElementById('footer-console-slot');
    const reg = window._serialConsoles;
    const count = reg ? reg.size : 0;
    let pill = document.getElementById('serial-console-dock-pill');
    if (!window._serialDockCollapsed || count === 0) { if (pill) pill.remove(); return; }
    const inFooterCls = 'flex items-center gap-2 px-2 py-0.5 rounded-full border border-slate-500 ' +
                        'text-[11px] text-white/90 hover:border-white transition-all';
    const floatCls = 'fixed bottom-2 right-4 z-50 flex items-center gap-2 px-3 py-1.5 rounded-full ' +
                     'bg-[#181818] border border-slate-600 shadow-2xl text-xs text-slate-200';
    if (!pill) {
        pill = document.createElement('div');
        pill.id = 'serial-console-dock-pill';
    }
    // (Re)home the pill into the footer slot when present, else float it.
    if (slot) {
        if (pill.parentElement !== slot) { pill.className = inFooterCls; slot.appendChild(pill); }
    } else if (pill.parentElement !== document.body) {
        pill.className = floatCls; document.body.appendChild(pill);
    }
    let anyGreen = false, anyRed = false;
    reg.forEach(e => { if (e.statusCls === 'text-green-400') anyGreen = true; else if (e.statusCls === 'text-red-400') anyRed = true; });
    const dot = anyGreen ? 'bg-green-400' : (anyRed ? 'bg-red-400' : 'bg-amber-400');
    const active = serialActiveConsole();
    const activeTxt = active ? escapeHtml(active.label || active.portId || '') : '';
    pill.innerHTML = `
        <button data-expand title="Restore the serial console dock" class="flex items-center gap-2 hover:text-white">
            <span class="w-2 h-2 rounded-full ${dot}"></span>
            <span>🖥 ${count} console${count > 1 ? 's' : ''}${activeTxt ? ' · ' + activeTxt : ''}</span>
            <span class="text-slate-400 leading-none">▴</span>
        </button>
        <button data-closeall title="Close all consoles" class="text-slate-500 hover:text-red-400 text-sm leading-none">&times;</button>`;
    pill.querySelector('[data-expand]').onclick = () => serialSetDockCollapsed(false);
    pill.querySelector('[data-closeall]').onclick = (ev) => { ev.stopPropagation(); serialCloseAllConsoles(); };
}

// Close one serial console: close its WS, dispose the xterm, drop its body +
// registry entry, then activate a sibling (or tear the dock down when last).
function serialCloseConsole(key) {
    const reg = window._serialConsoles;
    if (!reg) return;
    const e = reg.get(key);
    if (e) {
        try { if (e.resizeObserver) e.resizeObserver.disconnect(); } catch (err) {}
        try { if (e.ws) e.ws.close(); } catch (err) {}
        try { if (e.term) e.term.dispose(); } catch (err) {}
        if (e.bodyEl) e.bodyEl.remove();
        reg.delete(key);
    }
    if (reg.size === 0) { serialCloseAllConsoles(); return; }
    if (window._serialBroadcastGroup) window._serialBroadcastGroup.delete(key);
    if (window._serialActiveConsole === key) {
        serialActivateConsole(reg.keys().next().value);
    } else {
        serialRenderConsoleList();
        serialReflowBodies();
    }
    serialUpdateBroadcastBar();
}

// Close every serial console and remove the dock.
function serialCloseAllConsoles() {
    const reg = window._serialConsoles;
    if (reg) {
        reg.forEach(e => { try { if (e.resizeObserver) e.resizeObserver.disconnect(); } catch (err) {} try { if (e.ws) e.ws.close(); } catch (err) {} try { if (e.term) e.term.dispose(); } catch (err) {} });
        reg.clear();
    }
    window._serialActiveConsole = null;
    window._serialBroadcastGroup = null;
    window._serialBroadcastOn = false;
    window._serialConsoleFilter = '';
    window._serialDockCollapsed = false;
    // Sidebar width/collapsed preference deliberately survives a close — it's
    // a layout choice, not session state, so reopening later keeps it. Only
    // the transient drag flag is reset, in case consoles closed mid-drag.
    window._serialSidebarDragging = false;
    document.body.style.userSelect = '';
    if (window._serialHeartbeatTimer) { clearInterval(window._serialHeartbeatTimer); window._serialHeartbeatTimer = null; }
    const pill = document.getElementById('serial-console-dock-pill');
    if (pill) pill.remove();
    const modal = document.getElementById('serial-console-modal');
    if (modal) modal.remove();
    if (typeof currentView !== 'undefined' && currentView === 'console' && typeof loadConsoleData === 'function') loadConsoleData();
}

// Backward-compatible alias: older callers used a single-modal serial terminal.
function closeConsoleTerminal() { serialCloseAllConsoles(); }

function openConsoleSettingsModal(spokeId, portId) {
    const p = _consolePorts.find(x => x.port_id === portId && x.spoke_id === spokeId) || {};
    const s = p.settings || {};
    const bauds = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400];
    const baudOpts = bauds.map(b => `<option value="${b}" ${Number(s.baud) === b ? 'selected' : ''}>${b}</option>`).join('');
    const parOpts = ['N', 'E', 'O'].map(x => `<option value="${x}" ${(s.parity || 'N') === x ? 'selected' : ''}>${x}</option>`).join('');
    const flowOpts = ['none', 'rtscts', 'xonxoff'].map(x => `<option value="${x}" ${(s.flow || 'none') === x ? 'selected' : ''}>${x}</option>`).join('');
    // Direct Port Access: show the endpoint and let the operator pin this serial
    // port to a specific TCP port (blank = auto-assign). Only when DPA is on.
    const d = p.dpa || {};
    const dpaField = (proto, cur, pinned, label) => `<div><label class="text-[11px] text-slate-500">${label} port <span class="text-slate-400">(current ${escapeHtml(String(cur))}${pinned ? ', pinned' : ', auto'})</span></label>
                <input id="console-cfg-dpa-${proto}" type="number" min="1024" max="65535" placeholder="auto" value="${pinned ? escapeHtml(String(cur)) : ''}" data-orig="${pinned ? escapeHtml(String(cur)) : ''}" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></div>`;
    const dpaSection = (d.ssh_port || d.telnet_port) ? `<div class="pt-2 border-t border-slate-100">
            <div class="text-xs text-slate-500 uppercase font-bold mb-1">Direct Port Access <span class="normal-case text-slate-400 font-normal">— leave blank to auto-assign</span></div>
            ${d.ssh_port ? `<div class="text-[11px] font-mono text-sky-700 mb-1">${escapeHtml(_consoleDpaSshCmd(p))}</div>` : ''}
            <div class="grid grid-cols-2 gap-3">
              ${d.ssh_port ? dpaField('ssh', d.ssh_port, d.ssh_override, 'SSH') : ''}
              ${d.telnet_port ? dpaField('telnet', d.telnet_port, d.telnet_override, 'Telnet') : ''}
            </div>
          </div>` : '';
    const modal = document.createElement('div');
    modal.id = 'console-settings-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Port Settings</h3>
          <button onclick="this.closest('#console-settings-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-4">
          <div class="text-xs font-mono text-slate-400">${escapeHtml(portId)}</div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">Alias</label>
            <input id="console-cfg-alias" value="${(p.alias || '').replace(/"/g, '&quot;')}" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></div>
          <div class="grid grid-cols-3 gap-3">
            <div><label class="text-xs text-slate-500 uppercase font-bold">Baud</label><select id="console-cfg-baud" class="w-full border border-slate-300 rounded-md px-2 py-2 text-sm mt-1">${baudOpts}</select></div>
            <div><label class="text-xs text-slate-500 uppercase font-bold">Parity</label><select id="console-cfg-parity" class="w-full border border-slate-300 rounded-md px-2 py-2 text-sm mt-1">${parOpts}</select></div>
            <div><label class="text-xs text-slate-500 uppercase font-bold">Flow</label><select id="console-cfg-flow" class="w-full border border-slate-300 rounded-md px-2 py-2 text-sm mt-1">${flowOpts}</select></div>
          </div>
          <div class="pt-2 border-t border-slate-100">
            <div class="text-xs text-slate-500 uppercase font-bold mb-1">Paste pacing <span class="normal-case text-slate-400 font-normal">— slows large pastes so slow devices don't drop lines</span></div>
            <div class="grid grid-cols-2 gap-3">
              <div><label class="text-[11px] text-slate-500">Delay after each line (ms)</label>
                <input id="console-cfg-linedelay" type="number" min="0" max="2000" value="${Number.isFinite(+s.paste_line_delay_ms) ? +s.paste_line_delay_ms : 15}" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></div>
              <div><label class="text-[11px] text-slate-500">Chunk size (bytes)</label>
                <input id="console-cfg-chunk" type="number" min="1" max="4096" value="${Number.isFinite(+s.paste_chunk) ? +s.paste_chunk : 64}" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></div>
            </div>
          </div>
          ${dpaSection}
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#console-settings-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="saveConsoleSettings('${spokeId.replace(/'/g, "\\'")}','${portId.replace(/'/g, "\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">Save</button>
          </div>
        </div></div>`;
    document.body.appendChild(modal);
}

async function saveConsoleSettings(spokeId, portId) {
    const alias = document.getElementById('console-cfg-alias').value;
    const body = {
        spoke_id: spokeId, port_id: portId,
        baud: parseInt(document.getElementById('console-cfg-baud').value, 10),
        parity: document.getElementById('console-cfg-parity').value,
        flow: document.getElementById('console-cfg-flow').value,
        paste_line_delay_ms: parseInt(document.getElementById('console-cfg-linedelay').value, 10) || 0,
        paste_chunk: parseInt(document.getElementById('console-cfg-chunk').value, 10) || 64,
    };
    try {
        // Alias is a separate command on the spoke; send it first if changed.
        await fetch('/api/console/settings', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId, alias }),
        });
        const res = await fetch('/api/console/settings', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        for (const proto of ['ssh', 'telnet']) {
            const inp = document.getElementById(`console-cfg-dpa-${proto}`);
            if (!inp || inp.value.trim() === (inp.dataset.orig || '')) continue;
            const v = inp.value.trim();
            const r = await fetch('/api/console/dpa-port', {
                method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ spoke_id: spokeId, port_id: portId, proto, port: v ? parseInt(v, 10) : null }),
            });
            if (!r.ok) {
                const d = await r.json().catch(() => ({}));
                showToast(`DPA ${proto} port: ${d.detail || 'override failed'}`, 'error');
                return;
            }
        }
        if (res.ok) { showToast('Settings saved', 'success'); document.getElementById('console-settings-modal')?.remove(); loadConsoleData(); }
        else { const d = await res.json().catch(() => ({})); showToast(d.detail || 'Save failed', 'error'); }
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

// Direct Port Access knob (admin): per console agent, persisted on the agent
// and applied live. The SSH password is write-only (never read back).
function openConsoleDpaModal() {
  const existing = document.getElementById('console-dpa-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'console-dpa-modal';
  modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
  modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
    <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
      <h3 class="text-lg font-bold text-[#263040]">Direct Port Access</h3>
      <button onclick="this.closest('#console-dpa-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
    </div>
    <div class="p-6 space-y-4">
      <div><label class="text-xs text-slate-500 uppercase font-bold">Spoke</label>
        <select id="dpa-spoke" onchange="_consoleDpaLoad(this.value)" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></select></div>
      <div id="dpa-status" class="text-xs text-slate-500"></div>
      <div><label class="flex items-center space-x-2">
        <input type="checkbox" id="dpa-enabled" class="rounded">
        <span class="text-sm">Enable Direct Port Access</span>
      </label></div>
      <div><label class="flex items-center space-x-2">
        <input type="checkbox" id="dpa-ssh-enabled" class="rounded">
        <span class="text-sm">SSH (authenticated, encrypted)</span>
      </label>
      <div class="ml-6 mt-1 grid grid-cols-2 gap-2">
        <div><label class="text-xs text-slate-500">Bind address</label>
          <input id="dpa-ssh-bind" placeholder="0.0.0.0" class="w-full border border-slate-300 rounded-md px-3 py-1 text-sm"></div>
        <div><label class="text-xs text-slate-500">Base port</label>
          <input id="dpa-ssh-base" type="number" placeholder="3001" class="w-full border border-slate-300 rounded-md px-3 py-1 text-sm"></div>
      </div></div>
      <div><label class="flex items-center space-x-2">
        <input type="checkbox" id="dpa-telnet-enabled" class="rounded">
        <span class="text-sm">Telnet (unauthenticated — keep on 127.0.0.1)</span>
      </label>
      <div class="ml-6 mt-1 grid grid-cols-2 gap-2">
        <div><label class="text-xs text-slate-500">Bind address</label>
          <input id="dpa-telnet-bind" placeholder="127.0.0.1" class="w-full border border-slate-300 rounded-md px-3 py-1 text-sm"></div>
        <div><label class="text-xs text-slate-500">Base port</label>
          <input id="dpa-telnet-base" type="number" placeholder="2200" class="w-full border border-slate-300 rounded-md px-3 py-1 text-sm"></div>
      </div></div>
      <div><label class="text-xs text-slate-500 uppercase font-bold">Advertise host</label>
        <input id="dpa-advertise-host" placeholder="auto-detect" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
        <div class="text-xs text-slate-500 mt-1">Address shown to users in the ssh command (leave blank to auto-detect)</div></div>
      <div><label class="text-xs text-slate-500 uppercase font-bold">Allow from</label>
        <input id="dpa-allow" placeholder="source IPs/CIDRs, comma-separated (blank = any)" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></div>
      <div><label class="text-xs text-slate-500 uppercase font-bold">Password</label>
        <input id="dpa-password" type="password" autocomplete="new-password" placeholder="leave blank to keep current" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1">
        <div><label class="flex items-center space-x-2 mt-1">
          <input type="checkbox" id="dpa-clear-password" class="rounded">
          <span class="text-sm">Remove password</span>
        </label></div></div>
      <div><label class="text-xs text-slate-500 uppercase font-bold">Authorized SSH keys</label>
        <textarea id="dpa-keys" rows="3" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm font-mono mt-1 text-xs" placeholder="authorized SSH public keys, one per line"></textarea></div>
      <div class="pt-3 flex justify-end gap-3">
        <button onclick="this.closest('#console-dpa-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
        <button onclick="saveConsoleDpa()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">Save</button>
      </div>
    </div></div>`;
  document.body.appendChild(modal);

  const spokeSelect = modal.querySelector('#dpa-spoke');
  // Every connected console server (admin list from the hub), so a server with
  // no port visible under the current tenant can still have DPA enabled.
  _consoleDpaSpokes.forEach(({ spoke_id, name }) => {
    const option = document.createElement('option');
    option.value = spoke_id;
    option.textContent = name || spoke_id;
    spokeSelect.appendChild(option);
  });

  if (_consoleDpaSpokes.length > 0) {
    _consoleDpaLoad(_consoleDpaSpokes[0].spoke_id);
  }
}

async function _consoleDpaLoad(spokeId) {
  const statusEl = document.getElementById('dpa-status');
  try {
    const res = await fetch(`/api/console/dpa?spoke_id=${encodeURIComponent(spokeId)}`, {credentials:'same-origin'});
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      statusEl.textContent = d.detail || 'Failed to load';
      return;
    }
    const data = await res.json();

    const config = data.config;
    const status = data.runtime || {};

    document.getElementById('dpa-enabled').checked = !!config.enabled;
    document.getElementById('dpa-ssh-enabled').checked = !!config.ssh_enabled;
    document.getElementById('dpa-telnet-enabled').checked = !!config.telnet_enabled;
    document.getElementById('dpa-ssh-bind').value = config.ssh_bind || '';
    document.getElementById('dpa-ssh-base').value = config.ssh_base ? String(config.ssh_base) : '';
    document.getElementById('dpa-telnet-bind').value = config.telnet_bind || '';
    document.getElementById('dpa-telnet-base').value = config.telnet_base ? String(config.telnet_base) : '';
    document.getElementById('dpa-advertise-host').value = config.advertise_host || '';
    document.getElementById('dpa-allow').value = (config.allow || []).join(', ');
    document.getElementById('dpa-password').value = '';
    document.getElementById('dpa-clear-password').checked = false;
    document.getElementById('dpa-keys').value = config.authorized_keys || '';

    let statusText = `Password: ${config.has_password ? 'set' : 'not set'} · Advertised host: ${escapeHtml(status.advertise_host || '?')} · Listeners: ssh ${status.ssh_listeners}, telnet ${status.telnet_listeners}`;
    if (status.host_key_fingerprint) {
      statusText += ` · Host key: ${escapeHtml(status.host_key_fingerprint)}`;
    }
    if (!status.ssh_available && status.ssh_error) {
      statusText += ` · <span class="text-red-600">SSH unavailable: ${escapeHtml(status.ssh_error)}</span>`;
    }

    statusEl.innerHTML = statusText;
  } catch (e) {
    statusEl.textContent = 'Load failed: ' + e.message;
  }
}

async function saveConsoleDpa() {
  const spokeId = document.getElementById('dpa-spoke').value;
  const enabled = document.getElementById('dpa-enabled').checked;
  const sshEnabled = document.getElementById('dpa-ssh-enabled').checked;
  const telnetEnabled = document.getElementById('dpa-telnet-enabled').checked;
  const sshBind = document.getElementById('dpa-ssh-bind').value.trim();
  const telnetBind = document.getElementById('dpa-telnet-bind').value.trim();
  const advertiseHost = document.getElementById('dpa-advertise-host').value.trim();
  const sshBase = parseInt(document.getElementById('dpa-ssh-base').value);
  const telnetBase = parseInt(document.getElementById('dpa-telnet-base').value);
  const allow = document.getElementById('dpa-allow').value.split(/[, ]+/).map(s => s.trim()).filter(Boolean);
  const authorizedKeys = document.getElementById('dpa-keys').value;

  const body = {
    spoke_id: spokeId,
    enabled,
    ssh_enabled: sshEnabled,
    telnet_enabled: telnetEnabled,
    ssh_bind: sshBind,
    telnet_bind: telnetBind,
    advertise_host: advertiseHost,
    allow,
    authorized_keys: authorizedKeys
  };

  if (sshBase && !isNaN(sshBase)) body.ssh_base = sshBase;
  if (telnetBase && !isNaN(telnetBase)) body.telnet_base = telnetBase;

  const passwordValue = document.getElementById('dpa-password').value;
  if (passwordValue) {
    body.password = passwordValue;
  }

  if (document.getElementById('dpa-clear-password').checked) {
    body.clear_password = true;
  }

  try {
    const res = await fetch('/api/console/dpa', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (res.ok) {
      showToast('Direct Port Access saved', 'success');
      document.getElementById('console-dpa-modal').remove();
      loadConsoleData();
    } else {
      const d = await res.json().catch(() => ({}));
      showToast(d.detail || 'Save failed', 'error');
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, 'error');
  }
}

async function openConsolePortTenantModal(spokeId, portId, currentTenantId) {
    // Reassigning a port to another tenant is a GLOBAL-admin action only — a
    // tenant admin (or any non-global-admin) must not be able to move a device
    // between tenants. The row button is already hidden for them; guard here too
    // in case the modal is ever invoked another way. The server also enforces it.
    if (!isAdmin()) { showToast('Only a global admin can reassign a port to another tenant.', 'error'); return; }
    const modal = document.createElement('div');
    modal.id = 'console-port-tenant-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    let tenantOptions = '';
    try {
        const res = await setupFetch('/setup/tenants');
        if (res.ok) {
            const tenants = (await res.json()).tenants || [];
            tenantOptions = tenants.map(t => `<option value="${t.id}" ${t.id === currentTenantId ? 'selected' : ''}>${escapeHtml(t.name)}</option>`).join('');
        }
    } catch (e) { console.error('tenant fetch failed', e); }
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Assign Port to Tenant</h3>
          <button onclick="this.closest('#console-port-tenant-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-4">
          <div class="text-xs font-mono text-slate-400">${escapeHtml(portId)}</div>
          <p class="text-[11px] text-slate-400">A per-port override. Leave <b>(inherit agent)</b> to fall back to the whole console agent's tenant.</p>
          <select id="console-port-tenant" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm">
            <option value="" ${!currentTenantId ? 'selected' : ''}>(inherit agent)</option>${tenantOptions}
          </select>
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#console-port-tenant-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="saveConsolePortTenant('${spokeId.replace(/'/g, "\\'")}','${portId.replace(/'/g, "\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">Assign</button>
          </div>
        </div></div>`;
    _mountModal(modal);
}

async function saveConsolePortTenant(spokeId, portId) {
    if (!isAdmin()) { showToast('Only a global admin can reassign a port to another tenant.', 'error'); return; }
    const tenantId = document.getElementById('console-port-tenant').value;
    try {
        const res = await fetch('/api/console/tenant', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId, tenant_id: tenantId }),
        });
        if (res.ok) { showToast('Port tenant updated', 'success'); document.getElementById('console-port-tenant-modal')?.remove(); loadConsoleData(); }
        else { const d = await res.json().catch(() => ({})); showToast(d.detail || 'Assign failed', 'error'); }
    } catch (e) { showToast('Assign failed: ' + e.message, 'error'); }
}

function openConsoleConfigModal(spokeId, portId) {
    const eS = spokeId.replace(/'/g, "\\'"), eP = portId.replace(/'/g, "\\'");
    const modal = document.createElement('div');
    modal.id = 'console-config-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden flex flex-col" style="max-height:85vh">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Device Config — ${escapeHtml(portId)}</h3>
          <button onclick="this.closest('#console-config-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-3 overflow-y-auto">
          <p class="text-[11px] text-slate-400">Requires the device to have been Identified. Push is transactional — verify before + after, save on success, roll back on failure (a failed push is never saved).</p>
          <button onclick="consoleConfigBackup('${eS}','${eP}')" class="text-[11px] px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50">⤓ Read / backup running-config</button>
          <textarea id="console-config-text" rows="10" placeholder="Paste config to push (one command per line)…" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm font-mono"></textarea>
          <div class="flex items-center gap-4 text-sm flex-wrap">
            <label class="flex items-center gap-2"><input type="checkbox" id="console-config-save" checked class="rounded border-slate-300"> Save to startup on success</label>
            <label class="flex items-center gap-2">Rollback on fail:
              <select id="console-config-rollback" class="border border-slate-300 rounded px-2 py-1 text-sm"><option value="negate">no &lt;command&gt;</option><option value="reboot">reboot</option></select></label>
          </div>
          <pre id="console-config-output" class="text-xs bg-slate-900 text-slate-100 rounded-md p-3 overflow-auto hidden" style="max-height:240px"></pre>
          <div class="pt-2 flex justify-end gap-3">
            <button onclick="this.closest('#console-config-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Close</button>
            <button onclick="consoleConfigPush('${eS}','${eP}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">Push config</button>
          </div>
        </div></div>`;
    document.body.appendChild(modal);
}

function _consoleConfigOut(text, isErr) {
    const el = document.getElementById('console-config-output');
    if (!el) return;
    el.classList.remove('hidden');
    el.textContent = text;
    el.classList.toggle('text-red-300', !!isErr);
}

async function consoleConfigBackup(spokeId, portId) {
    _consoleConfigOut('Reading running-config…', false);
    try {
        const res = await fetch('/api/console/config/get', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok && d.status === 'SUCCESS') _consoleConfigOut(d.config || '(empty)', false);
        else _consoleConfigOut(d.message || d.detail || 'Backup failed', true);
    } catch (e) { _consoleConfigOut('Backup failed: ' + e.message, true); }
}

async function consoleConfigPush(spokeId, portId) {
    const config = document.getElementById('console-config-text').value;
    if (!config.trim()) { showToast('Nothing to push', 'error'); return; }
    _consoleConfigOut('Pushing + verifying…', false);
    try {
        const res = await fetch('/api/console/config/push', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                spoke_id: spokeId, port_id: portId, config,
                save: document.getElementById('console-config-save').checked,
                rollback: document.getElementById('console-config-rollback').value,
            }),
        });
        const d = await res.json().catch(() => ({}));
        const summary = `status: ${d.status}\nverify_ok: ${d.verify_ok}   saved: ${d.saved}   rolled_back: ${d.rolled_back}\n`
            + ((d.errors && d.errors.length) ? `errors:\n${d.errors.map(e => '  ' + e.line + ' → ' + (e.output || '')).join('\n')}\n` : '')
            + ((d.missing && d.missing.length) ? `missing after push:\n  ${d.missing.join('\n  ')}\n` : '')
            + (d.message ? '\n' + d.message : '');
        _consoleConfigOut(summary, d.status !== 'SUCCESS');
        showToast(d.status === 'SUCCESS' ? 'Config pushed + saved' : 'Push failed — rolled back',
                  d.status === 'SUCCESS' ? 'success' : 'error');
    } catch (e) { _consoleConfigOut('Push failed: ' + e.message, true); }
}

// VNC console opener (agent-terminates-WSS): POST /api/pxmx/console to mint a
// one-shot session, then open a modal hosting noVNC whose RFB connects to the
// hub's /ws/console/{session_id}?token=... byte relay. The hub relays browser
// bytes → agent (VNC_FRAME_DOWN) and Proxmox bytes → browser (VNC_FRAME_UP);
// the agent owns the Proxmox vncwebsocket (local root-authed token). noVNC is
// loaded once from CDN and cached on window.__noVNCRFB.
async function pxmxOpenConsole(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('VM not found in cache', 'error'); return; }
    // Already open? Don't mint a second session — just surface the console dock
    // and switch to that VM's existing tab.
    if (window._pxmxConsoles && window._pxmxConsoles.has(vm.unique_id)) {
        pxmxEnsureConsoleDock();
        pxmxActivateConsole(vm.unique_id);
        pxmxSetDockCollapsed(false);
        showToast(`Console for ${vm.name || vm.vmid} is already open`, 'info');
        return;
    }
    // Immediate feedback — the agent opens the Proxmox vncwebsocket + mints the
    // first-use VNC token, which can take several seconds on a busy host.
    showToast(`Connecting to console for ${vm.name || vm.vmid}…`, 'info');
    const _btn = document.getElementById('pxmx-vm-console-btn');
    const _btnHtml = _btn ? _btn.innerHTML : null;
    if (_btn) { _btn.disabled = true; _btn.innerHTML = '⏳ Connecting…'; }
    const _restoreBtn = () => { if (_btn && _btnHtml != null) { _btn.disabled = false; _btn.innerHTML = _btnHtml; } };
    let session;
    try {
        const r = await setupFetch('/api/pxmx/console', {
            method: 'POST',
            body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type || 'qemu', agent_id: vm.agent_id || '' }),
        });
        session = await r.json().catch(() => ({}));
        if (!r.ok || !session || !session.session_id) {
            _restoreBtn();
            showToast('Console start failed: ' + (session && (session.detail || session.message) || r.status), 'error');
            return;
        }
    } catch (e) {
        _restoreBtn();
        showToast('Console start failed: ' + (e.message || e), 'error');
        return;
    }
    const RFB = await pxmxLoadNoVNC();
    if (!RFB) { _restoreBtn(); showToast('Failed to load noVNC (CDN unreachable)', 'error'); return; }
    _restoreBtn();
    pxmxAddConsoleTab(vm, RFB, session);
}

// Load noVNC's RFB from CDN once, cache on window.__noVNCRFB. Mirrors the
// upstream cs reference (.scratch-shpe/cs-webui/templates/index.html:10).
let _pxmxNoVncPromise = null;
function pxmxLoadNoVNC() {
    if (window.__noVNCRFB) return Promise.resolve(window.__noVNCRFB);
    if (!_pxmxNoVncPromise) {
        _pxmxNoVncPromise = import('https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0/core/rfb.js')
            .then(m => { window.__noVNCRFB = m.RFB || m.default; return window.__noVNCRFB; })
            .catch(e => { console.error('noVNC load failed', e); _pxmxNoVncPromise = null; return null; });
    }
    return _pxmxNoVncPromise;
}

// ── Tabbed VM-console dock ──────────────────────────────────────────────────
// A single in-browser window hosting EVERY open console session as a tab, so an
// operator can keep several VM consoles connected at once and switch between
// them without dropping any. Each session's noVNC RFB renders into its own body
// div; inactive bodies are hidden (display:none) but their WebSocket stays open,
// so switching tabs is instant and non-destructive. Registry: window._pxmxConsoles
// (Map<unique_id, {vm, session, rfb, bodyEl, statusText, statusCls}>);
// window._pxmxActiveConsole holds the visible tab's key.

// Create (or reveal) the shared console dock shell. Idempotent — the list
// and bodies persist across opens; only wired once. Full-screen panel bounded
// by the header (top-16), footer (bottom-10), and left nav sidebar (left-56,
// index.html) — occupies the same box <main> does. A left-side search +
// scrollable list (pxmxRenderConsoleList) replaces the old horizontal tab
// strip, which became unusable once more than a handful of consoles were open.
function pxmxEnsureConsoleDock() {
    let modal = document.getElementById('pxmx-vnc-modal');
    if (modal) { modal.classList.remove('hidden'); return modal; }
    modal = document.createElement('div');
    modal.id = 'pxmx-vnc-modal';
    modal.className = 'fixed top-16 bottom-10 left-56 right-0 z-40 flex bg-[#1a1a2e] border-t border-slate-700 shadow-2xl';
    modal.innerHTML = `
        <div id="pxmx-vnc-sidebar" class="shrink-0 flex flex-col border-r border-slate-700 bg-[#141428] overflow-hidden">
            <div class="p-2 border-b border-slate-700 space-y-2 w-72">
                <div class="flex items-center justify-between">
                    <strong class="text-sm text-slate-200">VM Consoles</strong>
                    <button id="pxmx-vnc-closeall" title="Close all consoles" class="text-slate-400 hover:text-red-400 text-lg leading-none">&times;</button>
                </div>
                <div class="flex items-center gap-1">
                    <input id="pxmx-vnc-search" type="text" placeholder="Search VMs to open…"
                           class="flex-1 min-w-0 text-xs bg-[#1a1a2e] border border-slate-600 rounded px-2 py-1 text-slate-100 focus:outline-none focus:border-sky-500">
                    <button id="pxmx-vnc-refresh" title="Refresh the searchable VM directory (only VMs you have rights to)" class="shrink-0 text-slate-400 hover:text-sky-400 text-sm leading-none px-1">⟳</button>
                </div>
                <p class="text-[10px] text-slate-500 leading-tight">Type to search any VNC-capable VM you can access; empty shows only open consoles.</p>
            </div>
            <div id="pxmx-vnc-list" class="flex-1 overflow-y-auto w-72"></div>
        </div>
        <div id="pxmx-vnc-resize-handle" title="Drag to resize — collapse to fit two consoles side-by-side"
             class="w-1.5 shrink-0 cursor-col-resize bg-slate-700 hover:bg-sky-500 active:bg-sky-500 relative">
            <button id="pxmx-vnc-sidebar-collapse" title="Collapse/expand the console list"
                    class="absolute top-2 -left-2 w-4 h-8 flex items-center justify-center rounded-sm bg-slate-700 hover:bg-sky-600 text-slate-300 hover:text-white text-[10px] leading-none">◂</button>
        </div>
        <div class="flex-1 flex flex-col min-w-0">
            <div class="flex items-center gap-3 px-4 py-2 bg-[#16213e] border-b border-slate-700 text-slate-200 text-sm">
                <button id="pxmx-vnc-min" title="Minimize to the footer — keeps every session connected so you can browse the rest of the UI" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">▁ Minimize</button>
                <button id="pxmx-vnc-cad" title="Send Ctrl+Alt+Del to the active console" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">Ctrl+Alt+Del</button>
                <button id="pxmx-vnc-reconnect" title="Reconnect the active console — mints a fresh session and reattaches in the same tab, without disturbing the other open consoles" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">⟳ Reconnect</button>
                <button id="pxmx-vnc-fs" title="Fullscreen the active console" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">Fullscreen</button>
                <button id="pxmx-vnc-takeover" title="Take over write control from the other user" class="px-2 py-0.5 text-xs rounded border border-amber-500 text-amber-400 hover:bg-amber-900/40 hidden">Take Over</button>
                <span id="pxmx-vnc-status" class="ml-auto text-xs text-amber-400"></span>
            </div>
            <div id="pxmx-vnc-bodies" class="relative flex-1 bg-black overflow-hidden"></div>
        </div>`;
    document.body.appendChild(modal);
    modal.querySelector('#pxmx-vnc-takeover').onclick = () => pxmxForceTakeover();
    modal.querySelector('#pxmx-vnc-min').onclick = () => pxmxSetDockCollapsed(true);
    modal.querySelector('#pxmx-vnc-cad').onclick = () => { const c = pxmxActiveConsole(); if (c && c.rfb) c.rfb.sendCtrlAltDel(); };
    modal.querySelector('#pxmx-vnc-reconnect').onclick = () => pxmxReconnectConsole();
    modal.querySelector('#pxmx-vnc-fs').onclick = () => {
        const c = pxmxActiveConsole();
        const screen = c && c.bodyEl;
        if (document.fullscreenElement) document.exitFullscreen();
        else if (screen && screen.requestFullscreen) screen.requestFullscreen().catch(() => {});
    };
    modal.querySelector('#pxmx-vnc-closeall').onclick = () => pxmxCloseAllConsoles();
    modal.querySelector('#pxmx-vnc-search').addEventListener('input', (ev) => {
        window._pxmxConsoleFilter = ev.target.value.trim().toLowerCase();
        // Lazily pull the rights-scoped VM directory the first time the operator
        // actually types — the empty state deliberately stays "open consoles
        // only", so there's no reason to fetch the (potentially huge) inventory
        // until they search for something to open.
        if (window._pxmxConsoleFilter) pxmxRefreshConsoleDir(false);
        pxmxRenderConsoleList();
    });
    modal.querySelector('#pxmx-vnc-refresh').onclick = () => pxmxRefreshConsoleDir(true);
    // Sidebar starts at its remembered width (session-only — resets on a full
    // page reload) so reopening the dock keeps the operator's preferred split
    // instead of resetting to the default every time. Collapsing it (rather
    // than closing sessions) is what makes room to view the console body
    // without the VM list eating into the split.
    modal.querySelector('#pxmx-vnc-sidebar-collapse').onclick = () =>
        pxmxSetSidebarCollapsed(!window._pxmxSidebarCollapsed);
    pxmxSetSidebarCollapsed(!!window._pxmxSidebarCollapsed);
    modal.querySelector('#pxmx-vnc-resize-handle').addEventListener('mousedown', (ev) => {
        // A mousedown on the collapse button shouldn't also start a drag.
        if (ev.target.closest('#pxmx-vnc-sidebar-collapse')) return;
        window._pxmxSidebarDragging = true;
        document.body.style.userSelect = 'none';
        ev.preventDefault();
    });
    _pxmxWireSidebarResize();
    return modal;
}

// Expand/collapse the VM console LIST specifically (distinct from
// pxmxSetDockCollapsed, which minimizes the WHOLE dock to a footer pill).
// Collapsing just hides the browse-and-search sidebar, reclaiming its width
// for the console body area. No sessions are affected either way.
function pxmxSetSidebarCollapsed(collapsed) {
    window._pxmxSidebarCollapsed = !!collapsed;
    const modal = document.getElementById('pxmx-vnc-modal');
    if (!modal) return;
    const sidebar = modal.querySelector('#pxmx-vnc-sidebar');
    const btn = modal.querySelector('#pxmx-vnc-sidebar-collapse');
    if (sidebar) sidebar.style.width = collapsed ? '0px' : ((window._pxmxSidebarWidth || 288) + 'px');
    if (btn) { btn.textContent = collapsed ? '▸' : '◂'; btn.title = collapsed ? 'Expand the console list' : 'Collapse the console list'; }
}

// Drag-to-resize wiring for the sidebar — attached to `document` ONCE (guarded
// by a flag) rather than per dock-open, since the dock's DOM (and any
// listeners bound to ITS elements) is destroyed on close; a document-level
// listener would otherwise accumulate a stale copy every reopen. Looks up the
// current dock elements by id on every move rather than closing over them, so
// it naturally no-ops once the dock (or its drag) is gone.
function _pxmxWireSidebarResize() {
    if (window._pxmxResizeWired) return;
    window._pxmxResizeWired = true;
    const MIN_W = 160, MAX_W = 560;
    document.addEventListener('mousemove', (ev) => {
        if (!window._pxmxSidebarDragging) return;
        const modal = document.getElementById('pxmx-vnc-modal');
        const sidebar = document.getElementById('pxmx-vnc-sidebar');
        if (!modal || !sidebar) return;
        const w = Math.max(MIN_W, Math.min(MAX_W, ev.clientX - modal.getBoundingClientRect().left));
        window._pxmxSidebarWidth = w;
        window._pxmxSidebarCollapsed = false;
        sidebar.style.width = w + 'px';
        const btn = document.getElementById('pxmx-vnc-sidebar-collapse');
        if (btn) { btn.textContent = '◂'; btn.title = 'Collapse the console list'; }
    });
    document.addEventListener('mouseup', () => {
        if (!window._pxmxSidebarDragging) return;
        window._pxmxSidebarDragging = false;
        document.body.style.userSelect = '';
    });
}

// The registry entry for the currently visible tab (or null).
function pxmxActiveConsole() {
    return (window._pxmxConsoles && window._pxmxActiveConsole)
        ? window._pxmxConsoles.get(window._pxmxActiveConsole) : null;
}

// Mint a console tab: build its body div, attach a noVNC RFB, register it, and
// make it the active tab. Mirrors the old single-modal RFB wiring (ticket →
// VNC password, status events) but per-session.
function pxmxAddConsoleTab(vm, RFB, session) {
    if (!window._pxmxConsoles) window._pxmxConsoles = new Map();
    const key = vm.unique_id || String(session.session_id);
    const modal = pxmxEnsureConsoleDock();
    const bodies = modal.querySelector('#pxmx-vnc-bodies');
    const bodyEl = document.createElement('div');
    bodyEl.className = 'absolute inset-0 bg-black';
    bodyEl.setAttribute('data-console-key', key);
    bodies.appendChild(bodyEl);
    const ro = !!session.read_only;
    const entry = { key, vm, session, ro, rfb: null, bodyEl, statusText: 'Connecting…', statusCls: 'text-amber-400', viewers: [] };
    window._pxmxConsoles.set(key, entry);
    pxmxAttachRfb(entry, RFB);
    pxmxStartViewerPoll(entry);
    pxmxActivateConsole(key);
    pxmxSetDockCollapsed(false);
}

// Attach a fresh noVNC RFB to an existing console registry entry, wiring it
// against the entry's CURRENT session (session_id/ws_token/ticket). Shared by
// the initial tab creation and Reconnect so both use identical status,
// credential, and relay-URL handling — the one place the RFB contract lives.
function pxmxAttachRfb(entry, RFB) {
    const session = entry.session;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${location.host}/ws/console/${encodeURIComponent(session.session_id)}?token=${encodeURIComponent(session.ws_token)}`;
    const upd = (text, cls) => { entry.statusText = text; entry.statusCls = cls; pxmxRenderConsoleList(); pxmxSyncConsoleHeader(); if (window._pxmxDockCollapsed) pxmxRenderDockPill(); };
    try {
        // Proxmox's vncwebsocket ticket doubles as the RFB VNC password — the
        // agent mints it and the hub returns it in the /api/pxmx/console
        // response. noVNC must present it during the RFB security handshake or
        // Proxmox drops the session ("Security failure" / blank console).
        const vncPassword = (session && session.ticket) || '';
        const rfb = new RFB(entry.bodyEl, wsUrl, { credentials: { password: vncPassword } });
        rfb.scaleViewport = true;
        rfb.resizeSession = false;
        rfb.viewOnly = entry.ro;
        rfb.addEventListener('connect', () => upd(entry.ro ? 'Connected (read-only)' : 'Connected', 'text-green-400'));
        rfb.addEventListener('disconnect', (e) => upd('Disconnected: ' + ((e.detail && e.detail.reason) || 'closed'), 'text-red-400'));
        rfb.addEventListener('credentialsrequired', () => {
            // Ticket already supplied above; if Proxmox still asks, re-send it
            // rather than prompting the user for a password they don't have.
            if (vncPassword) rfb.sendCredentials({ password: vncPassword });
        });
        rfb.addEventListener('securityfailure', (e) => upd('Security failure: ' + ((e.detail && e.detail.reason) || 'unknown'), 'text-red-400'));
        entry.rfb = rfb;
    } catch (err) {
        entry.statusText = 'Error: ' + (err.message || err); entry.statusCls = 'text-red-400';
        entry.rfb = null;
    }
}

// Reconnect the active (or given) console IN PLACE: tear down its current RFB,
// mint a FRESH console session (the old ws_token/ticket are one-shot and are
// dead after a drop), and reattach a new noVNC RFB into the SAME tab/body. A
// console that dropped (agent restart, network blip, Proxmox idle timeout, or a
// takeover) comes back without losing its tab — and, critically, without
// touching any of the OTHER open consoles in the dock.
async function pxmxReconnectConsole(key) {
    const reg = window._pxmxConsoles;
    if (!reg) return;
    const entry = key ? reg.get(key) : pxmxActiveConsole();
    if (!entry) return;
    const vm = entry.vm || {};
    const btn = document.getElementById('pxmx-vnc-reconnect');
    if (btn) { btn.disabled = true; }
    // Drop the old RFB + clear the stale framebuffer so we don't stack a second
    // canvas in the same body.
    try { if (entry.rfb) entry.rfb.disconnect(); } catch (e) {}
    entry.rfb = null;
    if (entry.bodyEl) entry.bodyEl.innerHTML = '';
    entry.statusText = 'Reconnecting…'; entry.statusCls = 'text-amber-400';
    pxmxRenderConsoleList(); pxmxSyncConsoleHeader();
    try {
        const RFB = await pxmxLoadNoVNC();
        if (!RFB) {
            entry.statusText = 'Reconnect failed: noVNC unavailable'; entry.statusCls = 'text-red-400';
            showToast('Failed to load noVNC (CDN unreachable)', 'error');
            return;
        }
        const r = await setupFetch('/api/pxmx/console', {
            method: 'POST',
            body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type || 'qemu', agent_id: vm.agent_id || '' }),
        });
        const session = await r.json().catch(() => ({}));
        if (!r.ok || !session || !session.session_id) {
            entry.statusText = 'Reconnect failed: ' + ((session && (session.detail || session.message)) || r.status);
            entry.statusCls = 'text-red-400';
            showToast('Console reconnect failed', 'error');
            return;
        }
        entry.session = session;
        entry.ro = !!session.read_only;
        pxmxAttachRfb(entry, RFB);
        showToast(`Reconnecting console for ${vm.name || vm.vmid || ''}…`, 'info');
        if (entry.key === window._pxmxActiveConsole) pxmxRescaleConsole(entry);
    } catch (e) {
        entry.statusText = 'Reconnect failed: ' + (e.message || e); entry.statusCls = 'text-red-400';
        showToast('Console reconnect failed: ' + (e.message || e), 'error');
    } finally {
        if (btn) { btn.disabled = false; }
        pxmxRenderConsoleList(); pxmxSyncConsoleHeader();
    }
}

// Multiuser presence: poll who else is on this VM's console. Each viewer holds
// their own VNC session (QEMU multiplexes them onto one shared screen), so the
// roster lets a user see when a teammate is looking at / driving the same VM.
function pxmxStartViewerPoll(entry) {
    const poll = async () => {
        try {
            const vm = entry.vm || {};
            const qs = `unique_id=${encodeURIComponent(vm.unique_id || entry.key)}` +
                (vm.agent_id ? `&agent_id=${encodeURIComponent(vm.agent_id)}` : '');
            const r = await setupFetch(`/api/pxmx/console/viewers?${qs}`);
            const data = await r.json().catch(() => ({}));
            entry.viewers = (data && Array.isArray(data.viewers)) ? data.viewers : [];
            // Piggyback on the presence poll to notice a takeover elsewhere:
            // if OUR session held the write lock and no longer does, flip to
            // view-only live (there's no separate push channel for VNC — the
            // RFB object owns its WebSocket for the raw binary protocol, so a
            // side-band text frame isn't an option the way it is for serial).
            const self = entry.viewers.find(v => v.session_id === entry.session.session_id);
            if (self && entry.rfb && !self.is_writer && !entry.ro) {
                entry.ro = true;
                entry.rfb.viewOnly = true;
                entry.statusText = 'Connected (read-only) — control taken over';
                entry.statusCls = 'text-amber-400';
                showToast(`Console control for ${vm.name || vm.vmid || ''} was taken over by another user`, 'warning');
            }
        } catch (e) {
            entry.viewers = entry.viewers || [];
        }
        if (window._pxmxConsoles && window._pxmxConsoles.get(entry.key)) {
            pxmxRenderConsoleList();
            if (entry.key === window._pxmxActiveConsole) pxmxSyncConsoleHeader();
        }
    };
    poll();
    entry.presenceTimer = setInterval(poll, 5000);
}

// Force-takeover: claim the write lock for the active console's session,
// evicting whoever currently holds it. Server-gated to edit-tier + VM
// ownership regardless of what opening a read-only session required.
async function pxmxForceTakeover() {
    const c = pxmxActiveConsole();
    if (!c) return;
    const btn = document.getElementById('pxmx-vnc-takeover');
    if (btn) { btn.disabled = true; btn.textContent = 'Taking over…'; }
    try {
        const res = await setupFetch(`/api/pxmx/console/${encodeURIComponent(c.session.session_id)}/takeover`, {
            method: 'POST',
            body: JSON.stringify({ agent_id: (c.vm && c.vm.agent_id) || '' }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'Takeover failed', 'error'); return; }
        c.ro = false;
        if (c.rfb) c.rfb.viewOnly = false;
        c.statusText = 'Connected (you have control)';
        c.statusCls = 'text-green-400';
        showToast(`Console control taken over for ${(c.vm && (c.vm.name || c.vm.vmid)) || ''}`, 'success');
        pxmxRenderConsoleList();
        pxmxSyncConsoleHeader();
    } catch (e) {
        showToast('Takeover failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Take Over'; }
    }
}

// Show one tab's console, hide the rest (their WS stays open). Re-renders the
// tab strip + header and focuses the active console for keyboard input.
function pxmxActivateConsole(key) {
    window._pxmxActiveConsole = key;
    if (window._pxmxConsoles) {
        window._pxmxConsoles.forEach((e, k) => { if (e.bodyEl) e.bodyEl.classList.toggle('hidden', k !== key); });
    }
    pxmxRenderConsoleList();
    pxmxSyncConsoleHeader();
    const c = window._pxmxConsoles && window._pxmxConsoles.get(key);
    if (c && c.rfb && c.rfb.focus) { try { c.rfb.focus(); } catch (e) {} }
    // A body hidden via display:none reports 0×0, so nudging noVNC in the same
    // tick we un-hide it races the browser's layout and can leave the
    // framebuffer scaled to nothing — the "blank on switch-back" bug. Rescale on
    // the next frame, once the newly visible body actually has dimensions.
    pxmxRescaleConsole(c);
}

// Force one console's noVNC to rescale + re-present its framebuffer after its
// body becomes visible again (tab switch or dock restore). The body it renders
// into was display:none while inactive, so it reports 0×0 until the browser
// lays it out; a synchronous resize therefore scales the retained framebuffer
// bitmap to nothing (blank). We defer to an animation frame, wait until the body
// has real dimensions (retrying a few frames if needed), then toggle
// scaleViewport so noVNC recomputes the scale against the now-correct container
// size and re-presents the (still-intact) pixels.
function pxmxRescaleConsole(entry, tries) {
    if (!entry || !entry.rfb || !entry.bodyEl) return;
    requestAnimationFrame(() => {
        if (!window._pxmxConsoles || !window._pxmxConsoles.get(entry.key)) return;
        const el = entry.bodyEl;
        if ((el.clientWidth === 0 || el.clientHeight === 0) && (tries || 0) < 10) {
            pxmxRescaleConsole(entry, (tries || 0) + 1);
            return;
        }
        try {
            const rfb = entry.rfb;
            if ('scaleViewport' in rfb) { rfb.scaleViewport = false; rfb.scaleViewport = true; }
        } catch (e) {}
        try { window.dispatchEvent(new Event('resize')); } catch (e) {}
    });
}

// Is this VM one that can actually have a noVNC console? Mirrors the VM-table
// gating (pxmxVmTableHtml): LXC containers and templates have no VNC console,
// so the search picker must not offer to "open" one for them. Template
// membership uses the same pool set the directory fetch cached.
function pxmxVmIsVncCapable(vm) {
    if (!vm) return false;
    if (String(vm.type || '').toLowerCase() === 'lxc') return false;
    const pools = window._pxmxConsoleDirTemplatePools || window._pxmxTemplatePools || [];
    const isTpl = !!(vm.template || (vm.pool && pools.includes(String(vm.pool).toLowerCase())));
    return !isTpl;
}

// Lazily fetch + cache the rights-scoped VM directory that powers the console
// search picker. Reuses the SAME endpoint loadPxmxData uses — /api/pxmx/vms is
// already tenant-scoped + rights-filtered server-side, so the client never sees
// a VM the caller can't access (and the console-open itself is separately
// authorized server-side; this is just the UX affordance). Cached on
// window._pxmxConsoleDirVms; `force` bypasses the cache (the ⟳ button).
async function pxmxRefreshConsoleDir(force) {
    if (window._pxmxConsoleDirLoading) return;
    if (window._pxmxConsoleDirVms && !force) return;
    window._pxmxConsoleDirLoading = true;
    const btn = document.getElementById('pxmx-vnc-refresh');
    if (btn) btn.classList.add('animate-spin');
    try {
        const res = await fetch(`/api/pxmx/vms?tenant=${encodeURIComponent(currentTenant)}`,
                                { credentials: 'same-origin', _keepOnNavigate: true });
        if (res.ok) {
            const data = await res.json();
            window._pxmxConsoleDirVms = data.vms || [];
            window._pxmxConsoleDirTemplatePools = (data.template_pools || []).map(p => String(p).toLowerCase());
        }
    } catch (e) { /* keep last-known directory */ }
    finally {
        window._pxmxConsoleDirLoading = false;
        if (btn) btn.classList.remove('animate-spin');
    }
    pxmxRenderConsoleList();
}

// Open a console for a VM chosen from the search picker (a directory row that
// isn't open yet). pxmxOpenConsole resolves the VM from window._pxmxVms, which
// may not have been populated if the operator opened the dock without visiting
// the VM table first — so seed the chosen VM into that cache before delegating.
function pxmxOpenConsoleFromDir(key) {
    const vm = (window._pxmxConsoleDirVms || []).find(v => (v.unique_id || String(v.vmid)) === key);
    if (!vm) { showToast('VM not found', 'error'); return; }
    if (!window._pxmxVms) window._pxmxVms = [];
    if (!window._pxmxVms.some(v => v.unique_id === vm.unique_id)) window._pxmxVms.push(vm);
    pxmxOpenConsole(vm.unique_id || key);
}

// Paint the left-side console list. When the search box is EMPTY it lists ONLY
// the open console sessions (status dot, name, viewer/RO badges, close button) —
// deliberately NOT the whole VM inventory (unlike the serial dock, which lists
// its full directory by default; the user asked for search-only here because
// there are too many VMs to enumerate). When the operator TYPES a query it also
// folds in the rights-scoped, VNC-capable VM directory (window._pxmxConsoleDirVms)
// as click-to-open rows (a "+" affordance) so they can search for and connect to
// any VM they can access. Replaces the old horizontal tab strip.
function pxmxRenderConsoleList() {
    const modal = document.getElementById('pxmx-vnc-modal');
    if (!modal) return;
    const list = modal.querySelector('#pxmx-vnc-list');
    if (!list) return;
    const active = window._pxmxActiveConsole;
    const filter = window._pxmxConsoleFilter || '';
    const open = window._pxmxConsoles || new Map();

    // Merge open sessions with (only when searching) the VM directory, keyed by
    // VM unique_id. Open sessions always seed rows; directory rows are added
    // only under an active search and never override an already-open row.
    const byKey = new Map();
    open.forEach((e, key) => { byKey.set(key, { key, open: true, entry: e, vm: e.vm || {} }); });
    if (filter) {
        (window._pxmxConsoleDirVms || []).forEach(vm => {
            if (!pxmxVmIsVncCapable(vm)) return;
            const key = vm.unique_id || String(vm.vmid);
            if (byKey.has(key)) return;   // already open — the open row wins
            byKey.set(key, { key, open: false, entry: null, vm });
        });
    }

    let rows = Array.from(byKey.values());
    if (filter) {
        rows = rows.filter(r => {
            const vm = r.vm || {};
            return [vm.name, vm.vmid, vm.node, vm.cluster, r.key]
                .some(f => String(f == null ? '' : f).toLowerCase().includes(filter));
        });
    }
    // Open consoles first (keep live sessions at the top), then click-to-open
    // directory rows; each group alphabetized by display name.
    const nameOf = r => String((r.vm && (r.vm.name || r.vm.vmid)) || r.key || '');
    rows.sort((a, b) => ((b.open ? 1 : 0) - (a.open ? 1 : 0)) || nameOf(a).localeCompare(nameOf(b)));

    let emptyMsg;
    if (filter) {
        emptyMsg = (window._pxmxConsoleDirLoading && !window._pxmxConsoleDirVms)
            ? 'Searching…' : 'No consoles match your search.';
    } else {
        emptyMsg = 'No open consoles. Type above to search VMs to open.';
    }

    list.innerHTML = rows.length ? rows.map(r => {
        const vm = r.vm || {};
        const kAttr = escapeHtml(r.key);
        const label = escapeHtml(vm.name || vm.vmid || r.key);
        if (r.open) {
            const e = r.entry;
            const isA = r.key === active;
            const dot = e.statusCls === 'text-green-400' ? 'bg-green-400'
                : (e.statusCls === 'text-red-400' ? 'bg-red-400' : 'bg-amber-400');
            const rowCls = isA ? 'bg-[#1a1a2e] text-slate-100' : 'text-slate-400 hover:bg-[#1a1a30] hover:text-slate-200';
            const vc = (e.viewers && e.viewers.length) || 0;
            const viewerBadge = vc > 1
                ? `<span title="${vc} viewers on this console" class="ml-1 px-1 rounded bg-[#01A982]/20 text-[#01A982] text-[10px]">👁 ${vc}</span>`
                : '';
            const roBadge = e.ro ? '<span class="ml-1 px-1 rounded bg-amber-600 text-white text-[9px]">RO</span>' : '';
            return `<div data-key="${kAttr}" data-open="1" class="pxmx-vnc-row flex items-center gap-2 px-3 py-2 border-b border-[#1f1f38] cursor-pointer text-xs ${rowCls}">
                <span class="w-2 h-2 rounded-full ${dot} shrink-0"></span>
                <span class="truncate flex-1">${label}</span>${viewerBadge}${roBadge}
                <button data-reconnect="${kAttr}" title="Reconnect this console" class="text-slate-500 hover:text-sky-400 text-sm leading-none shrink-0">⟳</button>
                <button data-close="${kAttr}" title="Close this console" class="text-slate-500 hover:text-red-400 text-sm leading-none shrink-0">&times;</button>
            </div>`;
        }
        // Directory row — not open yet, click to open. Stopped VMs still open a
        // console fine, so keep them clickable and just flag the power state.
        const running = String(vm.status || '').toLowerCase() === 'running';
        const stateBadge = running
            ? '<span class="ml-1 px-1 rounded bg-green-900/50 text-green-300 text-[9px]">RUNNING</span>'
            : '<span class="ml-1 px-1 rounded bg-slate-700 text-slate-300 text-[9px]">STOPPED</span>';
        return `<div data-key="${kAttr}" data-open="0" title="Open a noVNC console to this VM" class="pxmx-vnc-row flex items-center gap-2 px-3 py-2 border-b border-[#1f1f38] cursor-pointer text-xs text-slate-400 hover:bg-[#1a1a30] hover:text-slate-200">
            <span class="w-[13px] shrink-0 text-center text-slate-500">+</span>
            <span class="w-2 h-2 rounded-full ${running ? 'bg-green-500' : 'bg-slate-600'} shrink-0"></span>
            <span class="truncate flex-1">${label}</span>${stateBadge}
        </div>`;
    }).join('') : `<div class="px-3 py-4 text-xs text-slate-500 italic">${emptyMsg}</div>`;

    list.querySelectorAll('.pxmx-vnc-row').forEach(el => {
        const key = el.getAttribute('data-key');
        const isOpen = el.getAttribute('data-open') === '1';
        el.onclick = (ev) => {
            if (ev.target.closest('[data-close]')) return;
            if (ev.target.closest('[data-reconnect]')) return;
            if (isOpen) { pxmxActivateConsole(key); return; }
            pxmxOpenConsoleFromDir(key);
        };
        const closeBtn = el.querySelector('[data-close]');
        if (closeBtn) closeBtn.onclick = (ev) => { ev.stopPropagation(); pxmxCloseConsole(key); };
        const reconnectBtn = el.querySelector('[data-reconnect]');
        if (reconnectBtn) reconnectBtn.onclick = (ev) => { ev.stopPropagation(); pxmxReconnectConsole(key); };
    });
}

// Sync the header status line to the active console's state.
function pxmxSyncConsoleHeader() {
    const modal = document.getElementById('pxmx-vnc-modal');
    if (!modal) return;
    const statusEl = modal.querySelector('#pxmx-vnc-status');
    if (!statusEl) return;
    const c = pxmxActiveConsole();
    let txt = c ? ((c.vm.name || c.vm.vmid || '') + ' — ' + c.statusText) : '';
    if (c && c.viewers && c.viewers.length > 1) {
        const names = c.viewers.map(v => v.username || '?').filter(Boolean);
        txt += `  · 👁 ${c.viewers.length} viewers` + (names.length ? ` (${names.join(', ')})` : '');
    }
    statusEl.textContent = txt;
    statusEl.className = 'ml-auto text-xs ' + (c ? c.statusCls : 'text-slate-400');
    const toBtn = modal.querySelector('#pxmx-vnc-takeover');
    if (toBtn) toBtn.classList.toggle('hidden', !(c && c.ro));
}

// Close one console: disconnect its RFB (→ hub VNC_DISCONNECT → agent drops the
// Proxmox WSS), drop its body + registry entry, then activate a sibling (or tear
// the dock down when it was the last one).
function pxmxCloseConsole(key) {
    const reg = window._pxmxConsoles;
    if (!reg) return;
    const e = reg.get(key);
    if (e) {
        if (e.presenceTimer) { try { clearInterval(e.presenceTimer); } catch (err) {} }
        try { if (e.rfb) e.rfb.disconnect(); } catch (err) {}
        if (e.bodyEl) e.bodyEl.remove();
        reg.delete(key);
    }
    if (reg.size === 0) { pxmxCloseAllConsoles(); return; }
    if (window._pxmxActiveConsole === key) {
        pxmxActivateConsole(reg.keys().next().value);
    } else {
        pxmxRenderConsoleList();
    }
    pxmxRenderDockPill();
}

// Collapse the VM-console dock to a footer pill (or restore it). Non-destructive
// — every noVNC RFB stays connected while hidden, exactly like pressing
// Minimize; the footer pill (pxmxRenderDockPill) restores it. Mirrors
// serialSetDockCollapsed for the serial console dock.
function pxmxSetDockCollapsed(collapsed) {
    window._pxmxDockCollapsed = !!collapsed;
    const modal = document.getElementById('pxmx-vnc-modal');
    if (modal) modal.classList.toggle('hidden', !!collapsed);
    pxmxRenderDockPill();
    if (!collapsed && modal) {
        const c = pxmxActiveConsole();
        if (c && c.rfb && c.rfb.focus) { try { c.rfb.focus(); } catch (e) {} }
        // A body hidden while minimized reports 0×0, so noVNC's scaleViewport is
        // stale on restore — rescale on the next frame (once it has dimensions)
        // rather than with a racy synchronous resize, else it restores blank.
        pxmxRescaleConsole(c);
    }
}

// Paint (or remove) the minimized VM-console dock pill. Shown only while the
// dock is collapsed AND at least one console is open; surfaces the live count +
// active VM + an aggregate status dot, restores the dock on click, and carries
// its own close-all affordance. Rendered inline in the footer slot
// (#footer-console-slot, shared with the serial-console pill); if that slot is
// missing it falls back to a floating fixed pill. Mirrors serialRenderDockPill.
function pxmxRenderDockPill() {
    const slot = document.getElementById('footer-console-slot');
    const reg = window._pxmxConsoles;
    const count = reg ? reg.size : 0;
    let pill = document.getElementById('pxmx-vnc-dock-pill');
    if (!window._pxmxDockCollapsed || count === 0) { if (pill) pill.remove(); return; }
    const inFooterCls = 'flex items-center gap-2 px-2 py-0.5 rounded-full border border-slate-500 ' +
                        'text-[11px] text-white/90 hover:border-white transition-all';
    const floatCls = 'fixed bottom-2 right-4 z-50 flex items-center gap-2 px-3 py-1.5 rounded-full ' +
                     'bg-[#181818] border border-slate-600 shadow-2xl text-xs text-slate-200';
    if (!pill) {
        pill = document.createElement('div');
        pill.id = 'pxmx-vnc-dock-pill';
    }
    if (slot) {
        if (pill.parentElement !== slot) { pill.className = inFooterCls; slot.appendChild(pill); }
    } else if (pill.parentElement !== document.body) {
        pill.className = floatCls; document.body.appendChild(pill);
    }
    let anyGreen = false, anyRed = false;
    reg.forEach(e => { if (e.statusCls === 'text-green-400') anyGreen = true; else if (e.statusCls === 'text-red-400') anyRed = true; });
    const dot = anyGreen ? 'bg-green-400' : (anyRed ? 'bg-red-400' : 'bg-amber-400');
    const active = pxmxActiveConsole();
    const activeTxt = active ? escapeHtml((active.vm && (active.vm.name || active.vm.vmid)) || '') : '';
    pill.innerHTML = `
        <button data-expand title="Restore the VM console dock" class="flex items-center gap-2 hover:text-white">
            <span class="w-2 h-2 rounded-full ${dot}"></span>
            <span>🖥 ${count} VM console${count > 1 ? 's' : ''}${activeTxt ? ' · ' + activeTxt : ''}</span>
            <span class="text-slate-400 leading-none">▴</span>
        </button>
        <button data-closeall title="Close all consoles" class="text-slate-500 hover:text-red-400 text-sm leading-none">&times;</button>`;
    pill.querySelector('[data-expand]').onclick = () => pxmxSetDockCollapsed(false);
    pill.querySelector('[data-closeall]').onclick = (ev) => { ev.stopPropagation(); pxmxCloseAllConsoles(); };
}

// Close every console and remove the dock.
function pxmxCloseAllConsoles() {
    const reg = window._pxmxConsoles;
    if (reg) {
        reg.forEach(e => { if (e.presenceTimer) { try { clearInterval(e.presenceTimer); } catch (err) {} } try { if (e.rfb) e.rfb.disconnect(); } catch (err) {} });
        reg.clear();
    }
    window._pxmxActiveConsole = null;
    window._pxmxConsoleFilter = '';
    window._pxmxDockCollapsed = false;
    const pill = document.getElementById('pxmx-vnc-dock-pill');
    if (pill) pill.remove();
    const modal = document.getElementById('pxmx-vnc-modal');
    if (modal) modal.remove();
}

// Render the clickable Nodes table; the selected row is highlighted.
// Short Proxmox version for table display: 'pve-manager/9.2.3/abc123' -> '9.2.3'.
// Falls back to the raw string if no N.N.N group is found, or '' when absent.
function pxmxShortVer(v) {
    if (v == null || v === '') return '';
    const m = String(v).match(/(\d+\.\d+\.\d+)/);
    return m ? m[1] : String(v);
}

// Cluster vs standalone badge beside a Proxmox node name (icon 101 Server Stack
// when clustered, 121 Server when standalone). Clustered = a real cluster name
// distinct from the node's own name (the agent sets cluster_name == hostname for
// a standalone host, so cluster === node means "not clustered").
function pxmxClusterBadge(n) {
    const clustered = !!(n && n.cluster && String(n.cluster) !== String(n.node));
    const title = clustered ? 'Clustered Proxmox' : 'Standalone Proxmox';
    const d = clustered
        ? 'M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008V8.25zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008V8.25z'
        : 'M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z';
    return `<span title="${title}" class="inline-flex align-text-bottom text-slate-400 ml-1"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="${d}"></path></svg></span>`;
}

function renderPxmxNodes() {
    const wrap = document.getElementById('pxmx-nodes-wrap');
    if (!wrap) return;
    const sel = window._pxmxNodeSel;
    const cols = ['Cluster', 'Node', 'Status', 'CPU %', 'Cores', 'RAM Used', 'RAM Total', 'Version', ''];
    const escAttr = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
    const escJs   = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    // Sort by Cluster then Node (numeric-aware so …svr-2/-3/-10 order
    // naturally, not lexically) — mirrors the VM Server fleet table's host
    // sort. Copy first — don't mutate the loaded array.
    const _cmp = (a, b) => String(a || '').localeCompare(String(b || ''), undefined,
        { numeric: true, sensitivity: 'base' });
    const nodes = (window._pxmxNodes || []).slice().sort((a, b) =>
        _cmp(a.cluster, b.cluster) || _cmp(a.node, b.node));
    const rows = nodes.map(n => {
        const key        = pxmxNodeKey(n.cluster, n.node);
        const ramUsedGb  = ((n.mem_used  || 0) / 1073741824).toFixed(1);
        const ramTotalGb = ((n.mem_total || 0) / 1073741824).toFixed(1);
        const statusCls  = n.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700';
        const selCls     = key === sel ? 'bg-green-50 ring-1 ring-green-300' : 'hover:bg-slate-50';
        return `<tr data-node-key="${escAttr(key)}" onclick="openNodeVms('${escJs(key)}')" class="border-b border-slate-100 cursor-pointer ${selCls}">
            <td class="px-4 py-2 text-xs text-slate-500">${n.cluster ? String(n.cluster).toUpperCase() : '—'}</td>
            <td class="px-4 py-2 font-medium">${String(n.node || '').toUpperCase()}${pxmxClusterBadge(n)}</td>
            <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${n.status}</span></td>
            <td class="px-4 py-2">${n.cpu_usage ?? '—'}%</td>
            <td class="px-4 py-2">${n.cpu_cores ?? '—'}</td>
            <td class="px-4 py-2">${ramUsedGb} GB</td>
            <td class="px-4 py-2">${ramTotalGb} GB</td>
            <td class="px-4 py-2 text-xs text-slate-400">${pxmxShortVer(n.proxmox_version) || '—'}</td>
            <td class="px-4 py-2 text-right" onclick="event.stopPropagation()">
                <button onclick="deletePxmxServer('${escJs(n.node)}','${escJs(n.cluster || '')}')"
                    class="text-xs text-red-600 hover:text-red-800 font-medium"
                    title="Remove this server from the view and clear its cached VMs. For a host you've intentionally shut down; a still-online host re-appears on the next poll.">Delete</button>
            </td>
        </tr>`;
    }).join('');
    wrap.innerHTML = tableWrap(tableHead(cols) + `<tbody>${rows}</tbody>`);
}

// Remove a hypervisor server (pxmx host) from the Overview / Virtual Machines
// view: purge its agent's hub state + clear the cached VM list so a
// shut-down host stops lingering. Resolves the node → agent_id from the cached
// VMs (each carries agent_id); the backend falls back to a hostname match.
async function deletePxmxServer(node, cluster) {
    if (!node) return;
    if (!await showConfirmToast(`Remove server '${node}'?\n\nPurges its agent and clears its cached VMs from the Hypervisors view. Use this for a host you've intentionally shut down — if it's still online it will re-appear on the next poll.`)) return;
    let agent_id = '';
    try {
        const hit = (window._pxmxVms || []).find(v => (v.node || '') === node && v.agent_id);
        if (hit) agent_id = hit.agent_id;
    } catch (e) { /* fall back to hostname match server-side */ }
    try {
        const res = await fetch('/api/pxmx/server', {
            method: 'DELETE', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ agent_id, node, cluster }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(d.message || 'Server removed', 'success');
            if (window._pxmxNodeSel === pxmxNodeKey(cluster, node)) window._pxmxNodeSel = null;
            loadPxmxData('Overview');
        } else {
            showToast(d.detail || 'Delete failed', 'error');
        }
    } catch (e) {
        showToast('Error: ' + (e.message || e), 'error');
    }
}

// Clicking a node on the Nodes tab sets it as the VM filter and navigates to the
// Virtual Machines tab, which renders scoped to that node. The one-shot
// _pxmxNodeFilterPending flag lets loadPxmxData('Virtual Machines') tell apart
// "arrived via a node click" (scoped) from "clicked the tab directly" (all VMs).
function openNodeVms(key) {
    window._pxmxNodeSel = key;
    window._pxmxNodeFilterPending = true;
    setSubView('Virtual Machines');
}

// HTML for a node's summary card + that node's VMs. Used by the scoped
// Virtual Machines view (entered via openNodeVms). Returns '' if the node
// isn't in the cached nodes list.
function pxmxNodeDetailHtml(node, vms) {
    if (!node) return '';
    const ramUsedGb  = ((node.mem_used  || 0) / 1073741824).toFixed(1);
    const ramTotalGb = ((node.mem_total || 0) / 1073741824).toFixed(1);
    const ramPct     = node.mem_total ? Math.round(((node.mem_used || 0) / node.mem_total) * 100) : null;
    const sel        = pxmxNodeKey(node.cluster, node.node);
    const nodeVms    = vms.filter(vm => pxmxNodeKey(vm.cluster, vm.node) === sel);
    const running    = nodeVms.filter(v => v.status === 'running').length;
    const statusCls  = node.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700';

    return `<div class="rounded-lg border border-slate-200 bg-slate-50/50 p-4 mb-4">
            <h3 class="text-base font-semibold text-[#263040]">${node.node}
                <span class="text-xs text-slate-400 font-normal">${node.cluster ? '· cluster ' + node.cluster : ''}</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>
            <p class="text-xs text-slate-500 mt-1">Status
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${node.status}</span>
                · CPU ${node.cpu_usage ?? '—'}% (${node.cpu_cores ?? '—'} cores)
                · RAM ${ramUsedGb} / ${ramTotalGb} GB${ramPct !== null ? ` (${ramPct}%)` : ''}
                · Proxmox ${pxmxShortVer(node.proxmox_version) || '—'}</p>
        </div>` +
        `<h3 class="text-base font-semibold text-[#263040] mb-3 px-1">Virtual Machines &amp; Containers
            <span class="text-xs text-slate-400 font-normal">(${nodeVms.length} on this node, ${running} running)</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>` +
        (nodeVms.length > 0
            ? pxmxVmTableHtml(nodeVms)
            : '<p class="p-4 text-slate-400 italic text-sm">No VMs on this node.</p>');
}

// Hypervisor Overview/VMs, ADMIN (default) scope: the hub deliberately does
// NOT accumulate every tenant's hosts under the built-in ADMIN tenant (it would
// be a cross-tenant firehose). It returns an empty, `select_tenant`-flagged
// payload instead; a Global Admin picks a specific tenant to see that tenant's
// hypervisor stats. Rendered in place of the data table for that scope.
function pxmxSelectTenantPromptHtml() {
    return `<div class="py-12 text-center space-y-3">
        <svg class="w-10 h-10 mx-auto text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0H5m14 0h2M5 21H3m4-14h.01M11 7h.01M7 11h.01M11 11h.01M7 15h.01M11 15h.01"/></svg>
        <p class="text-slate-600 text-sm font-semibold">Select a tenant to view its hypervisor stats</p>
        <p class="text-slate-400 text-xs max-w-md mx-auto">The ADMIN (default) view no longer aggregates every tenant's hosts. Choose a specific tenant from the tenant picker to see that tenant's hypervisors.</p>
    </div>`;
}

// One "we're showing cached data" banner for every Hypervisor tab. Overview and
// the VM list each carried a verbatim copy of this markup and Diagnostics had
// none at all — so a spoke restart blanked its drive table with no explanation.
// Kept in one place so the wording (and the "how old" hint) can't drift apart.
function pxmxStaleBanner(isStale, cachedAt) {
    if (!isStale) return '';
    const when = cachedAt ? _relTimeAgo(new Date(cachedAt * 1000)) : '';
    return `<div class="mb-4 px-3 py-2 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-700 flex items-center gap-2">
               <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.07 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
               <span>Showing cached data${when} — the agent is offline or not responding. Live stats resume automatically when it answers again.</span>
           </div>`;
}

async function renderPxmxDiagnostics(container, forceRefresh = false) {
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">' + (forceRefresh ? 'Polling drive diagnostics live…' : 'Loading drive diagnostics…') + '</p>';

    let res;
    try {
        const refreshParam = forceRefresh ? '&refresh=true' : '';
        res = await fetch(`/api/pxmx/drive-health?tenant=${encodeURIComponent(currentTenant || 'default')}${refreshParam}`);
    } catch (err) {
        container.innerHTML = `
            <div class="p-6">
                <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center justify-between">
                    <div>
                        <span class="font-bold">Failed to load Drive Diagnostics:</span> ${escapeHtml(err.message || String(err))}
                    </div>
                    <button onclick="loadPxmxData('Diagnostics')" class="text-xs px-3 py-1.5 rounded-md bg-white border border-red-300 text-red-700 hover:bg-red-50 font-medium" title="Retry fetching drive diagnostics">↻ Retry</button>
                </div>
            </div>`;
        return;
    }

    if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
            const errData = await res.json();
            if (errData && errData.detail) msg = errData.detail;
        } catch (_) {}
        container.innerHTML = `
            <div class="p-6">
                <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center justify-between">
                    <div>
                        <span class="font-bold">Failed to load Drive Diagnostics:</span> ${escapeHtml(msg)}
                    </div>
                    <button onclick="loadPxmxData('Diagnostics')" class="text-xs px-3 py-1.5 rounded-md bg-white border border-red-300 text-red-700 hover:bg-red-50 font-medium">↻ Retry</button>
                </div>
            </div>`;
        return;
    }

    let data;
    try {
        data = await res.json();
    } catch (err) {
        container.innerHTML = `
            <div class="p-6">
                <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center justify-between">
                    <div>
                        <span class="font-bold">Failed to parse drive diagnostics response:</span> ${escapeHtml(err.message || String(err))}
                    </div>
                    <button onclick="loadPxmxData('Diagnostics')" class="text-xs px-3 py-1.5 rounded-md bg-white border border-red-300 text-red-700 hover:bg-red-50 font-medium">↻ Retry</button>
                </div>
            </div>`;
        return;
    }

    // ADMIN (default) scope: the hub returns an empty, `select_tenant`-flagged
    // payload rather than a cross-tenant firehose. Check this BEFORE
    // spoke_connected — otherwise an empty payload renders as a falsely
    // reassuring "All drives healthy / 0 drives" dashboard.
    if (data.select_tenant) {
        container.innerHTML = pxmxSelectTenantPromptHtml();
        return;
    }

    const spokeConnected = data.spoke_connected !== false;
    // Cached-but-usable is NOT the same as "no spoke": the hub answers a spoke
    // restart with the last good diagnostics, stale-flagged and deliberately
    // spoke_connected=false. Branching on spoke_connected alone would throw
    // that data away and show "No Hypervisor Spoke Connected" instead — the
    // whole point of the fallback. Stale wins; the banner explains it.
    const isStale = data.stale === true;
    const staleBanner = pxmxStaleBanner(isStale, data.cached_at);
    const nodes = Array.isArray(data.nodes) ? data.nodes : [];
    const summary = data.summary || {
        total_drives: 0,
        healthy: 0,
        warning: 0,
        critical: 0,
        unknown: 0,
    };

    const nodesHaveIssues = nodes.some(n => !n.diagnostics || n.status === 'ERROR' || n.error);
    const hasAttention = (summary.critical || 0) > 0 || (summary.warning || 0) > 0 || nodesHaveIssues;
    const overallStatusBadge = hasAttention
        ? '<span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-red-100 text-red-800 border border-red-200">Attention needed</span>'
        : '<span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-800 border border-green-200">All drives healthy</span>';

    const relTime = (data.cached_at && !isStale)
        ? _relTimeAgo(new Date(data.cached_at * 1000)).replace(/[()]/g, '').trim()
        : '';
    const cachedNote = (data.cached_at && !isStale && relTime) ? ` · <span class="text-slate-400 font-normal">Last updated ${relTime}</span>` : '';
    const headerHtml = `
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
            <div>
                <div class="flex items-center gap-3">
                    <h2 class="text-xl font-bold text-slate-900">Drive Health & Diagnostics</h2>
                    ${overallStatusBadge}
                </div>
                <p class="text-xs text-slate-500 mt-1">Storage device telemetry and SSD wear level diagnostics across hypervisor nodes${cachedNote}</p>
            </div>
            <div>
                <button onclick="loadPxmxData('Diagnostics')" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 text-xs font-semibold shadow-sm transition-all" title="Reload SMART telemetry and SSD wear diagnostics from the hub cache (polled every 6 hours)">
                    ↻ Run Diagnostics / Refresh
                </button>
            </div>
        </div>`;

    const summaryCardsHtml = `
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
            <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider">Total Drives</div>
                <div class="text-2xl font-bold text-slate-800 mt-1">${summary.total_drives || 0}</div>
            </div>
            <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
                <div class="text-xs font-medium text-emerald-600 uppercase tracking-wider">Healthy</div>
                <div class="text-2xl font-bold text-emerald-700 mt-1">${summary.healthy || 0}</div>
            </div>
            <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
                <div class="text-xs font-medium text-amber-600 uppercase tracking-wider">Warning (wear >= 80%)</div>
                <div class="text-2xl font-bold text-amber-700 mt-1">${summary.warning || 0}</div>
            </div>
            <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
                <div class="text-xs font-medium text-red-600 uppercase tracking-wider">Critical (wear >= 90%)</div>
                <div class="text-2xl font-bold text-red-700 mt-1">${summary.critical || 0}</div>
            </div>
        </div>`;

    if (!spokeConnected && !isStale) {
        container.innerHTML = `
            <div class="p-4">
                ${headerHtml}
                ${summaryCardsHtml}
                <div class="bg-amber-50 border border-amber-200 rounded-lg p-6 text-center">
                    <div class="text-amber-800 font-semibold mb-1">No Hypervisor Spoke Connected</div>
                    <p class="text-xs text-amber-700 mb-4">No connected hypervisor spoke was found for the current tenant. Connect a Proxmox spoke to view drive diagnostics.</p>
                    <button onclick="loadPxmxData('Diagnostics')" class="text-xs px-3 py-1.5 rounded-md bg-white border border-amber-300 text-amber-800 hover:bg-amber-50 font-medium" title="Retry connecting to hypervisor spoke">↻ Retry Connection</button>
                </div>
            </div>`;
        return;
    }

    const totalDrives = (summary.total_drives || 0) || nodes.reduce((acc, n) => acc + ((n.drives || []).length), 0);
    if (totalDrives === 0 && nodes.length === 0) {
        container.innerHTML = `
            <div class="p-4">
                ${staleBanner}
                ${headerHtml}
                ${summaryCardsHtml}
                <div class="bg-white border border-slate-200 rounded-lg p-8 text-center text-slate-500 shadow-sm">
                    <div class="text-sm font-semibold text-slate-700 mb-1">No Storage Drives Detected</div>
                    <p class="text-xs text-slate-400">The hypervisor nodes did not report any storage drives, or smartctl diagnostics are not yet available.</p>
                </div>
            </div>`;
        return;
    }

    const cols = ['Node', 'Device Path', 'Vendor & Model', 'Serial Number', 'Wear Level', 'Health Status'];

    function getHealthBadge(status) {
        const s = String(status || 'unknown').toLowerCase();
        let cls = 'bg-slate-100 text-slate-700';
        if (s === 'healthy' || s === 'ok' || s === 'good') {
            cls = 'bg-green-100 text-green-800';
        } else if (s === 'warning' || s === 'warn') {
            cls = 'bg-amber-100 text-amber-800';
        } else if (s === 'critical' || s === 'crit' || s === 'error' || s === 'failed') {
            cls = 'bg-red-100 text-red-800';
        }
        return `<span class="px-2 py-0.5 rounded-full text-xs font-medium uppercase ${cls}">${escapeHtml(status || 'unknown')}</span>`;
    }

    function getWearBar(wear) {
        if (wear == null || wear === '') {
            return '<span class="text-slate-400 text-xs">—</span>';
        }
        const num = Number(wear);
        if (isNaN(num)) {
            return `<span class="text-slate-500 text-xs">${escapeHtml(String(wear))}</span>`;
        }
        const pct = Math.min(Math.max(num, 0), 100);
        let barColor = 'bg-[#01A982]';
        if (pct >= 90) {
            barColor = 'bg-red-600';
        } else if (pct >= 80) {
            barColor = 'bg-amber-500';
        }
        return `
            <div class="flex items-center gap-2">
                <div class="w-24 bg-slate-200 rounded-full h-2 overflow-hidden">
                    <div class="h-2 rounded-full ${barColor}" style="width: ${pct}%"></div>
                </div>
                <span class="text-xs font-mono font-medium text-slate-700">${pct}%</span>
            </div>`;
    }

    let tablesHtml = '';
    for (const n of nodes) {
        const nodeName = n.node || 'Unknown';
        const clusterName = n.cluster || '';
        const drives = Array.isArray(n.drives) ? n.drives : [];

        const diagUnavailable = !n.diagnostics || n.status === 'ERROR';
        let badgesHtml = '';
        if (n.agent_version) {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-600 border border-slate-200">Agent v${escapeHtml(n.agent_version)}</span> `;
        }
        if (diagUnavailable) {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-600 border border-slate-200">smartctl: Unknown</span> `;
        } else if (n.diagnostics.smartctl_installed) {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">smartctl: Installed</span> `;
        } else {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-800 border border-red-200">smartctl: Missing</span> `;
        }
        if (n.diagnostics && n.diagnostics.is_hpe) {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200">HPE Server</span> `;
        }
        if (n.diagnostics && n.diagnostics.has_raid) {
            if (n.diagnostics.ssacli_installed) {
                badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">ssacli: Installed</span> `;
            } else {
                badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200">ssacli: Missing</span> `;
            }
        }
        if (n.diagnostics && n.diagnostics.controller_type === 'direct_attached') {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-100 text-sky-800 border border-sky-200">Direct-Attached</span> `;
        }
        if (n.diagnostics && n.diagnostics.controller_type === 'mixed') {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-100 text-indigo-800 border border-indigo-200">RAID + Direct/NVMe</span> `;
        }
        if (n.diagnostics && n.diagnostics.nvme_tools_installed) {
            badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-teal-100 text-teal-800 border border-teal-200">nvme-cli: Installed</span> `;
        }

        let alertHtml = '';
        if (diagUnavailable) {
            alertHtml = `
            <div class="m-4 p-3 bg-slate-100 border border-slate-200 rounded-md text-xs text-slate-800">
                <div class="font-bold flex items-center gap-1 mb-1">
                    <span>ℹ️ Diagnostics Unavailable</span>
                </div>
                ${n.error ? `<p class="mb-1 text-red-700 font-mono text-[11px]">Error: ${escapeHtml(n.error)}</p>` : '<p class="mb-1">Diagnostics not yet reported for this node.</p>'}
            </div>`;
        } else if (!n.diagnostics.smartctl_installed) {
            alertHtml = `
            <div class="m-4 p-3 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-800">
                <div class="font-bold flex items-center gap-1 mb-1">
                    <span>⚠️ Software Prerequisites Incomplete</span>
                </div>
                <p>smartctl is not installed on this node. To collect drive wear and health telemetry, run on the hypervisor host:</p><code class="block mt-1 p-1 bg-white border border-amber-300 rounded font-mono text-[11px] text-slate-800 select-all">apt-get update && apt-get install -y smartmontools</code>
            </div>`;
        }

        const rows = drives.map(drive => {
            const devPath = drive.block_device || drive.scsi_path || '—';
            const vendorModel = `${drive.vendor || ''} ${drive.model || ''}`.trim() || '—';
            const serial = drive.serial || '—';
            const wear = drive.wear_level;
            const status = drive.health_status || (drive.success ? 'healthy' : 'unknown');

            const iface = (drive.interface || '').toUpperCase();
            const ifaceBadge = iface ? `<span class="ml-1.5 px-1.5 py-0.5 rounded text-[9px] font-bold ${iface === 'NVME' ? 'bg-purple-100 text-purple-700' : (iface === 'SAS' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600')}">${escapeHtml(iface)}</span>` : '';
            const tempHtml = drive.temperature ? `<span class="ml-1 text-[10px] font-mono text-slate-500 font-normal">(${escapeHtml(drive.temperature)}°C)</span>` : '';

            return `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-2.5 font-medium text-slate-800">${escapeHtml(nodeName)}</td>
                    <td class="px-4 py-2.5 font-mono text-xs text-slate-600">${escapeHtml(devPath)}${ifaceBadge}</td>
                    <td class="px-4 py-2.5 text-xs text-slate-800">${escapeHtml(vendorModel)}</td>
                    <td class="px-4 py-2.5 font-mono text-xs text-slate-500">${escapeHtml(serial)}</td>
                    <td class="px-4 py-2.5">${getWearBar(wear)}</td>
                    <td class="px-4 py-2.5">${getHealthBadge(status)}${tempHtml}</td>
                </tr>`;
        }).join('');

        let tableContent = '';
        if (drives.length > 0) {
            tableContent = tableWrap(tableHead(cols) + `<tbody>${rows}</tbody>`);
        } else if (!alertHtml) {
            tableContent = `<div class="px-4 py-4 text-center text-xs text-slate-500">No drives reported.</div>`;
        }

        tablesHtml += `
            <div class="mb-6 bg-white rounded-lg border border-slate-200 overflow-hidden shadow-sm">
                <div class="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <span class="text-xs font-bold uppercase tracking-wider text-slate-500">Node:</span>
                        <span class="text-sm font-semibold text-slate-800">${escapeHtml(nodeName)}</span>
                        ${clusterName ? `<span class="text-xs px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono">${escapeHtml(clusterName)}</span>` : ''}
                        <div class="ml-2 flex items-center gap-1 flex-wrap">
                            ${badgesHtml}
                        </div>
                    </div>
                    <span class="text-xs text-slate-500">${drives.length} drive${drives.length === 1 ? '' : 's'}</span>
                </div>
                ${alertHtml}
                ${tableContent}
            </div>`;
    }

    container.innerHTML = `
        <div class="p-4">
            ${staleBanner}
            ${headerHtml}
            ${summaryCardsHtml}
            ${tablesHtml}
        </div>`;
}

async function loadPxmxData(subMenu, forceRefresh = false) {    const container = document.getElementById('pxmx-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    const th = tableHead;  // shared helpers (tableWrap used directly)

    try {
        if (subMenu === 'Settings') {
            await renderPxmxSettings(container);
            return;
        }
        if (subMenu === 'Diagnostics') {
            await renderPxmxDiagnostics(container, forceRefresh);
            return;
        }
        if (subMenu === 'Overview' || subMenu === 'Virtual Machines') {
            // A one-shot flag distinguishes "arrived via node click" (scoped) from
            // "clicked the VM tab directly" (all VMs flat, no stale filter). Read
            // before the fetch: if the user leaves this tab mid-load, lmFetch drops
            // the response and the flag must not leak into a later VM tab visit.
            const filter = (subMenu === 'Virtual Machines' && window._pxmxNodeFilterPending)
                ? window._pxmxNodeSel : null;
            window._pxmxNodeFilterPending = false;
            const [vmR, nodesR] = await Promise.all([
                fetch(`/api/pxmx/vms?tenant=${encodeURIComponent(currentTenant)}`),
                fetch('/api/pxmx/nodes?tenant=' + encodeURIComponent(currentTenant)),
            ]);
            const vmData    = vmR.ok    ? await vmR.json()    : {};
            const nodesData = nodesR.ok ? await nodesR.json() : {};

            const vms   = vmData.vms   || [];
            const nodes = nodesData.nodes || [];

            // Shared cache for the clickable-node detail view (renderPxmxNodes /
            // openNodeVms / pxmxNodeDetailHtml).
            window._pxmxNodes = nodes;
            window._pxmxVms = vms;
            // Reconcile optimistic in-flight badges against this fresh list before
            // any rows are built (drop confirmed deletes, clear settled ops, time out).
            pxmxReconcileVmInflight(vms);
            window._pxmxAgentCount = vmData.agent_count || '?';
            // Template-pool names from the hub: VMs whose pool is in this set are
            // shared templates any tenant may clone (clone-from-template). The
            // hub enforces this server-side too — this is just the UI affordance.
            window._pxmxTemplatePools = (vmData.template_pools || []).map(p => String(p).toLowerCase());

            // --- 'Overview' landing: just the clickable nodes table -----------
            if (subMenu === 'Overview') {
                if (nodesData.select_tenant || vmData.select_tenant) {
                    container.innerHTML = pxmxSelectTenantPromptHtml();
                    return;
                }
                if (nodes.length === 0 && vms.length === 0) {
                    container.innerHTML = `<div class="py-10 text-center space-y-3">
                        <p class="text-slate-400 italic text-sm">No Proxmox agents connected.</p>
                        ${isAdmin() ? `<button onclick="showPxmxInstallModal()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm" title="Show bash installation command for Proxmox host agent">Show Install Command</button>` : ''}
                    </div>`;
                    return;
                }
                const isStale = vmData.stale || nodesData.stale;
                const staleBanner = pxmxStaleBanner(isStale, nodesData.cached_at || vmData.cached_at);
                container.innerHTML = staleBanner
                    + `<h3 class="text-base font-semibold text-[#263040] mb-3 px-1">Overview
                        <span class="text-xs text-slate-400 font-normal">(${nodes.length}) — click a node to view its VMs</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>`
                    + `<div id="pxmx-nodes-wrap"></div>`;
                renderPxmxNodes();
                return;
            }

            // --- 'Virtual Machines': scoped to a node if arrived via a node click ---
            if (vmData.select_tenant || nodesData.select_tenant) {
                container.innerHTML = pxmxSelectTenantPromptHtml();
                return;
            }
            if (vms.length === 0 && nodes.length === 0) {
                container.innerHTML = `<div class="py-10 text-center space-y-3">
                    <p class="text-slate-400 italic text-sm">No Proxmox agents connected.</p>
                    ${isAdmin() ? `<button onclick="showPxmxInstallModal()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Show Install Command</button>` : ''}
                </div>`;
                return;
            }

            const isStale = vmData.stale || nodesData.stale;
            const staleBanner = pxmxStaleBanner(isStale, nodesData.cached_at || vmData.cached_at);

            const backBtn = `<button onclick="setSubView('Overview'); window._pxmxNodeSel = null;"
                class="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-[#01A982] font-medium transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
                Overview
            </button>`;

            if (filter) {
                // Scoped to one node: summary card + that node's VMs.
                // pxmxNodeDetailHtml filters the passed VMs by pxmxNodeKey internally.
                const node = nodes.find(n => pxmxNodeKey(n.cluster, n.node) === filter);
                if (node) {
                    container.innerHTML = staleBanner + backBtn
                        + pxmxNodeDetailHtml(node, vms);
                    return;
                }
                // Node not found (vanished between fetch and click) — fall through to flat.
            }

            // All VMs flat (direct tab click, or no node telemetry yet) — with
            // the per-server tab strip (pxmxVmSectionHtml/pxmxSelectVmTab).
            container.innerHTML = staleBanner
                + `<div id="pxmx-vm-section">${pxmxVmSectionHtml()}</div>`;

        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

async function showPxmxInstallModal() {
    let cmd = 'Loading…';
    try {
        const r = await fetch('/api/pxmx/agent-install-cmd');
        const d = r.ok ? await r.json() : {};
        cmd = d.cmd || 'Could not generate command — check LM server logs.';
    } catch (e) {
        cmd = 'Error: ' + e.message;
    }
    const existing = document.getElementById('pxmx-install-modal');
    if (existing) existing.remove();
    const modal = document.createElement('div');
    modal.id = 'pxmx-install-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Install Proxmox Agent</h3>
                <button onclick="document.getElementById('pxmx-install-modal').remove()" class="text-slate-400 hover:text-slate-600" title="Close install modal"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-3">
                <p class="text-sm text-slate-600">Run this on each Proxmox host as <strong>root</strong>:</p>
                <pre id="pxmx-install-cmd" class="bg-slate-900 text-green-300 text-xs rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">${cmd.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
                <p class="text-xs text-slate-400">The <code>--id</code> flag uses <code>$(hostname)</code> — replace it with a unique name if running on multiple nodes.</p>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="navigator.clipboard.writeText(document.getElementById('pxmx-install-cmd').innerText)" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 border border-slate-300 rounded-md" title="Copy agent install script command to clipboard">Copy</button>
                <button onclick="document.getElementById('pxmx-install-modal').remove()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm" title="Dismiss install dialog">Done</button>
            </div>
        </div>`;
    _mountModal(modal);
}
