// fleet-admin.js — Network device fleet list, spokes and agents, users, groups, sessions, My Devices, logs, roles.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// Network Devices fleet list (Setup → Network Devices). Mirrors loadFirewallsList
// but reads /setup/nw-devices. Cache so the add/edit modal's editNwDevice can
// resolve a device without a second fetch.
let _nwDevicesCache = [];
async function loadNwDevices() {
    try {
        const data = await apiJson('/setup/nw-devices');
        _nwDevicesCache = Array.isArray(data.nw_devices) ? data.nw_devices : [];
        return _nwDevicesCache;
    } catch (e) {
        _nwDevicesCache = [];
        return [];
    }
}

const _NW_OBJECT_TYPES = {
    aos_switch: 'AOS Switch',
    cx_switch:  'CX Switch',
    ex_switch:  'EX Switch',
    gateway:    'Gateway',
};
const _NW_TRANSPORTS = { ssh: 'SSH/CLI', rest: 'REST API', snmp: 'SNMP', auto: 'Auto' };

async function loadNwDevicesList() {
    const listEl = document.getElementById('nw-devices-list');
    if (!listEl) return;
    try {
        const devices = await loadNwDevices();
        if (devices.length === 0) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No network devices configured.</p>';
            return;
        }
        listEl.innerHTML = devices.map(d => {
            const typeLabel = _NW_OBJECT_TYPES[d.object_type] || d.object_type || '—';
            const transport = _NW_TRANSPORTS[d.transport] || d.transport || 'auto';
            return `<div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${escapeHtml(d.name || d.id)}</span><span class="ml-2 text-xs text-slate-400">${escapeHtml(typeLabel)} · ${escapeHtml(transport)} · ${escapeHtml(d.address || '')}${d.port ? ':' + escapeHtml(String(d.port)) : ''}</span></div>
                <div class="flex gap-2">
                    <button onclick="editNwDevice('${escapeHtml(d.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                    <button onclick="deleteNwDeviceEntry('${escapeHtml(d.id)}')" class="text-xs text-red-400 hover:text-red-600 font-medium">Delete</button>
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading network devices: ${e.message}</p>`;
    }
}

async function deleteNwDeviceEntry(id) {
    if (!await showConfirmToast(`Delete network device ${id}?`)) return;
    try {
        await apiJson(`/setup/nw-devices/${id}`, { method: 'DELETE' });
        loadNwDevicesList();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

// loadSpokesAndAgents() — renders the Setup → Spokes & Agents admin TABLES
// (GET /setup/pending_spokes + GET /api/pxmx/agents; see core/src/api.py
// get_pending_spokes). This is the admin management view, distinct from the
// dashboard sidebar lists rendered by _renderDashboardLists() above. The rows
// here are full <table> rows with Approve/Remove action buttons and a DIFFERENT
// status-dot color scheme (bg-yellow-400 for pending, green dot without the
// 8px glow) than the sidebar cards, so they intentionally do NOT share the
// _renderSpokeAgentRow() helper — preserving exact output here matters more
// than de-duplicating the dot markup.
// Shared table-class bundle for the Spokes & Agents admin tables (mirrors the
// _SETUP_CLS pattern used by the Setup tiles). Kept as a const so the two
// render helpers below produce byte-identical output to the pre-split body.
const _SPOKES_TBL_CLS = {
    btnCls: 'px-3 py-1 rounded text-xs font-bold transition-colors',
    tblCls: 'overflow-hidden rounded-md border border-slate-200 bg-white',
    thCls:  'px-4 py-3 font-bold',
    tdCls:  'px-4 py-3',
};

// _identityChangeBanner(ic, clickExpr) — renders the amber "renamed/reimaged"
// banner surfaced when the hub's install-UUID correlation detected that this
// spoke/agent was cloned+renamed, hostname-renamed (pinned id), or reimaged.
// `ic` is the raw {event, ts, detail} from the spokes/agents API; `clickExpr`
// is the JS for the dismiss button's onclick (already escaped), which POSTs to
// the matching ack-change endpoint so the banner clears once an admin sees it.
function _identityChangeBanner(ic, clickExpr) {
    if (!ic || !ic.event) return '';
    const label = ic.event === 'identity_changed' ? 'Renamed'
                : ic.event === 'hostname_changed' ? 'Hostname changed'
                : ic.event === 'reimaged'         ? 'Re-imaged'
                : ic.event;
    const detail = (ic.detail || '').replace(/'/g, "\\'");
    return `<div class="mt-1 flex items-center gap-2 px-2 py-1 rounded bg-amber-50 border border-amber-200 text-amber-700">
                <span class="text-[10px] font-bold uppercase tracking-wide">${label}</span>
                ${detail ? `<span class="text-[10px] text-amber-600 truncate" title="${detail}">${detail}</span>` : ''}
                <button onclick="${clickExpr}" class="ml-auto text-[10px] font-bold text-amber-700 hover:text-amber-900 underline">Dismiss</button>
            </div>`;
}

// _ackIdentityChange(endpoint) — POST to a spoke/agent ack-change endpoint and
// reload the Spokes & Agents tile so the dismissed banner clears. Best-effort:
// on failure we surface the error but still refresh so the UI doesn't hang.
async function _ackIdentityChange(endpoint) {
    try {
        const res = await fetch(endpoint, { method: 'POST' });
        if (!res.ok) {
            const body = await res.text().catch(() => '');
            console.error('ack-change failed:', res.status, body);
        }
    } catch (err) {
        console.error('ack-change request failed:', err);
    } finally {
        if (typeof loadSpokesAndAgents === 'function') loadSpokesAndAgents();
    }
}

// _mgmtBtn(label, onclick, extraCls) — one action button for a management card
// row. Keeps the btn base class + per-button color consistent across the
// Spokes / Agents / Generic Agents tiles.
function _mgmtBtn(label, onclick, extraCls) {
    return `<button onclick="${onclick}" class="${_SPOKES_TBL_CLS.btnCls} ${extraCls || ''}">${label}</button>`;
}

// _mgmtDeleteActions(o) — the Decommission / Force Delete / Restore action set,
// built WITHOUT a /setup/diagnostics telemetry entry. _diagTelemetryExtras
// produces the same buttons, but ONLY when a diag entry exists for the row — so
// a spoke/agent with no telemetry (offline, never-diagnosed, or an approved
// entry not mirrored into known_modules) rendered with NO way to delete it. This
// mirrors the actions branch in _diagTelemetryExtras from the row's own
// approved/decommissioned flags so the destructive actions are ALWAYS present.
// o = { eSid, approved, decommissioned, deleteFn, decommFn, restoreFn }
function _mgmtDeleteActions(o) {
    const eSid = o.eSid;
    const deleteFn = o.deleteFn || 'deleteSpoke';
    const decommFn = o.decommissionFn || o.decommFn || 'decommissionSpoke';
    const restoreFn = o.restoreFn || 'restoreSpoke';
    if (o.decommissioned) {
        return [
            _mgmtBtn('Restore', `${restoreFn}('${eSid}')`, 'bg-green-600 hover:bg-green-700 text-white'),
            _mgmtBtn('Force Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white'),
        ];
    }
    if (o.approved) {
        return [
            _mgmtBtn('Decommission', `${decommFn}('${eSid}')`, 'bg-slate-500 hover:bg-slate-600 text-white'),
            _mgmtBtn('Force Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white'),
        ];
    }
    // Pending (not yet approved): only the hard delete makes sense.
    return [_mgmtBtn('Force Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white')];
}


// _quietMeta(parts) — join non-empty metadata fragments into ONE muted line
// separated by a faint middot. The Spokes/Agents rows use this instead of a row
// of fixed-width colored pills, so the row reads as calm secondary text and
// only EXCEPTIONS (out-of-date version, Pending, recovery, alerts) carry color.
function _quietMeta(parts) {
    return (parts || []).filter(p => p != null && p !== '')
        .join(' <span class="text-slate-300">·</span> ');
}

function _mgmtEntryCard(o) {
    const meta    = (o.metaLines || []).filter(Boolean).join('');
    const actions = (o.actions || []).filter(Boolean).join('');
    // Optional SECONDARY action row, rendered on its own line below the primary
    // actions. The Agents table uses it to drop the destructive Decommission /
    // Force Delete buttons onto their own line so the (more numerous) agent
    // action buttons — Edit, Tenant, Load Role, Approve — don't wrap mid-row.
    const actions2 = (o.actionsSecondary || []).filter(Boolean).join('');
    // Corner actions (e.g. Events / Copy) pin to the top-right of the header row.
    const corner  = (o.cornerActions || []).filter(Boolean).join(' ');
    // Card tone: amber = out of date, red = last seen > 30m (stale). The quiet
    // metadata line lives on its OWN full-width line BELOW the header so it can
    // use the whole card width instead of being boxed against the Events/Copy
    // corner (which is what made it wrap).
    const tone = o.cardTone === 'stale' ? 'border-red-300 bg-red-50 hover:bg-red-100'
               : o.cardTone === 'warn'  ? 'border-amber-300 bg-amber-50 hover:bg-amber-100'
               : 'border-slate-200 bg-white hover:bg-slate-50';
    return `<div class="lm-mgmt-card border ${tone} rounded-md p-2.5 space-y-1 transition-colors">
        <div class="flex items-center justify-between gap-3">
            <div class="flex items-center gap-2.5 min-w-0">
                <div class="w-2 h-2 rounded-full ${o.dot} shrink-0"></div>
                <div class="font-medium text-slate-700 break-words min-w-0" title="${escapeHtml(o.sid || '')}">${o.name}</div>
            </div>
            ${corner ? `<div class="flex items-center gap-2 shrink-0">${corner}</div>` : ''}
        </div>
        ${o.metaInline ? `<div class="text-[11px] text-slate-500 break-words leading-relaxed pl-[18px]">${o.metaInline}</div>` : ''}
        ${o.identityBanner || ''}
        ${meta}
        ${actions ? `<div class="flex items-center gap-2 flex-wrap pl-6">${actions}</div>` : ''}
        ${actions2 ? `<div class="flex items-center gap-2 flex-wrap pl-6">${actions2}</div>` : ''}
    </div>`;
}

// _renderSpokesTable() — renders the Spokes half of the Setup → Spokes & Agents
// admin view. Extracted from loadSpokesAndAgents; the fetch + split preamble
// stays in the caller. `diagBy` (Map<spoke_id, /setup/diagnostics entry>) folds
// the former Diagnostics tile's telemetry into each row — heartbeat/version/
// skew/recovery/alert badges, the status-text + last-error lines, Reset Secret
// / Delete / Recovery Pause / Events actions, and the expandable events panel —
// via _diagTelemetryExtras. Missing telemetry (diag fetch failed for this id)
// degrades gracefully to the approval-only row.
function _renderSpokesTable(spokesWrap, trueSpokes, diagBy) {
    if (!spokesWrap) return;
    const { btnCls, tblCls, thCls, tdCls } = _SPOKES_TBL_CLS;

    // LDAP (directory), DNS, and DHCP are lightweight service modules rather
    // than full infrastructure products — surface them as Type "Module" in the
    // table; everything else stays "Spoke".
    const MODULE_KIND_TYPES = new Set(['directory', 'dns', 'dhcp']);
    const spokeKind = mt => MODULE_KIND_TYPES.has(mt) ? 'Module' : 'Spoke';

    try {
        if (trueSpokes.length === 0) {
            spokesWrap.innerHTML = `<p class="py-8 text-center text-slate-400 italic text-xs">No spokes have connected yet.</p>`;
        } else {
            spokesWrap.innerHTML = `<div class="space-y-1.5">${trueSpokes.map(s => {
                const sid = s.spoke_id;
                const name = _spokeName(s);
                const approved = s.approved;
                const mtRaw = String(s.module_type || '').toLowerCase();
                const modLabel = moduleLabel(mtRaw);
                const kindLabel = spokeKind(mtRaw);
                const hostname = s.hostname || '';
                const ic = s.identity_change;
                const eSid = sid.replace(/'/g, "\\'");
                const eName = escJsAttr(name);
                const ackClick = `_ackIdentityChange('/setup/spokes/${encodeURIComponent(sid)}/ack-change')`;
                // Telemetry extras from the diagnostics endpoint. The heartbeat-
                // aware dot overrides the approval dot ONLY when the spoke is
                // approved (a pending spoke keeps amber; an approved-but-silent
                // spoke goes red). No diag entry → null → approval-only row.
                const extras = diagBy && diagBy.has(sid) ? _diagTelemetryExtras(diagBy.get(sid)) : null;
                const dot = (extras && approved) ? extras.dot
                          : (approved ? 'bg-green-500' : 'bg-yellow-400');
                // Tenant binding: any spoke can be assigned to a tenant (not just
                // cs, and not just from Simulations → Spoke Management, which only
                // ever surfaced this for cs spokes). Agent-hosting spokes (cs/pxmx)
                // seed newly-approved agents from this binding — see
                // approve_agent_under_spoke in api.py.
                const tenantId = s.tenant_id || '';
                const eTenant = tenantId.replace(/'/g, "\\'");
                // Revoked chip for the management card: an auto-revoke
                // (threat_auto) means the node tripped a recon/scan signature and
                // was hard-revoked by the tenant-side threat response; an admin
                // revoke shows the same way with its reason. Admin Approve (on the
                // row for any non-approved node) is the re-approval path.
                const _revChip = s.revoked
                    ? (() => {
                        const _auto = s.revoked_by === 'threat_auto';
                        const _when = s.revoked_ts ? new Date(s.revoked_ts * 1000).toLocaleString() : '';
                        const _t = `Revoked${_auto ? ' automatically (tenant-side threat response)' : ' by admin'}`
                            + (s.revoke_reason ? ` — ${s.revoke_reason}` : '')
                            + (_when ? ` (${_when})` : '') + '. Approve to re-instate.';
                        return `<span class="font-bold ${_auto ? 'text-red-700' : 'text-red-600'}" title="${escapeHtml(_t)}">⛔ ${_auto ? 'Auto-Revoked' : 'Revoked'}</span>`;
                    })()
                    : '';
                // A spoke bound to the SHARED tenant is visible to every tenant.
                // The server stamps `tenant_shared` per row (setup._aggregate_spokes);
                // fall back to the cached shared-tenant id so the badge still shows
                // if that field is ever absent. Mirrors the resource-chip badge.
                const _tenantShared = !!s.tenant_shared
                    || (!!tenantId && !!window._sharedTenantId && tenantId === window._sharedTenantId);
                // Role sub-spoke → its own row carries an "Unload Role" action
                // that removes the role from the parent agent (annotated in
                // loadSpokesAndAgents). Uniform with "Add role" on the agent.
                const eRoleParent = (s._roleParent || '').replace(/'/g, "\\'");
                const eRoleName = (s._roleName || '').replace(/'/g, "\\'");
                return _mgmtEntryCard({
                    dot,
                    name: escapeHtml(name), sid,
                    identityBanner: _identityChangeBanner(ic, ackClick),
                    metaLines: [
                        // host + tenant + Online/Offline status on ONE flex-wrap
                        // line (was three stacked divs) to save vertical space.
                        `<div class="flex items-center gap-x-3 gap-y-0.5 flex-wrap text-xs pl-6">`
                          + (hostname ? `<span class="font-mono text-slate-500">host: ${escapeHtml(hostname)}</span>` : '')
                          + `<span class="text-slate-500">tenant: ${tenantId ? `<span class="font-mono text-slate-700">${escapeHtml(tenantId)}</span>${_tenantShared ? ` <span class="text-[9px] px-1.5 py-0.5 rounded-full font-bold uppercase bg-amber-100 text-amber-800 align-middle" title="Shared tenant — its spokes are visible to all tenants">shared</span>` : ''}` : '<span class="italic text-slate-400">unassigned</span>'}</span>`
                          + (extras && extras.status ? `<span class="font-bold ${extras.status.tone}">${escapeHtml(extras.status.text)}</span>` : '')
                          + `</div>`,
                        ...(extras ? extras.metaLines : []),
                    ],
                    cardTone: extras ? extras.cardTone : '',
                    metaInline: _quietMeta([
                        escapeHtml(kindLabel),
                        (modLabel && modLabel !== '—') ? escapeHtml(modLabel) : '',
                        ...(extras ? extras.metaParts : []),
                        _revChip,
                        approved ? '' : '<span class="text-amber-600 font-semibold">Pending approval</span>',
                    ]),
                    actions: [
                        // Edit now hosts Reset Secret + Un-approve (moved off the
                        // row to declutter); pass `approved` so the modal shows
                        // Un-approve only for an already-approved spoke.
                        _mgmtBtn('Edit', `openSpokeMetadataModal('${eSid}','${eName}',${approved})`, 'bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982]'),
                        _mgmtBtn('Tenant', `openSpokeAssignModal('${eSid}','${eTenant}')`, 'bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982]'),
                        // Approve stays on the row (primary action for a pending
                        // spoke); Un-approve lives inside Edit for approved ones.
                        ...(approved ? [] : [_mgmtBtn('Approve', `approveSpoke('${eSid}')`, 'bg-blue-600 hover:bg-blue-700 text-white')]),
                        ...(s._roleName ? [_mgmtBtn('Unload Role', `unloadRole('${eRoleParent}','${eRoleName}')`, 'bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200')] : []),
                    ],
                    // Decommission / Force Delete (+ Restore for a retired spoke)
                    // drop to their own line — matches the Agents table so the
                    // destructive actions never wrap into the primary buttons.
                    // With diagnostics telemetry present, reuse its action set;
                    // otherwise build the same buttons from the row's own
                    // approved/decommissioned flags so a spoke with no diag entry
                    // is still deletable (was: no action row at all).
                    actionsSecondary: extras ? extras.actions
                        : _mgmtDeleteActions({ eSid, approved, decommissioned: !!s.decommissioned }),
                    cornerActions: extras ? extras.eventsActions : [],
                }) + (extras ? extras.eventsPanel : '');
            }).join('')}</div>`;
        }
    } catch (err) {
        spokesWrap.innerHTML = `<p class="py-6 text-center text-red-400 italic text-xs">Error: ${err.message}</p>`;
    }
}

// _renderAgentsTable() — renders the Agents half (generic Hub-direct agents +
// Proxmox node agents). Extracted from loadSpokesAndAgents; pxmxAgents are
// fetched by the caller and passed in. The Active Role column + Load Role
// action for generic agents were folded in from the former Setup → Generic
// Nodes tile so generic nodes are managed entirely from Spokes & Agents.
async function _renderAgentsTable(agentsWrap, genericAgents, pxmxAgents, diagBy) {
    if (!agentsWrap) return;
    const { btnCls, tblCls, thCls, tdCls } = _SPOKES_TBL_CLS;

    // Generic Hub-direct agents come from /setup/pending_spokes (module_type
    // "agent"); they approve through the standard spoke-approval path.
    const hubAgents = genericAgents.map(s => {
        const sid = s.spoke_id;
        const dn = _spokeName(s);
        // The Module column names the product the agent runs. AppBuilder is the
        // canonical generic hub agent; any other generic agent falls back to
        // its display name so the column still shows something meaningful.
        const module = /ab/i.test(sid) || /ab/i.test(dn) ? 'AppBuilder' : dn;
        return {
            agent_id: sid,
            display_name: dn,
            hostname: s.hostname || '',
            identity_change: s.identity_change || null,
            tenant_id: s.tenant_id || '',
            _status: s.approved ? 'connected' : 'pending',
            _decommissioned: !!s.decommissioned,
            _kind: 'spoke',
            _module_type: String(s.module_type || '').toLowerCase(),
            _module: module,
        };
    });

    // pxmxAgents were fetched up front (to scope the Spokes table); reuse
    // them here rather than re-fetching.
    const all = [...hubAgents, ...pxmxAgents];
    // Sort the Agents tile by display name (case-insensitive) so generic
    // Hub-direct agents and Proxmox node agents interleave by name, not by
    // fetch order. Falls back to hostname, then agent_id.
    all.sort((a, b) =>
        (a.display_name || a.hostname || a.agent_id || '').localeCompare(
            (b.display_name || b.hostname || b.agent_id || ''), undefined, { sensitivity: 'base' }));

    // Active Role column (folded in from the former Generic Nodes tile):
    // each connected generic agent hosts 0..N role sub-spokes, surfaced via
    // GET_AVAILABLE_ROLES on the generic relay. We paint the table immediately
    // with a per-row "loading roles…" placeholder, then fill each agent's cell
    // as its round-trip resolves — NO Promise.all barrier, so one sluggish
    // agent can't stall the rest (mirrors the progressive-render approach the
    // standalone Generic Nodes tile used). The role cell is keyed by agent_id;
    // a reload that rebuilt the table while a fetch was outstanding still
    // writes to the right cell if the agent is still listed, and silently
    // skips (querySelector returns null) if it has since dropped off.

    if (all.length === 0) {
        agentsWrap.innerHTML = `<p class="py-6 text-center text-slate-400 italic text-xs">No agents connected yet. Install the agent on a node (it appears here to be approved, then load a role) or install the agent on a Proxmox node to begin.</p>`;
    } else {
        agentsWrap.innerHTML = `<div class="space-y-1.5">${all.map(a => {
            const aid = a.agent_id;
            const label = _nodeLabel(a.display_name || a.hostname || aid, _tenantOf(a));
            const isPending = a._status === 'pending';
            const isOffline = a._status === 'offline';
            const isSpokeKind = a._kind === 'spoke';
            // Every card here is an agent. Type distinguishes the two flavors:
            // generic Hub-direct agents (module_type "agent", now shown here
            // only once they have a role loaded — idle ones sit in the Generic
            // Agents tile) vs Proxmox node agents relayed through the pxmx
            // spoke. The Module badge names what each one runs.
            const typeLabel = isSpokeKind ? 'Agent' : 'PXMX AGENT';
            const moduleLabelCell = a._module || '—';
            const statusLabel = isPending ? 'Pending' : (isSpokeKind ? 'Approved' : 'Connected');
            const eAid = aid.replace(/'/g, "\\'");
            const eLabel = label.replace(/'/g, "\\'");
            // Tenant binding, surfaced + editable per agent to mirror the Spokes
            // table. Generic agents ARE agent-type spokes so their binding lives
            // on tenant_id (set via the same approve_spoke path); Proxmox node
            // agents carry it in client_simulation.tenant_id (per-agent config).
            const rowTenant = isSpokeKind ? (a.tenant_id || '') : (a.client_simulation?.tenant_id || '');
            const eTenant = rowTenant.replace(/'/g, "\\'");
            // The owning spoke is already known on the rendered row (pxmx agents
            // carry spoke_id — see get_pxmx_agents). Pass it straight to Approve
            // so it never has to re-resolve via a tenant-scoped fetch, which
            // silently dropped the agent when its owning spoke was bound to a
            // different tenant than the picker (approval dead-ended with "could
            // not determine which spoke owns this agent").
            const eSpoke = String(a.spoke_id || '').replace(/'/g, "\\'");
            // Shared-tenant badge: `tenant_shared` is stamped by the server for
            // spoke-kind agents; for pxmx agents (no server flag) compare against
            // the cached shared-tenant id. Mirrors the spoke-row badge.
            const _rowTenantShared = !!a.tenant_shared
                || (!!rowTenant && !!window._sharedTenantId && rowTenant === window._sharedTenantId);
            // Active Role line: a keyed placeholder for connected generic agents
            // that is filled async after paint (no barrier). Proxmox node agents
            // have no roles; pending generic agents show an em-dash.
            let rolesLine;
            if (!isSpokeKind) {
                rolesLine = '';
            } else if (isPending) {
                rolesLine = `<div class="text-xs text-slate-500 pl-6">roles: <span class="text-slate-400 italic">—</span></div>`;
            } else {
                rolesLine = `<div class="text-xs text-slate-500 pl-6">roles: <span class="lm-agent-role-cell text-slate-400 italic" data-role-cell="${escapeHtml(aid)}">loading…</span></div>`;
            }
            // Telemetry extras folded in from the former Diagnostics tile.
            // Generic Hub-direct agents pull their entry from diagBy (the
            // /setup/diagnostics map); Proxmox node agents are normalized into
            // the same shape from the pxmx agent object itself (they connect
            // through the pxmx spoke, so the hub has no direct diag entry).
            // pxmx agents suppress Reset Secret (revokeAgent is already the
            // Un-approve button here) and Recovery Pause (watchdog is spoke-
            // scoped). The heartbeat dot overrides the approval dot only when
            // the agent is connected/approved — pending keeps amber.
            const extras = isSpokeKind
                ? (diagBy && diagBy.has(aid) ? _diagTelemetryExtras(diagBy.get(aid)) : null)
                : _diagTelemetryExtras(_normalizePxmxAgent(a), { resetFn: 'revokeAgent', deleteFn: 'deleteAgent', decommissionFn: 'decommissionAgent', restoreFn: 'restoreAgent', allowRecoveryPause: false, allowReset: false });
            const editFn = isSpokeKind ? 'openSpokeMetadataModal' : 'openAgentConfigModal';
            const approveFnName = isSpokeKind ? 'approveSpoke' : 'approveAgent';
            const unapproveFnName = isSpokeKind ? 'unapproveSpoke' : 'revokeAgent';
            const ic = a.identity_change || null;
            const ackEndpoint = isSpokeKind
                ? `/setup/spokes/${encodeURIComponent(aid)}/ack-change`
                : `/api/pxmx/agents/${encodeURIComponent(aid)}/ack-change`;
            const ackClick = `_ackIdentityChange('${ackEndpoint}')`;
            const nameWithCs = `${escapeHtml(label)}${a.client_simulation?.enabled ? ' <span class="ml-1 px-1.5 py-0.5 rounded-full text-[9px] font-bold uppercase bg-green-100 text-green-700 align-middle" title="Client Simulation mode">CS</span>' : ''}`;
            const dot = (extras && !isPending) ? extras.dot
                      : (isPending ? 'bg-amber-400' : 'bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]');
            return _mgmtEntryCard({
                dot,
                name: nameWithCs, sid: aid,
                identityBanner: _identityChangeBanner(ic, ackClick),
                metaLines: [
                    // host + tenant + Online/Offline status on ONE flex-wrap line
                    // (was three stacked divs) to save vertical space. rolesLine
                    // stays its own line below it.
                    `<div class="flex items-center gap-x-3 gap-y-0.5 flex-wrap text-xs pl-6">`
                      + (a.hostname ? `<span class="font-mono text-slate-500">host: ${escapeHtml(a.hostname)}</span>` : '')
                      + `<span class="text-slate-500">tenant: ${rowTenant ? `<span class="font-mono text-slate-700">${escapeHtml(rowTenant)}</span>${_rowTenantShared ? ` <span class="text-[9px] px-1.5 py-0.5 rounded-full font-bold uppercase bg-amber-100 text-amber-800 align-middle" title="Shared tenant — its spokes are visible to all tenants">shared</span>` : ''}` : '<span class="italic text-slate-400">unassigned</span>'}</span>`
                      + (extras && extras.status ? `<span class="font-bold ${extras.status.tone}">${escapeHtml(extras.status.text)}</span>` : '')
                      + `</div>`,
                    rolesLine,
                    ...(extras ? extras.metaLines : []),
                ],
                cardTone: extras ? extras.cardTone : '',
                metaInline: _quietMeta([
                    escapeHtml(typeLabel),
                    a._module ? escapeHtml(String(a._module)) : '',
                    ...(extras ? extras.metaParts : []),
                    isPending ? '<span class="text-amber-600 font-semibold">Pending approval</span>' : '',
                ]),
                actions: [
                    // Spoke-kind agents route Edit → openSpokeMetadataModal, which
                    // now hosts Reset Secret + Un-approve; pass approved (=!isPending)
                    // so the modal shows Un-approve. pxmx Edit (openAgentConfigModal)
                    // ignores the extra arg.
                    _mgmtBtn('Edit', `${editFn}('${eAid}','${eLabel}'${isSpokeKind ? ',' + (!isPending) : ''})`, 'bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982]'),
                    // Dedicated Tenant button, mirroring the Spokes table. Generic
                    // agents reuse the spoke assign modal (they bind via
                    // approve_spoke); Proxmox node agents get their own modal that
                    // writes client_simulation.tenant_id via the agent config API.
                    _mgmtBtn('Tenant',
                        isSpokeKind ? `openSpokeAssignModal('${eAid}','${eTenant}','Agent')` : `openAgentAssignModal('${eAid}','${eTenant}')`,
                        'bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982]'),
                    (isSpokeKind && !isPending)
                        ? _mgmtBtn('Load Role', `showLoadRoleModal('${eAid}')`, 'bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982]')
                        : '',
                    isPending
                        ? _mgmtBtn('Approve', isSpokeKind ? `${approveFnName}('${eAid}')` : `${approveFnName}('${eAid}','${eSpoke}')`, 'bg-blue-600 hover:bg-blue-700 text-white')
                        // Spoke-kind agents move Un-approve into Edit; pxmx agents
                        // keep revoke on the row (its Edit is a separate config modal).
                        // An OFFLINE agent has nothing to un-approve (no live link) —
                        // only Delete is meaningful, so drop the revoke button.
                        : ((isSpokeKind || isOffline) ? '' : _mgmtBtn('Un-approve', `${unapproveFnName}('${eAid}')`, 'bg-red-50 hover:bg-red-100 text-red-600 border border-red-200')),
                ],
                // Decommission / Force Delete (+ Restore for a retired agent) drop
                // to their own line — the Agents rows carry more primary buttons
                // (Edit, Tenant, Load Role, Approve) than the Spokes rows, so
                // keeping the destructive actions inline made the row wrap. When a
                // spoke-kind agent has no diagnostics entry, fall back to the same
                // buttons built from its own approved/decommissioned flags so it is
                // still deletable (pxmx agents always carry a synthesized extras).
                actionsSecondary: extras ? extras.actions
                    : (isSpokeKind ? _mgmtDeleteActions({ eSid: eAid, approved: !isPending, decommissioned: !!a._decommissioned }) : []),
                cornerActions: extras ? extras.eventsActions : [],
            }) + (extras ? extras.eventsPanel : '');
        }).join('')}</div>`;
        // Trickle: fill each connected generic agent's Active Role line as its
        // GET_AVAILABLE_ROLES resolves. No barrier, so a slow agent never delays
        // the others. Looks the cell up by data-role-cell each time so a reload
        // that rebuilt the tile mid-flight still targets the right agent (and
        // silently skips one that has since dropped off the list).
        all.forEach(a => {
            if (a._kind !== 'spoke' || a._status !== 'connected') return;
            const aid = a.agent_id;
            // Fetch hosted roles, durable deploy-role markers AND live deploy
            // status together so the cell reflects all three. A deploy role like
            // dns-server/dhcp-server/netbox-server hosts NO sub-role and its live
            // status is cleared on agent reload, so without the durable markers
            // this always read "none (idle)" with no sign it deployed anything.
            Promise.all([fetchAgentRoleState(aid), fetchDeployStatus(aid)]).then(([roleState, ds]) => {
                const cell = agentsWrap.querySelector(`.lm-agent-role-cell[data-role-cell="${CSS.escape(aid)}"]`);
                if (!cell) return;
                const active = (roleState && roleState.active) || [];
                const parts = [];
                if (Array.isArray(active) && active.length > 0) {
                    parts.push(...active.map(r => `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-700" title="${escapeHtml(r.sub_spoke_id || '')}">${escapeHtml((AGENT_ROLES[r.role] || {}).name || r.role)}</span>`));
                }
                // Live deploy-role badges (ephemeral — cleared on agent reload).
                // Render one badge PER tracked deploy role (ds.deploys), not just
                // the single most-recent one — a singular ds.deploy previously
                // meant loading a second deploy role (e.g. dhcp-server after
                // dns-server) hid the first one's badge entirely.
                const deps = Array.isArray(ds && ds.deploys) ? ds.deploys
                           : (ds && ds.deploy ? [ds.deploy] : []);
                const shownDeploy = new Set();
                for (const dep of deps) {
                    if (!dep || !dep.role || !dep.state) continue;
                    shownDeploy.add(dep.role);
                    const st = dep.state;
                    const cls = st === 'completed' ? 'bg-green-100 text-green-700'
                              : st === 'failed' || st === 'error' ? 'bg-red-100 text-red-700'
                              : 'bg-amber-100 text-amber-700';
                    const word = st === 'running' ? 'deploying…' : st;
                    // "running" can't be cleared (nothing to acknowledge yet);
                    // every settled state gets an × so a stuck badge (most
                    // often "failed") doesn't linger forever with no way to
                    // dismiss it — clearing only forgets the in-memory status,
                    // it never touches the installed service itself.
                    const clearBtn = st === 'running' ? '' :
                        `<button onclick="clearDeployStatus('${escapeHtml(aid)}','${escapeHtml(dep.role)}')" class="ml-1 font-bold leading-none hover:opacity-70" title="Clear this status">×</button>`;
                    parts.push(`<span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${cls} inline-flex items-center" title="deploy role">${escapeHtml((AGENT_ROLES[dep.role] || {}).name || dep.role)}: ${escapeHtml(word)}${clearBtn}</span>`);
                }
                // Durable deploy-role badges. A deploy role (dns-server,
                // dhcp-server, …) is an INSTALL, not a hosted sub-spoke, so it
                // never shows up in `active`; and ds.deploys is in-memory on the
                // agent, so it is empty after any agent restart. Without this the
                // tile read "none (idle)" for a node that is demonstrably running
                // Unbound/Kea — while the Roles dialog, which reads these same
                // durable markers, correctly listed them as loaded. Read the
                // marker (installed_deploy_roles) and the unit state
                // (active_deploy_roles) so the two views agree.
                const installedDeploy = (roleState && roleState.installed_deploy_roles) || [];
                const enabledDeploy = new Set((roleState && roleState.active_deploy_roles) || []);
                for (const role of installedDeploy) {
                    // netbox-server has its own dedicated badge + knob below.
                    if (role === 'netbox-server' || shownDeploy.has(role)) continue;
                    const on = enabledDeploy.has(role);
                    const cls = on ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-600';
                    const word = on ? 'installed' : 'installed (stopped)';
                    parts.push(`<span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${cls}" title="deploy role — installed on this node">${escapeHtml((AGENT_ROLES[role] || {}).name || role)}: ${word}</span>`);
                }
                // Durable NetBox-server marker + reset-admin-password knob.
                // installed_deploy_roles is the tenant-admin-visible fallback:
                // fetchDeployStatus is Global-Admin-only and returns null for
                // tenant admins, which used to hide the badge from them.
                if ((ds && ds.netbox_installed) || installedDeploy.includes('netbox-server')) {
                    parts.push(`<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-600" title="NetBox application deployed on this node">NetBox</span>`);
                    parts.push(`<button onclick="resetNetboxAdmin('${escapeHtml(aid)}')" class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-white text-[#01A982] border border-[#01A982] hover:bg-green-50 transition-colors" title="Reset the NetBox admin password">Reset admin pw</button>`);
                }
                cell.outerHTML = parts.length
                    ? `<span class="inline-flex flex-wrap items-center gap-1">${parts.join(' ')}</span>`
                    : '<span class="text-slate-400 italic">none (idle)</span>';
            });
        });
    }
}


async function loadSpokesAndAgents() {
    const spokesWrap = document.getElementById('spokes-table-wrap');
    const agentsWrap = document.getElementById('agents-table-wrap');

    // Fetch the full known-module list once and split it by module_type.
    // Treated as agents (shown in the Agents/Generic Agents sections, not
    // Spokes):
    //   - module_type "agent"  : generic Hub-direct agents (e.g. ab)
    // The pxmx "hypervisor" spoke is itself a spoke, so it is shown in the
    // Spokes section (its Proxmox node agents are fetched separately into the
    // Agents section).
    let spokes = [];
    let pxmxAgents = [];
    const pxmxAgentIds = new Set();
    let diagBy = null;
    let diagData = null;

    // Three independent fetches (pending spokes, pxmx agents, diagnostics) were
    // sequential — each awaited before the next started. Fan them out
    // concurrently with Promise.all so the Spokes & Agents view resolves in one
    // round-trip instead of three; each branch keeps its own try/catch so a
    // single failure degrades the same as before (best-effort).
    // The Agents fetch must follow THIS view's own tenant dropdown
    // (sa-tenant-filter), NOT the global currentTenant. /api/pxmx/agents filters
    // its (offline) roster server-side to the passed tenant, so pinning
    // currentTenant dropped an offline/unassigned pxmx agent BEFORE the "All
    // tenants" client-side filter (_saMatch) below could include it — the agent
    // whose parent spoke is offline then showed in neither list (invisible +
    // undeletable). For "All tenants"/"Unassigned" we fetch the FULL roster
    // (omit the param → admin session resolves to no scope) and let _saMatch
    // narrow; a specific-tenant selection is passed straight through.
    const _saFilterForFetch = document.getElementById('sa-tenant-filter')?.value || '__all__';
    const _agentsUrl = (_saFilterForFetch === '__all__' || _saFilterForFetch === '__unassigned__')
        ? '/api/pxmx/agents'
        : '/api/pxmx/agents?tenant=' + encodeURIComponent(_saFilterForFetch);
    const [spokesRes, agentsRes, diagRes] = await Promise.allSettled([
        (async () => setupFetch('/setup/pending_spokes'))(),
        (async () => fetch(_agentsUrl, { credentials: 'same-origin' }))(),
        (async () => setupFetch('/setup/diagnostics'))(),
    ]);

    if (spokesRes.status === 'fulfilled') {
        try {
            const res = spokesRes.value;
            if (res.ok) spokes = (await res.json()).spokes || [];
        } catch (err) {
            if (spokesWrap) spokesWrap.innerHTML = `<p class="py-6 text-center text-red-400 italic text-xs">Error: ${err.message}</p>`;
        }
    } else if (spokesWrap) {
        spokesWrap.innerHTML = `<p class="py-6 text-center text-red-400 italic text-xs">Error: ${spokesRes.reason?.message || spokesRes.reason}</p>`;
    }

    // Proxmox node agents are relayed through the pxmx hypervisor spoke. Fetch
    // them up front so we can (a) exclude their ids from the Spokes table — an
    // older approval leaked them into known_modules and rendered a bogus
    // spoke row, since the hub has no direct WebSocket for them — and (b)
    // render them in the Agents table below.
    if (agentsRes.status === 'fulfilled') {
        try {
            const res = agentsRes.value;
            if (res.ok) {
                const agentsData = await res.json();
                const connected = (agentsData.agents || []).map(a => ({ ...a, _status: 'connected', _kind: 'pxmx', _module: 'Proxmox' }));
                const pending   = (agentsData.pending_agents || []).map(a => ({ ...a, _status: 'pending', _kind: 'pxmx', _module: 'Proxmox' }));
                // Relayed agents whose PARENT spoke is offline — reconstructed by
                // the hub from persisted state so they can be seen + deleted even
                // though there's no live connection to fan GET_AGENTS to.
                const offline   = (agentsData.offline_agents || []).map(a => ({ ...a, _status: 'offline', _kind: 'pxmx', _module: 'Proxmox' }));
                pxmxAgents = [...connected, ...pending, ...offline];
                pxmxAgents.forEach(a => pxmxAgentIds.add(a.agent_id));
            }
        } catch (err) { console.error('loadSpokesAndAgents: pxmx agents fetch failed — generic agents still render', err); }
    }

    // Diagnostics telemetry (the former standalone Diagnostics tile, now folded
    // into the three management cards). Fetched once here and keyed by spoke_id
    // so each renderer can merge heartbeat/version/recovery/events into its row
    // via _diagTelemetryExtras. Best-effort: a failed/non-admin fetch leaves
    // diagBy empty and the tiles degrade to their approval-only rows. The same
    // response drives the summary bar (Hub/WebUI version + recovery counts).
    if (diagRes.status === 'fulfilled') {
        try {
            const res = diagRes.value;
            if (res.ok) {
                diagData = await res.json();
                diagBy = new Map((diagData.spokes || []).map(s => [s.spoke_id, s]));
            }
        } catch (err) { console.error('loadSpokesAndAgents: diagnostics fetch failed — telemetry badges skipped', err); }
    }
    _renderSpokesSummary(diagData);

    // A loaded role registers a sub-spoke "{agentBase}-{role}", so a spoke that
    // is the BASE of one is a generic agent hosting roles. Recognise it as an
    // agent even when its own module_type didn't round-trip (a disconnected or
    // pre-role agent can report module_type ""), so the AGENT itself lands in
    // the Agents area instead of being double-listed as a plain spoke. Each
    // role sub-spoke still keeps its OWN row in the Spokes table (its
    // module_type is the role's, not "agent") — the intended model is one entry
    // per role spoke plus one for the agent.
    //
    // B4: after the guid-primary migration (B1), the base agent + each role
    // sub-spoke are independent guid keys, so the pre-B1 "{base}-{role}"
    // string-prefix match no longer holds. The hub now stamps an explicit
    // ``parent_spoke_id`` (the parent's current primary key) + ``role_name`` on
    // each sub-spoke row; prefer that. The legacy prefix/endsWith fallbacks
    // stay for pre-B1 entries that don't carry the fields yet.
    const hasRole = baseId => spokes.some(o => o.spoke_id !== baseId && (
        (o.parent_spoke_id && o.parent_spoke_id === baseId) ||
        o.spoke_id.startsWith(baseId + '-')));
    const isAgent = s => String(s.module_type || '').toLowerCase() === 'agent' || hasRole(s.spoke_id);
    const trueSpokes    = spokes.filter(s => !isAgent(s) && !pxmxAgentIds.has(s.spoke_id));
    const genericAgents = spokes.filter(isAgent);

    // Annotate each role sub-spoke ("{agentBase}-{role}") with its parent agent
    // + role name, so the Spokes table can offer a per-role "Unload" action
    // (remove a role directly from its own spoke entry). The longest matching
    // agent-id prefix is the closest parent; the suffix after it is the role
    // name (== the _ROLE_MAP key the agent's UNLOAD_ROLE expects).
    const _agentIds = genericAgents.map(a => a.spoke_id);
    // Known role suffixes ("{agentBase}-{role}") from the role registry, longest
    // first so e.g. a compound key wins over a shorter prefix of it.
    const _roleKeys = Object.keys(AGENT_ROLES).sort((a, b) => b.length - a.length);
    trueSpokes.forEach(s => {
        // B4 primary: the hub-stamped explicit parent linkage (guid-stable,
        // works whether the parent is connected or offline). ``parent_spoke_id``
        // is the parent's current primary key (matches a genericAgent row's
        // ``spoke_id``); ``role_name`` is the _ROLE_MAP key.
        let parent = s.parent_spoke_id || '';
        let roleName = s.role_name || '';
        // Legacy prefix fallback (pre-B1 entries without parent_spoke_id): the
        // closest CURRENTLY-CONNECTED generic agent whose id is a prefix of this
        // sub-spoke id.
        if (!parent || !roleName) {
            const prefixParent = _agentIds
                .filter(aid => s.spoke_id !== aid && s.spoke_id.startsWith(aid + '-'))
                .sort((a, b) => b.length - a.length)[0];
            if (prefixParent && !parent) parent = prefixParent;
            if (prefixParent && !roleName) roleName = s.spoke_id.slice(prefixParent.length + 1);
        }
        // Fallback: identify a role sub-spoke by a trailing "-<knownRole>" even
        // when its parent agent isn't in the connected list right now (agent
        // flapping / not yet re-approved). This keeps "Unload Role" available on
        // the role's own row regardless of the parent's live state.
        if (!roleName) {
            const match = _roleKeys.find(role =>
                s.spoke_id.endsWith('-' + role) && s.spoke_id.length > role.length + 1);
            if (match) {
                roleName = match;
                if (!parent) parent = s.spoke_id.slice(0, s.spoke_id.length - match.length - 1);
            }
        }
        if (parent && roleName) {
            s._roleParent = parent;
            s._roleName = roleName;
        }
    });

    // Split generic agents by whether they host a role yet. A loaded role
    // registers a sub-spoke "{base}-{role}" (module_type = the role's), so a
    // generic agent is "active" iff some known spoke id starts with
    // "{base}-". Idle generic agents (no sub-spoke) go in the Generic Agents
    // tile until a role is loaded; active ones move to the Agents tile
    // alongside the Proxmox node agents. This needs no per-agent
    // GET_AVAILABLE_ROLES round-trip — the sub-spoke presence in the already-
    // fetched known-modules list is the signal (mirrors how the multi-role
    // design registers each role as its own spoke). hasRole is defined above.
    // Sort the Spokes tile by display name (case-insensitive) so the admin
    // view is browsable by name regardless of connect/approval order. Falls
    // back to spoke_id when no display_name is set.
    trueSpokes.sort((a, b) =>
        (_spokeName(a) || '').localeCompare(
            (b.display_name || b.spoke_id || ''), undefined, { sensitivity: 'base' }));

    // Tenant filter (Setup → Spokes & Agents dropdown). Applied LAST — after the
    // role-annotation pass above has run against the full set — so a role
    // sub-spoke's parent lookup is never broken by a filtered-out peer. Spokes
    // and generic agents carry tenant_id directly. A pxmx node agent's tenant
    // is its OWN pinned client_simulation.tenant_id when set (same precedence
    // as the DISPLAY label, _tenantOf) — NOT just its owning spoke's binding;
    // using the spoke's tenant_id here (ignoring the per-agent pin) silently
    // dropped a Proxmox agent explicitly assigned to a tenant (e.g. ADMIN/
    // "default") from that tenant's filtered view whenever its spoke itself
    // was bound/shared/unassigned differently — the reported "doesn't always
    // show all spokes and agents assigned to Admin" bug. "__unassigned__"
    // (the default) matches anything with no tenant binding — the freshly
    // onboarded spokes/agents an admin triages first; "__all__" disables the
    // filter.
    const _saFilter = document.getElementById('sa-tenant-filter')?.value || '__unassigned__';
    const _spokeTenantById = new Map(spokes.map(s => [s.spoke_id, (s.tenant_id || '').trim()]));
    const _saMatch = (tid) => {
        tid = (tid || '').trim();
        if (_saFilter === '__all__') return true;
        if (_saFilter === '__unassigned__') return !tid;
        return tid === _saFilter;
    };
    const trueSpokesF    = trueSpokes.filter(s => _saMatch(s.tenant_id));
    const genericAgentsF = genericAgents.filter(s => _saMatch(s.tenant_id));
    const pxmxAgentsF    = pxmxAgents.filter(a => _saMatch(_tenantOf(a) || _spokeTenantById.get(a.spoke_id)));


    _renderSpokesTable(spokesWrap, trueSpokesF, diagBy);
    // An agent is an agent — idle (no role yet) and active (role-loaded) generic
    // agents both render in the single Agents table alongside the Proxmox node
    // agents. (The former separate "Generic Agents" tile was removed — splitting
    // by idle/active gave no useful signal and just hid freshly-onboarded agents
    // in a second card.) Load Role + Approve affordances live in _renderAgentsTable.
    await _renderAgentsTable(agentsWrap, genericAgentsF, pxmxAgentsF, diagBy);
}

// _renderSpokesSummary(diagData) — the spoke-update recovery-count bar that sat
// at the top of the former Diagnostics tile, hoisted above the Spokes card now
// that the diagnostics telemetry lives inline in the management cards. The bar
// shows Recovering/Gave up/Paused pills only when there are recovery events and
// hides otherwise (the Hub/WebUI version pills + Heartbeat/SKEW/ALERT legend
// were removed by request). `diagData` is the /setup/diagnostics JSON (or null
// when the fetch failed / viewer is non-admin — bar clears so a broken telemetry
// fetch doesn't leave a stale summary). Stashes hub/webui version on window for
// File-a-Bug context.
function _renderSpokesSummary(diagData) {
    const el = document.getElementById('spokes-summary');
    if (!el) return;
    if (!diagData) { el.innerHTML = ''; return; }
    const hubVersion = diagData.hub_version || 'unknown';
    const webuiVersion = diagData.webui_version || 'unknown';
    window.__lmHubVersion = hubVersion;
    window.__lmWebuiVersion = webuiVersion;
    let recovering = 0, gaveUp = 0, paused = 0;
    for (const s of (diagData.spokes || [])) {
        const r = s.recovery || {};
        if (r.manual_pause) paused++;
        else if (r.gave_up) gaveUp++;
        else if (r.in_progress) recovering++;
    }
    // The Hub/WebUI version pills + the Heartbeat/SKEW/ALERT legend were removed
    // by request — the bar now surfaces only spoke-update recovery counts and
    // hides entirely when nothing is recovering/gave-up/paused. hub/webui version
    // is still stashed on window above for File-a-Bug context.
    if (!recovering && !gaveUp && !paused) {
        el.innerHTML = '';
        return;
    }
    el.innerHTML = `
        ${recovering ? `<span class="px-2 py-1 rounded-md bg-amber-100 text-amber-700 font-medium">Recovering: ${recovering}</span>` : ''}
        ${gaveUp ? `<span class="px-2 py-1 rounded-md bg-red-100 text-red-700 font-medium">Gave up: ${gaveUp}</span>` : ''}
        ${paused ? `<span class="px-2 py-1 rounded-md bg-slate-200 text-slate-600 font-medium">Paused: ${paused}</span>` : ''}
    `;
}

async function approveAgent(agentId, knownSpokeId) {
    // Prefer the spoke_id the caller already has from the rendered row — the
    // Agents tile tags every agent with its owning spoke_id (see
    // get_pxmx_agents), so re-deriving it is unnecessary and was actively
    // harmful: the old resolve fetched /api/pxmx/agents scoped to the tenant
    // PICKER, which drops any agent whose owning spoke is bound to a different
    // tenant (e.g. a hypervisor spoke on tenant "shared" while the picker is
    // on "lrb"). That made Approve dead-end with "could not determine which
    // spoke owns this agent" even though the row was plainly visible, and it
    // never POSTed at all.
    let spokeId = knownSpokeId || null;
    if (!spokeId) {
        try {
            // Fallback resolve is deliberately tenant-AGNOSTIC (no ?tenant=):
            // approval is an admin action and must not depend on the picker.
            const res = await fetch('/api/pxmx/agents', { credentials: 'same-origin' });
            const data = res.ok ? await res.json() : {};
            // offline_agents too: its rows carry spoke_id (routes/pxmx.py
            // _offline_relay_agents), and an agent whose parent spoke is briefly
            // disconnected appears ONLY there.
            const all = [...(data.agents || []), ...(data.pending_agents || []),
                         ...(data.offline_agents || [])];
            const found = all.find(a => a.agent_id === agentId);
            spokeId = found && found.spoke_id;
        } catch (e) { console.error('approveAgent: could not resolve owning spoke', e); }
    }
    if (!spokeId) {
        // Genuinely no owning spoke on record — the agent hasn't been relayed
        // by any connected spoke yet. This is now a true dead-end, not a
        // tenant-visibility artifact.
        showToast('Could not determine which spoke owns this agent — its owning '
                  + 'spoke may not be connected yet. Retry once the spoke is online.', 'error');
        return;
    }
    try {
        const res = await setupFetch(`/setup/spokes/${encodeURIComponent(spokeId)}/agents/${encodeURIComponent(agentId)}/approve`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
        });
        const d = await res.json();
        if (res.ok) { showToast(`Agent '${_spokeLabelFor(agentId)}' approved`, 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Approval failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function revokeAgent(agentId) {
    if (!await showConfirmToast(`Disconnect agent '${_spokeLabelFor(agentId)}'? It will auto-reconnect and require re-approval.`)) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/revoke`, {
            method: 'POST', credentials: 'same-origin',
        });
        const d = await res.json();
        if (res.ok) { showToast(d.message || 'Agent disconnected', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Revoke failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}


// Agent Configuration modal for Proxmox node agents — display name + Client
// Simulation mode toggle + tenant. Supersedes the editAgentName prompt; the
// row's Edit button (loadSpokesAndAgents) now opens this. Models on
// openSpokeMetadataModal / saveSpokeMetadata above.
async function openAgentConfigModal(agentId, currentLabel) {
    const modal = document.createElement('div');
    modal.id = 'agent-config-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    // Load the stored config. Tenant binding is NOT edited here — it has its own
    // "Tenant" button on the row (openAgentAssignModal), matching the Spokes
    // table where Edit is metadata-only and tenant is a separate action. The
    // current tenant is still read so we can show it read-only and preserve it
    // on save (Edit must never silently drop the binding).
    let displayName = (currentLabel && currentLabel !== agentId) ? currentLabel : '';
    let csEnabled = false;
    let tenantId = '';
    let managedCrontab = '';
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, { credentials: 'same-origin' });
        if (res.ok) {
            const data = await res.json();
            const cfg = data.config || {};
            if (cfg.display_name) displayName = cfg.display_name;
            const cs = cfg.client_simulation || {};
            csEnabled = !!cs.enabled;
            tenantId = cs.tenant_id || '';
            managedCrontab = typeof cfg.managed_crontab === 'string' ? cfg.managed_crontab : '';
        }
    } catch (e) { console.error('Error fetching agent config:', e); }

    const safeName = (displayName || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const safeTenant = (tenantId || '').replace(/"/g, '&quot;');
    const safeCron = (managedCrontab || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-3xl overflow-hidden max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Agent Configuration</h3>
                <button onclick="this.closest('#agent-config-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-2">${_spokeLabelFor(agentId)}</div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Display Name</label>
                    <input type="text" id="agent-cfg-display-name" value="${safeName}" placeholder="${agentId}" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Client Simulation</label>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" id="agent-cfg-cs-enabled" ${csEnabled ? 'checked' : ''} class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                        <label for="agent-cfg-cs-enabled" class="text-sm text-slate-600">Enable Client Simulation mode on this host</label>
                    </div>
                    <p class="text-[11px] text-slate-400">When enabled, this Proxmox agent activates the Client-Sim feature set (USB provisioning, VM clone/reclone, watchdogs, backup, reseed). Features are ported in incrementally.</p>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Managed Crontab</label>
                    <textarea id="agent-cfg-crontab" rows="5" spellcheck="false" placeholder="# One crontab line per job, e.g.\n0 2 * * * /usr/bin/vzdump --all --compress zstd\n*/15 * * * * /root/health-check.sh" class="w-full bg-slate-50 border border-slate-300 rounded-md px-3 py-2 text-xs font-mono outline-none focus:ring-2 focus:ring-green-500 resize-y">${safeCron}</textarea>
                    <p class="text-[11px] text-slate-400">Standard crontab lines the agent keeps in sync inside a managed block of <b>root's crontab</b> on this Proxmox server — your own crontab entries are left untouched. Applies to any host (simulation or not). Saving replaces the managed block; clearing this box removes it. Drift is re-corrected every ~10&nbsp;min.</p>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
                    <input type="hidden" id="agent-cfg-tenant" value="${safeTenant}">
                    <p class="text-sm text-slate-700">${tenantId ? `<span class="font-mono">${tenantId.replace(/</g, '&lt;')}</span>` : '<span class="italic text-slate-400">(unbound)</span>'}</p>
                    <p class="text-[11px] text-slate-400">Use the <b>Tenant</b> button on the agent row to change this binding.</p>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#agent-config-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveAgentConfig('${agentId.replace(/'/g, "\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
                </div>
            </div>
        </div>
    `;
    _mountModal(modal);
}

async function saveAgentConfig(agentId) {
    const displayName = document.getElementById('agent-cfg-display-name').value.trim();
    const csEnabled = document.getElementById('agent-cfg-cs-enabled').checked;
    const tenantId = document.getElementById('agent-cfg-tenant').value;
    const cronEl = document.getElementById('agent-cfg-crontab');
    try {
        const body = {
            display_name: displayName || agentId,
            client_simulation: { enabled: csEnabled, tenant_id: tenantId },
        };
        // Only send managed_crontab when the field is present (this modal) so
        // other callers of this endpoint don't inadvertently clear it.
        if (cronEl) body.managed_crontab = cronEl.value;
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            // d.queued: the owning spoke was momentarily unreachable and this
            // was queued via the Mailbox instead of dropped — surface that as
            // a distinct tone from an already-live push (see push_or_queue_to_spoke).
            showToast(d.message || 'Agent config saved', d.queued ? 'info' : 'success');
            document.getElementById('agent-config-modal')?.remove();
            loadSpokesAndAgents();
        } else {
            showToast(d.detail || 'Save failed', 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

/* Dedicated "Tenant" modal for Proxmox node agents — the agent-side counterpart
 * to openSpokeAssignModal, so every agent row has the same tenant action a spoke
 * row does. A Proxmox agent's binding lives in client_simulation.tenant_id (per-
 * agent config), not on a spoke approval, so this writes via the agent config
 * API rather than /setup/approve_spoke. Generic (agent-type spoke) agents use
 * openSpokeAssignModal directly. We read the current config first so saving the
 * tenant preserves display_name + the CS-enabled flag (stashed in hidden inputs)
 * — changing the tenant must never wipe the other config. */
async function openAgentAssignModal(agentId, currentTenantId) {
    const modal = document.createElement('div');
    modal.id = 'agent-assign-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let displayName = '';
    let csEnabled = false;
    let tenantId = currentTenantId || '';
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, { credentials: 'same-origin' });
        if (res.ok) {
            const cfg = (await res.json()).config || {};
            displayName = cfg.display_name || '';
            const cs = cfg.client_simulation || {};
            csEnabled = !!cs.enabled;
            tenantId = cs.tenant_id || tenantId;
        }
    } catch (e) { console.error('Error fetching agent config for tenant assign:', e); }

    let tenantOptions = '';
    try {
        const res = await setupFetch('/setup/tenants');
        if (res.ok) {
            const tenants = (await res.json()).tenants || [];
            const sel = tenantId || currentTenant || 'default';
            tenantOptions = tenants.map(t =>
                `<option value="${t.id}" ${t.id === sel ? 'selected' : ''}>${t.name}</option>`).join('');
        }
    } catch (e) { console.error('Error fetching tenants for agent assign:', e); }

    const safeDn = (displayName || '').replace(/"/g, '&quot;');

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Assign Agent to Tenant</h3>
                <button onclick="this.closest('#agent-assign-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-2">${_spokeLabelFor(agentId)}</div>
                <input type="hidden" id="agent-assign-dn" value="${safeDn}">
                <input type="hidden" id="agent-assign-cs" value="${csEnabled ? '1' : '0'}">
                <p class="text-[11px] text-slate-400">Binds this Proxmox node agent to a tenant so its telemetry appears in that tenant's VM Server. The agent's display name and Client-Simulation setting are preserved.</p>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
                    <select id="agent-assign-tenant" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="" ${!tenantId ? 'selected' : ''}>(unbound)</option>
                        ${tenantOptions}
                    </select>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#agent-assign-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveAgentTenant('${agentId.replace(/'/g, "\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Assign</button>
                </div>
            </div>
        </div>
    `;
    _mountModal(modal);
}

async function saveAgentTenant(agentId) {
    const tenantId = document.getElementById('agent-assign-tenant').value;
    const displayName = document.getElementById('agent-assign-dn').value;
    const csEnabled = document.getElementById('agent-assign-cs').value === '1';
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                display_name: displayName || agentId,
                client_simulation: { enabled: csEnabled, tenant_id: tenantId },
            }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(d.message || 'Agent tenant updated', d.queued ? 'info' : 'success');
            document.getElementById('agent-assign-modal')?.remove();
            loadSpokesAndAgents();
        } else {
            showToast(d.detail || 'Save failed', 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

/* Admin assigns/rebinds ANY spoke to a tenant — a "Tenant" button on every row
 * in Setup → Spokes & Agents (_renderSpokesTable), plus Simulations → Spoke
 * Management for cs spokes specifically. Mirrors openAgentConfigModal but
 * talks to the existing admin /setup/approve_spoke route (idempotent
 * re-approve + tenant binding). Agent-hosting spokes (cs/pxmx) seed any newly
 * approved agent's tenant from this binding (approve_agent_under_spoke in
 * api.py), so an agent connecting to a tenant-bound spoke inherits it without
 * per-agent configuration. Only the admin UI renders the button that opens
 * this, so /setup/tenants (admin-only) is safe to call here. */
async function openSpokeAssignModal(spokeId, currentTenantId, noun = 'Spoke') {
    const modal = document.createElement('div');
    modal.id = 'spoke-assign-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let tenantOptions = '';
    try {
        const res = await setupFetch('/setup/tenants');
        if (res.ok) {
            const tenants = (await res.json()).tenants || [];
            const sel = currentTenantId || currentTenant || 'default';
            tenantOptions = tenants.map(t =>
                `<option value="${t.id}" ${t.id === sel ? 'selected' : ''}>${t.name}</option>`).join('');
        }
    } catch (e) { console.error('Error fetching tenants for spoke assign:', e); }

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Assign ${noun} to Tenant</h3>
                <button onclick="this.closest('#spoke-assign-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-2">${noun}: ${_spokeLabelFor(spokeId)}</div>
                <p class="text-[11px] text-slate-400">Approving (re-approving) this ${noun.toLowerCase()} with a tenant binds it so its telemetry appears in that tenant's VM Server. Idempotent — the session secret is preserved.</p>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
                    <select id="spoke-assign-tenant" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="" ${!currentTenantId ? 'selected' : ''}>(unbound)</option>
                        ${tenantOptions}
                    </select>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#spoke-assign-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveSpokeAssign('${spokeId.replace(/'/g, "\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Assign</button>
                </div>
            </div>
        </div>
    `;
    _mountModal(modal);
}

async function saveSpokeAssign(spokeId) {
    const tenantId = document.getElementById('spoke-assign-tenant').value;
    try {
        const res = await setupFetch('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'approve', tenant_id: tenantId }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(d.message || 'Spoke assigned', 'success');
            document.getElementById('spoke-assign-modal')?.remove();
            // Now opened from two contexts: Simulations → Spoke Management
            // (cs spokes only) and Setup → Spokes & Agents (any spoke) — reload
            // whichever is actually on screen.
            if (currentView === 'setup') loadSpokesAndAgents();
            else if (typeof loadCSData === 'function') loadCSData('Spoke Management');
        } else {
            showToast(d.detail || 'Assign failed', 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteSpoke(spokeId, label) {
    const name = label || spokeId;
    if (!await showConfirmToast(`Force delete '${name}'?\n\nThis permanently removes the registration and its secret. ` +
                 `If it is currently connected it will be disconnected and must fully re-onboard to return. ` +
                 `This cannot be undone — prefer Decommission (reversible) unless you mean to wipe it.`)) return;
    try {
        const res = await setupFetch(`/setup/spokes/${encodeURIComponent(spokeId)}`, { method: 'DELETE' });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast(d.message || 'Removed', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Delete failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteAgent(agentId) {
    if (!await showConfirmToast(`Force delete agent '${_spokeLabelFor(agentId)}'?\n\nThis disconnects it if connected and clears its hub-side ` +
                 `state (config, display name, heartbeat, approval). Works even if its parent spoke is offline. ` +
                 `It will need re-approval to reconnect. This cannot be undone — prefer Decommission (reversible) ` +
                 `unless you mean to wipe it.`)) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}`, {
            method: 'DELETE', credentials: 'same-origin',
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast(d.message || 'Agent removed', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Delete failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// Soft-retire a spoke/generic-agent: keep the record (stays visible +
// re-onboardable) but flag it decommissioned so the out-of-contact alert loop
// skips it + the UI badged it grey. Reversible via restoreSpoke.
async function decommissionSpoke(spokeId, label) {
    const name = label || spokeId;
    if (!await showConfirmToast(`Decommission '${name}'?\n\nThis RETIRES it (keeps the record, suppresses its ` +
                 `out-of-contact alert) — reversible with Restore. Use Force Delete to remove it entirely.`)) return;
    try {
        const res = await setupFetch(`/setup/spokes/${encodeURIComponent(spokeId)}/decommission`, { method: 'POST' });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast('Decommissioned', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Decommission failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function restoreSpoke(spokeId, label) {
    const name = label || spokeId;
    if (!await showConfirmToast(`Restore '${name}' from decommission?\n\nThis re-enables its out-of-contact alerting. ` +
                 `If it is still offline the alert will resume next cycle.`)) return;
    try {
        const res = await setupFetch(`/setup/spokes/${encodeURIComponent(spokeId)}/restore`, { method: 'POST' });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast('Restored', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Restore failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function decommissionAgent(agentId) {
    if (!await showConfirmToast(`Decommission agent '${_spokeLabelFor(agentId)}'?\n\nThis RETIRES it (keeps the record, badged grey) — ` +
                 `reversible with Restore. Use Force Delete to remove it entirely.`)) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/decommission`, {
            method: 'POST', credentials: 'same-origin',
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast('Agent decommissioned', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Decommission failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function restoreAgent(agentId) {
    if (!await showConfirmToast(`Restore agent '${_spokeLabelFor(agentId)}' from decommission?`)) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/restore`, {
            method: 'POST', credentials: 'same-origin',
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast('Agent restored', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Restore failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function openSpokeMetadataModal(spokeId, currentName, approved) {
    const modal = document.createElement('div');
    modal.id = 'spoke-metadata-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let description = '';
    try {
        const res = await setupFetch(`/setup/spoke-metadata/${encodeURIComponent(spokeId)}`);
        if (res.ok) {
            const data = await res.json();
            description = data.metadata.description || '';
            currentName = data.metadata.display_name || currentName;
        }
    } catch (e) {
        console.error('Error fetching spoke metadata:', e);
    }

    const safeName = (currentName || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const safeDesc = description.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const eId = spokeId.replace(/'/g, "\\'");

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Spoke Metadata</h3>
                <button onclick="this.closest('#spoke-metadata-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-4">${_spokeLabelFor(spokeId)}</div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Display Name</label>
                    <input type="text" id="meta-display-name" value="${safeName}" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Description</label>
                    <textarea id="meta-description" rows="3" placeholder="Describe the purpose of this spoke..." class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${safeDesc}</textarea>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">System Hostname (Optional)</label>
                    <input type="text" id="meta-hostname" placeholder="e.g. opnsense-core" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="pt-4 border-t border-slate-200 space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Spoke Actions</label>
                    <div class="flex flex-wrap gap-2">
                        <button onclick="resetSpokeSecret('${eId}'); this.closest('#spoke-metadata-modal').remove()" class="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 transition-colors" title="Regenerate this spoke's shared secret — the spoke must be reconfigured with the new value">Reset Secret</button>
                        ${approved ? `<button onclick="unapproveSpoke('${eId}'); this.closest('#spoke-metadata-modal').remove()" class="px-3 py-1.5 text-xs font-medium rounded-md bg-red-50 hover:bg-red-100 text-red-600 border border-red-200 transition-colors">Un-approve</button>` : ''}
                    </div>
                    <p class="text-[11px] text-slate-400">Reset Secret wipes stored keys and forces re-onboarding. Un-approve revokes access until re-approved.</p>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#spoke-metadata-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveSpokeMetadata('${spokeId.replace(/'/g, "\\'")}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
                </div>
            </div>
        </div>
    `;
    _mountModal(modal);
}

async function saveSpokeMetadata(spokeId) {
    const displayName = document.getElementById('meta-display-name').value;
    const description = document.getElementById('meta-description').value;
    const hostname = document.getElementById('meta-hostname').value;

    try {
        const response = await setupFetch('/setup/spoke-metadata', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                spoke_id: spokeId,
                metadata: {
                    display_name: displayName,
                    description: description
                }
            })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            const errorMsg = errorData.detail || `HTTP ${response.status}: ${response.statusText}`;
            throw new Error(errorMsg);
        }

        if (hostname) {
            await setupFetch('/setup/spoke-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    spoke_id: spokeId,
                    display_name: displayName,
                    hostname: hostname
                })
            });
        }

        showToast('Spoke metadata updated successfully.', 'success');
        const modal = document.getElementById('spoke-metadata-modal');
        if (modal) modal.remove();
        await loadSpokesAndAgents();
        updateStatus();
    } catch (err) {
        showToast('Error updating metadata: ' + err.message, 'error');
    }
}

// Reload the active management surface after a spoke/agent state change
// (approve / un-approve / reset-secret / delete). The Setup > Spokes & Agents
// page now hosts the admin cards AND the folded-in diagnostics telemetry in
// one loadSpokesAndAgents() pass, so a single call repopulates both — a spoke
// state change surfaces in the telemetry badges too.
function _reloadActiveMgmtView() {
    loadSpokesAndAgents();
}

async function approveSpoke(spokeId) {
    try {
        await apiJson('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'approve' })
        });

        _reloadActiveMgmtView();
        updateStatus();
    } catch (err) {
        showToast('Error approving spoke: ' + err.message, 'error');
    }
}

async function unapproveSpoke(spokeId) {
    try {
        await apiJson('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'unapprove' })
        });

        _reloadActiveMgmtView();
        updateStatus();
    } catch (err) {
        showToast('Error un-approving spoke: ' + err.message, 'error');
    }
}

async function resetSpokeSecret(spokeId) {
    if (!await showConfirmToast(`Are you sure you want to reset the secret for ${_spokeLabelFor(spokeId)}? This will wipe all stored keys and force the spoke to re-onboard using a new first-secret.`)) {
        return;
    }
    try {
        await apiJson(`/setup/spokes/${encodeURIComponent(spokeId)}/reset-secret`, { method: 'POST' });

        showToast(`Secret for ${_spokeLabelFor(spokeId)} has been reset. Restart the agent install or trigger a new handshake.`, 'success');
        _reloadActiveMgmtView();
    } catch (err) {
        showToast('Error resetting secret: ' + err.message, 'error');
    }
}

async function loadUsers() {
    const bodyEl = document.getElementById('user-permissions-body');
    if (!bodyEl) return;

    try {
        // Tenant Admins manage their CURRENT tenant's users via the tenant-
        // scoped route; Global Admins see the whole fleet via /setup/users.
        const base = _taUsersBase();
        const data = await apiJson(base ? base : '/setup/users');
        const users = data.users || {};
        const viewerIsTadm = !!isTenantAdmin();

        if (Object.keys(users).length === 0) {
            bodyEl.innerHTML = `<tr class="text-center py-8 text-slate-400 italic"><td colspan="17">No users configured.</td></tr>`;
            return;
        }

        // Cache group id→name for the Groups column badges.
        window._permGroupNames = window._permGroupNames || {};
        bodyEl.innerHTML = Object.entries(users).map(([userId, user]) => {
            // Show EFFECTIVE access (groups ∪ per-user) so the table reflects
            // what the user actually gets; fall back to per-user perms if the
            // backend predates RBAC enrichment.
            const perms = user.effective_permissions || user.permissions || {};
            // Admin is stored in two equivalent forms (permissions.admin boolean
            // and permissions.role == "admin"); honor both so a role-only admin
            // (e.g. the first-run bootstrap admin) renders as checked.
            const adminCell = (perms.admin === true || perms.role === 'admin')
                ? `<svg class="w-4 h-4 text-green-500 mx-auto" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>`
                : (perms.role === 'tenant_admin')
                    ? `<span class="text-[10px] bg-amber-100 text-amber-800 border border-amber-200 px-1.5 py-0.5 rounded font-bold" title="Tenant-level Admin">Admin</span>`
                    : `<div class="w-4 h-4 rounded-full border-2 border-slate-200 mx-auto"></div>`;
            const check = (key) => perms[key] ?
                `<svg class="w-4 h-4 text-green-500 mx-auto" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>` :
                `<div class="w-4 h-4 rounded-full border-2 border-slate-200 mx-auto"></div>`;
            const authBadge = (user.auth_type === 'entra')
                ? `<span class="text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded font-medium">Entra</span>`
                : (user.auth_type === 'ldap')
                    ? `<span class="text-[10px] bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded font-medium">LDAP</span>`
                    : `<span class="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-medium">Local</span>`;
            const tenantBadges = (user.tenants || []).map(t =>
                `<span class="text-[10px] bg-green-50 text-green-700 border border-green-200 px-1.5 py-0.5 rounded font-mono cursor-pointer hover:bg-green-100" onclick="viewAsTenant('${t}')">${t}</span>`
            ).join(' ') || '<span class="text-[10px] text-slate-300 italic">none</span>';
            const groupBadges = (user.groups || []).map(g =>
                `<span class="text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-200 px-1.5 py-0.5 rounded font-medium">${window._permGroupNames[g] || g}</span>`
            ).join(' ') || '<span class="text-[10px] text-slate-300 italic">none</span>';

            const isProtected = !!user.protected;
            const lockIcon = `<svg class="w-3 h-3 inline-block text-slate-400 ml-1" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/></svg>`;
            // A tenant Admin may not edit/remove protected OR admin-tier users
            // (the backend 403s; hide the buttons so the UI matches). Global
            // Admins see the full action set for non-protected users.
            const lockedForTadm = viewerIsTadm && (isProtected || _isPermsAdminTier(perms));
            const actions = isProtected
                ? `<span class="text-slate-300 text-xs italic select-none">Protected${lockIcon}</span>`
                : lockedForTadm
                    ? `<span class="text-slate-300 text-xs italic select-none">Admin${lockIcon}</span>`
                    : `<button onclick="editUser('${userId}')" class="text-blue-400 hover:text-blue-600 text-xs font-bold mr-3">Edit</button>
                       <button onclick="deleteUser('${userId}')" class="text-red-400 hover:text-red-600 text-xs font-bold" title="Permanently delete this user account">Delete</button>`;

            // Resolve a human label for directory (Entra/LDAP) users from the
            // stored name/email; local users have only their username → show it
            // prominently as before, with the oid as a small subtitle otherwise.
            const nameLine = user.name ? `<div class="text-sm text-slate-800">${escapeHtml(user.name)}</div>` : '';
            const emailLine = (user.email && user.email !== user.name) ? `<div class="text-xs text-slate-500">${escapeHtml(user.email)}</div>` : '';
            const oidLine = `<div class="font-mono text-[10px] text-slate-400">${userId}${isProtected ? lockIcon : ''}</div>`;
            const userCell = (nameLine || emailLine)
                ? `${nameLine}${emailLine}${oidLine}`
                : `<div class="font-mono text-xs font-medium text-slate-700">${userId}${isProtected ? lockIcon : ''}</div>`;

            return `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3">${userCell}</td>
                    <td class="px-4 py-3">${authBadge}</td>
                    <td class="px-4 py-3 max-w-[140px]"><div class="flex flex-wrap gap-1">${tenantBadges}</div></td>
                    <td class="px-4 py-3 max-w-[140px]"><div class="flex flex-wrap gap-1">${groupBadges}</div></td>
                    <td class="px-4 py-3 text-center">${adminCell}</td>
                    <td class="px-4 py-3 text-center">${check('view')}</td>
                    <td class="px-4 py-3 text-center">${check('edit')}</td>
                    <td class="px-4 py-3 text-center">${check('pxmx')}</td>
                    <td class="px-4 py-3 text-center">${check('firewall')}</td>
                    <td class="px-4 py-3 text-center">${check('dns')}</td>
                    <td class="px-4 py-3 text-center">${check('nac')}</td>
                    <td class="px-4 py-3 text-center">${check('nw')}</td>
                    <td class="px-4 py-3 text-center">${check('ipam')}</td>
                    <td class="px-4 py-3 text-center">${check('cs')}</td>
                    <td class="px-4 py-3 text-center">${check('console')}</td>
                    <td class="px-4 py-3 text-center">${check('console_write')}</td>
                    <td class="px-4 py-3 text-right whitespace-nowrap">${actions}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading users:', err);
        bodyEl.innerHTML = `<tr class="text-center py-8 text-red-500 text-xs">Error loading users: ${err.message}</tr>`;
    }
}

async function deleteUser(userId) {
    const base = _taUsersBase();
    const verb = base ? `remove user ${userId} from tenant ${currentTenant}` : `delete user ${userId}`;
    if (!await showConfirmToast(`Are you sure you want to ${verb}?`)) return;
    try {
        const url = base ? `${base}/${encodeURIComponent(userId)}` : `/setup/users/${encodeURIComponent(userId)}`;
        const response = await setupFetch(url, { method: 'DELETE' });
        if (response.ok) {
            showToast(base ? 'User removed from tenant' : 'User deleted', 'success');
            await loadUsers();
        } else {
            const d = await response.json().catch(() => ({}));
            showToast(d.detail || 'Failed to delete user', 'error');
        }
    } catch (err) {
        showToast('Error deleting user: ' + err.message, 'error');
    }
}

// ── Permission Groups (RBAC) ───────────────────────────────────────────────
// Right-key → display label for the group editor + user-assignment checklists.
// Kept in sync with access.ENFORCED_RIGHTS on the backend.
const _RBAC_RIGHT_LABELS = {
    admin: 'Global Admin',
    tenant_admin: 'Admin (tenant)',
    edit: 'Edit (write user)',
    firewall: 'Firewall',
    nw: 'Network Devices',
    ipam: 'IPAM',
    nac: 'NAC',
    dns: 'DNS',
    dhcp: 'DHCP',
    ldap: 'Directory / LDAP',
    pxmx: 'Hypervisors',
    le: 'Certificates',
    console: 'Console',
    console_write: 'Console Write',
    cs: 'Simulations',
    reports: 'Reports',
};

async function loadGroups() {
    const bodyEl = document.getElementById('permission-groups-body');
    try {
        const data = await apiJson('/setup/groups');
        const groups = data.groups || {};
        // Cache for the users table Groups column + the modal checklists.
        window._permGroups = groups;
        window._permGroupNames = Object.fromEntries(
            Object.entries(groups).map(([gid, g]) => [gid, g.name || gid]));
        // Tenant names for the group-table scope badges + the modal checklist.
        await ensureTenants(true);
        if (!bodyEl) return;
        if (Object.keys(groups).length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-slate-400 italic">No groups yet — create one to bundle module access.</td></tr>`;
            return;
        }
        bodyEl.innerHTML = Object.entries(groups).map(([gid, g]) => {
            const perms = g.permissions || {};
            const isAdmin = perms.admin === true || perms.role === 'admin';
            const isTenantAdmin = perms.role === 'tenant_admin';
            const permBadges = isAdmin
                ? `<span class="text-[10px] bg-amber-100 text-amber-800 border border-amber-200 px-1.5 py-0.5 rounded font-bold">Global Admin</span>`
                : isTenantAdmin
                    ? `<span class="text-[10px] bg-amber-50 text-amber-700 border border-amber-200 px-1.5 py-0.5 rounded font-bold">Admin (tenant)</span>`
                    : (Object.keys(perms).filter(k => k !== 'role' && k !== 'tenant_admin' && perms[k]).map(k =>
                        `<span class="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-medium">${_RBAC_RIGHT_LABELS[k] || k}</span>`
                      ).join(' ') || '<span class="text-[10px] text-slate-300 italic">none</span>');
            const ldap = g.ldap_group
                ? `<span class="font-mono text-xs text-blue-600">${g.ldap_group}</span>`
                : '<span class="text-[10px] text-slate-300 italic">—</span>';
            // Granted tenant scope: a group may carry a ``tenants`` list so a
            // single Entra/LDAP group grants BOTH RBAC permissions AND tenant
            // scope. Show the tenant names (ids fall back when names unresolved).
            const tNames = (window._allTenantsName || {});
            const scopeBadges = (g.tenants && g.tenants.length)
                ? `<div class="mt-1 flex flex-wrap gap-1">${g.tenants.map(tid =>
                    `<span class="text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-100 px-1.5 py-0.5 rounded font-medium">${tNames[tid] || tid}</span>`).join('')}</div>`
                : '';
            return `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3"><div class="font-medium text-slate-700 text-sm">${g.name || gid}</div><div class="text-[11px] text-slate-400">${g.description || ''}</div>${scopeBadges}</td>
                    <td class="px-4 py-3"><div class="flex flex-wrap gap-1">${permBadges}</div></td>
                    <td class="px-4 py-3">${ldap}</td>
                    <td class="px-4 py-3 text-center text-slate-600">${g.member_count || 0}</td>
                    <td class="px-4 py-3 text-right whitespace-nowrap">
                        <button onclick="showGroupModal('${gid}')" class="text-blue-400 hover:text-blue-600 text-xs font-bold mr-3">Edit</button>
                        <button onclick="deleteGroup('${gid}')" class="text-red-400 hover:text-red-600 text-xs font-bold">Delete</button>
                    </td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Error loading groups:', err);
        if (bodyEl) bodyEl.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-red-500 text-xs">Error loading groups: ${err.message}</td></tr>`;
    }
}

// Fetch + cache the tenant list (id + name) for the group-modal tenant
// checklist and the group-table scope badges. /setup/tenants is admin-only;
// the group editor is itself admin-only, so this is safe to call here.
function _cacheAllTenants(tenants) {
    window._allTenants = tenants;
    window._allTenantsName = Object.fromEntries(
        tenants.map(t => [t.id, t.name || t.id]));
}

async function ensureTenants(force = false) {
    // Cache HIT only on a populated list. An empty array is truthy, so caching
    // [] (a transient fetch failure, or a fresh install with no tenants yet)
    // would short-circuit every later call to return [] — the "No tenants
    // defined yet" bug in the Add-User modal even after tenants appear. Re-fetch
    // whenever the cache is empty/missing so the list self-heals. Pass
    // force=true where a stale list blocks an action (tenant-scope pickers) so
    // a tenant added after page load is selectable.
    if (!force && window._allTenants && window._allTenants.length) return window._allTenants;
    try {
        const res = await setupFetch('/setup/tenants');
        if (!res.ok) return window._allTenants || [];
        const data = await res.json();
        const tenants = data.tenants || [];
        _cacheAllTenants(tenants);
        return tenants;
    } catch (_e) {
        // Don't poison the cache on a transient failure — leave whatever's
        // cached (possibly empty) so the next call retries.
        return window._allTenants || [];
    }
}

async function showGroupModal(groupId) {
    const groups = window._permGroups || {};
    const g = groupId ? (groups[groupId] || {}) : {};
    const perms = g.permissions || {};
    const isAdmin = perms.admin === true || perms.role === 'admin';
    const isTenantAdminGroup = perms.role === 'tenant_admin';
    const rightRows = Object.entries(_RBAC_RIGHT_LABELS).map(([key, label]) => {
        // admin/tenant_admin are stored as role, not a flag — check from the role.
        const checked = key === 'admin' ? isAdmin
            : key === 'tenant_admin' ? isTenantAdminGroup
            : !!perms[key];
        // Compact inline cell (checkbox + label on one line) so the grid packs
        // into 4 columns without the stacked label-above-checkbox making the
        // modal tall — matches the Tenant Scope row style below.
        return `<label class="flex items-center gap-2 text-xs text-slate-600 py-1"><input type="checkbox" id="grp-perm-${key}" ${checked ? 'checked' : ''} class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">${label}</label>`;
    }).join('');
    // Tenant scope checklist — a group may carry a ``tenants`` list so a single
    // Entra/LDAP group grants BOTH RBAC permissions AND tenant scope. The backend
    // validates each id is a real tenant (drops unknowns), so we list only known
    // tenants here; an id no longer in tenant_state is silently dropped on save.
    await ensureTenants(true);
    const tenants = window._allTenants || [];
    const granted = new Set(g.tenants || []);
    const tenantRows = tenants.length
        ? tenants.map(t => `<label class="flex items-center gap-2 text-sm text-slate-600 py-1"><input type="checkbox" id="grp-tenant-${t.id}" ${granted.has(t.id) ? 'checked' : ''} class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500"> ${t.name || t.id}</label>`).join('')
        : '<span class="text-[11px] text-slate-400 italic">No tenants defined yet.</span>';
    const modal = document.createElement('div');
    modal.id = 'group-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">
            <div class="shrink-0 px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">${groupId ? 'Edit' : 'New'} Permission Group</h3>
                <button onclick="closeGroupModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4 overflow-y-auto flex-1 min-h-0">
                <input type="hidden" id="grp-id" value="${groupId || ''}">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="space-y-1"><label class="text-xs text-slate-500 uppercase font-bold">Group Name</label><input type="text" id="grp-name" value="${g.name || ''}" placeholder="e.g. NOC Operators" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500"></div>
                    <div class="space-y-1"><label class="text-xs text-slate-500 uppercase font-bold">Description</label><input type="text" id="grp-desc" value="${g.description || ''}" placeholder="Optional" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500"></div>
                </div>
                <div class="space-y-1"><label class="text-xs text-slate-500 uppercase font-bold">Directory Group <span class="text-slate-400 normal-case font-normal">(optional — Entra group object ID or LDAP DN; maps a directory group to this bundle + its tenant scope)</span></label>
                    <div class="flex gap-2">
                        <input type="text" id="grp-ldap" value="${g.ldap_group || ''}" placeholder="Entra object ID or cn=noc,ou=groups,dc=example,dc=com" class="flex-1 bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500 font-mono">
                        <button type="button" onclick="loadEntraGroupPicker()" id="grp-entra-btn" class="whitespace-nowrap bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold">Pick from Entra</button>
                    </div>
                    <select id="grp-entra-select" onchange="onEntraGroupPick(this)" class="hidden w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></select>
                    <p id="grp-entra-msg" class="text-[11px] text-amber-600 hidden"></p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 border-t border-slate-200 pt-3">
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Tenant Scope <span class="text-slate-400 normal-case font-normal">(optional — grants tenant access to members)</span></label><div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 mt-2 max-h-56 overflow-y-auto pr-1">${tenantRows}</div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Permissions</label><div class="grid grid-cols-2 gap-x-4 gap-y-1 mt-2">${rightRows}</div></div>
                </div>
            </div>
            <div class="shrink-0 px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeGroupModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveGroup()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">${groupId ? 'Save' : 'Create'} Group</button>
            </div>
        </div>`;
    _mountModal(modal);
}

function closeGroupModal() {
    const modal = document.getElementById('group-modal');
    if (modal) modal.remove();
}

// Query Entra for its groups (via the hub's app-level Graph read) so the admin
// can pick a group by NAME to map to this permission group + its tenant scope,
// instead of pasting the object ID. Lazy — only hits Graph when clicked.
async function loadEntraGroupPicker() {
    const btn = document.getElementById('grp-entra-btn');
    const sel = document.getElementById('grp-entra-select');
    const msg = document.getElementById('grp-entra-msg');
    if (!sel) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Loading…'; }
    try {
        const res = await setupFetch('/setup/oidc/groups');
        const d = await res.json().catch(() => ({}));
        const groups = (d && d.groups) || [];
        if (!groups.length) {
            if (msg) {
                msg.textContent = (d && d.warning)
                    || 'No Entra groups returned. The app registration needs Graph Group.Read.All (application) with admin consent, and a generated certificate.';
                msg.classList.remove('hidden');
            }
            sel.classList.add('hidden');
        } else {
            sel.innerHTML = '<option value="">— select an Entra group —</option>' +
                groups.map(gr => `<option value="${escapeHtml(gr.id)}">${escapeHtml(gr.displayName)} — ${escapeHtml(gr.id)}</option>`).join('');
            sel.classList.remove('hidden');
            if (msg) msg.classList.add('hidden');
        }
    } catch (e) {
        if (msg) { msg.textContent = 'Failed to load Entra groups: ' + (e.message || e); msg.classList.remove('hidden'); }
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Pick from Entra'; }
    }
}

// Selecting an Entra group fills the object ID into the directory-group field
// (what login matches on) and seeds the group name if it's still blank.
function onEntraGroupPick(sel) {
    const id = sel.value;
    if (!id) return;
    const ldap = document.getElementById('grp-ldap');
    if (ldap) ldap.value = id;
    const nameInput = document.getElementById('grp-name');
    const label = (sel.options[sel.selectedIndex] && sel.options[sel.selectedIndex].textContent) || '';
    const disp = label.split(' — ')[0].trim();
    if (nameInput && !nameInput.value.trim() && disp) nameInput.value = disp;
}

async function saveGroup() {
    const name = document.getElementById('grp-name').value.trim();
    if (!name) { showToast('Please enter a group name', 'error'); return; }
    const permissions = {};
    Object.keys(_RBAC_RIGHT_LABELS).forEach(key => {
        if (document.getElementById('grp-perm-' + key)?.checked) permissions[key] = true;
    });
    // Collect granted tenant scope. Sending an explicit list (even empty)
    // replaces the stored set — matches the backend's "list = replace, empty =
    // clear" contract. Unknown ids are dropped server-side.
    const tenants = (window._allTenants || []).map(t => t.id).filter(tid =>
        document.getElementById('grp-tenant-' + tid)?.checked);
    const body = {
        group_id: document.getElementById('grp-id').value || '',
        name,
        description: document.getElementById('grp-desc').value.trim(),
        ldap_group: document.getElementById('grp-ldap').value.trim(),
        permissions,
        tenants,
    };
    try {
        const resp = await setupFetch('/setup/groups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (resp.ok) {
            closeGroupModal();
            await loadGroups();
            await loadUsers();  // effective perms may have shifted
        } else {
            const d = await resp.json().catch(() => ({}));
            showToast(d.detail || 'Failed to save group', 'error');
        }
    } catch (err) {
        showToast('Error saving group: ' + err.message, 'error');
    }
}

async function deleteGroup(groupId) {
    const g = (window._permGroups || {})[groupId] || {};
    const n = g.member_count || 0;
    const warn = n > 0 ? `\n\n${n} user(s) are in this group and will be detached.` : '';
    if (!await showConfirmToast(`Delete permission group "${g.name || groupId}"?${warn}`)) return;
    try {
        const resp = await setupFetch(`/setup/groups/${groupId}`, { method: 'DELETE' });
        if (resp.ok) {
            await loadGroups();
            await loadUsers();
        } else {
            const d = await resp.json().catch(() => ({}));
            showToast(d.detail || 'Failed to delete group', 'error');
        }
    } catch (err) {
        showToast('Error deleting group: ' + err.message, 'error');
    }
}

// Fill a checklist container (add-user modal) with a checkbox per group.
async function _populateUserGroupChecklist(containerId, selectedIds) {
    const el = document.getElementById(containerId);
    if (!el) return;
    let groups = window._permGroups;
    if (!groups) {
        try {
            const resp = await setupFetch('/setup/groups');
            groups = resp.ok ? (await resp.json()).groups || {} : {};
            window._permGroups = groups;
        } catch { groups = {}; }
    }
    const sel = new Set(selectedIds || []);
    const entries = Object.entries(groups);
    if (entries.length === 0) {
        el.innerHTML = '<span class="text-[11px] text-slate-400 italic">No groups defined — create one below.</span>';
        return;
    }
    el.classList.remove('italic', 'text-slate-400');
    el.innerHTML = entries.map(([gid, g]) => `
        <label class="flex items-center gap-2 px-2 py-1 border border-slate-200 rounded-md cursor-pointer hover:bg-slate-50">
            <input type="checkbox" data-grp="${gid}" ${sel.has(gid) ? 'checked' : ''} class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">
            <span class="text-xs text-slate-700">${g.name || gid}</span>
        </label>`).join('');
}

function _collectCheckedGroups(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return [];
    return Array.from(el.querySelectorAll('input[data-grp]'))
        .filter(cb => cb.checked).map(cb => cb.getAttribute('data-grp'));
}

// ── API Tokens (Settings → API Tokens) ──────────────────────────────────────
// Self-service Bearer/refresh token management for the logged-in user. Backend:
// POST /auth/token (issue), GET /auth/tokens (list), POST /auth/token/revoke.
async function loadApiTokens() {
    const body = document.getElementById('apitok-table-body');
    if (!body) return;
    try {
        const data = await apiJson('/auth/tokens', { credentials: 'same-origin' });
        const toks = data.tokens || [];
        if (!toks.length) {
            body.innerHTML = '<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic">No API tokens.</td></tr>';
            return;
        }
        const fmt = (s) => s ? new Date(s * 1000).toLocaleString() : '—';
        body.innerHTML = toks.map(t => `
            <tr>
                <td class="px-4 py-3 font-medium text-slate-700">${escapeHtml(t.name || '(unnamed)')}</td>
                <td class="px-4 py-3 text-slate-500">${fmt(t.created)}</td>
                <td class="px-4 py-3 text-slate-500">${fmt(t.expires)}</td>
                <td class="px-4 py-3 text-right"><button onclick="revokeApiToken('${escJsAttr(String(t.id))}')" class="text-xs text-red-600 hover:text-red-700 font-medium" title="Immediately invalidate this API token">Revoke</button></td>
            </tr>`).join('');
    } catch (e) {
        body.innerHTML = '<tr><td colspan="4" class="px-4 py-6 text-center text-red-400 italic">Failed to load.</td></tr>';
    }
}

async function createApiToken() {
    const btn = document.getElementById('apitok-create-btn');
    const name = (document.getElementById('apitok-name') || {}).value || '';
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
    try {
        const data = await apiJson('/auth/token', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
        });
        const box = document.getElementById('apitok-new');
        if (box) {
            box.className = 'rounded-md border border-green-300 bg-green-50 p-4 space-y-2 text-xs';
            box.innerHTML = `
                <p class="font-bold text-green-800">Token created — copy these now; they won't be shown again.</p>
                <div><span class="text-slate-500">Access token (Bearer, 4h):</span><code class="block break-all bg-white border border-slate-200 rounded px-2 py-1 mt-1">${escapeHtml(data.access_token)}</code></div>
                <div><span class="text-slate-500">Refresh token (rotate via POST /auth/token/refresh):</span><code class="block break-all bg-white border border-slate-200 rounded px-2 py-1 mt-1">${escapeHtml(data.refresh_token)}</code></div>`;
        }
        const nm = document.getElementById('apitok-name'); if (nm) nm.value = '';
        loadApiTokens();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Create failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Create token'; }
    }
}

async function revokeApiToken(id) {
    if (!await (typeof showConfirmToast === 'function'
            ? showConfirmToast('Revoke this API token? Any client using it stops working immediately.')
            : Promise.resolve(confirm('Revoke this API token?')))) return;
    try {
        const res = await fetch('/auth/token/revoke', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id }),
        });
        if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || res.status); }
        if (typeof showToast === 'function') showToast('Token revoked.', 'success');
        loadApiTokens();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Revoke failed: ' + e.message, 'error');
    }
}

// mTLS readiness + enable (System → Hub Status). Green when ready; per-spoke
// dots show which spokes already have the wildcard + CA bundle. Auto-provision
// toggles hub-brokered distribution + auto-enable once the fleet is ready.
async function loadMtlsReadiness() {
    const ind = document.getElementById('mtls-readiness');
    const chk = document.getElementById('mtls-enabled');
    const autoChk = document.getElementById('mtls-auto-provision');
    const spokesEl = document.getElementById('mtls-spokes');
    const hint = document.getElementById('mtls-auto-provision-hint');
    if (!ind) return;
    try {
        const r = await setupFetch('/setup/mtls-readiness');
        if (!r.ok) { ind.textContent = 'Readiness unavailable.'; return; }
        const d = await r.json();
        if (chk) chk.checked = !!d.enabled;
        if (autoChk) autoChk.checked = !!d.auto_provision;
        const green = !!d.ready;
        const dot = `<span class="inline-block w-2.5 h-2.5 rounded-full ${green ? 'bg-green-500' : 'bg-amber-500'}"></span>`;
        const label = green
            ? `<span class="text-green-600 font-semibold">System ready for mTLS</span> · ${d.connected_spokes} spoke(s) connected`
            : `<span class="text-amber-600 font-semibold">Not ready</span> — ${(d.blockers || []).join('; ') || 'distribute the LE wildcard first'}`;
        ind.innerHTML = `${dot} ${label}`;
        // Per-spoke breakdown: a dot + label per connected primary spoke.
        if (spokesEl) {
            const spokes = d.spokes || [];
            if (spokes.length) {
                spokesEl.classList.remove('hidden');
                spokesEl.innerHTML = `<div class="text-xs text-slate-400 mb-1.5 uppercase tracking-wider font-semibold">Per-spoke readiness</div>` +
                    spokes.map(s => {
                        const c = s.ready ? 'bg-green-500' : (s.online ? 'bg-amber-500' : 'bg-slate-300');
                        const t = s.ready ? 'ready' : (s.online ? 'missing materials' : 'offline — will receive on reconnect');
                        // Spoke/agent names render UPPERCASE to match the
                        // section header's `uppercase tracking-wider` treatment.
                        // Styled, not transformed: the underlying value stays
                        // intact for the title tooltip, copy/paste and search.
                        return `<div class="flex items-center gap-2 text-xs text-slate-600 py-0.5"><span class="inline-block w-2 h-2 rounded-full ${c}"></span><span class="font-medium uppercase" title="${escapeHtml(s.id)}">${escapeHtml(s.name || s.id)}</span><span class="text-slate-400">· ${escapeHtml(s.type || '')} · ${t}</span></div>`;
                    }).join('');
            } else {
                spokesEl.classList.add('hidden');
            }
        }
        if (hint) {
            hint.textContent = d.auto_provision
                ? (d.ready ? 'fleet ready' : 'distributing…')
                : '';
        }
    } catch (e) { ind.textContent = 'Readiness check failed.'; }
}

async function saveMtlsEnable(btn) {
    const chk = document.getElementById('mtls-enabled');
    if (!chk) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/mtls-enable', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: chk.checked }),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) { showToast(d.message || 'Saved.', 'success'); loadMtlsReadiness(); }
        else if (r.status === 409) showToast(d.detail || 'Not ready for mTLS.', 'error');
        else showToast('Failed: ' + (d.detail || r.status), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save'; } }
}

async function saveMtlsAutoProvision(btn) {
    const chk = document.getElementById('mtls-auto-provision');
    if (!chk) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/mtls-auto-provision', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: chk.checked }),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) { showToast(d.message || 'Saved.', 'success'); loadMtlsReadiness(); }
        else showToast('Failed: ' + (d.detail || r.status), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save'; } }
}

// Idle session timeout (Settings → Active Sessions area). 0 = disabled; default 60.
async function loadSessionTimeout() {
    const sel = document.getElementById('session-timeout-minutes');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/session-timeout');
        if (!r.ok) return;
        const d = await r.json();
        const mins = String(d.minutes);
        // If the stored value isn't one of the preset options, inject it so it shows.
        if (!Array.from(sel.options).some(o => o.value === mins)) {
            const opt = document.createElement('option');
            opt.value = mins; opt.textContent = `${mins} minutes`;
            sel.appendChild(opt);
        }
        sel.value = mins;
    } catch (e) { /* leave default */ }
}

async function saveSessionTimeout(btn) {
    const sel = document.getElementById('session-timeout-minutes');
    if (!sel) return;
    const minutes = parseInt(sel.value, 10) || 0;
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/session-timeout', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ minutes }),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) showToast(d.message || 'Idle timeout saved.', 'success');
        else showToast('Failed to save: ' + (d.detail || r.status), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save'; } }
}

async function loadActiveSessions() {
    const tbody = document.getElementById('sessions-table-body');
    if (!tbody) return;
    try {
        const r = await setupFetch('/admin/sessions');
        if (!r.ok) throw new Error(r.statusText);
        const { sessions } = await r.json();
        if (!sessions.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-slate-400 italic">No active sessions.</td></tr>`;
            return;
        }
        const fmtExpiry = (secs) => {
            if (secs > 3600) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
            if (secs > 60)   return `${Math.floor(secs / 60)}m`;
            return `${secs}s`;
        };
        tbody.innerHTML = sessions.map(s => `
            <tr class="hover:bg-slate-50">
                <td class="px-4 py-3 font-medium text-slate-700" title="${escapeHtml(s.user_id || '')}">${escapeHtml(s.name || s.user_id || '')}</td>
                <td class="px-4 py-3">
                    ${s.is_admin
                        ? `<span class="px-2 py-0.5 rounded-full bg-green-100 text-green-700 text-[10px] font-bold uppercase">Admin</span>`
                        : `<span class="px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-bold uppercase">User</span>`}
                </td>
                <td class="px-4 py-3 text-slate-500 text-xs">${s.tenants.length ? s.tenants.join(', ') : '—'}</td>
                <td class="px-4 py-3 text-slate-500 text-xs">${fmtExpiry(s.expires_in)}</td>
                <td class="px-4 py-3 text-right">
                    <button onclick="revokeSession('${s.sid}')" title="Force sign-out of this session"
                        class="text-xs text-red-400 hover:text-red-600 font-medium">Revoke</button>
                </td>
            </tr>`).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-red-400 italic">Failed to load sessions: ${e.message}</td></tr>`;
    }
}

async function revokeSession(sid) {
    if (!await showConfirmToast(`Revoke session ${sid}?`)) return;
    try {
        const r = await setupFetch(`/admin/sessions/${encodeURIComponent(sid)}`, { method: 'DELETE' });
        const d = await r.json();
        if (r.ok) {
            showToast(d.message || 'Session revoked', 'success');
            loadActiveSessions();
        } else {
            showToast(d.detail || 'Revoke failed', 'error');
        }
    } catch (e) {
        showToast('Revoke error: ' + e.message, 'error');
    }
}

// Human-readable label + tone for each hub-side connection lifecycle event.
// Mirrors the events recorded by Hub.record_spoke_event (core/src/main.py).
const SPOKE_EVENT_LABELS = {
    auth_attempt:        { label: 'Auth attempt',          tone: 'text-slate-600' },
    auth_ok:              { label: 'Authenticated',         tone: 'text-green-600' },
    auth_failed:          { label: 'Auth failed',           tone: 'text-red-600' },
    pending_negotiation:  { label: 'Zero-touch (no secret)', tone: 'text-amber-600' },
    connected:            { label: 'Connected',             tone: 'text-green-600' },
    mutual_auth_complete: { label: 'Mutual auth OK',        tone: 'text-green-600' },
    mutual_auth_skipped:  { label: 'Mutual auth skipped',    tone: 'text-slate-500' },
    mutual_auth_failed:   { label: 'Mutual auth failed',    tone: 'text-red-600' },
    mutual_auth_timeout:  { label: 'Mutual auth timeout',   tone: 'text-red-600' },
    registered:           { label: 'Registered',           tone: 'text-slate-600' },
    pending_approval:     { label: 'Pending approval',      tone: 'text-amber-600' },
    connection_closed:    { label: 'Connection closed',     tone: 'text-amber-600' },
    connection_error:     { label: 'Connection error',       tone: 'text-red-600' },
    replaced_connection:  { label: 'Reconnected (old socket closed)', tone: 'text-amber-600' },
    stale_key_rejected:   { label: 'Stale key rejected',     tone: 'text-red-600' },
    spoke_out_of_contact: { label: 'Out of contact (alert)', tone: 'text-amber-600' },
    spoke_back_in_contact:{ label: 'Back in contact',        tone: 'text-green-600' },
    // Spoke refused the Hub's identity proof (all known hub_secrets stale +
    // TLS verify off) — see the ConnectionClosed handler in main.py's
    // mutual-auth block. Previously invisible: the hub recorded nothing here
    // and the spoke retries forever, so this event is the only trace.
    hub_identity_rejected:{ label: 'Hub identity rejected',  tone: 'text-red-600' },
    // Spoke verified the Hub via an OLDER entry in the rotation-window
    // signatures list (not the current root secret) — the hub proactively
    // re-pushed SPOKE_SET_HUB_SECRET so it doesn't keep drifting behind.
    // See LabManagerHub._maybe_reprovision_hub_secret.
    hub_secret_reprovisioned:{ label: 'Hub secret re-provisioned', tone: 'text-amber-600' },
};

// Map a spoke's last_status + authenticated + flapping flags to a single
// diagnostic message that distinguishes the failure modes that previously
// all collapsed to "Never connected — service may not be running".
function spokeStatusMessage(s) {
    if (s.authenticated) {
        return s.approved ? { text: 'Online', tone: 'text-green-600' }
                          : { text: 'Online — pending approval', tone: 'text-amber-600' };
    }
    if (s.flapping) {
        return { text: `Flapping — ${s.recent_drops} drops in 5 min (process alive but not holding connection)`, tone: 'text-red-600' };
    }
    switch (s.last_status) {
        case 'AUTH_FAILED':    return { text: 'Auth failed — secret rejected (retrying / falling back to zero-touch)', tone: 'text-amber-600' };
        case 'PENDING_SECRET':  return { text: 'Zero-touch connected — awaiting admin approval', tone: 'text-amber-600' };
        case 'DISCONNECTED':    return s.parent_online
            // A role sub-spoke has no systemd unit of its own — it is a
            // connection inside the parent agent's process. If the parent is
            // connected, systemd is demonstrably fine and the role is simply
            // reloading (self-update restart, role re-seed), so blaming
            // systemd here sent operators chasing a unit that doesn't exist.
            ? { text: 'Role reloading — parent agent is online (role restarts with the agent process, no unit of its own)', tone: 'text-amber-600' }
            : { text: 'Disconnected (clean exit) — likely self-update restart that systemd did not revive', tone: 'text-red-600' };
        case 'ERROR':           return { text: `Connection error: ${s.last_error || 'see hub logs'}`, tone: 'text-red-600' };
        case 'CONNECTED':       return { text: 'Briefly connected then dropped (see event log)', tone: 'text-amber-600' };
        // Spoke refused this Hub's identity proof (its stored hub_secrets —
        // including the rotation window — didn't match, and TLS verify is
        // off so there's no independent authenticator). Without this case
        // it fell into the generic default below and showed as "Never
        // connected", hiding the actual cause from the operator.
        case 'HUB_IDENTITY_REJECTED': return { text: `Hub identity rejected by spoke: ${s.last_error || 'see event log'}`, tone: 'text-red-600' };
        default:
            // After a hub reboot, spoke_telemetry is empty so last_status is
            // UNKNOWN and we land here — but a persisted last_seen (re-seeded
            // into heartbeat.last_seen at startup) still gives a real
            // heartbeat_age_s. Distinguish "was connected recently, hub just
            // rebooted" (amber) from "truly stale / never seen" (red). 15-min
            // (900s) threshold per operator request: red only if last contact
            // was more than 15 minutes ago.
            if (s.heartbeat_age_s != null) {
                const mins = Math.floor(s.heartbeat_age_s / 60);
                const secs = s.heartbeat_age_s % 60;
                const ago = mins > 0 ? `${mins}m ${secs}s ago` : `${secs}s ago`;
                if (s.heartbeat_age_s >= 900) {
                    return { text: `Last seen ${ago} — service may not be running`, tone: 'text-red-600' };
                }
                return { text: `Last seen ${ago} — reconnecting after hub reboot`, tone: 'text-amber-600' };
            }
            return { text: 'Never connected — service may not be running', tone: 'text-red-600' };
    }
}

function spokeEventRow(e) {
    const meta = SPOKE_EVENT_LABELS[e.event] || { label: e.event, tone: 'text-slate-600' };
    const when = new Date(e.ts * 1000).toLocaleTimeString();
    const detail = e.detail ? ` — ${e.detail}` : '';
    return `<div class="py-0.5"><span class="text-slate-400">${when}</span> <span class="${meta.tone} font-medium">${meta.label}</span><span class="text-slate-500">${detail}</span></div>`;
}

// Render one relayed WARNING/ERROR/CRITICAL log line in the per-spoke events
// panel (operational errors/warnings, distinct from the lifecycle events).
function spokeLogEventRow(le) {
    const lvl = String(le.level || '').toUpperCase();
    const tone = (lvl === 'ERROR' || lvl === 'CRITICAL') ? 'text-red-600'
               : lvl === 'WARNING' ? 'text-amber-600' : 'text-slate-600';
    const t = String(le.ts_str || '');
    const when = (t.split(' ')[1] || t).split(',')[0];
    return `<div class="py-0.5"><span class="text-slate-400">${escapeHtml(when)}</span> <span class="${tone} font-bold">${escapeHtml(lvl)}</span> <span class="text-slate-400">${escapeHtml(le.name || '')}</span> <span class="text-slate-600 break-all">${escapeHtml(le.msg || '')}</span></div>`;
}

// Build the inner HTML of a spoke's events panel from its events + log_events
// arrays. Same markup the LIST payload used to pre-render inline; now shared by
// the lazy loader and the compat inline path. Errors/warnings first (relayed
// WARNING/ERROR/CRITICAL log lines), then lifecycle events.
function _renderSpokeEventsInner(events, log_events) {
    events = events || [];
    log_events = log_events || [];
    return `${log_events.length ? `<div class="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-0.5">Errors &amp; warnings</div>${log_events.map(spokeLogEventRow).join('')}<div class="border-t border-slate-200 my-1.5"></div>` : ''}${events.length ? `<div class="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-0.5">Lifecycle</div>${events.map(spokeEventRow).join('')}` : (log_events.length ? '' : '<span class="text-slate-400 italic">No events recorded.</span>')}`;
}

// Lazily fetch + render a spoke's events into its panel the first time it's
// needed (panel expand or Copy). GET /setup/diagnostics/{spoke_id} returns the
// events/log_events arrays that the polled LIST no longer carries. Idempotent:
// data-loaded="1" short-circuits repeat calls. Best-effort — a failed fetch
// leaves an error note in the panel rather than throwing.
async function ensureSpokeEventsLoaded(spokeId) {
    const panel = document.getElementById(`events-${spokeId}`);
    if (!panel || panel.dataset.loaded === '1') return;
    try {
        const d = await apiJson('/setup/diagnostics/' + encodeURIComponent(spokeId));
        panel.innerHTML = _renderSpokeEventsInner(d.events || [], d.log_events || []);
        panel.dataset.loaded = '1';
    } catch (err) {
        panel.innerHTML = '<span class="text-red-500 italic">Failed to load events.</span>';
        console.error('ensureSpokeEventsLoaded failed', err);
    }
}

async function toggleSpokeEvents(spokeId) {
    const panel = document.getElementById(`events-${spokeId}`);
    if (!panel) return;
    const willShow = panel.classList.contains('hidden');
    if (willShow) await ensureSpokeEventsLoaded(spokeId);
    panel.classList.toggle('hidden');
}

// Copy a spoke/agent's connection-events panel to the clipboard — same
// clipboard-write + fallback + toast pattern as copyLogs() (Setup → Logs).
async function copySpokeEvents(spokeId) {
    const panel = document.getElementById(`events-${spokeId}`);
    if (!panel) return;
    // Ensure the events are fetched even if the operator clicks Copy without
    // first expanding the panel (the LIST no longer ships the arrays inline).
    await ensureSpokeEventsLoaded(spokeId);
    const text = panel.innerText;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {
                throw new Error('execCommand copy failed');
            }
            document.body.removeChild(textArea);
        }
        if (typeof showToast === 'function') showToast('Events copied to clipboard.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast('Copy failed: ' + e.message, 'error');
    }
}

// Minimal HTML escaper for safely interpolating server-provided strings
// (spoke IDs, error text, module types) into template literals.
function escapeHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Safe interpolation of a value into an onclick="fn('...')" JS-STRING that sits
// inside an HTML attribute. escapeHtml ALONE is wrong here: the browser decodes
// &#39; back to ' BEFORE the JS parser runs, so a value with an apostrophe breaks
// the handler (or injects). JS-escape backslash + single-quote first, THEN
// HTML-escape for the attribute context.
function escJsAttr(s) {
    return escapeHtml(String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"));
}

/**
 * Shared modal shell — dimmed full-screen overlay + centered white card.
 * Removes any existing element with the same id first (idempotent re-open),
 * then appends to <body>. Callers wire their own buttons/handlers on the
 * returned overlay element (querySelector into it).
 *
 * @param {string} id       DOM id for the overlay (also used to close it).
 * @param {string} bodyHtml Card contents (everything inside the white card).
 * @param {object} [opts]
 *   card:          card classes after 'bg-white rounded-xl shadow-xl '
 *                  (default 'w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto').
 *   overlay:       extra classes appended to the overlay (e.g. 'overflow-y-auto py-6').
 *   backdropClose: true → clicking the dimmed backdrop closes the modal.
 * @returns {HTMLElement} The overlay element.
 */
// Withdraw the per-tab "+ Add …" action. Those buttons render into the
// trailing #top-nav-actions strip (see renderTopNav), so there is no local
// element handle to hide -- the error paths below used to reach for an
// `addBtn` variable that no longer exists anywhere, which threw a
// ReferenceError and aborted the whole loader, replacing the spoke-error
// banner it was about to draw with a bare JS error.
function _clearTopNavActions() {
    const el = document.getElementById('top-nav-actions');
    if (el) el.innerHTML = '';
}

function openModal(id, bodyHtml, opts = {}) {
    document.getElementById(id)?.remove();
    const modal = document.createElement('div');
    modal.id = id;
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50' + (opts.overlay ? ' ' + opts.overlay : '');
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl ${opts.card || 'w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto'}">${bodyHtml}</div>`;
    if (opts.backdropClose) modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
    return modal;
}

// Mount a hand-built modal, replacing any previous copy with the same id.
//
// openModal() above has always dropped a same-id node before appending, but the
// openers that build their own element skipped that -- and the ones that AWAIT
// their data before appending are re-entrant, because nothing stops a second
// click while the first fetch is still outstanding. Clicking "Credentials" on
// the Console page twice therefore stacked two live copies of the dialog, and
// because they shared one id every close button (getElementById(..).remove())
// only ever removed the first, so the stack had to be dismissed one layer at a
// time.
function _mountModal(modal) {
    if (modal.id) document.getElementById(modal.id)?.remove();
    document.body.appendChild(modal);
    return modal;
}

// Collapse repeat invocations of an async opener while its first call is still
// in flight.
//
// _mountModal alone keeps the screen to one dialog, but the duplicate work
// still happens: the later response replaces a dialog the user may already be
// typing into, discarding the input. Keyed on the ARGUMENTS so suppression is
// limited to re-clicking the same button -- picking a different row (editUser(7)
// after editUser(3)) is a different key and still opens. A pending call from
// before the last navigation is ignored: lmFetch drops its response, so it
// never settles and would otherwise block the opener for good.
function _singleFlight(fn) {
    const pending = new Map();   // key -> { out, nav }
    return function (...args) {
        let key;
        try { key = JSON.stringify(args); } catch (e) { key = String(args); }
        const prev = pending.get(key);
        if (prev && prev.nav === _lmNavSeq) return prev.out;
        const out = fn.apply(this, args);
        // Only a thenable has a window during which a second click can land; a
        // synchronous opener is finished before the next event can be handled.
        if (out && typeof out.then === 'function') {
            pending.set(key, { out, nav: _lmNavSeq });
            const clear = () => { if (pending.get(key)?.out === out) pending.delete(key); };
            out.then(clear, clear);
        }
        return out;
    };
}

// Every opener that appends only AFTER an await. Inline onclick= resolves these
// off the global object, so rebinding the property is enough to cover the
// handlers in markup. Declarations hoist, so all of them already exist here.
['editReport', 'openAgentConfigModal', 'openAgentAssignModal', 'openSpokeAssignModal',
 'openSpokeMetadataModal', 'showGroupModal', 'openConsoleCaptureModal',
 'openConsoleCredentialsModal', 'openConsolePortTenantModal', 'showPxmxInstallModal',
 'showDnsCredentialsModal', 'showAddUserModal', 'editUser'].forEach(name => {
    if (typeof window[name] === 'function') window[name] = _singleFlight(window[name]);
});

// ── Self-service spoke onboarding ("Add Server") ────────────────────────────
// A tenant-admin (who has no access to the Global-Admin-only Setup → Spokes
// approval screen) generates a one-time onboarding key for their OWN tenant
// and gets an install command for a brand-new spoke of a given role — the new
// box self-registers and auto-binds to that tenant the moment it connects
// with the key (main.py._try_psk_self_provision), no admin click required.
// Reusable across every per-tenant-spoke module (nac/dns/dhcp/nw/...) —
// parameterized by role. Backend: routes/onboarding.py, mounted at
// /tenant/{tenant}/onboarding-psk — a GENERIC, module-agnostic twin of the
// Simulations-specific card in sim-views.js (csSpokeMgmtPskCard), which
// manages the same underlying PSK but ALSO pushes it to the tenant's cs
// spoke for a different (sub-agent relay) mechanism this does not use.
function addServerButtonHtml(role, label) {
    if (!isTenantAdmin() && !isAdmin()) return '';
    return `<button onclick="openAddServerModal('${escapeHtml(role)}', '${escapeHtml(label)}')"
        class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold shadow-sm"
        title="Self-service: onboard a new ${escapeHtml(label)} server for your tenant">+ Add Server</button>`;
}

function openAddServerModal(role, label) {
    const tenant = currentTenant && currentTenant !== 'default' ? currentTenant : null;
    if (!tenant) {
        if (typeof showToast === 'function') showToast('Select a tenant first', 'error');
        return;
    }
    const body = `
        <h3 class="text-lg font-bold text-[#263040]">Add ${escapeHtml(label)} Server</h3>
        <p class="text-sm text-slate-500">Generate a one-time onboarding key, then run the install command below on the new server. It registers and binds to <b>${escapeHtml(tenant)}</b> automatically — no admin approval needed.</p>
        <div id="add-server-psk-area" class="text-xs text-slate-400 italic">No key generated yet.</div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="document.getElementById('add-server-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Close</button>
            <button onclick="_addServerGenPsk('${escapeHtml(role)}', '${escapeHtml(tenant)}')" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Generate Key</button>
        </div>`;
    openModal('add-server-modal', body, { backdropClose: true });
}

async function _addServerGenPsk(role, tenant) {
    const area = document.getElementById('add-server-psk-area');
    try {
        const r = await apiJson(`/tenant/${encodeURIComponent(tenant)}/onboarding-psk`, { method: 'POST', body: '{}' });
        if (!area) return;
        const cmd = `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \\\n  | sudo bash -s -- --onboarding-psk ${r.psk} --tenant-hint ${tenant}`;
        area.innerHTML = `<p class="text-xs font-bold text-slate-600 mb-1">Run this on the new server:</p>
            <pre id="add-server-cmd" class="bg-slate-50 border border-slate-200 rounded-md p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">${escapeHtml(cmd)}</pre>
            <button onclick="_addServerCopyCmd()" class="mt-2 text-xs text-[#01A982] hover:underline">Copy command</button>
            <p class="mt-2 text-[11px] text-slate-400">This key is single-use for onboarding — it does not expire on its own. Revoke it from the tenant's onboarding key list once the server has connected.</p>`;
    } catch (e) {
        console.error('_addServerGenPsk: generate failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
}

function _addServerCopyCmd() {
    const el = document.getElementById('add-server-cmd');
    if (!el) return;
    navigator.clipboard.writeText(el.textContent || '');
    if (typeof showToast === 'function') showToast('Copied', 'success');
}

// --- My Devices: tenant-admin self-service spokes/agents list + onboarding keys.
// Solves the onboarding chicken/egg: a tenant-admin with no approved spoke can't
// reach the Global-Admin spoke screens (the Simulations nav only lights once a cs
// spoke is approved), so these two cards live in the always-visible My Devices
// view. Backend is tenant-scoped (routes/onboarding.py); the client only ever
// passes its own currentTenant, which the server re-checks against session tenants.
function _myDevTenant() {
    return currentTenant && currentTenant !== 'default' ? currentTenant : null;
}

async function loadMyDeviceSpokes() {
    const el = document.getElementById('my-spokes-list');
    if (!el) return;
    const tenant = _myDevTenant();
    if (!tenant) { el.innerHTML = '<p class="text-xs text-slate-400 italic">Select a tenant first.</p>'; return; }
    try {
        const r = await apiJson(`/tenant/${encodeURIComponent(tenant)}/spokes`);
        const rows = (r && r.spokes) || [];
        if (!rows.length) {
            el.innerHTML = '<p class="text-xs text-slate-400 italic">No spokes or agents onboarded yet. Generate an onboarding key below to add your first one.</p>';
            return;
        }
        el.innerHTML = rows.map((s) => {
            const conn = s.connected
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-green-100 text-green-700">connected</span>'
                : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-500">offline</span>';
            const appr = s.approved
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700">approved</span>'
                : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-700">pending</span>';
            // Revoked surface: a node auto-contained by the tenant-side threat
            // response (or an admin revoke) shows WHY, so a tenant-admin sees the
            // reason inline instead of a silent "pending". Re-approval (by an
            // admin) is required to return.
            const revoked = s.revoked
                ? (() => {
                    const _auto = s.revoked_by === 'threat_auto';
                    const _when = s.revoked_ts ? new Date(s.revoked_ts * 1000).toLocaleString() : '';
                    const _t = `Revoked${_auto ? ' automatically (tenant-side threat response)' : ' by admin'}`
                        + (s.revoke_reason ? ` — ${s.revoke_reason}` : '')
                        + (_when ? ` (${_when})` : '') + '. Admin re-approval required.';
                    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold ${_auto ? 'bg-red-600 text-white' : 'bg-red-100 text-red-700'}" title="${escapeHtml(_t)}">${_auto ? '⛔ auto-revoked' : '⛔ revoked'}</span>`;
                })()
                : '';
            // A bare agent (module_type "agent") can host roles — offer Load/Unload
            // via the same modal the Global-Admin Spokes & Agents view uses. The
            // backend (/tenant/agent/*) re-checks that this spoke is bound to the
            // caller's tenant, so a tenant-admin can only manage their own nodes.
            const canRoles = s.connected && s.approved && (s.module_type === 'agent');
            const eSid = String(s.spoke_id).replace(/'/g, "\\'");
            const rolesBtn = canRoles
                ? `<button onclick="showLoadRoleModal('${eSid}')" class="px-2.5 py-1 rounded-md text-[11px] font-bold bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982] transition-colors" title="Load or unload roles (DNS, DHCP, Edge Proxy, …) on this agent">Roles</button>`
                : '';
            // Delete permanently removes the registration + crypto material; the
            // spoke must fully re-onboard (a fresh key) to return. Tenant-scoped
            // server-side (/tenant/{tenant}/spokes/{id}) — a tenant-admin can
            // only delete a spoke bound to their own tenant.
            const eName = String(s.display_name || s.spoke_id).replace(/'/g, "\\'");
            const delBtn = `<button onclick="_myDevDeleteSpoke('${eSid}', '${eName}')" class="px-2.5 py-1 rounded-md text-[11px] font-bold bg-white hover:bg-red-50 text-red-600 border border-red-300 transition-colors" title="Permanently remove this spoke/agent — it must re-onboard to return">Delete</button>`;
            return `<div class="flex items-center justify-between border border-slate-100 rounded-md px-3 py-2">
                <div><span class="text-sm font-medium text-slate-700">${escapeHtml(_nodeLabel(s.display_name || s.spoke_id, s.tenant_id || tenant))}</span>
                <span class="ml-2 text-[11px] text-slate-400 font-mono">${escapeHtml(s.module_type || '—')}</span></div>
                <div class="flex items-center gap-2">${rolesBtn}${revoked}${appr}${conn}${delBtn}</div></div>`;
        }).join('');
    } catch (e) {
        console.error('loadMyDeviceSpokes failed', e);
        el.innerHTML = `<p class="text-xs text-red-500 italic">Failed to load spokes: ${escapeHtml(e.message || 'error')}</p>`;
    }
}

// Relayed Proxmox node agents (dial a hypervisor/simulation spoke's /ws/agent
// directly, not the hub) scoped to this tenant — the tenant-admin self-service
// counterpart to Setup → Spokes & Agents' Agents tile, backed by
// /tenant/{tenant}/agents (routes/onboarding.py), which does NOT require the
// `pxmx` module right the admin tile's /api/pxmx/agents does.
async function loadMyDeviceAgents() {
    const el = document.getElementById('my-pxmx-agents-list');
    if (!el) return;
    const tenant = _myDevTenant();
    if (!tenant) { el.innerHTML = '<p class="text-xs text-slate-400 italic">Select a tenant first.</p>'; return; }
    try {
        const r = await apiJson(`/tenant/${encodeURIComponent(tenant)}/agents`);
        const rows = [
            ...(r.pending_agents || []).map((a) => ({ ...a, _status: 'pending' })),
            ...(r.agents || []).map((a) => ({ ...a, _status: 'connected' })),
            ...(r.offline_agents || []).map((a) => ({ ...a, _status: 'offline' })),
        ];
        if (!rows.length) {
            el.innerHTML = '<p class="text-xs text-slate-400 italic">No Proxmox node agents relayed through your tenant\'s spokes yet.</p>';
            return;
        }
        el.innerHTML = rows.map((a) => {
            const badge = a._status === 'pending'
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-700">pending</span>'
                : a._status === 'connected'
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-green-100 text-green-700">connected</span>'
                : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-500">offline</span>';
            const eAid = String(a.agent_id).replace(/'/g, "\\'");
            const eSpk = String(a.spoke_id || '').replace(/'/g, "\\'");
            const approveBtn = a._status === 'pending'
                ? `<button onclick="_myDevApproveAgent('${eSpk}', '${eAid}')" class="px-2.5 py-1 rounded-md text-[11px] font-bold bg-white hover:bg-green-50 text-green-700 border border-green-300 transition-colors">Approve</button>`
                : '';
            // Client-Simulation toggle: only meaningful once approved (a
            // pending agent has no tenant pin yet, and the tenant-scoped
            // cs-config route gates on that pin — see set_tenant_agent_cs_config).
            // A cs-spoke-dialed agent already arrives with this ON (auto-
            // enabled at approval time), so the common case is just a status
            // badge; this lets it be turned off (or a hypervisor-spoke agent
            // turned on) without an admin.
            const csEnabled = !!(a.client_simulation && a.client_simulation.enabled);
            const csToggle = a._status !== 'pending'
                ? `<button onclick="_myDevToggleAgentCs('${eAid}', ${!csEnabled})" class="px-2.5 py-1 rounded-md text-[11px] font-bold border transition-colors ${csEnabled ? 'bg-white hover:bg-red-50 text-red-600 border-red-300' : 'bg-white hover:bg-green-50 text-green-700 border-green-300'}" title="Client-Simulation mode">${csEnabled ? 'Disable CS' : 'Enable CS'}</button>`
                : '';
            return `<div class="flex items-center justify-between border border-slate-100 rounded-md px-3 py-2">
                <div><span class="text-sm font-medium text-slate-700">${escapeHtml(String(a.hostname || a.agent_id || '').toUpperCase())}</span>
                <span class="ml-2 text-[11px] text-slate-400 font-mono">via ${escapeHtml(a.spoke_id || '—')}</span>
                ${csEnabled ? '<span class="ml-2 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700">CS</span>' : ''}</div>
                <div class="flex items-center gap-2">${badge}${approveBtn}${csToggle}</div></div>`;
        }).join('');
    } catch (e) {
        console.error('loadMyDeviceAgents failed', e);
        el.innerHTML = `<p class="text-xs text-red-500 italic">Failed to load agents: ${escapeHtml(e.message || 'error')}</p>`;
    }
}

async function _myDevApproveAgent(spokeId, agentId) {
    const tenant = _myDevTenant();
    if (!tenant) return;
    try {
        await apiJson(`/tenant/${encodeURIComponent(tenant)}/agents/${encodeURIComponent(spokeId)}/${encodeURIComponent(agentId)}/approve`,
            { method: 'POST' });
        if (typeof showToast === 'function') showToast('Agent approved', 'success');
        loadMyDeviceAgents();
    } catch (e) {
        console.error('_myDevApproveAgent failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
}

async function _myDevToggleAgentCs(agentId, enabled) {
    const tenant = _myDevTenant();
    if (!tenant) return;
    try {
        await apiJson(`/tenant/${encodeURIComponent(tenant)}/agents/${encodeURIComponent(agentId)}/cs-config`,
            { method: 'POST', body: JSON.stringify({ enabled }) });
        if (typeof showToast === 'function') showToast(enabled ? 'Client-Simulation enabled' : 'Client-Simulation disabled', 'success');
        loadMyDeviceAgents();
    } catch (e) {
        console.error('_myDevToggleAgentCs failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
}

async function loadMyDevicePsks() {
    const el = document.getElementById('my-psk-list');
    if (!el) return;
    const tenant = _myDevTenant();
    if (!tenant) { el.innerHTML = '<p class="text-xs text-slate-400 italic">Select a tenant first.</p>'; return; }
    try {
        const r = await apiJson(`/tenant/${encodeURIComponent(tenant)}/onboarding-psk`);
        const keys = (r && r.psks) || [];
        if (!keys.length) { el.innerHTML = '<p class="text-xs text-slate-400 italic">No active onboarding keys.</p>'; return; }
        // Prefer the configured Hub URL so the install command points spokes at
        // the HUB, not the proxy that may be serving this WebUI (location.host).
        // It comes from the onboarding route itself, which a TENANT ADMIN can
        // reach. Reading it from /setup/config (admin-only) meant a tenant admin
        // always 403'd here, fell through to location.host, and was shown the
        // proxy alias instead of the hub. /setup/config is kept only as a
        // fallback for an older hub that does not yet return hub_url.
        let hubUrl = ((r && r.hub_url) || '').trim();
        if (!hubUrl) {
            try {
                const cr = await setupFetch('/setup/config');
                if (cr.ok) {
                    const cfg = await cr.json();
                    hubUrl = (((cfg.global_config || {}).hub || {}).url || '').trim();
                }
            } catch (e) { console.error('loadMyDevicePsks hub-url fetch failed', e); }
        }
        el.innerHTML = keys.map((k, i) => {
            const cmd = _myDevInstallCmd(k, tenant, hubUrl);
            const uninstall = 'curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall.sh \\\n  | bash -s -- --yes';
            return `<div class="border border-slate-100 rounded-md px-3 py-2">
                <div class="flex items-center justify-between gap-3">
                    <code class="text-[11px] font-mono text-slate-600 break-all">${escapeHtml(k)}</code>
                    <button onclick="_myDevRevokePsk('${escapeHtml(k)}')" class="text-xs text-red-500 hover:underline shrink-0">Revoke</button>
                </div>
                <p class="text-[11px] font-bold text-slate-500 mt-2 mb-1">Install command:</p>
                <pre id="my-psk-cmd-${i}" class="bg-slate-50 border border-slate-200 rounded-md p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">${escapeHtml(cmd)}</pre>
                <button onclick="_myDevCopyEl('my-psk-cmd-${i}')" class="mt-1 text-xs text-[#01A982] hover:underline">Copy command</button>
                <p class="text-[11px] text-slate-400 mt-2">The spoke installs as a bare agent and loads roles later from this page. To pre-assign roles instead, append <code>--roles &lt;module&gt;</code> (comma-separated, e.g. <code>--roles simulation</code> or <code>--roles dns,dhcp</code>). Installing <code>--roles simulation</code> also makes this box host the client-sim <code>/ws/agent</code> listener, so a Proxmox Host Agent (below) can report to it.</p>
                <p class="text-[11px] font-bold text-slate-500 mt-2 mb-1">Uninstall (removes all LM components from that host):</p>
                <pre id="my-psk-uninstall-${i}" class="bg-slate-50 border border-slate-200 rounded-md p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">${escapeHtml(uninstall)}</pre>
                <button onclick="_myDevCopyEl('my-psk-uninstall-${i}')" class="mt-1 text-xs text-[#01A982] hover:underline">Copy uninstall</button>
            </div>`;
        }).join('');
    } catch (e) {
        console.error('loadMyDevicePsks failed', e);
        el.innerHTML = `<p class="text-xs text-red-500 italic">Failed to load keys: ${escapeHtml(e.message || 'error')}</p>`;
    }
}

// Build the one-line installer for an onboarding key, with the hub address and
// PSK/tenant pre-filled so it runs as-is. The spoke comes up as a bare agent and
// loads roles later from My Devices; roles can be pre-assigned by appending
// --roles (see the note beside the command).
//
// The hub address prefers the configured Hub URL (global_config.hub.url, set in
// Setup → Spokes & Agents) so spokes dial the HUB directly. Only when no Hub URL
// is configured do we fall back to the host serving this WebUI (location.host) —
// which, behind an edge proxy, is the PROXY, not the hub, so spokes would wrongly
// dial the proxy. Matches install_agent.sh's `--hub wss://HOST[:port]`.
function _myDevHubHost(raw) {
    // Normalize any hub address to a bare host[:port].
    // Strips ws://, wss://, http:// AND https:// — http(s) was previously left
    // in place, so a hub configured as `https://host` produced the nonsense
    // `wss://https:` (the later /-strip ate everything after the scheme colon).
    // Then drops any /path (e.g. /ws/agent), keeping only the authority.
    let u = (raw || '').trim().replace(/^(wss?|https?):\/\//i, '').replace(/\/.*$/, '');
    // Legacy-alias canonicalization: the hub's canonical DNS short-name is
    // `lm-hub` (HUB_SHORT_NAME — the installer sets the hub host's hostname
    // to it), so rewrite the older `labmanager` alias to `lm-hub` in the
    // copy/paste install command. Anchored to the first host label + only
    // when followed by `.`/`:`/end, so it rewrites labmanager.<domain>[:port]
    // and never a host that merely contains the substring.
    return u.replace(/^labmanager(?=[.:]|$)/i, 'lm-hub');
}

function _myDevHubArg(configuredHubUrl) {
    const u = _myDevHubHost(configuredHubUrl);
    if (u) return `wss://${u}`;
    // Fallback: the host serving this page. This is a LAST resort -- it is the
    // proxy/WebUI address, not necessarily the hub -- so it must go through the
    // SAME normalization. It previously did not, which is how the legacy
    // `labmanager` alias kept appearing in the install command for anyone whose
    // configured hub URL came back empty.
    const fallback = (typeof location !== 'undefined' && location.host)
        ? _myDevHubHost(location.host) : '';
    return fallback ? `wss://${fallback}` : 'auto';
}

function _myDevInstallCmd(psk, tenant, configuredHubUrl) {
    const hub = _myDevHubArg(configuredHubUrl);
    return `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \\\n`
        + `  | bash -s -- --hub ${hub} --onboarding-psk ${psk} --tenant-hint ${tenant}`;
}

async function _myDevGenPsk() {
    const tenant = _myDevTenant();
    if (!tenant) { if (typeof showToast === 'function') showToast('Select a tenant first', 'error'); return; }
    try {
        await apiJson(`/tenant/${encodeURIComponent(tenant)}/onboarding-psk`, { method: 'POST', body: '{}' });
        // The new key (with its copy-paste install command) renders in the list.
        loadMyDevicePsks();
        if (typeof showToast === 'function') showToast('Onboarding key generated', 'success');
    } catch (e) {
        console.error('_myDevGenPsk failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
}

// Proxmox Host Agent install-command builder: lets a tenant-admin pick one of
// their own connected agent-listener-hosting spokes from a dropdown instead of
// hand-typing an IP, and pins --spoke-ip accordingly. The target listener is
// hosted by EITHER a hypervisor (pxmx) spoke (always on) OR a simulation (cs)
// spoke with the agent-listener role loaded (opt-in) — see the card's own
// prose above — so both module types are offered here. uninstall.sh has no
// remote/spoke-targeting flag at all (it only runs locally on the box being
// removed), so only the install command is dynamic here.
async function loadMyPxmxSpokes() {
    const sel = document.getElementById('my-pxmx-spoke');
    if (!sel) return;
    const tenant = _myDevTenant();
    if (!tenant) { _myDevPxmxUpdateInstall(); return; }
    try {
        const r = await apiJson(`/tenant/${encodeURIComponent(tenant)}/spokes`);
        const rows = ((r && r.spokes) || []).filter((s) =>
            (s.module_type === 'hypervisor' || s.module_type === 'simulation') && s.connected && s.approved && s.ip);
        const prior = sel.value;
        sel.innerHTML = '<option value="">— auto-discover (omit --spoke-ip) —</option>'
            + rows.map((s) => {
                const kind = s.module_type === 'hypervisor' ? 'pxmx' : 'cs';
                return `<option value="${escapeHtml(s.ip)}">${escapeHtml(s.display_name || s.spoke_id)} (${kind}, ${escapeHtml(s.ip)})</option>`;
            }).join('');
        if (prior && rows.some((s) => s.ip === prior)) sel.value = prior;
    } catch (e) {
        console.error('loadMyPxmxSpokes failed', e);
    }
    _myDevPxmxUpdateInstall();
}

function _myDevPxmxUpdateInstall() {
    const pre = document.getElementById('my-pxmx-install');
    if (!pre) return;
    const sel = document.getElementById('my-pxmx-spoke');
    const ip = sel ? sel.value.trim() : '';
    pre.textContent = ip
        ? `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \\\n  | sudo bash -s -- --spoke-ip ${ip}`
        : `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \\\n  | sudo bash`;
}

function _myDevCopyEl(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent || '');
    if (typeof showToast === 'function') showToast('Copied', 'success');
}

async function _myDevRevokePsk(psk) {
    const tenant = _myDevTenant();
    if (!tenant) return;
    try {
        await apiJson(`/tenant/${encodeURIComponent(tenant)}/onboarding-psk`, { method: 'DELETE', body: JSON.stringify({ psk }) });
        loadMyDevicePsks();
    } catch (e) {
        console.error('_myDevRevokePsk failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
}

// Permanently delete a spoke/agent bound to the current tenant. Server-side the
// DELETE /tenant/{tenant}/spokes/{id} route re-checks that the spoke is bound to
// a tenant the caller owns (anti-IDOR), then runs the same teardown as the
// Global-Admin delete — the spoke must re-onboard (fresh key) to return.
async function _myDevDeleteSpoke(spokeId, label) {
    const tenant = _myDevTenant();
    if (!tenant) { if (typeof showToast === 'function') showToast('Select a tenant first', 'error'); return; }
    const name = label || spokeId;
    if (!await showConfirmToast(`Delete spoke “${name}”? This permanently removes its registration and crypto material — it must re-onboard (a new install/key) to return. Any roles it hosts are torn down.`)) return;
    try {
        await apiJson(`/tenant/${encodeURIComponent(tenant)}/spokes/${encodeURIComponent(spokeId)}`, { method: 'DELETE' });
        loadMyDeviceSpokes();
        if (typeof loadMyPxmxSpokes === 'function' && document.getElementById('my-pxmx-spoke')) loadMyPxmxSpokes();
        if (typeof showToast === 'function') showToast(`Spoke “${name}” removed`, 'success');
    } catch (e) {
        console.error('_myDevDeleteSpoke failed', e);
        if (typeof showToast === 'function') showToast(e.message, 'error');
    }
}

// Watchdog recovery badge for a spoke. The hub's run_spoke_recovery_loop
// restarts stranded units (reset-failed + restart, backoff 60/120/180s) and
// exposes per-spoke state via GET_SPOKE_STATUS + /setup/diagnostics. This maps
// that state to a single colored badge so an operator can see — without CLI —
// whether a spoke is healthy, being recovered, gave up (needs a reinstall), or
// is paused by an admin.
function recoveryBadge(rec) {
    rec = rec || {};
    if (rec.manual_pause) return { text: 'Paused', tone: 'bg-slate-100 text-slate-500', title: 'Recovery paused by admin' };
    if (rec.gave_up)       return { text: 'Gave up', tone: 'bg-red-100 text-red-600', title: `Gave up: ${rec.last_error || 'unknown'}` };
    if (rec.in_progress)  return { text: `Recovering ${rec.attempts}/3`, tone: 'bg-amber-100 text-amber-600', title: `Last action: ${rec.last_action || 'restart'}` };
    if (rec.attempts > 0)  return { text: 'Recovered', tone: 'bg-green-100 text-green-600', title: `Recovered after ${rec.attempts} attempt(s)` };
    return { text: '—', tone: 'bg-slate-50 text-slate-400', title: 'No recovery activity' };
}


// _diagTelemetryExtras(s, fns) — the diagnostics-only telemetry bits for one
// spoke/agent, factored out of the former standalone Diagnostics tile so the
// Spokes / Agents / Generic Agents management cards can fold them in without
// re-rendering the name / module / approve row they already own. Returns the
// heartbeat-aware status dot plus the telemetry badges (heartbeat · age,
// version, skew, recovery, out-of-contact alert), the status-text + last-error
// meta lines, the Reset Secret / Delete / Recovery Pause / Events action row,
// and the expandable events panel — everything _mgmtEntryCard doesn't already
// get from the management renderer that calls this.
//
// `s` is a /setup/diagnostics entry (true spokes + generic Hub-direct agents)
// or a _normalizePxmxAgent() shape (Proxmox node agents). `fns` selects action
// handlers: spokes + generic agents use the spoke endpoints (defaults);
// Proxmox node agents pass the pxmx relay endpoints, suppress Recovery Pause
// (the hub watchdog is spoke-scoped, not per-agent), and suppress Reset Secret
// (revokeAgent is already the Agents tile's Un-approve button — no duplicate).
function _diagTelemetryExtras(s, fns) {
    fns = fns || {};
    const deleteFn = fns.deleteFn || 'deleteSpoke';
    const decommFn = fns.decommissionFn || 'decommissionSpoke';
    const restoreFn = fns.restoreFn || 'restoreSpoke';
    // Soft-retire flag: the record is kept (stays visible + re-onboardable) but
    // the out-of-contact alert loop skips it. UI badged grey + the action row
    // swaps to Restore / Force Delete. Decommission is only meaningful for an
    // approved/connected box — a pending one is just deleted.
    const decomm = !!(s.decommissioned && (s.approved || s.authenticated));
    // resetFn/allowReset are no longer consumed here — Reset Secret moved into
    // the spoke Edit modal (openSpokeMetadataModal). Callers may still pass them.
    const status = spokeStatusMessage(s);
    // event_count is the light badge value shipped in the /setup/diagnostics
    // LIST; the actual events/log_events arrays are lazily fetched on expand
    // (see toggleSpokeEvents). Fall back to inline arrays for compatibility.
    const evCount = (s.event_count != null)
        ? s.event_count
        : ((s.events || []).length + (s.log_events || []).length);
    const rec = s.recovery || {};
    const badge = recoveryBadge(rec);
    const _recTextTone = rec.gave_up ? 'text-red-600'
                       : rec.in_progress ? 'text-amber-600'
                       : rec.attempts > 0 ? 'text-green-600' : 'text-slate-500';
    // Heartbeat: status color + age since last heartbeat frame.
    const hbStatus = String(s.heartbeat_status || '');
    const hbAge = (s.heartbeat_age_s == null) ? 'never'
               : (s.heartbeat_age_s === 0 ? 'now' : `${s.heartbeat_age_s}s`);
    const hbBadgeTone = hbStatus === 'GREEN' ? 'bg-green-100 text-green-700'
                      : hbStatus === 'YELLOW' ? 'bg-amber-100 text-amber-700'
                      : 'bg-red-100 text-red-700';
    // Out-of-contact alert badge (SpokeAlertMixin) — separate, forgiving tier
    // (warning >=5m / error >=30m) distinct from the realtime heartbeat light.
    const aTier = String(s.alert_tier || '');
    // A decommissioned (retired) box never fires spoke_out_of_contact (the alert
    // loop skips it + the endpoint clears any active tier), so suppress the red
    // alert badge for it — it would otherwise read as "alerting" when it's
    // intentionally retired.
    const alertBadge = (aTier === 'error' || aTier === 'warning') && !decomm
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${aTier === 'error' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}" title="Out of contact ${Math.round((s.alert_duration_s || 0) / 60)}m — forgiving alert tier (separate from the heartbeat light)">alert · ${aTier}</span>`
        : '';
    // Version chip color: GREEN = up to date, RED = out of date, slate =
    // unknown (no telemetry to compare against). "Out of date" is EITHER of two
    // signals, both hub-computed: version_behind (spoke's .NN is older than the
    // latest .NN the hub knows for ITS repo — a genuine "newer build exists")
    // OR version_skew (reported version isn't on the .NN numbering at all — a
    // stale X.Y.Z / v-tag / pre-reset value). Folds both into the version chip.
    const _ver = s.version || 'unknown';
    const _verUnknown = !s.version || _ver === 'unknown';
    const _behind = !!s.version_behind;
    const _stale = !!s.version_skew;
    const _outOfDate = _behind || _stale;
    // Card warning states: out-of-date (amber) or last contact > 30 min (stale, red).
    const _stale30 = (s.heartbeat_age_s != null && s.heartbeat_age_s > 1800);
    const _verTone = _verUnknown ? 'bg-slate-100 text-slate-600'
                   : (_outOfDate ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700');
    const _verTitle = _verUnknown ? 'Version unknown — no telemetry to compare'
                    : _behind ? ('Out of date — running ' + _ver + ' / latest ' + (s.latest_version || '?'))
                    : _stale ? 'Out of date — behind the current .NN version'
                    : 'Up to date';
    // Heartbeat-aware status dot: green = healthy & beating, amber = slow-but-
    // live, red = offline/never/RED, slate = no heartbeat telemetry yet. The
    // management renderers use this in place of their approval-only dot when
    // telemetry is available AND the spoke is approved/connected — a pending
    // spoke keeps its amber approval dot (heartbeat is meaningless pre-approval)
    // but an approved-but-silent spoke goes red even though it is approved.
    const dot = decomm ? 'bg-slate-400'
              : !s.authenticated
              // Offline: red only if we have NO recent last-seen, or last contact
              // was >15 min ago. A spoke that was connected seconds before a hub
              // reboot (persisted last_seen re-seeded at startup → real
              // heartbeat_age_s) shows amber, not red — it's almost certainly
              // reconnecting, not dead.
              ? ((s.heartbeat_age_s != null && s.heartbeat_age_s < 900) ? 'bg-amber-400' : 'bg-red-500')
              : hbStatus === 'GREEN' ? 'bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]'
              : hbStatus === 'YELLOW' ? 'bg-amber-400'
              : hbStatus === 'RED' ? 'bg-red-500'
              : 'bg-slate-300';
    const eSid = s.spoke_id.replace(/'/g, "\\'");
    return {
        dot,
        cardTone: _stale30 ? 'stale' : (_outOfDate ? 'warn' : ''),
        // Raw {text, tone} so the caller can render the Online/Offline status
        // INLINE on the host/tenant row (one line) instead of its own stacked
        // div — saves vertical space on the Spokes & Agents tiles.
        status,
        // Quiet metadata fragments (version · seen · recovery · alert). Colour
        // ONLY when it matters: out-of-date version red, recovery/alert states.
        metaParts: [
            decomm ? `<span class="text-slate-500 font-semibold" title="Soft-retired — record kept, out-of-contact alert suppressed. Restore to re-enable.">decommissioned</span>` : '',
            _verUnknown ? '' : `<span class="${_outOfDate ? 'text-red-600 font-semibold' : ''}" title="${_verTitle}">v${escapeHtml(_ver)}${_outOfDate ? ' · out of date' : ''}</span>`,
            `<span title="Time since the last inbound heartbeat frame">${hbAge === 'never' ? 'never seen' : (hbAge === 'now' ? 'seen just now' : `seen ${escapeHtml(hbAge)} ago`)}</span>`,
            (badge.text !== '—') ? `<span class="${_recTextTone} font-semibold" title="${escapeHtml(badge.title)}">${escapeHtml(badge.text)}</span>` : '',
            ((aTier === 'error' || aTier === 'warning') && !decomm) ? `<span class="${aTier === 'error' ? 'text-red-600' : 'text-amber-600'} font-semibold" title="Out of contact ${Math.round((s.alert_duration_s || 0) / 60)}m — forgiving alert tier">alert: ${escapeHtml(aTier)}</span>` : '',
        ],
        metaLines: [
            // status text moved INLINE to the caller's host/tenant row.
            s.last_error ? `<div class="text-[10px] text-red-500 font-mono pl-6 break-all">${escapeHtml(s.last_error)}</div>` : '',
        ],
        actions: decomm ? [
            // Retired box: Restore (re-enables alerting) + Force Delete (the hard
            // wipe — the existing DELETE, now labelled to make the destructiveness
            // obvious next to the reversible Decommission/Restore).
            _mgmtBtn('Restore', `${restoreFn}('${eSid}')`, 'bg-green-600 hover:bg-green-700 text-white'),
            _mgmtBtn('Force Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white'),
        ] : (s.approved || s.authenticated ? [
            // Live/approved: soft-retire (reversible) OR hard delete.
            _mgmtBtn('Decommission', `${decommFn}('${eSid}')`, 'bg-slate-500 hover:bg-slate-600 text-white'),
            _mgmtBtn('Force Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white'),
        ] : [
            // Pending (not yet approved): only the hard delete makes sense.
            _mgmtBtn('Force Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white'),
        ]),
        // Events (+ Copy) pinned to the far right of the header row (next to the
        // ID) via _mgmtEntryCard's cornerActions slot, not the bottom action row.
        eventsActions: [
            `<button onclick="toggleSpokeEvents('${eSid}')" class="text-blue-500 hover:text-blue-700 font-medium text-xs">${evCount} events ▾</button>`,
            evCount ? `<button onclick="copySpokeEvents('${eSid}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Copy</button>` : '',
        ],
        // Empty container — the events/log_events arrays are fetched from
        // GET /setup/diagnostics/{spoke_id} the first time the panel is expanded
        // (toggleSpokeEvents), keeping the polled LIST payload light. If the
        // entry still carries inline arrays (compat), render them immediately and
        // mark the panel loaded so no fetch fires.
        eventsPanel: `<div id="events-${s.spoke_id}" data-loaded="${(s.events || s.log_events) ? '1' : '0'}" class="hidden font-mono text-[11px] bg-slate-50 border border-slate-200 rounded p-3 max-h-56 overflow-y-auto ml-6 mt-1">${(s.events || s.log_events) ? _renderSpokeEventsInner(s.events || [], s.log_events || []) : '<span class="text-slate-400 italic">Loading…</span>'}</div>`,
    };
}

// Map a Proxmox node agent (from /api/pxmx/agents) into the same telemetry
// shape spokes/generic-agents use, so _diagTelemetryExtras can fold its
// heartbeat/version into the Agents card the same way it does for spokes.
// These agents connect through the pxmx hypervisor spoke; the pxmx spoke now
// relays their AGENT_HEARTBEAT up, so the hub HeartbeatManager tracks them
// (keyed spoke_id:agent_id) and /api/pxmx/agents carries heartbeat_status +
// heartbeat_age_s. We fall back to the spoke's own last_seen so a freshly-seen
// agent still shows a status before the first relayed beat lands. Recovery/
// events stay empty/neutral (the watchdog is spoke-scoped, not per-agent).
// True when v is a bare per-repo ".NN" version (e.g. ".33"). Each repo's .NN
// is an independent bump counter, so a component .NN differing from the hub's
// .NN is normal; SKEW now flags only versions NOT in this shape (stale X.Y.Z /
// v-tag / pre-reset). Mirrors the backend _is_nn check in api.py get_diagnostics.
function _isNN(v) { const s = String(v == null ? '' : v).trim(); return /^\.\d+$/.test(s) || /^\d+\.\d+$/.test(s); }

function _normalizePxmxAgent(a) {
    const connected = a._status === 'connected';
    // Offline relayed agent: parent spoke is down, reconstructed by the hub from
    // persisted state (offline_agents). Not authenticated, not pending — it just
    // hasn't been seen. Drives spokeStatusMessage to the "Last seen …" branch and
    // the red/amber age-based dot, and keeps the Delete button so it's removable.
    const offline = a._status === 'offline' || a.offline === true;
    let hbStatus = a.heartbeat_status || '';
    let hbAge = a.heartbeat_age_s;
    if ((hbAge == null || !hbStatus) && typeof a.last_seen === 'number') {
        const age = Math.max(0, Math.floor(Date.now() / 1000 - a.last_seen));
        if (hbAge == null) hbAge = age;
        if (!hbStatus) hbStatus = age < 120 ? 'GREEN' : age < 300 ? 'YELLOW' : 'RED';
    }
    const ver = a.version || a.sw_version || 'unknown';
    return {
        spoke_id: a.agent_id,
        display_name: a.display_name || a.hostname || a.agent_id,
        // A connected pxmx-hosted agent is by definition approved — it only
        // reaches connected_agents on the spoke after authenticating with the
        // real secret, which it only has post-approval. The raw agent object
        // from GET_AGENTS never carries an explicit "approved" field (only
        // hub.approved_modules does, which isn't merged in here), so without
        // this, spokeStatusMessage() saw authenticated=true + approved=false
        // and showed "Online — pending approval" next to an already-green
        // "Connected" badge.
        approved: connected || !!a.approved,
        authenticated: connected,
        connection_state: connected ? 'CONNECTED' : (offline ? 'OFFLINE' : 'PENDING'),
        module_type: 'pxmx',
        version: ver,
        version_skew: ver !== 'unknown' && !_isNN(ver),
        heartbeat_status: hbStatus,
        heartbeat_age_s: hbAge,
        // Offline → '' so spokeStatusMessage falls through to the "Last seen X ago"
        // branch (using heartbeat_age_s) rather than the "awaiting approval" one.
        last_status: connected ? '' : (offline ? '' : 'PENDING_SECRET'),
        last_error: null,
        flapping: false,
        recent_drops: 0,
        events: [],
        recovery: {},
        // Soft-retire flag from /api/pxmx/agents (hub.state.is_agent_decommissioned).
        decommissioned: !!a.decommissioned,
        _kind: 'pxmx',
    };
}

// ── Log collapse / counter ────────────────────────────────────────────────
//
// Repeating log lines (e.g. the per-minute `NetboxSpoke - INFO - NetBox
// command: NETBOX_GET_PREFIXES` poll) are collapsed into a single row with a
// "×N" counter so a chatty event doesn't drown the view. Two lines group
// together when they are identical EXCEPT for the leading timestamp — the
// operator's "same event, different timestamp" rule. Each group renders once,
// at the position of its first (newest) occurrence; click the row to expand
// and see every occurrence with its own timestamp. Copy still emits every raw
// line with its timestamp (copyLogs reads container._rawLogs, not innerText),
// so the collapse is a display concern only — no data is lost.

// Grouping key for collapsing repeats. The DISPLAYED row is always the
// original line (with its real timestamp/uuid/counters); only this collapse
// KEY is normalized, so no data is lost — expanding a ×N group shows every
// occurrence verbatim. We normalize the per-instance parts that vary between
// otherwise-identical lines so "same event, different timestamp/uuid/counter"
// lines collapse into one ×N row (the operator's "combine all the common
// ones" rule):
//   1. leading `[source] ` prefix + leading `YYYY-MM-DD HH:MM:SS - ` timestamp
//      (the original de-dup keys; tolerate ,ms/.ms fractional seconds some
//      loggers append). Without stripping these the timestamp landed INSIDE
//      the key and every occurrence was unique, so spoke logs never collapsed.
//   2. UUIDs (8-4-4-4-12) — the per-request msg_id in `Request Timeout: [CMD]
//      <uuid> from <spoke>`, the `Request: <uuid> -> ...` debug id, the `Late
//      reply for <uuid>` id. Random correlation ids, never meaningful.
//   3. durations with a time unit (5.0s / 160s / 30ms) — timeout/backoff/
//      elapsed values that vary per occurrence (`Reconnecting in 160s`,
//      `after 5.0s`).
//   4. key=N counters (queue=16 / uptime_s=0 / count=5) — per-tick metrics in
//      heartbeat/telemetry lines.
// Identifiers that merely CONTAIN digits (cs-svr-03-spoke, lm-agent-opnsense,
// module=firewall, spoke_id=lm-agent) are NOT touched — they are not a leading
// [source]/timestamp, not a UUID, not a bare digit+time-unit, and not key=N
// (the value isn't digits) — so different spokes/modules/reasons still group
// SEPARATELY; only the noisy metrics within one spoke's stream collapse.
/**
 * Normalize a log line into a stable grouping key so identical-repeat events
 * (same source/level/message, differing only by timestamp/UUID/duration/counter)
 * collapse into one ×N row in the log view. Strips: leading [source] prefix,
 * leading timestamp (+optional ,ms/.ms), per-request UUIDs, durations
 * (`5.0s`/`30ms`), and `key=<N>` counter values. Two lines that differ ONLY in
 * those fields share a key and are grouped by `_renderGroupedLogs`.
 * @param {string} log - raw single log line
 * @returns {string} grouping key
 */
function _logLineKey(log) {
    return String(log)
        // Normalize the legacy two-line relay shape
        //   "[src] <ts> <name> <LEVEL>\n<msg>"   (space-sep, msg on next line)
        // to the canonical single-line shape
        //   "[src] <ts> - <name> - <LEVEL> - <msg>"
        // so both on-the-wire formats key identically and group together.
        // Some spokes (older cs builds) still relay uvicorn.access this way;
        // the canonical dash-sep shape is left untouched (it has no newline
        // right after the level, so this regex won't match it).
        .replace(/^(\[[^\]]*\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Z]+)[ \t]*\r?\n/, '$1$2 - $3 - $4 - ')
        .replace(/^\[[^\]]*\]\s*/, '')                                       // leading [source] prefix
        .replace(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[,.]\d+)?\s*-\s*/, '')  // timestamp (+ optional ,ms/.ms)
        .replace(/\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b/g, '<addr>')               // client IP:port (uvicorn.access) — ephemeral port varies per request
        .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '<uuid>')  // per-request UUID (Request Timeout / Request / Late reply)
        .replace(/\b\d+(?:\.\d+)?(?:ms|s|us)\b/g, '<T>')                      // duration (5.0s / 160s / 30ms)
        .replace(/(\b\w+)=\d+\b/g, '$1=<N>');                                 // counter (queue=16 / uptime_s=0)
}

// A subtle per-row "file a bug from this log line" affordance. Appears only on
// row hover (opacity-0 group-hover:opacity-100, plus focus:opacity-100 for
// keyboard users) so it never clutters the dense log view, and is pinned to the
// row's right. The raw line/level/source ride in data-* attributes (escaped
// here, decoded back by the handler's getAttribute) so no fragile inline-quote
// escaping is needed. Styled with the HPE-green accent used on the bug Submit
// button. NOTE: onclick is its OWN attribute — never inside class="…", or the
// inner quote closes the class early and the handler is silently swallowed.
function _logBugBtn(log, level, source) {
    return `<button type="button" title="File a bug report pre-filled from this log line"`
        + ` data-logline="${escapeHtml(log)}" data-level="${escapeHtml(level || '')}" data-source="${escapeHtml(source || '')}"`
        + ` onclick="fileBugFromLog(event, this)"`
        + ` class="lm-logbug-btn absolute right-1.5 top-1 z-10 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] rounded px-1.5 py-0.5 text-[10px] leading-none font-bold shadow-sm">🐞 Bug</button>`;
}

// One log line → a highlighted row. `count` (>1) adds a "×N" badge and wires the
// click-to-expand handler used by grouped rows. `lineRowFn` override lets the
// recovery view pass its own GAVE_UP styling while still collapsing repeats.
function _renderLogLineRow(log, count, lineRowFn) {
    if (lineRowFn) return lineRowFn(log, count);
    const u = log.toUpperCase();
    let cls = 'text-slate-600';
    let bg = 'hover:bg-slate-50';
    if (u.includes(' ERROR ') || u.includes(' CRITICAL ')) { cls = 'text-red-700 font-semibold'; bg = 'bg-red-50 hover:bg-red-100'; }
    else if (u.includes(' WARNING ') || u.includes(' WARN ')) { cls = 'text-amber-700'; bg = 'bg-amber-50 hover:bg-amber-100'; }
    else if (u.includes(' DEBUG ')) { cls = 'text-slate-400'; }
    // Highlight timestamp + source for both prefixed spoke logs
    // (`[lm-svcs-netbox] <ts> - Source - LEVEL - msg`) and bare hub logs
    // (`<ts> - Source - LEVEL - msg`). Also accept the legacy two-line relay
    // shape (`[src] <ts> <name> <LEVEL>\n<msg>` — space-sep, no dashes, message
    // on the next line) so older cs spoke builds render with the same
    // header + indented-message display and collapse via _logLineKey.
    const tsMatch = log.match(/^(?:\[([^\]]*)\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([^-]+?) - ([A-Z]+) - ([\s\S]*)$/)
        || log.match(/^(?:\[([^\]]*)\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Z]+)[ \t]*\r?\n([\s\S]*)$/);
    const badge = count && count > 1
        ? `<span class="ml-2 px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-slate-200 text-slate-600 align-middle whitespace-nowrap" title="${count} identical events (same except timestamp) — click to expand">×${count}</span>`
        : '';
    // Keep the onclick as its OWN attribute — embedding `onclick="..."` inside
    // the double-quoted class attribute lets the inner `"` close class early so
    // the handler is silently swallowed and clicks never fire.
    const isGroup = count && count > 1;
    const clsExtra = isGroup ? ' cursor-pointer select-none' : '';
    const onClick = isGroup ? ' onclick="toggleLogGroup(this)"' : '';
    // Header (source + timestamp + logger + level + ×N badge) on the first
    // line, the message payload on a second indented line — easier to scan a
    // long trail than one long wrapped line. copyLogs reads the raw array, so
    // Copy still emits the original single-line `<ts> - Source - LEVEL - msg`.
    if (tsMatch) {
        const head = `${tsMatch[1] ? `<span class="text-slate-400">[${tsMatch[1]}]</span> ` : ''}<span class="text-slate-400">${tsMatch[2]}</span> <span class="text-indigo-500 font-semibold">${tsMatch[3].trim()}</span> <span class="opacity-60">${tsMatch[4]}</span>${badge}`;
        return `<div class="group relative px-4 py-0.5 border-b border-slate-100 text-xs font-mono ${cls} ${bg}${clsExtra}"${onClick}>${_logBugBtn(log, tsMatch[4], tsMatch[1] || tsMatch[3])}${head}<div class="pl-4 mt-0.5 break-all">${tsMatch[5]}</div></div>`;
    }
    return `<div class="group relative px-4 py-0.5 border-b border-slate-100 text-xs font-mono ${cls} ${bg}${clsExtra}"${onClick}>${_logBugBtn(log, '', '')}${log}${badge}</div>`;
}

// Group `logs` (newest-first) by message key; render each group once at its
// first-occurrence position. Single-occurrence lines render as a plain row.
function _renderGroupedLogs(logs, lineRowFn) {
    const groups = [];
    const byKey = new Map();
    for (const log of logs) {
        const key = _logLineKey(log);
        let g = byKey.get(key);
        if (!g) { g = { key, lines: [] }; byKey.set(key, g); groups.push(g); }
        g.lines.push(log);
    }
    return groups.map(g => {
        if (g.lines.length === 1) return _renderLogLineRow(g.lines[0], 1, lineRowFn);
        // Header = newest occurrence + ×N badge; expand block = the remaining
        // N-1 older occurrences (header already shows the newest, so no dup).
        const header = _renderLogLineRow(g.lines[0], g.lines.length, lineRowFn);
        const expanded = g.lines.slice(1).map(l => _renderLogLineRow(l, 1, lineRowFn)).join('');
        return `<div class="log-group">${header}<div class="log-group-expanded hidden">${expanded}</div></div>`;
    }).join('');
}

// Click handler for a grouped log header: toggle the expand block. Walk up to
// the .log-group wrapper and find its .log-group-expanded child — robust to the
// header row containing nested elements (badge span, second-line payload div)
// and to the click landing on any of them.
function toggleLogGroup(headerEl) {
    const group = headerEl.closest ? headerEl.closest('.log-group') : null;
    if (!group) return;
    const block = group.querySelector('.log-group-expanded');
    if (block) block.classList.toggle('hidden');
}

async function loadModuleLogs(module, isRefresh = false) {
    const container = document.getElementById('system-logs-container');
    if (!container) return;

    if (!isRefresh) {
        container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${module} logs...</div>`;
    }

    try {
        const endpoint = module === 'hub' ? '/setup/logs' : `/setup/logs/${module}`;
        const data = await apiJson(endpoint);
        // Reverse so newest entries are at the top (log files are oldest-first on disk)
        const logs = (data.logs || []).slice().reverse();

        if (logs.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No logs available for ${module}.</div>`;
            return;
        }

        if (module === 'agents' && !Array.isArray(logs)) {
            // Flatten every agent's lines so copyLogs emits all of them with
            // timestamps regardless of the per-agent collapse state below.
            container._rawLogs = Object.values(logs).flat();
            container.innerHTML = Object.entries(logs).map(([agentId, agentLogs]) => `
                <div class="mb-6">
                    <div class="px-4 py-2 bg-slate-100 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase tracking-widest flex justify-between">
                        <span>Agent: ${_spokeLabelFor(agentId)}</span>
                        <span class="opacity-60">Count: ${agentLogs.length}</span>
                    </div>
                    <div class="divide-y divide-slate-100">
                        ${_renderGroupedLogs(agentLogs)}
                    </div>
                </div>
            `).join('');
        } else {
            // Store the raw (timestamped) lines so copyLogs can emit every one
            // — the collapsed view's innerText only shows one row per group.
            container._rawLogs = logs;
            container.innerHTML = _renderGroupedLogs(logs);
        }

    } catch (err) {
        console.error(`Error loading ${module} logs:`, err);
        if (!isRefresh) {
            container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${module} logs: ${err.message}</div>`;
        }
    }
}

async function clearLogs(refreshFn) {
    // Destructive + fleet-wide: clears the hub's in-memory deque, every
    // relayed agent/spoke deque, the on-disk /var/log/lm/*.log files on the
    // hub box, AND broadcasts CLEAR_LOGS to every connected spoke so each
    // remote box truncates its own on-disk logs. Admin-only server-side.
    // After clearing, refresh the current tab (the loader passed in) so the
    // view empties immediately instead of showing the stale cached lines.
    if (!confirm('Clear ALL logs?\n\nThis wipes the hub logs, every agent/spoke log buffer, and the on-disk /var/log/lm/*.log files on the hub AND every connected spoke. This cannot be undone.')) {
        return;
    }
    try {
        const resp = await fetch('/setup/logs/clear', { method: 'POST' });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        const data = await resp.json().catch(() => ({}));
        const n = (data.disk_files_truncated || []).length;
        if (typeof showToast === 'function') {
            showToast(`Cleared logs: ${data.hub_lines || 0} hub + ${data.agent_lines || 0} agent/spoke lines, ${n} file(s) on disk, broadcast to ${data.spokes_broadcast || 0} spoke(s).`, 'success');
        }
        if (typeof refreshFn === 'function') refreshFn();
    } catch (err) {
        console.error('Clear logs failed:', err);
        if (typeof showToast === 'function') showToast('Failed to clear logs: ' + err.message, 'error');
    }
}

async function copyLogs() {
    const container = document.getElementById('system-logs-container');
    if (!container) return;

    // Copy EVERY raw log line with its timestamp — not the collapsed view's
    // innerText (which only shows one row per repeated group). The collapse is
    // a display concern; Copy emits the full trail so an incident paste has all
    // occurrences. Falls back to innerText for views that don't set _rawLogs.
    const raw = container._rawLogs;
    const text = Array.isArray(raw) ? raw.join('\n') : container.innerText;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {
                throw new Error('execCommand copy failed');
            }
            document.body.removeChild(textArea);
        }
        if (typeof showToast === 'function') showToast('Logs copied to clipboard.', 'success');
    } catch (err) {
        if (typeof showToast === 'function') showToast('Failed to copy logs: ' + err.message, 'error');
    }
}

async function toggleDebugLogging() {
    try {
        const statusData = await apiJson('/setup/debug-mode');
        const newState = !statusData.enabled;

        const response = await setupFetch('/setup/debug-mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: newState })
        });

        if (!response.ok) throw new Error('Failed to toggle debug mode');
        const data = await response.json();

        updateDebugButtonUI(data.enabled);
        showToast(`Debug logging has been ${data.enabled ? 'ENABLED' : 'DISABLED'} for all systems.`, 'success');
    } catch (err) {
        showToast('Error toggling debug mode: ' + err.message, 'error');
    }
}

function updateDebugButtonUI(enabled) {
    const btn = document.getElementById('debug-toggle-btn');
    const text = document.getElementById('debug-mode-text');
    if (!btn || !text) return;

    if (enabled) {
        btn.className = 'text-[10px] bg-[#01A982]/10 text-[#01A982] border border-[#01A982] px-2 py-1 rounded hover:bg-[#01A982]/20 transition-colors font-bold flex items-center gap-1';
        text.textContent = 'Debug Logging: ON';
    } else {
        btn.className = 'text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium flex items-center gap-1';
        text.textContent = 'Debug Logging: OFF';
    }
}

async function refreshDebugButtonState() {
    try {
        const response = await setupFetch('/setup/debug-mode');
        if (response.ok) {
            const data = await response.json();
            updateDebugButtonUI(data.enabled);
        }
    } catch (err) {
        console.error('Error refreshing debug button state:', err);
    }
}

async function loadApprovedSpokes() {
    try {
        // Global Admins read the full roster (/setup/pending_spokes, admin-only);
        // tenant-admins read only the spokes they may bind to via the
        // session-scoped /tenant/devices/spokes (same row shape).
        const data = await apiJson(isAdmin() ? '/setup/pending_spokes' : '/tenant/devices/spokes');
        (data.spokes || []).forEach(s => { if (typeof _spokeName === 'function') _spokeName(s); });
        return (data.spokes || []).filter(s => s.approved);
    } catch (err) {
        console.error('Error loading approved spokes:', err);
        return [];
    }
}

async function fetchAgentRoleState(spokeId) {
    // Fetch hosted roles plus durable deploy-role installation markers.
    // A tenant-admin (non-Global-Admin) can't reach /api/agent/* — use the
    // tenant-scoped, ownership-checked /tenant/agent/{id}/roles instead.
    try {
        const res = (typeof isAdmin === 'function' && isAdmin())
            ? await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'GET_AVAILABLE_ROLES' }),
              })
            : await fetch(`/tenant/agent/${encodeURIComponent(spokeId)}/roles`);
        if (!res.ok) return { active: [], installed_deploy_roles: [] };
        const data = await res.json();
        return {
            ...data,
            active: Array.isArray(data.active) ? data.active : [],
            installed_deploy_roles: Array.isArray(data.installed_deploy_roles)
                ? data.installed_deploy_roles : [],
        };
    } catch (e) { return { active: [], installed_deploy_roles: [] }; }
}

async function fetchLoadedRoles(spokeId) {
    return (await fetchAgentRoleState(spokeId)).active;
}

// Deploy-role status for a generic agent (netbox-server, ab). Returns
// { deploy, active_role, netbox_installed } or null. netbox_installed survives
// an agent reload, so it's the durable gate for the reset-admin-password knob.
async function fetchDeployStatus(spokeId) {
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'GET_DEPLOY_STATUS' }),
        });
        if (!res.ok) return null;
        return await res.json();
    } catch (e) { return null; }
}

// Dismiss a settled (completed/failed/error) deploy-role badge — e.g. the
// "NetBox Server: failed" badge that otherwise has no way to clear. Only
// forgets the in-memory status on the agent; does NOT touch the installed
// service, retry the deploy, or affect "installed_deploy_roles"/durable
// markers. Re-loading the role starts a fresh status regardless.
async function clearDeployStatus(spokeId, role) {
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'CLEAR_DEPLOY_STATUS', data: { role } }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.status !== 'SUCCESS') {
            showToast(data.message || data.detail || 'Clear failed', 'error');
            return;
        }
        loadSpokesAndAgents();
    } catch (e) { showToast(e.message, 'error'); }
}

// Prompt for a new NetBox admin password and reset it on the node that ran the
// netbox-server role (via the agent's NETBOX_RESET_ADMIN_PASSWORD command).
async function resetNetboxAdmin(spokeId) {
    const pw = await showPromptToast(
        `New NetBox admin password for ${_spokeLabelFor(spokeId)}:`,
        { type: 'password', placeholder: 'new admin password', confirmLabel: 'Reset' });
    if (pw === null) return;                 // cancelled
    if (!pw || pw.length < 4) { showToast('Password must be at least 4 characters.', 'error'); return; }
    showToast(`Resetting NetBox admin password on ${_spokeLabelFor(spokeId)}…`, 'info');
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'NETBOX_RESET_ADMIN_PASSWORD', data: { password: pw } }),
        });
        const data = await res.json();
        if (res.ok && data.status === 'SUCCESS') {
            showToast(data.message || 'NetBox admin password reset.', 'success');
        } else {
            showToast(`Reset failed: ${data.detail || data.message || JSON.stringify(data)}`, 'error');
        }
    } catch (err) {
        showToast(`Reset failed: ${err.message}`, 'error');
    }
}

async function showLoadRoleModal(spokeId) {
    if (!(window._spokeNameCache||{})[spokeId]) { try { await loadApprovedSpokes(); } catch (_e) { /* label is best-effort */ } }
    const existing = document.getElementById('load-role-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'load-role-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden border border-slate-200">
            <div class="px-6 py-4 bg-slate-50 border-b border-slate-200 flex justify-between items-center shrink-0">
                <div>
                    <h3 class="text-lg font-bold text-[#263040]">Load Role</h3>
                    <p class="text-xs text-slate-500 mt-0.5 font-mono">${_spokeLabelFor(spokeId)}</p>
                </div>
                <button onclick="document.getElementById('load-role-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4 overflow-y-auto">
                <p class="text-xs text-slate-500">An agent can host <strong>multiple roles at once</strong>. Each role opens its own sub-spoke (<code class="bg-slate-100 px-1 rounded">${spokeId}-&lt;role&gt;</code>) that auto-approves via this agent.</p>
                <div id="role-list" class="grid grid-cols-3 gap-2 max-h-44 overflow-y-auto pr-1">
                    <p class="text-xs text-slate-400 italic col-span-3">Loading roles…</p>
                </div>
                <div id="loaded-role-controls" class="hidden"></div>
                <div id="netbox-admin-creds" class="hidden p-3 bg-slate-50 border border-slate-200 rounded-md space-y-2">
                    <p class="text-xs font-semibold text-slate-700">NetBox admin account</p>
                    <div class="grid grid-cols-2 gap-2">
                        <input id="nb-admin-user" type="text" value="admin" placeholder="admin username" autocomplete="off"
                            class="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500">
                        <input id="nb-admin-pass" type="password" placeholder="admin password (blank = auto-generate)" autocomplete="new-password"
                            class="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <p class="text-[11px] text-slate-500">Sets the NetBox WebUI login. Leave blank to auto-generate (shown in the deploy log).</p>
                </div>
                <div id="ldap-server-cfg" class="hidden p-3 bg-slate-50 border border-slate-200 rounded-md">
                    <p class="text-xs text-slate-600">No settings needed here. This server joins the directory set in <strong>Setup → Directory (LDAP)</strong>: it gets that domain and admin account, and replication with the other LDAP servers is set up automatically. If the directory isn't set up yet, the server installs on its own; Apply in Setup → Directory then includes it.</p>
                </div>
                <div id="console-dpa-cfg" class="hidden p-3 bg-slate-50 border border-slate-200 rounded-md space-y-2">
                    <label class="flex items-center gap-2 text-xs font-semibold text-slate-700">
                        <input type="checkbox" id="crole-dpa-enabled" class="rounded border-slate-300" onchange="syncNetboxCreds()" title="Turn on per-port telnet listeners for this console role. Off by default; when enabled the DPA endpoint appears in the Console port list."> Enable Direct Port Access (telnet terminal server)
                    </label>
                    <p class="text-[11px] text-slate-500">Exposes each detected serial port over a per-port telnet listener (auto-assigned from 2200) so you can attach a terminal straight to the line. The endpoint then shows in the Console port list. <strong>Off by default</strong>; telnet is unauthenticated/unencrypted, so it binds localhost unless you widen it.</p>
                    <div id="crole-dpa-detail" class="hidden grid grid-cols-2 gap-2">
                        <input id="crole-dpa-bind" type="text" value="127.0.0.1" placeholder="bind address (127.0.0.1 = localhost only)" autocomplete="off" oninput="syncNetboxCreds()" title="Address the telnet listeners bind to. Keep 127.0.0.1 (localhost) so the port is only reachable via an SSH tunnel; widen it only with an allow-list set." class="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500">
                        <input id="crole-dpa-allow" type="text" placeholder="source-IP allow-list, comma-separated (required if not localhost)" autocomplete="off" title="Comma-separated source IPs/CIDRs allowed to connect. Required when the bind address is not localhost, since telnet is unauthenticated." class="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500">
                        <p id="crole-dpa-warn" class="hidden col-span-2 text-[11px] text-amber-700 font-semibold">⚠ Binding beyond 127.0.0.1 exposes an unauthenticated, unencrypted telnet console on the network. Set a source-IP allow-list, and prefer SSH-tunnelling to localhost instead.</p>
                    </div>
                </div>
                <p id="role-desc" class="text-xs text-slate-500 italic min-h-[1.5rem]"></p>
                <div id="role-note" class="p-3 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-800">
                    The agent installs required system packages (e.g. unbound, kea, certbot) and hosts the role as a new sub-spoke. This may take 30–60 seconds per role.
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 shrink-0">
                <button onclick="document.getElementById('load-role-modal').remove()"
                    class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="loadRole('${spokeId}')"
                    class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Activate Selected</button>
            </div>
        </div>`;
    document.body.appendChild(modal);

    const roleState = await fetchAgentRoleState(spokeId);
    const active = roleState.active;
    const loadedRoleIds = new Set((active || []).map(a => a.role));
    const activeDeployRoleIds = new Set(roleState.active_deploy_roles || []);
    if (roleState.deploy?.state === 'running' && roleState.deploy?.role) {
        activeDeployRoleIds.add(roleState.deploy.role);
    }
    const list = document.getElementById('role-list');
    const availableRoles = Object.entries(AGENT_ROLES)
        .filter(([id]) => !loadedRoleIds.has(id) && !activeDeployRoleIds.has(id));
    const rows = availableRoles.map(([id, r]) => {
        const deployNote = r.deploy ? ' (background deploy — own service)' : '';
        const clash = roleListenerConflict([...loadedRoleIds], id);
        if (clash) {
            return `
                <label class="flex items-start gap-2 p-2 rounded-md border border-slate-200 bg-slate-50 cursor-not-allowed opacity-70" title="${escapeHtml(roleListenerConflictText(id, clash))}">
                    <input type="checkbox" value="${id}" disabled class="w-4 h-4 rounded mt-0.5 shrink-0">
                    <span class="min-w-0">
                        <span class="text-sm text-slate-500 font-medium">${r.name}</span>
                        <span class="block text-[11px] text-amber-700 mt-0.5">${escapeHtml(roleListenerConflictText(id, clash))}</span>
                    </span>
                </label>`;
        }
        return `
            <label class="flex items-center gap-2 p-2 rounded-md border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer" onfocus="updateRoleDesc('${id}')" onmouseover="updateRoleDesc('${id}')">
                <input type="checkbox" value="${id}" class="role-check w-4 h-4 rounded text-[#01A982] focus:ring-green-500" onchange="updateRoleDesc('${id}')">
                <span class="text-sm text-slate-700 font-medium">${r.name}${deployNote}</span>
            </label>`;
    }).join('');
    list.innerHTML = rows || '<p class="text-xs text-slate-400 italic col-span-3">All available roles are already loaded.</p>';
    const loadedControls = document.getElementById('loaded-role-controls');
    // Deploy roles that own a background service (stop = Unload, purge = Uninstall).
    const SERVICE_DEPLOY_ROLES = ['dns-server', 'dhcp-server', 'zabbix-server', 'zbxproxy', 'zbxagent'];
    const stoppableServers = [...activeDeployRoleIds]
        .filter(id => SERVICE_DEPLOY_ROLES.includes(id)
            && !(roleState.deploy?.state === 'running' && roleState.deploy?.role === id));
    // Servers whose package is still on disk. A role that was unloaded is
    // STOPPED but still installed, so it drops out of activeDeployRoleIds and
    // used to render no control at all — leaving "installed (stopped)" on the
    // node with no way to remove it from the UI. Uninstall is offered for these
    // too, which is the only action that clears the installed marker.
    const installedDeployRoleIds = new Set(roleState.installed_deploy_roles || []);
    const uninstallableServers = [...installedDeployRoleIds]
        .filter(id => SERVICE_DEPLOY_ROLES.includes(id)
            && !(roleState.deploy?.state === 'running' && roleState.deploy?.role === id));
    const loadedControlIds = [...new Set([
        ...(active || []).map(item => item.role),
        ...stoppableServers,
        ...uninstallableServers,
    ])];
    if (loadedControls && loadedControlIds.length) {
        loadedControls.classList.remove('hidden');
        loadedControls.innerHTML = `
            <p class="text-xs font-semibold text-slate-600 mb-2">Loaded roles and server services</p>
            <div class="flex flex-wrap gap-2">${loadedControlIds.map(id => {
                const isServer = SERVICE_DEPLOY_ROLES.includes(id);
                const moduleLoaded = isServer && loadedRoleIds.has(id.replace(/-server$/, ''));
                const running = activeDeployRoleIds.has(id);
                const installed = installedDeployRoleIds.has(id);
                const stateNote = (isServer && installed && !running)
                    ? ' <span class="text-[10px] text-slate-500">(stopped)</span>' : '';
                return `
                <div class="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2">
                    <span class="text-sm font-medium text-slate-700">${escapeHtml(AGENT_ROLES[id]?.name || id)}${stateNote}</span>
                    ${(!isServer || running) ? `<button onclick="unloadRole('${spokeId}','${id}')"
                        ${moduleLoaded ? 'disabled title="Unload the management module first"' : ''}
                        class="text-xs font-bold text-red-600 hover:text-red-700 disabled:text-slate-400 disabled:cursor-not-allowed">Unload</button>` : ''}
                    ${(isServer && installed) ? `<button onclick="uninstallRole('${spokeId}','${id}',${moduleLoaded ? `'${id.replace(/-server$/, '')}'` : 'null'})"
                        ${moduleLoaded ? 'title="Also unloads the management module, which is using this server"' : ''}
                        class="text-xs font-bold text-red-700 hover:text-red-800 underline">Uninstall</button>` : ''}
                </div>`;
            }).join('')}</div>`;
    }
    const activateButton = modal.querySelector('button[onclick^="loadRole"]');
    if (activateButton && availableRoles.length === 0) {
        activateButton.disabled = true;
        activateButton.classList.add('opacity-50', 'cursor-not-allowed');
    }
}

// Show the NetBox admin-account inputs only while the netbox-server role is
// checked — the deploy passes them through to install.sh as the admin login.
function syncNetboxCreds() {
    const cb = document.querySelector('.role-check[value="netbox-server"]');
    const creds = document.getElementById('netbox-admin-creds');
    if (creds) creds.classList.toggle('hidden', !(cb && cb.checked));
    const lcb = document.querySelector('.role-check[value="ldap-server"]');
    const lcfg = document.getElementById('ldap-server-cfg');
    if (lcfg) lcfg.classList.toggle('hidden', !(lcb && lcb.checked));
    // Console role → reveal the optional Direct Port Access (DPA) config, and
    // reveal the bind/allow-list detail (with a network-exposure warning) only
    // once DPA itself is enabled.
    const ccb = document.querySelector('.role-check[value="console"]');
    const ccfg = document.getElementById('console-dpa-cfg');
    if (ccfg) ccfg.classList.toggle('hidden', !(ccb && ccb.checked));
    const dpaOn = document.getElementById('crole-dpa-enabled');
    const dpaDetail = document.getElementById('crole-dpa-detail');
    if (dpaDetail) dpaDetail.classList.toggle('hidden', !(dpaOn && dpaOn.checked));
    const dpaBind = document.getElementById('crole-dpa-bind');
    const dpaWarn = document.getElementById('crole-dpa-warn');
    if (dpaWarn) dpaWarn.classList.toggle('hidden', !(dpaBind && dpaBind.value.trim() && dpaBind.value.trim() !== '127.0.0.1'));
}

// Two roles that bind the same host port can't be selected together either.
// Once one is checked, grey out its rivals so the combination is unreachable
// rather than failing later with a 409 from the hub.
function syncListenerConflicts() {
    const boxes = Array.from(document.querySelectorAll('.role-check'));
    const checked = boxes.filter(b => b.checked).map(b => b.value);
    boxes.forEach(b => {
        if (b.checked) return;
        const clash = roleListenerConflict(checked, b.value);
        b.disabled = !!clash;
        const label = b.closest('label');
        if (!label) return;
        label.classList.toggle('opacity-50', !!clash);
        label.classList.toggle('cursor-not-allowed', !!clash);
        label.title = clash ? roleListenerConflictText(b.value, clash) : '';
    });
}

function updateRoleDesc(roleId) {
    syncNetboxCreds();
    syncListenerConflicts();
    const r = AGENT_ROLES[roleId];
    const desc = document.getElementById('role-desc');
    if (desc) desc.textContent = r?.desc || '';
    const note = document.getElementById('role-note');
    if (note) {
        if (r?.deploy) {
            note.innerHTML = `The agent runs the role's install script in the background and stays online as an agent. The deployed service installs as a systemd unit and connects to the Hub as its own agent. This can take a few minutes; watch <strong>Setup → Spokes & Agents</strong> for the new agent to appear.`;
        } else {
            note.textContent = `The agent installs required system packages (e.g. unbound, kea, certbot) and hosts the role as a new sub-spoke, auto-approved via this agent. This may take 30–60 seconds; the new spoke appears in Spokes & Agents as Connected.`;
        }
    }
}

async function loadRole(spokeId) {
    const checked = Array.from(document.querySelectorAll('.role-check:checked')).map(el => el.value);
    if (checked.length === 0) { showToast('Select at least one role to load.', 'info'); return; }
    for (let i = 0; i < checked.length; i++) {
        const clash = roleListenerConflict(checked.slice(0, i), checked[i]);
        if (clash) {
            showToast(roleListenerConflictText(checked[i], clash), 'error');
            return;
        }
    }

    const btn = document.querySelector('#load-role-modal button[onclick^="loadRole"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Activating…'; }

    // Collect the NetBox admin account (if the netbox-server role is selected)
    // BEFORE the loop removes the modal; passed as LOAD_ROLE config → install.sh.
    let netboxCfg = null;
    if (checked.includes('netbox-server')) {
        const u = document.getElementById('nb-admin-user')?.value.trim();
        const p = document.getElementById('nb-admin-pass')?.value;
        netboxCfg = {};
        if (u) netboxCfg.admin_user = u;
        if (p) netboxCfg.admin_password = p;
    }

    // ldap-server: the hub fills in the whole config from Setup → Directory
    // (core/src/ldap_cluster.py join_config), so the modal sends nothing.
    const ldapSrvCfg = checked.includes('ldap-server') ? {} : null;

    // console role: optional Direct Port Access (DPA). Off by default; only sent
    // when the operator ticks it. Bind stays 127.0.0.1 unless widened, and a
    // widened bind carries the source-IP allow-list.
    let consoleCfg = null;
    if (checked.includes('console') && document.getElementById('crole-dpa-enabled')?.checked) {
        consoleCfg = { console_dpa_enabled: true };
        const bind = document.getElementById('crole-dpa-bind')?.value.trim();
        if (bind) consoleCfg.console_dpa_bind = bind;
        const allow = (document.getElementById('crole-dpa-allow')?.value || '')
            .split(',').map(s => s.trim()).filter(Boolean);
        if (allow.length) consoleCfg.console_dpa_allow = allow;
    }

    // One batched request — the backend loads the roles SEQUENTIALLY on the agent
    // (each is a git clone + package install, can't run concurrently) and returns
    // a per-role results[]. Replaces the old one-POST-per-role loop.
    const rolesPayload = checked.map(roleId => {
        const r = { role: roleId };
        if (roleId === 'netbox-server' && netboxCfg && Object.keys(netboxCfg).length) r.config = netboxCfg;
        if (roleId === 'ldap-server' && ldapSrvCfg) r.config = ldapSrvCfg;
        if (roleId === 'console' && consoleCfg) r.config = consoleCfg;
        return r;
    });
    const results = [];
    try {
        const _admin = (typeof isAdmin === 'function') && isAdmin();
        const res = await fetch(_admin
                ? `/api/agent/${encodeURIComponent(spokeId)}/load-role`
                : `/tenant/agent/${encodeURIComponent(spokeId)}/load-role`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ roles: rolesPayload }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && Array.isArray(data.results)) {
            for (const item of data.results) {
                const roleId = item.role;
                const name = AGENT_ROLES[roleId]?.name || roleId || '?';
                if (item.status === 'SUCCESS') {
                    if (item.deploy) {
                        results.push(`✓ ${name}: deployment started (watch Spokes & Agents)`);
                    } else {
                        results.push(`✓ ${name}: sub-spoke ${item.sub_spoke_id || spokeId + '-' + roleId} connecting (auto-approved)`);
                    }
                } else {
                    results.push(`✗ ${name}: ${item.message || item.detail || 'failed'}`);
                }
            }
        } else {
            const msg = res.status === 503
                ? 'agent not connected — reconnect it to manage roles'
                : (data.detail || data.message || JSON.stringify(data));
            results.push(`✗ ${msg}`);
        }
    } catch (err) {
        results.push(`✗ ${err.message}`);
    }
    document.getElementById('load-role-modal')?.remove();
    const anyFailed = results.some(r => r.startsWith('✗'));
    showToast(`Role activation on ${_spokeLabelFor(spokeId)}:\n${results.join('\n')}`, anyFailed ? 'error' : 'success');
    // Refresh whichever view is showing this spoke: the Global-Admin Spokes &
    // Agents table (Active Role column) or a tenant-admin's My Devices list.
    if (currentView === 'setup') loadSpokesAndAgents();
    if (typeof loadMyDeviceSpokes === 'function' && document.getElementById('my-spokes-list')) loadMyDeviceSpokes();
}

async function uninstallRole(spokeId, role, blockingModule) {
    if (!(window._spokeNameCache||{})[spokeId]) { try { await loadApprovedSpokes(); } catch (_e) { /* label is best-effort */ } }
    const roleLabel = AGENT_ROLES[role]?.name || role;
    // The agent refuses to purge a server while its management sub-spoke is
    // still loaded (that would leave both in an undefined state). That guard
    // used to surface as a greyed-out button with only a tooltip, which is a
    // dead end: the operator can see the action but can never reach it. Offer
    // the chain instead — unload the module first, then uninstall.
    const moduleLabel = blockingModule
        ? (AGENT_ROLES[blockingModule]?.name || blockingModule) : '';
    const preamble = blockingModule
        ? `"${roleLabel}" is still being managed by the "${moduleLabel}" role, which has to be `
          + `unloaded first.\n\nUnload "${moduleLabel}" AND uninstall "${roleLabel}" from ${_spokeLabelFor(spokeId)}? `
        : `Uninstall "${roleLabel}" from ${_spokeLabelFor(spokeId)}? `;
    if (!await showConfirmToast(
        preamble + `The service will be stopped and its ` +
        `packages, configuration and data will be PERMANENTLY REMOVED from the host. ` +
        `This cannot be undone — re-adding the role means a fresh deploy.`)) return;
    const modalOpen = !!document.getElementById('load-role-modal');
    const _admin = (typeof isAdmin === 'function') && isAdmin();
    const _post = (path, body) => fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    const _refresh = () => {
        if (currentView === 'setup') loadSpokesAndAgents();
        if (typeof loadMyDeviceSpokes === 'function' && document.getElementById('my-spokes-list')) loadMyDeviceSpokes();
        if (modalOpen) showLoadRoleModal(spokeId);
    };
    try {
        if (blockingModule) {
            // Abort the whole operation if the unload fails — going ahead would
            // only hit the agent-side guard and would have unloaded the module
            // for nothing.
            showToast(`Unloading "${moduleLabel}" from ${_spokeLabelFor(spokeId)}...`, 'info');
            const ures = _admin
                ? await _post(`/api/agent/${encodeURIComponent(spokeId)}/command`,
                    { command: 'UNLOAD_ROLE', data: { role: blockingModule } })
                : await _post(`/tenant/agent/${encodeURIComponent(spokeId)}/unload-role`,
                    { role: blockingModule });
            const udata = await ures.json();
            const upayload = udata.payload?.data || udata.payload || udata;
            if (!(ures.ok && (udata.status === 'SUCCESS' || upayload?.status === 'SUCCESS'))) {
                showToast(`Could not unload "${moduleLabel}", so "${roleLabel}" was left installed: `
                    + (upayload?.message || udata.detail || udata.message || JSON.stringify(udata)), 'error');
                _refresh();
                return;
            }
        }
        showToast(`Uninstalling "${roleLabel}" from ${_spokeLabelFor(spokeId)} - this can take a few minutes...`, 'info');
        // Global Admin uses the arbitrary-command relay; a tenant-admin uses the
        // ownership-checked, role-only route.
        const res = _admin
            ? await _post(`/api/agent/${encodeURIComponent(spokeId)}/command`,
                { command: 'UNINSTALL_ROLE', data: { role } })
            : await _post(`/tenant/agent/${encodeURIComponent(spokeId)}/uninstall-role`,
                { role });
        const data = await res.json();
        const payload = data.payload?.data || data.payload || data;
        if (res.ok && (data.status === 'SUCCESS' || payload?.status === 'SUCCESS')) {
            showToast(payload?.message || `"${roleLabel}" uninstalled from ${_spokeLabelFor(spokeId)}`, 'success');
            _refresh();
        } else {
            const msg = res.status === 503
                ? `${_spokeLabelFor(spokeId)} is not connected — reconnect the agent to manage its roles.`
                : (payload?.message || data.detail || data.message || JSON.stringify(data));
            showToast('Failed to uninstall role: ' + msg, 'error');
            _refresh();
        }
    } catch (err) {
        showToast('Error uninstalling role: ' + err.message, 'error');
    }
}

async function unloadRole(spokeId, role) {
    if (!(window._spokeNameCache||{})[spokeId]) { try { await loadApprovedSpokes(); } catch (_e) { /* label is best-effort */ } }
    const roleLabel = AGENT_ROLES[role]?.name || role;
    const impact = AGENT_ROLES[role]?.deploy
        ? 'The server service will be stopped and disabled, but its package and configuration will remain installed.'
        : 'Its sub-spoke will disconnect.';
    if (!await showConfirmToast(`Unload role "${roleLabel}" from ${_spokeLabelFor(spokeId)}? ${impact}`)) return;
    // Only reopen the Load Role modal if the unload was triggered from inside it
    // (not from the per-role Unload action on a Spokes row).
    const modalOpen = !!document.getElementById('load-role-modal');
    try {
        const _admin = (typeof isAdmin === 'function') && isAdmin();
        // Global Admin uses the arbitrary-command relay; a tenant-admin uses the
        // ownership-checked, role-only /tenant/agent/{id}/unload-role.
        const res = _admin
            ? await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'UNLOAD_ROLE', data: { role } }),
              })
            : await fetch(`/tenant/agent/${encodeURIComponent(spokeId)}/unload-role`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role }),
              });
        const data = await res.json();
        if (res.ok && (data.status === 'SUCCESS' || data.payload?.status === 'SUCCESS')) {
            showToast(`Role "${roleLabel}" unloaded from ${_spokeLabelFor(spokeId)}`, 'success');
            if (currentView === 'setup') loadSpokesAndAgents();
            if (typeof loadMyDeviceSpokes === 'function' && document.getElementById('my-spokes-list')) loadMyDeviceSpokes();
            if (modalOpen) showLoadRoleModal(spokeId);
        } else {
            const msg = res.status === 503
                ? `${_spokeLabelFor(spokeId)} is not connected — reconnect the agent to manage its roles.`
                : (data.detail || data.message || JSON.stringify(data));
            showToast('Failed to unload role: ' + msg, 'error');
        }
    } catch (err) {
        showToast('Error unloading role: ' + err.message, 'error');
    }
}







async function loadOpnsenseManagement() {
    const container = document.getElementById('opn-table-container');
    if (!container) return;

    const subMenu = currentSubView;
    if (subMenu === 'Configuration' || subMenu === 'config') return;

    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${subMenu} data…</div>`;

    const firewalls = await _ensureFirewalls();
    if (firewalls.length === 0) {
        const _actions = document.getElementById('top-nav-actions');
        if (_actions) _actions.innerHTML = '';
        container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No firewalls configured. Add one in Setup → Firewalls.</div>`;
        return;
    }

    // Show/hide the "+ Add" button based on writable sub-views. It lives in the
    // menu strip (far-right #top-nav-actions) rather than the page body. The
    // target firewall is resolved inside the modal (auto-select when only one is
    // configured, a picker otherwise).
    const writable = ['Firewall Rules', 'NAT Policies', 'DNS Records', 'Aliases', 'Impairment'];
    const actions = document.getElementById('top-nav-actions');
    if (actions) {
        if (writable.includes(subMenu) && canEdit()) {
            actions.innerHTML = `<button onclick="showOpnsenseAddModal('${subMenu}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm" title="Create a new ${subMenu.replace(/s$/, '')} on the firewall">+ Add ${subMenu.replace(/s$/, '')}</button>`;
        } else {
            actions.innerHTML = '';
        }
    }

    try {
        // Map the active sub-view to the per-firewall endpoint suffix.
        const suffixFor = sm => {
            if (sm === 'Firewall Rules') return 'rules';
            if (sm === 'DHCP Leases') return 'dhcp';
            if (sm === 'Interfaces') return 'interfaces';
            if (sm === 'NAT Policies') return 'nat';
            if (sm === 'DNS Records') return 'dns';
            if (sm === 'Aliases') return 'aliases';
            if (sm === 'Impairment') return 'impair';
            return null;
        };
        const suffix = suffixFor(subMenu);
        if (!suffix) return;

        // Pull from every configured firewall in parallel and merge into one
        // table, tagging each row with its source firewall (_fwId / firewall).
        // ?tenant=currentTenant scopes the server-side subnet filter to the
        // selected tenant — including for admins (via the switcher), who
        // otherwise bypass the filter. Applies to every tab (rules/nat/dns/
        // interfaces/dhcp/aliases); aliases filter on their content IPs.
        const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
        const results = await Promise.allSettled(firewalls.map(fw =>
            fetch(`/api/firewall/${fw.id}/${suffix}${tenantQs}`)
                .then(r => r.ok ? r.json()
                    // Non-OK: read the FastAPI error body so we can show *why*
                    // (e.g. "OPNsense NAT API returned errors … < 26.1") instead
                    // of a generic "unreachable" count.
                    : r.json().catch(() => ({})).then(body => Promise.reject(
                        new Error(body.detail || `${r.status} ${r.statusText}`))))
                .then(data => ({ fw, data }))
        ));
        const extractItems = data => {
            if (Array.isArray(data)) return data;
            if (data && typeof data === 'object') {
                if (Array.isArray(data.data)) return data.data;
                if (Array.isArray(data.payload?.data)) return data.payload.data;
                if (data.rows && Array.isArray(data.rows)) return data.rows;
            }
            return [];
        };
        let items = [];
        const errors = [];
        results.forEach(res => {
            if (res.status === 'fulfilled') {
                const fwItems = extractItems(res.value.data).map(it => ({
                    ...it, _fwId: res.value.fw.id, firewall: res.value.fw.name || res.value.fw.id
                }));
                items = items.concat(fwItems);
            } else {
                errors.push(String((res.reason && res.reason.message) || res.reason));
            }
        });

        if (items.length === 0) {
            if (subMenu === 'Impairment' && !errors.length) {
                container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No impairments. Use "+ Add Impairment" to add latency or packet loss for a host or subnet (needs the os-netimpair plugin on the firewall).</div>`;
                return;
            }
            // Distinguish "legitimately empty" from "the spoke returned an error"
            // — the latter carries a real reason (version/permissions) the user
            // needs to see, not a bare "No <things> found."
            const errNote = errors.length
                ? `<div class="text-xs text-amber-600 mt-2 max-w-2xl mx-auto">${errors.length} firewall(s) reported an error: ${escapeHtml(errors[0])}</div>`
                : '';
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${subMenu} found.${errNote}</div>`;
            return;
        }

        let keys;
        if (subMenu === 'Firewall Rules') keys = ['firewall', 'source', 'destination', 'protocol', 'action', 'description'];
        else if (subMenu === 'Interfaces') keys = ['firewall', 'description', 'ip', 'status', 'macaddr', 'mtu', 'media'];
        else if (subMenu === 'NAT Policies') keys = ['firewall', 'type', 'protocol', 'source', 'external_ip', 'external_port', 'internal_ip', 'internal_port', 'description'];
        else if (subMenu === 'DNS Records') keys = ['firewall', 'hostname', 'ip', 'type', 'ttl', 'description'];
        else if (subMenu === 'Aliases') keys = ['firewall', 'name', 'type', 'content', 'category', 'description'];
        else if (subMenu === 'Impairment') {
            keys = ['firewall', 'target', 'interface', 'direction', 'latency', 'packet_loss', 'state', 'description'];
            items.forEach(it => {
                it.latency = `${it.delay} ms`;
                it.packet_loss = `${it.loss} %`;
                it.state = !it.complete ? 'incomplete' : (it.enabled ? 'active' : 'disabled');
            });
        }
        else keys = ['firewall', ...Object.keys(items[0] || {}).filter(k => k !== 'id' && !k.toLowerCase().includes('hit') && k !== 'firewall' && !k.startsWith('_'))];

        const hiddenRules = JSON.parse(localStorage.getItem('lm_hidden_firewall_rules') || '[]');
        let filteredItems = items;
        if (subMenu === 'Firewall Rules') {
            // Subnet filtering for rules is enforced server-side
            // (_filter_fw → filter_firewall_rules, with OPNsense alias
            // expansion) so the tenant already receives only their in-prefix
            // rules. The client-side firewallRuleInTenantPrefixes can't resolve
            // alias/interface names and would wrongly hide rules the server
            // showed, so it is intentionally NOT applied here — only the
            // per-rule hide-toggle (localStorage) filter remains. Admins see all
            // (server no-op for admins).
            filteredItems = items.filter(item => {
                const rawId = item.id || JSON.stringify(item);
                const ruleId = `${item._fwId}:${rawId}`;   // firewall-scoped (hide checkbox + localStorage)
                return showHiddenOnlyFirewallRules ? hiddenRules.includes(ruleId) : !hiddenRules.includes(ruleId);
            });
        } else if (subMenu === 'NAT Policies') {
            // Subnet filtering for NAT is enforced server-side (_filter_fw →
            // filter_items_by_prefixes over source/internal_ip/external_ip, plus
            // the OPNsense category attribution) so the tenant already receives
            // only their NAT policies. The client-side itemInTenantPrefixes has
            // no category awareness and would hide category-attributed policies
            // the server showed, so it is intentionally NOT applied here (mirrors
            // the Firewall Rules path). Admins see all (server no-op for admins).
            filteredItems = items;
        } else if (subMenu === 'DHCP Leases') {
            filteredItems = items.filter(item => itemInTenantPrefixes(item, ['ip', 'address']));
        } else if (subMenu === 'DNS Records') {
            filteredItems = items.filter(item => itemInTenantPrefixes(item, ['ip', 'value']));
        } else if (subMenu === 'Interfaces') {
            filteredItems = items.filter(item => itemInTenantPrefixes(item, ['ip', 'ipaddr']));
        }

        const showDelete = writable.includes(subMenu);
        const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
        const hideHeader = subMenu === 'Firewall Rules' ? '<th class="px-4 py-3 text-center">Hide</th>' : '';
        const delHeader = showDelete ? '<th class="px-4 py-3"></th>' : '';

        _opnCurrentItems = {};
        const rows = filteredItems.map((item, idx) => {
            const rawId = item.id || item.uuid || JSON.stringify(item);
            const ruleId = `${item._fwId}:${rawId}`;   // firewall-scoped (hide checkbox + localStorage)
            _opnCurrentItems[idx] = item;
            const cells = keys.map(k => {
                const val = item[k] !== undefined ? String(item[k]) : '-';
                const eVal = escapeHtml(val);  // OPNsense-editable (alias/rule/NAT names + descriptions) → escape
                if (k === 'action' && typeof item[k] === 'string') {
                    const color = item[k] === 'pass' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600';
                    return `<td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${color}">${eVal}</span></td>`;
                }
                if (k === 'status') {
                    const color = val === 'up' ? 'text-green-600' : 'text-slate-400';
                    return `<td class="px-4 py-3 font-mono text-xs ${color}">${eVal}</td>`;
                }
                if (k === 'firewall') {
                    return `<td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${eVal}</td>`;
                }
                return `<td class="px-4 py-3 text-slate-600 font-mono text-xs max-w-[200px] truncate" title="${eVal}">${eVal}</td>`;
            }).join('');

            const hideCell = subMenu === 'Firewall Rules' ? `
                <td class="px-4 py-3 text-center"><label class="flex items-center justify-center cursor-pointer">
                    <input type="checkbox" data-rule-id="${ruleId.replace(/"/g,'&quot;')}" onchange="toggleFirewallRuleVisibility(this.dataset.ruleId,this.checked)" ${hiddenRules.includes(ruleId)?'checked':''} class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                </label></td>` : '';

            const delCell = showDelete ? `
                <td class="px-4 py-3 text-right">
                    <div class="flex items-center justify-end gap-1">
                        <button onclick="showOpnsenseEditModal('${item._fwId}','${subMenu}',${idx})" class="p-1 text-slate-400 hover:text-blue-600 transition-colors" title="Edit ${subMenu.replace(/s$/, '')}">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
                        </button>
                        <button onclick="deleteOpnsenseItem('${item._fwId}','${subMenu}','${escJsAttr(rawId)}')" class="p-1 text-slate-400 hover:text-red-600 transition-colors" title="Delete ${subMenu.replace(/s$/, '')}">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        </button>
                    </div>
                </td>` : '';

            return `<tr class="hover:bg-slate-50 transition-colors">${cells}${hideCell}${delCell}</tr>`;
        }).join('');

        let footerHtml = '';
        if (subMenu === 'Firewall Rules' && hiddenRules.length > 0) {
            footerHtml = `<div class="pt-3 flex items-center gap-4">
                <span class="text-xs text-slate-400">${hiddenRules.length} rules manually hidden</span>
                <button onclick="toggleHiddenFirewallRules()" class="text-xs font-medium text-blue-600 hover:text-blue-800" title="Toggle visibility of hidden firewall rules">${showHiddenOnlyFirewallRules ? 'Show All' : 'View Hidden'}</button>
                <button onclick="unhideAllFirewallRules()" class="text-xs font-medium text-blue-600 hover:text-blue-800" title="Reset and unhide all hidden firewall rules">Unhide All</button>
            </div>`;
        }

        const moduleKey = subMenu === 'Firewall Rules' ? 'rules' : subMenu === 'NAT Policies' ? 'nat'
            : subMenu === 'DHCP Leases' ? 'dhcp' : subMenu === 'DNS Records' ? 'dns' : 'interfaces';
        const refreshBtn = !isAdmin() ? `<button onclick="refreshModuleCache('${moduleKey}').then(()=>loadOpnsenseManagement())"
            class="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1" title="Refresh ${subMenu} from firewall cache">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
            Refresh</button>` : '';

        const errBanner = errors.length ? `<div class="text-xs text-amber-600">${errors.length} of ${firewalls.length} firewall(s) unreachable.</div>` : '';
        container.innerHTML = `
            <div class="space-y-4">
                ${refreshBtn ? `<div class="flex justify-end">${refreshBtn}</div>` : ''}
                ${errBanner}
                <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}${hideHeader}${delHeader}</tr></thead>
                        <tbody class="divide-y divide-slate-200">${rows}</tbody>
                    </table>
                </div>
                ${footerHtml}
            </div>`;
    } catch (err) {
        console.error(`[OPNsense] Error in loadOpnsenseManagement:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${subMenu}: ${err.message}</div>`;
    }
}
