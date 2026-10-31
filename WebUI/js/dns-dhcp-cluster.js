// dns-dhcp-cluster.js — DNS (Unbound), clustered DNS / HA DHCP panels, cluster topology editor.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── DNS (Unbound) ───────────────────────────────────────────────────────────

// _spokeFetch — shared fetch helper for the DNS/DHCP spoke-relay endpoints.
// The hub relay (`_relay_spoke` in api.py) now translates a spoke-side ERROR
// into HTTP 502 with {detail} (was: 200 + {status:'ERROR',message}), matching
// the rest of the API error contract. Success bodies are the spoke's
// {status:'SUCCESS', ...} payload, unchanged. Returns {ok, status, data,
// detail}: on success data is the parsed body; on failure data is null and
// detail carries the spoke's message (or the HTTP status text). Consolidates
// the 8 near-identical `r.ok ? r.json() : {}` / `if (d.status === 'ERROR')`
// blocks across the DNS + DHCP consumers — and fixes the prior UX gap where a
// 503 (spoke down) rendered as "No records found" instead of the real message.
async function _spokeFetch(url, opts) {
    const r = await fetch(url, opts);
    if (r.ok) {
        // `.catch` only fires on a PARSE failure, but a body of the literal
        // JSON token `null` parses perfectly well and yields null — so it slid
        // through as {ok:true, data:null} and the first field access in every
        // consumer threw "null is not an object (evaluating 'd.status')"
        // instead of rendering the amber banner. Coerce any non-object success
        // body to {} so callers keep the envelope contract they expect; the
        // hub now also refuses to emit a null body (_spoke_payload_or_raise),
        // this is the belt-and-braces half.
        const body = await r.json().catch(() => null);
        return { ok: true, status: r.status,
                 data: (body && typeof body === 'object') ? body : {}, detail: null };
    }
    const e = await r.json().catch(() => ({}));
    return { ok: false, status: r.status, data: null, detail: e.detail || e.message || r.statusText };
}

// Amber error banner used by the DNS/DHCP list views on a spoke failure.
// The exact detail string the hub raises (api._spoke_payload_or_raise →
// SPOKE_UPDATING_DETAIL) when a relay target is mid self-update. Keep in
// lockstep with the Python constant.
const SPOKE_UPDATING_DETAIL = 'Update in progress — please wait';

// True when a spoke relay failed only because the target is restarting on new
// code (not a real fault). Callers use it to render a neutral notice and to
// drop remediation hints that would be a false lead during an update.
function _isSpokeUpdating(detail) {
    return detail === SPOKE_UPDATING_DETAIL;
}

// Amber error banner used by the DNS/DHCP list views on a spoke failure. A
// mid-update target is NOT a failure — the spoke is briefly restarting on new
// code — so it renders as a neutral blue "update in progress" notice rather
// than a red error, so a routine update no longer reads as a broken spoke.
function _spokeErrorBanner(detail, fallback) {
    if (_isSpokeUpdating(detail)) {
        return `<p class="p-4 text-blue-600 text-sm font-medium">⏳ ${escapeHtml(SPOKE_UPDATING_DETAIL)} — this node is restarting on new code and will respond again shortly.</p>`;
    }
    return `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${escapeHtml(detail || fallback)}</p>`;
}

// Admin combined DHCP view: the hub fans the list out to EVERY dhcp spoke and
// merges. A spoke whose Kea is unreachable used to be dropped silently, so a
// DOWN cluster looked exactly like an EMPTY one — "DHCP shows no reservations"
// with nothing to explain it. _dhcp_merge_fanout now reports the casualties in
// `_degraded`; surface them above the table so the missing cluster is named.
function _spokeCachedBadge(d) {
    if (!d || d.stale !== true) return '';
    const when = d.cached_at ? ' ' + _relTimeAgo(new Date(d.cached_at * 1000)) : '';
    return `<div class="mb-3 px-3 py-2 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-700 flex items-center gap-2">
        <span class="px-2 py-0.5 rounded-full bg-amber-200 text-amber-800 font-bold uppercase text-[10px]">cached</span>
        <span>Spoke offline — showing last-known data${escapeHtml(when)}. Live data resumes when the spoke reconnects.</span>
    </div>`;
}

function _dhcpDegradedBanner(d) {
    const bad = (d && d._degraded) || [];
    if (!bad.length) return '';
    const items = bad.map(b => `<li><span class="font-medium">${escapeHtml(b.tenant || b.spoke || 'unknown')}</span>
        <span class="text-amber-700/70">— ${escapeHtml(b.error || 'unreachable')}</span></li>`).join('');
    return `<div class="mb-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
        <div class="font-semibold">Showing a partial list — ${bad.length} DHCP cluster${bad.length > 1 ? 's' : ''} did not respond.</div>
        <ul class="mt-1 ml-4 list-disc text-xs space-y-0.5">${items}</ul>
        <div class="mt-1 text-xs text-amber-700/80">Rows owned by ${bad.length > 1 ? 'those clusters' : 'that cluster'} are missing, not deleted. Check DHCP → Diagnostics.</div>
    </div>`;
}

// ── Shared stat-tile + utilization-bar helpers for the DNS/DHCP analytics
// panels (Phase 3). Kept local to the resolver views; mirror the compact
// tile look used elsewhere in the app.
function _ddTile(label, value, sub, valueColor, actionHtml) {
    return `<div class="bg-white border border-slate-200 rounded-lg p-4">
        <div class="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">${escapeHtml(label)}</div>
        <div class="mt-1 text-2xl font-bold ${valueColor || 'text-slate-800'}">${escapeHtml(String(value))}</div>
        ${(sub || actionHtml) ? `<div class="text-xs text-slate-400 mt-0.5 flex items-center justify-between gap-1">${sub ? `<span class="truncate">${escapeHtml(String(sub))}</span>` : '<span></span>'}${actionHtml || ''}</div>` : ''}
    </div>`;
}

function _showDhcpConfigDetailsModal() {
    const cfg = window._dhcpConfigTest || {};
    const text = (cfg.output || cfg.error || 'No output recorded.').trim();
    const status = cfg.ok ? '<span class="text-emerald-600 font-bold">PASS</span>' : '<span class="text-red-600 font-bold">FAIL</span>';
    openModal('dhcp-cfg-details-modal', `
        <div class="flex items-center justify-between pb-3 border-b border-slate-200">
            <h3 class="text-base font-bold text-[#263040]">Kea DHCP Configuration Test — ${status}</h3>
            <button onclick="document.getElementById('dhcp-cfg-details-modal').remove()" class="text-slate-400 hover:text-slate-600 text-lg leading-none">&times;</button>
        </div>
        <div class="mt-3">
            <div class="text-xs font-semibold text-slate-500 uppercase mb-1">Command Output</div>
            <pre class="bg-slate-900 text-slate-100 p-3 rounded font-mono text-xs whitespace-pre-wrap max-h-96 overflow-y-auto">${escapeHtml(text)}</pre>
        </div>
        <div class="flex justify-end pt-3">
            <button onclick="document.getElementById('dhcp-cfg-details-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium">Close</button>
        </div>`, { card: 'w-full max-w-2xl p-6 space-y-3 max-h-[90vh] overflow-y-auto', backdropClose: true });
}

// A horizontal utilization/percentage bar, green→amber→red by threshold.
function _ddBar(pct, label) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    const color = p >= 90 ? 'bg-red-500' : p >= 70 ? 'bg-amber-500' : 'bg-emerald-500';
    return `<div class="flex items-center gap-2">
        <div class="flex-1 bg-slate-100 rounded-full h-2 overflow-hidden"><div class="${color} h-2 rounded-full" style="width:${p}%"></div></div>
        <span class="text-xs font-mono text-slate-500 w-12 text-right">${p}%</span>
        ${label ? `<span class="text-xs text-slate-400">${escapeHtml(label)}</span>` : ''}
    </div>`;
}

// Humanize an uptime in seconds → "3d 4h 12m".
function _ddUptime(sec) {
    sec = Number(sec) || 0;
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return (d ? `${d}d ` : '') + (h || d ? `${h}h ` : '') + `${m}m`;
}

// ─── Clustered DNS / HA DHCP panels ────────────────────────────────────────
// Rendered inside the existing DNS + DHCP Diagnostics tabs whenever the module
// reports a multi-host deployment. A single-host module sends no `cluster`
// block (or `enabled: false`), so these return '' and the page is unchanged.

function _ddClusterBadge(state) {
    const map = {
        converged: ['text-emerald-700', 'bg-emerald-50 border-emerald-200'],
        healthy:   ['text-emerald-700', 'bg-emerald-50 border-emerald-200'],
        partial:   ['text-amber-700', 'bg-amber-50 border-amber-200'],
        degraded:  ['text-amber-700', 'bg-amber-50 border-amber-200'],
        // Blue, not amber: a node re-reading a freshly-synced config is doing
        // exactly what it should. Amber here made every routine NetBox sync
        // look like a two-node outage.
        updating:  ['text-sky-700', 'bg-sky-50 border-sky-200'],
        diverged:  ['text-red-700', 'bg-red-50 border-red-200'],
        down:      ['text-red-700', 'bg-red-50 border-red-200'],
        invalid:   ['text-red-700', 'bg-red-50 border-red-200'],
    };
    const [text, box] = map[state] || ['text-slate-600', 'bg-slate-50 border-slate-200'];
    return `<span class="px-2 py-0.5 rounded-full border text-xs font-bold ${text} ${box}">${escapeHtml(String(state || 'unknown'))}</span>`;
}

const _DD_MEMBER_TONE = {
    converged: 'text-emerald-600', healthy: 'text-emerald-600',
    drifted: 'text-amber-600', degraded: 'text-amber-600',
    unknown: 'text-amber-600', updating: 'text-sky-600',
    unreachable: 'text-red-600',
};

// Two Unbound resolvers behind one DNS module: per-member applied version +
// digest against the coordinator's desired set, so drift is visible rather than
// inferred.
function _dnsClusterPanel(c) {
    if (!c || c.enabled === false) return '';
    const desired = c.desired || {};
    const members = Array.isArray(c.members) ? c.members : [];
    const commit = c.last_commit || {};
    const admin = typeof isAdmin === 'function' && isAdmin();
    const rows = members.map(m => {
        const tone = _DD_MEMBER_TONE[m.convergence] || 'text-slate-600';
        const ver = m.applied_version == null ? '—' : `v${m.applied_version}`;
        const seen = m.seconds_since_seen == null ? '—' : `${m.seconds_since_seen}s ago`;
        // Human-friendly name is the primary label (see display_name in
        // core/src/routes/net_services.py); the raw id (UUID/agent-id) is
        // kept right below it, and in a title tooltip, so identity stays
        // traceable even when a friendly name is shown. A member with no
        // known name falls back to the id as the label and shows no
        // secondary line — unchanged from before this field existed.
        const memberName = m.display_name || m.id || '—';
        const showId = m.id && m.display_name && m.display_name !== m.id;
        const eId = escJsAttr(m.id || '');
        return `<tr class="border-b border-slate-100">
            <td class="px-4 py-2 font-medium" title="${escapeHtml(m.id || '')}">
                ${escapeHtml(memberName)}
                ${showId ? `<div class="font-mono text-[11px] text-slate-400">${escapeHtml(m.id)}</div>` : ''}
            </td>
            <td class="px-4 py-2 font-mono text-xs">${escapeHtml(m.host || '—')}</td>
            <td class="px-4 py-2 text-xs font-bold ${tone}">${escapeHtml(m.convergence || 'unknown')}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(ver)}</td>
            <td class="px-4 py-2 text-xs">${m.unbound_running === false ? '<span class="text-red-600 font-bold">stopped</span>' : (m.unbound_running ? 'running' : '—')}</td>
            <td class="px-4 py-2 text-xs text-slate-500">${escapeHtml(seen)}</td>
            ${admin ? `<td class="px-4 py-2 text-right">
                <button onclick="removeDnsClusterMember('${eId}')" title="Remove this member from the resolver cluster" class="p-1 text-slate-300 hover:text-red-500 transition-colors"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>
            </td>` : ''}
        </tr>`;
    }).join('');
    const partial = commit.status && commit.status !== 'SUCCESS';
    return `
        <div class="bg-white border border-slate-200 rounded-lg overflow-hidden mb-4">
            <div class="px-4 py-3 border-b border-slate-200 flex items-center justify-between gap-3">
                <div class="text-sm font-semibold text-slate-700">Resolver cluster ${_ddClusterBadge(c.state)}</div>
                <div class="text-xs text-slate-400">${c.converged_count || 0}/${c.member_count || 0} converged on desired set v${desired.version == null ? '?' : desired.version} (${desired.record_count || 0} records)</div>
            </div>
            ${tableWrap(tableHead(['Member', 'Host', 'Convergence', 'Applied', 'Unbound', 'Last seen'].concat(admin ? [''] : [])) + `<tbody>${rows}</tbody>`)}
            ${partial ? `<div class="px-4 py-3 border-t border-slate-200 text-xs text-amber-700 bg-amber-50">
                Last commit v${escapeHtml(String(commit.version))} reported <b>${escapeHtml(commit.status)}</b> — applied on ${escapeHtml((commit.applied || []).join(', ') || 'no member')}; not applied on ${escapeHtml((commit.failed || []).join(', ') || 'none')}.
                ${Object.entries(commit.errors || {}).map(([k, v]) => `<div class="mt-1 font-mono">${escapeHtml(k)}: ${escapeHtml(String(v))}</div>`).join('')}
            </div>` : ''}
            <div class="px-4 py-3 border-t border-slate-200">
                <button onclick="reconcileDnsCluster()" class="px-3 py-1.5 rounded-md text-xs font-bold bg-white border border-slate-300 hover:bg-slate-50">Reconcile now</button>
                <span class="text-xs text-slate-400 ml-2">Re-pushes the desired record set to any resolver that has drifted.</span>
            </div>
        </div>`;
}

// Drop a single member from the resolver cluster (e.g. a host whose DNS Server
// role was uninstalled/decommissioned and will never converge again) without
// touching the others — posts the remaining member set to the same
// DNS_CLUSTER_CONFIG endpoint the "Edit cluster" modal uses. Only {id, host}
// travel back: the rest of each row (convergence, applied version/digest,
// last-seen …) is live reporting data, not configuration, and must not be
// persisted into cluster.json.
async function removeDnsClusterMember(id) {
    const cluster = (window._svcClusterState || {}).dns;
    const current = (cluster && Array.isArray(cluster.members)) ? cluster.members : [];
    if (!current.some(m => m && m.id === id)) {
        showToast('Could not find that member in the current cluster report — try refreshing.', 'error');
        return;
    }
    if (!confirm(`Remove "${id}" from the DNS resolver cluster? Use this for a host that was decommissioned or had its DNS Server role uninstalled — the remaining resolver(s) keep serving.`)) {
        return;
    }
    const remaining = current.filter(m => m && m.id !== id)
        .map(m => ({ id: m.id, host: m.host || '' }));
    try {
        const res = await fetch('/api/dns/cluster' + _tenantQS(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ members: remaining }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'Remove failed', 'error'); return; }
        if (data.status === 'ERROR') { showToast(data.message || 'Remove failed', 'error'); return; }
        showToast(`Removed "${id}" from the resolver cluster`, 'success');
    } catch (e) { showToast(e.message, 'error'); }
    loadDNSData('Diagnostics');
}

// A real Kea HA pair behind one DHCP module: per-node HA state + lease sync +
// shared-config drift.
function _dhcpHaPanel(c) {
    if (!c || c.enabled === false) return '';
    const members = Array.isArray(c.members) ? c.members : [];
    const apply = c.last_apply || {};
    const admin = typeof isAdmin === 'function' && isAdmin();
    const rows = members.map(m => {
        const tone = _DD_MEMBER_TONE[m.health] || 'text-slate-600';
        const scopes = (m.scopes || []).join(', ') || '—';
        const eId = escJsAttr(m.id || '');
        return `<tr class="border-b border-slate-100">
            <td class="px-4 py-2 font-mono font-medium" title="${escapeHtml(m.id || '—')}">${escapeHtml(m.display_name || m.id || '—')}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(m.ha_role || '—')}</td>
            <td class="px-4 py-2 text-xs font-bold ${tone}">${escapeHtml(m.health || 'unknown')}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(m.ha_enabled ? (m.ha_state || 'unknown') : 'HA hook not loaded')}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(m.remote_state || '—')}${m.communication_interrupted ? ' <span class="text-red-600 font-bold">(interrupted)</span>' : ''}</td>
            <td class="px-4 py-2 font-mono text-[11px] text-slate-500">${escapeHtml(scopes)}</td>
            <td class="px-4 py-2 font-mono text-[11px] text-slate-500">${escapeHtml(m.config_digest ? String(m.config_digest).slice(0, 12) + '…' : '—')}</td>
            ${admin ? `<td class="px-4 py-2 text-right">
                <button onclick="removeDhcpHaMember('${eId}')" title="Remove this node from the Kea HA pair" class="p-1 text-slate-300 hover:text-red-500 transition-colors"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>
            </td>` : ''}
        </tr>`;
    }).join('');
    const partial = apply.status && apply.status !== 'SUCCESS';
    // Resolve raw member ids in "no report from ..." to friendly names, same
    // convention as the table rows above (id kept as tooltip via title=).
    const _nameById = {};
    members.forEach(m => { if (m && m.id) _nameById[m.id] = m.display_name || m.id; });
    const missingLabel = (c.config_digests_missing || []).map(id => _nameById[id] || id).join(', ');
    // While a config-set is settling the digests legitimately differ for ~30s.
    // Calling that "MISMATCHED" in red told the operator they had a two-node
    // config split when they had a sync in flight.
    const configLabel = c.config_converged
        ? 'matched'
        : ((c.config_digests_missing || []).length
            ? `<b class="text-amber-600">UNKNOWN</b> (no report from ${escapeHtml(missingLabel)})`
            : (c.updating
                ? '<b class="text-sky-600">CONVERGING</b>'
                : '<b class="text-red-600">MISMATCHED</b>'));
    const syncLabel = c.updating
        ? `${c.serving_count || 0}/${c.member_count || 0} serving · applying configuration`
        : `${c.healthy_count || 0}/${c.member_count || 0} in sync`;
    return `
        <div class="bg-white border border-slate-200 rounded-lg overflow-hidden mb-4">
            <div class="px-4 py-3 border-b border-slate-200 flex items-center justify-between gap-3">
                <div class="text-sm font-semibold text-slate-700">Kea HA pair ${_ddClusterBadge(c.state)}</div>
                <div class="text-xs text-slate-400">${escapeHtml(c.mode || 'hot-standby')} · ${syncLabel} · configuration ${configLabel}</div>
            </div>
            ${c.updating ? `<div class="px-4 py-2 border-b border-slate-200 text-xs text-sky-800 bg-sky-50">
                <b>Applying configuration.</b> Kea re-reads its config and re-synchronises the HA pair after a NetBox sync or a re-apply.
                Each node takes itself out of service while it does so and returns on its own, normally within about 30 seconds. No action needed.
            </div>` : ''}
            ${tableWrap(tableHead(['Node', 'Role', 'Health', 'HA state', 'Partner', 'Scopes', 'Config digest'].concat(admin ? [''] : [])) + `<tbody>${rows}</tbody>`)}
            ${partial ? `<div class="px-4 py-3 border-t border-slate-200 text-xs text-amber-700 bg-amber-50">
                Last apply reported <b>${escapeHtml(apply.status)}</b> at stage <b>${escapeHtml(apply.stage || '?')}</b> — applied on ${escapeHtml((apply.applied || []).join(', ') || 'no node')}${(apply.rolled_back || []).length ? `, rolled back ${escapeHtml(apply.rolled_back.join(', '))}` : ''}.
                ${Object.entries(apply.errors || {}).map(([k, v]) => `<div class="mt-1 font-mono">${escapeHtml(k)}: ${escapeHtml(String(v))}</div>`).join('')}
            </div>` : ''}
            <div class="px-4 py-3 border-t border-slate-200">
                <button onclick="applyDhcpHaConfig()" class="px-3 py-1.5 rounded-md text-xs font-bold bg-white border border-slate-300 hover:bg-slate-50">Re-apply configuration to both nodes</button>
                <span class="text-xs text-slate-400 ml-2">Validates both nodes, then applies standby first and primary last.</span>
                <button onclick="syncDhcpFromNetbox()" class="px-3 py-1.5 rounded-md text-xs font-bold bg-white border border-slate-300 hover:bg-slate-50 ml-2">Sync from NetBox</button>
                <span class="text-xs text-slate-400 ml-2">Pulls subnets/reservations from NetBox first — needed before Re-apply if nothing has synced yet.</span>
            </div>
        </div>`;
}

// Drop a single Kea node from the HA pair — the DHCP twin of
// removeDnsClusterMember, and the only way to retire a decommissioned /
// permanently-offline DHCP server from the Diagnostics tab where the operator
// actually sees it failing. Posts the remaining member set to the same
// DHCP_HA_CONFIG endpoint the "Edit cluster" modal uses; only {id, host}
// travel back, because everything else on the row (health, HA state, scopes,
// config digest …) is live reporting data, not configuration.
//
// Unlike DNS, a Kea pair is exactly two nodes: the spoke treats fewer than two
// members as "stand down and serve single-host", so dropping either node ends
// HA. The confirm text says so rather than implying the survivor stays paired.
// This removes the node from the DHCP topology only — the host's spoke/agent
// record is deleted separately from Setup → Spokes & Agents (Unload Role,
// then Delete).
async function removeDhcpHaMember(id) {
    const cluster = (window._svcClusterState || {}).dhcp;
    const current = (cluster && Array.isArray(cluster.members)) ? cluster.members : [];
    const victim = current.find(m => m && m.id === id);
    if (!victim) {
        showToast('Could not find that node in the current HA report — try refreshing.', 'error');
        return;
    }
    const label = victim.display_name || id;
    const remaining = current.filter(m => m && m.id !== id)
        .map(m => ({ id: m.id, host: m.host || '' }));
    const after = remaining.length >= 2
        ? `The remaining ${remaining.length} nodes stay paired.`
        : (remaining.length === 1
            ? `Only one node is left, so the HA pair stands down and that node serves DHCP on its own.`
            : `No nodes are left, so this DHCP module goes back to single-host.`);
    if (!confirm(`Remove "${label}" from the Kea HA pair? ${after} This edits the DHCP topology only — it does not delete the host's spoke record (do that from Setup → Spokes & Agents) and does not remove any scopes, leases or reservations.`)) {
        return;
    }
    try {
        const res = await fetch('/api/dhcp/ha' + _tenantQS(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ members: remaining }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'Remove failed', 'error'); return; }
        if (data.status === 'ERROR') { showToast(data.message || 'Remove failed', 'error'); return; }
        if (data.status === 'PARTIAL') {
            showToast(data.message || `Removed "${label}", but cleanup was incomplete`, 'error');
        } else {
            showToast(`Removed "${label}" from the Kea HA pair`, 'success');
        }
    } catch (e) { showToast(e.message, 'error'); }
    loadDHCPData('Diagnostics');
}

// Per-member evidence blocks (each worker's own diagnostics recommendations).
// `updatingIds` are nodes the cluster reports as mid-apply: their local Kea is
// deliberately out of service while it re-reads config, so "needs attention"
// would be wrong for them.
// Query-log evidence from DNS diagnostics: explains an empty "Queries by
// Destination" / per-client query log (file, running config, AppArmor, journal).
function _dnsQueryLogPanel(q) {
    if (!q) return '';
    const e = escapeHtml;
    const kv = (k, v) => `<tr class="border-b border-slate-100"><td class="px-3 py-1 text-slate-500 whitespace-nowrap">${e(k)}</td><td class="px-3 py-1 font-mono break-all">${e(v == null || v === '' ? '—' : String(v))}</td></tr>`;
    const pre = (title, lines) => `<div class="mt-2"><div class="font-semibold text-slate-600 mb-1">${e(title)}</div><pre class="whitespace-pre-wrap break-all font-mono text-[11px] text-slate-600 bg-slate-50 p-2 rounded">${e((lines && lines.length) ? lines.join('\n') : '(none)')}</pre></div>`;
    const lf = q.log_file || {}, ld = q.log_dir || {}, mem = q.memory || {};
    const fs = o => o.exists ? `${o.mode} ${o.owner || '?'}:${o.group || '?'}, ${o.size} bytes, modified ${o.age_seconds}s ago` : `missing (${o.error || ''})`;
    const findings = q.findings || [];
    return `<div class="mt-3 border-t border-slate-200 pt-3 text-xs">
        <div class="text-sm font-semibold text-slate-700 mb-1">Query logging</div>
        ${findings.length ? `<ul class="list-disc pl-5 mb-2 text-red-700">${findings.map(x => `<li>${e(x)}</li>`).join('')}</ul>`
            : (q.error ? '<div class="text-amber-600 mb-2">Query-logging check could not complete.</div>' : '<div class="text-emerald-600 mb-2">No query-logging problems detected.</div>')}
        ${q.error ? `<div class="text-red-600">${e(q.error)}</div>` : ''}
        <table class="w-full">
            ${kv('Log file', q.query_log)}${kv('Log file state', fs(lf))}${kv('Log directory', fs(ld))}
            ${kv('Lines parsed in last tail', q.log_tail_parsed)}
            ${kv('Config file included by unbound.conf', q.conf_dir_included)}
            ${kv('Running log-queries', q.running_log_queries)}${kv('Running logfile', q.running_logfile)}${kv('Running use-syslog', q.running_use_syslog)}
            ${kv('Configured log-queries', q.configured_log_queries)}${kv('Configured logfile', q.configured_logfile)}
            ${kv('Unbound version', q.unbound_version)}${kv('Unbound active since', q.unbound_active_since)}
            ${kv('AppArmor profile present', q.apparmor_profile_present)}${kv('AppArmor lm override present', q.apparmor_override_present)}
            ${kv('AppArmor override has log rule', q.apparmor_override_has_rule)}${kv('AppArmor unbound profile', q.apparmor_unbound_status)}
            ${kv('Query lines in journal', q.journal_query_lines)}
            ${kv('In-memory events / tracked names', `${mem.events} / ${mem.tracked_names}`)}${kv('Tail offset / inode', `${mem.log_offset} / ${mem.log_inode}`)}
        </table>
        ${pre('lm-logging.conf', (q.logging_conf_content || '').split('\n'))}
        ${pre('Last log lines', q.log_tail)}
        ${pre('AppArmor denials (kernel log)', q.apparmor_denials)}
        ${pre('Journal (unbound)', q.journal_tail)}
    </div>`;
}

function _ddMemberEvidence(members, kind, updatingIds) {
    const entries = Object.entries(members || {});
    if (!entries.length) return '';
    const upd = new Set(Array.isArray(updatingIds) ? updatingIds : []);
    const cards = entries.map(([id, diag]) => {
        const okBadge = diag && diag.status === 'SUCCESS'
            ? (diag.healthy ? '<span class="text-emerald-600 font-bold">healthy</span>'
                : (upd.has(id) ? '<span class="text-sky-600 font-bold">updating</span>'
                               : '<span class="text-amber-600 font-bold">needs attention</span>'))
            : '<span class="text-red-600 font-bold">unavailable</span>';
        const recs = (diag && diag.recommendations) || [];
        // display_name (added server-side for DNS, see _dns_member_display_name)
        // is the friendly label; raw id stays as a tooltip so identity is
        // still traceable, same convention as the cluster/HA member tables.
        const name = (diag && diag.display_name) || id;
        // DNS carries full per-node Unbound evidence (interfaces, detected
        // IPv4s, access-control lines, port-53 listeners, query probes) in
        // EVERY member's own diagnostics reply — previously only ONE named
        // "source" member's copy was ever rendered (the big tiles below the
        // cluster panel), so a 2nd/3rd healthy resolver's own interfaces/
        // probes were invisible. Render them per-member here instead.
        const dnsEvidence = (kind === 'dns' && diag && diag.status === 'SUCCESS') ? (() => {
            const sockets = diag.sockets || {};
            const listeners = Array.isArray(sockets.listeners) ? sockets.listeners : [];
            const probes = Array.isArray(diag.probes) ? diag.probes : [];
            // The four PASS/FAIL tiles used to be rendered ONCE, from the
            // "source" member only, below the cluster panel. On a 2-resolver
            // cluster that meant the second node's service/config/listener
            // verdicts were never shown -- and the first node's evidence was
            // printed twice. They belong to a node, so render them per node.
            const svc = diag.service || {};
            const cfg = diag.config || {};
            const tile = (label, pass, detailText) => _ddTile(
                label, pass ? 'PASS' : 'FAIL', detailText || '',
                pass ? 'text-emerald-600' : 'text-red-600');
            const probeRows = probes.map(p => `<tr class="border-b border-slate-100">
                <td class="px-3 py-1.5 font-mono text-xs">${escapeHtml(p.server || '—')}:53</td>
                <td class="px-3 py-1.5 font-bold text-xs ${p.responded ? 'text-emerald-600' : 'text-red-600'}">${p.responded ? 'Responded' : 'No response'}</td>
                <td class="px-3 py-1.5 text-xs">${p.rcode == null ? '—' : escapeHtml(String(p.rcode))}</td>
                <td class="px-3 py-1.5 text-xs">${p.latency_ms == null ? '—' : `${escapeHtml(String(p.latency_ms))} ms`}</td>
            </tr>`).join('');
            return `
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-3">
                ${tile('Unbound Service', !!svc.ok, svc.output || svc.error || 'inactive')}
                ${tile('Configuration', !!cfg.ok, cfg.output || cfg.error || 'valid')}
                ${tile('Port 53', !!sockets.has_port_53_listener, sockets.has_port_53_listener ? `${listeners.length} listener(s)` : (sockets.error || 'not listening'))}
                ${tile('LAN Listener', !!sockets.has_lan_listener, sockets.has_lan_listener ? 'non-loopback address bound' : 'loopback only or absent')}
            </div>
            <div class="grid sm:grid-cols-2 gap-3 mt-3 text-xs">
                <div>
                    <div class="font-semibold text-slate-600 mb-1">Configured interfaces</div>
                    <div class="font-mono text-slate-600">${(diag.configured_interfaces || []).map(escapeHtml).join('<br>') || 'none found'}</div>
                    <div class="font-semibold text-slate-600 mt-2 mb-1">Detected local IPv4 addresses</div>
                    <div class="font-mono text-slate-600">${(diag.local_ipv4s || []).map(escapeHtml).join('<br>') || 'none found'}</div>
                    <div class="font-semibold text-slate-600 mt-2 mb-1">Access controls</div>
                    <div class="font-mono text-slate-600">${(diag.access_controls || []).map(escapeHtml).join('<br>') || 'none found'}</div>
                </div>
                <div>
                    <div class="font-semibold text-slate-600 mb-1">Port 53 listeners</div>
                    <pre class="whitespace-pre-wrap break-all font-mono text-slate-600">${escapeHtml(listeners.join('\n') || sockets.error || 'none')}</pre>
                </div>
            </div>
            <div class="mt-3">
                <div class="font-semibold text-slate-600 mb-1 text-xs">Local DNS query probes</div>
                ${tableWrap(tableHead(['Target', 'Result', 'RCODE', 'Latency']) + `<tbody>${probeRows}</tbody>`)}
            </div>
            ${_dnsQueryLogPanel(diag.query_logging)}`;
        })() : '';
        return `<div class="bg-white border border-slate-200 rounded-lg p-4">
            <div class="text-sm font-semibold text-slate-700 mb-1" title="${escapeHtml(id)}">${escapeHtml(name)} — ${okBadge}</div>
            ${diag && diag.status !== 'SUCCESS' ? `<div class="text-xs text-red-600">${escapeHtml(diag.message || 'no response')}</div>` : ''}
            ${recs.length ? `<ul class="list-disc pl-5 space-y-1 text-xs text-slate-600 mt-1">${recs.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>`
                          : '<div class="text-xs text-slate-400">No findings reported.</div>'}
            ${dnsEvidence}
        </div>`;
    }).join('');
    return `<div class="grid ${kind === 'dns' ? '' : 'lg:grid-cols-2'} gap-4 mb-4">${cards}</div>`;
}

// Query-string suffix carrying the tenant picker's current selection. EVERY
// cluster/HA/diagnostic call must pass it: these endpoints resolve which spoke
// answers via the caller's effective tenant, so an unscoped request silently
// lands on whichever module spoke connected first — a different tenant's.
function _tenantQS(prefix = '?') {
    const t = (typeof currentTenant === 'string' && currentTenant) ? currentTenant : '';
    return t ? `${prefix}tenant=${encodeURIComponent(t)}` : '';
}

// Compact multi-host service summary for Settings -> Diagnostics: one line per
// clustered service module. Renders NOTHING when both modules are single-host or
// unreachable, so a normal deployment sees no new noise.
async function loadServiceClusterSummary() {
    const el = document.getElementById('service-cluster-summary');
    if (!el) return;
    const grab = async (url) => {
        try {
            const res = await fetch(url);
            if (!res.ok) return null;
            const data = await res.json();
            return (data && data.enabled !== false) ? data : null;
        } catch (_e) { return null; }
    };
    const [dns, dhcp] = await Promise.all([
        grab('/api/dns/cluster' + _tenantQS()),
        grab('/api/dhcp/ha' + _tenantQS())]);
    const rows = [];
    if (dns) {
        rows.push(`<tr class="border-b border-slate-100">
            <td class="px-4 py-2 font-medium">DNS resolvers</td>
            <td class="px-4 py-2">${_ddClusterBadge(dns.state)}</td>
            <td class="px-4 py-2 text-xs">${dns.converged_count || 0}/${dns.member_count || 0} converged · desired v${(dns.desired || {}).version == null ? '?' : dns.desired.version}</td>
            <td class="px-4 py-2 text-xs text-slate-500">${escapeHtml(((dns.recommendations || [])[0]) || 'No findings.')}</td>
        </tr>`);
    }
    if (dhcp) {
        rows.push(`<tr class="border-b border-slate-100">
            <td class="px-4 py-2 font-medium">Kea HA pair</td>
            <td class="px-4 py-2">${_ddClusterBadge(dhcp.state)}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(dhcp.mode || 'hot-standby')} · ${dhcp.healthy_count || 0}/${dhcp.member_count || 0} in sync · config ${dhcp.config_converged ? 'matched' : 'MISMATCHED'}</td>
            <td class="px-4 py-2 text-xs text-slate-500">${escapeHtml(((dhcp.recommendations || [])[0]) || 'No findings.')}</td>
        </tr>`);
    }
    if (!rows.length) { el.innerHTML = ''; return; }
    el.innerHTML = `<div class="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div class="px-4 py-3 text-sm font-semibold text-slate-700 border-b border-slate-200">Clustered service modules</div>
        ${tableWrap(tableHead(['Service', 'State', 'Members', 'Top finding']) + `<tbody>${rows.join('')}</tbody>`)}
    </div>`;
}

// ─── Cluster / HA topology editor ──────────────────────────────────────────
// Admin-only. Defines the two worker members (and, for DHCP, the HA mode) that
// a single dns/dhcp module drives. The shared worker secret is write-only: it
// is stored as the module's listener PSK and never read back, so the same value
// must be given to each worker's installer (--worker-secret).

// The canonical HA TLS layout install_dhcp.sh writes on every node. The spoke
// defaults to exactly these paths, so a pair configured from this form is a
// valid mutually-verified HA pair without the operator typing anything.
const SVC_HA_TLS_DIR = '/etc/kea/ha-tls';

function openServiceClusterModal(kind, current) {
    const isDns = kind === 'dns';
    const members = (current && Array.isArray(current.members) ? current.members : []);
    const m = i => members[i] || {};
    // "Already enabled" = the module reports 2+ members, i.e. a worker secret is
    // already stored. Only then may the secret field be left blank.
    const alreadyEnabled = members.length >= 2;
    const body = `
        <h3 class="text-lg font-bold text-[#263040]">${isDns ? 'DNS resolver cluster' : 'Kea HA pair'}</h3>
        <p class="text-sm text-slate-500">${isDns
            ? 'Two Unbound hosts managed by this DNS module. The module owns the record set and keeps both resolvers identical.'
            : 'Two Kea hosts run as one HA pair. Both nodes get the same scopes and reservations; only their HA identity differs.'}</p>
        ${[0, 1].map(i => `
        <div class="grid grid-cols-2 gap-2">
            <div>
                <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">Member ${i + 1} id</label>
                <input id="svc-cl-id-${i}" value="${escapeHtml(m(i).id || '')}" placeholder="${isDns ? 'dns-a' : 'kea-a'}" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            </div>
            <div>
                <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">Member ${i + 1} host</label>
                <input id="svc-cl-host-${i}" value="${escapeHtml(m(i).host || '')}" placeholder="10.0.1.${i + 10}" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            </div>
        </div>`).join('')}
        ${isDns ? '' : `
        <div>
            <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">HA mode</label>
            <select id="svc-cl-mode" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm" disabled>
                <option value="hot-standby" selected>hot-standby</option>
            </select>
            <p class="text-[11px] text-slate-400 mt-1">Load-balancing is not offered: it requires each subnet's pool to be split between the two servers by client class, which this module does not yet generate. Both nodes would allocate from the same range.</p>
        </div>
        <div class="grid grid-cols-2 gap-2">
            <div>
                <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">HA control user</label>
                <input id="svc-cl-hauser" value="${escapeHtml(m(0).ha_user || 'kea-ha')}" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            </div>
            <div>
                <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">HA control password${m(0).ha_password_set ? '' : ' <span class="text-red-600">(required)</span>'}</label>
                <input id="svc-cl-hapass" type="password" placeholder="${m(0).ha_password_set ? 'unchanged' : 'required to enable the pair'}" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            </div>
        </div>
        <p class="text-[11px] text-slate-400">Write-only, and carried over when left blank. Must match <code>--ha-user</code>/<code>--ha-password</code> on both nodes. Peer traffic is HTTPS with mutual cert verification; these credentials travel inside that TLS session.</p>
        <div>
            <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">HA peer addresses (firewall scope)</label>
            <input id="svc-cl-hapeers" value="${escapeHtml((current && (current.ha_peers || []).join(', ')) || '')}" placeholder="10.0.1.10, 10.0.1.11" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            <p class="text-[11px] text-slate-400 mt-1">Passed to each node's installer as <code>--ha-peer</code>; the HA port accepts only these sources.</p>
        </div>
        <div>
            <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">HA TLS directory (on each node)</label>
            <input id="svc-cl-hatls" value="${escapeHtml((m(0).ha_trust_anchor || '').replace(/\/ha-ca\.pem$/, '') || SVC_HA_TLS_DIR)}" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            <p class="text-[11px] text-slate-400 mt-1">Where <code>install_dhcp.sh --ha-ca/--ha-cert/--ha-key</code> placed the material: <code>${escapeHtml(SVC_HA_TLS_DIR)}/ha-ca.pem</code>, <code>node.crt</code>, <code>node.key</code>. Leave as-is unless you installed them elsewhere.</p>
        </div>`}
        <div>
            <label class="block text-[11px] uppercase tracking-wide text-slate-400 font-semibold">Worker secret${alreadyEnabled ? '' : ' <span class="text-red-600">(required)</span>'}</label>
            <input id="svc-cl-secret" type="password" placeholder="${alreadyEnabled ? 'leave blank to keep the current secret' : 'required to enable the cluster'}" class="w-full border border-slate-300 rounded-md px-2 py-1 text-sm">
            <p class="text-[11px] text-slate-400 mt-1">Write-only. Choose it here and give the SAME value to each host's installer:
                <code>--worker-secret &lt;value&gt;</code>. Nothing generates it for you — a secret you cannot read could never be handed to the workers — and it is never displayed again.</p>
        </div>
        <div id="svc-cl-error" class="hidden text-xs text-red-600"></div>`;
    // The Kea HA form has enough fields that the old single scrolling card let
    // Save scroll out of view below the fold. Widen the card and split it into
    // a scrollable content region + a footer pinned outside that scroll area
    // (via flex-col + shrink-0) so Cancel/Save stay visible no matter how far
    // the form scrolls. DNS's shorter form still fits without scrolling, but
    // the wider/pinned-footer treatment is harmless there too.
    const wrapped = `
        <div class="flex-1 overflow-y-auto space-y-4 p-6">${body}</div>
        <div class="shrink-0 flex justify-between items-center gap-2 px-6 py-4 border-t border-slate-100">
            ${alreadyEnabled ? `<button onclick="deleteServiceCluster('${escapeHtml(kind)}')" class="px-4 py-1.5 text-sm rounded-md border border-red-300 text-red-600 hover:bg-red-50 font-bold">Delete cluster</button>` : '<span></span>'}
            <div class="flex gap-2">
                <button onclick="document.getElementById('svc-cluster-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
                <button onclick="saveServiceCluster('${escapeHtml(kind)}', ${alreadyEnabled}, ${!!m(0).ha_password_set})" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Save</button>
            </div>
        </div>`;
    openModal('svc-cluster-modal', wrapped, {
        backdropClose: true,
        card: 'w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden',
    });
}

async function saveServiceCluster(kind, alreadyEnabled, haCredsStored) {
    const err = document.getElementById('svc-cl-error');
    const fail = (msg) => {
        if (err) { err.textContent = msg; err.classList.remove('hidden'); }
        showToast(msg, 'error');
    };
    const haUser = (document.getElementById('svc-cl-hauser')?.value || '').trim();
    const haPass = (document.getElementById('svc-cl-hapass')?.value || '').trim();
    const haTlsDir = ((document.getElementById('svc-cl-hatls')?.value || '').trim()
                      || SVC_HA_TLS_DIR).replace(/\/+$/, '');
    const members = [0, 1].map(i => {
        const member = {
            id: (document.getElementById(`svc-cl-id-${i}`)?.value || '').trim(),
            host: (document.getElementById(`svc-cl-host-${i}`)?.value || '').trim(),
        };
        // Write-only HA credentials: send them only when the operator typed a
        // value. The spoke carries the stored one forward for a blank field, so
        // re-saving the form can never erase the pair's credential.
        if (kind === 'dhcp') {
            if (haUser) member.ha_user = haUser;
            if (haPass) member.ha_password = haPass;
            // Always send the TLS material explicitly: the payload this form
            // produces must be a complete, build_peers-valid pair on its own,
            // not one that only works because the spoke happened to default it.
            member.ha_trust_anchor = `${haTlsDir}/ha-ca.pem`;
            member.ha_cert = `${haTlsDir}/node.crt`;
            member.ha_key = `${haTlsDir}/node.key`;
        }
        return member;
    }).filter(x => x.id);

    const secret = (document.getElementById('svc-cl-secret')?.value || '').trim();
    if (members.length >= 2 && !secret && !alreadyEnabled) {
        fail('A worker secret is required to enable the cluster. Choose one here and pass the same value to each host installer with --worker-secret.');
        return;
    }
    // The Kea HA control agent rejects an unauthenticated peer, so a pair
    // configured without credentials could never heartbeat. Blank is allowed
    // only when the spoke already holds them (it carries them forward).
    if (kind === 'dhcp' && members.length >= 2 && !haCredsStored
            && (!haUser || !haPass)) {
        fail('HA control credentials are required to enable the pair. Enter the same ha-user/ha-password you passed to each node installer (--ha-user/--ha-password); the Kea HA control agent rejects an unauthenticated peer.');
        return;
    }
    const payload = { members };
    if (secret) payload.worker_secret = secret;
    if (kind === 'dhcp') {
        payload.mode = 'hot-standby';
        const peers = (document.getElementById('svc-cl-hapeers')?.value || '')
            .split(',').map(x => x.trim()).filter(Boolean);
        if (peers.length) payload.ha_peers = peers;
    }
    try {
        const url = (kind === 'dns' ? '/api/dns/cluster' : '/api/dhcp/ha') + _tenantQS();
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { fail(data.detail || 'Save failed'); return; }
        if (data.status && data.status === 'ERROR') { fail(data.message || 'Save failed'); return; }
        if (data.status === 'PARTIAL') {
            showToast(data.message || 'Saved with incomplete cleanup', 'error');
        } else {
            showToast(members.length >= 2
                ? `${kind.toUpperCase()} cluster configured (${members.map(x => x.id).join(', ')})`
                : `${kind.toUpperCase()} cluster cleared — the module is single-host again`, 'success');
        }
        document.getElementById('svc-cluster-modal')?.remove();
    } catch (e) { fail(e.message); }
    if (kind === 'dns') loadDNSData('Diagnostics'); else loadDHCPData('Diagnostics');
}

// "Delete cluster" button on an already-enabled Edit Cluster modal — posts an
// empty member list to the same *_HA_CONFIG/*_CLUSTER_CONFIG endpoint
// saveServiceCluster already uses for a 0-member save (which the spoke
// already treats as "disable the pair/cluster and go back to single-host").
// A confirm prompt guards it since this is destructive to the topology
// (each node stands down and reverts to serving independently).
async function deleteServiceCluster(kind) {
    const label = kind === 'dns' ? 'resolver cluster' : 'HA pair';
    if (!confirm(`Delete the ${label}? Both nodes will stand down and go back to serving independently. This does not remove any DHCP/DNS data — only the cluster topology.`)) {
        return;
    }
    try {
        const url = (kind === 'dns' ? '/api/dns/cluster' : '/api/dhcp/ha') + _tenantQS();
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ members: [] }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'Delete failed', 'error'); return; }
        if (data.status === 'ERROR') { showToast(data.message || 'Delete failed', 'error'); return; }
        showToast(`${kind.toUpperCase()} cluster deleted — the module is single-host again`, 'success');
        document.getElementById('svc-cluster-modal')?.remove();
    } catch (e) { showToast(e.message, 'error'); }
    if (kind === 'dns') loadDNSData('Diagnostics'); else loadDHCPData('Diagnostics');
}

// Header button shown on the DNS/DHCP Diagnostics tabs (admin only) so an
// operator can define the pair even before any worker exists.
function serviceClusterButton(kind, cluster) {
    if (typeof isAdmin === 'function' && !isAdmin()) return '';
    const label = cluster ? 'Edit cluster' : (kind === 'dns' ? 'Configure resolver cluster' : 'Configure HA pair');
    window._svcClusterState = window._svcClusterState || {};
    window._svcClusterState[kind] = cluster || null;
    return `<button onclick="openServiceClusterModal('${kind}', (window._svcClusterState||{})['${kind}'])" class="px-3 py-1.5 rounded-md text-xs font-bold bg-white border border-slate-300 hover:bg-slate-50">${label}</button>`;
}

async function reconcileDnsCluster() {
    try {
        const res = await fetch('/api/dns/cluster/reconcile' + _tenantQS(),
                                { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'Reconcile failed', 'error'); return; }
        const done = (data.reconciled || []).length;
        showToast(done ? `Re-pushed the desired record set to ${done} resolver(s)`
                       : 'All resolvers already converged',
                  data.status === 'SUCCESS' ? 'success' : 'error');
    } catch (e) { showToast(e.message, 'error'); }
    loadDNSData('Diagnostics');
}

// Manual "Sync from NetBox" for DHCP — pulls subnets/reservations into the
// coordinator's desired state. Needed before the first Re-apply on a fresh
// coordinator (DHCP_HA_APPLY refuses to push an empty subnet4 fleet-wide),
// otherwise the operator would have to wait for the ~5min background loop.
async function syncDhcpFromNetbox() {
    try {
        const res = await fetch('/api/dhcp/sync', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'DHCP sync failed', 'error'); return; }
        showToast(data.subnets_synced != null
            ? `Synced ${data.subnets_synced} subnet(s) / ${data.reservations_synced || 0} reservation(s) from NetBox`
            : (data.reason || data.message || 'DHCP sync complete'),
            'success');
    } catch (e) { showToast(e.message, 'error'); }
    loadDHCPData('Diagnostics');
}

async function applyDhcpHaConfig() {
    try {
        const res = await fetch('/api/dhcp/ha/apply' + _tenantQS(),
                                { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || 'HA apply failed', 'error'); return; }
        showToast(data.status === 'SUCCESS'
            ? `Configuration applied to ${(data.applied || []).join(' and ')}`
            : (data.message || `HA apply reported ${data.status}`),
            data.status === 'SUCCESS' ? 'success' : 'error');
    } catch (e) { showToast(e.message, 'error'); }
    loadDHCPData('Diagnostics');
}

// Real-time Kea -> Unbound DNS registration hook ("Option 1"): a spoke
// run_script hook that registers A/PTR records in Unbound the moment a Kea
// lease is committed/released, independent of the NetBox sync loop shown
// above. Status-only render when the GET failed/is unreachable — an older
// dhcp spoke without the DHCP_DNS_HOOK_STATUS command must not break the
// rest of the Diagnostics tab (hence the null guard, not an error banner).
// ── DHCP client request trace (POST /api/dhcp/packet-trace) ─────────────
// "Is the DHCP server even seeing my client?" — Kea's per-MAC log, an
// optional raw UDP/67-68 capture on the Kea node(s), counter deltas, and a
// verdict for where the DORA exchange stops. Admin-only (server-enforced).
function _dhcpPacketTracePanel() {
    if (!(typeof isAdmin === 'function' && isAdmin())) return '';
    const last = window._dhcpPacketTraceLast || {};
    return `
        <div class="bg-white border border-slate-200 rounded-lg p-4 mt-4">
            <div class="text-sm font-semibold text-slate-700">Client request trace</div>
            <div class="text-xs text-slate-400 mb-3">Shows whether the Kea server(s) are receiving a client's DHCP requests and where the exchange stops (DISCOVER → OFFER → REQUEST → ACK). For a packet-level check, set a capture window and make the client retry (unplug/replug, renew) while it runs. Leave the MAC empty to list every client Kea has heard from.</div>
            <div class="flex flex-wrap items-end gap-3">
                <label class="text-xs text-slate-600">Client MAC
                    <input id="dhcp-trace-mac" type="text" placeholder="aa:bb:cc:dd:ee:ff" value="${escapeHtml(last.mac || '')}" class="mt-1 block w-48 px-2 py-1.5 border border-slate-300 rounded text-xs font-mono"></label>
                <label class="text-xs text-slate-600">Log window (min)
                    <input id="dhcp-trace-minutes" type="number" min="1" max="1440" value="${escapeHtml(String(last.minutes || 30))}" class="mt-1 block w-24 px-2 py-1.5 border border-slate-300 rounded text-xs"></label>
                <label class="text-xs text-slate-600">Live capture (s, 0–60)
                    <input id="dhcp-trace-capture" type="number" min="0" max="60" value="${escapeHtml(String(last.capture_seconds != null ? last.capture_seconds : 20))}" class="mt-1 block w-24 px-2 py-1.5 border border-slate-300 rounded text-xs"></label>
                <button id="dhcp-trace-btn" onclick="runDhcpPacketTrace()" class="px-3 py-1.5 rounded-md text-xs font-bold bg-[#01A982] text-white hover:bg-[#008f6e]">Trace</button>
            </div>
            <div id="dhcp-trace-result" class="mt-4">${window._dhcpPacketTraceHtml || ''}</div>
        </div>`;
}

async function runDhcpPacketTrace() {
    const mac = (document.getElementById('dhcp-trace-mac') || {}).value || '';
    const minutes = Number((document.getElementById('dhcp-trace-minutes') || {}).value || 30);
    const capture = Number((document.getElementById('dhcp-trace-capture') || {}).value || 0);
    const out = document.getElementById('dhcp-trace-result');
    const btn = document.getElementById('dhcp-trace-btn');
    window._dhcpPacketTraceLast = { mac, minutes, capture_seconds: capture };
    if (btn) { btn.disabled = true; btn.textContent = capture > 0 ? `Capturing ${capture}s…` : 'Tracing…'; }
    if (out) out.innerHTML = `<p class="text-xs text-slate-500">${capture > 0 ? `Listening on the Kea node(s) for ${capture}s — make the client retry now.` : 'Reading Kea logs…'}</p>`;
    try {
        const d = await apiJson('/api/dhcp/packet-trace' + _tenantQS(), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac: mac.trim(), minutes, capture_seconds: capture }),
        });
        window._dhcpPacketTraceHtml = _dhcpPacketTraceResult(d);
    } catch (err) {
        window._dhcpPacketTraceHtml = `<p class="text-xs text-red-600">Trace failed: ${escapeHtml(err.message || String(err))}</p>`;
    }
    if (out) out.innerHTML = window._dhcpPacketTraceHtml;
    if (btn) { btn.disabled = false; btn.textContent = 'Trace'; }
}

function _dhcpPacketTraceResult(d) {
    if (!d || d.status === 'ERROR') return `<p class="text-xs text-red-600">${escapeHtml((d && (d.message || d.error)) || 'No result')}</p>`;
    const counts = o => Object.entries(o || {}).map(([k, v]) => `${escapeHtml(k)}×${v}`).join(', ') || '—';
    const pre = (title, lines) => lines.length ? `<div class="text-xs font-semibold text-slate-700 mt-3 mb-1">${title}</div><pre class="text-[11px] whitespace-pre-wrap break-all text-slate-600 max-h-72 overflow-auto bg-slate-50 rounded p-2">${escapeHtml(lines.join('\n'))}</pre>` : '';
    const evLines = (d.events || []).map(e => `${e.ts} ${e.level} ${e.msg_id} ${e.text}`);
    const probLines = (d.server_problems || []).map(e => `${e.ts} ${e.level} ${e.msg_id} ${e.text}`);
    const cap = d.capture || {};
    const capLines = (cap.packets || []).map(p => `+${p.t}s ${p.direction === 'out' ? 'OUT' : 'IN '} ${p.interface} ${p.type} ${p.src} → ${p.dst} chaddr=${p.chaddr} xid=${p.xid}${p.giaddr !== '0.0.0.0' ? ` giaddr=${p.giaddr}` : ''}${p.yiaddr !== '0.0.0.0' ? ` yiaddr=${p.yiaddr}` : ''}${p.requested_ip ? ` req=${p.requested_ip}` : ''}${p.server_id ? ` server-id=${p.server_id}` : ''}${p.hostname ? ` host=${p.hostname}` : ''}`);
    const capNote = cap.ran ? `<div class="text-xs text-slate-500 mt-2">Live capture: ${cap.seconds}s, ${(cap.packets || []).length} packet(s)${cap.truncated ? ' (truncated)' : ''}.</div>` : (cap.error ? `<div class="text-xs text-amber-700 mt-2">Live capture unavailable: ${escapeHtml(cap.error)}</div>` : '');
    const delta = Object.keys(d.counters_delta || {}).length ? `<div class="text-xs text-slate-500 mt-1">Kea counters during capture: ${counts(d.counters_delta)}</div>` : '';
    const errs = (d.errors || []).length ? `<div class="text-xs text-amber-700 mt-2">${(d.errors || []).map(escapeHtml).join('<br>')}</div>` : '';
    const members = d.members ? Object.entries(d.members).map(([id, r]) => `<li>${escapeHtml(r.display_name || id)}: ${r.status === 'SUCCESS' ? escapeHtml(((r.verdict || {}).code) || `${(r.events_total || 0)} event(s)`) : `<span class="text-red-600">${escapeHtml(r.message || r.error || 'error')}</span>`}</li>`).join('') : '';
    const memberBlock = members ? `<div class="text-xs text-slate-500 mt-2">Per node${d.trace_source_name ? ` (details below from ${escapeHtml(d.trace_source_name)})` : ''}:<ul class="list-disc pl-5">${members}</ul></div>` : '';
    if (!d.mac) {
        const rows = (d.clients || []).map(c => `<tr class="border-b border-slate-100"><td class="px-3 py-1.5 font-mono text-xs">${escapeHtml(c.mac)}</td><td class="px-3 py-1.5 text-xs">${escapeHtml(c.last_seen)}</td><td class="px-3 py-1.5 text-xs">${counts(c.received)}</td><td class="px-3 py-1.5 text-xs">${counts(c.sent)}</td><td class="px-3 py-1.5 font-mono text-xs">${escapeHtml(c.last_lease || '—')}</td><td class="px-3 py-1.5 text-xs">${c.problems || 0}</td></tr>`).join('');
        return memberBlock + (rows ? tableWrap(tableHead(['MAC', 'Last seen', 'Received', 'Sent', 'Last lease', 'Problems']) + `<tbody>${rows}</tbody>`) : `<p class="text-xs text-slate-500">Kea logged no client packets in the last ${d.minutes} min.</p>`)
            + capNote + delta + pre('Captured packets', capLines) + pre('Server warnings/errors', probLines) + errs;
    }
    const v = d.verdict || {};
    const good = v.code === 'ACKED';
    const s = d.summary || {};
    const leases = (d.leases || []).map(l => `${l.ip} (subnet ${l.subnet_id})`).join(', ') || 'none';
    const res = (d.reservations || []).map(r => `${r.ip} in ${r.subnet}`).join(', ') || 'none';
    return `
        <div class="p-3 rounded-lg border ${good ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-amber-50 border-amber-200 text-amber-800'}">
            <div class="text-sm font-semibold">${escapeHtml(v.code || 'UNKNOWN')}</div>
            <div class="text-xs mt-1">${escapeHtml(v.message || '')}</div>
            ${(v.findings || []).length ? `<ul class="list-disc pl-5 mt-2 text-xs space-y-1">${v.findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>` : ''}
        </div>
        ${memberBlock}
        <div class="grid md:grid-cols-2 gap-2 mt-3 text-xs text-slate-600">
            <div>Kea received: ${counts(s.kea_received)}</div>
            <div>Kea sent: ${counts(s.kea_sent)}</div>
            <div>Captured from client: ${counts(s.captured_from_client)}</div>
            <div>Captured to client: ${counts(s.captured_to_client)}</div>
            <div>Interfaces: ${escapeHtml((s.interfaces || []).join(', ') || '—')} · Kea listens on: ${escapeHtml((d.interfaces_configured || []).join(', ') || '—')}</div>
            <div>Relays / sources: ${escapeHtml((s.relays_or_sources || []).join(', ') || '—')}</div>
            <div>Current lease: ${escapeHtml(d.leases == null ? 'unavailable' : leases)}</div>
            <div>Reservation: ${escapeHtml(res)}</div>
            <div>First / last seen: ${escapeHtml(s.first_seen || '—')} / ${escapeHtml(s.last_seen || '—')}</div>
            <div>Server IPs: ${escapeHtml((d.server_ips || []).join(', ') || '—')}</div>
        </div>
        ${capNote}${delta}
        ${pre(`Kea log for ${d.mac} (last ${d.minutes} min, ${d.events_total || 0} event(s))`, evLines)}
        ${pre('Captured packets', capLines)}
        ${pre('Server warnings/errors (all clients)', probLines)}
        ${errs}`;
}

function _dhcpDnsHookPanel(dnsHook) {
    if (!dnsHook) return '';
    const settings = dnsHook.settings || {};
    const enabled = !!settings.enabled;
    const loaded = dnsHook.loaded_in_running_config;
    const admin = typeof isAdmin === 'function' && isAdmin();
    const targets = (settings.targets || []).join(', ') || '127.0.0.1@8953';
    const logTail = (dnsHook.log_tail || []).slice(-10);
    return `
        <div class="bg-white border border-slate-200 rounded-lg p-4 mt-4">
            <div class="flex items-center justify-between gap-3 mb-2">
                <div>
                    <div class="text-sm font-semibold text-slate-700">Real-time DNS registration (Kea → Unbound)</div>
                    <div class="text-xs text-slate-400">Registers/retracts a client's DNS record in Unbound the instant a Kea lease is committed, renewed, released, expired, or declined — no dependency on the NetBox sync loop above.</div>
                </div>
                ${admin ? `<button onclick="toggleDhcpDnsHook(${enabled ? 'false' : 'true'})" class="px-3 py-1.5 rounded-md text-xs font-bold ${enabled ? 'bg-white border border-slate-300 hover:bg-slate-50' : 'bg-[#01A982] text-white hover:bg-[#018a6c]'} flex-shrink-0">${enabled ? 'Disable' : 'Enable'}</button>` : ''}
            </div>
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                ${_ddTile('Hook', enabled ? 'ENABLED' : 'DISABLED', enabled ? `targets: ${escapeHtml(targets)}` : 'not configured', enabled ? 'text-emerald-600' : 'text-slate-500')}
                ${_ddTile('Loaded in Kea', loaded === true ? 'YES' : (loaded === false ? 'NO' : '—'), loaded === false && enabled ? 'drift: enabled but not loaded — re-apply' : '', loaded === false && enabled ? 'text-red-600' : 'text-slate-600')}
            </div>
            ${logTail.length ? `<div class="mt-3"><div class="text-xs font-semibold text-slate-500 mb-1">Recent hook events</div><pre class="text-[11px] whitespace-pre-wrap break-all text-slate-600">${escapeHtml(logTail.join('\n'))}</pre></div>` : ''}
        </div>`;
}

// Flips `enabled` while preserving every other on-disk setting (targets,
// domain, ttl, register_ptr) — a toggle must never silently reset an
// operator's existing hook configuration.
async function toggleDhcpDnsHook(enable) {
    const st = window._dhcpDnsHookStatus;
    if (!st || !st.settings || st.status === 'ERROR') {
        showToast('DNS hook status unavailable — refresh before toggling so existing settings are preserved', 'error');
        return;
    }
    const prior = st.settings;
    const body = Object.assign({}, prior, { enabled: enable });
    try {
        const res = await fetch('/api/dhcp/dns-hook' + _tenantQS(),
                                { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                  body: JSON.stringify(body) });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.status === 'ERROR') { showToast(data.detail || data.message || 'DNS hook update failed', 'error'); return; }
        showToast(enable ? 'Real-time DNS registration enabled' : 'Real-time DNS registration disabled', 'success');
    } catch (e) { showToast(e.message, 'error'); }
    loadDHCPData('Diagnostics');
}


// Renders the "Queries by Destination" rows — e.g. "A record for
// www.dwx.com — 42 queries" — from the /api/dns/stats `query_names` list
// (already sorted/filtered server-side; this just formats it), plus a
// collapsed "source" line listing which client IP(s) made those queries.
function _ddQueryNameRows(names, searchActive = false) {
    if (!names.length && !searchActive) {
        return '<p class="text-slate-400 italic text-sm">No DNS queries recorded yet. This may mean:<br>• Unbound DNS is not running<br>• Query logging is not enabled<br>• No DNS queries have been made recently.</p>';
    }
    return `<div class="max-h-80 overflow-y-auto divide-y divide-slate-100">${names.map(q => {
        const sources = q.sources || [];
        // Each source carries a best-effort ``host`` (DHCP lease hostname for
        // that client IP, falling back to the raw IP when no lease matches —
        // see /api/dns/stats' ip_to_host enrichment) so operators can see
        // WHICH DEVICE queried a name, not just its IP.
        const sourceLine = sources.length
            ? `<div class="text-[11px] text-slate-400 font-mono mt-0.5">from ${sources.slice(0, 5).map(s => {
                  const host = s.host && s.host !== s.ip ? `${escapeHtml(s.host)} (${escapeHtml(s.ip)})` : escapeHtml(s.ip);
                  return `${host} (${(s.count || 0).toLocaleString()})`;
              }).join(', ')}${sources.length > 5 ? `, +${sources.length - 5} more` : ''}</div>`
            : '';
        return `
        <div class="py-1.5 text-xs">
            <div class="flex items-center justify-between gap-3">
                <span><span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 font-medium mr-2">${escapeHtml(q.type)}</span>
                      <span class="font-mono text-slate-700">${escapeHtml(q.name)}</span></span>
                <span class="font-mono text-slate-500 whitespace-nowrap">${(q.count || 0).toLocaleString()} queries</span>
            </div>
            ${sourceLine}
        </div>`;
    }).join('')}</div>`;
}

// Best-effort "last NetBox → Unbound/Kea auto-sync" line for the analytics
// panels; silent when the status endpoint is unreachable.
async function _ddSyncStatusLine(side) {
    try {
        const { ok, data } = await _spokeFetch('/api/dns-dhcp/sync-status');
        if (!ok || !data) return '';
        const s = (data.status || {})[side] || {};
        const cfg = data.config || {};
        if (!s.last_run) {
            return `<div class="text-xs text-slate-400 mt-2">NetBox auto-sync: ${cfg.enabled === false ? 'disabled' : 'enabled'} (every ${cfg.interval || 300}s) — no run yet</div>`;
        }
        const when = new Date(s.last_run * 1000).toLocaleString();
        const badge = s.status === 'ok' ? 'text-emerald-600' : s.status === 'error' ? 'text-red-500' : 'text-amber-500';
        const detail = side === 'dns'
            ? (s.records_synced != null ? `${s.records_synced} records` : (s.reason || s.error || ''))
            : (s.subnets_synced != null ? `${s.subnets_synced} subnets / ${s.reservations_synced} reservations` : (s.reason || s.error || ''));
        // A sync that applied NO reservations still reports "ok" — the spoke
        // did as it was told, there was just no enabled scope to put them in.
        // Without this the list is simply empty, which reads as "you have no
        // reservations" rather than "123 of them were dropped".
        const warn = s.warning
            ? `<div class="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-2 py-1 mt-2">⚠ ${escapeHtml(s.warning)}</div>`
            : '';
        return `${warn}<div class="text-xs text-slate-400 mt-2">NetBox auto-sync: <span class="${badge} font-medium">${escapeHtml(s.status)}</span> · ${escapeHtml(detail)} · <span title="${escapeHtml(when)}">${escapeHtml(when)}</span></div>`;
    } catch (_e) { return ''; }
}

async function loadDNSData(subMenu, skipWorkerDiscovery = false) {
    const container = document.getElementById('dns-content');
    if (!container) return;
    // External DNS subtab: "all things DNS" also covers internet-facing DNS
    // providers (HE.NET, …). Each connected provider is rendered as its own
    // tile (or drilled straight into when only one is connected) inside the
    // shared dns-content pane, so hide the top-nav actions and hand off.
    const navActions = document.getElementById('top-nav-actions');
    if (subMenu === 'External DNS') {
        if (navActions) navActions.innerHTML = '';
        return loadExternalDNS();
    }
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    // ALL per-tab action buttons — "+ Add Record" (Records tab only), "+ Add
    // Forwarder" (Forwarders tab only) — render into the trailing
    // #top-nav-actions strip in the sub-nav bar, pinned right next to the
    // help "i" icon (see renderTopNav), rather than a page-body button row.
    // No "+ Add Server" here: a DNS module is provisioned by loading the DNS
    // Server role onto a host (Fleet → Load Role), not by self-service
    // onboarding a standalone spoke — the button offered a path that never
    // actually worked for this module.
    if (navActions) {
        const addRecordBtn = ((subMenu === 'Records') && (isAdmin() || isTenantAdmin()))
            ? `<button id="dns-add-btn" onclick="showDnsRecordModal()" title="Add a new DNS record" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm">+ Add Record</button>`
            : '';
        const addForwarderBtn = (subMenu === 'Forwarders' && isAdmin())
            ? `<button id="dns-forwarder-add-btn" onclick="showDnsForwarderModal()" title="Add a new persistent upstream DNS forwarder" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm">+ Add Forwarder</button>`
            : '';
        const addProfileBtn = (subMenu === 'Overrides' && isAdmin())
            ? `<button id="dns-override-profile-add-btn" onclick="showDnsOverrideProfileModal()" title="Define a new DNS override profile (custom answers for chosen clients)" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm">+ Add Profile</button>`
            : '';
        const assignOverrideBtn = (subMenu === 'Overrides' && (isAdmin() || isTenantAdmin()))
            ? `<button id="dns-override-assign-btn" onclick="showDnsOverrideAssignModal()" title="Apply an override profile to a device IP or subnet" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm ml-2">+ Assign</button>`
            : '';
        navActions.innerHTML = addRecordBtn + addForwarderBtn + addProfileBtn + assignOverrideBtn;
    }

    const th = tableHead, tw = tableWrap;  // shared table helpers
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;

    try {
        if (!skipWorkerDiscovery && (typeof isAdmin === 'function') && isAdmin()) {
            window._dnsWorkerDiscovery = window._dnsWorkerDiscovery || fetch(
                '/api/dns/cluster/discover' + _tenantQS(), { method: 'POST' })
                .then(async res => {
                    const data = await res.json().catch(() => ({}));
                    if (!res.ok) throw new Error(data.detail || 'DNS worker discovery failed');
                    const configuring = (data.workers || [])
                        .filter(w => w.status === 'configuring').length;
                    const configured = (data.workers || [])
                        .filter(w => w.status === 'configured').length;
                    if (configuring) {
                        showToast(`Discovered ${configuring} DNS Server worker(s); configuring them now.`, 'success');
                    } else if (configured) {
                        showToast(`Discovered and configured ${configured} DNS Server worker(s).`, 'success');
                    }
                    // Re-render the tab that is ACTUALLY on screen when this
                    // resolves, not the ``subMenu`` this particular call was
                    // kicked off for. Discovery runs in the background (this
                    // fetch is intentionally un-awaited above) and a steady-
                    // state cluster reports its already-configured workers on
                    // every call, so ``data.workers.length`` is truthy on
                    // nearly every load — if the operator switched tabs (e.g.
                    // Records -> Forwarders, added a forwarder, and it
                    // rendered correctly) before an EARLIER tab's discovery
                    // call finished, this callback used to blindly re-run
                    // ``loadDNSData`` for that earlier, now-stale tab and
                    // silently overwrite the currently-visible one with it —
                    // no error, the data just "disappeared" underneath the
                    // forwarder the operator just added. Reading the live
                    // ``currentView``/``currentSubView`` globals instead (the
                    // same ones ``setSubView`` maintains for nav highlighting)
                    // means a still-in-flight discovery from a different tab,
                    // or one from before the operator navigated to a
                    // different top-level view entirely, is a no-op here.
                    if ((data.workers || []).length && currentView === 'dns') {
                        loadDNSData(currentSubView, true);
                    }
                    return data;
                })
                .catch(err => {
                    console.warn('DNS worker auto-discovery:', err);
                    showToast(err.message || 'DNS worker discovery failed', 'error');
                    return null;
                })
                .finally(() => {
                    window._dnsWorkerDiscovery = null;
                });
        }
        // ── Overview: Unbound query telemetry (OPNsense-grade) ────────────
        if (subMenu === 'Overview') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dns/stats' + _tenantQS() + (_tenantQS() ? '&' : '?') + 'range=month');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DNS spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'unbound-control stats unavailable'); return;
            }
            const g = d.global || {};
            const qt = d.query_types || {};
            const syncLine = await _ddSyncStatusLine('dns');
            // Clustered stats are a SUM across resolvers. Say so, and say when
            // one of them did not answer -- otherwise an under-reported total
            // looks authoritative.
            const statErrors = (d.member_errors && typeof d.member_errors === 'object')
                ? Object.entries(d.member_errors) : [];
            const sourceLine = d.cluster ? `<div class="text-xs text-slate-400 mb-3">Combined across ${d.members_reporting == null ? (d.member_count || 0) : d.members_reporting} of ${d.member_count || 0} resolver(s).</div>` : '';
            // Tenant-scoped: the resolver is shared, so its server-wide cache /
            // recursion counters can't be attributed to one tenant. The hub
            // withholds them (null) and derives totals from this tenant's own
            // devices' queries instead.
            const scoped = !!d.tenant_scoped;
            const scopeLine = scoped ? `<div class="text-xs text-slate-400 mb-3">Showing only queries from this tenant's subnets (last month). Cache and recursion counters are server-wide and hidden on a shared resolver.</div>` : '';
            const statErrorBanner = statErrors.length
                ? `<div class="mb-3 p-3 rounded-md bg-amber-50 border border-amber-200 text-xs text-amber-800">
                    <span class="font-semibold">${statErrors.length} resolver(s) did not report statistics</span>
                    — the totals below exclude them:
                    <ul class="list-disc pl-5 mt-1">
                        ${statErrors.map(([mid, msg]) => `<li><span class="font-mono">${escapeHtml(mid)}</span>: ${escapeHtml(String(msg))}</li>`).join('')}
                    </ul>
                </div>`
                : '';
            const tiles = scoped ? [
                _ddTile('Total Queries', (g.total_queries || 0).toLocaleString(), 'from this tenant'),
                _ddTile('Cache Hit Ratio', '—', 'server-wide only'),
                _ddTile('Recursive Replies', '—', 'server-wide only'),
            ].join('') : [
                _ddTile('Total Queries', (g.total_queries || 0).toLocaleString()),
                _ddTile('Cache Hit Ratio', `${g.cache_hit_ratio || 0}%`, `${(g.cache_hits || 0).toLocaleString()} hits / ${(g.cache_misses || 0).toLocaleString()} miss`,
                        (g.cache_hit_ratio || 0) >= 70 ? 'text-emerald-600' : 'text-amber-600'),
                _ddTile('Recursive Replies', (g.num_recursive || 0).toLocaleString(), `avg ${g.recursion_time_avg || 0}s`),
            ].join('');
            // Per-type query breakdown as proportion-of-total bars.
            const typeTotal = Object.values(qt).reduce((a, b) => a + b, 0) || 1;
            const typeRows = Object.entries(qt).sort((a, b) => b[1] - a[1]).map(([t, c]) => `
                <div class="flex items-center gap-3 py-1">
                    <span class="w-16 text-xs font-mono font-medium text-slate-600">${escapeHtml(t)}</span>
                    <div class="flex-1">${_ddBar(Math.round(c / typeTotal * 100))}</div>
                    <span class="w-20 text-right text-xs font-mono text-slate-500">${c.toLocaleString()}</span>
                </div>`).join('');
            container.innerHTML = `
                ${sourceLine}${scopeLine}${statErrorBanner}
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">${tiles}</div>
                <div class="bg-white border border-slate-200 rounded-lg p-4 mb-4">
                    <div class="text-sm font-semibold text-slate-700 mb-2">Queries by Type</div>
                    ${typeRows || '<p class="text-slate-400 italic text-sm">No query-type data yet.</p>'}
                </div>
                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <div class="flex items-center justify-between mb-2 gap-3">
                        <div class="text-sm font-semibold text-slate-700">Queries by Destination</div>
                        <div class="flex gap-2">
                            <select id="dns-query-range" title="Limit this breakdown to a recent window — the spoke only retains a month of history, so data older than that is already dropped"
                                    class="text-xs border border-slate-300 rounded-md px-2 py-1 focus:outline-none focus:ring-1 focus:ring-blue-400">
                                <option value="day">Last Day</option>
                                <option value="week">Last Week</option>
                                <option value="month" selected>Last Month</option>
                            </select>
                            <input id="dns-query-name-search" type="search" placeholder="Search domain" title="Filter query log by domain or prefix"
                                   class="text-xs border border-slate-300 rounded-md px-2 py-1 w-56 focus:outline-none focus:ring-1 focus:ring-blue-400" />
                            <input id="dns-query-host-search" type="search" placeholder="Search host/IP" title="Filter query log by client host or IP"
                                   class="text-xs border border-slate-300 rounded-md px-2 py-1 w-56 focus:outline-none focus:ring-1 focus:ring-blue-400" />
                        </div>
                    </div>
                    <div id="dns-query-name-list">${_ddQueryNameRows(d.query_names || [], false)}</div>
                </div>
                <div class="bg-white border border-slate-200 rounded-lg p-4 mt-4">
                    <div class="flex items-center justify-between mb-2 gap-3">
                        <div class="text-sm font-semibold text-slate-700">Queries by Device</div>
                        <div class="flex gap-2">
                            <input id="dns-client-ip" type="search" placeholder="Device IP or hostname"
                                   class="text-xs border border-slate-300 rounded-md px-2 py-1 w-56 focus:outline-none focus:ring-1 focus:ring-blue-400" />
                            <select id="dns-client-minutes" class="text-xs border border-slate-300 rounded-md px-2 py-1">
                                <option value="5">Last 5 min</option>
                                <option value="10" selected>Last 10 min</option>
                                <option value="15">Last 15 min</option>
                                <option value="60">Last 60 min</option>
                                <option value="300">Last 300 min</option>
                            </select>
                            <button id="dns-client-go" class="text-xs bg-[#01A982]/10 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md font-bold">Show</button>
                        </div>
                    </div>
                    <div id="dns-client-list"><p class="text-slate-400 italic text-sm">Enter a device IP to list every DNS query it made in the chosen window.</p></div>
                </div>
                ${syncLine}`;
            const clientGo = document.getElementById('dns-client-go');
            if (clientGo) {
                const runClient = async () => {
                    const list = document.getElementById('dns-client-list');
                    const who = (document.getElementById('dns-client-ip').value || '').trim();
                    const mins = document.getElementById('dns-client-minutes').value;
                    list.innerHTML = '<p class="text-sm text-slate-400 italic">Loading…</p>';
                    const qs = (_tenantQS() ? '&' : '?') + 'client=' + encodeURIComponent(who) + '&minutes=' + encodeURIComponent(mins);
                    const { ok: okc, data: dc, detail: det } = await _spokeFetch('/api/dns/client-queries' + _tenantQS() + qs);
                    if (!okc || !dc) { list.innerHTML = `<p class="text-sm text-red-500">${escapeHtml(det || 'Query failed')}</p>`; return; }
                    const qs2 = dc.queries || [];
                    if (!qs2.length) { list.innerHTML = `<p class="text-slate-400 italic text-sm">No queries from ${escapeHtml(who || 'any device')} in the last ${escapeHtml(String(mins))} minutes${dc.source === 'journal' ? ' (read from the journal: query log file not yet active)' : ''}.</p>`; return; }
                    list.innerHTML = `<div class="text-xs text-slate-500 mb-1">${(dc.total || 0).toLocaleString()} queries${dc.total > qs2.length ? ` (showing newest ${qs2.length})` : ''}</div>
                        <div class="max-h-96 overflow-y-auto divide-y divide-slate-100">${qs2.map(q => `
                        <div class="py-1 text-xs flex items-center justify-between gap-3">
                            <span><span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 font-medium mr-2">${escapeHtml(q.type)}</span><span class="font-mono text-slate-700">${escapeHtml(q.name)}</span>${who ? '' : `<span class="text-slate-400 ml-2">${escapeHtml(q.host && q.host !== q.client ? q.host + ' (' + q.client + ')' : q.client)}</span>`}</span>
                            <span class="font-mono text-slate-400 whitespace-nowrap">${new Date(q.time * 1000).toLocaleTimeString()}</span>
                        </div>`).join('')}</div>`;
                };
                clientGo.addEventListener('click', runClient);
                document.getElementById('dns-client-ip').addEventListener('keydown', e => { if (e.key === 'Enter') runClient(); });
            }
            const searchInput = document.getElementById('dns-query-name-search');
            const hostInput = document.getElementById('dns-query-host-search');
            const rangeSelect = document.getElementById('dns-query-range');
            if (searchInput || hostInput || rangeSelect) {
                let debounce;
                const runSearch = () => {
                    clearTimeout(debounce);
                    debounce = setTimeout(async () => {
                        const list = document.getElementById('dns-query-name-list');
                        if (!list) return;
                        const rangeVal = (rangeSelect && rangeSelect.value) || 'month';
                        const params = ['range=' + encodeURIComponent(rangeVal)];
                        if (searchInput && searchInput.value) params.push('search=' + encodeURIComponent(searchInput.value));
                        if (hostInput && hostInput.value) params.push('host=' + encodeURIComponent(hostInput.value));
                        // "Filtered" (for the empty-state message) means the operator
                        // narrowed the view — a non-default range counts, since a
                        // genuinely empty "Last Day" is a narrowing result, not
                        // evidence Unbound has never logged a query.
                        const narrowed = (searchInput && !!searchInput.value) || (hostInput && !!hostInput.value) || rangeVal !== 'month';
                        const qs = (_tenantQS() ? '&' : '?') + params.join('&');
                        const { ok: ok2, data: d2 } = await _spokeFetch('/api/dns/stats' + _tenantQS() + qs);
                        if (ok2 && d2) list.innerHTML = _ddQueryNameRows(d2.query_names || [], narrowed);
                    }, 250);
                };
                if (searchInput) searchInput.addEventListener('input', runSearch);
                if (hostInput) hostInput.addEventListener('input', runSearch);
                if (rangeSelect) rangeSelect.addEventListener('change', runSearch);
            }
            return;
        }

        // ── Diagnostics: explain installed-but-not-queryable Unbound ──────
        if (subMenu === 'Diagnostics') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dns/diagnostics' + _tenantQS());
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DNS diagnostics unavailable'); return; }
            const good = !!d.healthy;
            const svc = d.service || {};
            const cfg = d.config || {};
            const sockets = d.sockets || {};
            const probes = Array.isArray(d.probes) ? d.probes : [];
            const listeners = Array.isArray(sockets.listeners) ? sockets.listeners : [];
            const recommendations = Array.isArray(d.recommendations) ? d.recommendations : [];
            const probeRows = probes.map(p => `<tr class="border-b border-slate-100">
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(p.server || '—')}:53</td>
                <td class="px-4 py-2 font-bold ${p.responded ? 'text-emerald-600' : 'text-red-600'}">${p.responded ? 'Responded' : 'No response'}</td>
                <td class="px-4 py-2 text-xs">${p.rcode == null ? '—' : escapeHtml(String(p.rcode))}</td>
                <td class="px-4 py-2 text-xs">${p.latency_ms == null ? '—' : `${escapeHtml(String(p.latency_ms))} ms`}</td>
                <td class="px-4 py-2 text-xs text-red-600">${escapeHtml(p.error || '')}</td>
            </tr>`).join('');
            const check = (label, pass, detailText) => _ddTile(
                label, pass ? 'PASS' : 'FAIL', detailText || '',
                pass ? 'text-emerald-600' : 'text-red-600');
            // Clustered DNS: the module drives 2+ resolvers. Each member's own
            // interfaces/IPv4s/access-controls/listeners/probes are rendered
            // individually (kind='dns'); the cluster panel separately carries
            // convergence/drift for the whole set.
            const cluster = d.cluster && d.cluster.enabled !== false ? d.cluster : null;
            const clusterPanel = _dnsClusterPanel(cluster);
            const memberEvidence = cluster ? _ddMemberEvidence(d.members, 'dns') : '';
            container.innerHTML = `
                <div class="flex items-center justify-between gap-3 mb-4">
                    <div>
                        <div class="text-sm font-semibold ${good ? 'text-emerald-700' : 'text-red-700'}">${good ? (cluster ? 'DNS cluster healthy' : 'DNS listener healthy') : (cluster ? 'DNS cluster needs attention' : 'DNS listener needs attention')}</div>
                        <div class="text-xs text-slate-400">${cluster ? `Cluster of ${cluster.member_count || 0} resolver(s); each resolver's own checks and evidence are shown below.` : 'Live checks run on the Unbound server.'}</div>
                    </div>
                    <div class="flex items-center gap-2">
                        ${serviceClusterButton('dns', cluster)}
                        <button onclick="loadDNSData('Diagnostics')" title="Run DNS diagnostics again" class="px-3 py-1.5 rounded-md text-xs font-bold bg-white border border-slate-300 hover:bg-slate-50">Run again</button>
                    </div>
                </div>
                ${clusterPanel}
                ${memberEvidence}
                ${cluster ? '' : `
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
                    ${check('Unbound Service', !!svc.ok, svc.output || svc.error || 'inactive')}
                    ${check('Configuration', !!cfg.ok, cfg.output || cfg.error || 'valid')}
                    ${check('Port 53', !!sockets.has_port_53_listener, sockets.has_port_53_listener ? `${listeners.length} listener(s)` : (sockets.error || 'not listening'))}
                    ${check('LAN Listener', !!sockets.has_lan_listener, sockets.has_lan_listener ? 'non-loopback address bound' : 'loopback only or absent')}
                </div>`}
                ${recommendations.length ? `<div class="mb-4 p-4 rounded-lg bg-amber-50 border border-amber-200">
                    <div class="text-sm font-semibold text-amber-800 mb-2">Recommended checks</div>
                    <ul class="list-disc pl-5 space-y-1 text-xs text-amber-800">${recommendations.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>
                </div>` : ''}
                ${cluster ? '' : `
                <div class="grid lg:grid-cols-2 gap-4 mb-4">
                    <div class="bg-white border border-slate-200 rounded-lg p-4">
                        <div class="text-sm font-semibold text-slate-700 mb-2">Configured interfaces</div>
                        <div class="font-mono text-xs text-slate-600">${(d.configured_interfaces || []).map(escapeHtml).join('<br>') || 'none found'}</div>
                        <div class="text-sm font-semibold text-slate-700 mt-4 mb-2">Detected local IPv4 addresses</div>
                        <div class="font-mono text-xs text-slate-600">${(d.local_ipv4s || []).map(escapeHtml).join('<br>') || 'none found'}</div>
                        <div class="text-sm font-semibold text-slate-700 mt-4 mb-2">Access controls</div>
                        <div class="font-mono text-xs text-slate-600">${(d.access_controls || []).map(escapeHtml).join('<br>') || 'none found'}</div>
                    </div>
                    <div class="bg-white border border-slate-200 rounded-lg p-4">
                        <div class="text-sm font-semibold text-slate-700 mb-2">Port 53 listeners</div>
                        <pre class="text-[11px] whitespace-pre-wrap break-all text-slate-600">${escapeHtml(listeners.join('\n') || sockets.error || 'none')}</pre>
                    </div>
                </div>
                <div class="bg-white border border-slate-200 rounded-lg overflow-hidden">
                    <div class="px-4 py-3 text-sm font-semibold text-slate-700 border-b border-slate-200">Local DNS query probes</div>
                    ${tw(th(['Target', 'Result', 'RCODE', 'Latency', 'Error']) + `<tbody>${probeRows}</tbody>`)}
                </div>
                <div class="bg-white border border-slate-200 rounded-lg p-4 mt-4">${_dnsQueryLogPanel(d.query_logging)}</div>`}`;
            return;
        }

        // ── Forwarders: configured upstream resolvers ─────────────────────
        if (subMenu === 'Forwarders') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dns/forwarders' + _tenantQS());
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DNS spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'unbound-control forwarders unavailable'); return;
            }
            const fwds = d.forwarders || [];
            window._dnsForwarders = fwds;
            const showMember = fwds.some(f => f.member_id);
            const cols = (showMember ? ['Member'] : []).concat(['Zone', 'Class', 'Upstream Servers', '']);
            const rows = fwds.map(f => {
                const zoneVal = f.zone || '.';
                const eZone = String(zoneVal).replace(/'/g, "\\'");
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                ${showMember ? `<td class="px-4 py-2 font-mono text-xs">${escapeHtml(f.member_id || '—')}</td>` : ''}
                <td class="px-4 py-2 font-mono font-medium">${escapeHtml(zoneVal)}</td>
                <td class="px-4 py-2 text-xs">${escapeHtml(f.class || 'IN')}</td>
                <td class="px-4 py-2 font-mono text-xs">${(f.upstreams || []).map(u => escapeHtml(u)).join(', ') || '—'}</td>
                <td class="px-4 py-2 whitespace-nowrap text-right">
                    <button onclick="editDnsForwarder('${eZone}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                    <button onclick="deleteDnsForwarder('${eZone}')" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                </td>
            </tr>`;
            }).join('');
            // The cluster fanout (dns_spoke.py's _cluster_forwarders) reports a
            // SUCCESS status + whatever it *could* collect even when one or
            // more members failed to answer — a member drop mid-fanout would
            // otherwise silently shrink this list with nothing on screen to
            // explain it. Surface member_errors (already computed server-side)
            // as a warning instead of a blank/incomplete-looking table.
            const memberErrors = (d.member_errors && typeof d.member_errors === 'object')
                ? Object.entries(d.member_errors) : [];
            const errorBanner = memberErrors.length
                ? `<div class="mb-3 p-3 rounded-md bg-amber-50 border border-amber-200 text-xs text-amber-800">
                    <span class="font-semibold">${memberErrors.length} resolver(s) did not report their forwarders</span>
                    — the list below may be incomplete:
                    <ul class="list-disc pl-5 mt-1">
                        ${memberErrors.map(([mid, msg]) => `<li><span class="font-mono">${escapeHtml(mid)}</span>: ${escapeHtml(String(msg))}</li>`).join('')}
                    </ul>
                </div>`
                : '';
            container.innerHTML = errorBanner + (fwds.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No upstream forwarders configured (Unbound is resolving recursively from root).</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`));
            return;
        }

        // ── Overrides: per-client answer profiles (Unbound views) ──────────
        if (subMenu === 'Overrides') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dns/overrides' + _tenantQS());
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DNS spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'DNS overrides unavailable'); return;
            }
            window._dnsOverrides = d;
            container.innerHTML = _dnsOverridesView(d, editIcon, delIcon);
            loadDnsOverrideLiveCheck();
            return;
        }

        // ── Records (default) ─────────────────────────────────────────────
        const overridesP = _spokeFetch('/api/dns/overrides' + _tenantQS()).catch(() => ({ ok: false }));
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/records?tenant=' + encodeURIComponent(currentTenant));
        if (!ok) {
            container.innerHTML = `${_spokeErrorBanner(detail, 'DNS spoke not connected')}${_isSpokeUpdating(detail) ? '' : '<p class="px-4 pb-4 text-xs text-slate-400">Verify the Unbound configuration in Setup → DNS.</p>'}`;
            _clearTopNavActions();
            return;
        }
        // Only show forward records in the editable list; auto-generated PTRs
        // (type PTR) are derived from A/AAAA values and not directly editable.
        const records = (d.records || []).filter(r => r.type !== 'PTR');
        window._dnsRecords = records;
        // Admin combined view (2+ dns spokes, one per tenant): each record is
        // tagged _tenant by the merge fanout (see net_services.py's
        // _dns_merge_fanout) — show a Tenant column then.
        const showTenantCol = records.some(r => r && r._tenant);
        // Per-client override profiles: show which profile (if any) each
        // device's address is assigned, and offer one-click apply/remove.
        const ovr = await overridesP;
        const overrides = (ovr && ovr.ok && ovr.data && ovr.data.status === 'SUCCESS') ? ovr.data : null;
        window._dnsOverrides = overrides;
        const showOverrideCol = !!(overrides && (overrides.profiles || []).length);
        const canAssign = isAdmin() || isTenantAdmin();
        const cols = (showTenantCol ? ['Tenant'] : []).concat(['Name', 'Value'], showOverrideCol ? ['Override'] : [], ['']);
        const rows = records.map((r, idx) => {
            const eName = String(r.name).replace(/'/g, "\\'");
            const eType = String(r.type).replace(/'/g, "\\'");
            const isHost = r.type === 'A' || r.type === 'AAAA';
            const assigned = (showOverrideCol && isHost) ? _dnsOverrideFor(r.value) : null;
            const overrideCell = !showOverrideCol ? '' : `<td class="px-4 py-2 text-xs whitespace-nowrap">${
                !isHost ? '<span class="text-slate-300">—</span>'
                : `${assigned ? `<span class="px-2 py-0.5 rounded-full font-medium ${assigned.exact ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'}" title="${assigned.exact ? 'Assigned to this device' : 'Inherited from subnet ' + escapeHtml(assigned.target)}">${escapeHtml(assigned.profile)}</span>` : '<span class="text-slate-400">none</span>'}${
                    canAssign ? ` <button onclick="dnsOverrideForRecord(${idx})" title="Apply or remove a DNS override profile for this device or its subnet" class="ml-1 text-[#01A982] hover:underline font-bold">Override…</button>` : ''}`
            }</td>`;
            return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                ${showTenantCol ? `<td class="px-4 py-2 text-xs font-medium text-slate-500">${escapeHtml(r._tenant || '—')}</td>` : ''}
                <td class="px-4 py-2 font-mono font-medium">${escapeHtml(r.name)}</td>
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.value)}</td>
                ${overrideCell}
                <td class="px-4 py-2 whitespace-nowrap">
                    <button onclick="editDnsRecord('${eName}','${eType}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                    <button onclick="deleteDnsRecord('${eName}','${eType}')" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                </td>
            </tr>`;
        }).join('');
        container.innerHTML = _spokeCachedBadge(d) + (records.length === 0
            ? '<p class="p-4 text-slate-400 italic text-sm">No DNS records found.</p>'
            : tw(th(cols) + `<tbody>${rows}</tbody>`));
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}
