// Directory → AD: the tenant's Active Directory accounts (GET /api/ldap/ad).
// Read-only. An ES module: loadLDAPData (js/cppm-ldap-users.js) opens it
// through lmViews.directoryAd(opts); nothing here is a window global.
// The table lists the accounts of every AD connection of the tenant, with a
// header row per connection. A connection that could not be read shows its
// error in place of its accounts, so "no accounts" and "couldn't ask" differ.
import { safeHtml } from '../core/safe-html.js';
import { createView } from '../core/view.js';

// Page state. `isCurrent()` is false once loadLDAPData started a newer load;
// nothing from an older load may redraw.
const state = {
    tenant: '', loaded: false, configured: true, error: '', connections: [],
    isCurrent: () => false,
};

// The "cached" badge (fleet rule 4.3): only when the list is over 5 minutes old.
function cachedBadge(c) {
    const age = c.cached_at ? Date.now() / 1000 - c.cached_at : 0;
    if (age <= 300) return '';
    const why = c.stale ? 'AD could not be refreshed; showing the last known list' : 'Last read from AD';
    return safeHtml`<span title="${why} ${_relTimeAgo(new Date(c.cached_at * 1000))}" class="ml-2 px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 text-xs font-bold">cached</span>`;
}

// One connection's heading row, then its accounts (or its error).
function connectionRows(c) {
    const cell = 'px-4 py-3 whitespace-nowrap';
    const note = c.truncated ? ' (first 1000 accounts)' : '';
    const head = safeHtml`<tr class="bg-slate-50"><td colspan="100%" class="px-4 py-2 text-xs font-bold text-slate-600">
        ${c.name}${c.domain && c.domain !== c.name ? ` · ${c.domain}` : ''}${note}${cachedBadge(c)}</td></tr>`;
    if (c.error) {
        return safeHtml`${head}<tr><td colspan="100%" class="px-4 py-3 text-red-500">Could not read this AD: ${c.error}</td></tr>`;
    }
    if (!(c.users || []).length) {
        return safeHtml`${head}<tr><td colspan="100%" class="px-4 py-3 text-slate-500 italic">No accounts found.</td></tr>`;
    }
    return safeHtml`${head}${c.users.map(u => {
        // enabled is null when the bind account cannot read userAccountControl.
        const badge = 'px-2 py-0.5 rounded-full text-xs font-bold';
        const status = u.enabled === false
            ? safeHtml`<span class="${badge} bg-slate-100 text-slate-600">Disabled</span>`
            : u.enabled === true
                ? safeHtml`<span class="${badge} bg-blue-100 text-blue-700">Enabled</span>`
                : safeHtml`<span class="${badge} bg-amber-100 text-amber-800" title="The AD bind account cannot read this account's state">Unknown</span>`;
        return safeHtml`<tr class="hover:bg-slate-50 transition-colors">
            <td class="${cell} font-medium text-slate-700">${u.username || ''}</td>
            <td class="${cell} text-slate-600">${u.display_name || ''}</td>
            <td class="${cell} text-slate-500 text-xs">${u.upn || u.email || ''}</td>
            <td class="${cell}">${status}</td></tr>`;
    })}`;
}

// The table body.
function renderRows() {
    const msg = text => safeHtml`<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-500 italic">${text}</td></tr>`;
    if (!state.loaded) return msg('Fetching Active Directory accounts…');
    if (state.error) return safeHtml`<tr><td colspan="100%" class="px-4 py-8 text-center text-red-500">${state.error}</td></tr>`;
    if (!state.configured) return msg('No Active Directory connection for this tenant (a Global Admin adds one under Setup → Module Management).');
    return safeHtml`${state.connections.map(connectionRows)}`;
}

const rowsView = createView({ el: 'ldap-table-body', state, render: renderRows });

// Entry point from loadLDAPData: draw the AD subview for `tenant`.
async function renderDirectoryAd({ tenant, isCurrent = () => true }) {
    Object.assign(state, { tenant, isCurrent, loaded: false, error: '', configured: true, connections: [] });
    rowsView.refresh();
    try {
        const data = await apiJson('/api/ldap/ad?tenant=' + encodeURIComponent(tenant));
        if (!isCurrent()) return;
        Object.assign(state, { configured: data.configured !== false, connections: data.connections || [] });
    } catch (e) {
        if (!isCurrent()) return;
        state.error = `Active Directory unavailable: ${e.message || e}`;
    }
    state.loaded = true;
    rowsView.refresh();
}

lmViews.directoryAd = renderDirectoryAd;
