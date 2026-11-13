// Directory → Entra: the tenant's Entra accounts and groups (GET /api/ldap/entra).
// An ES module: classic code (loadLDAPData in js/cppm-ldap-users.js) opens it
// through lmViews.directoryEntra(opts); nothing here is a window global.
// The left panel lists the tenant's Entra groups ("All accounts" = the
// tenant's base group); the table shows the accounts of the picked group.
// Tenant admins create and delete accounts (password typed, or generated and
// shown once here), create and delete groups, and change group membership.
// Object ids only travel in data-* attributes; the UI shows names and UPNs.
import { safeHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

// Page state. `picked` is the group id shown in the table (null = all
// accounts). `form` is the open inline form; `secret` the one-time password
// box after a create. `isCurrent()` is false once loadLDAPData started a newer
// load or the panel was hidden; nothing from an older load may redraw or write.
const state = {
    tenant: '', loaded: false, configured: true, error: '', users: [], groups: [],
    picked: null, form: null, secret: null, canWrite: false, busy: false, nav: -1,
    cachedAt: null, stale: false, isCurrent: () => false,
};

// Generated passwords whose create finished after the admin left the
// subview ({tenant, user, upn, password}; a list, as several creates can
// finish late). They live only in memory (never in the DOM) until a visit to
// Entra for that tenant shows them one at a time, so a navigation during a
// create cannot lose the only copy of a password. `user` is the LM user who
// made the account: logging out does not reload the page, so only that user
// gets a password back (after a session expiry, for example), never the next
// person to sign in on this browser.
const pendingSecrets = [];

// True while the Entra subview is on screen: not replaced by another Directory
// subview or tenant (isCurrent) and not left for another module (a module
// switch bumps _lmNavSeq without rerunning loadLDAPData).
function onScreen() {
    return state.isCurrent() && state.nav === _lmNavSeq;
}

// The id of the person signed in to LM (currentUser is main.js's global).
// While a Global Admin impersonates someone, user_id is the impersonated
// user, so the admin's own id comes from impersonator.
function userId() {
    return currentUser?.impersonator?.user_id || currentUser?.user_id || '';
}

// Move the next pending password of the shown tenant, made by the signed-in
// user, into the password box.
function takePendingSecret() {
    const i = pendingSecrets.findIndex(p => p.tenant === state.tenant && p.user && p.user === userId());
    if (i < 0) return false;
    [state.secret] = pendingSecrets.splice(i, 1);
    return true;
}

// True while the panel is on screen for the tenant picked in the tenant
// selector. Uses onScreen() so a confirm toast clicked after leaving the
// module cannot send its write.
function live() {
    return onScreen() && state.tenant === window._ldapTenant;
}

// The tenant's own groups (not the base group).
function tenantGroups() {
    return state.groups.filter(g => !g.base);
}

// A tenant group by id.
function groupById(id) {
    return tenantGroups().find(g => g.id === id) || null;
}

// The names of the tenant groups an account is in.
function groupsOf(userId) {
    return tenantGroups().filter(g => (g.members || []).some(m => m.id === userId)).map(g => g.name);
}

// The accounts the table shows: all, or the picked group's members.
function shownUsers() {
    if (state.picked === null) return state.users;
    const g = groupById(state.picked);
    return g ? g.members || [] : [];
}

// One row of the group list, with its member count.
function groupRow(id, name, count, title) {
    const active = id === state.picked;
    const cls = active ? 'bg-slate-100 font-bold text-slate-800' : 'text-slate-600 hover:bg-slate-50';
    return safeHtml`<button data-action="pick" data-id="${id || ''}" title="${title}"
        class="w-full flex justify-between items-center py-1.5 px-2 rounded text-left text-sm whitespace-nowrap ${cls}">
        <span class="truncate">${name}</span><span class="text-xs text-slate-500 ml-2">${count}</span></button>`;
}

// The inline form for the open action (new account, new group, add to group),
// or the one-time password box after an account was created.
function formHtml() {
    const inp = 'w-full border border-slate-300 rounded-md px-2 py-1 text-sm';
    const btn = 'px-3 py-1 rounded-md text-xs font-bold';
    if (state.secret) {
        return safeHtml`<div class="border-t border-slate-200 pt-3 space-y-2">
            <div class="text-xs text-slate-500 font-bold">Password for ${state.secret.upn}</div>
            <code id="entra-secret" class="block bg-slate-100 rounded px-2 py-1 text-sm select-all break-all"
                title="Shown once: copy it now. It is not stored anywhere.">${state.secret.password}</code>
            <div class="flex justify-end"><button data-action="dismiss" class="${btn} bg-slate-100 text-slate-600">Done</button></div></div>`;
    }
    const f = state.form;
    if (!f) return '';
    const buttons = safeHtml`<div class="flex justify-end gap-2">
        <button data-action="cancel" class="${btn} bg-slate-100 text-slate-600">Cancel</button>
        <button data-action="submit" ${state.busy ? 'disabled' : ''} class="${btn} bg-primary text-white">Save</button></div>`;
    if (f.kind === 'account') {
        return safeHtml`<div class="border-t border-slate-200 pt-3 space-y-2">
            <div class="text-xs text-slate-500 font-bold">New Entra account</div>
            <input id="entra-upn" class="${inp}" placeholder="user@domain" title="User principal name (sign-in name) in a verified Entra domain">
            <input id="entra-name" class="${inp}" placeholder="Display name" title="Display name (optional)">
            <input id="entra-password" type="password" data-account-password autocomplete="new-password" class="${inp}" placeholder="Password (blank = generate)"
                title="Typed by you, or leave blank and a password is generated and shown once">
            ${tenantGroups().map(g => safeHtml`<label class="flex items-center gap-2 text-xs text-slate-600">
                <input type="checkbox" class="entra-new-group" value="${g.id}" ${g.id === state.picked ? 'checked' : ''}> ${g.name}</label>`)}
            ${buttons}</div>`;
    }
    if (f.kind === 'group') {
        return safeHtml`<div class="border-t border-slate-200 pt-3 space-y-2">
            <div class="text-xs text-slate-500 font-bold">New Entra group</div>
            <form data-submit="submit"><input id="entra-group-name" class="${inp}" maxlength="64"
                title="Group name: created in Entra as LM-<tenant>-<name>"></form>
            ${buttons}</div>`;
    }
    // Add an account to one of the tenant's groups it is not in yet.
    const options = tenantGroups().filter(g => !(g.members || []).some(m => m.id === f.userId));
    return safeHtml`<div class="border-t border-slate-200 pt-3 space-y-2">
        <div class="text-xs text-slate-500 font-bold">Add ${f.upn} to</div>
        <select id="entra-add-target" class="${inp}" title="Group to add the account to">${options.map(g => safeHtml`
            <option value="${g.id}">${g.name}</option>`)}</select>
        ${buttons}</div>`;
}

// The "cached" badge (caching contract, fleet rule 4.3): shown only when the
// list is more than 5 minutes old; `stale` (Graph refresh failing) only
// changes its tooltip.
function cachedBadge() {
    const age = state.cachedAt ? Date.now() / 1000 - state.cachedAt : 0;
    if (age <= 300) return '';
    const when = state.cachedAt ? ' ' + _relTimeAgo(new Date(state.cachedAt * 1000)) : '';
    const why = state.stale ? 'Entra could not be refreshed; showing the last known list' : 'Last read from Entra';
    return safeHtml`<span id="entra-cached" title="${why}${when}" class="ml-1 px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 text-xs font-bold">cached</span>`;
}

// The group panel: All accounts, the tenant groups, then the actions.
function renderPanel() {
    // The one-time password box survives a failed reload: it is the only copy.
    if (!state.configured || state.error) {
        return state.secret ? safeHtml`<div data-entra-panel class="space-y-1">${formHtml()}</div>` : '';
    }
    const act = 'px-2 py-1 rounded-md text-xs font-bold bg-slate-100 text-slate-600 hover:bg-slate-200 disabled:opacity-50';
    const picked = groupById(state.picked);
    const actions = state.canWrite ? safeHtml`<div class="flex flex-wrap gap-1 pt-2">
        <button data-action="newAccount" class="${act}" ${state.secret ? 'disabled' : ''} title="Create an Entra account for this tenant">+ Account</button>
        <button data-action="newGroup" class="${act}" ${state.secret ? 'disabled' : ''} title="Create an Entra group for this tenant">+ Group</button>
        <button data-action="deleteGroup" class="${act}" ${picked ? '' : 'disabled'} title="Delete the selected group in Entra (its accounts stay)">Delete</button>
    </div>` : '';
    return safeHtml`<div data-entra-panel class="space-y-1">
        <div class="text-xs text-slate-500 font-bold px-2 pb-1">Entra groups${cachedBadge()}</div>
        ${groupRow(null, 'All accounts', state.users.length, "Every Entra account of this tenant")}
        ${tenantGroups().map(g => groupRow(g.id, g.name, (g.members || []).length, g.name))}
        ${actions}${formHtml()}</div>`;
}

// The accounts table rows (the legacy page owns the <thead>/<tbody>).
function renderRows() {
    const msg = text => safeHtml`<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-500 italic">${text}</td></tr>`;
    if (!state.loaded) return msg('Fetching Entra accounts…');
    if (!state.configured) return msg('Entra is not set up (Settings → Single sign-on).');
    if (state.error) return safeHtml`<tr><td colspan="100%" class="px-4 py-8 text-center text-red-500">${state.error}</td></tr>`;
    const users = shownUsers();
    if (!users.length) return msg(state.picked === null ? 'No Entra accounts in this tenant.' : 'No accounts in this group.');
    const icon = 'px-2 py-1 rounded-md text-xs font-bold bg-slate-100 text-slate-600';
    return safeHtml`${users.map(u => {
        const status = u.enabled === false
            ? safeHtml`<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-slate-100 text-slate-600">Disabled</span>`
            : safeHtml`<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-700">Enabled</span>`;
        const inGroup = state.picked !== null;
        const actions = state.canWrite ? safeHtml`<td class="px-4 py-3 text-right whitespace-nowrap space-x-1">
            ${inGroup
                ? safeHtml`<button data-action="removeMember" data-id="${u.id}" title="Remove from this group (the account stays)" class="${icon} hover:text-red-600">Remove</button>`
                : safeHtml`<button data-action="addMember" data-id="${u.id}" ${!state.secret && groupsOf(u.id).length < tenantGroups().length ? '' : 'disabled'} title="Add to one of this tenant's groups" class="${icon} hover:text-blue-600 disabled:opacity-50">+ Group</button>`}
            <button data-action="deleteAccount" data-id="${u.id}" title="Delete the account in Entra" class="${icon} hover:text-red-600">Delete</button>
        </td>` : safeHtml`<td></td>`;
        return safeHtml`<tr class="hover:bg-slate-50 transition-colors">
            <td class="px-4 py-3 font-medium text-slate-700 whitespace-nowrap">${u.upn || ''}</td>
            <td class="px-4 py-3 text-slate-600 whitespace-nowrap">${u.name || ''}</td>
            <td class="px-4 py-3">${status}</td>
            <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap">${groupsOf(u.id).join(', ')}</td>
            ${actions}</tr>`;
    })}`;
}

const panelView = createView({ el: 'ldap-ou-panel', state, render: renderPanel });
const rowsView = createView({ el: 'ldap-table-body', state, render: renderRows });

// Redraw both halves. The panel is hidden while Entra is not set up or the
// list failed (unless a one-time password is shown), so no empty card sits
// next to the message in the table.
function refresh() {
    const panel = document.getElementById('ldap-ou-panel');
    if (panel && state.isCurrent()) panel.classList.toggle('hidden', state.loaded && (!state.configured || !!state.error) && !state.secret);
    panelView.refresh();
    rowsView.refresh();
}

// The UPN of an account id (for messages).
function upnOf(id) {
    return (state.users.find(u => u.id === id) || {}).upn || 'the account';
}

// Send an Entra write to the hub; toast the result and reload the list.
// Returns the reply (even when the page moved on meanwhile: it may hold a
// generated password), or null when it failed or was not sent.
async function write(method, url, body, done) {
    // Step 1: never write for a tenant other than the one selected.
    if (!live() || state.busy) return null;
    const current = state.isCurrent;
    state.busy = true;
    refresh();
    // Step 2: send it; on success close the form and reload this tenant.
    // The reload is not awaited: a page GET cancelled by navigation never
    // settles (lmFetch), and the reply (a generated password) must reach the
    // caller and `busy` must clear whatever the reload does.
    try {
        const reply = await apiJson(url, {
            method, headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: state.tenant, ...body }),
        });
        showToast(done, 'success');
        if (current()) {
            state.form = null;
            load();
        }
        return reply;
    } catch (e) {
        showToast(e.message || String(e), 'error');
        return null;
    } finally {
        // Step 3: re-enable the form if the page is still ours (a fresh
        // visit already reset `busy`; a late write must not clear the flag
        // of a newer one).
        if (current()) {
            state.busy = false;
            refresh();
        }
    }
}

// Save the open inline form.
async function submitForm() {
    const f = state.form;
    if (!f || state.busy) return;
    if (f.kind === 'account') {
        // Create the account; show a generated password once.
        const upn = (document.getElementById('entra-upn')?.value || '').trim();
        if (!upn) { showToast('Enter the account UPN', 'error'); return; }
        const groups = [...document.querySelectorAll('.entra-new-group:checked')].map(el => el.value);
        const tenant = state.tenant;
        const user = userId();
        const reply = await write('POST', '/api/ldap/entra/users', {
            upn, name: (document.getElementById('entra-name')?.value || '').trim(),
            password: document.getElementById('entra-password')?.value || '', group_ids: groups,
        }, `Entra account ${upn} created.`);
        if (reply && reply.password) {
            const secret = { tenant, user, upn: reply.upn || upn, password: reply.password };
            const here = onScreen() && state.tenant === tenant;
            if (here && !state.secret && user === userId()) {
                state.secret = secret;
                refresh();
            } else {
                // The admin left during the create, or another password is
                // still on screen: keep it until it can be shown.
                pendingSecrets.push(secret);
                showToast(here ? `The password for ${secret.upn} is shown after you click Done.`
                    : `Open Directory → Entra to copy the password for ${secret.upn}.`, 'info');
            }
        }
        return;
    }
    if (f.kind === 'group') {
        const name = (document.getElementById('entra-group-name')?.value || '').trim();
        if (!name) { showToast('Enter a group name', 'error'); return; }
        return write('POST', '/api/ldap/entra/groups', { name }, `Entra group ${name} created.`);
    }
    const groupId = document.getElementById('entra-add-target')?.value;
    if (!groupId) { showToast('The account is already in every group', 'error'); return; }
    return write('POST', '/api/ldap/entra/groups/members', { group_id: groupId, user_id: f.userId },
        `${f.upn} added to ${(groupById(groupId) || {}).name || 'the group'}.`);
}

// Every button and field in the panel and the table.
const actions = {
    pick: el => { state.picked = el.dataset.id || null; state.form = null; refresh(); },
    // While a one-time password is shown, the form actions are disabled
    // (and ignored here) so nothing but Done can drop it.
    newAccount: () => { if (state.secret) return; state.form = { kind: 'account' }; refresh(); },
    newGroup: () => { if (state.secret) return; state.form = { kind: 'group' }; refresh(); },
    cancel: () => { state.form = null; refresh(); },
    // Done: close the box, or show the next password still waiting.
    dismiss: () => { state.secret = null; takePendingSecret(); refresh(); },
    submit: () => submitForm(),
    addMember: el => {
        if (state.secret) return;
        state.form = { kind: 'add', userId: el.dataset.id, upn: upnOf(el.dataset.id) };
        refresh();
    },
    removeMember: async el => {
        const g = groupById(state.picked);
        if (!g || !await showConfirmToast(`Remove ${upnOf(el.dataset.id)} from the Entra group ${g.name}?`)) return;
        write('DELETE', '/api/ldap/entra/groups/members', { group_id: g.id, user_id: el.dataset.id },
            `${upnOf(el.dataset.id)} removed from ${g.name}.`);
    },
    deleteAccount: async el => {
        const upn = upnOf(el.dataset.id);
        if (!await showConfirmToast(`Delete the Entra account ${upn}?`)) return;
        write('DELETE', '/api/ldap/entra/users', { id: el.dataset.id }, `Entra account ${upn} deleted.`);
    },
    deleteGroup: async () => {
        const g = groupById(state.picked);
        if (!g || !await showConfirmToast(`Delete the Entra group ${g.name}? Its accounts stay.`)) return;
        write('DELETE', '/api/ldap/entra/groups', { id: g.id }, `Entra group ${g.name} deleted.`);
    },
};

// Fetch the tenant's Entra accounts and groups (from the hub cache) and redraw.
async function load() {
    const current = state.isCurrent;
    try {
        const data = await apiJson('/api/ldap/entra?tenant=' + encodeURIComponent(state.tenant));
        if (!current()) return;
        Object.assign(state, {
            configured: data.configured !== false, users: data.users || [],
            groups: data.groups || [], error: '', loaded: true,
            cachedAt: data.cached_at || null, stale: data.stale === true,
        });
    } catch (e) {
        if (!current()) return;
        // A failed request says nothing about setup; drop an earlier "not set
        // up" answer so the error is what shows.
        Object.assign(state, { error: `Entra unavailable: ${e.message || e}`, configured: true, loaded: true });
    }
    // A picked group that is gone (deleted) falls back to all accounts.
    if (state.picked !== null && !groupById(state.picked)) state.picked = null;
    refresh();
}

// Entry point from loadLDAPData: draw the Entra subview for `tenant`.
async function renderDirectoryEntra({ tenant, canWrite, isCurrent = () => true }) {
    // A new tenant or a fresh visit starts at All accounts with nothing open.
    if (tenant !== state.tenant || state.nav !== _lmNavSeq) {
        Object.assign(state, { picked: null, form: null, secret: null, users: [], groups: [], loaded: false, configured: true, cachedAt: null, stale: false, busy: false });
    }
    Object.assign(state, { tenant, canWrite, nav: _lmNavSeq, isCurrent, error: '' });
    if (!state.secret) takePendingSecret();
    const panel = document.getElementById('ldap-ou-panel');
    const body = document.getElementById('ldap-table-body');
    if (!panel || !body) return;
    panel.classList.remove('hidden');
    // The shared panel's tooltip describes OUs; keep it to restore on leaving.
    if (!('ouTitle' in panel.dataset)) panel.dataset.ouTitle = panel.title;
    panel.title = "This tenant's Entra groups";
    delegate(panel, actions);
    delegate(body, actions);
    refresh();
    await load();
}

// Hide the Entra panel (another subview, a tenant switch, or a reload of
// this one); nothing from the hidden state may write or redraw. A shown
// one-time password goes back to the in-memory queue (only Done drops it),
// and the drawn panel and rows are cleared at once, so it is not left on
// screen while (or if) the next subview's fetch is still running.
function hideDirectoryEntra() {
    state.isCurrent = () => false;
    state.form = null;
    if (state.secret) pendingSecrets.unshift({ tenant: state.tenant, ...state.secret });
    state.secret = null;
    const panel = document.getElementById('ldap-ou-panel');
    if (panel && 'ouTitle' in panel.dataset) panel.title = panel.dataset.ouTitle;
    if (panel && panel.querySelector('[data-entra-panel]')) {
        panel.replaceChildren();
        document.getElementById('ldap-table-body')?.replaceChildren();
    }
}

// "+ Add" in the page header while on the Entra subview: the account form.
function addDirectoryEntra() {
    if (!live() || !state.canWrite) return;
    if (state.secret) { showToast('Copy the password, then click Done first.', 'info'); return; }
    actions.newAccount();
}

lmViews.directoryEntra = renderDirectoryEntra;
lmViews.directoryHideEntra = hideDirectoryEntra;
lmViews.directoryEntraAdd = addDirectoryEntra;
