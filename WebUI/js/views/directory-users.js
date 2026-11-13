// Directory → Users with OUs. An ES module: classic code (loadLDAPData in
// js/cppm-ldap-users.js) opens it through lmViews.directoryUsers(opts); nothing
// here is a window global. The left panel is the tenant's OU tree (folders
// below the tenant's ou=users, from GET /api/ldap/ous) with user counts; the
// table shows the users of the picked OU. Tenant admins create, rename and
// delete OUs and move users between OUs of their own tenant (the hub takes the
// tenant from the session, so a user can never leave the tenant).
import { safeHtml, rawHtml } from '../core/safe-html.js';
import { createView, delegate } from '../core/view.js';

// Page state. `picked` is the OU path shown in the table: null = every user,
// [] = the top level, ['Eng', 'Lab'] = that OU. `form` is the open inline form.
// `nav` is the page navigation (_lmNavSeq, main.js) the state belongs to.
// `isCurrent()` is false once loadLDAPData started a newer load or the panel
// was hidden; nothing from an older load may redraw or write after that.
const state = {
    tenant: '', users: [], ous: [], rootCount: 0, ouError: '',
    picked: null, form: null, canWrite: false, busy: false, nav: -1,
    isCurrent: () => false,
};

// True while the panel shows the tenant picked in the tenant selector.
function live() {
    return state.isCurrent() && state.tenant === window._ldapTenant;
}

// "Eng/Lab" for a path; "Top level" for [].
function pathLabel(path) {
    return path && path.length ? path.join('/') : 'Top level';
}

// Same path? (null only equals null.)
function samePath(a, b) {
    if (a === null || b === null) return a === b;
    return a.length === b.length && a.every((p, i) => p === b[i]);
}

// The users the table shows for the picked OU (only that OU, not below it,
// matching the per-OU counts).
function shownUsers() {
    if (state.picked === null) return state.users;
    return state.users.filter(u => samePath(u.ou_path || [], state.picked));
}

// One row of the OU tree; indented by depth, with its user count.
function ouRow(path, count) {
    const active = samePath(path, state.picked);
    const cls = active ? 'bg-slate-100 font-bold text-slate-800' : 'text-slate-600 hover:bg-slate-50';
    const pad = path && path.length ? `padding-left:${0.5 + path.length * 0.75}rem` : 'padding-left:0.5rem';
    const name = path === null ? 'All users' : (path.length ? path[path.length - 1] : 'Top level');
    return safeHtml`<button data-action="pick" data-path="${JSON.stringify(path)}"
        title="${path === null ? 'Every user in this tenant' : pathLabel(path)}"
        class="w-full flex justify-between items-center py-1.5 pr-2 rounded text-left text-sm whitespace-nowrap ${cls}" style="${pad}">
        <span class="truncate">${name}</span><span class="text-xs text-slate-500 ml-2">${count}</span></button>`;
}

// The inline form for the open action (new OU, rename OU, move user).
function formHtml() {
    const f = state.form;
    if (!f) return '';
    const inp = 'w-full border border-slate-300 rounded-md px-2 py-1 text-sm';
    const btn = 'px-3 py-1 rounded-md text-xs font-bold';
    const buttons = safeHtml`<div class="flex justify-end gap-2">
        <button data-action="cancel" class="${btn} bg-slate-100 text-slate-600">Cancel</button>
        <button data-action="submit" ${state.busy ? 'disabled' : ''} class="${btn} bg-primary text-white">${f.kind === 'move' ? 'Move' : 'Save'}</button></div>`;
    if (f.kind === 'move') {
        const targets = [[]].concat(state.ous.map(o => o.path));
        return safeHtml`<div class="border-t border-slate-200 pt-3 space-y-2">
            <div class="text-xs text-slate-500 font-bold">Move ${f.uid} to</div>
            <select id="dir-move-target" class="${inp}" title="OU to move the user to">${targets.map(p => safeHtml`
                <option value="${JSON.stringify(p)}" ${samePath(p, f.from) ? 'disabled' : ''}>${pathLabel(p)}</option>`)}</select>
            ${buttons}</div>`;
    }
    const label = f.kind === 'new' ? `New OU in ${pathLabel(f.parent)}` : `Rename ${pathLabel(f.path)}`;
    return safeHtml`<div class="border-t border-slate-200 pt-3 space-y-2">
        <div class="text-xs text-slate-500 font-bold">${label}</div>
        <form data-submit="submit"><input id="dir-ou-name" class="${inp}" value="${f.kind === 'rename' ? f.path[f.path.length - 1] : ''}"
            title="OU name: letters, digits, space, dot, dash, underscore" maxlength="64"></form>
        ${buttons}</div>`;
}

// The OU panel: tree, then the OU actions for the picked OU.
function renderPanel() {
    const picked = state.picked;
    const isOu = picked && picked.length > 0;
    const pickedCount = isOu ? (state.ous.find(o => samePath(o.path, picked)) || {}).user_count || 0 : 0;
    // An OU with child OUs can't be deleted either.
    const hasChildren = isOu && state.ous.some(o => o.path.length > picked.length && samePath(o.path.slice(0, picked.length), picked));
    const act = 'px-2 py-1 rounded-md text-xs font-bold bg-slate-100 text-slate-600 hover:bg-slate-200 disabled:opacity-50';
    const actions = state.canWrite && !state.ouError ? safeHtml`<div class="flex flex-wrap gap-1 pt-2">
        <button data-action="newOu" class="${act}" title="Create an OU inside ${pathLabel(picked || [])}">+ OU</button>
        <button data-action="renameOu" class="${act}" ${isOu ? '' : 'disabled'} title="Rename the selected OU; its users and group memberships follow">Rename</button>
        <button data-action="deleteOu" class="${act}" ${isOu && !pickedCount && !hasChildren ? '' : 'disabled'} title="Delete the selected OU (only when it holds no users or OUs)">Delete</button>
    </div>` : '';
    const tree = state.ouError
        ? safeHtml`<div class="text-xs text-slate-500 p-2">${state.ouError}</div>`
        : [ouRow([], state.rootCount), ...state.ous.map(o => ouRow(o.path, o.user_count || 0))];
    return safeHtml`<div class="space-y-1">
        <div class="text-xs text-slate-500 font-bold px-2 pb-1">OUs</div>
        ${ouRow(null, state.users.length)}${tree}${actions}${formHtml()}</div>`;
}

// The users table rows (the legacy page owns the <thead>/<tbody>).
function renderRows() {
    const users = shownUsers();
    if (!users.length) {
        return safeHtml`<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-500 italic">No users in ${state.picked === null ? 'this tenant' : pathLabel(state.picked)}.</td></tr>`;
    }
    const icon = 'p-1 text-slate-500 transition-colors';
    return safeHtml`${users.map(u => {
        const uid = u.uid || u.username || '';
        const entra = u.auth_mode === 'entra';
        const badge = entra
            ? safeHtml`<span title="Authenticates via Entra — no local password" class="px-2 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-700">Entra</span>`
            : safeHtml`<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-slate-100 text-slate-600">Local</span>`;
        const actions = state.canWrite ? safeHtml`<td class="px-4 py-3 text-right whitespace-nowrap">
            <button data-action="edit" data-uid="${uid}" title="Edit user details" class="${icon} hover:text-blue-600">${rawHtml(LDAP_ICONS.edit)}</button>
            ${entra ? '' : safeHtml`<button data-action="password" data-uid="${uid}" title="Reset user password" class="${icon} hover:text-blue-600">${rawHtml(LDAP_ICONS.pw)}</button>`}
            <button data-action="move" data-uid="${uid}" title="Move to another OU in this tenant" class="${icon} hover:text-blue-600">⇄</button>
            <button data-action="delete" data-uid="${uid}" title="Delete user" class="${icon} hover:text-red-600">${rawHtml(LDAP_ICONS.del)}</button>
        </td>` : safeHtml`<td></td>`;
        const name = u.name || [u.first_name, u.last_name].filter(Boolean).join(' ');
        return safeHtml`<tr class="hover:bg-slate-50 transition-colors">
            <td class="px-4 py-3 font-medium text-slate-700 whitespace-nowrap">${uid}</td>
            <td class="px-4 py-3 text-slate-600 whitespace-nowrap">${name}</td>
            <td class="px-4 py-3">${badge}</td>
            <td class="px-4 py-3 text-slate-600 whitespace-nowrap">${u.email || u.upn || ''}</td>
            <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap">${pathLabel(u.ou_path || [])}</td>
            ${actions}</tr>`;
    })}`;
}

const panelView = createView({ el: 'ldap-ou-panel', state, render: renderPanel });
const rowsView = createView({ el: 'ldap-table-body', state, render: renderRows });

// Redraw both halves.
function refresh() {
    panelView.refresh();
    rowsView.refresh();
}

// Send an OU write to the hub; toast the result and reload the page data.
async function write(method, url, body, done) {
    // Never write for a tenant other than the one selected (mid-switch).
    if (!live()) return;
    const current = state.isCurrent;
    state.busy = true;
    refresh();
    try {
        await apiJson(url, {
            method, headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: state.tenant, ...body }),
        });
        showToast(done, 'success');
        // Reload only if the user is still on this view; else leave the new one.
        if (current()) { state.form = null; loadLDAPData('Users'); }
    } catch (e) {
        showToast(e.message || String(e), 'error');
    } finally {
        state.busy = false;
        if (current()) refresh();
    }
}

// Save the open inline form.
function submitForm() {
    const f = state.form;
    if (!f || state.busy) return;
    if (f.kind === 'move') {
        // Every option is disabled when the user is already in the only place.
        const picked = document.getElementById('dir-move-target').value;
        if (!picked) { showToast('No other OU to move to. Create an OU first.', 'error'); return; }
        const target = JSON.parse(picked);
        return write('POST', '/api/ldap/users/move', { uid: f.uid, target_path: target },
            `Moved ${f.uid} to ${pathLabel(target)}.`);
    }
    const name = (document.getElementById('dir-ou-name')?.value || '').trim();
    if (!name) { showToast('Enter an OU name', 'error'); return; }
    if (f.kind === 'new') {
        return write('POST', '/api/ldap/ous', { name, parent_path: f.parent }, `OU ${name} created.`);
    }
    return write('PUT', '/api/ldap/ous', { path: f.path, new_name: name }, `OU renamed to ${name}.`);
}

// Every button and field in the panel and the table.
const actions = {
    pick: el => { state.picked = JSON.parse(el.dataset.path); state.form = null; refresh(); },
    newOu: () => { state.form = { kind: 'new', parent: state.picked || [] }; refresh(); },
    renameOu: () => { state.form = { kind: 'rename', path: state.picked }; refresh(); },
    // Deleting removes the OU from the directory, so ask first, naming the
    // tenant and OU. A deleted OU drops out of the reloaded list, so the
    // table falls back to all.
    deleteOu: async () => {
        const path = state.picked;
        const tenant = (window._ldapTenants || []).find(t => t.id === state.tenant) || {};
        if (!await showConfirmToast(`Delete OU ${pathLabel(path)} from ${tenant.name || 'this tenant'}'s directory?`)) return;
        return write('DELETE', '/api/ldap/ous', { path }, `OU ${pathLabel(path)} deleted.`);
    },
    cancel: () => { state.form = null; refresh(); },
    submit: () => submitForm(),
    move: el => {
        const u = state.users.find(x => (x.uid || x.username) === el.dataset.uid) || {};
        state.form = { kind: 'move', uid: el.dataset.uid, from: u.ou_path || [] };
        refresh();
    },
    edit: el => editLDAPUser(el.dataset.uid),
    password: el => showLDAPPasswordModal(el.dataset.uid),
    delete: el => deleteLDAPUser(el.dataset.uid),
};

// Entry point from loadLDAPData: draw the Users subview for `tenant`. The OU
// list is fetched here; an older spoke without OUs still shows every user.
// `isCurrent()` is false once loadLDAPData has started a newer load (tenant
// picker, Users/Groups switch), so a late OU reply never redraws old rows.
async function renderDirectoryUsers({ tenant, users, canWrite, isCurrent = () => true }) {
    // A new tenant or a fresh visit to the page starts at "All users"; a
    // reload after a write keeps the picked OU.
    if (tenant !== state.tenant || state.nav !== _lmNavSeq) { state.picked = null; state.form = null; }
    if (tenant !== state.tenant) { state.ous = []; state.rootCount = 0; }
    Object.assign(state, { tenant, users: users || [], canWrite, ouError: '', nav: _lmNavSeq, isCurrent });
    const panel = document.getElementById('ldap-ou-panel');
    const body = document.getElementById('ldap-table-body');
    if (!panel || !body) return;
    panel.classList.remove('hidden');
    delegate(panel, actions);
    delegate(body, actions);
    rowsView.refresh();
    try {
        const data = await apiJson('/api/ldap/ous?tenant=' + encodeURIComponent(tenant));
        if (!isCurrent()) return;  // a newer load started meanwhile
        state.ous = data.ous || [];
        state.rootCount = data.root_user_count || 0;
    } catch (e) {
        if (!isCurrent()) return;
        state.ous = [];
        state.ouError = String(e.message || e).startsWith('501')
            ? 'Update the directory spoke to use OUs.' : `OUs unavailable: ${e.message || e}`;
    }
    // A picked OU that no longer exists (deleted or renamed) falls back to all.
    if (state.picked && state.picked.length && !state.ous.some(o => samePath(o.path, state.picked))) {
        state.picked = null;
    }
    refresh();
}

// Hide the OU panel (Groups subview, or a tenant switch until the new tenant's
// users arrive); nothing from the hidden state may write or redraw.
function hideDirectoryOus() {
    state.isCurrent = () => false;
    state.form = null;
    document.getElementById('ldap-ou-panel')?.classList.add('hidden');
}

// The OU path new users are created in: the picked OU of the selected tenant,
// else the top level.
function directoryOuPath() {
    return live() && state.picked && state.picked.length ? state.picked : [];
}

lmViews.directoryUsers = renderDirectoryUsers;
lmViews.directoryHideOus = hideDirectoryOus;
lmViews.directoryOuPath = directoryOuPath;
