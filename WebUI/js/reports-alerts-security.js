// reports-alerts-security.js — Reports, alert rules, subscriptions, security blocklist, credential vault, log analysis, bug reports.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ── Reports module (Setup → Reports nav, gated by the ``reports`` right) ──────
// First report: the Simulations Dashboard → Checks + Client Count, tenant-scoped
// (a tenant only ever sees its own sites). A Global Admin can switch tenant in the
// header and manage/run any tenant's report. Config + send: /api/reports/email-report.
async function loadReportsData() {
    const el = document.getElementById('reports-content');
    if (!el) return;
    el.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    let reports = [];
    try {
        reports = ((await apiJson('/api/reports/list?tenant=' + encodeURIComponent(currentTenant))) || {}).reports || [];
    } catch (e) { el.innerHTML = `<div class="hpe-card rounded-lg p-5 text-red-600">Could not load reports: ${escapeHtml(e.message || String(e))}</div>`; return; }
    window._reportsCache = reports;
    const freqLabel = s => { s = s || {}; const f = s.freq || 'weekly'; const when = f === 'weekly' ? ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][s.dow || 0] : (f === 'monthly' ? ('day ' + (s.dom || 1)) : ''); return `${f}${when ? ' ' + when : ''} @ ${String(s.hour != null ? s.hour : 7).padStart(2, '0')}:00`; };
    const rows = reports.length ? reports.map(r => `<tr class="border-b border-slate-100">
        <td class="px-3 py-2"><span class="font-semibold text-slate-700">${escapeHtml(r.name || '')}</span></td>
        <td class="px-3 py-2 text-slate-500">${escapeHtml(r.tenant || '')}</td>
        <td class="px-3 py-2 text-slate-500 text-xs">${[r.sections && r.sections.checks ? 'Checks' : '', r.sections && r.sections.clients ? 'Client Count' : ''].filter(Boolean).join(', ') || '—'}</td>
        <td class="px-3 py-2 text-slate-500 text-xs">${escapeHtml((r.recipients || []).join(', ')) || '—'}</td>
        <td class="px-3 py-2 text-slate-500 text-xs">${escapeHtml(freqLabel(r.schedule))}</td>
        <td class="px-3 py-2">${r.enabled ? '<span class="text-green-600 text-xs font-bold">on</span>' : '<span class="text-slate-400 text-xs">off</span>'}</td>
        <td class="px-3 py-2 text-right whitespace-nowrap">
          <button onclick="testReport('${r.id}')" class="text-xs text-slate-500 hover:text-slate-700 mr-2">Test</button>
          <button onclick="editReport('${r.id}')" class="text-xs text-[#01A982] hover:underline mr-2">Edit</button>
          <button onclick="deleteReport('${r.id}')" class="text-xs text-red-500 hover:text-red-700">Delete</button></td></tr>`).join('') : '<tr><td colspan="7" class="px-3 py-4 text-slate-400 italic">No reports yet — click "Add report".</td></tr>';
    el.innerHTML = `<div class="hpe-card rounded-lg p-5 shadow-sm">
      <div class="flex items-center justify-between mb-3">
        <p class="text-xs text-slate-400 max-w-2xl">Emailed reports — each sends a tenant's Dashboard <b>Checks</b> + <b>Client Count</b> to its recipients on a schedule (via the provider under Setup → Notifications). A Global Admin can target any tenant; a tenant user sees only its own.</p>
        <button onclick="editReport('')" class="shrink-0 bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-sm font-bold">+ Add report</button>
      </div>
      <div class="overflow-x-auto"><table class="w-full text-sm"><thead class="text-[10px] uppercase text-slate-400"><tr><th class="px-3 py-1 text-left">Name</th><th class="px-3 py-1 text-left">Tenant</th><th class="px-3 py-1 text-left">Sections</th><th class="px-3 py-1 text-left">Recipients</th><th class="px-3 py-1 text-left">Schedule</th><th class="px-3 py-1 text-left">On</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    </div>
    <div id="alerts-content" class="hpe-card rounded-lg p-5 shadow-sm mt-4"><p class="text-sm text-slate-400 italic">Loading alert rules…</p></div>
`;
    loadAlertRules();
}

// ── Alert Rules (edge-triggered breach + recovery) ──────────────────────────
// One tile for every alert kind. Realtime rules are per-tenant (/api/alerts/rules);
// Cert Monitor rules are hub-wide (/api/certmon/alerts/rules) and are listed +
// offered as sources only to a Global Admin while the monitor is enabled.
const _ALERT_SRCL = { dashboard_check: 'Dashboard check breach', vm_offline: 'VM / hypervisor offline', quota_unmet: "Quota engine can't meet requirement", adaptive_quota_maxed: 'Adaptive quota — at max, alert not firing', spoke_offline: 'Spoke / agent offline', cert_issue_failed: 'Certificate Request Failed', cert_renew_failed: 'Certificate Renewal Failed', cert_deploy_failed: 'Certificate Deploy Failed', bulk_dongle_failure: 'Dongle quarantine — bulk client failure', single_bus_failing: 'Dongle quarantine — single bus failing' };
const _certMonAlertsAllowed = () => isAdmin() && !!window.__lmCertMonEnabled;

async function loadAlertRules() {
    const el = document.getElementById('alerts-content');
    if (!el) return;
    let d = {};
    try {
        const r = await setupFetch('/api/alerts/rules?tenant=' + encodeURIComponent(currentTenant || 'default'));
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || ('HTTP ' + r.status));
        d = await r.json();
    } catch (e) { el.innerHTML = `<p class="text-sm text-red-500">Could not load alert rules: ${escapeHtml(e.message)}</p>`; return; }
    window._alertSources = d.sources || [];
    window._alertRulesCache = d.rules || [];
    window._certMonAlertMeta = null;
    let certErr = '';
    if (_certMonAlertsAllowed()) {
        try {
            const r = await setupFetch('/api/certmon/alerts/rules');
            const cd = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(cd.detail || ('HTTP ' + r.status));
            window._certMonAlertMeta = cd;
        } catch (e) { certErr = e.message; }
    }
    const certRules = (window._certMonAlertMeta && window._certMonAlertMeta.rules) || [];
    const fmt = r => r.format === 'raw' ? '<span class="text-purple-600 font-mono">raw/JSON</span>' : '<span class="text-slate-500">human</span>';
    const row = (r, kind, srcHtml) => `<tr class="border-b border-slate-100">
        <td class="px-3 py-2"><span class="font-semibold text-slate-700">${escapeHtml(r.name || '')}</span></td>
        <td class="px-3 py-2 text-slate-500 text-xs">${srcHtml}</td>
        <td class="px-3 py-2 text-xs">${fmt(r)}</td>
        <td class="px-3 py-2 text-slate-500 text-xs">${escapeHtml((r.recipients || []).join(', ')) || '—'}</td>
        <td class="px-3 py-2">${r.enabled ? '<span class="text-green-600 text-xs font-bold">on</span>' : '<span class="text-slate-400 text-xs">off</span>'}</td>
        <td class="px-3 py-2 text-right whitespace-nowrap"><button onclick="testAlertRule('${escapeHtml(r.id)}', '${kind}')" class="text-xs text-slate-500 hover:text-slate-700 mr-2">Test</button><button onclick="editAlertRule('${escapeHtml(r.id)}', '${kind}')" class="text-xs text-[#01A982] hover:underline mr-2">Edit</button><button onclick="deleteAlertRule('${escapeHtml(r.id)}', '${kind}')" class="text-xs text-red-500 hover:text-red-700">Delete</button></td></tr>`;
    const rowsArr = (d.rules || []).map(r => row(r, 'sim', escapeHtml(_ALERT_SRCL[r.source] || r.source || '')))
        .concat(certRules.map(r => row(r, 'certmon', `Cert Monitor — ${escapeHtml(_certMonRuleWhat(r))} <span class="text-[10px] text-slate-400">(hub-wide)</span>`)));
    const rows = rowsArr.length ? rowsArr.join('') : '<tr><td colspan="6" class="px-3 py-4 text-slate-400 italic">No alert rules — click "Add alert".</td></tr>';
    el.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <div><p class="text-sm font-bold text-slate-600">Alert Rules <span class="text-slate-400 font-normal">— ${escapeHtml(currentTenant || 'default')}</span></p><p class="text-xs text-slate-400 max-w-xl">One email when a monitored source breaches, one on recovery; Cert Monitor rules can also remind on a schedule. Pick a source + who to notify. Delivered via Setup → Notifications.</p></div>
        <button onclick="editAlertRule('')" class="shrink-0 bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 border border-amber-500 px-3 py-1.5 rounded-md text-sm font-bold">+ Add alert</button>
      </div>
      ${certErr ? `<p class="text-xs text-red-500 mb-2">Could not load Cert Monitor alert rules: ${escapeHtml(certErr)}</p>` : ''}
      <div class="overflow-x-auto"><table class="w-full text-sm"><thead class="text-[10px] uppercase text-slate-400"><tr><th class="px-3 py-1 text-left">Name</th><th class="px-3 py-1 text-left">Source</th><th class="px-3 py-1 text-left">Format</th><th class="px-3 py-1 text-left">Recipients</th><th class="px-3 py-1 text-left">On</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function _certMonRuleWhat(r) {
    const L = window._certMonAlertMeta?.trigger_labels || {};
    const base = r.trigger === 'expiring' ? `Expiring in < ${r.threshold_days} days` : (L[r.trigger] || r.trigger);
    return base + ((r.services || []).length ? ` · ${r.services.join(', ')}` : ' · all services') + ' · ' + _certMonCadence(r);
}

// "once", "every 24h", "once; <7d every 24h; expired every 6h" …
function _certMonCadence(r) {
    const every = h => h ? `every ${h}h` : 'once';
    const steps = (r.reminders || []).map(st => `${st.days > 0 ? '<' + st.days + 'd' : (st.days === 0 ? 'expired' : 'expired >' + (-st.days) + 'd')} ${every(st.every_hours)}`);
    return [every(r.repeat_hours || 0)].concat(steps).join('; ');
}

function _alrStepRow(st) {
    return `<div class="alr-step flex items-center gap-2 text-xs text-slate-600">
        <span>fewer than</span><input type="number" min="-365" max="825" class="alr-step-days w-16 border border-slate-300 rounded px-2 py-1" value="${escapeHtml(String(st.days))}"><span>days left → every</span>
        <input type="number" min="0" max="720" class="alr-step-hours w-16 border border-slate-300 rounded px-2 py-1" value="${escapeHtml(String(st.every_hours))}"><span>hours</span>
        <button type="button" onclick="this.closest('.alr-step').remove()" class="text-red-500 hover:text-red-700 ml-auto" title="Remove step">&times;</button></div>`;
}
function _alrAddStep() {
    document.getElementById('alr-steps')?.insertAdjacentHTML('beforeend', _alrStepRow({ days: 0, every_hours: 6 }));
}

// A Cert Monitor source is encoded as "certmon:<trigger>" in the source picker.
function _alrSourceChanged() {
    const v = (document.getElementById('alr-source') || {}).value || '';
    const cert = v.startsWith('certmon:');
    const w = document.getElementById('alr-cert-w');
    const dw = document.getElementById('alr-days-w');
    const lw = document.getElementById('alr-ladder-w');
    if (w) w.style.display = cert ? '' : 'none';
    if (dw) dw.style.display = v === 'certmon:expiring' ? '' : 'none';
    if (lw) lw.style.display = v === 'certmon:expiring' ? '' : 'none';
}

function editAlertRule(id, kind) {
    const meta = window._certMonAlertMeta || null;
    const isCert = kind === 'certmon';
    const existing = id ? ((isCert ? (meta && meta.rules) : window._alertRulesCache) || []).find(r => r.id === id) || null : null;
    const sources = (window._alertSources && window._alertSources.length) ? window._alertSources : ['dashboard_check', 'vm_offline', 'quota_unmet', 'spoke_offline'];
    const L = (meta && meta.trigger_labels) || {};
    const trig = (meta && meta.triggers && meta.triggers.length) ? meta.triggers : ['expiring', 'error', 'untrusted'];
    const selVal = existing ? (isCert ? 'certmon:' + existing.trigger : existing.source) : '';
    // An existing rule can't switch store (tenant ↔ hub-wide), so editing offers only its own kind.
    const simOpts = sources.map(s => `<option value="${escapeHtml(s)}" ${selVal === s ? 'selected' : ''}>${escapeHtml(_ALERT_SRCL[s] || s)}</option>`).join('');
    const certOpts = trig.map(t => `<option value="certmon:${escapeHtml(t)}" ${selVal === 'certmon:' + t ? 'selected' : ''}>${escapeHtml(L[t] || t)}</option>`).join('');
    const showSim = !existing || !isCert;
    const showCert = meta && (!existing || isCert);
    const srcOpts = (showSim ? (showCert ? `<optgroup label="Realtime (${escapeHtml(currentTenant || 'default')})">${simOpts}</optgroup>` : simOpts) : '')
        + (showCert ? `<optgroup label="Cert Expiry Monitor (hub-wide)">${certOpts}</optgroup>` : '');
    const svcSel = new Set(isCert && existing ? (existing.services || []) : []);
    const svcBoxes = ((meta && meta.services) || []).map(s => `<label class="flex items-center gap-2"><input type="checkbox" class="alr-svc w-4 h-4 rounded" value="${escapeHtml(s)}" ${svcSel.has(s) ? 'checked' : ''}> ${escapeHtml(s)}</label>`).join('');
    const days = isCert && existing ? existing.threshold_days : ((meta && meta.default_threshold_days) || 30);
    const repeatH = isCert && existing ? (existing.repeat_hours || 0) : 0;
    // New rules start with an example ladder: daily inside a week, every 6h once expired.
    const steps = isCert && existing ? (existing.reminders || []) : [{ days: 7, every_hours: 24 }, { days: 0, every_hours: 6 }];
    document.getElementById('alert-edit-modal')?.remove();
    const modal = document.createElement('div');
    modal.id = 'alert-edit-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    const inner = document.createElement('div');
    inner.className = 'bg-white rounded-xl shadow-xl w-full max-w-lg p-6 space-y-3 max-h-[90vh] overflow-y-auto';
    inner.innerHTML = `
      <div class="flex justify-between items-start"><p class="font-bold text-base text-[#263040]">${existing ? 'Edit alert rule' : 'New alert rule'}</p><button class="alr-close text-slate-400 hover:text-slate-600 text-xl leading-none">&times;</button></div>
      <label class="block text-xs text-slate-500">Name<input id="alr-name" value="${escapeHtml(existing ? existing.name : '')}" placeholder="VM offline → NOC" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm"></label>
      <label class="block text-xs text-slate-500">Source (what to watch)<select id="alr-source" onchange="_alrSourceChanged()" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm">${srcOpts}</select></label>
      <div id="alr-cert-w" class="space-y-3" style="display:none">
        <label id="alr-days-w" class="block text-xs text-slate-500">Alert when fewer than N days are left<input id="alr-days" type="number" min="1" max="825" value="${escapeHtml(String(days))}" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm"><span class="block text-[11px] text-slate-400 mt-1">Expired certs always match.</span></label>
        <label class="block text-xs text-slate-500">Repeat every N hours while still bad<input id="alr-repeat" type="number" min="0" max="720" value="${escapeHtml(String(repeatH))}" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm"><span class="block text-[11px] text-slate-400 mt-1">0 = one email when it first breaches (plus one on recovery).</span></label>
        <div id="alr-ladder-w" class="text-xs text-slate-500">Escalation <span class="text-slate-400">(overrides the repeat as expiry gets closer)</span>
          <div id="alr-steps" class="space-y-1 mt-1">${steps.map(_alrStepRow).join('')}</div>
          <button type="button" onclick="_alrAddStep()" class="mt-1 text-[#01A982] hover:underline">+ Add step</button>
          <span class="block text-[11px] text-slate-400 mt-1">0 days = expired. 0 hours = one email on entering the step. Entering a more urgent step emails right away.</span></div>
        <div class="text-xs text-slate-500">Services <span class="text-slate-400">(none ticked = all)</span><div class="grid grid-cols-2 gap-1 mt-1 text-slate-600">${svcBoxes}</div></div>
      </div>
      <label class="block text-xs text-slate-500">Format<select id="alr-format" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm">
        <option value="human" ${!existing || existing.format !== 'raw' ? 'selected' : ''}>Human — formatted email</option>
        <option value="raw" ${existing && existing.format === 'raw' ? 'selected' : ''}>Raw — JSON body (for automation to ingest)</option>
      </select><span class="block text-[11px] text-slate-400 mt-1">Human = a person; Raw = a system/automation mailbox. Add two rules on one source to send both.</span></label>
      <label class="block text-xs text-slate-500">Recipients <span class="text-slate-400">(comma-separated)</span><input id="alr-recips" value="${escapeHtml(existing ? (existing.recipients || []).join(', ') : '')}" placeholder="noc@acme.com" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm"></label>
      <label class="flex items-center gap-2 text-xs text-slate-600 pt-1"><input type="checkbox" id="alr-enabled" ${!existing || existing.enabled ? 'checked' : ''} class="w-4 h-4 rounded"> Enabled</label>
      <div id="alr-result" class="text-xs"></div>
      <div class="flex justify-end gap-2 pt-1"><button class="alr-cancel bg-slate-200 text-slate-700 px-4 py-2 rounded text-sm font-bold">Cancel</button><button id="alr-save" class="bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 border border-amber-500 px-4 py-2 rounded text-sm font-bold">Save</button></div>`;
    modal.appendChild(inner);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    inner.querySelector('.alr-close').addEventListener('click', () => modal.remove());
    inner.querySelector('.alr-cancel').addEventListener('click', () => modal.remove());
    document.body.appendChild(modal);
    _alrSourceChanged();
    document.getElementById('alr-save').addEventListener('click', () => saveAlertRule(existing ? existing.id : ''));
}
async function saveAlertRule(id) {
    const v = x => document.getElementById(x);
    const resEl = v('alr-result');
    const src = v('alr-source').value || '';
    const common = { name: (v('alr-name').value || '').trim(), format: v('alr-format').value, recipients: (v('alr-recips').value || '').split(',').map(x => x.trim()).filter(Boolean), enabled: v('alr-enabled').checked };
    let url, body;
    if (src.startsWith('certmon:')) {
        body = Object.assign(common, {
            trigger: src.slice('certmon:'.length),
            threshold_days: parseInt(v('alr-days').value, 10) || 30,
            repeat_hours: parseInt(v('alr-repeat').value, 10) || 0,
            reminders: Array.from(document.querySelectorAll('#alr-steps .alr-step')).map(row => ({
                days: row.querySelector('.alr-step-days').value,
                every_hours: parseInt(row.querySelector('.alr-step-hours').value, 10) || 0,
            })).filter(st => st.days !== '').map(st => Object.assign(st, { days: parseInt(st.days, 10) })),
            services: Array.from(document.querySelectorAll('#alert-edit-modal .alr-svc:checked')).map(x => x.value),
        });
        url = id ? ('/api/certmon/alerts/rules/' + encodeURIComponent(id)) : '/api/certmon/alerts/rules';
    } else {
        body = Object.assign(common, { source: src });
        url = (id ? ('/api/alerts/rules/' + id) : '/api/alerts/rules') + '?tenant=' + encodeURIComponent(currentTenant || 'default');
    }
    try {
        const r = await setupFetch(url, { method: id ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));
        document.getElementById('alert-edit-modal')?.remove();
        showToast('Alert rule saved.', 'success');
        loadAlertRules();
    } catch (e) { if (resEl) resEl.innerHTML = `<span class="text-red-500">${escapeHtml(e.message)}</span>`; }
}
async function deleteAlertRule(id, kind) {
    if (kind === 'certmon') return deleteCertMonAlertRule(id);
    if (!confirm('Delete this alert rule?')) return;
    const t = 'tenant=' + encodeURIComponent(currentTenant || 'default');
    try { const r = await setupFetch('/api/alerts/rules/' + id + '?' + t, { method: 'DELETE' }); if (!r.ok) throw new Error('HTTP ' + r.status); showToast('Alert rule deleted.', 'success'); loadAlertRules(); }
    catch (e) { showToast('Delete failed: ' + e.message, 'error'); }
}
async function testAlertRule(id, kind) {
    if (kind === 'certmon') return testCertMonAlertRule(id);
    showToast('Sending test…', 'info');
    const t = 'tenant=' + encodeURIComponent(currentTenant || 'default');
    try { const r = await setupFetch('/api/alerts/rules/' + id + '/test?' + t, { method: 'POST' }); const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status)); showToast('Test alert sent to ' + ((d.to || []).join(', ') || 'recipients'), 'success'); }
    catch (e) { showToast('Send failed: ' + e.message, 'error'); }
}

async function editReport(id) {
    const existing = (window._reportsCache || []).find(r => r.id === id) || null;
    let tenants = [];
    try { const r = await setupFetch('/api/reports/tenants'); tenants = ((await r.json()).tenants) || []; } catch (e) { }
    document.getElementById('report-edit-modal')?.remove();
    const modal = document.createElement('div');
    modal.id = 'report-edit-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    const s = (existing && existing.schedule) || { freq: 'weekly', dow: 0, dom: 1, hour: 7 };
    const sec = (existing && existing.sections) || { checks: true, clients: true };
    const tOpts = tenants.map(t => `<option value="${escapeHtml(t.id)}" ${existing && existing.tenant === t.id ? 'selected' : ''}>${escapeHtml(t.name)} (${escapeHtml(t.id)})</option>`).join('') || '<option value="default">ADMIN (default)</option>';
    const freqOpts = ['daily', 'weekly', 'monthly'].map(f => `<option value="${f}" ${s.freq === f ? 'selected' : ''}>${f}</option>`).join('');
    const dowOpts = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((d, i) => `<option value="${i}" ${s.dow == i ? 'selected' : ''}>${d}</option>`).join('');
    const hourOpts = Array.from({ length: 24 }, (_, h) => `<option value="${h}" ${s.hour == h ? 'selected' : ''}>${String(h).padStart(2, '0')}:00</option>`).join('');
    const inner = document.createElement('div');
    inner.className = 'bg-white rounded-xl shadow-xl w-full max-w-lg p-6 space-y-3 max-h-[90vh] overflow-y-auto';
    inner.innerHTML = `
      <div class="flex justify-between items-start"><p class="font-bold text-base text-[#263040]">${existing ? 'Edit report' : 'New report'}</p><button class="rpt-close text-slate-400 hover:text-slate-600 text-xl leading-none">&times;</button></div>
      <label class="block text-xs text-slate-500">Name<input id="rpt-name" value="${escapeHtml(existing ? existing.name : '')}" placeholder="Weekly Acme dashboard" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm"></label>
      <label class="block text-xs text-slate-500">Tenant dashboard to email<select id="rpt-tenant" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm">${tOpts}</select></label>
      <div class="flex gap-4 text-xs text-slate-600 pt-1">
        <label class="flex items-center gap-2"><input type="checkbox" id="rpt-checks" ${sec.checks !== false ? 'checked' : ''} class="w-4 h-4 rounded"> Dashboard Checks</label>
        <label class="flex items-center gap-2"><input type="checkbox" id="rpt-clients" ${sec.clients !== false ? 'checked' : ''} class="w-4 h-4 rounded"> Client Count</label>
      </div>
      <label class="block text-xs text-slate-500">Recipients <span class="text-slate-400">(comma-separated)</span><input id="rpt-recips" value="${escapeHtml(existing ? (existing.recipients || []).join(', ') : '')}" placeholder="noc@acme.com, ops@acme.com" class="w-full mt-1 border border-slate-300 rounded px-3 py-2 text-sm"></label>
      <div class="grid grid-cols-3 gap-2 text-xs text-slate-500">
        <label>Frequency<select id="rpt-freq" onchange="_rptWhen()" class="w-full mt-1 border border-slate-300 rounded px-2 py-2">${freqOpts}</select></label>
        <label id="rpt-dow-w">Day of week<select id="rpt-dow" class="w-full mt-1 border border-slate-300 rounded px-2 py-2">${dowOpts}</select></label>
        <label id="rpt-dom-w" style="display:none">Day of month<input id="rpt-dom" type="number" min="1" max="28" value="${s.dom || 1}" class="w-full mt-1 border border-slate-300 rounded px-2 py-2"></label>
        <label>Hour<select id="rpt-hour" class="w-full mt-1 border border-slate-300 rounded px-2 py-2">${hourOpts}</select></label>
      </div>
      <label class="flex items-center gap-2 text-xs text-slate-600 pt-1"><input type="checkbox" id="rpt-enabled" ${existing && existing.enabled ? 'checked' : ''} class="w-4 h-4 rounded"> Enabled (send on the schedule)</label>
      <div id="rpt-result" class="text-xs"></div>
      <div class="flex justify-end gap-2 pt-1"><button class="rpt-cancel bg-slate-200 text-slate-700 px-4 py-2 rounded text-sm font-bold">Cancel</button><button id="rpt-save" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded text-sm font-bold">Save</button></div>`;
    modal.appendChild(inner);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    inner.querySelector('.rpt-close').addEventListener('click', () => modal.remove());
    inner.querySelector('.rpt-cancel').addEventListener('click', () => modal.remove());
    _mountModal(modal);
    _rptWhen();
    document.getElementById('rpt-save').addEventListener('click', () => saveReport(existing ? existing.id : ''));
}
function _rptWhen() {
    const f = document.getElementById('rpt-freq') && document.getElementById('rpt-freq').value;
    const dw = document.getElementById('rpt-dow-w'), dm = document.getElementById('rpt-dom-w');
    if (dw) dw.style.display = f === 'weekly' ? '' : 'none';
    if (dm) dm.style.display = f === 'monthly' ? '' : 'none';
}
async function saveReport(id) {
    const v = x => document.getElementById(x);
    const resEl = v('rpt-result');
    const body = {
        name: (v('rpt-name').value || '').trim(),
        tenant: v('rpt-tenant').value,
        sections: { checks: v('rpt-checks').checked, clients: v('rpt-clients').checked },
        recipients: (v('rpt-recips').value || '').split(',').map(x => x.trim()).filter(Boolean),
        schedule: { freq: v('rpt-freq').value, dow: parseInt(v('rpt-dow').value, 10) || 0, dom: parseInt(v('rpt-dom').value, 10) || 1, hour: parseInt(v('rpt-hour').value, 10) || 7 },
        enabled: v('rpt-enabled').checked,
    };
    try {
        const r = await setupFetch(id ? ('/api/reports/' + id) : '/api/reports', { method: id ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));
        document.getElementById('report-edit-modal')?.remove();
        showToast('Report saved.', 'success');
        loadReportsData();
    } catch (e) { if (resEl) resEl.innerHTML = `<span class="text-red-500">${escapeHtml(e.message)}</span>`; }
}
async function deleteReport(id) {
    if (!confirm('Delete this report?')) return;
    try {
        const r = await setupFetch('/api/reports/' + id, { method: 'DELETE' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        showToast('Report deleted.', 'success');
        loadReportsData();
    } catch (e) { showToast('Delete failed: ' + e.message, 'error'); }
}
async function testReport(id) {
    showToast('Sending test…', 'info');
    try {
        const r = await setupFetch('/api/reports/' + id + '/test', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));
        showToast('Test sent to ' + ((d.to || []).join(', ') || 'recipients'), 'success');
    } catch (e) { showToast('Send failed: ' + e.message, 'error'); }
}

// ── Cert Expiry Monitor (Global Admin only, opt-in) ─────────────────────────
// Backed by routes/cert_monitor.py (/api/certmon/*). The left-nav item only
// renders while window.__lmCertMonEnabled is true (refreshed on each status
// poll, throttled); the toggle lives in System → General.
let _certMonFlagAt = 0;
async function _refreshCertMonFlag(force = false) {
    if (!isAdmin()) { window.__lmCertMonEnabled = false; return; }
    const now = Date.now();
    if (!force && now - _certMonFlagAt < 60000) return;
    _certMonFlagAt = now;
    try {
        const r = await fetch('/api/certmon/status', { credentials: 'same-origin' });
        if (!r.ok) return;
        const d = await r.json();
        const on = !!d.enabled;
        if (on !== !!window.__lmCertMonEnabled) {
            window.__lmCertMonEnabled = on;
            if (window.__lmNavArgs) _rebuildMainNav(...window.__lmNavArgs);
            if (!on && currentView === 'certmon') setView('dashboard');
        }
    } catch (e) { /* transient — next poll retries */ }
}

async function loadCertMonToggle() {
    const cb = document.getElementById('certmon-enabled');
    if (!cb) return;
    try {
        const r = await setupFetch('/api/certmon/status');
        if (r.ok) cb.checked = !!(await r.json()).enabled;
    } catch (e) { /* leave unchecked */ }
}

async function _certMonPutConfig(body) {
    const r = await setupFetch('/api/certmon/config', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));
    return d;
}

async function saveCertMonEnabled(cb) {
    const want = !!cb.checked;
    try {
        const d = await _certMonPutConfig({ enabled: want });
        showToast(want ? ('Cert Expiry Monitor enabled' + (d.check_started ? ' — first check running' : '')) : 'Cert Expiry Monitor disabled', 'success');
        await _refreshCertMonFlag(true);
    } catch (e) {
        cb.checked = !want;
        showToast('Save failed: ' + e.message, 'error');
    }
}

function _certMonDate(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); } catch (e) { return iso; }
}

async function loadCertMonData() {
    const el = document.getElementById('certmon-content');
    if (!el) return;
    let d;
    try {
        const r = await setupFetch('/api/certmon/overview');
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || ('HTTP ' + r.status));
        d = await r.json();
    } catch (e) {
        el.innerHTML = `<div class="hpe-card rounded-lg p-5"><p class="text-sm text-red-500">Failed to load: ${escapeHtml(e.message)}</p></div>`;
        return;
    }
    window._certMonData = d;
    const card = 'hpe-card rounded-lg p-5 shadow-sm';
    const c = d.counts || {};
    const th = d.thresholds || { red_days: 30, yellow_days: 90 };
    const tile = (label, n, cls) => `<div class="rounded-lg border px-4 py-3 ${cls}"><div class="text-2xl font-bold">${n || 0}</div><div class="text-[11px] uppercase tracking-wider font-semibold">${label}</div></div>`;
    const lastRun = d.last_run ? new Date(d.last_run).toLocaleString() : 'never';
    const nextRun = d.next_run ? new Date(d.next_run).toLocaleString() : (d.config && d.config.enabled ? 'shortly' : '—');

    const rowCls = { red: 'bg-red-50', yellow: 'bg-amber-50', green: '', error: 'bg-slate-50', unknown: 'bg-slate-50' };
    const pill = (r) => {
        const s = r.status;
        const dl = r.days_left;
        if (s === 'red') return `<span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-red-600 text-white">${dl < 0 ? 'EXPIRED' : dl + ' d'}</span>`;
        if (s === 'yellow') return `<span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-amber-400 text-amber-950">${dl} d</span>`;
        if (s === 'green') return `<span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-green-600 text-white">${dl} d</span>`;
        return `<span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-slate-300 text-slate-700">n/a</span>`;
    };
    // Ignored certs keep their real status pill, muted and tagged "(ignored)".
    const statusCell = (r) => r.ignored
        ? `<span class="opacity-50">${pill(r)}</span><div class="text-[10px] font-semibold text-slate-500 mt-0.5" title="${escapeHtml(['Ignored', r.ignored_by && 'by ' + r.ignored_by, r.ignored_at && new Date(r.ignored_at).toLocaleString()].filter(Boolean).join(' '))}">(ignored)</div>`
        : pill(r);
    const filt = (window._certMonFilter || '').toLowerCase();
    const results = (d.results || []).filter(r => !filt || [r.host, r.service, r.region, r.role, r.provider, r.issuer_cn, r.subject_cn].join(' ').toLowerCase().includes(filt));
    const rows = results.map(r => {
        const trust = r.trusted ? '' : (r.verify_error ? `<span class="ml-1 text-[10px] text-slate-500" title="${escapeHtml(r.verify_error)}">(private CA / untrusted)</span>` : '');
        const err = r.error ? `<div class="text-[11px] text-red-600">${escapeHtml(r.error)}</div>` : '';
        const san = r.san_count ? `<div class="text-[10px] text-slate-400" title="${escapeHtml((r.san || []).join(', '))}">CN ${escapeHtml(r.subject_cn || '')} · ${r.san_count} SAN</div>` : (r.subject_cn ? `<div class="text-[10px] text-slate-400">CN ${escapeHtml(r.subject_cn)}</div>` : '');
        const ignBtn = `<button onclick="certMonSetIgnored(this, ${escapeHtml(JSON.stringify(r.host || ''))}, ${Number(r.port) || 443}, ${r.ignored ? 'false' : 'true'})" class="text-[11px] px-2 py-0.5 rounded-md border ${r.ignored ? 'border-[#01A982] text-[#01A982] hover:bg-green-50' : 'border-slate-300 text-slate-600 hover:bg-slate-100'}" title="${r.ignored ? 'Count this cert in the status totals and alerts again' : 'Keep listing this cert but leave it out of the status totals and alerts'}">${r.ignored ? 'Un-ignore' : 'Ignore'}</button>`;
        return `<tr class="${r.ignored ? 'bg-slate-50 text-slate-400' : (rowCls[r.status] || '')}">
            <td class="px-3 py-2 whitespace-nowrap">${statusCell(r)}</td>
            <td class="px-3 py-2 font-mono text-xs">${escapeHtml(r.host)}${r.port && r.port !== 443 ? ':' + r.port : ''}${san}${err}</td>
            <td class="px-3 py-2 text-xs">${escapeHtml(r.service || '')}<div class="text-[10px] text-slate-400">${escapeHtml([r.region, r.role].filter(Boolean).join(' · '))}</div></td>
            <td class="px-3 py-2 text-xs">${escapeHtml(r.provider || '')}${trust}<div class="text-[10px] text-slate-400">${escapeHtml(r.issuer_cn || '')}</div></td>
            <td class="px-3 py-2 text-xs">${escapeHtml(r.cert_type || '')}<div class="text-[10px] text-slate-400">${escapeHtml(r.key_type || '')}${r.signature_algorithm ? ' · ' + escapeHtml(r.signature_algorithm) : ''}</div></td>
            <td class="px-3 py-2 text-xs whitespace-nowrap">${escapeHtml(_certMonDate(r.not_after))}</td>
            <td class="px-3 py-2 text-right whitespace-nowrap">${ignBtn}</td>
        </tr>`;
    }).join('');
    const cfg = d.config || {};
    el.innerHTML = `
      <div class="${card}">
        <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div class="text-xs text-slate-500">Last check: <b>${escapeHtml(lastRun)}</b>${d.duration_s != null ? ` (${d.duration_s}s)` : ''} · Next: <b>${escapeHtml(nextRun)}</b> · ${(d.results || []).length} hosts${c.ignored ? ` (${c.ignored} ignored — not counted)` : ''}${d.running ? ' · <span class="text-[#01A982] font-semibold animate-pulse">checking…</span>' : ''}</div>
          <div class="flex items-center gap-2">
            <input id="certmon-filter" type="text" placeholder="Filter…" value="${escapeHtml(window._certMonFilter || '')}" oninput="window._certMonFilter=this.value; clearTimeout(window._certMonFt); window._certMonFt=setTimeout(loadCertMonData, 250)" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-xs outline-none focus:ring-2 focus:ring-green-500">
            <button onclick="certMonRunNow(this)" class="text-xs bg-[#01A982] hover:bg-[#008f6e] text-white px-3 py-1 rounded-md font-medium" ${d.running ? 'disabled' : ''}>Check now</button>
          </div>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          ${tile('< ' + th.red_days + ' days', c.red, 'bg-red-50 border-red-200 text-red-700')}
          ${tile('< ' + th.yellow_days + ' days', c.yellow, 'bg-amber-50 border-amber-200 text-amber-700')}
          ${tile(th.yellow_days + '+ days', c.green, 'bg-green-50 border-green-200 text-green-700')}
          ${tile('Unreachable / error', (c.error || 0) + (c.unknown || 0), 'bg-slate-50 border-slate-200 text-slate-600')}
        </div>
        <div class="overflow-x-auto rounded-md border border-slate-200">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-100 text-slate-600 uppercase text-[11px]"><tr>
              <th class="px-3 py-2 min-w-[7rem] whitespace-nowrap">Expires in</th><th class="px-3 py-2">Host</th><th class="px-3 py-2">Service</th>
              <th class="px-3 py-2">Provider (issuer)</th><th class="px-3 py-2">Type / key</th><th class="px-3 py-2">Expiry date</th><th class="px-3 py-2"></th>
            </tr></thead>
            <tbody class="divide-y divide-slate-200">${rows || `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-400 italic">${d.last_run ? 'No matching hosts' : 'No check has run yet — click <b>Check now</b>.'}</td></tr>`}</tbody>
          </table>
        </div>
        <p class="text-[10px] text-slate-400 mt-2">Results file: <span class="font-mono">${escapeHtml(d.results_file || '')}</span>. "Private CA / untrusted" = the endpoint presents a device-CA cert (Mist terminators, Aruba device endpoints) — its expiry is still tracked. <b>Ignore</b> keeps a cert listed (with its real status) but leaves it out of the totals above and every cert alert rule.</p>
      </div>
      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Custom hosts</h3>
        <p class="text-xs text-slate-400 mb-2">Extra endpoints to monitor, one per line (<span class="font-mono">host</span> or <span class="font-mono">host:port</span>). The ${(d.builtin_hosts || []).length} built-in Aruba Central / GreenLake / Mist endpoints are always included${(cfg.disabled_builtin || []).length ? ` (${cfg.disabled_builtin.length} disabled)` : ''}.</p>
        <textarea id="certmon-custom" rows="4" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-xs font-mono outline-none focus:ring-2 focus:ring-green-500">${escapeHtml((cfg.custom_hosts || []).join('\n'))}</textarea>
        <div class="flex justify-end mt-2"><button onclick="certMonSaveCustom(this)" class="text-xs px-3 py-1 rounded-md bg-green-600 text-white hover:bg-green-700">Save</button></div>
      </div>
      <div class="${card}">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Built-in host list</h3>
        <p class="text-xs text-slate-400 mb-2">Refreshed once a day, before the check, from the vendors' published endpoint lists: new endpoints are added and retired ones dropped. A page that can't be read keeps its last list.</p>
        <ul class="text-xs text-slate-600 space-y-1">${(d.host_sources || []).map(_certMonSourceLine).join('')}</ul>
      </div>
      <p class="text-xs text-slate-400">Cert alert rules (expiry / error / untrusted emails) are managed under <a href="#" onclick="setView('reports'); return false;" class="text-[#01A982] hover:underline">Reports</a>.</p>`;
    if (filt) { const f = document.getElementById('certmon-filter'); if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); } }
    if (d.running) { clearTimeout(window._certMonPoll); window._certMonPoll = setTimeout(() => { if (currentView === 'certmon') loadCertMonData(); }, 5000); }
}

// One line per host-list source: "Juniper Mist — 100 hosts, updated <date> · +2 −1 (hover for names)".
function _certMonSourceLine(s) {
    const what = escapeHtml(s.service + (s.role ? ' ' + s.role + 's' : ''));
    const when = s.updated_at ? `${s.hosts} hosts, updated ${escapeHtml(new Date(s.updated_at).toLocaleString())}` : 'not read yet (using the built-in list)';
    const chg = (s.added.length || s.removed.length)
        ? ` · <span class="text-green-700" title="${escapeHtml(s.added.join('\n'))}">+${s.added.length}</span> <span class="text-red-600" title="${escapeHtml(s.removed.join('\n'))}">−${s.removed.length}</span> on ${escapeHtml(new Date(s.changed_at).toLocaleDateString())}`
        : '';
    const err = s.error ? ` · <span class="text-red-600">last read failed: ${escapeHtml(s.error)}</span>` : '';
    return `<li><a href="${escapeHtml(s.url)}" target="_blank" rel="noopener" class="text-[#01A982] hover:underline">${what}</a> — ${when}${chg}${err}</li>`;
}

async function certMonRunNow(btn) {
    if (btn) btn.disabled = true;
    try {
        const r = await setupFetch('/api/certmon/run', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));
        showToast(d.status === 'started' ? 'Certificate check started' : 'A check is already running', 'success');
    } catch (e) { showToast('Check failed: ' + e.message, 'error'); }
    setTimeout(loadCertMonData, 800);
}

async function certMonSetIgnored(btn, host, port, ignored) {
    if (btn) btn.disabled = true;
    try {
        const r = await setupFetch('/api/certmon/ignore', {
            method: 'POST', body: JSON.stringify({ host, port, ignored }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));
        showToast(ignored ? `Ignoring ${host} — excluded from totals and alerts` : `${host} is monitored again`, 'success');
    } catch (e) {
        showToast('Update failed: ' + e.message, 'error');
        if (btn) btn.disabled = false;
        return;
    }
    loadCertMonData();
}

async function certMonSaveCustom(btn) {
    const ta = document.getElementById('certmon-custom');
    const hosts = (ta ? ta.value : '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
    try {
        await _certMonPutConfig({ custom_hosts: hosts });
        showToast('Custom hosts saved — included in the next check', 'success');
        loadCertMonData();
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

// Cert Monitor alert rules (/api/certmon/alerts/*) — listed and edited in the
// unified Reports → Alert Rules tile (loadAlertRules / editAlertRule).
async function deleteCertMonAlertRule(id) {
    if (!confirm('Delete this alert rule?')) return;
    try { const r = await setupFetch('/api/certmon/alerts/rules/' + encodeURIComponent(id), { method: 'DELETE' }); if (!r.ok) throw new Error('HTTP ' + r.status); showToast('Alert rule deleted.', 'success'); loadAlertRules(); }
    catch (e) { showToast('Delete failed: ' + e.message, 'error'); }
}
async function testCertMonAlertRule(id) {
    showToast('Sending test…', 'info');
    try { const r = await setupFetch('/api/certmon/alerts/rules/' + encodeURIComponent(id) + '/test', { method: 'POST' }); const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status)); showToast('Test alert sent to ' + ((d.to || []).join(', ') || 'recipients'), 'success'); }
    catch (e) { showToast('Send failed: ' + e.message, 'error'); }
}

// ── Security / Threat Monitor (admin-only nav) ───────────────────────────────
// Policy config, the auth-failure audit log, and SEPARATE tiles for permanent
// blocks / 24h-TTL blocks / manual blocks / never-block allow list — each its
// own tile so long lists stay manageable. Backed by admin-only /api/security/*.
async function loadSecurityData() {
    const el = document.getElementById('security-content');
    if (!el) return;
    el.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    let d = {};
    try {
        const r = await setupFetch('/api/security/overview');
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || ('HTTP ' + r.status));
        d = await r.json();
    } catch (e) {
        el.innerHTML = `<div class="hpe-card rounded-lg p-5"><p class="text-sm text-red-500">Failed to load: ${escapeHtml(e.message)}</p></div>`;
        return;
    }
    const c = d.config || {};
    window._secAllowPriority = (d.allow_rule || {}).priority;  // for save-time ordering check
    window._secDenyPriority = c.block_priority;                // stored deny (for save ordering)
    const card = 'hpe-card rounded-lg p-5 shadow-sm';
    const fmtTs = ts => { try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return ''; } };

    const cfg = `
      <div class="${card}">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Policy</h3>
          <button onclick="securityReconcile()" class="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md font-medium" title="Push the trusted allow-list and the blocked-IP set onto the active cloud NSG (Azure or OCI) now">Sync NSG now</button>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <label class="flex items-center gap-2 text-slate-600 col-span-2"><input type="checkbox" id="sec-enabled" ${c.enabled ? 'checked' : ''} class="w-4 h-4 rounded"> Detection enabled (log invalid attempts)</label>
          <label class="flex items-center gap-2 text-amber-700 font-bold col-span-2"><input type="checkbox" id="sec-autoblock" ${c.auto_block ? 'checked' : ''} class="w-4 h-4 rounded"> Auto-block via NSG (off = log-only)</label>
          <label class="text-slate-500">Block after &gt; N fails<input type="number" id="sec-threshold" min="1" value="${c.threshold != null ? c.threshold : 5}" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          <label class="text-slate-500">Window (min)<input type="number" id="sec-window" min="1" value="${Math.round((c.window_s || 600) / 60)}" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          <label class="text-slate-500">TTL (hours)<input type="number" id="sec-ttl" min="1" value="${Math.round((c.ttl_s || 86400) / 3600)}" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          <label class="text-slate-500">Permanent after N re-blocks<input type="number" id="sec-permafter" min="1" value="${c.permanent_after != null ? c.permanent_after : 3}" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          <label class="text-slate-500">NSG deny rule name<input type="text" id="sec-rule" value="${escapeHtml(c.block_rule_name || 'lm-threat-block')}" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          <label class="text-slate-500">NSG allow priority<input type="number" id="sec-allow-priority" min="100" max="4096" value="${(d.allow_rule || {}).priority != null ? (d.allow_rule || {}).priority : 300}" oninput="_secPrioLive()" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          <label class="text-slate-500">NSG deny priority<input type="number" id="sec-priority" min="100" max="4096" value="${c.block_priority != null ? c.block_priority : 400}" oninput="_secPrioLive()" class="w-full mt-1 border border-slate-300 rounded px-2 py-1"></label>
          ${(() => {
            const ar = d.allow_rule || {};
            return `<div class="col-span-2 md:col-span-4 text-[11px] text-slate-500 bg-slate-50 rounded px-2 py-1.5 leading-relaxed">
              <b>Allow must be a lower number than Deny; both below 1000 (NSG's default allow on 443).</b> The <b>allow rule</b> (name <b>${escapeHtml(ar.name || 'lm-allowlist')}</b>) is also editable under <b>Settings → Cloud → Azure → NSG</b> — saving here updates <b>both</b> priorities (allow → NSG, deny → threat monitor).
              <span id="sec-prio-check"></span>
            </div>`;
          })()}
        </div>
        <div class="flex justify-end mt-3"><button onclick="saveSecurityConfig()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold">Save</button></div>
      </div>`;

    // One unified "Blocked IPs" list: permanent ∪ temporary = every current
    // block (disjoint, backend-guaranteed). Manual blocks live inside those two
    // by their `permanent` flag; each row carries a per-entry type badge
    // (Perm / 24h TTL / Manual) so the three old tiles collapse into one. The
    // full list is searchable via securityBlocksModal(). Stash on window so the
    // modal reads it without a refetch.
    const allBlocks = (d.permanent || []).concat(d.temporary || []);
    window._secBlocks = allBlocks;
    const _PREVIEW_N = 8;
    const blockedTile = `<div class="${card}">
        <div class="flex items-center justify-between mb-1">
          <h3 class="text-sm font-bold text-red-700">Blocked IPs <span class="text-slate-400 font-normal">(${allBlocks.length})</span></h3>
          <button onclick="securityBlocksModal('all')" class="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md font-medium">Search / view all →</button>
        </div>
        <p class="text-[11px] text-slate-400 mb-2">Each entry is tagged <b>Perm</b>, <b>24h&nbsp;TTL</b>, or <b>Manual</b> — the full list is searchable via the button.</p>
        <div class="text-xs">${allBlocks.length
            ? allBlocks.slice(0, _PREVIEW_N).map(_secBlockRowHtml).join('')
              + (allBlocks.length > _PREVIEW_N ? `<button onclick="securityBlocksModal('all')" class="mt-2 text-[11px] text-blue-500 hover:text-blue-700 font-medium">+ ${allBlocks.length - _PREVIEW_N} more — view all</button>` : '')
            : '<p class="text-slate-400 italic">none</p>'}</div>
      </div>`;

    // Shared trusted list — the SAME global_config.azure_nsg.entries the Azure
    // NSG tile edits. Each entry is both never-auto-blocked AND allowed through
    // the NSG. Prefer full {ip, description} entries; fall back to bare IPs.
    const trusted = (d.trusted && d.trusted.length) ? d.trusted
        : (d.never_block || []).map(ip => ({ ip, description: '' }));
    const allowOn = (d.allow_rule || {}).enabled;
    const neverRow = e => `<div class="flex items-center justify-between gap-3 py-1 border-b border-slate-100 last:border-0">
        <div class="min-w-0"><span class="font-mono text-slate-700">${escapeHtml(e.ip)}</span>
          ${e.description ? `<div class="text-[11px] text-slate-400 truncate" title="${escapeHtml(e.description)}">${escapeHtml(e.description)}</div>` : ''}</div>
        <button onclick="securityNeverRemove('${escJsAttr(e.ip)}')" class="text-[11px] text-slate-500 hover:text-red-600 font-medium shrink-0">Remove</button></div>`;
    const neverTile = `<div class="${card}">
        <h3 class="text-sm font-bold text-green-600 mb-1">Trusted IPs — never auto-blocked <span class="text-slate-500">AND allowed through the Azure NSG</span> <span class="text-slate-400 font-normal">(${trusted.length})</span></h3>
        <p class="text-[11px] text-slate-400 mb-2">Shared list — the same one edited under <b>Settings → Cloud → Azure → NSG</b>. Adding an entry here also opens an <b>allow rule</b> hole in the NSG when NSG management is enabled${allowOn ? '' : ' (currently disabled — entries still exempt from auto-block)'}.</p>
        <div class="flex gap-2 mb-2">
          <input id="sec-never-ip" placeholder="IP or CIDR" class="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono">
          <input id="sec-never-desc" placeholder="description (optional)" class="flex-1 border border-slate-300 rounded px-2 py-1 text-xs">
          <button onclick="securityNeverAdd()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded text-xs font-medium whitespace-nowrap">Add</button>
        </div>
        <div class="text-xs max-h-56 overflow-y-auto">${trusted.length ? trusted.map(neverRow).join('') : '<p class="text-slate-400 italic">none</p>'}</div>
      </div>`;

    // Strikes on addresses with NO active block. Strikes drive permanent_after,
    // but were only ever visible on a live block record — so an address could
    // sit one strike from an unappealable permanent ban with nothing in the UI
    // saying so until it tripped.
    const strikes = d.strikes || [];
    const strikeRow = r => `<div class="flex items-center justify-between gap-3 py-1 border-b border-slate-100 last:border-0">
        <div class="min-w-0"><span class="font-mono text-slate-700">${escapeHtml(r.ip)}</span>
          <span class="ml-2 ${r.at_limit ? 'text-red-600 font-bold' : 'text-slate-500'}">${r.strikes} / ${r.permanent_after}</span>
          ${r.at_limit ? '<div class="text-[11px] text-red-500">at the limit — its next block would be permanent</div>' : ''}</div>
        <button onclick="securityForgive('${escJsAttr(r.ip)}')" class="text-[11px] text-slate-500 hover:text-green-600 font-medium shrink-0">Forgive</button></div>`;
    const strikeTile = strikes.length ? `<div class="${card}">
        <h3 class="text-sm font-bold text-amber-600 mb-1">Strikes — addresses with a block history <span class="text-slate-400 font-normal">(${strikes.length})</span></h3>
        <p class="text-[11px] text-slate-400 mb-2">None of these are blocked right now. A strike is recorded per block; at <b>${escapeHtml(String((d.config || {}).permanent_after ?? ''))}</b> the next block becomes <b>permanent</b> — no TTL, no auto-release. Lifting a block now forgives its strike automatically; <b>Forgive</b> clears a backlog left by blocks overturned before that.</p>
        <div class="text-xs max-h-56 overflow-y-auto">${strikes.map(strikeRow).join('')}</div>
      </div>` : '';

    const manualBlock = `<div class="${card}">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Manual block</h3>
        <div class="flex flex-wrap gap-2 items-center text-xs">
          <input id="sec-mb-ip" placeholder="IP" class="border border-slate-300 rounded px-2 py-1 w-40">
          <input id="sec-mb-reason" placeholder="reason (optional)" class="border border-slate-300 rounded px-2 py-1 flex-1">
          <label class="flex items-center gap-1 text-slate-600"><input type="checkbox" id="sec-mb-perm" class="w-4 h-4 rounded"> permanent</label>
          <button onclick="securityBlock()" class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded font-bold">Block</button>
        </div></div>`;

    const t = d.totals || {};
    const bk = t.by_kind || {};
    window._secEvents = d.events || [];   // stash for drill-down modals
    const statChip = (label, val, tone, onclick, title) => `<div class="text-center${onclick ? ' cursor-pointer hover:bg-slate-50 rounded-lg py-1 -my-1 transition-colors' : ''}"${onclick ? ` onclick="${onclick}" title="${title || 'Click to drill into these events'}"` : ''}>
        <div class="text-2xl font-bold ${tone || 'text-slate-700'}" title="${Number(val || 0).toLocaleString()}">${fmtCompactNum(val)}</div>
        <div class="text-[11px] text-slate-400 uppercase tracking-wider">${label}${onclick ? ' <span class="text-slate-300">🔍</span>' : ''}</div></div>`;
    const kindChips = Object.keys(bk).sort((a, b) => bk[b] - bk[a]).map(k =>
        `<span onclick="securityEventsModal('kind:${escapeHtml(k)}')" class="inline-block px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 cursor-pointer text-slate-600 text-[11px] mr-1 mb-1" title="${Number(bk[k] || 0).toLocaleString()} ${escapeHtml(k)} events — click to see"><b>${fmtCompactNum(bk[k])}</b> ${escapeHtml(k)}</span>`).join('');
    const stats = `<div class="${card}">
        <div class="flex items-center justify-between mb-3 flex-wrap gap-1">
          <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Lifetime activity <span class="text-slate-400 normal-case font-normal">— cumulative; survives block expiry / unblock</span></h3>
          <div class="flex items-center gap-2">
            <button onclick="securitySelfTest()" class="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md font-medium" title="Record a synthetic detection signal to confirm the pipeline is live (never blocks anyone)">Run self-test</button>
            <span class="text-[11px] text-slate-400">since ${fmtTs(t.since)}${t.last_ts ? ` · last signal ${fmtTs(t.last_ts)}` : ''}</span>
          </div>
        </div>
        <div class="grid grid-cols-3 md:grid-cols-6 gap-3">
          ${statChip('Signals seen', t.signals, 'text-slate-800', "securityEventsModal('all','Signals seen')")}
          ${statChip('Auth failures', t.failures, 'text-amber-600', "securityEventsModal('auth','Auth failures')")}
          ${statChip('Anomalies', t.anomalies, 'text-amber-700', "securityEventsModal('anomaly','Anomalies')")}
          ${statChip('Blocks placed', t.blocks_placed, 'text-red-600')}
          ${statChip('Perm blocks', t.currently_permanent, 'text-red-700', "securityBlocksModal('perm')", 'Click for the full permanently-blocked IP list')}
          ${statChip('Active now', t.currently_blocked, 'text-slate-700', "securityBlocksModal('all')", 'Click for the full blocked-IP list (searchable)')}
        </div>
        ${kindChips ? `<div class="pt-3 mt-3 border-t border-slate-100"><span class="text-[11px] text-slate-400 uppercase tracking-wider mr-2">By kind</span>${kindChips}</div>` : ''}
        ${!t.signals ? '<p class="text-[11px] text-slate-400 italic mt-2">No security signals evaluated yet — the pipeline is armed and will tally every attempt here as it occurs, even after individual blocks expire.</p>' : ''}
      </div>`;

    const evts = d.events || [];
    const evtRows = evts.slice(0, 60).map((e, i) => `<tr class="border-b border-slate-100 cursor-pointer hover:bg-slate-50" onclick="securityEventDetail(${i})" title="Click for full details">
        <td class="px-2 py-1 text-slate-400 whitespace-nowrap">${fmtTs(e.ts)}</td>
        <td class="px-2 py-1 font-mono">${escapeHtml(e.ip)}${e.ip ? `<div class="text-[10px] font-sans font-normal" data-geo-ip="${escapeHtml(e.ip)}"></div>` : ''}</td>
        <td class="px-2 py-1"><span class="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] uppercase">${escapeHtml(e.kind)}</span></td>
        <td class="px-2 py-1 text-slate-500">${escapeHtml(e.username || '')}</td>
        <td class="px-2 py-1 text-slate-400 truncate max-w-[180px]" title="${escapeHtml(e.detail || '')}">${e.meta ? '<span class="text-[#01A982] mr-1" title="has evidence">🔍</span>' : ''}${escapeHtml(e.detail || '')}</td></tr>`).join('');
    const events = `<div class="${card}">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Recent invalid attempts <span class="text-slate-400 font-normal">(${evts.length})</span> <span class="text-[11px] text-slate-400 normal-case font-normal">— click a row to drill in</span></h3>
        <div class="overflow-x-auto max-h-72 overflow-y-auto"><table class="w-full text-xs"><thead class="text-slate-400 text-[10px] uppercase"><tr><th class="px-2 py-1 text-left">When</th><th class="px-2 py-1 text-left">Source IP</th><th class="px-2 py-1 text-left">Kind</th><th class="px-2 py-1 text-left">User</th><th class="px-2 py-1 text-left">Detail</th></tr></thead><tbody>${evtRows || '<tr><td colspan="5" class="px-2 py-3 text-slate-400 italic">no events yet</td></tr>'}</tbody></table></div></div>`;

    const subCard = `<div class="${card}" id="subscription-card">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Threat Monitor Subscription</h3>
        <p class="text-sm text-slate-400 italic">Loading…</p></div>`;

    // The subscription sits directly under the Threat Monitor config it
    // extends, not at the foot of the tab: it is a configuration decision, and
    // below the 60-row event table nobody scrolls to it.
    el.innerHTML = `
      ${stats}
      ${cfg}
      ${subCard}
      ${manualBlock}
      ${blockedTile}
      ${strikeTile}
      ${neverTile}
      ${events}`;
    _secPrioLive();
    _loadSubscription();
    // Best-effort origin enrichment (country / ISP / reverse-DNS) for every IP
    // shown in the blocked-IP preview and the recent-attempt feed. Lazy + cached
    // server-side, so it never blocks the initial paint.
    _secDecorateGeo([...allBlocks.map(b => b.ip), ...evts.map(e => e.ip)], el);
}

// ── Threat Monitor subscription (Security) ───────────────────────────────────
// How a tenant gets threat and simulation intelligence. The sensor content is
// not distributed as source to anyone, so a subscription to the exchange is
// the only supported route — the operator-facing extension-source tile that
// used to sit alongside this one has been removed from the Security page.
//
// There is deliberately NO service URL field. A tenant chooses whether to take
// part and in what — they do not choose where their sensor reports are sent.
async function _loadSubscription() {
    const el = document.getElementById('subscription-card');
    if (!el) return;
    let d = {};
    try {
        const r = await setupFetch('/api/security/subscription');
        if (!r.ok) throw new Error('HTTP ' + r.status);
        d = await r.json();
    } catch (e) {
        el.innerHTML = `<h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Threat Monitor Subscription</h3>
            <p class="text-xs text-red-500">Failed to load: ${escapeHtml(e.message)}</p>`;
        return;
    }
    const inp = 'w-full mt-1 border border-slate-300 rounded px-2 py-1 text-xs';
    // "pending" is a normal outcome, not a failure: without an enrolment PSK an
    // install waits for a person to approve it. Colouring it red would push an
    // operator into re-enrolling something that is already queued.
    const badge = {
        approved: '<span class="text-[#01A982]">subscribed</span>',
        pending: '<span class="text-amber-600">awaiting approval</span>',
        denied: '<span class="text-red-500">declined</span>',
        error: '<span class="text-red-500">last attempt failed</span>',
        not_enrolled: '<span class="text-slate-400">not subscribed</span>',
    }[d.status] || `<span class="text-slate-400">${escapeHtml(d.status || 'unknown')}</span>`;
    const store = d.credential_storage === 'vault'
        ? '<span class="text-[#01A982]">held in the cloud vault</span>'
        : (d.credential_storage === 'state'
            ? `<span class="text-slate-600">held encrypted in hub state</span>${d.vault_available ? '' : ' — no vault configured'}`
            : '<span class="text-slate-400">none yet</span>');
    const chans = (d.available_channels || []).map(c => `
        <label class="flex items-center gap-2 text-slate-600">
          <input type="checkbox" class="sub-chan w-4 h-4 rounded" value="${escapeHtml(c.id)}" ${(d.channels || []).includes(c.id) ? 'checked' : ''}>
          ${escapeHtml(c.label)}</label>`).join('');
    el.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Threat Monitor Subscription</h3>
        <div class="flex gap-2">
          ${d.credential_set || d.status !== 'not_enrolled'
            ? '<button onclick="unsubscribeData(event)" class="text-xs bg-slate-100 hover:bg-red-100 text-red-600 px-3 py-1 rounded-md font-medium" title="Stop taking part and forget the stored credential">Unsubscribe</button>'
            : ''}
          <button onclick="enrollSubscription(event)" class="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md font-medium" title="Register this install with the exchange">${d.credential_set ? 'Re-enroll' : 'Enroll'}</button>
          <button onclick="saveSubscription(event)" class="text-xs bg-[#01A982] hover:bg-[#018f6f] text-white px-3 py-1 rounded-md font-medium">Save</button>
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
        <label class="flex items-center gap-2 text-slate-600 md:col-span-4"><input type="checkbox" id="sub-enabled" ${d.enabled ? 'checked' : ''} class="w-4 h-4 rounded"> Subscribe to the shared threat &amp; simulation databases</label>
        <div class="md:col-span-2 flex flex-col gap-1.5">
          <span class="text-slate-500">Databases</span>
          ${chans || '<span class="text-slate-400 italic">none offered</span>'}
        </div>
        <label class="text-slate-500">Contact email<input type="text" id="sub-email" value="${escapeHtml(d.contact_email || '')}" placeholder="who to reach about this install" class="${inp}"></label>
        <label class="text-slate-500">Enrollment key (optional)<input type="password" id="sub-psk" autocomplete="new-password" placeholder="${d.psk_set ? '•••••• stored — leave blank to keep' : 'none — approval by a human'}" class="${inp}"></label>
        <label class="text-slate-500 md:col-span-2">Organization ID <span class="text-slate-400 font-normal">— share across your hubs so they count as one participant</span><input type="text" id="sub-tenant" value="${escapeHtml(d.tenant_id || '')}" class="${inp}"></label>
        <div class="md:col-span-2 text-slate-500 pt-4">Install ID <span class="font-mono text-slate-600">${escapeHtml(d.install_uuid || '—')}</span></div>
        <div class="md:col-span-4 text-[11px] text-slate-500 bg-slate-50 rounded px-2 py-1.5 leading-relaxed">
          Status: ${badge}. Credential: ${store}.
          The exchange this install reports to is fixed at build time and not settable from here.
          Publishing is reciprocal on the threat database: an install that takes the feed also contributes to it, and it also receives this install's own decoy routes.
          ${d.psk_set ? '<label class="inline-flex items-center gap-1 ml-2 text-red-600"><input type="checkbox" id="sub-clear-psk" class="w-3 h-3 rounded"> clear stored key</label>' : ''}
          ${d.last_error ? `<span class="ml-2 text-red-500">${escapeHtml(d.last_error)}</span>` : ''}
          <span id="sub-status" class="ml-2"></span>
        </div>
      </div>`;
}

function _subChannels() {
    return [...document.querySelectorAll('.sub-chan')].filter(c => c.checked).map(c => c.value);
}

async function saveSubscription(ev) {
    const btn = ev && ev.currentTarget;
    if (btn) btn.disabled = true;
    const st = document.getElementById('sub-status');
    try {
        const body = {
            enabled: document.getElementById('sub-enabled').checked,
            channels: _subChannels(),
            contact_email: document.getElementById('sub-email').value.trim(),
            enrollment_psk: document.getElementById('sub-psk').value,
            clear_psk: !!(document.getElementById('sub-clear-psk') || {}).checked,
            tenant_id: document.getElementById('sub-tenant').value.trim(),
        };
        const r = await setupFetch('/api/security/subscription', {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
        showToast('Subscription saved', 'success');
        _loadSubscription();
    } catch (e) {
        if (st) st.innerHTML = `<span class="text-red-500">${escapeHtml(e.message)}</span>`;
        showToast('Save failed: ' + e.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function enrollSubscription(ev) {
    const btn = ev && ev.currentTarget;
    const label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Enrolling…'; }
    const st = document.getElementById('sub-status');
    try {
        const r = await setupFetch('/api/security/subscription/enroll', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: '' }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
        if (j.status === 'approved') {
            showToast('Subscribed — the feed is now available', 'success');
        } else if (j.status === 'pending') {
            // Not a failure. Say so plainly so nobody retries a queued request.
            showToast('Submitted — waiting for approval', 'success');
        } else {
            throw new Error(j.reason || 'enrollment did not complete');
        }
        _loadSubscription();
    } catch (e) {
        if (st) st.innerHTML = `<span class="text-red-500">${escapeHtml(e.message)}</span>`;
        showToast('Enrollment failed: ' + e.message, 'error');
        _loadSubscription();
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = label || 'Enroll'; }
    }
}

async function unsubscribeData(ev) {
    const btn = ev && ev.currentTarget;
    if (!confirm('Unsubscribe from the shared databases?\n\nThe stored credential is deleted. Your install ID is kept, so re-subscribing later rejoins as the same participant rather than starting over.')) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Working…'; }
    const st = document.getElementById('sub-status');
    try {
        const r = await setupFetch('/api/security/subscription/unsubscribe', { method: 'POST' });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
        showToast('Unsubscribed — credential forgotten', 'success');
        _loadSubscription();
    } catch (e) {
        if (st) st.innerHTML = `<span class="text-red-500">${escapeHtml(e.message)}</span>`;
        showToast('Unsubscribe failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Unsubscribe'; }
    }
}

// ── IP origin enrichment (reverse DNS + geolocation) ─────────────────────────
// Decorates blocked-IP rows and recent-attempt rows with the source IP's
// country / ISP / reverse-DNS, fetched lazily from /api/security/geo (cached
// server-side). Results are stashed on window._secGeo and painted into any
// [data-geo-ip] slot, so modals opened later reuse the same cache.
window._secGeo = window._secGeo || {};
function _secGeoFmt(g) {
    if (!g) return '';
    if (g.scope === 'private') return '<span class="text-slate-400" title="Internal / LAN address — not geolocated">🏠 private/LAN</span>';
    if (g.scope === 'reserved' || g.scope === 'invalid') return `<span class="text-slate-400">${escapeHtml(g.label || g.scope)}</span>`;
    const loc = [g.city, g.region, g.country].filter(Boolean).join(', ');
    const bits = [];
    if (loc) bits.push((g.flag ? g.flag + ' ' : '🌐 ') + escapeHtml(loc));
    if (g.isp) bits.push(escapeHtml(g.isp));
    if (!bits.length && g.ptr) bits.push(escapeHtml(g.ptr));
    if (!bits.length) return '';
    const title = [g.ptr ? 'PTR: ' + g.ptr : '', g.asn ? 'ASN: ' + g.asn : '',
                   g.org && g.org !== g.isp ? 'Org: ' + g.org : ''].filter(Boolean).join(' · ');
    return `<span class="text-slate-500"${title ? ` title="${escapeHtml(title)}"` : ''}>${bits.join(' · ')}</span>`;
}
async function _secFetchGeo(ips) {
    const need = [...new Set(ips)].filter(ip => ip && !(ip in window._secGeo));
    if (!need.length) return;
    try {
        const d = await apiJson('/api/security/geo', { method: 'POST', body: JSON.stringify({ ips: need }) });
        Object.assign(window._secGeo, (d && d.geo) || {});
        // Cache misses as 'unknown' so a repeated poll doesn't refetch them.
        need.forEach(ip => { if (!(ip in window._secGeo)) window._secGeo[ip] = { ip, scope: 'unknown' }; });
    } catch (e) { /* best-effort — geo is purely advisory */ }
}
function _secApplyGeo(root) {
    (root || document).querySelectorAll('[data-geo-ip]').forEach(el => {
        const html = _secGeoFmt(window._secGeo[el.getAttribute('data-geo-ip')]);
        if (html) el.innerHTML = html;
    });
}
async function _secDecorateGeo(ips, root) {
    _secApplyGeo(root);            // paint anything already cached, instantly
    await _secFetchGeo(ips);
    _secApplyGeo(root);            // repaint with freshly-fetched records
}

// ── Security event drill-down ───────────────────────────────────────────────
// The Lifetime-activity stat chips (Signals / Auth failures / Anomalies) and
// the by-kind chips open a filtered list of the retained recent-events feed;
// each row drills into the full per-event evidence (incl. the structured
// ``meta`` captured at detection time — e.g. a session-hijack's bound vs.
// presented IP, user, user-agent). Reads window._secEvents stashed by
// loadSecurity(); no refetch needed.
function _secFmtTs(ts) { try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return String(ts); } }

function securityEventsModal(filter, title) {
    const all = window._secEvents || [];
    const kindMatch = String(filter || '').startsWith('kind:') ? String(filter).slice(5) : null;
    if (!title) title = kindMatch ? ('Kind: ' + kindMatch)
        : filter === 'auth' ? 'Auth failures'
        : filter === 'anomaly' ? 'Anomalies' : 'Signals seen';
    const idx = all.map((e, i) => i).filter(i => {
        const e = all[i];
        if (kindMatch) return e.kind === kindMatch;
        if (filter === 'auth') return !e.anomaly;
        if (filter === 'anomaly') return !!e.anomaly;
        return true; // 'all'
    });
    const rows = idx.map(i => {
        const e = all[i];
        return `<tr class="border-b border-slate-100 cursor-pointer hover:bg-slate-50" onclick="securityEventDetail(${i})" title="Click for full details">
            <td class="px-2 py-1 text-slate-400 whitespace-nowrap">${_secFmtTs(e.ts)}</td>
            <td class="px-2 py-1 font-mono">${escapeHtml(e.ip || '')}${e.ip ? `<div class="text-[10px] font-sans font-normal" data-geo-ip="${escapeHtml(e.ip)}"></div>` : ''}</td>
            <td class="px-2 py-1"><span class="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] uppercase">${escapeHtml(e.kind || '')}</span></td>
            <td class="px-2 py-1 text-slate-500">${escapeHtml(e.username || '')}</td>
            <td class="px-2 py-1 text-slate-400 truncate max-w-[220px]" title="${escapeHtml(e.detail || '')}">${e.meta ? '<span class="text-[#01A982] mr-1">🔍</span>' : ''}${escapeHtml(e.detail || '')}</td></tr>`;
    }).join('');
    const body = `
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-bold text-[#263040]">${escapeHtml(title || 'Events')} <span class="text-sm text-slate-400 font-normal">(${idx.length} retained)</span></h3>
          <button onclick="document.getElementById('sec-events-modal')?.remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">&times;</button>
        </div>
        <p class="text-[11px] text-slate-400">Showing the recent-events evidence feed (capped, newest first). Lifetime totals may be higher; click any row for full details.</p>
        <div class="overflow-x-auto max-h-[60vh] overflow-y-auto"><table class="w-full text-xs"><thead class="text-slate-400 text-[10px] uppercase sticky top-0 bg-white"><tr><th class="px-2 py-1 text-left">When</th><th class="px-2 py-1 text-left">Source IP</th><th class="px-2 py-1 text-left">Kind</th><th class="px-2 py-1 text-left">User</th><th class="px-2 py-1 text-left">Detail</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="px-2 py-3 text-slate-400 italic">no matching events retained</td></tr>'}</tbody></table></div>`;
    openModal('sec-events-modal', body, { backdropClose: true, card: 'w-full max-w-3xl p-6 space-y-3 max-h-[90vh] overflow-y-auto' });
    _secDecorateGeo(idx.map(i => all[i].ip), document.getElementById('sec-events-modal'));
}

function securityEventDetail(i) {
    const e = (window._secEvents || [])[i];
    if (!e) return;
    const row = (k, v) => `<div class="flex gap-3 py-1 border-b border-slate-100 last:border-0">
        <div class="w-40 shrink-0 text-[11px] uppercase tracking-wider text-slate-400 pt-0.5">${escapeHtml(k)}</div>
        <div class="text-sm text-slate-700 break-all font-mono">${escapeHtml(String(v))}</div></div>`;
    let core = row('When', _secFmtTs(e.ts))
        + row('Source IP', e.ip || '—')
        + row('Kind', e.kind || '—')
        + (e.username ? row('User', e.username) : '')
        + (e.severity ? row('Severity', e.severity) : '')
        + row('Category', e.anomaly ? 'anomaly' : 'auth failure')
        + (e.detail ? row('Detail', e.detail) : '');
    const g = (window._secGeo || {})[e.ip];
    if (g && g.scope === 'public') {
        const loc = [g.city, g.region, g.country].filter(Boolean).join(', ');
        core += (loc ? row('Origin', (g.flag ? g.flag + ' ' : '') + loc) : '')
            + (g.isp ? row('ISP', g.isp) : '')
            + (g.org && g.org !== g.isp ? row('Org', g.org) : '')
            + (g.asn ? row('ASN', g.asn) : '')
            + (g.ptr ? row('Reverse DNS', g.ptr) : '');
    } else if (g && (g.scope === 'private' || g.scope === 'reserved')) {
        core += row('Origin', g.label || g.scope);
    }
    const meta = e.meta || {};
    const metaRows = Object.keys(meta).map(k => row(k, meta[k])).join('');
    const body = `
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-bold text-[#263040]">Event detail</h3>
          <button onclick="document.getElementById('sec-event-detail-modal')?.remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">&times;</button>
        </div>
        <div>${core}</div>
        ${metaRows ? `<div class="pt-2 mt-1 border-t border-slate-200"><div class="text-[11px] uppercase tracking-wider text-[#01A982] font-bold mb-1">Evidence</div>${metaRows}</div>`
            : '<p class="text-[11px] text-slate-400 italic pt-2 border-t border-slate-200 mt-1">No structured evidence captured for this event.</p>'}
        <div class="flex justify-end pt-2">
          <button onclick="document.getElementById('sec-event-detail-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Close</button>
        </div>`;
    openModal('sec-event-detail-modal', body, { backdropClose: true, card: 'w-full max-w-lg p-6 space-y-3 max-h-[90vh] overflow-y-auto', overlay: 'z-[60]' });
}

// ── Unified blocked-IP list + full-screen searchable modal ──────────────────
// Replaces the old three separate tiles (permanent / 24h-TTL / manual). Every
// current block carries a per-entry type badge derived from its own fields:
//   duration  → b.permanent ? PERM : 24h TTL
//   source    → String(b.source).startsWith('manual') ? MANUAL (else auto)
// so a manual permanent block shows both PERM and MANUAL. Data comes from
// window._secBlocks (permanent ∪ temporary), stashed by loadSecurityData().
function _secExpIn(b) {
    if (b.permanent) return 'never';
    if (!b.expires_at) return '—';
    const s = Math.max(0, b.expires_at - Date.now() / 1000);
    return s > 3600 ? Math.round(s / 3600) + 'h' : Math.round(s / 60) + 'm';
}
function _secBlockBadges(b) {
    const dur = b.permanent
        ? '<span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 text-[10px] font-bold uppercase">Perm</span>'
        : '<span class="px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 text-[10px] font-bold uppercase">24h&nbsp;TTL</span>';
    const src = String(b.source || '').startsWith('manual')
        ? ' <span class="px-1.5 py-0.5 rounded bg-slate-200 text-slate-600 text-[10px] font-bold uppercase">Manual</span>'
        : '';
    return dur + src;
}
function _secBlockRowHtml(b) {
    return `<div class="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 last:border-0">
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2 flex-wrap"><span class="font-mono text-slate-700 text-sm">${escapeHtml(b.ip || '')}</span>${_secBlockBadges(b)}${b.permanent ? '' : `<span class="text-[10px] text-slate-400">expires ${_secExpIn(b)}</span>`}</div>
          <div class="text-[11px]" data-geo-ip="${escapeHtml(b.ip || '')}"></div>
          <div class="text-[11px] text-slate-400 truncate" title="${escapeHtml(b.reason || '')}">${escapeHtml(b.reason || '')}</div>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <button onclick="_secModalUnblock('${escJsAttr(b.ip || '')}')" title="Unblock and clear the strike this block banked (the block was wrong)" class="text-[11px] text-red-500 hover:text-red-700 font-medium">Unblock</button>
          <button onclick="_secModalUnblock('${escJsAttr(b.ip || '')}', false)" title="Unblock but keep the strike on record (the block was justified)" class="text-[11px] text-slate-400 hover:text-slate-600 font-medium">keep strike</button>
        </div>
      </div>`;
}
function securityBlocksModal(filter) {
    window._secBlocksFilter = filter || 'all';
    const body = `
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-lg font-bold text-[#263040]">Blocked IPs <span id="sec-blocks-count" class="text-sm text-slate-400 font-normal"></span></h3>
          <button onclick="document.getElementById('sec-blocks-modal')?.remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">&times;</button>
        </div>
        <div class="flex items-center gap-2 mb-3 flex-wrap">
          <input id="sec-blocks-search" oninput="_secBlocksRender()" placeholder="Search IP or reason…" class="flex-1 min-w-[180px] border border-slate-300 rounded px-3 py-1.5 text-sm font-mono">
          <div id="sec-blocks-filters" class="flex gap-1"></div>
        </div>
        <div id="sec-blocks-list" class="max-h-[65vh] overflow-y-auto pr-1"></div>`;
    openModal('sec-blocks-modal', body, { backdropClose: true, card: 'w-full max-w-3xl p-6 max-h-[90vh] overflow-y-auto' });
    _secBlocksRender();
    setTimeout(() => document.getElementById('sec-blocks-search')?.focus(), 30);
}
function _secBlocksSetFilter(f) { window._secBlocksFilter = f; _secBlocksRender(); }
function _secBlocksRender() {
    const listEl = document.getElementById('sec-blocks-list');
    if (!listEl) return; // modal not open
    const all = window._secBlocks || [];
    const f = window._secBlocksFilter || 'all';
    const term = (document.getElementById('sec-blocks-search')?.value || '').trim().toLowerCase();
    const isManual = b => String(b.source || '').startsWith('manual');
    const counts = { all: all.length, perm: all.filter(b => b.permanent).length, '24h': all.filter(b => !b.permanent).length, manual: all.filter(isManual).length };
    let rows = all.filter(b => f === 'perm' ? b.permanent : f === '24h' ? !b.permanent : f === 'manual' ? isManual(b) : true);
    if (term) rows = rows.filter(b => (b.ip || '').toLowerCase().includes(term) || (b.reason || '').toLowerCase().includes(term));
    const fb = document.getElementById('sec-blocks-filters');
    if (fb) {
        const active = 'bg-slate-700 text-white', idle = 'bg-slate-100 text-slate-600 hover:bg-slate-200';
        const btn = (key, label) => `<button onclick="_secBlocksSetFilter('${key}')" class="px-2.5 py-1 rounded text-[11px] font-bold ${f === key ? active : idle}">${label} <span class="opacity-70">${counts[key]}</span></button>`;
        fb.innerHTML = btn('all', 'All') + btn('perm', 'Perm') + btn('24h', '24h') + btn('manual', 'Manual');
    }
    const cnt = document.getElementById('sec-blocks-count');
    if (cnt) cnt.textContent = `(${rows.length}${(term || f !== 'all') ? ` of ${all.length}` : ''})`;
    listEl.innerHTML = rows.length ? rows.map(_secBlockRowHtml).join('') : '<p class="text-slate-400 italic py-3 text-sm">no matching blocked IPs</p>';
    _secDecorateGeo(rows.map(b => b.ip), listEl);
}
async function _secModalUnblock(ip, forgive = true) {
    await _securityReq('/api/security/unblock', 'POST', { ip, forgive },
        forgive ? `Unblocked ${ip}` : `Unblocked ${ip} (strike kept)`);
    await loadSecurityData(); // rebuilds the tab + refreshes window._secBlocks
    _secBlocksRender();       // refresh the open modal list (no-op if closed)
}


// ── Shared NSG allow/deny priority helpers (used by BOTH the Security tile and
// the Settings → Azure NSG tile — single source of truth, edit in either) ─────
// Invariant (Azure evaluates LOWER priority numbers FIRST): allow < deny < 1000.
function _nsgPriorityCheck(allow, deny) {
    const a = Number(allow), d = Number(deny);
    if (isNaN(a) || isNaN(d)) return { ok: false, msg: 'Enter numeric allow and deny priorities.' };
    const problems = [];
    if (!(a < d)) problems.push(`Allow (${a}) must be a LOWER number than Deny (${d}).`);
    if (!(d < 1000)) problems.push(`Deny (${d}) must be below 1000 (NSG's default allow on 443).`);
    if (!(a < 1000)) problems.push(`Allow (${a}) must be below 1000 (NSG's default allow on 443).`);
    return problems.length ? { ok: false, msg: problems.join(' ') } : { ok: true, msg: 'ordering OK' };
}
function _prioCheckHtml(allow, deny) {
    const r = _nsgPriorityCheck(allow, deny);
    return r.ok ? '<span class="text-green-600 font-medium">✓ ordering OK</span>'
                : `<span class="text-red-600 font-bold">⚠ ${escapeHtml(r.msg)}</span>`;
}
function _secPrioLive() {
    const a = document.getElementById('sec-allow-priority'), d = document.getElementById('sec-priority');
    const out = document.getElementById('sec-prio-check');
    if (a && d && out) out.innerHTML = ' ' + _prioCheckHtml(a.value, d.value);
}
// Persist the ALLOW priority to its canonical store (azure_nsg) by patching the
// current Azure config so no other field is clobbered. Triggers NSG reconcile.
async function _saveAllowPriority(allow) {
    let cfg = {};
    try { const d = await apiJson('/setup/azure-nsg'); cfg = (d && d.config) || {}; } catch (e) { cfg = {}; }
    cfg.priority = Number(allow);
    return apiJson('/setup/azure-nsg', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) });
}
// Persist the DENY priority to its canonical store (threat_monitor).
async function _saveDenyPriority(deny) {
    return apiJson('/api/security/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ block_priority: Number(deny) }) });
}
// Run the two single-field writes in an order that never trips the server-side
// allow<deny guard mid-flight (both final values are already client-validated).
async function _saveOrderedPriorities(allow, storedDeny, saveAllowFn, saveDenyFn) {
    if (Number(allow) < Number(storedDeny)) { await saveAllowFn(); await saveDenyFn(); }
    else { await saveDenyFn(); await saveAllowFn(); }
}

async function saveSecurityConfig() {
    const num = id => parseInt(document.getElementById(id).value, 10);
    const allow = num('sec-allow-priority');
    const deny = num('sec-priority');
    // Client-side guard (server enforces the same invariant). Block save when bad.
    const chk = _nsgPriorityCheck(allow, deny);
    if (!chk.ok) { showToast('Cannot save: ' + chk.msg, 'error'); return; }
    const body = {
        enabled: document.getElementById('sec-enabled').checked,
        auto_block: document.getElementById('sec-autoblock').checked,
        threshold: num('sec-threshold'),
        window_s: Math.max(60, num('sec-window') * 60),
        ttl_s: Math.max(300, num('sec-ttl') * 3600),
        permanent_after: num('sec-permafter'),
        block_rule_name: (document.getElementById('sec-rule').value || '').trim(),
        block_priority: deny,
    };
    // Save BOTH priorities: allow → Azure NSG, deny (+ policy) → threat monitor.
    const storedDeny = Number(window._secDenyPriority != null ? window._secDenyPriority : deny);
    try {
        await _saveOrderedPriorities(allow, storedDeny,
            () => _saveAllowPriority(allow),
            () => apiJson('/api/security/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }));
        showToast('Policy saved', 'success');
    } catch (e) { showToast('Failed: ' + (e.message || e), 'error'); }
    loadSecurityData();
}
async function securityBlock() {
    const ip = (document.getElementById('sec-mb-ip').value || '').trim();
    if (!ip) { showToast('Enter an IP.', 'error'); return; }
    await _securityReq('/api/security/block', 'POST',
        { ip, reason: (document.getElementById('sec-mb-reason').value || '').trim(), permanent: document.getElementById('sec-mb-perm').checked }, `Blocked ${ip}`);
    loadSecurityData();
}
async function securityUnblock(ip, forgive = true) { await _securityReq('/api/security/unblock', 'POST', { ip, forgive }, forgive ? `Unblocked ${ip}` : `Unblocked ${ip} (strike kept)`); loadSecurityData(); }
async function securityForgive(ip) {
    await _securityReq('/api/security/forgive', 'POST', { ip }, `Cleared strikes for ${ip}`);
    loadSecurityData();
}
async function securityNeverAdd() { const cidr = (document.getElementById('sec-never-ip').value || '').trim(); if (!cidr) return; const descEl = document.getElementById('sec-never-desc'); const description = (descEl && descEl.value || '').trim(); await _securityReq('/api/security/never-block', 'POST', { cidr, description }, `Added ${cidr} to trusted list`); loadSecurityData(); }
async function securityNeverRemove(cidr) { await _securityReq('/api/security/never-block', 'DELETE', { cidr }, `Removed ${cidr}`); loadSecurityData(); }
async function securityReconcile() { await _securityReq('/api/security/reconcile', 'POST', {}, 'NSG sync requested'); }
async function securitySelfTest() { await _securityReq('/api/security/selftest', 'POST', {}, 'Self-test recorded — pipeline live'); loadSecurityData(); }
async function _securityReq(url, method, body, okMsg) {
    try {
        const r = await setupFetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || d.message || ('HTTP ' + r.status));
        showToast(d.message || okMsg, (d.status === 'ERROR') ? 'error' : 'success');
        if (d.warning) showToast(d.warning, 'error');  // non-fatal advisories (e.g. priority ordering)
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}




function initView(viewId, subView) {
    switch (viewId) {
        case 'dashboard':
            updateStatus();
            if (isAdmin()) loadAllTenantsOverview();
            else loadDashboardSummary();
            loadInfraStatus();
            break;
        case 'opnsense':
            _loadFirewallData();
            break;
        case 'ldap':
            loadLDAPData(subView || 'Users');
            startLdapHealthPoll();
            break;
        case 'settings':
            _renderSettingsSection(subView || 'Hub Status');
            break;
        case 'logs':
            _renderLogsSection(subView || 'logs-hub');
            break;
        case 'bugs':
            _renderLogsSection('logs-bugs');
            break;
        case 'features':
            _renderLogsSection('logs-features');
            break;
        case 'templates':
            renderTemplateRepo();
            break;
        case 'setup':
            _renderSetupSection(subView || 'Spokes & Agents');
            break;
        case 'mydevices':
            loadAllDevices();
            loadMyDeviceSpokes();
            loadMyDeviceAgents();
            loadMyDevicePsks();
            loadMyPxmxSpokes();
            break;
        case 'cppm':
            loadCPPMNACStatus();
            break;
        case 'pxmx':
            loadPxmxData(subView || 'Overview');
            break;
        case 'netbox':
            loadNetboxData(subView || 'Overview');
            break;
        case 'dns':
            loadDNSData(subView || 'Overview');
            break;
        case 'dhcp':
            loadDHCPData(subView || 'Overview');
            break;
        case 'nw':
            loadNwData(subView || 'Overview');
            break;
        case 'console':
            loadConsoleData();
            break;
        case 'le':
            loadLEData(subView || 'Certificates');
            break;
        case 'cs':
            loadCSData(subView || 'Dashboard', currentSubChild);
            break;
        case 'security':
            loadSecurityData();
            break;
        case 'osupdates':
            _renderOsUpdatesView(document.getElementById('osupdates-content'));
            break;
        case 'reports':
            loadReportsData();
            break;
        case 'credvault':
            loadCredVault();
            break;
        case 'certmon':
            loadCertMonData();
            break;
    }
}

// Populate the configured-firewalls list (once) and render the aggregated
// table. The Firewalls page shows every firewall's data in one view — there is
// no single-firewall selector anymore.
async function _ensureFirewalls() {
    if (_opnFirewalls.length > 0) return _opnFirewalls;
    try {
        _opnFirewalls = await loadFirewalls();
    } catch (e) {
        _opnFirewalls = [];
    }
    return _opnFirewalls;
}

async function _loadFirewallData() {
    await _ensureFirewalls();
    loadOpnsenseManagement();
}

/**
 * Authenticated wrapper around the browser `fetch` for hub REST routes under
 * /setup/* (and a few other admin endpoints). It only guarantees a JSON
 * Content-Type header today; credentials ride the same-origin lm_session cookie
 * automatically, so no explicit Authorization header is added.
 *
 * When to use which fetch helper:
 *   - setupFetch(url)  -> hub /setup/* + /api/* admin routes (core/src/api.py).
 *                         Same-origin cookie auth; JSON body. Prefer this for
 *                         any hub-side call that may need admin scoping.
 *   - raw fetch(url)   -> public/same-origin routes that need no JSON header
 *                         (e.g. /status, /api/pxmx/agents, /api/dhcp/*).
 *   - csFetch(path)    -> Simulations sub-module ONLY. Defined in sim-views.js,
 *                         it prepends `/sim/api` + the tenant id, handles
 *                         401/404 specially, and parses JSON/text. See
 *                         sim-views.js csFetch (~line 55). Routes live in
 *                         core/src/simulations/routes.py.
 *
 * @param {string} url  Request URL (absolute path, e.g. '/setup/pending_spokes').
 * @param {RequestInit} [options] Standard fetch options; headers are merged.
 * @returns {Promise<Response>} Raw Response — callers must check .ok and parse.
 */
async function setupFetch(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    return fetch(url, { ...options, headers });
}

/**
 * JSON-first wrapper over setupFetch, modeled on sim-views.js csFetch. Checks
 * res.ok, surfaces the server's JSON error detail ({detail|message|error}) in
 * the thrown Error, and parses the body (JSON when the Content-Type says so,
 * text otherwise). 401s never reach this: the global fetch override (lmFetch)
 * calls handleSessionExpired() and throws 'Session expired' first.
 *
 * Prefer this over raw setupFetch for any call that just wants the parsed
 * body — it replaces the hand-rolled `.ok` check + `.json()` + detail
 * extraction at each call site. Use raw setupFetch only when you need the
 * Response itself (status branching, headers, blobs).
 *
 * @param {string} url  Request URL (absolute path, e.g. '/setup/tenants').
 * @param {RequestInit} [options] Standard fetch options; headers are merged.
 * @returns {Promise<any>} Parsed JSON (object/array), or text for non-JSON.
 * @throws {Error} On any non-ok status, with the server's detail surfaced.
 */
async function apiJson(url, options = {}) {
    const res = await setupFetch(url, options);
    if (!res.ok) {
        let detail = '';
        try {
            const j = await res.json();
            detail = (j && (j.detail || j.message || j.error)) || '';
        } catch (_e) { detail = ''; }
        throw new Error(detail ? `${res.status} ${detail}` : `${res.status} ${res.statusText}`);
    }
    const ct = res.headers.get('content-type') || '';
    const body = ct.includes('application/json') ? await res.json() : await res.text();
    // A route that serializes Python None emits a body of the literal JSON
    // token `null`. res.json() RESOLVES that to null rather than throwing, so
    // it bypassed every try/catch and callers doing `const d = await apiJson();
    // d.status` threw "null is not an object". Normalize to {} so the envelope
    // contract every caller assumes still holds. Arrays/strings pass through.
    return body === null ? {} : body;
}
// ──────────────────────────────────────────────────────────────────

// ── Credential Vault (left-nav 'credvault'; routes/cred_vault.py) ────────────
// Hub-side per-tenant secret locker. A tenant-admin sees only their own tenant
// buckets; a Global Admin additionally sees every tenant bucket plus the
// non-tenant __admin__ slot and can load an arbitrary bucket + import the
// console login list. Reach is decided by role (server-enforced); every
// read/write also requires the bucket pass-phrase (PSK). Revealed plaintext is
// shown once, copied via a self-clearing clipboard, and purged from the DOM.
let _cvIsGlobalAdmin = false;
let _cvAdminSlot = '__admin__';
let _cvVaultAvailable = true;
let _cvBuckets = [];
let _cvCurrentBucket = '';
let _cvSecrets = [];
let _cvSearchQuery = '';

async function loadCredVault() {
    const host = document.getElementById('credvault-content');
    if (!host) return;
    try {
        const d = await apiJson('/tenant/cred-vault/buckets');
        _cvIsGlobalAdmin = !!d.is_global_admin;
        _cvAdminSlot = d.admin_slot || '__admin__';
        _cvVaultAvailable = d.vault_available !== false;
        _cvBuckets = d.buckets || [];
        if (!_cvBuckets.some(b => b.bucket === _cvCurrentBucket)) {
            _cvCurrentBucket = _cvBuckets.length ? _cvBuckets[0].bucket : '';
        }
        _cvRenderShell();
    } catch (e) {
        host.innerHTML = `<div class="hpe-card rounded-lg p-5 shadow-sm"><p class="text-sm text-red-600">Failed to load: ${escapeHtml(e.message)}</p></div>`;
    }
}

function _cvBucketLabel(b) {
    if (b.bucket === _cvAdminSlot) return 'Global Admin slot';
    // An orphaned bucket matches no tenant, so nothing tenant-scoped can ever
    // use it. Say so inline — otherwise a stray bucket named e.g. "admin" sits
    // in the dropdown right next to "Global Admin slot" and reads like a second
    // admin scope, which is exactly how credentials end up in a dead end.
    if (b.is_orphan) return `${b.bucket} (orphaned — no matching tenant)`;
    // Prefer the server-provided friendly tenant name; fall back to the id.
    return b.name && b.name !== b.bucket ? `${b.name} (${b.bucket})` : b.bucket;
}

function _cvRenderShell() {
    const host = document.getElementById('credvault-content');
    if (!host) return;
    if (!_cvBuckets.length) {
        // A Global Admin always gets the __admin__ slot (and every tenant
        // bucket) from the server, so an empty list here means the account is
        // NOT a Global Admin (a tenant-admin with no tenant buckets). Explain
        // the role scoping instead of showing a dead-end.
        const help = `<p class="text-sm text-slate-600">No credential buckets are reachable for your account.</p>
               <p class="text-xs text-slate-500">The Credential Vault is scoped by role: a <b>tenant-admin</b> can only access buckets for tenants assigned to their account, and a <b>Global Admin</b> additionally gets a shared admin slot. Your account currently has no reachable tenant buckets — ask a Global Admin to assign your user to a tenant, or to grant Global Admin rights.</p>`;
        host.innerHTML = `<div class="hpe-card rounded-lg p-5 shadow-sm space-y-2">${help}</div>`;
        return;
    }
    const opts = _cvBuckets.map(b =>
        `<option value="${escapeHtml(b.bucket)}"${b.bucket === _cvCurrentBucket ? ' selected' : ''}>${escapeHtml(_cvBucketLabel(b))}${b.has_psk ? '' : ' (no pass-phrase)'}</option>`).join('');
    const storageHint = _cvVaultAvailable ? '' : `
      <div class="text-xs px-3 py-2 rounded-md bg-amber-50 text-amber-700 border border-amber-200">No Key Vault is configured — secrets are stored locally (encrypted in hub state). Configure a vault under Setup → Cloud → Cloud Service Provider → Vault to store them there instead.</div>`;
    host.innerHTML = `
      <div class="hpe-card rounded-lg p-5 shadow-sm space-y-4">
        ${storageHint}
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div class="flex items-center gap-2">
            <label class="text-xs font-bold text-slate-500 uppercase tracking-wider">Bucket</label>
            <select id="cv-bucket-select" onchange="_cvSwitchBucket(this.value)" class="px-3 py-1.5 text-sm border border-slate-300 rounded-md bg-white">${opts}</select>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="_cvSetPskModal()" class="px-3 py-1.5 text-xs rounded-md border border-slate-300 hover:bg-slate-50">Set / change pass-phrase</button>
          <button onclick="_cvAddSecretModal()" class="px-3 py-1.5 text-xs rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">+ Add secret</button>
        </div>
        <div id="cv-secrets"><p class="text-sm text-slate-400 italic">Loading secrets…</p></div>
      </div>`;
    _cvRenderBucketBody();
}

function _cvSwitchBucket(v) { _cvCurrentBucket = v; _cvRenderBucketBody(); }

async function _cvRenderBucketBody() {
    const el = document.getElementById('cv-secrets');
    if (!el) return;
    el.innerHTML = `<p class="text-sm text-slate-400 italic">Loading secrets…</p>`;
    try {
        const d = await apiJson('/tenant/cred-vault/secrets?bucket=' + encodeURIComponent(_cvCurrentBucket));
        const secrets = d.secrets || [];
        _cvSecrets = secrets;  // cached for in-place Edit (look up type/mode by name)
        // Sync the authoritative has_psk from the read back into the bucket record
        // so the "+ Add secret" guard (and the dropdown label) reflect reality —
        // e.g. a Global-Admin-loaded bucket whose PSK state wasn't known upfront.
        const _cur = _cvBuckets.find(b => b.bucket === _cvCurrentBucket);
        if (_cur) _cur.has_psk = !!d.has_psk;
        // An orphaned bucket is a dead end — nothing tenant-scoped can reference
        // it and no tenant-admin can reach it. Say so where the operator is
        // actually looking, and offer the two ways out: rescue the credentials
        // into a real bucket, or remove the bucket.
        const orphanBanner = (_cur && _cur.is_orphan && _cvIsGlobalAdmin) ? `
          <div class="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-md px-3 py-2 mb-3 space-y-2">
            <p><b>This bucket matches no tenant.</b> Credential sets are matched by tenant id, so nothing can reference what is stored here and no tenant-admin can reach it. It is not the Global Admin slot — that one is <span class="font-mono">${escapeHtml(_cvAdminSlot)}</span>.</p>
            <div class="flex gap-2">
              <button onclick="_cvMoveSecretModal()" class="px-2 py-1 rounded border border-amber-300 bg-white hover:bg-amber-100 font-semibold">Move a secret out…</button>
              <button onclick="_cvDeleteBucketModal()" class="px-2 py-1 rounded bg-red-600 text-white font-semibold hover:bg-red-700">Delete this bucket</button>
            </div>
          </div>` : '';
        if (!d.has_psk) {
            el.innerHTML = orphanBanner + `<div class="text-sm text-amber-600 space-y-2">
              <p>This bucket has no pass-phrase yet. A pass-phrase is required before you can add or reveal secrets.</p>
              <button onclick="_cvSetPskModal()" class="px-3 py-1.5 text-xs rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Set a pass-phrase</button>
            </div>`;
            return;
        }
        if (!secrets.length) {
            el.innerHTML = orphanBanner + `<p class="text-sm text-slate-400 italic">No secrets stored in this bucket.</p>`;
            return;
        }
        // Persistent search bar (outside the re-rendered table so typing keeps
        // focus) + a table area that _cvRenderSecretsTable filters in place.
        el.innerHTML = orphanBanner + `
          <div class="flex items-center gap-2 mb-3">
            <input id="cv-search" type="text" value="${escapeHtml(_cvSearchQuery)}" oninput="_cvOnSearch(this.value)"
                   placeholder="Search secrets (name / type / description)…" autocomplete="off"
                   class="w-72 px-3 py-1.5 text-sm border border-slate-300 rounded-md">
            <span id="cv-search-count" class="text-xs text-slate-400"></span>
          </div>
          <div id="cv-secrets-table"></div>`;
        _cvRenderSecretsTable();
    } catch (e) {
        el.innerHTML = `<p class="text-sm text-red-600">Failed to load secrets: ${escapeHtml(e.message)}</p>`;
    }
}

// Filter the loaded bucket's secrets by name / type / description (metadata
// only — values are never held client-side). Persists across bucket switches.
function _cvOnSearch(v) { _cvSearchQuery = v; _cvRenderSecretsTable(); }

function _cvRenderSecretsTable() {
    const wrap = document.getElementById('cv-secrets-table');
    if (!wrap) return;
    const q = (_cvSearchQuery || '').trim().toLowerCase();
    const list = !q ? _cvSecrets : _cvSecrets.filter(s =>
        [s.name, s.type, s.description].some(x => String(x || '').toLowerCase().includes(q)));
    const cnt = document.getElementById('cv-search-count');
    if (cnt) cnt.textContent = q ? `${list.length} of ${_cvSecrets.length}` : '';
    if (!list.length) {
        wrap.innerHTML = `<p class="text-sm text-slate-400 italic">No secrets match “${escapeHtml(_cvSearchQuery)}”.</p>`;
        return;
    }
    wrap.innerHTML = `
      <table class="w-full text-sm">
        <thead><tr class="text-left text-xs text-slate-500 uppercase tracking-wider border-b border-slate-200">
          <th class="py-2">Name</th><th>Type</th><th>Mode</th><th>Description</th><th class="text-right">Actions</th>
        </tr></thead>
        <tbody>${list.map(_cvRenderSecretRow).join('')}</tbody>
      </table>`;
}

// Display label for a secret's stored type. 'apikey' and 'token' are the same
// shape and are now a single choice in the editor, but secrets stored earlier
// still carry either spelling -- show one label so the list does not appear to
// offer two different kinds. The STORED value is left untouched (a legacy
// 'token' secret is only rewritten to 'apikey' if someone edits and saves it).
function _cvTypeLabel(t) {
    const v = t || 'generic';
    return (v === 'apikey' || v === 'token') ? 'api key / token' : v;
}

function _cvRenderSecretRow(s) {
    const enc = encodeURIComponent(s.name);
    const mode = s.mode === 'hub'
        ? '<span class="text-xs px-2 py-0.5 rounded-full bg-sky-100 text-sky-700" title="Automation-readable (hub-mode)">automation</span>'
        : '<span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600" title="Pass-phrase-only (psk-mode)">pass-phrase</span>';
    return `<tr class="border-b border-slate-100">
      <td class="py-2 font-mono text-slate-800">${escapeHtml(s.name)}</td>
      <td class="text-slate-600">${escapeHtml(_cvTypeLabel(s.type))}${(Array.isArray(s.fields) && s.fields.includes('client_id')) ? ' <span class="text-[10px] px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-700 align-middle" title="OAuth2 account — Client ID + Client secret (grant_type=client_credentials)">OAuth2</span>' : ''}</td>
      <td>${mode}</td>
      <td class="text-slate-500">${escapeHtml(s.description || '')}</td>
      <td class="text-right whitespace-nowrap">
        <button onclick="_cvRevealModal('${enc}')" class="px-2 py-1 text-xs rounded-md border border-slate-300 hover:bg-slate-50">Reveal</button>
        <button onclick="_cvEditModal('${enc}')" class="px-2 py-1 text-xs rounded-md border border-slate-300 hover:bg-slate-50">Edit</button>
        <button onclick="_cvDeleteModal('${enc}')" class="px-2 py-1 text-xs rounded-md border border-red-200 text-red-600 hover:bg-red-50">Delete</button>
      </td>
    </tr>`;
}

const _CV_INP = 'w-full px-3 py-2 text-sm border border-slate-300 rounded-md';

function _cvSetPskModal() {
    const cur = _cvBuckets.find(b => b.bucket === _cvCurrentBucket);
    const hasPsk = cur && cur.has_psk;
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">${hasPsk ? 'Change' : 'Set'} pass-phrase — ${escapeHtml(_cvBucketLabel(cur || { bucket: _cvCurrentBucket }))}</h3>
      <p class="text-sm text-slate-500">The pass-phrase decrypts this bucket's pass-phrase-mode secrets. Changing it re-encrypts them; the hub never stores it.</p>
      ${hasPsk ? `<input id="cv-old-psk" type="password" autocomplete="off" placeholder="current pass-phrase" class="${_CV_INP}">` : ''}
      <input id="cv-new-psk" type="password" autocomplete="off" placeholder="new pass-phrase (min 8 chars)" class="${_CV_INP}">
      ${(hasPsk && _cvIsGlobalAdmin) ? `<p class="text-xs text-slate-400">Lost the current pass-phrase? <button onclick="_cvResetPskModal()" class="text-[#01A982] font-semibold hover:underline">Reset it</button> (Global Admin only).</p>` : ''}
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="document.getElementById('cv-psk-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button onclick="_cvDoSetPsk()" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Save</button>
      </div>`;
    openModal('cv-psk-modal', body, { backdropClose: true });
}

// Last-resort recovery for a lost/corrupted bucket pass-phrase (Global Admin
// only — the server enforces it and 404s for anyone else). The rotate path
// verifies the old pass-phrase first, so without this a forgotten pass-phrase
// bricked the bucket permanently.
//
// The blast radius is stated up front and comes from the server: `hub`-mode
// secrets are encrypted with the hub key, not the pass-phrase, so they survive
// a reset untouched; only `psk`-mode secrets die, and they were already
// undecryptable. A bucket holding no psk-mode secrets resets with no data loss
// at all, so that case does not demand a destructive confirmation.
function _cvResetPskModal() {
    document.getElementById('cv-psk-modal')?.remove();
    const cur = _cvBuckets.find(b => b.bucket === _cvCurrentBucket) || { bucket: _cvCurrentBucket };
    const doomed = Number(cur.psk_secret_count || 0);
    const total = Number(cur.secret_count || 0);
    const impact = doomed
        ? `<div class="text-sm text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2 space-y-1">
             <p><b>${doomed}</b> of this bucket's ${total} secret(s) are encrypted with the lost pass-phrase and <b>cannot be recovered</b> — resetting discards them and you will have to re-enter those credentials.</p>
             <label class="flex items-center gap-2 text-xs font-semibold"><input id="cv-reset-confirm" type="checkbox" class="rounded border-slate-300"> I understand these secrets will be permanently deleted.</label>
           </div>`
        : `<p class="text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-3 py-2">No secret in this bucket is encrypted with the pass-phrase — all ${total} are hub-mode (encrypted with the hub key, still serving automation). <b>Resetting loses nothing.</b></p>`;
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">Reset pass-phrase — ${escapeHtml(_cvBucketLabel(cur))}</h3>
      <p class="text-sm text-slate-500">Sets a new pass-phrase without the old one. This is audit-logged against your account.</p>
      ${impact}
      <input id="cv-reset-psk" type="password" autocomplete="off" placeholder="new pass-phrase (min 8 chars)" class="${_CV_INP}">
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="document.getElementById('cv-reset-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button onclick="_cvDoResetPsk()" class="px-4 py-1.5 text-sm rounded-md bg-red-600 text-white font-bold hover:bg-red-700">Reset pass-phrase</button>
      </div>`;
    openModal('cv-reset-modal', body, { backdropClose: true });
}

async function _cvDoResetPsk() {
    const newPsk = document.getElementById('cv-reset-psk')?.value || '';
    const confirmEl = document.getElementById('cv-reset-confirm');
    if (confirmEl && !confirmEl.checked) {
        showToast('Tick the confirmation — those secrets cannot be recovered.', 'error');
        return;
    }
    try {
        const d = await apiJson('/tenant/cred-vault/reset-psk', {
            method: 'POST',
            body: JSON.stringify({ bucket: _cvCurrentBucket, new_psk: newPsk, confirm_destroy: !!(confirmEl && confirmEl.checked) }),
        });
        document.getElementById('cv-reset-modal')?.remove();
        const lost = (d.destroyed || []).length;
        showToast(lost ? `Pass-phrase reset — ${lost} unrecoverable secret(s) removed, ${d.kept} kept.`
                       : `Pass-phrase reset — all ${d.kept} secret(s) kept.`, 'success');
        loadCredVault();
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

function _cvMoveSecretModal() {
    // Only hub-mode secrets can be moved without pass-phrases; psk-mode ones are
    // encrypted with the SOURCE bucket's key, so both sides must be unlocked.
    const secrets = _cvSecrets || [];
    if (!secrets.length) { showToast('This bucket has no secrets to move.', 'error'); return; }
    const dests = (_cvBuckets || []).filter(b => b.bucket !== _cvCurrentBucket && b.has_psk);
    if (!dests.length) { showToast('No other bucket has a pass-phrase set — set one first.', 'error'); return; }
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">Move a secret out of ${escapeHtml(_cvCurrentBucket)}</h3>
      <p class="text-sm text-slate-500">The stored value is not copied — only its bucket is re-pointed, so the credential is never duplicated and never briefly missing.</p>
      <label class="block text-xs font-semibold text-slate-500">Secret
        <select id="cv-move-name" onchange="_cvMoveOnPick()" class="${_CV_INP}">
          ${secrets.map(s => `<option value="${escapeHtml(s.name)}" data-mode="${escapeHtml(s.mode || 'psk')}">${escapeHtml(s.name)}${(s.mode === 'hub') ? '' : ' (pass-phrase protected)'}</option>`).join('')}
        </select></label>
      <label class="block text-xs font-semibold text-slate-500">Destination bucket
        <select id="cv-move-dest" class="${_CV_INP}">
          ${dests.map(b => `<option value="${escapeHtml(b.bucket)}">${escapeHtml(_cvBucketLabel(b))}</option>`).join('')}
        </select></label>
      <div id="cv-move-psks" class="space-y-2 hidden">
        <p class="text-xs text-slate-500">This secret is encrypted with its bucket's pass-phrase, so both buckets must be unlocked to re-encrypt it.</p>
        <input id="cv-move-psk" type="password" autocomplete="off" placeholder="this bucket's pass-phrase" class="${_CV_INP}">
        <input id="cv-move-to-psk" type="password" autocomplete="off" placeholder="destination bucket's pass-phrase" class="${_CV_INP}">
      </div>
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="document.getElementById('cv-move-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button onclick="_cvDoMoveSecret()" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Move secret</button>
      </div>`;
    openModal('cv-move-modal', body, { backdropClose: true });
    _cvMoveOnPick();
}

function _cvMoveOnPick() {
    const mode = document.getElementById('cv-move-name')?.selectedOptions?.[0]?.dataset?.mode;
    document.getElementById('cv-move-psks')?.classList.toggle('hidden', mode === 'hub');
}

async function _cvDoMoveSecret() {
    const name = document.getElementById('cv-move-name')?.value || '';
    const toBucket = document.getElementById('cv-move-dest')?.value || '';
    try {
        await apiJson('/tenant/cred-vault/move-secret', {
            method: 'POST',
            body: JSON.stringify({
                bucket: _cvCurrentBucket, name, to_bucket: toBucket,
                psk: document.getElementById('cv-move-psk')?.value || '',
                to_psk: document.getElementById('cv-move-to-psk')?.value || '',
            }),
        });
        document.getElementById('cv-move-modal')?.remove();
        showToast(`Moved "${name}" to ${toBucket}.`, 'success');
        loadCredVault();
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

function _cvDeleteBucketModal() {
    const left = (_cvSecrets || []).map(s => s.name);
    const impact = left.length
        ? `<div class="text-sm text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2 space-y-1">
             <p><b>${left.length} secret(s) are still stored here and will be destroyed:</b></p>
             <ul class="list-disc list-inside font-mono text-xs">${left.map(n => `<li>${escapeHtml(n)}</li>`).join('')}</ul>
             <label class="flex items-center gap-2 text-xs font-semibold"><input id="cv-delbucket-confirm" type="checkbox" class="rounded border-slate-300"> Destroy these secrets — if any is still worth keeping, cancel and move it out first.</label>
           </div>`
        : `<p class="text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-3 py-2">The bucket is empty, so nothing is lost.</p>`;
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">Delete bucket — ${escapeHtml(_cvCurrentBucket)}</h3>
      <p class="text-sm text-slate-500">Removes the bucket and its pass-phrase. This cannot be undone.</p>
      ${impact}
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="document.getElementById('cv-delbucket-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button onclick="_cvDoDeleteBucket()" class="px-4 py-1.5 text-sm rounded-md bg-red-600 text-white font-bold hover:bg-red-700">Delete bucket</button>
      </div>`;
    openModal('cv-delbucket-modal', body, { backdropClose: true });
}

async function _cvDoDeleteBucket() {
    const confirmEl = document.getElementById('cv-delbucket-confirm');
    if (confirmEl && !confirmEl.checked) {
        showToast('Tick the confirmation — those secrets cannot be recovered.', 'error');
        return;
    }
    try {
        const d = await apiJson('/tenant/cred-vault/delete-bucket', {
            method: 'POST',
            body: JSON.stringify({ bucket: _cvCurrentBucket, confirm_destroy: !!(confirmEl && confirmEl.checked) }),
        });
        document.getElementById('cv-delbucket-modal')?.remove();
        _cvCurrentBucket = null;
        const n = (d.destroyed || []).length;
        showToast(`Bucket deleted${n ? ` — ${n} secret(s) destroyed` : ''}.`, 'success');
        loadCredVault();
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

async function _cvDoSetPsk() {
    const newPsk = document.getElementById('cv-new-psk')?.value || '';
    const oldPsk = document.getElementById('cv-old-psk')?.value;
    try {
        await apiJson('/tenant/cred-vault/psk', { method: 'POST', body: JSON.stringify({ bucket: _cvCurrentBucket, new_psk: newPsk, old_psk: oldPsk }) });
        document.getElementById('cv-psk-modal')?.remove();
        showToast('Pass-phrase saved', 'success');
        loadCredVault();
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

function _cvAddSecretModal(preset) {
    // A write always needs the bucket pass-phrase (server-enforced). Steer the
    // operator to set one first instead of letting the save fail with an error.
    const cur = _cvBuckets.find(b => b.bucket === _cvCurrentBucket);
    if (!cur || !cur.has_psk) {
        showToast('Set a bucket pass-phrase first, then add secrets.', 'error');
        _cvSetPskModal();
        return;
    }
    // Edit mode: a POST to the same name overwrites (upsert), so "Edit" reuses
    // this form. The NAME is the identity key (locked); the type and mode can be
    // changed on save (put_secret overwrites both) — the value fields must be
    // re-entered regardless, so a type/mode switch is safe.
    const editing = !!(preset && preset.name);
    // Encoded once for the Reveal button's inline onclick. encodeURIComponent
    // leaves an apostrophe untouched, which would terminate the JS string
    // literal, so escape it too — secret names are free text.
    const encName = editing ? encodeURIComponent(preset.name).replace(/'/g, '%27') : '';
    const nameAttrs = editing ? `value="${escapeHtml(preset.name)}" readonly` : `placeholder="secret name (e.g. henet-dns)"`;
    const sel = (v, want) => v === want ? ' selected' : '';
    const pType = editing ? (preset.type || 'generic') : '';
    const pMode = editing ? (preset.mode || 'psk') : '';
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} secret — ${escapeHtml(_cvBucketLabel({ bucket: _cvCurrentBucket }))}</h3>
      <input id="cv-add-name" type="text" autocomplete="off" ${nameAttrs} title="A name to identify this secret within the bucket (e.g. 'HE.NET DDNS key', 'Cloudflare token')" class="${_CV_INP}${editing ? ' bg-slate-100 text-slate-500' : ''}">
      <div class="flex gap-2">
        <select id="cv-add-type" onchange="_cvRenderAddFields()" class="${_CV_INP}" title="Secret shape. 'API key / token' holds one opaque secret (an API key, bearer token, or similar). DNS = DNS provider creds (a 'Hurricane Electric (account login)' DNS secret is used by BOTH the External DNS / HE.NET module and certificate DNS-01 issuance, so store just one HE credential); Login = username+password (or an OAuth client pair).">
          <option value="login"${sel(pType, 'login')}>Login (username + password)</option>
          <option value="apikey"${(pType === 'apikey' || pType === 'token') ? ' selected' : ''}>API key / token (single secret)</option>
          <option value="dns"${sel(pType, 'dns')}>DNS</option>
          ${(editing && pType === 'henet') ? `<option value="henet" selected>HE.NET DDNS key (Hurricane Electric public DNS)</option>` : ``}
          <option value="generic"${sel(pType, 'generic')}>Generic (key + value)</option>
        </select>
        <select id="cv-add-mode" class="${_CV_INP}" title="pass-phrase = human-only; automation = hub can read it unattended for tooling">
          <option value="psk"${sel(pMode, 'psk')}>Pass-phrase only</option>
          <option value="hub"${sel(pMode, 'hub')}>Automation-readable</option>
        </select>
      </div>
      ${editing ? `<div class="flex items-start gap-2">
        <p class="text-[11px] text-slate-400 flex-1">Name is fixed. Values are stored encrypted and are never pre-filled. Enter the bucket pass-phrase below, then <b>Reveal current values</b> to load them here for editing — or just type new ones to overwrite. You may also change the type or mode.</p>
        <button type="button" id="cv-add-reveal-btn" onclick="_cvRevealIntoEdit('${encName}')" title="Load the stored values into this form so you can edit them instead of retyping from scratch" class="shrink-0 px-2 py-1 text-xs rounded-md border border-slate-300 hover:bg-slate-50">Reveal current values</button>
      </div>` : ''}
      <div id="cv-add-fields"></div>
      <input id="cv-add-desc" type="text" autocomplete="off" value="${editing ? escapeHtml(preset.description || '') : ''}" placeholder="description (optional)" class="${_CV_INP}">
      <input id="cv-add-psk" type="password" autocomplete="off" placeholder="bucket pass-phrase (the one you set for this bucket)" title="The bucket pass-phrase you set — required to encrypt/store the secret" class="${_CV_INP}">
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="_cvClearAddSecret()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button onclick="_cvDoAddSecret()" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Save</button>
      </div>`;
    const m = openModal('cv-add-modal', body, { backdropClose: true });
    // Reveal can load plaintext into these inputs, so blank them before the
    // node is discarded rather than leaving secrets in a detached DOM node --
    // the same hygiene _cvClearReveal applies to the reveal dialog.
    m.addEventListener('click', e => { if (e.target === m) _cvClearAddSecret(); });
    // Seed the login OAuth toggle (client_id/client_secret vs username/password)
    // from the edited secret before rendering the type's value fields.
    window._cvLoginOauth = !!(preset && preset.oauth);
    // _cvRenderAddFields renders the value fields for the selected type and
    // governs the mode select (forced to automation-readable for dns / henet,
    // free choice otherwise) — for both add and edit, so a type switch in
    // edit mode updates the fields + mode correctly.
    _cvRenderAddFields();
}

// Edit an existing secret in place: reuse the add-secret form with the name,
// type and mode locked to the stored values. A save overwrites (upsert by name)
// — the bucket pass-phrase is still required (server-enforced write).
function _cvEditModal(enc) {
    const name = decodeURIComponent(enc);
    const s = _cvSecrets.find(x => x.name === name);
    if (!s) { showToast('Secret not found — reload the bucket', 'error'); return; }
    _cvAddSecretModal({ name: s.name, type: s.type || 'generic', mode: s.mode || 'psk', description: s.description || '', oauth: Array.isArray(s.fields) && s.fields.includes('client_id') });
}

function _cvRenderAddFields() {
    const t = document.getElementById('cv-add-type')?.value || 'login';
    const el = document.getElementById('cv-add-fields');
    if (!el) return;
    const f = (id, ph, type = 'text') => `<input id="${id}" type="${type}" autocomplete="off" placeholder="${ph}" class="${_CV_INP}">`;
    if (t === 'login') { _cvRenderLoginFields(); const ms = document.getElementById('cv-add-mode'); if (ms) ms.disabled = false; return; }
    // 'apikey' and the legacy 'token' are ONE shape: a single opaque secret.
    // They were once two dropdown entries that rendered the same field and
    // differed only in the stored key name, which just invited people to hunt
    // for a difference that did not exist. Now merged into one entry stored as
    // 'apikey'. 'token' is still accepted here (and in _cvCollectAddValue) so
    // secrets ALREADY stored under it keep opening and saving correctly.
    //
    // 'apikey' is the canonical spelling deliberately: it appears in EVERY
    // instance_vault.SECRET_FIELDS alias tuple, whereas 'token' is absent from
    // nw_devices.password and nw_scan_credentials.password -- so canonicalising
    // the other way would stop a re-saved secret resolving as a device password.
    else if (t === 'apikey' || t === 'token') el.innerHTML = f('cv-f-apikey', 'api key or token', 'password');
    else if (t === 'dns') {
        // A DNS-01 credential the LE module resolves unattended at issue time.
        // Present the same friendly, per-provider fields the LE module used
        // (e.g. Hurricane Electric = account email + password); the certbot
        // provider + credentials INI are auto-generated on save. Automation-
        // readable is required (the hub reads it without a pass-phrase), forced.
        const provOpts = Object.entries(DNS_CRED_PROVIDERS)
            .map(([k, v]) => `<option value="${k}">${escapeHtml(v.label)}</option>`).join('');
        el.innerHTML = `
          <label class="block text-[11px] text-slate-500 mb-0.5">provider</label>
          <select id="cv-f-dns-provider" onchange="_cvDnsRenderFields()" class="${_CV_INP}">${provOpts}</select>
          <div id="cv-f-dns-fields" class="mt-2 space-y-2"></div>`;
        const modeSel = document.getElementById('cv-add-mode');
        if (modeSel) { modeSel.value = 'hub'; modeSel.disabled = true; }
        _cvDnsRenderFields();
        return;
    }
    else if (t === 'henet') {
        // HE.NET dynamic-DNS key the henet module resolves unattended when it
        // pushes A/AAAA records to dns.he.net. Automation-readable is required
        // (the hub reads it without a pass-phrase), so force + lock hub mode.
        el.innerHTML = `
          <label class="block text-[11px] text-slate-500 mb-0.5">HE DDNS key (per-record "dynamic DNS" key from dns.he.net)</label>
          <input id="cv-f-henet-key" type="password" autocomplete="off" placeholder="HE DDNS key" title="The per-record 'dynamic DNS' key generated in the dns.he.net UI — the hub uses it to push A/AAAA records unattended" class="${_CV_INP}">`;
        const modeSel = document.getElementById('cv-add-mode');
        if (modeSel) { modeSel.value = 'hub'; modeSel.disabled = true; }
        return;
    }
    else el.innerHTML = f('cv-f-key', 'key') + f('cv-f-value', 'value', 'password');
    const modeSel = document.getElementById('cv-add-mode');
    if (modeSel) modeSel.disabled = false;  // re-enable if switching away from dns
}

// Render the per-provider input fields for the vault DNS-01 secret form
// (mirrors the LE module's old credential editor: friendly labels per provider,
// e.g. Hurricane Electric = account email + password).
function _cvDnsRenderFields() {
    const p = document.getElementById('cv-f-dns-provider')?.value || '';
    const def = DNS_CRED_PROVIDERS[p];
    const box = document.getElementById('cv-f-dns-fields');
    if (!def || !box) return;
    box.innerHTML = def.fields.map(f => `
      <div class="flex flex-col">
        <label class="text-[11px] text-slate-500 mb-0.5">${escapeHtml(f.label)}</label>
        <input id="cv-f-dns-${f.k}" type="${f.type}" autocomplete="off"
               placeholder="${f.placeholder ? escapeHtml(f.placeholder) : ''}" class="${_CV_INP}">
      </div>`).join('');
}

// Login secret fields — a username/password login OR a ClearPass OAuth2 API
// client (Client ID + Client secret, grant_type=client_credentials). The
// checkbox flips which pair is stored: {username,password} vs
// {client_id,client_secret}; the NAC/ClearPass overlay picks the grant by which
// fields the resolved secret carries (instance_vault.SECRET_FIELDS.nac_instances).
function _cvRenderLoginFields() {
    const el = document.getElementById('cv-add-fields');
    if (!el) return;
    const oauth = !!window._cvLoginOauth;
    const f = (id, ph, type = 'text') => `<input id="${id}" type="${type}" autocomplete="off" placeholder="${ph}" class="${_CV_INP}">`;
    el.innerHTML = `
      <label class="flex items-center gap-2 text-xs text-slate-600 mb-1 cursor-pointer" title="Check for a ClearPass OAuth2 API client (Client ID + Client secret, grant_type=client_credentials) instead of a username/password login.">
        <input type="checkbox" id="cv-f-login-oauth" ${oauth ? 'checked' : ''} onchange="_cvLoginToggleOauth(this.checked)" class="w-4 h-4 accent-[#01A982]">
        OAuth2 account (ClearPass) — use Client ID + Client secret
      </label>
      <div id="cv-f-login-inputs" class="space-y-2">${oauth
        ? f('cv-f-client-id', 'OAuth2 Client ID') + f('cv-f-client-secret', 'OAuth2 Client secret', 'password')
        : f('cv-f-username', 'username') + f('cv-f-password', 'password', 'password')}</div>
      <p class="text-[11px] text-slate-400 mt-1">Set the mode to <b>Automation-readable</b> to also use this login for the Console module's device auto-identify.</p>`;
}

function _cvLoginToggleOauth(checked) {
    window._cvLoginOauth = !!checked;
    const box = document.getElementById('cv-f-login-inputs');
    if (!box) return;
    const f = (id, ph, type = 'text') => `<input id="${id}" type="${type}" autocomplete="off" placeholder="${ph}" class="${_CV_INP}">`;
    box.innerHTML = checked
        ? f('cv-f-client-id', 'OAuth2 Client ID') + f('cv-f-client-secret', 'OAuth2 Client secret', 'password')
        : f('cv-f-username', 'username') + f('cv-f-password', 'password', 'password');
}

function _cvCollectAddValue() {
    const t = document.getElementById('cv-add-type')?.value || 'login';
    const v = id => (document.getElementById(id)?.value || '');
    if (t === 'login') return window._cvLoginOauth
        ? { client_id: v('cv-f-client-id'), client_secret: v('cv-f-client-secret') }
        : { username: v('cv-f-username'), password: v('cv-f-password') };
    if (t === 'apikey' || t === 'token') return { apikey: v('cv-f-apikey') };
    if (t === 'dns') {
        const p = document.getElementById('cv-f-dns-provider')?.value || '';
        const def = DNS_CRED_PROVIDERS[p];
        if (!def) return { provider: p };
        // he-login stores email/password directly (no INI); all other providers
        // auto-assemble the certbot credentials INI from the friendly fields.
        if (def.login) {
            return { provider: p, he_username: v('cv-f-dns-username'), he_password: v('cv-f-dns-password') };
        }
        const ini = def.fields
            .filter(f => f.ini && v('cv-f-dns-' + f.k).trim() !== '')
            .map(f => `${f.ini} = ${v('cv-f-dns-' + f.k).trim()}`)
            .join('\n');
        return { provider: p, dns_creds: ini };
    }
    if (t === 'henet') return { ddns_key: v('cv-f-henet-key') };
    const k = v('cv-f-key').trim();
    return k ? { [k]: v('cv-f-value') } : {};
}

// Populate the add/edit form's value inputs from a revealed secret — the exact
// inverse of _cvCollectAddValue. Used by the edit dialog's "Reveal current
// values" button (lm#488): before this, Edit showed the name/type/mode but no
// values and offered no way to see them, so the only way to change one field of
// a multi-field secret was to cancel, Reveal, copy each value, then re-open Edit
// and retype the lot. Worse, _cvDoAddSecret upserts by name, so a partial
// re-entry silently overwrote the untouched fields with blanks.
function _cvFillAddFields(value) {
    const set = (id, v) => {
        const el = document.getElementById(id);
        if (el && v !== undefined && v !== null) el.value = String(v);
    };
    const t = document.getElementById('cv-add-type')?.value || 'login';
    if (t === 'login') {
        // Which pair came back decides the OAuth toggle, not the other way
        // round: a ClearPass client stores client_id/client_secret.
        const oauth = ('client_id' in value) || ('client_secret' in value);
        const box = document.getElementById('cv-f-login-oauth');
        if (box) box.checked = oauth;
        _cvLoginToggleOauth(oauth);  // re-renders the inputs to match
        if (oauth) {
            set('cv-f-client-id', value.client_id);
            set('cv-f-client-secret', value.client_secret);
        } else {
            set('cv-f-username', value.username);
            set('cv-f-password', value.password);
        }
        return;
    }
    // 'token' is the legacy spelling of 'apikey' and still exists in stored
    // secrets — accept either key, matching _cvCollectAddValue.
    if (t === 'apikey' || t === 'token') {
        set('cv-f-apikey', value.apikey !== undefined ? value.apikey : value.token);
        return;
    }
    if (t === 'henet') { set('cv-f-henet-key', value.ddns_key); return; }
    if (t === 'dns') {
        const provSel = document.getElementById('cv-f-dns-provider');
        if (provSel && value.provider) {
            provSel.value = value.provider;
            _cvDnsRenderFields();  // provider decides which inputs exist
        }
        const def = DNS_CRED_PROVIDERS[(provSel && provSel.value) || value.provider];
        if (!def) return;
        if (def.login) {
            set('cv-f-dns-username', value.he_username);
            set('cv-f-dns-password', value.he_password);
            return;
        }
        // Non-login providers store the assembled certbot INI in dns_creds;
        // split it back into the friendly per-field inputs it was built from.
        const ini = {};
        String(value.dns_creds || '').split('\n').forEach(line => {
            const i = line.indexOf('=');
            if (i > 0) ini[line.slice(0, i).trim()] = line.slice(i + 1).trim();
        });
        def.fields.forEach(f => {
            if (f.ini && ini[f.ini] !== undefined) set('cv-f-dns-' + f.k, ini[f.ini]);
        });
        return;
    }
    // generic: a single {key: value} pair
    const keys = Object.keys(value);
    if (keys.length) { set('cv-f-key', keys[0]); set('cv-f-value', value[keys[0]]); }
}

// "Reveal current values" in the edit dialog. Same endpoint and same
// pass-phrase requirement as the standalone Reveal dialog — this only changes
// where the plaintext lands (the form you are editing) so a single field can be
// corrected without retyping the others.
async function _cvRevealIntoEdit(enc) {
    const name = decodeURIComponent(enc);
    const psk = document.getElementById('cv-add-psk')?.value || '';
    if (!psk) {
        showToast('Enter the bucket pass-phrase below, then Reveal', 'error');
        document.getElementById('cv-add-psk')?.focus();
        return;
    }
    const btn = document.getElementById('cv-add-reveal-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Revealing…'; }
    try {
        const d = await apiJson('/tenant/cred-vault/reveal', {
            method: 'POST',
            body: JSON.stringify({ bucket: _cvCurrentBucket, name, psk }),
        });
        _cvFillAddFields(d.value || {});
        showToast('Current values loaded — edit any field and Save', 'success');
        if (btn) btn.remove();  // single-shot, like the reveal dialog
    } catch (e) {
        showToast('Reveal failed: ' + e.message, 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Reveal current values'; }
    }
}
window._cvRevealIntoEdit = _cvRevealIntoEdit;

// Close the add/edit dialog, blanking any revealed plaintext first.
function _cvClearAddSecret() {
    document.querySelectorAll('#cv-add-modal input').forEach(el => { el.value = ''; });
    document.getElementById('cv-add-modal')?.remove();
}
window._cvClearAddSecret = _cvClearAddSecret;

async function _cvDoAddSecret() {
    const name = (document.getElementById('cv-add-name')?.value || '').trim();
    const type = document.getElementById('cv-add-type')?.value || 'generic';
    const mode = document.getElementById('cv-add-mode')?.value || 'psk';
    const description = document.getElementById('cv-add-desc')?.value || '';
    const psk = document.getElementById('cv-add-psk')?.value || '';
    const value = _cvCollectAddValue();
    if (!name) { showToast('Name is required', 'error'); return; }
    // A DNS/provider secret always carries a non-secret `provider` marker, so the
    // generic "all empty" test below would pass even with blank credential fields
    // and silently OVERWRITE the stored secret with empty creds (the edit form
    // can't prefill an encrypted password). Validate the real credential fields,
    // ignoring the `provider` marker, so a blank re-save is rejected — not stored.
    const credVals = Object.entries(value).filter(([k]) => k !== 'provider').map(([, v]) => v);
    if (!credVals.length || credVals.every(x => !x)) { showToast('Enter a value', 'error'); return; }
    if (value.provider && DNS_CRED_PROVIDERS[value.provider] && DNS_CRED_PROVIDERS[value.provider].login
        && (!value.he_username || !value.he_password)) {
        showToast('Enter both the account email and password', 'error'); return;
    }
    if (type === 'login' && window._cvLoginOauth && (!value.client_id || !value.client_secret)) {
        showToast('Enter both the Client ID and Client secret', 'error'); return;
    }
    if (type === 'login' && !window._cvLoginOauth && (!value.username || !value.password)) {
        showToast('Enter both the username and password', 'error'); return;
    }
    try {
        await apiJson('/tenant/cred-vault/secret', { method: 'POST', body: JSON.stringify({ bucket: _cvCurrentBucket, name, value, mode, type, description, psk }) });
        document.getElementById('cv-add-modal')?.remove();
        showToast('Secret saved', 'success');
        loadCredVault();
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

function _cvRevealModal(enc) {
    const name = decodeURIComponent(enc);
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">Reveal — ${escapeHtml(name)}</h3>
      <p class="text-sm text-slate-500">The pass-phrase is required and the plaintext is shown once, never cached. It is cleared from this page the moment you close the dialog.</p>
      <input id="cv-rev-psk" type="password" autocomplete="off" placeholder="bucket pass-phrase" class="${_CV_INP}">
      <div id="cv-rev-out"></div>
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="_cvClearReveal()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Close</button>
        <button id="cv-rev-btn" onclick="_cvDoReveal('${enc}')" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Reveal</button>
      </div>`;
    const m = openModal('cv-rev-modal', body, { backdropClose: true });
    // Purge any revealed plaintext from the DOM if the dialog is dismissed.
    m.addEventListener('click', e => { if (e.target === m) _cvClearReveal(); });
}

async function _cvDoReveal(enc) {
    const name = decodeURIComponent(enc);
    const psk = document.getElementById('cv-rev-psk')?.value || '';
    try {
        const d = await apiJson('/tenant/cred-vault/reveal', { method: 'POST', body: JSON.stringify({ bucket: _cvCurrentBucket, name, psk }) });
        _cvShowRevealed(d.value || {});
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

function _cvShowRevealed(value) {
    const out = document.getElementById('cv-rev-out');
    if (!out) return;
    const rows = Object.keys(value).map(k => {
        const enc = encodeURIComponent(k);
        return `<div class="flex items-center gap-2 py-1">
          <span class="text-xs font-bold text-slate-500 w-24 shrink-0">${escapeHtml(k)}</span>
          <code class="cv-rev-val flex-1 px-2 py-1 bg-slate-100 rounded text-sm break-all" data-k="${enc}">${escapeHtml(String(value[k]))}</code>
          <button onclick="_cvCopy('${enc}')" class="px-2 py-1 text-xs rounded-md border border-slate-300 hover:bg-slate-50">Copy</button>
        </div>`;
    }).join('');
    out.innerHTML = `<div class="mt-2 border-t border-slate-200 pt-2">${rows}</div>`;
    // Once revealed, hide the pass-phrase field + reveal button (single-shot).
    document.getElementById('cv-rev-psk')?.remove();
    document.getElementById('cv-rev-btn')?.remove();
}

function _cvCopy(enc) {
    const el = document.querySelector(`#cv-rev-out .cv-rev-val[data-k="${enc}"]`);
    if (!el) return;
    const txt = el.textContent;
    navigator.clipboard?.writeText(txt).then(() => {
        showToast('Copied — clipboard auto-clears in 20s', 'success');
        // Self-clearing clipboard so the secret can't be harvested later.
        setTimeout(() => { navigator.clipboard?.writeText('').catch(() => {}); }, 20000);
    }).catch(() => showToast('Copy failed', 'error'));
}

function _cvClearReveal() {
    // Overwrite the revealed plaintext before removing the node, so it never
    // lingers in a detached DOM node the GC hasn't reclaimed yet.
    document.querySelectorAll('#cv-rev-out .cv-rev-val').forEach(el => { el.textContent = ''; });
    const out = document.getElementById('cv-rev-out');
    if (out) out.innerHTML = '';
    document.getElementById('cv-rev-modal')?.remove();
}

function _cvDeleteModal(enc) {
    const name = decodeURIComponent(enc);
    const body = `
      <h3 class="text-lg font-bold text-[#263040]">Delete — ${escapeHtml(name)}</h3>
      <p class="text-sm text-slate-500">This permanently removes the secret from the vault. The bucket pass-phrase is required.</p>
      <input id="cv-del-psk" type="password" autocomplete="off" placeholder="bucket pass-phrase" class="${_CV_INP}">
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="document.getElementById('cv-del-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button onclick="_cvDoDelete('${enc}')" class="px-4 py-1.5 text-sm rounded-md bg-red-600 text-white font-bold hover:bg-red-700">Delete</button>
      </div>`;
    openModal('cv-del-modal', body, { backdropClose: true });
}

async function _cvDoDelete(enc) {
    const name = decodeURIComponent(enc);
    const psk = document.getElementById('cv-del-psk')?.value || '';
    try {
        await apiJson('/tenant/cred-vault/delete', { method: 'POST', body: JSON.stringify({ bucket: _cvCurrentBucket, name, psk }) });
        document.getElementById('cv-del-modal')?.remove();
        showToast('Secret deleted', 'success');
        loadCredVault();
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

// ──────────────────────────────────────────────────────────────────

function _renderLogsSection(subMenu) {
    const content = document.getElementById('logs-content');
    if (!content) return;
    const card = 'hpe-card rounded-lg shadow-sm overflow-hidden';
    const module = subMenu.replace('logs-', '');
    const title = SUBMENU_LABELS[subMenu] || (module + ' Logs');
    // The Recovery tab is a filtered view of the hub log (the [recovery]
    // watchdog lines already stream through Hub Logs unfiltered); load it with
    // the dedicated loader instead of the generic /setup/logs/<module> one.
    // Bug Reports / Feature Requests are table views of the hub's bug-report
    // store (loadBugReports filters by type: 'bug' | 'feature').
    const isRecovery = subMenu === 'logs-recovery';
    const isBugs = subMenu === 'logs-bugs';
    const isFeatures = subMenu === 'logs-features';
    const bugType = isBugs ? 'bug' : isFeatures ? 'feature' : null;
    const refreshCall = isRecovery ? "loadRecoveryLogs()"
        : bugType ? `loadBugReports('${bugType}')` : `loadModuleLogs('${module}')`;
    // Clear Logs is destructive + fleet-wide (hub deque + every relayed
    // agent/spoke deque + on-disk /var/log/lm/*.log on the hub AND, via a
    // CLEAR_LOGS broadcast, every connected spoke's own disk). Hidden on the
    // Bug Reports / Feature Requests tabs — those are a separate store, not
    // a log source.
    const clearBtn = (isBugs || isFeatures) ? '' :
        `<button onclick="clearLogs(()=>${refreshCall})" class="text-xs text-red-500 hover:text-red-700 font-medium">Clear</button>`;
    // AI Log Analysis — delegated to the ab spoke's LLM. Not a log source, so
    // it's hidden on the Bug Reports / Feature Requests tabs.
    const analysisBtn = (isBugs || isFeatures) ? '' :
        `<button id="lm-log-analysis-btn" onclick="runLmLogAnalysis('${module}')" class="text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 px-2 py-1 rounded">✨ Log Analysis</button>`;
    // Debug-logging toggle is a Global-Admin log control, not a bug-store action —
    // hidden on Bug Reports / Feature Requests (and it would 403 for a read-only
    // tenant admin who now reaches those tabs).
    const debugToggleBtn = (isBugs || isFeatures) ? '' :
        `<button id="debug-toggle-btn" onclick="toggleDebugLogging()"
                        class="text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium flex items-center gap-1">
                        <span id="debug-mode-text">Debug Logging: OFF</span>
                    </button>`;
    const analysisPanel = (isBugs || isFeatures) ? '' : `
            <div id="lm-log-analysis-panel" class="px-4 py-3 border-b border-slate-200 bg-indigo-50/40">
                <div class="flex items-center gap-2 mb-1 flex-wrap">
                    <span class="text-[11px] font-bold uppercase tracking-wider text-indigo-700">✨ Log Analysis</span>
                    <span id="lm-log-analysis-verdict" class="hidden text-[10px] font-bold px-1.5 py-0.5 rounded"></span>
                    <span id="lm-log-analysis-meta" class="text-[10px] text-slate-400"></span>
                    <span class="flex-1"></span>
                    <span id="lm-log-analysis-config" class="text-[10px] text-slate-400 flex items-center gap-1"></span>
                </div>
                <div id="lm-log-analysis-body" class="text-xs text-slate-700 whitespace-pre-wrap leading-relaxed bg-white rounded border border-slate-200 p-3 max-h-72 overflow-y-auto">—</div>
            </div>`;
    content.innerHTML = `
        <div class="${card}">
            <div class="px-4 py-3 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-sm font-bold text-slate-600">${title} ${helpIcon('logging-observability-contract', null, 'Logs help')}</h3>
                <div class="flex gap-3 items-center">
                    ${debugToggleBtn}
                    ${analysisBtn}
                    <button onclick="copyLogs()" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Copy</button>
                    ${clearBtn}
                    <button onclick="${refreshCall}" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Refresh</button>
                </div>
            </div>${analysisPanel}
            <div id="system-logs-container" class="h-[32rem] overflow-y-auto font-mono text-xs bg-white border border-slate-200 rounded-md text-slate-700 space-y-0"></div>
        </div>${isRecovery && typeof isAdmin === 'function' && isAdmin() ? _stateResetCardHtml() : ''}`;
    if (isRecovery) {
        loadRecoveryLogs();
        if (typeof isAdmin === 'function' && isAdmin()) _initStateResetCard();
    } else if (bugType) {
        loadBugReports(bugType);
    } else {
        loadModuleLogs(module);
    }
    if (!isBugs && !isFeatures) _lmLoadCachedAnalysis(module);
    refreshDebugButtonState();
}

// ── AI Log Analysis (delegated to the ab spoke's LLM) ──
const _lmAutoRan = new Set();  // per-session guard so tab-flipping doesn't fan out LLM calls
const _LM_VERDICT = {
    escalate: ['ESCALATE', 'bg-red-100 text-red-700'],
    watch: ['WATCH', 'bg-amber-100 text-amber-700'],
    none: ['HEALTHY', 'bg-green-100 text-green-700'],
};
function _lmLaRender(la) {
    const body = document.getElementById('lm-log-analysis-body');
    const meta = document.getElementById('lm-log-analysis-meta');
    const vEl = document.getElementById('lm-log-analysis-verdict');
    const btn = document.getElementById('lm-log-analysis-btn');
    if (!body) return;
    if (la && la.running) { body.textContent = 'Analyzing…'; if (btn) btn.disabled = true; return; }
    if (btn) btn.disabled = false;
    if (la && la.error) body.textContent = '⚠ ' + la.error;
    else if (la && la.analysis) body.textContent = la.analysis;
    else body.textContent = 'No analysis yet — click Log Analysis to run one.';
    if (vEl) {
        const v = (la && la.verdict) || '';
        if (_LM_VERDICT[v]) {
            vEl.textContent = _LM_VERDICT[v][0];
            vEl.className = 'text-[10px] font-bold px-1.5 py-0.5 rounded ' + _LM_VERDICT[v][1];
            vEl.classList.remove('hidden');
        } else { vEl.classList.add('hidden'); }
    }
    if (meta) meta.textContent = (la && la.title ? la.title + ' · ' : '')
        + (la && la.at ? 'analyzed ' + la.at : '')
        + (la && la.duration_s != null ? ' · ' + la.duration_s + 's' : '');
}
async function _lmLoadSentinelConfig() {
    const el = document.getElementById('lm-log-analysis-config');
    if (!el) return;
    try {
        const c = await (await setupFetch('/setup/log-analysis/config')).json();
        const m = c.metric || {};
        const metricTxt = m.at ? ` · last sweep ${m.last_sweep_s ?? '?'}s${m.avg_module_s != null ? ' · avg ' + m.avg_module_s + 's/mod' : ''}` : '';
        el.innerHTML =
            `<label class="cursor-pointer flex items-center gap-1" title="Unattended per-module log sentinel">Auto`
            + `<input type="checkbox" ${c.auto ? 'checked' : ''} onchange="_lmSetSentinel({auto:this.checked})"></label>`
            + ` every <input type="number" min="1" value="${c.interval_min}" onchange="_lmSetSentinel({interval_min:parseInt(this.value)||15})" class="w-9 text-center border border-slate-300 rounded">m`
            + `<span class="text-slate-400">${metricTxt}</span>`
            + (c.ab_online ? '' : ' · <span class="text-red-500">AppBuilder offline</span>');
    } catch (e) { /* config unavailable */ }
}
async function _lmSetSentinel(patch) {
    try {
        await setupFetch('/setup/log-analysis/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch)
        });
    } catch (e) { /* ignore */ }
    _lmLoadSentinelConfig();
}
async function _lmLoadCachedAnalysis(module) {
    const panel = document.getElementById('lm-log-analysis-panel');
    if (!panel) return;
    _lmLoadSentinelConfig();
    try {
        const la = await (await setupFetch('/setup/log-analysis?module=' + encodeURIComponent(module || 'hub'))).json();
        if (la && (la.analysis || la.error)) { _lmLaRender(la); return; }
        // Option A: no cached analysis for this module — auto-run ONCE this session so
        // the panel is populated on open (throttled so switching tabs doesn't fan out).
        const key = module || 'hub';
        if (!_lmAutoRan.has(key)) { _lmAutoRan.add(key); runLmLogAnalysis(module); }
    } catch (e) { /* no cached analysis */ }
}
async function runLmLogAnalysis(module) {
    const body = document.getElementById('lm-log-analysis-body');
    const btn = document.getElementById('lm-log-analysis-btn');
    if (body) body.textContent = 'Asking AppBuilder to read the logs… (this can take a bit)';
    if (btn) btn.disabled = true;
    try {
        const r = await setupFetch('/setup/log-analysis', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ module: module || 'hub' })
        });
        const la = await r.json();
        _lmLaRender(la);
    } catch (e) {
        if (body) body.textContent = 'Log Analysis failed: ' + (e.message || e);
        if (btn) btn.disabled = false;
    }
}

// ── Corruption-recovery: reset DERIVED cached data (global / per-tenant) ──────
// Wipes only regenerable cache/history JSON (sharded per tenant+module) — check
// history, poll window, client-count, simulations_cache, central status. NEVER
// touches config/identity (tenant registration, spoke PSKs, users, sessions), so
// spokes stay connected + nobody is logged out; the data rebuilds from the next
// poll/telemetry. Global-Admin only (backend re-gates). POST /admin/state/reset.
function _stateResetCardHtml() {
    return `
        <div class="hpe-card rounded-lg mt-4 border border-amber-300">
            <div class="px-4 py-3 border-b border-amber-200 bg-amber-50 rounded-t-lg">
                <h3 class="text-sm font-bold text-amber-800">Reset cached data (corruption recovery)</h3>
            </div>
            <div class="p-4 space-y-3 text-xs text-slate-600">
                <p>Wipes only <b>regenerable cache/history</b> (dashboard check history, poll window,
                   client-count, VM/telemetry cache, central status). <b>Preserved:</b> tenants, spoke
                   secrets, users, sessions — spokes stay connected, nobody is logged out. The data
                   rebuilds from the next poll/telemetry cycle. Use only if a dashboard is stuck on
                   corrupt/stale data.</p>
                <div class="flex flex-wrap items-center gap-2">
                    <select id="state-reset-tenant" class="border border-slate-300 rounded-md px-2 py-1 text-xs">
                        <option value="">— select a tenant —</option>
                    </select>
                    <button onclick="resetDerivedState('tenant')"
                        class="bg-amber-100 hover:bg-amber-200 text-amber-800 border border-amber-300 px-3 py-1.5 rounded-md text-xs font-bold">
                        Wipe this tenant's cached data</button>
                    <span class="text-slate-300">|</span>
                    <button onclick="resetDerivedState('global')"
                        class="bg-red-100 hover:bg-red-200 text-red-700 border border-red-300 px-3 py-1.5 rounded-md text-xs font-bold">
                        Wipe ALL cached data</button>
                </div>
                <div id="state-reset-status" class="text-[11px]"></div>
            </div>
        </div>`;
}

async function _initStateResetCard() {
    const sel = document.getElementById('state-reset-tenant');
    if (!sel) return;
    try {
        const data = await setupFetch('/setup/tenants').then(r => r.ok ? r.json() : null).catch(() => null);
        const tenants = (data && (data.tenants || data)) || [];
        (Array.isArray(tenants) ? tenants : []).forEach(t => {
            const id = t.tenant_id || t.id || t;
            const nm = t.name || t.display_name || id;
            if (id) sel.insertAdjacentHTML('beforeend',
                `<option value="${escapeHtml(String(id))}">${escapeHtml(String(nm))}</option>`);
        });
    } catch (e) { /* dropdown just stays empty-selectable */ }
}

window.resetDerivedState = async function (scope) {
    const statusEl = document.getElementById('state-reset-status');
    let url = '/admin/state/reset';
    let label = 'ALL tenants';
    if (scope === 'tenant') {
        const sel = document.getElementById('state-reset-tenant');
        const tid = sel && sel.value;
        if (!tid) { if (statusEl) statusEl.textContent = 'Select a tenant first.'; return; }
        url += '?tenant=' + encodeURIComponent(tid);
        label = 'tenant "' + tid + '"';
    }
    const typed = window.prompt(`Type RESET to wipe cached data for ${label}.\n(Config, spokes, users are preserved.)`);
    if (typed !== 'RESET') { if (statusEl) statusEl.textContent = 'Cancelled.'; return; }
    if (statusEl) statusEl.textContent = 'Resetting…';
    try {
        const r = await setupFetch(url, { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (r.ok) {
            if (typeof showToast === 'function') showToast(`Cache reset (${label}) — ${d.files_removed ?? 0} file(s) removed; rebuilding.`, 'success');
            if (statusEl) statusEl.textContent = `Done — removed ${d.files_removed ?? 0} file(s). Data rebuilds on the next poll.`;
        } else {
            if (statusEl) statusEl.textContent = 'Failed: ' + (d.detail || r.status);
        }
    } catch (e) { if (statusEl) statusEl.textContent = 'Error: ' + (e.message || e); }
};

// Recovery logs: the hub watchdog emits greppable [recovery] lines for every
// restart/give-up/clear action. This loads the hub log and filters to those
// lines so an operator can watch auto-recovery without CLI / journalctl.
async function loadRecoveryLogs() {
    const container = document.getElementById('system-logs-container');
    if (!container) return;
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching recovery logs...</div>`;
    try {
        const data = await apiJson('/setup/logs');
        const logs = (data.logs || []).slice().reverse();
        const rec = logs.filter(l => typeof l === 'string' && l.includes('[recovery]'));
        if (rec.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No [recovery] log lines yet. The watchdog logs here when it restarts a stranded spoke or gives up.</div>`;
            return;
        }
        // Collapse repeating [recovery] lines (same except timestamp) with a
        // counter + expand-on-click, same as the main log view. GAVE_UP rows
        // keep their red styling in both the header and the expanded rows.
        container._rawLogs = rec;
        const recoveryRow = (log, count) => {
            const isGiveUp = log.includes('GAVE_UP');
            const cls = isGiveUp ? 'text-red-700 font-semibold bg-red-50' : 'text-slate-600 hover:bg-slate-50';
            const badge = count && count > 1
                ? `<span class="ml-2 px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-slate-200 text-slate-600 align-middle whitespace-nowrap" title="${count} identical events — click to expand">×${count}</span>`
                : '';
            // onclick must be its own attribute, not embedded in the class string.
            const isGroup = count && count > 1;
            const clsExtra = isGroup ? ' cursor-pointer select-none' : '';
            const onClick = isGroup ? ' onclick="toggleLogGroup(this)"' : '';
            const tsMatch = log.match(/^(?:\[([^\]]*)\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([^-]+?) - ([A-Z]+) - (.*)$/s);
            const body = tsMatch
                ? `${tsMatch[1] ? `<span class="text-slate-400">[${tsMatch[1]}]</span> ` : ''}<span class="text-slate-400">${tsMatch[2]}</span> <span class="font-semibold">${tsMatch[3].trim()}</span> <span class="opacity-60">${tsMatch[4]}</span>${badge}<div class="pl-4 mt-0.5 break-all">${escapeHtml(tsMatch[5])}</div>`
                : `${escapeHtml(log)}${badge}`;
            return `<div class="group relative px-4 py-0.5 border-b border-slate-100 text-xs font-mono ${cls}${clsExtra}"${onClick}>${_logBugBtn(log, tsMatch ? tsMatch[4] : '', tsMatch ? (tsMatch[1] || tsMatch[3]) : '')}${body}</div>`;
        };
        container.innerHTML = _renderGroupedLogs(rec, recoveryRow);
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading recovery logs: ${err.message}</div>`;
    }
}

// Bug Reports / Feature Requests: the WebUI "Bug/Feature Request" footer
// button writes each report to the hub's bug store (with a `type` of "bug" or
// "feature"); ab later files a GitHub issue (Bug → auto-fix labels;
// feature → enhancement, no auto-fix) and flips `filed` to true with the
// issue_url. ``typeFilter`` ('bug' | 'feature') restricts the list to one kind
// so the Bug Report and Feature Request nav items each show only their own.
// A tenant admin gets a READ-ONLY, tenant-scoped view of their own tenant's
// reports via /tenant/bug-reports; a Global Admin keeps the full /setup/ view
// (all tenants + approve/delete). Approve/Delete are hidden for tenant admins
// (the /setup/ mutate routes are Global-Admin-only server-side anyway).
function _bugReportsBase() {
    return (typeof isAdmin === 'function' && isAdmin()) ? '/setup/bug-reports' : '/tenant/bug-reports';
}

async function loadBugReports(typeFilter) {
    const container = document.getElementById('system-logs-container');
    if (!container) return;
    // Remember the active view so an inline action (approve/delete) can refresh
    // the SAME filtered list instead of resetting to the mixed view.
    container.dataset.bugFilter = typeFilter || '';
    const kindLabel = typeFilter === 'feature' ? 'feature request' : 'bug report';
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${kindLabel}s...</div>`;
    try {
        const data = await apiJson(_bugReportsBase());
        let reports = data.reports || [];
        // Legacy reports (pre-type-field) default to "bug"; only filter when a
        // typeFilter is given (the two nav views). No filter = show everything.
        if (typeFilter) reports = reports.filter(r => (r.type || 'bug') === typeFilter);
        if (reports.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${kindLabel}s yet. Use the 🐞 Bug/Feature Request button in the footer to capture the console, page HTML, and a screenshot${typeFilter === 'feature' ? ' (check the feature-request box)' : ''}.</div>`;
            return;
        }
        container.className = 'h-[32rem] overflow-y-auto bg-white border border-slate-200 rounded-md text-slate-700';
        container.innerHTML = reports.map(r => {
            const ts = r.ts ? new Date(r.ts * 1000).toLocaleString() : '—';
            const sev = (r.severity || 'medium').toLowerCase();
            const sevColor = sev === 'high' ? 'bg-red-100 text-red-700'
                : sev === 'low' ? 'bg-slate-100 text-slate-500'
                : 'bg-amber-100 text-amber-700';
            const isFeat = (r.type || 'bug') === 'feature';
            const typeBadge = isFeat
                ? `<span class="shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-100 text-purple-700" title="Feature request">💡 Feature</span>`
                : `<span class="shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-100 text-blue-700" title="Bug">🐛 Bug</span>`;
            // Feature requests are gated: an admin must Approve before ab
            // may file the GitHub issue and work it. Bugs skip the gate.
            const _st = (r.status || (r.filed ? 'filed' : '')).toLowerCase();
            let status;
            if (_st === 'fixed') {
                status = `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-green-600 font-semibold hover:underline" title="Closed on GitHub — fixed by AppBuilder">✓ Fixed ↗</a>`;
            } else if (_st === 'closed') {
                // Closed WITHOUT a fix — must NOT look like "Fixed".
                status = `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-slate-500 font-semibold hover:underline" title="Issue closed on GitHub without a fix — reopen if still broken">⊘ Closed (not fixed) ↗</a>`;
            } else if (_st === 'duplicate') {
                // Recurrence: ab matched this to an existing issue instead of
                // filing a new one — link the SAME issue (must win over r.filed).
                status = `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-slate-500 font-semibold hover:underline" title="Duplicate — links the same GitHub issue">⧉ Duplicate ↗</a>`;
            } else if (_st === 'in_progress') {
                // ab is actively working the issue right now — must win over
                // r.filed (a report being worked is also filed).
                status = r.issue_url
                    ? `<a href="${escapeHtml(r.issue_url)}" target="_blank" class="text-amber-600 font-semibold hover:underline" title="AppBuilder is actively working on this">⚙ In Progress ↗</a>`
                    : `<span class="text-amber-600 font-semibold" title="AppBuilder is actively working on this">⚙ In Progress</span>`;
            } else if (r.filed) {
                status = `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline">Filed ↗</a>`;
            } else if (isFeat && _st !== 'approved') {
                // Awaiting admin approval — offer the Approve action inline
                // (Global Admin only; a tenant admin's view is read-only).
                status = (typeof isAdmin === 'function' && isAdmin())
                    ? `<button onclick="event.stopPropagation(); approveBugReport('${escapeHtml(r.id)}')" class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-600 text-white hover:bg-emerald-700" title="Approve this feature so AppBuilder can file &amp; work it">Approve</button>`
                    : `<span class="text-amber-600" title="Awaiting a Global Admin's approval">Pending approval</span>`;
            } else if (isFeat && _st === 'approved') {
                status = `<span class="text-emerald-600 font-medium" title="Approved — AppBuilder will file &amp; work it">Approved</span>`;
            } else {
                status = `<span class="text-amber-600">Pending</span>`;
            }
            return `<div onclick="showBugReport('${escapeHtml(r.id)}')" class="px-4 py-2 border-b border-slate-100 hover:bg-slate-50 cursor-pointer flex items-center gap-3">
                <span class="text-slate-400 w-44 shrink-0">${escapeHtml(ts)}</span>
                ${typeBadge}
                <span class="shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevColor}">${escapeHtml(sev)}</span>
                <span class="flex-1 truncate text-slate-700">${escapeHtml(r.summary || '(no summary)')}</span>
                <span class="shrink-0 text-[10px] text-slate-400 font-mono">${escapeHtml(r.id)}</span>
                <span class="shrink-0 w-20 text-center text-xs font-medium">${status}</span>
                ${(typeof isAdmin === 'function' && isAdmin()) ? `<button onclick="event.stopPropagation(); deleteBugReport('${escapeHtml(r.id)}')" title="Delete report" class="shrink-0 p-1 text-slate-300 hover:text-red-500 transition-colors"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>` : ''}
            </div>`;
        }).join('');
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${kindLabel}s: ${err.message}</div>`;
    }
}

// ── Remote Client Debug Log panel ────────────────────────────────────────────
// Streams one cs client's debug logs from the hub's per-host ring buffer
// (CS_DEBUG_LOG → _handle_cs_debug_log → GET /api/cs/clients/{host}/debug-logs).
// Clones loadRecoveryLogs' shape but feeds the hub's {ts,level,line} entries
// reformatted into the canonical "<ts> - <src> - DEBUG - <line>" string the
// shared _renderGroupedLogs/_renderLogLineRow/_logLineKey helpers expect, so
// repeat-collapsing + timestamp highlighting work unchanged. Live-refreshes via
// pollManager (modeled on startLeInflightPollers/clearLeInflightPollers): the
// poller self-unregisters when the modal is gone, so no manual clearInterval.
let _clientDebugPoller = null;
function _clientDebugFmtTs(epoch) {
    // YYYY-MM-DD HH:MM:SS (UTC) — the regex in _renderLogLineRow keys on this
    // exact shape; entries carry the hub receive time (epoch seconds), not a
    // pre-formatted asctime. UTC keeps it unambiguous across boxes.
    const d = new Date((epoch || 0) * 1000);
    const p = n => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}
async function _loadClientDebugLog(host, tenantRaw) {
    const container = document.getElementById('client-debug-log-body');
    if (!container) return;
    try {
        const data = await apiJson(`/api/cs/clients/${encodeURIComponent(host)}/debug-logs?tenant=${encodeURIComponent(tenantRaw || '')}`);
        const headerEl = document.getElementById('client-debug-status');
        if (headerEl) {
            const until = data.active_until ? new Date(data.active_until * 1000).toLocaleTimeString() : null;
            headerEl.innerHTML = data.active
                ? `<span class="text-green-600 font-semibold">● Active</span>${data.level ? ` · ${escapeHtml(data.level)}` : ''}${until ? ` · auto-off ~${escapeHtml(until)}` : ''}`
                : `<span class="text-slate-400">○ Inactive</span>`;
        }
        // Newest-first (the deque iterates oldest→newest); format each entry to
        // the canonical log-line shape so _renderGroupedLogs groups repeats.
        const lines = (data.logs || []).slice().reverse()
            .map(e => `${_clientDebugFmtTs(e.ts)} - ${host}:${e.level || 'basic'} - DEBUG - ${e.line || ''}`);
        container.innerHTML = lines.length === 0
            ? `<div class="py-12 text-center text-slate-400 italic">No debug log lines yet for ${escapeHtml(host)}. Enable Debug then wait a few seconds for the client's tailer to stream up.</div>`
            : _renderGroupedLogs(lines);
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading debug logs: ${err.message}</div>`;
    }
}
window.openClientDebugLog = function (host, tenantRaw) {
    const body = `
      <div class="flex items-center justify-between mb-2">
        <h3 class="text-sm font-bold text-slate-700">Client Debug Log — <span class="font-mono">${escapeHtml(host)}</span></h3>
        <span id="client-debug-status" class="text-xs text-slate-400"></span>
      </div>
      <div class="flex justify-end gap-2 mb-2">
        <button onclick="window._clientDebugStop('${escapeHtml(host)}','${escapeHtml(tenantRaw || '')}')"
          class="bg-red-100 hover:bg-red-200 text-red-700 px-3 py-1 rounded text-xs font-bold">Stop Debug</button>
      </div>
      <div id="client-debug-log-body" class="h-[34rem] overflow-y-auto bg-white border border-slate-200 rounded-md text-slate-700"></div>
      <p class="text-[10px] text-slate-400 mt-2">Live logs from the client's <code>sim.log</code> + debug logs (advanced adds journal/dmesg). Ephemeral — cleared on hub restart. 30-min auto-off. Times are UTC.</p>`;
    openModal('client-debug-modal', body,
        { card: 'w-full max-w-3xl p-5 max-h-[92vh] flex flex-col', backdropClose: true });
    if (_clientDebugPoller) { pollManager.unregister(_clientDebugPoller); _clientDebugPoller = null; }
    _loadClientDebugLog(host, tenantRaw);
    _clientDebugPoller = pollManager.register(() => {
        // Self-clean: when the modal was closed (backdrop/Stop/close), the next
        // tick finds it gone and unregisters — no separate close handler needed.
        if (!document.getElementById('client-debug-modal')) {
            pollManager.unregister(_clientDebugPoller); _clientDebugPoller = null; return;
        }
        _loadClientDebugLog(host, tenantRaw);
    }, 3000);
};
window._clientDebugStop = async function (host, tenantRaw) {
    try {
        await apiJson(`/api/cs/clients/${encodeURIComponent(host)}/debug?tenant=${encodeURIComponent(tenantRaw || '')}`,
            { method: 'DELETE' });
        showToast(`Debug stopped for ${host}`, 'success');
        _loadClientDebugLog(host, tenantRaw);
    } catch (e) { showToast(`Stop failed: ${e.message}`, 'error'); }
};

async function deleteBugReport(rid) {
    if (!rid) return;
    if (!await showConfirmToast(`Delete bug report ${rid}? This removes the stored console / HTML / screenshot artifacts on the hub. The public GitHub issue (if ab already filed one) is NOT touched.`)) return;
    try {
        await apiJson(`/setup/bug-reports/${encodeURIComponent(rid)}`, { method: 'DELETE' });
        showToast('Bug report deleted', 'success');
        // Close the detail modal if open, then refresh the list if it's mounted.
        const ov = document.getElementById('bug-detail-overlay');
        if (ov) ov.remove();
        const _c = document.getElementById('system-logs-container');
        if (_c) loadBugReports(_c.dataset.bugFilter || undefined);
    } catch (e) {
        showToast(`Delete failed: ${e.message}`, 'error');
    }
}
window.deleteBugReport = deleteBugReport;

async function approveBugReport(rid) {
    // Admin approves a feature request → ab may then file the GitHub issue
    // and work it (unapproved features are hidden from ab). Bugs skip this.
    if (!rid) return;
    try {
        await apiJson(`/setup/bug-reports/${encodeURIComponent(rid)}/approve`, { method: 'POST' });
        showToast('Feature approved — AppBuilder will file &amp; work it', 'success');
        const c = document.getElementById('system-logs-container');
        if (c) loadBugReports(c.dataset.bugFilter || undefined);
    } catch (e) {
        showToast(`Approve failed: ${e.message}`, 'error');
    }
}
window.approveBugReport = approveBugReport;

async function showBugReport(rid) {
    const overlay = document.createElement('div');
    overlay.id = 'bug-detail-overlay';
    overlay.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-[100] p-4';
    overlay.innerHTML = `
        <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div class="px-5 py-3 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 id="bug-detail-title" class="text-sm font-bold text-slate-700">Bug Report <span class="font-mono text-slate-400">${escapeHtml(rid)}</span></h3>
                <div class="flex items-center gap-3">
                    <button onclick="deleteBugReport('${escapeHtml(rid)}')" title="Delete report" class="text-xs font-bold text-red-500 hover:text-red-700 border border-red-200 hover:border-red-300 px-3 py-1 rounded transition-colors">Delete</button>
                    <button onclick="document.getElementById('bug-detail-overlay').remove()" class="text-slate-400 hover:text-slate-600 text-xl">✕</button>
                </div>
            </div>
            <div id="bug-detail-body" class="p-5 overflow-y-auto text-xs space-y-4">
                <div class="py-12 text-center text-slate-400 animate-pulse">Loading...</div>
            </div>
        </div>`;
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    document.body.appendChild(overlay);
    const body = overlay.querySelector('#bug-detail-body');
    try {
        const r = await apiJson(`${_bugReportsBase()}/${encodeURIComponent(rid)}`);
        const ctx = r.context || {};
        let report = {};
        try { report = JSON.parse(r.report_json || '{}'); } catch { report = {}; }
        const consoleText = r.console || '(no console captured)';
        const domText = (r.dom || '').slice(0, 4000) || '(no HTML captured)';
        const isFeat = (r.type || (report.type || 'bug')) === 'feature';
        const sev = r.severity || 'medium';
        const titleEl = overlay.querySelector('#bug-detail-title');
        if (titleEl) titleEl.innerHTML = `${isFeat ? '💡 Feature Request' : '🐛 Bug Report'} <span class="font-mono text-slate-400">${escapeHtml(rid)}</span>`;
        const _dst = (r.status || (r.filed ? 'filed' : '')).toLowerCase();
        let status;
        if (_dst === 'closed') {
            status = `<span class="text-slate-500 font-semibold">⊘ Closed (not fixed) — the issue was closed on GitHub without a fix</span> — <a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline break-all">${escapeHtml(r.issue_url || 'GitHub issue')}</a>`;
        } else if (_dst === 'fixed') {
            status = `<span class="text-green-600 font-semibold">✓ Fixed (issue closed on GitHub)</span> — <a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline break-all">${escapeHtml(r.issue_url || 'GitHub issue')}</a>`;
        } else if (_dst === 'duplicate') {
            status = `<span class="text-slate-500 font-semibold">⧉ Duplicate</span> — same issue: <a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline break-all">${escapeHtml(r.issue_url || 'GitHub issue')}</a>`;
        } else if (r.filed) {
            status = `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline break-all">${escapeHtml(r.issue_url || 'Filed')}</a>`;
        } else if (isFeat && _dst !== 'approved') {
            const _approveBtn = (typeof isAdmin === 'function' && isAdmin())
                ? ` <button onclick="approveBugReport('${escapeHtml(rid)}')" class="ml-2 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-600 text-white hover:bg-emerald-700">Approve</button>`
                : '';
            status = `<span class="text-amber-600">Awaiting approval</span>${_approveBtn}`;
        } else if (isFeat && _dst === 'approved') {
            status = `<span class="text-emerald-600 font-medium">Approved — AppBuilder will file &amp; work it</span>`;
        } else {
            status = `<span class="text-amber-600">Pending — ab has not filed this yet</span>`;
        }
        const shot = r.screenshot_b64
            ? `<img src="${escapeHtml(r.screenshot_b64)}" class="mt-2 max-w-full rounded border border-slate-200" alt="screenshot">`
            : `<span class="text-slate-400 italic">No screenshot captured</span>`;
        body.innerHTML = `
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Status</div>
                <div class="text-sm">${status}</div>
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Explanation</div>
                <div class="text-sm text-slate-700 whitespace-pre-wrap">${escapeHtml(report.explanation || r.summary || '(none)')}</div>
            </div>
            <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <div><span class="text-slate-400">Type:</span> <span class="font-medium">${isFeat ? '💡 Feature Request' : '🐛 Bug'}</span></div>
                <div><span class="text-slate-400">Severity:</span> <span class="font-medium">${escapeHtml(sev)}</span></div>
                <div><span class="text-slate-400">View:</span> <span class="font-medium">${escapeHtml(ctx.currentView || '—')}</span></div>
                <div><span class="text-slate-400">URL:</span> <span class="font-medium break-all">${escapeHtml(ctx.url || '—')}</span></div>
                <div><span class="text-slate-400">Tenant:</span> <span class="font-medium">${escapeHtml(ctx.currentTenant || '—')}</span></div>
                <div><span class="text-slate-400">Hub:</span> <span class="font-medium">${escapeHtml(ctx.hubVersion || '—')}</span></div>
                <div><span class="text-slate-400">WebUI:</span> <span class="font-medium">${escapeHtml(ctx.webuiVersion || '—')}</span></div>
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Screenshot</div>
                ${shot}
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Console</div>
                <pre class="bg-slate-900 text-slate-100 p-3 rounded max-h-64 overflow-auto whitespace-pre-wrap">${escapeHtml(consoleText)}</pre>
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">DOM (first 4KB)</div>
                <pre class="bg-slate-900 text-slate-100 p-3 rounded max-h-64 overflow-auto whitespace-pre-wrap break-all">${escapeHtml(domText)}</pre>
            </div>`;
    } catch (err) {
        body.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading bug report: ${err.message}</div>`;
    }
}
