// certificates.js — Certificate management (le), spoke registry diagnostics, DNS records.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── Certificate Management (le) view ──────────────────────────────────────
// Status bar (managed count) + a certificates table. The le spoke's handlers
// are structured stubs until certbot/acme.sh is wired, so the table is usually
// empty and the status bar carries the "not yet wired" message from the spoke.
// Static legend under the Certificates table — what the target status badges,
// the Add chips, and the expiry colors mean. Same look as the Spokes/Clients
// legends.
// certbot / ACME-profile diagnostic panel on the Certificates page. Surfaces the
// le spoke's certbot version + whether it supports ACME profiles (--preferred-profile,
// certbot >=4.0) + the CA's advertised profiles — the answer to "I requested
// clientAuth / short-lived but the cert didn't change". Fetches /api/le/acme-info.
async function loadLeAcmeInfo() {
    const el = document.getElementById('le-acme-info');
    if (!el) return;
    const esc = (s) => escapeHtml(String(s == null ? '' : s));
    try {
        const r = await _spokeFetch('/api/le/acme-info');
        const a = (r.ok && r.data) ? r.data : {};
        if (a.available === false) {
            el.innerHTML = `<div class="px-3 py-2 rounded-md bg-slate-50 border border-slate-200 text-slate-500">certbot / ACME info unavailable: ${esc(a.reason || a.error || 'le spoke not connected')}</div>`;
            return;
        }
        const profs = a.profiles || {};
        const names = Object.keys(profs);
        const supp = a.supports_profiles;
        const reqProfile = a.clientauth_profile || 'classic';
        const reqMissing = names.length && !names.includes(reqProfile);
        const profChips = names.length
            ? names.map(n => `<span class="inline-block px-1.5 py-0.5 rounded ${/classic/i.test(n) ? 'bg-[#01A982]/15 text-[#01A982]' : 'bg-slate-100 text-slate-600'} font-mono mr-1" title="${esc(profs[n] || '')}">${esc(n)}</span>`).join('')
            : `<span class="text-amber-600">CA advertises no profiles (this ACME server may not support profile selection)</span>`;
        const warn = (supp === false)
            ? `<div class="mt-1 text-red-600 font-bold">⚠ certbot too old (need ≥ 4.0) — the le spoke's certbot auto-upgrade hasn't landed; clientAuth/short-lived profiles will be ignored until it does.</div>`
            : (reqMissing ? `<div class="mt-1 text-red-600 font-bold">⚠ clientAuth profile "${esc(reqProfile)}" is NOT in the CA's list — set LM_LE_CLIENTAUTH_PROFILE to one of the names above.</div>` : '');
        el.innerHTML = `<div class="px-3 py-2 rounded-md bg-slate-50 border border-slate-200 text-slate-600">
            <span class="font-bold uppercase tracking-wider text-slate-400 mr-2">certbot / ACME</span>
            <span>certbot <span class="font-mono">${esc(a.certbot_version || '?')}</span></span>
            <span class="mx-2 text-slate-300">|</span>
            <span>profiles: <b class="${supp ? 'text-[#01A982]' : 'text-red-600'}">${supp === null ? 'unknown' : (supp ? 'supported' : 'NOT supported')}</b></span>
            <span class="mx-2 text-slate-300">|</span>
            <span>clientAuth via <span class="font-mono">${esc(reqProfile)}</span></span>
            <div class="mt-1">CA profiles: ${profChips}</div>
            ${warn}
        </div>`;
    } catch (e) {
        el.innerHTML = `<div class="px-3 py-2 rounded-md bg-slate-50 border border-slate-200 text-slate-500">certbot / ACME info error: ${esc(e.message || e)}</div>`;
    }
}

function _leLegend() {
    const pill = (cls, t) => `<span class="${cls} px-1.5 py-0.5 rounded text-xs font-medium">${t}</span>`;
    const lbl = t => `<span class="font-bold uppercase tracking-wider text-slate-400 mr-1">${t}</span>`;
    return `<div class="mt-4 mx-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500 pb-3">
      <span class="font-bold uppercase tracking-wider text-slate-400">Legend</span>
      <div class="mt-2 space-y-1.5">
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Target')}
          <span class="flex items-center gap-1.5">${pill('bg-green-100 text-green-700', '\u2713 target')} deployed OK</span>
          <span class="flex items-center gap-1.5">${pill('bg-red-100 text-red-700', '\u2717 target')} last push failed</span>
          <span class="flex items-center gap-1.5">${pill('bg-slate-100 text-slate-500', '\u00b7 target')} pending (not pushed yet)</span>
          <span class="flex items-center gap-1.5">${pill('bg-amber-100 text-amber-800 border border-amber-300', '\u25cf target 3s')} deploying now</span>
          <span class="text-slate-400">click a target badge to re-deploy</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Add')}
          <span class="flex items-center gap-1.5">${pill('bg-[#01A982]/10 text-[#01A982] border border-[#01A982]', 'target \u2713')} added (this cert deploys here)</span>
          <span class="flex items-center gap-1.5">${pill('bg-slate-100 text-slate-500 border border-slate-200', 'target +')} available — click to add</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Cert')}
          <span class="flex items-center gap-1.5">${pill('bg-purple-100 text-purple-700', '★ AppBuilder')} pinned mTLS identity (hub mints its clientAuth cert from the Local CA)</span>
          <span class="flex items-center gap-1.5">${pill('bg-amber-100 text-amber-700', 'shortlived')} non-default ACME profile (short-lived ~7d). mTLS client certs come from the 🔒 hub Local CA, not here.</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Expiry')}
          <span class="flex items-center gap-1.5">${pill('bg-green-100 text-green-700', '&gt; 30d')} healthy</span>
          <span class="flex items-center gap-1.5">${pill('bg-amber-100 text-amber-700', '&lt; 30d')} renew due</span>
          <span class="flex items-center gap-1.5">${pill('bg-red-100 text-red-700', '&lt; 7d / expired')} at risk</span>
        </div>
      </div>
    </div>`;
}

// Friendly challenge-type label for the Certificates table. The le spoke stores
// the ACME challenge (e.g. "dns"/"dns-01"); show DNS-01 variants as just "DNS".
function _leChallengeLabel(v) {
    const s = String(v || '').toLowerCase();
    if (s === 'dns' || s === 'dns-01' || s === 'dns01') return 'DNS';
    return v || '—';
}

async function loadLEData(subMenu) {
    // Holds the _lmNavSeq of the running load. A load from an earlier navigation
    // doesn't block: lmFetch dropped its response, so its finally never runs.
    if (window._leLoading === _lmNavSeq) return;  // don't overlap the inflight poller
    const container = document.getElementById('le-content');
    if (!container) return;
    const nav = _lmNavSeq;
    window._leLoading = nav;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    // Live in-flight indicators (yellow target badges + elapsed timer) need a
    // periodic refresh so a deploy transitions when it completes — start the
    // poller/ticker for this tab (idempotent; cleared on tab switch).
    startLeInflightPollers();
    // Hub-level wildcard fan-out toggle (OFF while testing).
    loadLeWildcardAllSpokes();
    // Hub-level failed-distribution retry interval (hours; default 1).
    loadLeRetryInterval();
    // certbot / ACME-profile diagnostic (why a clientAuth/short-lived re-issue may
    // not apply): certbot version + the CA's advertised profiles.
    loadLeAcmeInfo();

    const th = tableHead, tw = tableWrap;  // shared table helpers
    // The le spoke returns nested {status, data:{...}}; unwrap to the inner data
    // so both the nested le shape and a flat sibling shape resolve the same way.
    const inner = b => (b && typeof b.data === 'object' && b.data !== null) ? b.data : (b || {});

    // Status bar from /api/le/status (best-effort — falls back to the certs call).
    try {
        const s = await _spokeFetch('/api/le/status');
        const bar = document.getElementById('le-status-bar');
        if (bar && s.ok && s.data) {
            const d = inner(s.data);
            bar.innerHTML =
                `<span><b class="text-sm text-slate-700">${d.certs_managed ?? 0}</b> Certificates Managed</span>`;
        } else if (bar) {
            bar.innerHTML = `<span class="text-amber-600">${s.detail || 'le spoke not connected'}</span>`;
        }
    } catch (e) { /* status is decorative; the certs call surfaces the real error */ }

    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/le/certs?tenant=' + encodeURIComponent(currentTenant));
        if (!ok) {
            container.innerHTML = `${_spokeErrorBanner(detail, 'Certificate (le) spoke not connected')}${_isSpokeUpdating(detail) ? '' : '<p class="px-4 pb-4 text-xs text-slate-400">Install the le spoke (install_all.sh, or its install_le.sh) and approve it in Setup → Spokes &amp; Agents.</p>'}`;
            return;
        }
        const body = inner(d);
        const certs = body.certs || [];
        window._leCerts = certs;
        // In-flight distributions: targets the hub is currently pushing (waiting
        // on INSTALL_CERT confirmation). Fetched from the hub (not the le spoke)
        // and merged into the badges by domain|module_type|identifier so a
        // deploying target shows yellow with a live elapsed timer instead of its
        // stale last_status. See startLeInflightPollers for the periodic refresh.
        try {
            const ifr = await _spokeFetch('/api/le/inflight');
            const ifb = (ifr && ifr.ok) ? inner(ifr.data) : null;
            const ifList = (ifb && Array.isArray(ifb.inflight)) ? ifb.inflight : [];
            const imap = {};
            for (const it of ifList) imap[`${it.domain}|${it.module_type}|${it.identifier || ''}`] = it.since;
            window._leInflightMap = imap;
        } catch (e) { window._leInflightMap = {}; }
        // Available cert-capable targets (connected spokes/agents) — fetched once
        // per load and cached for the Manage modal (showLeTargetsModal) so its
        // module <select> lists only connected cert-capable spokes/agents. Adding
        // /removing a target is done via Manage, not inline on the main screen.
        try {
            const ar = await _spokeFetch('/api/le/targets/available');
            const ab = (ar && ar.ok) ? inner(ar.data) : null;
            window._leAvailableTargets = (ab && Array.isArray(ab.targets)) ? ab.targets : [];
        } catch (e) { window._leAvailableTargets = []; }
        const inflightMap = window._leInflightMap || {};
        // Friendly "how long ago" for a target's last_pushed_at — relative time
        // makes a re-push loop obvious at a glance (e.g. "2m ago" that keeps
        // resetting), with the absolute local time in parentheses.
        const _leWhen = (iso) => {
            if (!iso) return 'never';
            const dt = new Date(iso);
            if (isNaN(dt)) return String(iso);
            const secs = Math.max(0, Math.floor((Date.now() - dt.getTime()) / 1000));
            let rel;
            if (secs < 60) rel = `${secs}s ago`;
            else if (secs < 3600) rel = `${Math.floor(secs / 60)}m ago`;
            else if (secs < 86400) rel = `${Math.floor(secs / 3600)}h ago`;
            else rel = `${Math.floor(secs / 86400)}d ago`;
            return `${rel} (${dt.toLocaleString()})`;
        };
        const tgtBadge = (t, domain) => {
            const dEsc = escJsAttr(String(domain || ''));
            const mtEsc = escJsAttr(String(t.module_type || ''));
            const idEsc = escJsAttr(String(t.identifier || ''));
            const ifk = `${domain}|${t.module_type}|${t.identifier || ''}`;
            const since = inflightMap[ifk];
            // Purple ★ prefix for the ab target so it's visually distinct
            // from fleet/spoke targets — this is the target the AppBuilder agent
            // presents the cert to over mTLS. (The cert's AppBuilder-identity tag
            // itself is set via the checkbox inside Manage.)
            const isBf = String(t.module_type || '').toLowerCase() === 'ab';
            const bfStar = isBf ? `<span class="text-purple-600 font-bold mr-0.5" title="AppBuilder target — ab presents this cert over mTLS">★</span>` : '';
            if (since) {
                // Yellow while we wait for deployment confirmation. The elapsed
                // span is updated every 1s by updateLeInflightTimers. Not
                // clickable — a deploy is already running for this target.
                return `<span class="px-1.5 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 border border-amber-300" data-inflight-since="${since}" title="Deployment in progress…">
                    <span class="inline-block w-2 h-2 rounded-full bg-amber-500 animate-pulse mr-1 align-middle"></span>${bfStar}${t.module_type}${t.identifier ? '/' + t.identifier : ''} <span class="le-inflight-elapsed" data-elapsed-since="${since}">0s</span>
                </span>`;
            }
            const ok = t.last_status === 'SUCCESS';
            const cls = ok ? 'bg-green-100 text-green-700' : (t.last_status === 'ERROR' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500');
            const mark = ok ? '✓' : (t.last_status === 'ERROR' ? '✗' : '·');
            const label = `${t.module_type}${t.identifier ? '/' + t.identifier : ''}`;
            // Surface the last push OUTCOME (status + message + when) in the
            // tooltip so an operator sees success/errors without SSHing to the
            // node — the whole point of the le.distribution log, brought to the
            // badge. Failed targets also get an inline red line below (errNote).
            const when = t.last_pushed_at ? _leWhen(t.last_pushed_at) : 'never';
            const statusTxt = t.last_status || 'not pushed yet';
            const msgPart = t.last_message ? ` — ${t.last_message}` : '';
            const tip = `${label}: ${statusTxt}${msgPart} (last push: ${when}). Click to deploy now.`;
            const btn = `<button onclick="leDeployTarget('${dEsc}','${mtEsc}','${idEsc}')" class="px-1.5 py-0.5 rounded text-xs font-medium ${cls} cursor-pointer hover:brightness-95 active:scale-95 transition" title="${escJsAttr(tip)}">${mark} ${bfStar}${label}</button>`;
            // Fleet spokes (nw): the spoke-level badge above is the success
            // signal (spoke holds the cert). The per-device detail lives in a
            // collapsed, lazy-loaded section BELOW the targets (leFleetDetail) —
            // the badge just carries the aggregate; the section shows the fleet.
            return btn;
        };
        // Color-coded expiry badge from not_after. The le renewal loop renews
        // within 30d, so amber (<30d) = renew pending/failed, red (<7d / expired)
        // = at risk — surfaces a stuck renewal the hourly distribution wouldn't.
        const leExpiry = na => {
            if (!na) return { text: '—', cls: 'text-slate-400', days: null };
            const dt = new Date(na);
            if (isNaN(dt)) return { text: String(na).slice(0, 10), cls: 'text-slate-500', days: null };
            const days = Math.floor((dt.getTime() - Date.now()) / 86400000);
            let cls, label;
            if (days < 0) { cls = 'bg-red-100 text-red-700'; label = `expired ${-days}d ago`; }
            else if (days < 7) { cls = 'bg-red-100 text-red-700'; label = `${days}d left`; }
            else if (days < 30) { cls = 'bg-amber-100 text-amber-700'; label = `${days}d left`; }
            else { cls = 'bg-green-100 text-green-700'; label = `${days}d left`; }
            return { text: `${dt.toISOString().slice(0, 10)} · ${label}`, cls, days };
        };
        const cols = ['Domain', 'Email', 'Challenge', 'Staging', 'Expires', 'Actions'];
        // Per-domain last-issue indicator. Prefers the in-memory tracker
        // (window._leIssueStatus, fed by _leRunIssue this session) but falls
        // back to the BACKEND-persisted last_issue_error on the cert entry, so a
        // failed issue still shows red + offers Edit/Retry after a reboot or a
        // fresh page load (the tracker is memory-only and empty then).
        const issueDot = domain => {
            const st = window._leIssueStatus && window._leIssueStatus[domain];
            if (st) {
                if (st.state === 'pending') return `<span class="inline-block w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse mr-2 align-middle" title="Issuing…"></span>`;
                if (st.state === 'success') return `<span class="inline-block w-2.5 h-2.5 rounded-full bg-green-500 mr-2 align-middle" title="Last issue succeeded"></span>`;
                if (st.state === 'failed') return `<span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500 mr-2 align-middle" title="Last issue failed: ${escJsAttr(st.message || '')}"></span>`;
            }
            const cc = (window._leCerts || []).find(x => x.domain === domain);
            if (cc && cc.last_issue_error) return `<span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500 mr-2 align-middle" title="Last issue failed: ${escJsAttr(cc.last_issue_error)}"></span>`;
            return '';
        };
        const rows = certs.map(c => {
            const dEsc = escJsAttr(c.domain || '');
            const st = window._leIssueStatus && window._leIssueStatus[c.domain];
            const isFailed = (st && st.state === 'failed') || !!c.last_issue_error;
            const tgts = c.targets || [];
            const tgtBadges = tgts.length
                ? `<div class="flex flex-wrap gap-1">${tgts.map(t => tgtBadge(t, c.domain)).join('')}</div>`
                : `<span class="text-xs text-slate-400 italic">none yet — click Manage to add</span>`;
            // Warn when a group ("all nodes") AND an individual node target are
            // both selected for the same agent-hosting type — they deploy the
            // same cert to the same node(s) (in the split topology hypervisor +
            // simulation share the cs-owned agents), causing pveproxy restart
            // contention. Surfaces an existing overlap; addLeTarget also confirms.
            const _redund = _leRedundantTargetTypes(tgts);
            const redundNote = _redund.length
                ? `<div class="mt-1 flex items-start gap-1 text-[11px] text-amber-700" title="${escJsAttr(_LE_TARGET_OVERLAP_HINT)}">
                     <span class="leading-4">⚠</span>
                     <span>Both a group (<b>all nodes</b>) and an individual node target are selected for <b>${escapeHtml(_redund.join(', '))}</b> — these deploy the same cert to the same node(s) and cause repeated restarts. Keep one or the other.</span>
                   </div>`
                : '';
            // Inline last-push OUTCOME for failed targets — the error message +
            // when, shown WITHOUT a hover so an operator sees why a deploy failed
            // (and spots a re-push loop via the ticking "Xs ago") straight from
            // the Certificates list instead of SSHing to the node.
            const _failed = tgts.filter(t => t.last_status === 'ERROR');
            const errNote = _failed.length
                ? `<div class="mt-1 space-y-0.5">${_failed.map(t =>
                    `<div class="text-[11px] text-red-600 flex items-start gap-1"><span class="leading-4">✗</span><span><b>${escapeHtml(t.module_type + (t.identifier ? '/' + t.identifier : ''))}</b>: ${escapeHtml(t.last_message || 'failed')}${t.last_pushed_at ? ` <span class="text-red-400">— ${escapeHtml(_leWhen(t.last_pushed_at))}</span>` : ''}</span></div>`).join('')}</div>`
                : '';
            const tgtCell = `${tgtBadges}${redundNote}${errNote}${leFleetDetail(c.domain, tgts)}`;
            const exp = leExpiry(c.not_after);
            const retryBtn = isFailed
                ? `<button onclick="leEditIssue('${dEsc}')" class="text-xs text-slate-600 hover:text-slate-800 font-medium" title="Edit the failed request and re-file">Edit</button>
                   <button onclick="leRetryIssue('${dEsc}')" class="text-xs text-amber-700 hover:text-amber-800 font-medium" title="Retry last issue (re-uses the stored params)">Retry</button>`
                : '';
            // Inline badges beside the domain (see the legend at the bottom of the
            // page). ★ AppBuilder = pinned mTLS identity; 🔐 clientAuth = has the
            // clientAuth EKU (mTLS-client-capable); a profile chip = non-default
            // ACME profile (e.g. a short-lived cert).
            const bfBadge = c.ab ? ` <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-700 align-middle" title="Pinned as the AppBuilder mTLS identity (Manage → ★ AppBuilder)">★ AppBuilder</span>` : '';
            const caBadge = '';
            const profBadge = (c.profile && String(c.profile).toLowerCase() !== 'classic') ? ` <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-700 align-middle" title="ACME profile: ${escapeHtml(String(c.profile))} (lifetime set by the CA profile)">${escapeHtml(String(c.profile))}</span>` : '';
            // Owner-tenant chips + a shared badge. A cert is owned by one or more
            // tenants (auto-assigned to the issuer's tenant); a "Shared" cert may
            // be deployed by any tenant to their own devices but only changed by
            // an owner/admin. Legacy certs (no owners) show nothing here.
            const _tenChips = (c.tenants || []).map(t =>
                `<span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 align-middle" title="Owner tenant">${escapeHtml(String(t))}</span>`).join(' ');
            const sharedBadge = c.shared ? ` <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-teal-100 text-teal-700 align-middle" title="Shared certificate — any tenant may deploy it to their own devices, but only an owner/admin may change it">Shared</span>` : '';
            const roBadge = (c.can_edit === false) ? ` <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-200 text-slate-500 align-middle" title="Read-only — this certificate belongs to another tenant. You can deploy it to your own devices but not change it.">read-only</span>` : '';
            const tenChips = _tenChips ? ` ${_tenChips}${sharedBadge}${roBadge}` : (sharedBadge + roBadge);
            // Change ops (Renew/Revoke) require ownership; a read-only (shared,
            // not-owned) cert only exposes Manage (→ deploy to your own devices).
            const canEdit = (c.can_edit !== false);
            const manageBtn = `<button onclick="showLeTargetsModal('${dEsc}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold transition-all shadow-sm" title="${canEdit ? 'Manage distribution targets, AppBuilder identity + clientAuth' : 'Deploy this shared certificate to your own devices'}">${canEdit ? 'Manage' : 'Deploy'}</button>`;
            const changeBtns = canEdit
                ? `<button onclick="leRenewCert('${dEsc}')" class="bg-slate-700/10 hover:bg-slate-700/20 text-slate-700 border border-slate-700 px-3 py-1.5 rounded-md text-xs font-bold transition-all shadow-sm" title="Renew this cert">Renew</button>
                            <button onclick="leRevokeCert('${dEsc}')" class="bg-red-600/10 hover:bg-red-600/20 text-red-600 border border-red-600 px-3 py-1.5 rounded-md text-xs font-bold transition-all shadow-sm" title="Revoke + remove from managed list">Revoke</button>`
                : '';
            // 2-row group per cert: row 1 = the data (domain, email, challenge,
            // staging, expiry+renew-window) WITH the Manage/Renew/Revoke actions
            // stacked vertically in a pinned-right Actions cell on that same row
            // (so the cert name + renewal time sit beside the buttons that act on
            // them); row 2 = the clickable targets list alone (full width below).
            // Targets moved out of the data row so each badge has room to be a
            // click-to-deploy button (mirrors the CS spoke-clients click-to-act).
            return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-mono font-medium">${issueDot(c.domain)}${c.domain || '—'}${bfBadge}${caBadge}${profBadge}${tenChips}</td>
                <td class="px-4 py-2 text-xs">${c.email || '—'}</td>
                <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-700">${escapeHtml(_leChallengeLabel(c.challenge))}</span></td>
                <td class="px-4 py-2 text-center text-xs">${c.staging ? 'yes' : 'no'}</td>
                <td class="px-4 py-2 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded-full text-xs font-medium ${exp.cls} whitespace-nowrap">${exp.text}</span>
                    <div class="text-[11px] text-slate-400 mt-0.5" title="Renewal loop triggers this many days before expiry (per-cert override; default 7)">renew @ ${c.renew_window_days_effective ?? 7}d</div>
                </td>
                <td class="px-4 py-2 whitespace-nowrap">
                    <div class="flex flex-col items-end gap-1.5">
                        ${retryBtn ? `<div>${retryBtn}</div>` : ''}
                        <div class="flex flex-row items-center justify-end gap-1.5">
                            ${manageBtn}
                            ${changeBtns}
                        </div>
                    </div>
                </td>
            </tr>
            <tr class="border-b border-slate-200 hover:bg-slate-50">
                <td colspan="6" class="px-4 py-2">
                    <div class="flex flex-wrap items-center gap-1.5">
                        <span class="text-[11px] text-slate-400 uppercase tracking-wide mr-1">Targets</span>
                        ${tgtCell}
                    </div>
                </td>
            </tr>`;
        }).join('');
        // Pending / failed attempt rows for domains that have NO cert yet —
        // surfaced above the cert rows so a red indicator + Retry appear even
        // before a cert exists (the issue failed, nothing was issued). On a
        // successful retry the domain graduates to a green cert row and the
        // attempt row drops out (certsDomains then contains it).
        const certsDomains = new Set(certs.map(c => c.domain));
        const tracked = window._leIssueStatus || {};
        const attemptRows = Object.entries(tracked)
            .filter(([dom, s]) => !certsDomains.has(dom) && (s.state === 'pending' || s.state === 'failed'))
            .sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0))
            .map(([dom, s]) => {
                const dEsc = escJsAttr(dom);
                if (s.state === 'pending') {
                    return `<tr class="border-b border-slate-100 bg-amber-50/60">
                        <td class="px-4 py-2 font-mono font-medium"><span class="inline-block w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse mr-2 align-middle"></span>${escapeHtml(dom)}</td>
                        <td class="px-4 py-2 text-xs italic text-amber-700" colspan="4">issuing…</td>
                        <td class="px-4 py-2"></td>
                    </tr>`;
                }
                return `<tr class="border-b border-slate-100 bg-red-50/60">
                    <td class="px-4 py-2 font-mono font-medium"><span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500 mr-2 align-middle"></span>${escapeHtml(dom)}</td>
                    <td class="px-4 py-2 text-xs text-red-700" colspan="3">last issue failed: ${escapeHtml(s.message || '')}</td>
                    <td class="px-4 py-2"><button onclick="leEditIssue('${dEsc}')" class="text-xs text-slate-600 hover:text-slate-800 font-medium mr-2" title="Edit the failed request and re-file">Edit</button><button onclick="leRetryIssue('${dEsc}')" class="text-xs text-amber-700 hover:text-amber-800 font-medium" title="Retry last issue">Retry</button></td>
                    <td class="px-4 py-2"></td>
                </tr>`;
            }).join('');
        // Top-of-card banner if any cert is expiring soon / expired / stuck
        // renewing (the le loop renews <30d, so amber+red here mean a renewal
        // that didn't land — worth surfacing above the table).
        const soon = certs.filter(c => { const x = leExpiry(c.not_after); return x.days !== null && x.days < 30; });
        const expBanner = soon.length === 0 ? '' : (() => {
            const expired = soon.filter(c => leExpiry(c.not_after).days < 0).length;
            const cls = expired > 0 ? 'bg-red-50 border-red-200 text-red-700' : 'bg-amber-50 border-amber-200 text-amber-700';
            const msg = expired > 0
                ? `${expired} cert(s) EXPIRED, ${soon.length - expired} expiring within 30d — check the le renewal loop / journalctl -u lm-le.`
                : `${soon.length} cert(s) expiring within 30d — the le renewal loop should renew these; verify with ⚡ Distribute now.`;
            return `<div class="mx-4 mt-3 mb-1 px-3 py-2 rounded-md border text-xs ${cls}">${msg}</div>`;
        })();
        // AppBuilder identity indicator — which managed cert is pinned as the
        // AppBuilder mTLS identity (the gate for hub log reads + fleet update
        // commands). Only one cert should be tagged; if several are, list them
        // all so the operator can un-tag the extras. Surfaced as a persistent
        // banner ABOVE the table so you don't have to scan every row's "★
        // AppBuilder" button to find it. c.ab is reconciled from the hub's
        // authoritative pinned list in loadLEData / leToggleAppBuilderChk (the
        // checkbox inside the Manage modal).
        const bfCerts = (certs || []).filter(c => c.ab);
        const bfBanner = (() => {
            if (!bfCerts.length) {
                return '';  // no cert tagged → no banner (guidance lives in Manage)
            }
            const names = bfCerts.map(c => `<span class="font-mono font-bold text-purple-700">${escapeHtml(c.domain || '(unnamed)')}</span>`).join(', ');
            const extra = bfCerts.length > 1 ? ` <span class="text-amber-600">— ${bfCerts.length} tagged; un-tag extras so only one is pinned.</span>` : '';
            const deployed = bfCerts.some(c => (c.targets || []).some(t => (t.module_type || '').toLowerCase() === 'ab'));
            const depNote = deployed
                ? ` <span class="text-green-600">— deployed to a ab target ✓</span>`
                : ` <span class="text-amber-600">— not yet deployed to a ab target (Manage → add a ab target)</span>`;
            return `<div class="mx-4 mt-3 mb-1 px-3 py-2 rounded-md border text-xs bg-purple-50 border-purple-200 text-purple-800 flex items-center gap-2"><span class="text-purple-600 font-bold">★</span><span><b>AppBuilder identity:</b> ${names}${depNote}${extra}</span></div>`;
        })();
        const note = body.message ? `<p class="px-4 pb-3 text-xs text-slate-400 italic">${body.message}</p>` : '';
        container.innerHTML = (certs.length === 0 && !attemptRows)
            ? `${note}<p class="p-4 text-slate-400 italic text-sm">No managed certificates yet. Click <b class="text-slate-600 not-italic">＋ Issue certificate</b> above to configure an ACME account (email + challenge type) and issue your first cert.</p>`
            : bfBanner + expBanner + note + tw(th(cols) + `<tbody>${attemptRows}${rows}</tbody>`) + _leLegend();
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    } finally {
        if (window._leLoading === nav) window._leLoading = false;
    }
}

// ── In-flight distribution indicator (yellow target badge + live timer) ─────
// While the hub is pushing INSTALL_CERT to a target, the target badge turns
// yellow with an elapsed timer — we can't predict how fast a cert will transfer
// or install (esp. the hypervisor path's pveproxy restart, which can take many
// minutes), so "what's in flight" needs a live indicator, not just the stale
// last_status. The 1s ticker updates the elapsed text purely client-side; the
// 12s poller re-renders so a deploy transitions yellow→green/red on completion.
// Started when the Certificates tab loads, cleared on tab switch (setSubView).
let _leInflightPoller = null;
let _leInflightTicker = null;

function updateLeInflightTimers() {
    const now = Date.now();
    document.querySelectorAll('[data-elapsed-since]').forEach(el => {
        const since = Number(el.getAttribute('data-elapsed-since'));
        if (!since) return;
        const secs = Math.max(0, Math.floor((now - since * 1000) / 1000));
        el.textContent = secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m${secs % 60}s`;
    });
}

function clearLeInflightPollers() {
    if (_leInflightPoller) { pollManager.unregister(_leInflightPoller); _leInflightPoller = null; }
    if (_leInflightTicker) { pollManager.unregister(_leInflightTicker); _leInflightTicker = null; }
}

function startLeInflightPollers() {
    if (_leInflightPoller) return;  // idempotent — don't stack intervals
    _leInflightTicker = pollManager.register(updateLeInflightTimers, 1000);
    _leInflightPoller = pollManager.register(() => {
        if (window._leLoading === _lmNavSeq) return;  // don't overlap a manual load
        if (!document.getElementById('le-content')) { clearLeInflightPollers(); return; }
        // Only auto-refresh while a cert distribution is IN FLIGHT (there's a
        // pending deploy whose result we're waiting on) — no constant reloading
        // when the page is idle, which re-rendered the whole table every 12s and
        // felt like a jittery refresh. Idle = the operator refreshes by re-opening
        // the tab or after an action (issue/renew/distribute already reload).
        if (!document.querySelector('[data-inflight-since]')) return;
        loadLEData();
    }, 12000);
}

// Re-push any stale cert material to its targets now (no certbot invocation —
// the hub pulls LE_GET_CERT and pushes INSTALL_CERT for changed targets only).
// The route returns inner.distribution (a flat per-target summary, mirrors
// /api/le/issue) so we can show a per-target toast — without it, Distribute now
// gave zero UI feedback (results were only in Logs/Certificates, which needs a
// manual refresh). SKIPPED entries (no targets / all current) are surfaced so
// the operator sees WHY nothing was pushed instead of an unexplained no-op.
// Wildcard-all-spokes toggle (hub-level, lives in global_config.certs
// .wildcard_all_spokes; OFF by default while the operator tests explicit-target
// distribution). When ON, a wildcard cert (*.domain) is fanned to EVERY
// connected cert-capable spoke + the hub on each distribution, not just its
// explicit targets. Saved via POST /setup/config (shallow-merged into
// global_config; only wildcard_all_spokes lives under "certs" today, so the
// whole-section replace is safe — DNS creds live in the per-tenant store).
async function loadLeWildcardAllSpokes() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const on = ((data.global_config || {}).certs || {}).wildcard_all_spokes === true;
        const el = document.getElementById('le-wildcard-all-spokes');
        if (el) el.checked = on;
    } catch (e) { console.error('loadLeWildcardAllSpokes failed', e); }
}

async function saveLeWildcardAllSpokes(checked) {
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { certs: { wildcard_all_spokes: !!checked } } })
        });
        if (r.ok) showToast(checked
            ? 'Wildcard fan-out ENABLED — next distribution pushes to every cert-capable spoke.'
            : 'Wildcard fan-out disabled.', 'success');
        else showToast('Failed to save wildcard toggle.', 'error');
    } catch (e) { showToast('Error saving wildcard toggle: ' + e.message, 'error'); }
}

// Wildcard fan-out coverage: which spokes WOULD receive a wildcard cert
// (eligible) vs would NOT (ineligible + reason). Read-only view so the operator
// knows the reach of "Fan wildcard → all spokes" before/while using it.
async function showLeWildcardCoverage() {
    let d;
    try {
        const r = await _spokeFetch('/api/le/wildcard/eligibility');
        d = (r && r.ok) ? (r.data && typeof r.data.data === 'object' ? r.data.data : r.data) : null;
        if (!d) throw new Error((r && r.detail) || 'failed to load');
    } catch (e) { showToast('Coverage failed: ' + (e.message || e), 'error'); return; }
    const elig = d.eligible || [], inelig = d.ineligible || [];
    const rowE = t => `<tr class="border-b border-slate-100">
        <td class="px-3 py-1.5 text-xs font-mono text-slate-700">${escapeHtml(t.label || t.spoke_id)}</td>
        <td class="px-3 py-1.5 text-xs text-slate-500">${escapeHtml(t.module_type || '—')}</td></tr>`;
    const rowI = t => `<tr class="border-b border-slate-100">
        <td class="px-3 py-1.5 text-xs font-mono text-slate-600">${escapeHtml(t.label || t.spoke_id)}</td>
        <td class="px-3 py-1.5 text-xs text-slate-500">${escapeHtml(t.module_type || '—')}</td>
        <td class="px-3 py-1.5 text-xs text-amber-700">${escapeHtml(t.reason || '')}</td></tr>`;
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm p-4';
    modal.onclick = (ev) => { if (ev.target === modal) modal.remove(); };
    modal.innerHTML = `
      <div class="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[85vh] overflow-y-auto">
        <div class="flex items-center justify-between px-5 py-3 border-b border-slate-100">
          <h3 class="text-sm font-bold text-slate-700">Wildcard fan-out coverage</h3>
          <button onclick="this.closest('.fixed').remove()" title="Close dialog" class="text-slate-400 hover:text-slate-600 text-lg leading-none">&times;</button>
        </div>
        <div class="p-5 space-y-5">
          <p class="text-xs text-slate-500">Fan-out is currently <b class="${d.enabled ? 'text-green-600' : 'text-slate-500'}">${d.enabled ? 'ENABLED' : 'OFF'}</b>. A wildcard cert (<code>*.domain</code>) is pushed to every <b>connected, cert-capable</b> spoke below (plus the hub). Ineligible spokes are skipped — connect them or note that their module type can't host a cert.</p>
          <div>
            <div class="text-[11px] font-bold text-green-700 uppercase tracking-wide mb-1">Eligible <span class="text-slate-400 font-normal">(${elig.length})</span></div>
            <table class="w-full border border-slate-200 rounded-md overflow-hidden"><thead class="bg-slate-50"><tr><th class="px-3 py-1.5 text-left text-[10px] uppercase text-slate-400">Spoke</th><th class="px-3 py-1.5 text-left text-[10px] uppercase text-slate-400">Type</th></tr></thead><tbody>${elig.map(rowE).join('') || '<tr><td colspan="2" class="px-3 py-2 text-xs text-slate-400 italic">none</td></tr>'}</tbody></table>
          </div>
          <div>
            <div class="text-[11px] font-bold text-amber-700 uppercase tracking-wide mb-1">Ineligible <span class="text-slate-400 font-normal">(${inelig.length})</span></div>
            <table class="w-full border border-slate-200 rounded-md overflow-hidden"><thead class="bg-slate-50"><tr><th class="px-3 py-1.5 text-left text-[10px] uppercase text-slate-400">Spoke</th><th class="px-3 py-1.5 text-left text-[10px] uppercase text-slate-400">Type</th><th class="px-3 py-1.5 text-left text-[10px] uppercase text-slate-400">Why not</th></tr></thead><tbody>${inelig.map(rowI).join('') || '<tr><td colspan="3" class="px-3 py-2 text-xs text-slate-400 italic">none — every known spoke is eligible</td></tr>'}</tbody></table>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
}
window.showLeWildcardCoverage = showLeWildcardCoverage;

// distribution_retry_hours: how soon the hub retries a FAILED cert distribution
// to a target. The hub's run_cert_distribution_loop sweeps on this cadence and
// re-pushes any target whose last push errored (successful targets are skipped
// by the le-ledger skip-check). Default 1h. Saved via POST /setup/config
// (shallow-merged into global_config.certs alongside wildcard_all_spokes).
async function loadLeRetryInterval() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        let hrs = ((data.global_config || {}).certs || {}).distribution_retry_hours;
        if (hrs == null || isNaN(Number(hrs)) || Number(hrs) <= 0) hrs = 1;
        const el = document.getElementById('le-distribution-retry-hours');
        if (el) el.value = String(Math.max(1, Math.round(Number(hrs))));
    } catch (e) { console.error('loadLeRetryInterval failed', e); }
}

async function saveLeRetryInterval(v) {
    let hrs = parseInt(v, 10);
    if (!Number.isFinite(hrs) || hrs < 1) { showToast('Retry interval must be a whole number of hours (>= 1).', 'error'); loadLeRetryInterval(); return; }
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { certs: { distribution_retry_hours: hrs } } })
        });
        if (r.ok) showToast(`Failed-distribution retry set to every ${hrs}h.`, 'success');
        else showToast('Failed to save retry interval.', 'error');
    } catch (e) { showToast('Error saving retry interval: ' + e.message, 'error'); }
    loadLeRetryInterval();
}

async function leDistributeNow() {
    // Immediate feedback — distribution fans out to every target and can take a
    // while; the "Distribute complete" toast below fires when it finishes.
    showToast('Certificates are being distributed to all targets…', 'info');
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/distribute', { method: 'POST' });
        if (!ok) { showToast('Distribute failed: ' + (detail || ''), 'error'); await loadLEData(); return; }
        const inner = (data && data.data) ? data.data : (data || {});
        const dist = inner.distribution || [];
        let msg = '';
        let failed = false;
        if (dist.length) {
            const okN = dist.filter(d => d.status === 'SUCCESS').length;
            const skipN = dist.filter(d => d.skipped || d.status === 'SKIPPED').length;
            const defN = dist.filter(d => d.status === 'DEFERRED').length;
            const failN = dist.filter(d => d.status === 'ERROR').length;
            failed = failN > 0;  // deferred (offline, retries on reconnect) is NOT a failure
            const firstErr = dist.find(d => d.status === 'ERROR');
            msg = ` · ${okN} OK` +
                  (skipN ? ` · ${skipN} skipped` : '') +
                  (defN ? ` · ${defN} deferred` : '') +
                  (failN ? ` — ${failN} FAILED` + (firstErr && firstErr.message ? `: ${firstErr.message}` : '') : '');
        } else {
            msg = ' · no certs to distribute';
        }
        showToast('Distribute complete' + msg, failed ? 'error' : 'success');
        console.info('[le] distribute', dist);
        await loadLEData();
    } catch (e) { showToast('Distribute failed: ' + e.message, 'error'); }
}

// Deploy ONE certificate to all of ITS OWN targets — the per-cert "Distribute
// now" in the targets modal. Unlike leDistributeNow() (fleet-wide /api/le/distribute,
// Global-Admin only), this loops the cert's targets and hits the ownership-guarded
// per-target endpoint, so a tenant-admin can (re)deploy a cert they own without
// tripping the Global-Admin gate. No targets → the wildcard fan-out / issue path
// handles distribution, so just nudge a reload.
async function leDistributeCert(domain) {
    const cert = (window._leCerts || []).find(c => c.domain === domain) || {};
    const tgts = cert.targets || [];
    if (!tgts.length) { showToast('No targets to distribute for ' + domain + '.', 'info'); return; }
    showToast(`Deploying ${domain} to ${tgts.length} target(s)…`, 'info');
    let okN = 0, failN = 0, firstErr = '';
    for (const t of tgts) {
        const label = `${t.module_type}${t.identifier ? '/' + t.identifier : ''}`;
        try {
            const body = { module_type: t.module_type };
            if (t.identifier) body.identifier = t.identifier;
            if (t.spoke_id) body.spoke_id = t.spoke_id;
            const { ok, data, detail } = await _spokeFetch(
                `/api/le/certs/${encodeURIComponent(domain)}/distribute`,
                { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            const inner = (data && data.data) ? data.data : (data || {});
            const d0 = (inner.distribution || [])[0] || {};
            if (ok && d0.status === 'SUCCESS') okN++;
            else { failN++; if (!firstErr) firstErr = `${label}: ${d0.message || detail || 'failed'}`; }
        } catch (e) { failN++; if (!firstErr) firstErr = `${label}: ${e.message}`; }
    }
    const msg = `${okN} OK` + (failN ? ` — ${failN} FAILED (${firstErr})` : '');
    showToast(`Deploy ${domain}: ${msg}`, failN ? 'error' : 'success');
    await loadLEData();
}

async function leDeployTarget(domain, module_type, identifier) {
    // Per-target click-to-deploy: push this cert to ONE target only (the
    // clicked spoke/agent badge). The server builds the target without
    // last_pushed_hash so the skip-check always fires the push — a click is an
    // explicit re-deploy, even on an already-green target. Mirrors the CS
    // spoke-clients click-to-act pattern.
    const tgt = `${module_type}${identifier ? '/' + identifier : ''}`;
    try {
        const body = { module_type };
        if (identifier) body.identifier = identifier;
        const { ok, data, detail } = await _spokeFetch(
            `/api/le/certs/${encodeURIComponent(domain)}/distribute`,
            { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!ok) { showToast(`Deploy to ${tgt} failed: ` + (detail || ''), 'error'); await loadLEData(); return; }
        const inner = (data && data.data) ? data.data : (data || {});
        const dist = inner.distribution || [];
        const d0 = dist[0] || {};
        if (d0.status === 'SUCCESS') {
            showToast(`${tgt}: ${d0.skipped ? 'already up to date' : 'deployed'}`, 'success');
        } else {
            showToast(`${tgt} deploy failed: ${d0.message || detail || ''}`, 'error');
        }
        await loadLEData();
    } catch (e) { showToast(`Deploy to ${tgt} failed: ` + e.message, 'error'); }
}

// Per-cert target manager modal. The hub brokers cert material from the le
// spoke to each target spoke (resolved by module_type); each target applies the
// cert to its own device. Wired INSTALL_CERT targets: firewall (OPNsense Trust
// API) + hypervisor (Proxmox — spoke relays to the per-node agent, which runs
// `pvenode cert set` on its local pveproxy; the target `identifier` is the node
// name) + directory (OpenLDAP — spoke writes PEM to /etc/ldap/tls, points
// slapd's olcTLS* via ldapmodify -Y EXTERNAL over ldapi, restarts slapd). Other
// module types record an ERROR ("does not support cert install yet") until wired.
// Friendly label for a cert-capable module_type — used ONLY for the option text
// of the module <select>. Which module_types are OFFERED is driven by the live
// /api/le/targets/available list (installed + has a device), NOT this map, so a
// module that isn't installed (or has no device) can never be selected. dns/dhcp
// are intentionally absent — they aren't cert-capable.
const LE_MODULE_LABELS = {
    hub: 'hub (LM WebUI)', firewall: 'firewall (OPNsense)',
    ipam: 'ipam (NetBox)', hypervisor: 'hypervisor (Proxmox)',
    nac: 'nac (ClearPass)', directory: 'directory (LDAP)',
    simulation: 'simulation (Client Sim)', nw: 'nw (Network Devices)',
    statuspage: 'statuspage',
};

// ── LE target picker: drive both dropdowns from the live available list ──
// The module <select> lists only module_types present in window._leAvailableTargets
// (installed + cert-capable + has ≥1 device); the identifier <select> lists only
// the REAL devices/targets for the chosen module. Both come from the same
// /api/le/targets/available payload the chips use, so the picker can never offer
// a module that isn't installed or a device that doesn't exist.
function _leTargetsByModule() {
    const out = {};
    for (const t of (window._leAvailableTargets || [])) {
        (out[t.module_type] = out[t.module_type] || []).push(t);
    }
    return out;
}
// <option>s for the module dropdown — one per installed-and-has-device module.
function leModuleOptions() {
    const mods = Object.keys(_leTargetsByModule());
    if (!mods.length) {
        return '<option value="" disabled selected>No installed modules with devices</option>';
    }
    return mods.map(mt => `<option value="${mt}">${LE_MODULE_LABELS[mt] || mt}</option>`).join('');
}
// <option>s for the identifier dropdown of one module — the real devices/targets
// (deduped by identifier; e.g. hypervisor → 'all nodes' + each Proxmox node).
function leIdentifierOptions(mt) {
    const byMod = _leTargetsByModule();
    const list = byMod[mt] || [];
    const seen = new Set();
    const opts = [];
    for (const t of list) {
        const id = String(t.identifier || '');
        if (seen.has(id)) continue;  // collapse duplicate broadcast/spoke entries
        seen.add(id);
        opts.push(`<option value="${escapeHtml(id)}">${escapeHtml(t.label || (id || '(default)'))}</option>`);
    }
    if (!opts.length) return '<option value="" disabled selected>No devices</option>';
    return opts.join('');
}
// onchange for the module <select> — repopulate the identifier <select> for the
// newly chosen module and preselect the first device.
function leTgtMtChange(mtSelId, idSelId) {
    const mtSel = document.getElementById(mtSelId);
    const idSel = document.getElementById(idSelId);
    if (!mtSel || !idSel) return;
    idSel.innerHTML = leIdentifierOptions(mtSel.value);
    if (idSel.options.length) idSel.selectedIndex = 0;
}
// Ensure window._leAvailableTargets is fresh before opening a modal — a module
// installed since the last LE load should be selectable without a full reload.
async function _leRefreshAvailableTargets() {
    try {
        const r = await _spokeFetch('/api/le/targets/available');
        const b = (r && r.ok) ? inner(r.data) : null;
        window._leAvailableTargets = (b && Array.isArray(b.targets)) ? b.targets : (window._leAvailableTargets || []);
    } catch (e) { /* keep whatever we have */ }
}

async function showLeTargetsModal(domain) {
    // Refresh the live available-target list if we don't have one yet so a
    // freshly-installed module is selectable without a full LE reload.
    if (!window._leAvailableTargets || !window._leAvailableTargets.length) {
        await _leRefreshAvailableTargets();
    }
    const cert = (window._leCerts || []).find(c => c.domain === domain) || {};
    const tgts = cert.targets || [];
    const isBfCert = !!cert.ab;
    const isCA = !!cert.client_auth;
    const canEdit = (cert.can_edit !== false);  // owner/admin (or legacy cert)
    const esc = s => String(s || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
    const row = (t, i) => {
        const ok = t.last_status === 'SUCCESS';
        const cls = ok ? 'bg-green-100 text-green-700' : (t.last_status === 'ERROR' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500');
        return `<tr class="border-b border-slate-100">
            <td class="px-3 py-2 text-xs font-mono">${t.module_type || '—'}${t.identifier ? ' / ' + esc(t.identifier) : ''}</td>
            <td class="px-3 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${t.last_status || 'pending'}</span></td>
            <td class="px-3 py-2 text-xs text-slate-500">${(t.last_pushed_at || '—').slice(0, 19).replace('T', ' ')}</td>
            <td class="px-3 py-2 text-xs text-slate-500">${t.last_message ? `<span title="${escapeHtml(t.last_message)}">${escapeHtml(t.last_message)}</span>` : ''}</td>
            <td class="px-3 py-2">${canEdit ? `<button onclick="removeLeTarget('${esc(domain)}', ${i})" title="Remove this distribution target" class="text-xs text-red-600 hover:text-red-700 font-medium">remove</button>` : ''}</td>
        </tr>`;
    };
    const mtOpts = leModuleOptions();
    const roNote = canEdit ? '' : `<div class="mb-4 p-3 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-600">This is a <b>shared</b> certificate owned by another tenant. You can <b>deploy</b> it to devices in your own tenant (below), but you cannot change its targets, identity, or tenants.</div>`;
    const bfBlock = canEdit ? `<label class="flex items-start gap-2 mb-4 p-3 rounded-md border ${isBfCert ? 'bg-purple-50 border-purple-200' : 'bg-slate-50 border-slate-200'} cursor-pointer" title="Tag this cert as the AppBuilder mTLS identity — the gate for hub log reads + fleet update commands. Then add a ab target below so the cert is deployed to the ab agent.">
            <input type="checkbox" id="le-ab-chk" ${isBfCert ? 'checked' : ''} onchange="leToggleAppBuilderChk(this, '${esc(domain)}')" class="mt-0.5 accent-purple-600" />
            <span class="text-xs text-slate-700"><span class="font-bold text-purple-700">★ AppBuilder identity</span> — pin this cert's name as the AppBuilder mTLS identity (hub logs + fleet updates). <span class="text-slate-500">The hub mints ab's clientAuth mTLS cert from its Local CA for this SAN automatically; also add a <span class="font-mono">ab</span> target below (★) to deploy this cert as ab's WebUI/server cert.</span></span>
        </label>` : '';
    const addBlock = canEdit ? `<div class="flex flex-wrap items-end gap-2 border-t border-slate-200 pt-4">
            <div class="flex flex-col">
                <label class="text-xs text-slate-500 mb-1">Module type</label>
                <select id="le-tgt-mt" onchange="leTgtMtChange('le-tgt-mt','le-tgt-id')" title="Select target module type" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${mtOpts}</select>
            </div>
            <div class="flex flex-col flex-1 min-w-[180px]">
                <label class="text-xs text-slate-500 mb-1">Device</label>
                <select id="le-tgt-id" title="Select target device or node identifier" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></select>
            </div>
            <button onclick="addLeTarget('${esc(domain)}')" title="Add distribution target for this certificate" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Add target</button>
            <button onclick="leDistributeCert('${esc(domain)}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold" title="Deploy this certificate to all of its targets">Distribute now</button>
            <button onclick="document.getElementById('le-targets-modal').remove()" title="Close dialog" class="ml-auto bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium">Close</button>
        </div>` : `<div class="flex border-t border-slate-200 pt-4">
            <button onclick="document.getElementById('le-targets-modal').remove()" title="Close dialog" class="ml-auto bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium">Close</button>
        </div>`;
    const modal = openModal('le-targets-modal', `
        <h3 class="text-lg font-bold mb-1">Distribution targets — <span class="font-mono">${esc(domain)}</span></h3>
        <p class="text-xs text-slate-500 mb-4">Each target is a spoke (by module type) the hub pushes this cert to; that spoke installs it on its device. Only installed modules with at least one device are listed.</p>
        ${roNote}
        <div id="le-tenants-box" class="mb-4"></div>
        ${bfBlock}
        <div class="overflow-x-auto mb-3"><table class="w-full text-sm">
            <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>
                <th class="px-3 py-2 text-left font-medium">Target</th>
                <th class="px-3 py-2 text-left font-medium">Status</th>
                <th class="px-3 py-2 text-left font-medium">Last push</th>
                <th class="px-3 py-2 text-left font-medium">Message</th>
                <th></th>
            </tr></thead>
            <tbody>${tgts.length ? tgts.map(row).join('') : '<tr><td colspan="5" class="px-3 py-3 text-xs text-slate-400 italic">No targets yet — add one below.</td></tr>'}</tbody>
        </table></div>
        ${addBlock}`, { card: 'max-w-2xl w-full p-6 max-h-[90vh] overflow-y-auto' });
    if (canEdit) leTgtMtChange('le-tgt-mt', 'le-tgt-id');  // seed the device list for the first module
    _leRenderTenantsSection(domain, cert, canEdit);
}

// ── Per-cert tenant ownership editor (Manage modal) ──────────────────────────
// A cert is owned by one or more tenants; owners/admins may add or remove other
// tenants (and add the SHARED tenant to let every tenant deploy it to their own
// devices) but a non-admin owner may never remove their own tenant. Renders the
// "le-tenants-box" section from the cert's tagged {tenants,shared} + the tenant
// list at /setup/tenants; POSTs the new list to /api/le/cert-tenants.
async function _leRenderTenantsSection(domain, cert, canEdit) {
    const box = document.getElementById('le-tenants-box');
    if (!box) return;
    const owners = Array.isArray(cert.tenants) ? cert.tenants.slice() : [];
    const sharedId = window._sharedTenantId || null;
    const myTenant = currentTenant || 'default';
    const admin = (typeof isAdmin === 'function') && isAdmin();
    if (!canEdit) {
        // Read-only viewers just see who owns it + the shared flag.
        const chips = owners.map(t => `<span class="inline-block px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600">${escapeHtml(t)}${sharedId && t === sharedId ? ' (shared)' : ''}</span>`).join(' ');
        box.innerHTML = `<div class="p-3 rounded-md border border-slate-200 bg-white">
            <div class="text-xs font-semibold text-slate-500 uppercase mb-1.5">Owner tenants</div>
            <div class="flex flex-wrap gap-1.5">${chips || '<span class="text-xs text-slate-400 italic">—</span>'}</div></div>`;
        return;
    }
    // Load the full tenant list so an owner can add another tenant / the shared one.
    let all = [];
    try {
        const r = await _spokeFetch('/setup/tenants');
        const d = (r && r.ok) ? r.data : null;
        all = (d && Array.isArray(d.tenants)) ? d.tenants : [];
    } catch (e) { all = []; }
    // Build the selectable universe: every known tenant id + the shared tenant.
    const known = new Map();
    all.forEach(t => { if (t && t.id) known.set(String(t.id), t.name || t.id); });
    owners.forEach(t => { if (!known.has(t)) known.set(t, t); });
    if (sharedId && !known.has(sharedId)) known.set(sharedId, 'Shared (all tenants)');
    window._leTenantEdit = { domain, owners: new Set(owners), myTenant, admin, sharedId };
    _leRenderTenantChips();
    const opts = Array.from(known.entries())
        .filter(([id]) => !owners.includes(id))
        .map(([id, name]) => `<option value="${escapeHtml(id)}">${escapeHtml(name)}${sharedId && id === sharedId ? ' — makes cert shared' : ''}</option>`).join('');
    box.insertAdjacentHTML('beforeend', `
        <div class="flex flex-wrap items-end gap-2 mt-2">
            <div class="flex flex-col flex-1 min-w-[180px]">
                <label class="text-xs text-slate-500 mb-1">Add a tenant (or the shared tenant to share)</label>
                <select id="le-tenant-add" title="Select tenant to grant certificate ownership or sharing" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">— select —</option>${opts}</select>
            </div>
            <button onclick="_leAddTenantChip()" title="Add selected tenant to owners" class="bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 px-3 py-2 rounded-md text-sm font-medium">Add</button>
            <button onclick="_leSaveTenants()" title="Save tenant ownership list" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Save tenants</button>
        </div>`);
}

function _leRenderTenantChips() {
    const box = document.getElementById('le-tenants-box');
    const st = window._leTenantEdit;
    if (!box || !st) return;
    let holder = document.getElementById('le-tenant-chips-holder');
    if (!holder) {
        box.innerHTML = `<div class="p-3 rounded-md border border-slate-200 bg-white">
            <div class="text-xs font-semibold text-slate-500 uppercase mb-1.5">Owner tenants</div>
            <div id="le-tenant-chips-holder" class="flex flex-wrap gap-1.5"></div>
            <p class="text-[11px] text-slate-400 mt-1.5">Add the shared tenant so any tenant can deploy this cert to their own devices. You cannot remove your own tenant.</p>
        </div>`;
        holder = document.getElementById('le-tenant-chips-holder');
    }
    const chips = Array.from(st.owners).map(t => {
        const isSelf = (!st.admin && t === st.myTenant);
        const isShared = st.sharedId && t === st.sharedId;
        const rm = isSelf ? '' : `<button onclick="_leRemoveTenantChip('${escJsAttr(t)}')" class="ml-1 text-slate-400 hover:text-red-600" title="Remove">×</button>`;
        return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${isShared ? 'bg-teal-100 text-teal-700' : 'bg-slate-100 text-slate-600'}">${escapeHtml(t)}${isShared ? ' (shared)' : ''}${isSelf ? ' (you)' : ''}${rm}</span>`;
    }).join(' ');
    holder.innerHTML = chips || '<span class="text-xs text-slate-400 italic">—</span>';
}

function _leAddTenantChip() {
    const sel = document.getElementById('le-tenant-add');
    const st = window._leTenantEdit;
    if (!sel || !st || !sel.value) return;
    st.owners.add(sel.value);
    const opt = sel.querySelector(`option[value="${CSS.escape(sel.value)}"]`);
    if (opt) opt.remove();
    sel.value = '';
    _leRenderTenantChips();
}

function _leRemoveTenantChip(tid) {
    const st = window._leTenantEdit;
    if (!st) return;
    if (!st.admin && tid === st.myTenant) { showToast("You cannot remove your own tenant.", 'error'); return; }
    st.owners.delete(tid);
    _leRenderTenantChips();
}

async function _leSaveTenants() {
    const st = window._leTenantEdit;
    if (!st) return;
    const tenants = Array.from(st.owners);
    if (!st.admin && !tenants.includes(st.myTenant)) {
        showToast("You cannot remove your own tenant.", 'error');
        return;
    }
    // The tenant list is an idempotent full REPLACE, so it is safe to retry.
    // A stale reused keep-alive connection (the hub reaps idle HTTP conns) fails
    // the very first POST with a transport-level "TypeError: Load failed";
    // browsers auto-retry GETs on a dead connection but never a POST, so we do
    // it ourselves — the retry opens a fresh connection and succeeds.
    const _post = () => _spokeFetch('/api/le/cert-tenants', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: st.domain, tenants })
    });
    try {
        let res;
        try {
            res = await _post();
        } catch (e1) {
            if (!(e1 instanceof TypeError)) throw e1;  // not a transport error
            res = await _post();  // one retry on a fresh connection
        }
        const { ok, detail } = res;
        if (!ok) { showToast(detail || 'Failed to save tenants', 'error'); return; }
        showToast('Tenants updated', 'success');
        // Reflect the change locally so the modal + row badges update on reload.
        const c = (window._leCerts || []).find(x => x.domain === st.domain);
        if (c) { c.tenants = tenants; c.shared = !!(st.sharedId && tenants.includes(st.sharedId)); }
        if (typeof loadLEData === 'function') loadLEData();
        const m = document.getElementById('le-targets-modal'); if (m) m.remove();
    } catch (e) {
        // A TypeError from fetch() (e.g. WebKit "Load failed") is a transport
        // failure — the request never reached the hub — not an app error.
        const net = (e instanceof TypeError);
        showToast(net
            ? 'Could not reach the hub to save tenants — check your connection / the certificates service and try again.'
            : ('Failed to save tenants: ' + e), 'error');
    }
}

// Agent-hosting cert targets (simulation/hypervisor) can be added as a GROUP
// ("all nodes", identifier empty) OR as an individual node (identifier =
// agent_id). Selecting BOTH for the same module_type deploys the same cert to
// the same node(s) — and in the split topology hypervisor + simulation share
// the cs-owned pxmx agents — which causes pveproxy restart contention (and,
// before the agent verify-on-disk fix, a re-push loop). Pick one or the other.
const _LE_AGENT_HOSTING = ['simulation', 'hypervisor'];
// Fleet spokes: ONE spoke-level cert target deploys to MANY devices. The badge
// shows the aggregate ("installed on 8/10"); a 'devices' drill-down shows the
// per-device breakdown (which switches got the cert). nw = the Aruba switch fleet.
const _LE_FLEET_TYPES = ['nw'];

// Per-spoke device detail (nw switch fleet): a collapsed, LAZY-LOADED section
// below the cert's targets. The spoke-level badge is the success signal; this
// shows all the devices that spoke manages + each one's cert status, loaded only
// when the operator expands it (a 100-switch fleet shouldn't render up front).
function _leDevRepId(domain, mt, id) {
    return 'le-devrep-' + (String(domain) + '|' + String(mt) + '|' + String(id || '')).replace(/[^a-zA-Z0-9]/g, '_');
}
function leFleetDetail(domain, tgts) {
    const fleet = (tgts || []).filter(t => _LE_FLEET_TYPES.includes(String(t.module_type || '')));
    if (!fleet.length) return '';
    // ONE consolidated "All devices" section pinned at the bottom — the operator
    // wants to see + deploy to the individual switches/gateways, not the spokes
    // that manage them. Uses the (spoke-level) nw target; the backend returns the
    // whole live fleet regardless of which spoke owns it.
    const t = fleet[0];
    const cid = _leDevRepId(domain, t.module_type, t.identifier || '');
    return `<div class="w-full mt-3 pt-2 basis-full border-t border-slate-200">
        <button onclick="toggleLeFleetDetail('${escJsAttr(domain)}','${escJsAttr(t.module_type)}','${escJsAttr(t.identifier || '')}')" class="text-sm font-semibold text-slate-600 hover:text-slate-800 flex items-center gap-1.5" title="Show every network device + its cert status; deploy the cert per device">
            <span id="${cid}-caret" class="inline-block w-2.5">▸</span> All devices
        </button>
        <div id="${cid}" class="hidden mt-2 ml-3 pl-2 border-l-2 border-slate-100"></div>
    </div>`;
}
function _leRenderDeviceTable(d) {
    const devs = d.devices || [];
    const domain = d.domain || '', mt = d.module_type || '', ident = d.identifier || '';
    const when = d.at ? new Date(d.at).toLocaleString() : 'never';
    const pill = s => {
        const map = { SUCCESS: 'bg-green-100 text-green-700', ERROR: 'bg-red-100 text-red-700', PARTIAL: 'bg-amber-100 text-amber-700', SKIPPED: 'bg-slate-100 text-slate-500' };
        const label = s || 'not deployed';
        return `<span class="px-2 py-0.5 rounded-full text-sm font-medium ${map[s] || 'bg-slate-100 text-slate-500'}">${escapeHtml(label)}</span>`;
    };
    if (!devs.length) {
        return '<p class="text-sm text-slate-400 italic py-1">No devices found on this spoke (is it online and are devices configured in Setup → Network Devices?).</p>';
    }
    const rows = devs.map(v => {
        const did = String(v.device_id || v.name || '');
        const capable = v.cert_capable === true || String(v.object_type || '').toLowerCase() === 'cx_switch';
        const action = capable
            ? `<button onclick="leDeployDevice('${escJsAttr(domain)}','${escJsAttr(did)}','${escJsAttr(mt)}','${escJsAttr(ident)}',this)" title="Deploy certificate directly to this network device" class="text-sm text-[#01A982] hover:underline font-bold">Deploy</button>`
            : `<span class="text-xs text-slate-400" title="${escapeHtml(v.message || 'cert install not supported for this device type')}">unsupported</span>`;
        return `<tr class="border-b border-slate-100">
            <td class="px-3 py-1.5 text-sm font-mono text-slate-700">${escapeHtml(v.name || did || '—')}</td>
            <td class="px-3 py-1.5 text-sm text-slate-500 font-mono">${escapeHtml(v.ip || '')}</td>
            <td class="px-3 py-1.5 text-sm text-slate-500">${escapeHtml(v.object_type || '')}</td>
            <td class="px-3 py-1.5">${pill(v.status)}</td>
            <td class="px-3 py-1.5 text-sm text-slate-500">${v.message ? `<span title="${escapeHtml(v.message)}">${escapeHtml(v.message)}</span>` : ''}</td>
            <td class="px-3 py-1.5 whitespace-nowrap">${action}</td></tr>`;
    }).join('');
    return `<div class="text-xs text-slate-400 mb-1.5">${d.message ? `<b>${escapeHtml(d.message)}</b> · ` : ''}last run: ${escapeHtml(when)}. Deploy the cert to individual devices below, or to the whole fleet via the target badge.</div>
        <div class="overflow-x-auto"><table class="w-full border border-slate-200 rounded-md overflow-hidden"><thead class="bg-slate-50"><tr>
        <th class="px-3 py-1.5 text-left text-xs uppercase text-slate-400">Device</th>
        <th class="px-3 py-1.5 text-left text-xs uppercase text-slate-400">IP</th>
        <th class="px-3 py-1.5 text-left text-xs uppercase text-slate-400">Type</th>
        <th class="px-3 py-1.5 text-left text-xs uppercase text-slate-400">Cert</th>
        <th class="px-3 py-1.5 text-left text-xs uppercase text-slate-400">Message</th>
        <th class="px-3 py-1.5 text-left text-xs uppercase text-slate-400"></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
async function _leLoadDeviceBox(box, domain, mt, identifier) {
    box.innerHTML = '<p class="text-xs text-slate-400 italic py-1">Loading devices…</p>';
    try {
        const q = `module_type=${encodeURIComponent(mt)}&identifier=${encodeURIComponent(identifier || '')}`;
        const r = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/devices?${q}`);
        const d = (r && r.ok) ? (r.data && typeof r.data.data === 'object' ? r.data.data : r.data) : null;
        if (!d) throw new Error((r && r.detail) || 'failed to load');
        box.innerHTML = _leRenderDeviceTable(d);
        box.dataset.loaded = '1';
    } catch (e) {
        box.innerHTML = `<p class="text-xs text-red-600 py-1">Failed to load devices: ${escapeHtml(e.message || String(e))}</p>`;
    }
}
async function toggleLeFleetDetail(domain, mt, identifier) {
    const cid = _leDevRepId(domain, mt, identifier || '');
    const box = document.getElementById(cid);
    const caret = document.getElementById(cid + '-caret');
    if (!box) return;
    if (!box.classList.contains('hidden')) {   // collapse
        box.classList.add('hidden');
        if (caret) caret.textContent = '▸';
        return;
    }
    box.classList.remove('hidden');            // expand
    if (caret) caret.textContent = '▾';
    if (box.dataset.loaded === '1') return;    // lazy-load only once
    await _leLoadDeviceBox(box, domain, mt, identifier);
}
async function leDeployDevice(domain, deviceId, mt, identifier, btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Deploying…'; }
    try {
        const r = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/devices/${encodeURIComponent(deviceId)}/deploy`, { method: 'POST' });
        const d = (r && r.ok) ? (r.data && typeof r.data.data === 'object' ? r.data.data : r.data) : null;
        if (!r || !r.ok) throw new Error((r && r.detail) || (d && d.message) || 'deploy failed');
        const ok = (d && d.result_status) === 'SUCCESS';
        showToast(ok ? `Cert deployed to ${deviceId}.` : `Deploy to ${deviceId}: ${(d && d.message) || 'failed'}`, ok ? 'success' : 'error');
        // Refresh the device box so the new status shows.
        const box = document.getElementById(_leDevRepId(domain, mt, identifier || ''));
        if (box) { box.dataset.loaded = ''; await _leLoadDeviceBox(box, domain, mt, identifier); }
    } catch (e) {
        showToast('Deploy failed: ' + (e.message || e), 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Deploy'; }
    }
}
window.leFleetDetail = leFleetDetail; window.toggleLeFleetDetail = toggleLeFleetDetail;
window.leDeployDevice = leDeployDevice;
// The one-liner reused by the inline ⚠ note, the chip tooltips, and the add
// confirm so the guidance reads identically everywhere (and matches the docs
// "Distribution targets — pick one granularity" warning).
const _LE_TARGET_OVERLAP_HINT =
    'Pick ONE granularity per module: a group ("all nodes") OR individual node '
    + 'targets — not both. Both deploy the same cert to the same node(s) and '
    + 'cause repeated pveproxy restarts.';
// Return the agent-hosting module_types in `tgts` that have BOTH a group
// (identifier empty) and an individual (identifier set) target selected.
function _leRedundantTargetTypes(tgts) {
    const out = [];
    for (const mt of _LE_AGENT_HOSTING) {
        const ofType = (tgts || []).filter(t => (t.module_type || '') === mt);
        const hasGroup = ofType.some(t => !String(t.identifier || '').trim());
        const hasIndividual = ofType.some(t => String(t.identifier || '').trim());
        if (hasGroup && hasIndividual) out.push(mt);
    }
    return out;
}

async function addLeTarget(domain, preset) {
    // ``preset`` ({module_type, identifier}) comes from a click on an available-
    // target chip; without it we read the manual add form below.
    const mt = preset ? preset.module_type : document.getElementById('le-tgt-mt')?.value;
    const identifier = preset ? (preset.identifier || '') : (document.getElementById('le-tgt-id')?.value?.trim() || '');
    if (!mt) { showToast('Module type required', 'error'); return; }
    // "All nodes" supersedes individual nodes for agent-hosting types:
    //  - adding an INDIVIDUAL node while the group is selected → block (the group
    //    already covers it; its chip is hidden, this guards manual/stale adds).
    //  - adding the GROUP ("all nodes") → allowed; existing individual-node
    //    targets of this type are removed after the add so nothing is redundant.
    let _supersedeNodes = [];
    if (_LE_AGENT_HOSTING.includes(mt)) {
        const cert = (window._leCerts || []).find(c => c.domain === domain) || {};
        const existing = cert.targets || [];
        const addingGroup = !String(identifier).trim();
        const hasGroup = existing.some(t => String(t.module_type || '') === mt && !(t.identifier || ''));
        if (!addingGroup && hasGroup) {
            showToast(`"${mt} — all nodes" is already selected — individual nodes are covered by it.`, 'error');
            return;
        }
        if (addingGroup) {
            _supersedeNodes = existing
                .filter(t => String(t.module_type || '') === mt && (t.identifier || ''))
                .map(t => t.identifier);
        }
    }
    try {
        const { ok, detail } = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/targets`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ module_type: mt, identifier }),
        });
        if (!ok) { showToast('Add target failed: ' + (detail || ''), 'error'); return; }
        // Remove the now-redundant individual nodes (all-nodes supersedes them).
        for (const nid of _supersedeNodes) {
            await removeLeTargetByKey(domain, mt, nid);
        }
        await loadLEData();
        // Re-open the modal only if it's already open (an add from the main
        // screen's click-to-add chip shouldn't pop the modal open).
        if (document.getElementById('le-targets-modal')) showLeTargetsModal(domain);
    } catch (e) { showToast('Add target failed: ' + e.message, 'error'); }
}

// Disable distribution to a target by (module_type, identifier) — the first-page
// toggle-off (the DELETE endpoint is index-based, so resolve the index from the
// cached cert targets first). No confirm: it's trivially re-enabled with a click.
async function removeLeTargetByKey(domain, mt, identifier) {
    const cert = (window._leCerts || []).find(c => c.domain === domain) || {};
    const idx = (cert.targets || []).findIndex(
        t => String(t.module_type || '') === String(mt || '')
            && String(t.identifier || '') === String(identifier || ''));
    if (idx < 0) { await loadLEData(); return; }   // already gone — just refresh
    await removeLeTarget(domain, idx);
    if (typeof showToast === 'function') {
        showToast(`Distribution disabled for ${mt}${identifier ? '/' + identifier : ''}`, 'success');
    }
}

async function removeLeTarget(domain, idx) {
    try {
        const { ok, detail } = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/targets/${idx}`, { method: 'DELETE' });
        if (!ok) { showToast('Remove target failed: ' + (detail || ''), 'error'); return; }
        await loadLEData();
        if (document.getElementById('le-targets-modal')) showLeTargetsModal(domain);
    } catch (e) { showToast('Remove target failed: ' + e.message, 'error'); }
}

// ── le action UI: issue / renew / revoke ─────────────────────────────────────
// All four spoke endpoints (/api/le/issue, /renew, /revoke, /distribute) already
// exist — this is the WebUI write/action half that was deferred when the read
// half (list + targets modal) was built. The issue modal's email field is the
// "configure certbot/acme account" entry point: certbot keeps the ACME account
// in /etc/letsencrypt/accounts/ keyed by the email supplied per-issue.

// DNS-01 providers supported by the le spoke (le/src/acme.py:_DNS_PLUGIN_APT).
// cloudflare + route53 are preinstalled by install_le.sh; the rest are
// apt-installed on demand by the spoke's ensure_dns_plugin(). Entries whose
// value is an alias (LE_DNS_PROVIDER_ALIAS) map to a different certbot plugin
// name at submit time — e.g. Hurricane Electric's free DNS (dns.he.net) does
// dynamic updates over RFC 2136 + TSIG, so it uses the certbot-dns-rfc2136
// plugin and the spoke receives dns_provider="rfc2136" (so certbot gets
// --dns-rfc2136 and creds land at /etc/lm-le/dns-rfc2136.ini).
const LE_DNS_PROVIDERS = [
    ['cloudflare', 'Cloudflare'],
    ['route53', 'AWS Route 53'],
    ['google', 'Google Domains'],
    ['digitalocean', 'DigitalOcean'],
    ['linode', 'Linode'],
    ['rfc2136', 'RFC 2136 (BIND)'],
    ['he-login', 'Hurricane Electric (account login)'],
    ['he', 'Hurricane Electric (RFC 2136 / TSIG)'],
    ['hetzner', 'Hetzner'],
    ['inwx', 'INWX'],
    ['transip', 'TransIP'],
];

// Frontend-only provider aliases → the certbot plugin name the spoke must
// receive. Keys are LE_DNS_PROVIDERS entries; values are the real
// _DNS_PLUGIN_APT name in le/src/acme.py.
const LE_DNS_PROVIDER_ALIAS = {
    he: 'rfc2136',
};

// Per-provider INI key shown as the DNS creds placeholder. The le spoke writes
// the raw content to /etc/lm-le/dns-<provider>.ini at 0600 (write_dns_creds).
const LE_DNS_CREDS_HINT = {
    cloudflare: 'dns_cloudflare_api_token = YOUR_TOKEN',
    route53:    'dns_route53_access_key_id = ...\ndns_route53_secret_access_key = ...',
    google:     'dns_google_domains_access_token = ...',
    digitalocean: 'dns_digitalocean_token = ...',
    linode:     'dns_linode_api_key = ...',
    rfc2136:    'dns_rfc2136_server = ...\ndns_rfc2136_name = ...\ndns_rfc2136_secret = ...',
    he:         '# Hurricane Electric dns.he.net — TSIG dynamic update\n' +
                'dns_rfc2136_server = 216.218.130.2\n' +  // ns1.he.net (certbot needs an IP)
                'dns_rfc2136_port = 53\n' +
                'dns_rfc2136_name = YOUR_KEY_NAME\n' +
                'dns_rfc2136_secret = YOUR_TSIG_SECRET\n' +
                'dns_rfc2136_algorithm = hmac-sha256',
    hetzner:    'dns_hetzner_api_token = ...',
    inwx:       'dns_inwx_url = https://api.domrobot.com/xmlrpc/\ndns_inwx_username = ...\ndns_inwx_password = ...',
    transip:    'dns_transip_username = ...\ndns_transip_api_key = ...',
};

// RFC 2136 family — providers whose certbot plugin is --dns-rfc2136 and whose
// only user-supplied secrets are a TSIG key name + key secret. For these we
// show a friendly two-field form (server/port/algorithm under "Advanced") and
// assemble the INI ourselves, instead of the raw textarea. Hurricane Electric
// (he) is an alias of rfc2136 (LE_DNS_PROVIDER_ALIAS above).
const LE_RFC2136_PROVIDERS = new Set(['rfc2136', 'he']);

// Default server pre-fill for the Advanced "Server" field, by provider. Empty
// string = leave the placeholder visible (user fills it).
// certbot-dns-rfc2136 requires the server as a literal IP (a hostname is
// rejected). ns1.he.net = 216.218.130.2 (HE's stable anycast); default to the IP
// so the form works even before the le spoke's hostname resolver is deployed.
const LE_RFC2136_DEFAULT_SERVER = { he: '216.218.130.2', rfc2136: '' };

// Initial-targets picker state for the issue modal. Array of {module_type, identifier}.
let _leIssueTargets = [];

function leIssueToggleChallenge() {
    const sel = document.getElementById('le-issue-challenge');
    if (!sel) return;
    const ch = sel.value;                       // http | http-webroot | dns | tls-alpn
    const set = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    set('le-issue-webroot-row', ch === 'http-webroot');
    set('le-issue-dns-cred-row', ch === 'dns');
    set('le-issue-dns-provider-row', ch === 'dns');
    set('le-issue-dns-creds-row', ch === 'dns');
    // Populate the DNS fields for the (default) provider as soon as the DNS-01
    // row appears, so the right input shape is visible without a provider
    // re-select. Also load the tenant's saved credentials into the picker.
    if (ch === 'dns') { leIssueUpdateDnsFields(); leIssuePopulateCreds(); }
}

// Load the tenant's saved DNS credentials into the issue-form picker.
async function leIssuePopulateCreds() {
    const sel = document.getElementById('le-issue-dns-credential');
    if (!sel || sel.dataset.loaded) return;
    let opts = '<option value="">— enter manually below —</option>';
    // (1) Named DNS credentials stored on the le spoke (this tenant's store).
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', { method: 'GET' });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        const creds = d.credentials || [];
        opts += creds.map(c => {
            const label = (DNS_CRED_PROVIDERS[c.provider] || {}).label || c.provider;
            return `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)} — ${escapeHtml(label)}</option>`;
        }).join('');
    } catch (e) { /* leave manual entry available */ }
    // (2) Automation-readable DNS credentials from the Credential Vault. The
    // module only ever holds the {bucket,name} reference — the secret value is
    // resolved server-side at issue time and never exposed to the browser.
    try {
        const v = await apiJson('/tenant/cred-vault/automation-secrets?type=dns');
        const vaultCreds = (v && v.secrets) || [];
        if (vaultCreds.length) {
            opts += '<optgroup label="Credential Vault">' + vaultCreds.map(s => {
                const bucketLabel = s.is_admin_slot ? 'Global Admin' : s.bucket;
                return `<option value="vault:${escapeHtml(s.bucket)}/${escapeHtml(s.name)}">🔐 ${escapeHtml(s.name)} — ${escapeHtml(bucketLabel)}</option>`;
            }).join('') + '</optgroup>';
        }
    } catch (e) { /* vault optional / not reachable — spoke creds still offered */ }
    sel.innerHTML = opts;
    sel.dataset.loaded = '1';
}

// When a saved credential is picked, it supplies the provider + secrets, so hide
// the manual provider/creds inputs; "— enter manually —" shows them again.
function leIssueToggleSavedCred() {
    const useSaved = !!document.getElementById('le-issue-dns-credential')?.value;
    const set = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    set('le-issue-dns-provider-row', !useSaved);
    set('le-issue-dns-creds-row', !useSaved);
    if (!useSaved) leIssueUpdateDnsFields();
}

function leIssueAddTarget() {
    const mt = document.getElementById('le-issue-tgt-mt')?.value;
    const identifier = document.getElementById('le-issue-tgt-id')?.value?.trim() || '';
    if (!mt) { showToast('Pick a module type first', 'success'); return; }
    _leIssueTargets.push({ module_type: mt, identifier });
    // Reset the device dropdown back to the first device for the chosen module.
    leTgtMtChange('le-issue-tgt-mt', 'le-issue-tgt-id');
    leIssueRenderTargets();
}

function leIssueRemoveTarget(i) {
    _leIssueTargets.splice(i, 1);
    leIssueRenderTargets();
}

function leIssueRenderTargets() {
    const cell = document.getElementById('le-issue-targets-list');
    if (!cell) return;
    cell.innerHTML = _leIssueTargets.length === 0
        ? `<span class="text-xs text-slate-400 italic">none — add below (optional)</span>`
        : `<div class="flex flex-wrap gap-1">${_leIssueTargets.map((t, i) =>
            `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                ${t.module_type}${t.identifier ? '/' + escapeHtml(t.identifier) : ''}
                <button onclick="leIssueRemoveTarget(${i})" class="text-slate-400 hover:text-red-600" type="button">✕</button>
            </span>`).join('')}</div>`;
}

// Populate the issue-cert Domain datalist with the caller's eligible domains: the
// A/AAAA hostnames from their tenant's DNS (DNS module + firewalls) + a derived
// *.<domain> wildcard per parent domain. Best-effort — free text still works, but
// with the `le` subnet filter ON a cert only shows for a domain that resolves into
// the tenant's subnet, so this steers the operator to a DNS entry they've configured.
async function leIssuePopulateDomains() {
    const dl = document.getElementById('le-issue-domain-list');
    if (!dl) return;
    try {
        const { ok, data } = await _spokeFetch('/api/le/eligible-domains');
        if (!ok || !data) return;
        const esc = escapeHtml;  // shared escaper (escapes &<>"')
        const opts = [...(data.hosts || []), ...(data.wildcards || [])];
        dl.innerHTML = opts.map(h => `<option value="${esc(h)}"></option>`).join('');
    } catch (e) { /* best-effort — the field is still free-text */ }
}

async function showLeIssueModal(prefill) {
    _leIssueTargets = [];
    if (!window._leAvailableTargets || !window._leAvailableTargets.length) {
        await _leRefreshAvailableTargets();
    }
    const mtOpts = leModuleOptions();
    const dnsOpts = LE_DNS_PROVIDERS.map(([v, lbl]) => `<option value="${v}">${lbl}</option>`).join('');
    // Remove any prior modal (e.g. left over from a previous open).
    document.getElementById('le-issue-modal')?.remove();
    const modal = openModal('le-issue-modal', `
        <h3 class="text-lg font-bold mb-1">Issue a certificate</h3>
        <p class="text-xs text-slate-500 mb-4">Runs <code>certbot certonly</code> on the le spoke. The ACME account email below is registered with Let's Encrypt on first use and reused after. Staging issues an untrusted cert — use it to validate the flow before going live.</p>
        <div class="space-y-3">
            <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">Domain <span class="text-red-500">*</span></label>
                    <input id="le-issue-domain" type="text" list="le-issue-domain-list" placeholder="pick or type a domain" title="Target domain or FQDN to issue certificate for (e.g. example.com or *.example.com)" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                    <datalist id="le-issue-domain-list"></datalist>
                    <p class="text-[11px] text-slate-400 mt-1">Your DNS entries (from DNS + firewalls). A cert only shows on your Certificates page if its domain resolves into your subnet.</p>
                </div>
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">ACME account email <span class="text-red-500">*</span></label>
                    <input id="le-issue-email" type="email" placeholder="admin@example.com" title="ACME account contact email address for renewal notices" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">Challenge type</label>
                    <select id="le-issue-challenge" onchange="leIssueToggleChallenge()" title="Select ACME challenge validation type" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="http">HTTP-01 (standalone)</option>
                        <option value="http-webroot">HTTP-01 (webroot)</option>
                        <option value="dns">DNS</option>
                        <option value="tls-alpn">TLS-ALPN-01</option>
                    </select>
                </div>
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">Key type</label>
                    <select id="le-issue-keytype" title="Select cryptographic key type" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="rsa">RSA</option>
                        <option value="ecdsa">ECDSA</option>
                    </select>
                </div>
            </div>
            <div id="le-issue-webroot-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">Webroot path</label>
                <input id="le-issue-webroot" type="text" placeholder="/var/www/html" title="Path to webroot directory for HTTP-01 challenge" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
            </div>
            <div id="le-issue-dns-cred-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">Saved DNS credential</label>
                <select id="le-issue-dns-credential" onchange="leIssueToggleSavedCred()" title="Select saved tenant DNS credential" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    <option value="">— enter manually below —</option>
                </select>
                <p class="text-[11px] text-slate-400 mt-1">Pick one of your tenant's saved credentials (manage via 🔑 DNS Credentials), or enter one manually below.</p>
            </div>
            <div id="le-issue-dns-provider-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">DNS provider</label>
                <select id="le-issue-dns-provider" onchange="leIssueUpdateDnsFields()" title="Select DNS provider plugin" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${dnsOpts}</select>
            </div>
            <div id="le-issue-dns-creds-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">DNS credentials <span class="text-slate-400">(written to /etc/lm-le/dns-&lt;provider&gt;.ini at 0600)</span></label>
                <!-- RFC 2136 family (rfc2136, Hurricane Electric): structured
                     key name + key secret — the only two values you actually
                     need. Server/port/algorithm are behind "Advanced". -->
                <div id="le-issue-dns-structured" class="space-y-2 hidden">
                    <div class="grid grid-cols-2 gap-3">
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">Key name <span class="text-red-500">*</span></label>
                            <input id="le-issue-dns-keyname" type="text" placeholder="YOUR_KEY_NAME" title="TSIG key name" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">Key secret <span class="text-red-500">*</span></label>
                            <input id="le-issue-dns-keysecret" type="password" placeholder="YOUR_TSIG_SECRET" title="TSIG key secret" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                    </div>
                    <details class="text-xs">
                        <summary class="cursor-pointer text-slate-500 hover:text-slate-700 select-none">Advanced — server / port / algorithm</summary>
                        <div class="grid grid-cols-3 gap-2 mt-2">
                            <div class="flex flex-col">
                                <label class="text-[11px] text-slate-400 mb-0.5">Server</label>
                                <input id="le-issue-dns-server" type="text" placeholder="216.218.130.2 (IP, not a hostname)" title="Primary authoritative DNS server IP address" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                            </div>
                            <div class="flex flex-col">
                                <label class="text-[11px] text-slate-400 mb-0.5">Port</label>
                                <input id="le-issue-dns-port" type="text" value="53" title="Authoritative DNS server port (default 53)" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                            </div>
                            <div class="flex flex-col">
                                <label class="text-[11px] text-slate-400 mb-0.5">Algorithm</label>
                                <select id="le-issue-dns-algo" title="TSIG HMAC algorithm" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500">
                                    <option value="hmac-sha256">hmac-sha256</option>
                                    <option value="hmac-sha512">hmac-sha512</option>
                                    <option value="hmac-sha1">hmac-sha1</option>
                                    <option value="hmac-md5">hmac-md5</option>
                                </select>
                            </div>
                        </div>
                    </details>
                </div>
                <!-- Hurricane Electric ACCOUNT LOGIN (dns.he.net web panel; no
                     TSIG, no IP). Blank fields → use the saved HE account knob
                     (Setup → Certificates). -->
                <div id="le-issue-he-login" class="space-y-2 hidden">
                    <p class="text-[11px] text-slate-400">Sets the <span class="font-mono">_acme-challenge</span> TXT via the dns.he.net web panel with your HE account — no per-record TSIG keys. Leave blank to use the saved HE account (Setup → Certificates → Hurricane Electric login).</p>
                    <div class="grid grid-cols-2 gap-3">
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">HE account email</label>
                            <input id="le-issue-he-user" type="text" placeholder="(use saved account)" autocomplete="off" title="Hurricane Electric account username or email" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">HE account password</label>
                            <input id="le-issue-he-pass" type="password" placeholder="(use saved account)" autocomplete="new-password" title="Hurricane Electric account password" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                    </div>
                </div>
                <!-- Non-rfc2136 providers: raw INI textarea (field shapes vary
                     per provider — sample shown as a grey placeholder). -->
                <textarea id="le-issue-dns-creds" rows="5" placeholder="" title="Provider-specific INI credentials configuration" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500 placeholder:text-slate-400 placeholder:font-mono placeholder:text-xs"></textarea>
            </div>
            <div class="flex items-center gap-4 flex-wrap">
                <label class="flex items-center gap-2 text-sm text-slate-700">
                    <input id="le-issue-staging" type="checkbox" title="Issue staging certificate from Let's Encrypt staging environment" class="rounded border-slate-300" />
                    Use Let's Encrypt <b>staging</b> (untrusted — for testing)
                </label>
                <label class="flex items-center gap-1 text-sm text-slate-700" title="Let's Encrypt sets the certificate LIFETIME via a named ACME profile, not an arbitrary duration. Standard is ~90 days; short-lived is ~7 days. mTLS CLIENT certs are NOT issued here — the hub mints those from its Local CA (see the 🔒 mTLS status panel).">
                    Lifetime
                    <select id="le-issue-profile" title="ACME certificate lifetime profile" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="">Standard (~90 days)</option>
                        <option value="shortlived">Short-lived (~7 days)</option>
                    </select>
                </label>
                <label class="flex items-center gap-1 text-sm text-slate-700" title="How many days before expiry the renewal loop triggers for THIS cert. Default 7. A larger window renews earlier (more retry slack before it actually expires); a smaller one renews later.">
                    Renew before expiry
                    <input id="le-issue-renew-window" type="number" min="1" value="7" title="Days before expiration when renewal triggers" class="w-16 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                    days
                </label>
            </div>
            <div class="border-t border-slate-200 pt-3">
                <label class="text-xs text-slate-500 mb-1 block">Initial distribution targets (optional)</label>
                <div id="le-issue-targets-list" class="mb-2"></div>
                <div class="flex flex-wrap items-end gap-2">
                    <div class="flex flex-col">
                        <label class="text-[11px] text-slate-400 mb-0.5">Module type</label>
                        <select id="le-issue-tgt-mt" onchange="leTgtMtChange('le-issue-tgt-mt','le-issue-tgt-id')" title="Select spoke or target module type" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${mtOpts}</select>
                    </div>
                    <div class="flex flex-col flex-1 min-w-[160px]">
                        <label class="text-[11px] text-slate-400 mb-0.5">Device</label>
                        <select id="le-issue-tgt-id" title="Select target device or node identifier" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></select>
                    </div>
                    <button onclick="leIssueAddTarget()" type="button" title="Add distribution target" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-2 rounded-md text-sm font-medium">Add</button>
                </div>
            </div>
        </div>
        <div class="flex justify-end gap-2 mt-5">
            <button onclick="document.getElementById('le-issue-modal').remove()" title="Cancel and close dialog" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium">Cancel</button>
            <button id="le-issue-submit" onclick="leIssueCert()" title="Submit certificate issuance request" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Issue certificate</button>
        </div>`, { card: 'max-w-2xl w-full p-6 my-auto', overlay: 'overflow-y-auto py-6' });
    leIssuePopulateDomains();
    leIssueRenderTargets();
    leIssueUpdateDnsFields();
    leTgtMtChange('le-issue-tgt-mt', 'le-issue-tgt-id');  // seed device list for the first module
    if (prefill) await _leApplyIssuePrefill(prefill);
}

// Populate the Issue-certificate modal from a stored request body (used by the
// "Edit" action on a failed row). Mirrors leIssueCert's body shape in reverse:
// domain/email/challenge/key/profile/staging/renew + the DNS credential choice
// (vault ref → named cred → manual provider / HE-login / INI) + targets.
async function _leApplyIssuePrefill(p) {
    if (!p || typeof p !== 'object') return;
    const setV = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
    setV('le-issue-domain', p.domain);
    setV('le-issue-email', p.email);
    const chSel = document.getElementById('le-issue-challenge');
    if (chSel) {
        // leIssueCert normalizes http-webroot → challenge:'http' + a webroot; the
        // presence of webroot distinguishes the two HTTP modes on the way back.
        chSel.value = p.webroot ? 'http-webroot'
            : (p.challenge === 'dns' ? 'dns' : p.challenge === 'tls-alpn' ? 'tls-alpn' : 'http');
    }
    setV('le-issue-keytype', p.key_type);
    setV('le-issue-profile', p.profile || '');
    if (p.renew_window_days) setV('le-issue-renew-window', p.renew_window_days);
    const stg = document.getElementById('le-issue-staging'); if (stg) stg.checked = !!p.staging;
    setV('le-issue-webroot', p.webroot);
    _leIssueTargets = Array.isArray(p.targets) ? p.targets.slice() : [];
    leIssueRenderTargets();
    leIssueToggleChallenge();  // reveal the rows for the selected challenge
    if (chSel && chSel.value === 'dns') {
        await leIssuePopulateCreds();  // ensure the saved/vault credential list is loaded
        const credSel = document.getElementById('le-issue-dns-credential');
        if (p.dns_vault_credential && p.dns_vault_credential.bucket) {
            if (credSel) credSel.value = `vault:${p.dns_vault_credential.bucket}/${p.dns_vault_credential.name}`;
        } else if (p.dns_credential) {
            if (credSel) credSel.value = p.dns_credential;
        } else if (p.dns_provider != null || p.he_username != null) {
            if (credSel) credSel.value = '';  // manual entry
            const provSel = document.getElementById('le-issue-dns-provider');
            // he_username/he_password imply the HE account-login provider.
            const prov = (p.he_username != null || p.he_password != null) ? 'he-login' : (p.dns_provider || '');
            if (provSel && prov) provSel.value = prov;
            leIssueUpdateDnsFields();
            setV('le-issue-he-user', p.he_username);
            setV('le-issue-he-pass', p.he_password);
            if (p.dns_creds) setV('le-issue-dns-creds', p.dns_creds);
        }
        leIssueToggleSavedCred();  // show/hide manual inputs to match the credential choice
    }
}

// Toggle the DNS-01 input shape for the selected provider. RFC 2136 family
// (rfc2136, Hurricane Electric) gets the friendly key-name + key-secret form
// (server/port/algorithm under "Advanced"); every other provider gets the raw
// INI textarea with a per-provider sample placeholder.
function leIssueUpdateDnsFields() {
    const p = document.getElementById('le-issue-dns-provider')?.value;
    if (!p) return;
    const heLogin = p === 'he-login';
    const structured = LE_RFC2136_PROVIDERS.has(p);
    const setShown = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    setShown('le-issue-he-login', heLogin);
    setShown('le-issue-dns-structured', structured && !heLogin);
    setShown('le-issue-dns-creds', !structured && !heLogin);
    if (heLogin) {
        // nothing to prefill — creds come from the fields or the saved knob
    } else if (structured) {
        // Pre-fill the Advanced "Server" field with the provider default when
        // it's empty (Hurricane Electric → ns1.he.net) so the user only types
        // the two secrets. Don't clobber a value they already entered.
        const srv = document.getElementById('le-issue-dns-server');
        const def = LE_RFC2136_DEFAULT_SERVER[p] || '';
        if (srv && !srv.value) srv.value = def;
    } else {
        const ta = document.getElementById('le-issue-dns-creds');
        if (ta) ta.placeholder = LE_DNS_CREDS_HINT[p] || '';
    }
}

// Assemble the rfc2136 INI from the structured fields. Sent as `dns_creds` —
// the le spoke writes it to /etc/lm-le/dns-rfc2136.ini at 0600 (write_dns_creds).
function leIssueBuildRfc2136Ini() {
    const kn = document.getElementById('le-issue-dns-keyname')?.value?.trim() || '';
    const ks = document.getElementById('le-issue-dns-keysecret')?.value || '';
    const srv = document.getElementById('le-issue-dns-server')?.value?.trim() || '';
    const port = document.getElementById('le-issue-dns-port')?.value?.trim() || '53';
    const algo = document.getElementById('le-issue-dns-algo')?.value || 'hmac-sha256';
    let ini = '';
    if (srv) ini += `dns_rfc2136_server = ${srv}\n`;
    ini += `dns_rfc2136_port = ${port}\n`;
    // certbot-dns-rfc2136 property names are dns_rfc2136_name / _secret (NOT
    // _key_name / _key_secret) — the wrong keys produced "Property
    // dns_rfc2136_name not found" and the issue failed.
    ini += `dns_rfc2136_name = ${kn}\n`;
    ini += `dns_rfc2136_secret = ${ks}\n`;
    ini += `dns_rfc2136_algorithm = ${algo}\n`;
    return { ini, keyName: kn, keySecret: ks };
}

async function leIssueCert() {
    const domain = document.getElementById('le-issue-domain')?.value?.trim();
    const email = document.getElementById('le-issue-email')?.value?.trim();
    const chSel = document.getElementById('le-issue-challenge')?.value || 'http';
    const challenge = chSel === 'http-webroot' ? 'http' : chSel;
    const webroot = chSel === 'http-webroot' ? (document.getElementById('le-issue-webroot')?.value?.trim() || '') : '';
    // A saved (named) DNS credential wins — it supplies the provider + secrets
    // server-side, so the manual provider/creds inputs are skipped entirely.
    const savedCred = chSel === 'dns' ? (document.getElementById('le-issue-dns-credential')?.value || '') : '';
    const dnsProvider = chSel === 'dns' ? (document.getElementById('le-issue-dns-provider')?.value || '') : '';
    // For rfc2136-family providers the creds come from the structured key-name
    // / key-secret fields (assembled into an INI below); otherwise from the
    // raw INI textarea.
    const _heLogin = chSel === 'dns' && dnsProvider === 'he-login';
    const _rfc = chSel === 'dns' && dnsProvider && LE_RFC2136_PROVIDERS.has(dnsProvider);
    const _rfcIni = _rfc ? leIssueBuildRfc2136Ini() : null;
    const dnsCreds = _rfc ? _rfcIni.ini
        : (chSel === 'dns' ? (document.getElementById('le-issue-dns-creds')?.value || '') : '');
    const staging = !!document.getElementById('le-issue-staging')?.checked;
    const keyType = document.getElementById('le-issue-keytype')?.value || 'rsa';
    const profile = document.getElementById('le-issue-profile')?.value || '';

    if (!domain) { showToast('Domain is required', 'error'); return; }
    if (!email) { showToast('ACME account email is required', 'error'); return; }
    if (chSel === 'http-webroot' && !webroot) { showToast('Webroot path is required for HTTP-01 webroot', 'error'); return; }
    if (challenge === 'dns' && !savedCred) {
        if (!dnsProvider) { showToast('Pick a saved DNS credential or a DNS provider for DNS-01', 'success'); return; }
        if (_rfc) {
            if (!_rfcIni.keyName) { showToast('TSIG key name is required', 'error'); return; }
            if (!_rfcIni.keySecret) { showToast('TSIG key secret is required', 'error'); return; }
        } else if (!_heLogin && !dnsCreds.trim()) {
            showToast('DNS credentials INI is required for DNS-01', 'error'); return;
        }
    }

    const body = { domain, email, challenge, staging, key_type: keyType };
    if (profile) body.profile = profile;   // ACME profile (e.g. shortlived — lifetime only)
    // Per-cert renewal window (days before expiry the loop triggers). Send only
    // a positive int; blank/invalid → omitted → spoke stores None → uses the
    // 7-day default. The le spoke validates + normalizes (bad → None).
    const rwd = parseInt(document.getElementById('le-issue-renew-window')?.value, 10);
    if (Number.isFinite(rwd) && rwd > 0) body.renew_window_days = rwd;
    if (chSel === 'http-webroot') body.webroot = webroot;
    // Resolve frontend provider aliases (e.g. Hurricane Electric → rfc2136) so
    // the spoke receives the real certbot plugin name.
    if (challenge === 'dns' && savedCred.startsWith('vault:')) {
        // Vaulted DNS credential: send only the {bucket,name} reference. The hub
        // resolves the secret value server-side (automation_get) at issue time
        // and never exposes it to the browser.
        const rest = savedCred.slice('vault:'.length);
        const slash = rest.indexOf('/');
        body.dns_vault_credential = { bucket: rest.slice(0, slash), name: rest.slice(slash + 1) };
    } else if (challenge === 'dns' && savedCred) {
        // Named tenant credential: the spoke resolves provider + secrets from it.
        body.dns_credential = savedCred;
    } else if (challenge === 'dns') {
        body.dns_provider = LE_DNS_PROVIDER_ALIAS[dnsProvider] || dnsProvider;
        if (_heLogin) {
            // HE account login: send per-request creds if typed, else the spoke
            // uses the saved knob. No dns_creds INI for this provider.
            const hu = document.getElementById('le-issue-he-user')?.value?.trim() || '';
            const hp = document.getElementById('le-issue-he-pass')?.value || '';
            if (hu) body.he_username = hu;
            if (hp) body.he_password = hp;
        } else {
            body.dns_creds = dnsCreds;
        }
    }
    if (_leIssueTargets.length) body.targets = _leIssueTargets;

    // Hand off to the shared runner — it toasts on queue, tracks per-domain
    // status, logs success/fail, and refreshes the cert list. The modal stays
    // OPEN on failure so the operator can tweak a field and click Issue again
    // (retry without re-filling); it closes only on success.
    return _leRunIssue(body, { closeModalOnSuccess: true });
}

// Client-side LE issue job tracker: per-domain latest issue attempt.
//   state: 'pending' | 'success' | 'failed'
// Lets the cert list show a green/red/spinner indicator for the last issue and a
// Retry button that re-posts the stored params without re-filling the form.
window._leIssueStatus = window._leIssueStatus || {};

// Core issue runner — shared by the modal submit (leIssueCert) and the Retry
// button (leRetryIssue). Queues the request with a toast, tracks per-domain
// status, logs success/fail to the console, and refreshes the cert list so the
// indicator flips live. The spoke call can take ~3 min for DNS-01 (hub
// _LE_CERTBOT_TIMEOUT=200s), so this is fire-and-forget from the UI's POV: the
// toast is shown immediately and the row gets a spinner while we wait.
async function _leRunIssue(body, { closeModalOnSuccess = false } = {}) {
    const domain = body.domain;
    window._leIssueStatus[domain] = { state: 'pending', ts: Date.now(), message: 'Queued — issuing…', params: body };
    // Issuing (esp. DNS-01) + distribution can take minutes. Don't hold the modal
    // open on a synchronous wait: close it NOW and tell the operator to check
    // back. The request runs in the background (this fn is not awaited by the
    // click handler); the pending row + per-domain status update the table when
    // it finishes.
    document.getElementById('le-issue-modal')?.remove();
    showToast('Certificate request for ' + domain + ' queued — check the Certificates page in ~15 minutes for details.', 'info');
    await loadLEData(); // show the pending spinner row immediately
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/issue', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!ok) {
            window._leIssueStatus[domain] = { state: 'failed', ts: Date.now(), message: detail || 'Issue failed', params: body };
            showToast('Issue failed for ' + domain + ': ' + (detail || ''), 'error');
            console.warn('[le] issue failed', domain, detail);
            await loadLEData();
            return;
        }
        // The spoke returns nested {status, data:{...}}; the hub adds
        // data.distribution (per-target push summary from net_services.py:le_issue_cert).
        const inner = (data && data.data) ? data.data : (data || {});
        const dist = inner.distribution || [];
        // Per-target outcome: ✓/✗ count + the first error message inline so a
        // distribution failure (the common "issued but not distributed" case)
        // is visible in the toast — not buried. The cert-level indicator
        // stays GREEN on a dist failure (the cert WAS issued — re-issuing would
        // waste a certbot run / risk rate-limiting); the retry path is the
        // "Distribute now" button or the targets modal, not re-Issue.
        let distMsg = '';
        let distFailed = false;
        if (dist.length) {
            const okN = dist.filter(d => d.status === 'SUCCESS').length;
            const failN = dist.length - okN;
            distFailed = failN > 0;
            const firstErr = dist.find(d => d.status === 'ERROR');
            distMsg = ` · distributed ${okN}/${dist.length}` +
                (failN > 0 ? ` — ${failN} FAILED` +
                    (firstErr && firstErr.message ? `: ${firstErr.message}` : '') : '');
        }
        window._leIssueStatus[domain] = { state: 'success', ts: Date.now(), message: 'Issued' + distMsg, params: body };
        showToast('Issued ' + domain + (body.staging ? ' (staging)' : '') + distMsg,
            distFailed ? 'error' : 'success');
        console.info('[le] issued', domain, dist);
        await loadLEData();
    } catch (e) {
        window._leIssueStatus[domain] = { state: 'failed', ts: Date.now(), message: e.message || 'Issue failed', params: body };
        showToast('Issue failed for ' + domain + ': ' + e.message, 'error');
        console.warn('[le] issue error', domain, e);
        await loadLEData();
    }
}

// Retry the last failed issue for a domain using the stored params — fired from
// the Retry button on a failed cert/attempt row. Re-enters the shared runner so
// the toast + indicator + log behave exactly like a fresh submit; no modal.
async function leRetryIssue(domain) {
    const st = window._leIssueStatus && window._leIssueStatus[domain];
    if (!st || !st.params) {
        // No in-memory params (e.g. after a reboot/reload) — a blind retry is
        // impossible because the DNS credential/secret was never persisted.
        // Open the Edit modal pre-filled from the persisted cert entry so the
        // operator can re-select the credential and re-file.
        return leEditIssue(domain);
    }
    return _leRunIssue(st.params, { closeModalOnSuccess: false });
}

// Edit a failed request before re-filing: reopen the Issue-certificate modal
// pre-populated with the stored params (fixes the "can't edit the request"
// gap — Retry alone re-posts the same params blindly). Prefers the in-memory
// tracker's params; falls back to the BACKEND-persisted cert entry (from
// window._leCerts) so Edit still works after a reboot/reload, when the
// in-memory tracker is empty. The persisted entry carries domain/email/
// challenge/staging/targets/profile/renew window — but NOT the DNS secret
// (never stored), so the operator re-selects the credential.
async function leEditIssue(domain) {
    const st = window._leIssueStatus && window._leIssueStatus[domain];
    if (st && st.params) return showLeIssueModal(st.params);
    const c = (window._leCerts || []).find(x => x.domain === domain);
    if (c) {
        return showLeIssueModal({
            domain: c.domain,
            email: c.email,
            challenge: c.challenge,
            staging: c.staging,
            profile: c.profile,
            renew_window_days: c.renew_window_days,
            dns_provider: c.dns_provider,
            dns_credential: c.dns_credential,
            dns_vault_credential: c.dns_vault_credential,
            targets: c.targets,
        });
    }
    return showLeIssueModal({ domain });
}



// ── Per-tenant DNS-01 credential manager (settings screen) ───────────────────
// Multi-tenant, multi-provider: each tenant keeps named credentials for
// he-login / cloudflare / rfc2136 / route53. Certs pick one BY NAME at issue.
const DNS_CRED_PROVIDERS = {
    'he-login':   { label: 'Hurricane Electric (account login)', login: true, fields: [
        { k: 'username', label: 'Account email', type: 'text' },
        { k: 'password', label: 'Account password', type: 'password', secret: true } ] },
    'cloudflare': { label: 'Cloudflare (API token)', fields: [
        { k: 'api_token', label: 'API token (Zone.DNS edit)', type: 'password', secret: true, ini: 'dns_cloudflare_api_token' } ] },
    'rfc2136':    { label: 'RFC2136 dynamic DNS (TSIG)', fields: [
        { k: 'server', label: 'DNS server (IP address)', type: 'text', placeholder: 'e.g. 192.0.2.53', ini: 'dns_rfc2136_server' },
        { k: 'name', label: 'TSIG key name', type: 'text', ini: 'dns_rfc2136_name' },
        { k: 'secret', label: 'TSIG key secret', type: 'password', secret: true, ini: 'dns_rfc2136_secret' },
        { k: 'algorithm', label: 'Algorithm', type: 'text', placeholder: 'HMAC-SHA512', ini: 'dns_rfc2136_algorithm' } ] },
    'route53':    { label: 'AWS Route 53', fields: [
        { k: 'access_key_id', label: 'AWS access key ID', type: 'text', ini: 'dns_route53_access_key_id' },
        { k: 'secret_access_key', label: 'AWS secret access key', type: 'password', secret: true, ini: 'dns_route53_secret_access_key' } ] },
};

async function showDnsCredentialsModal() {
    // Whether a Credential Vault is configured decides which mode this modal
    // runs in. With a vault, DNS-01 secrets belong there and this is a
    // read-only list + cleanup view. With NO vault there is nowhere else to put
    // them, so the spoke-local store (encrypted at rest) is the supported path
    // and the add/edit form is shown. The backend enforces the same rule.
    let vaultOn = false;
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', { method: 'GET' });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        vaultOn = !!(d.vault_enabled ?? (r.data && r.data.vault_enabled));
    } catch (e) { /* fall back to showing the editor; the API is the real gate */ }

    const modal = document.createElement('div');
    modal.id = 'dns-creds-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    const provOpts = Object.entries(DNS_CRED_PROVIDERS).map(([k, v]) => `<option value="${k}">${escapeHtml(v.label)}</option>`).join('');
    const note = vaultOn
        ? `<div class="text-xs px-3 py-2 rounded bg-blue-50 text-blue-700 border border-blue-100">🔐 New DNS credentials are managed in the <b>Credential Vault</b> (add a <b>DNS</b> secret there, then pick it in the issue-cert form). Creating raw credentials here is disabled; existing ones below still work and can be deleted.</div>
          <p class="text-xs text-slate-500">Saved DNS credentials for <b>your tenant</b> (stored on the le spoke). A certificate can still pick one of these by name when issuing. Delete any you've migrated to the vault.</p>`
        : `<p class="text-xs text-slate-500">Saved DNS credentials for <b>your tenant</b>. A certificate picks one by name when issuing. Secrets are stored on the le spoke, <b>encrypted at rest</b>, and are never shown again — leave a secret blank when editing to keep it.</p>
           <p class="text-[11px] text-slate-400">No Credential Vault is configured, so credentials are kept locally. Configure a vault under Setup → Cloud to manage them centrally instead.</p>`;
    const form = vaultOn ? '' : `
          <div class="border-t border-slate-200 pt-4">
            <h4 id="dns-cred-form-title" class="text-sm font-bold text-slate-600 mb-2">Add a credential</h4>
            <div class="grid grid-cols-2 gap-3">
              <div class="flex flex-col"><label class="text-[11px] text-slate-500 mb-0.5">Name</label>
                <input id="dns-cred-name" type="text" placeholder="e.g. HE - lrbtech" title="Descriptive label for this DNS credential set" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
              <div class="flex flex-col"><label class="text-[11px] text-slate-500 mb-0.5">Provider</label>
                <select id="dns-cred-provider" onchange="dnsCredRenderFields()" title="Select DNS provider service" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${provOpts}</select></div>
            </div>
            <div id="dns-cred-fields" class="grid grid-cols-2 gap-3 mt-3"></div>
            <div class="flex justify-end gap-2 mt-3">
              <button onclick="dnsCredResetForm()" title="Clear form fields" class="px-3 py-1.5 text-sm text-slate-600 hover:text-slate-800">Clear</button>
              <button onclick="saveDnsCredential()" title="Save DNS provider credential" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-sm font-bold">Save credential</button>
            </div>
          </div>`;
    modal.innerHTML = `
      <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">DNS Credentials</h3>
          <button onclick="document.getElementById('dns-creds-modal').remove()" title="Close dialog" class="text-slate-400 hover:text-slate-600">✕</button>
        </div>
        <div class="p-6 space-y-4 overflow-y-auto">
          ${note}
          <div id="dns-creds-list" class="space-y-2"><p class="text-sm text-slate-400 italic">Loading…</p></div>
          ${form}
        </div>
      </div>`;
    _mountModal(modal);
    modal.dataset.vaultOn = vaultOn ? '1' : '';
    if (!vaultOn) dnsCredRenderFields();
    await dnsCredReloadList();
}

function dnsCredRenderFields(values) {
    const p = document.getElementById('dns-cred-provider')?.value;
    const def = DNS_CRED_PROVIDERS[p];
    const box = document.getElementById('dns-cred-fields');
    if (!def || !box) return;
    values = values || {};
    const secretsSet = values.__secrets__ || {};
    box.innerHTML = def.fields.map(f => `
      <div class="flex flex-col">
        <label class="text-[11px] text-slate-500 mb-0.5">${escapeHtml(f.label)}</label>
        <input id="dns-cred-f-${f.k}" type="${f.type}" value="${f.secret ? '' : escapeHtml(values[f.k] || '')}"
               placeholder="${f.secret && secretsSet[f.k] ? '(keep stored)' : (f.placeholder ? escapeHtml(f.placeholder) : '')}"
               title="${escapeHtml(f.label)}"
               autocomplete="off" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
      </div>`).join('');
}

function dnsCredEdit(c) {
    const nameEl = document.getElementById('dns-cred-name');
    const provEl = document.getElementById('dns-cred-provider');
    if (nameEl) nameEl.value = c.name || '';
    if (provEl) provEl.value = c.provider || 'he-login';
    const title = document.getElementById('dns-cred-form-title');
    if (title) title.textContent = 'Edit "' + (c.name || '') + '"';
    dnsCredRenderFields({ ...(c.fields || {}), __secrets__: c.secrets_set || {} });
}

function dnsCredResetForm() {
    const nameEl = document.getElementById('dns-cred-name'); if (nameEl) nameEl.value = '';
    const title = document.getElementById('dns-cred-form-title'); if (title) title.textContent = 'Add a credential';
    dnsCredRenderFields();
}

async function saveDnsCredential() {
    const name = document.getElementById('dns-cred-name')?.value?.trim() || '';
    const provider = document.getElementById('dns-cred-provider')?.value || '';
    if (!name) { showToast('Credential name is required.', 'error'); return; }
    const def = DNS_CRED_PROVIDERS[provider];
    const fields = {};
    def.fields.forEach(f => {
        const v = document.getElementById('dns-cred-f-' + f.k)?.value ?? '';
        if (v !== '' || !f.secret) fields[f.k] = v;  // empty secret → omit (keep stored)
    });
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, provider, fields }),
        });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        if (!r.ok || d.status === 'ERROR') { showToast('Save failed: ' + (d.message || r.detail || ''), 'error'); return; }
        showToast('DNS credential saved', 'success');
        dnsCredResetForm();
        await dnsCredReloadList();
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

async function dnsCredReloadList() {
    const box = document.getElementById('dns-creds-list');
    if (!box) return;
    const vaultOn = !!document.getElementById('dns-creds-modal')?.dataset.vaultOn;
    let creds = [];
    let warn = '';
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', { method: 'GET' });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        creds = d.credentials || [];
        warn = d.migrate_warning || (r.data && r.data.migrate_warning) || '';
    } catch (e) { box.innerHTML = `<p class="text-sm text-red-500">Could not load: ${escapeHtml(e.message)}</p>`; return; }
    const warnBanner = warn
        ? `<div class="text-xs px-3 py-2 mb-2 rounded bg-amber-50 text-amber-800 border border-amber-200">⚠ ${escapeHtml(warn)}</div>`
        : '';
    if (!creds.length) {
        const empty = vaultOn
            ? 'No credentials stored here — add a DNS secret in the Credential Vault.'
            : 'No credentials yet — add one below.';
        box.innerHTML = warnBanner + `<p class="text-sm text-slate-400 italic">${empty}</p>`;
        return;
    }
    box.innerHTML = warnBanner + creds.map(c => {
        const label = (DNS_CRED_PROVIDERS[c.provider] || {}).label || c.provider;
        const editBtn = vaultOn ? '' :
            `<button onclick='dnsCredEdit(${escapeHtml(JSON.stringify(c))})' title="Edit this stored DNS provider credential" class="text-xs text-slate-600 hover:text-slate-800 border border-slate-200 rounded px-2 py-1">Edit</button>`;
        return `<div class="flex items-center justify-between border border-slate-200 rounded-md px-3 py-2">
          <div><span class="text-sm font-medium text-slate-700">${escapeHtml(c.name)}</span>
            <span class="text-[11px] text-slate-400 ml-2">${escapeHtml(label)}</span></div>
          <div class="flex gap-2">
            ${editBtn}
            <button onclick="deleteDnsCredential(${escapeHtml(JSON.stringify(c.name))})" class="text-xs text-red-500 hover:text-red-700 border border-red-200 rounded px-2 py-1" title="Delete this stored DNS provider credential">Delete</button>
          </div></div>`;
    }).join('');
}

async function deleteDnsCredential(name) {
    if (!confirm('Delete DNS credential "' + name + '"?')) return;
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', {
            method: 'DELETE', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
        });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        if (!r.ok || d.status === 'ERROR') { showToast('Delete failed: ' + (d.message || r.detail || ''), 'error'); return; }
        showToast('DNS credential deleted', 'success');
        await dnsCredReloadList();
    } catch (e) { showToast('Delete failed: ' + e.message, 'error'); }
}

// Tag / un-tag a managed cert as the AppBuilder identity (H1), driven by the
// checkbox inside the Manage modal. Only a connection presenting a tagged cert
// over mTLS may use the reverse HUB_REQUEST channel (read every tenant's hub
// logs + run fleet TRIGGER_* update commands). This just records which domain's
// cert is the AppBuilder identity; deploy the cert itself to a ab target
// (also in Manage) so the agent presents it. POST /api/le/certs/{domain}/ab.
async function leToggleAppBuilderChk(cb, domain) {
    const enable = cb ? cb.checked : true;
    if (cb) { cb.disabled = true; }
    try {
        const { ok, data, detail } = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/ab`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enable })
        });
        if (!ok) {
            showToast('AppBuilder tag failed: ' + (detail || 'request rejected'), 'error');
            if (cb) { cb.checked = !enable; cb.disabled = false; }
            return;
        }
        // Re-tag the cached certs from the hub's authoritative pinned list (the
        // POST response) so the table reflects the real server state — don't rely
        // solely on the re-fetch, which can lose to the inflight poller's guard.
        const pinned = (data && Array.isArray(data.pinned)) ? data.pinned.map(s => String(s).toLowerCase()) : null;
        if (pinned && Array.isArray(window._leCerts)) {
            for (const c of window._leCerts) {
                const names = [c.domain, ...(c.domains || [])].map(s => String(s || '').toLowerCase());
                c.ab = names.some(n => n && pinned.includes(n));
            }
        }
        showToast(enable
            ? `Tagged ${domain} as the AppBuilder cert — add a ab target (★) below so it presents over mTLS`
            : `Removed the AppBuilder tag from ${domain}`, 'success');
        // The hub mints ab's clientAuth mTLS cert from its Local CA for the
        // pinned SAN on the next connect (public CAs can't issue clientAuth) — kick
        // a re-provision now so it takes effect immediately.
        if (enable) {
            try { await _spokeFetch('/api/mtls/reprovision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ spoke_id: 'ab' }) }); } catch (e) { /* best-effort */ }
        }
        window._leLoading = false;   // clear any stuck guard so the re-render runs
        await loadLEData();          // refresh the top banner + row target stars
        if (cb) cb.disabled = false;
    } catch (e) {
        showToast('AppBuilder tag failed: ' + (e.message || e), 'error');
        if (cb) { cb.checked = !enable; cb.disabled = false; }
    }
}

// Revoke a spoke's Hub-CA mTLS client cert — it reconnects cert-less.
async function mtlsRevoke(spokeId, label) {
    if (!confirm(`Revoke ${label || spokeId}'s mTLS client cert?\n\nThe spoke reconnects cert-less and (if AppBuilder) loses hub-log/update access until you re-issue. Auto-provision won't re-mint until you click issue.`)) return;
    try {
        const { ok, detail } = await _spokeFetch('/api/mtls/revoke', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId })
        });
        if (!ok) { showToast('Revoke failed: ' + (detail || ''), 'error'); return; }
        showToast(`Revoked ${label || spokeId}'s mTLS cert`, 'success');
        setTimeout(() => { if (document.getElementById('mtls-debug-modal')) showMtlsDebug(); }, 1500);
    } catch (e) { showToast('Revoke failed: ' + (e.message || e), 'error'); }
}

// Toggle hub auto-provisioning of mTLS certs on spoke connect.
async function mtlsSetAutoProvision(enabled) {
    try {
        const { ok, detail } = await _spokeFetch('/api/mtls/auto-provision', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (!ok) { showToast('Auto-provision toggle failed: ' + (detail || ''), 'error'); return; }
        showToast(enabled ? 'Auto-provision ON — spokes get a cert on connect' : 'Auto-provision OFF — manage mTLS certs manually', 'success');
    } catch (e) { showToast('Auto-provision toggle failed: ' + (e.message || e), 'error'); }
}

// Issue/renew Hub-Local-CA mTLS client certs. spokeId '' = every connected spoke.
// The hub mints a clientAuth cert (public CAs can't) + delivers it; the spoke
// restarts to present it, then shows mTLS ✓ here.
async function mtlsProvision(spokeId) {
    showToast(spokeId ? `Issuing mTLS cert for ${spokeId}…` : 'Issuing mTLS certs for all connected spokes…', 'info');
    try {
        const { ok, data, detail } = await _spokeFetch('/api/mtls/reprovision', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(spokeId ? { spoke_id: spokeId } : {})
        });
        if (!ok) { showToast('Provision failed: ' + (detail || ''), 'error'); return; }
        const n = (data && data.count) || 0;
        showToast(`Issued/renewed ${n} mTLS cert(s) — spokes reconnect to present them`, 'success');
        setTimeout(() => { if (document.getElementById('mtls-debug-modal')) showMtlsDebug(); }, 1500);
    } catch (e) { showToast('Provision failed: ' + (e.message || e), 'error'); }
}

// Remove a STALE/orphaned Hub-CA mTLS client cert from the hub registry. This is
// the only way to clear a registry entry for a spoke that is NOT connected right
// now (e.g. a replaced or reset AppBuilder box left an orphaned cert behind — the
// connected-spokes table can't touch it). Reuses the same revoke endpoint (which
// also deletes the registry entry), just with wording for the orphaned-entry case.
async function mtlsRemoveCert(pk, label) {
    if (!confirm(`Remove the stored mTLS cert for ${label || pk}?\n\nIf that box is gone this clears the orphaned entry. If the spoke is still connected it will reconnect cert-less until reissued.`)) return;
    try {
        const { ok, detail } = await _spokeFetch('/api/mtls/revoke', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: pk })
        });
        if (!ok) { showToast('Remove failed: ' + (detail || ''), 'error'); return; }
        showToast(`Removed stored mTLS cert for ${label || pk}`, 'success');
        setTimeout(() => { if (document.getElementById('mtls-debug-modal')) showMtlsDebug(); }, 1500);
    } catch (e) { showToast('Remove failed: ' + (e.message || e), 'error'); }
}

// mTLS debug screen: which connected spokes/agents are ACTUALLY presenting a
// verified mTLS client cert vs. connected cert-less (permissive fallback), plus the
// hub's client-verify trust bundle + the pinned AppBuilder cert verify. Fetches
// /api/mtls/trust-diag (admin) and renders a modal. Answers "is mTLS really on
// fleet-wide, and who's using it" — since CERT_OPTIONAL lets a spoke work either way.
// Hub Health & Connectivity — inline card on System → Hub Status. Renders the
// hub event-loop overload + per-spoke transport signals so an operator can tell
// a saturated hub loop from a network/transport problem (the hub is in Azure).
async function loadHubHealthCard() {
    const body = document.getElementById('hub-health-body');
    if (!body) return;
    try {
        const d = await apiJson('/api/hub/health');
        body.innerHTML = _hubHealthHtml(d);
    } catch (e) {
        body.innerHTML = `<p class="text-red-500 text-xs">Hub health failed: ${escapeHtml(e.message)}</p>`;
    }
}
window.loadHubHealthCard = loadHubHealthCard;

function _hubHealthHtml(d) {
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const _fmtBytes = (n) => n == null ? '—' : n >= 1048576 ? (n/1048576).toFixed(1)+' MB'
        : n >= 1024 ? (n/1024).toFixed(1)+' KB' : n + ' B';
    const th = d.thresholds || {};
    const lagHi = th.loop_lag_high_s || 0.75;
    const lag = d.loop_lag_s || 0, lagMax = d.loop_lag_max_s || 0;
    const lagColor = lag >= lagHi ? 'text-red-600' : lag >= lagHi/2 ? 'text-amber-600' : 'text-[#01A982]';
    const cpuColor = (d.cpu_pct||0) >= (th.cpu_high_pct||90) ? 'text-red-600' : 'text-slate-800';
    const memColor = (d.mem_pct||0) >= (th.mem_high_pct||90) ? 'text-red-600' : 'text-slate-800';
    const conns = d.connections || [];
    const anyHiRtt = conns.some(c => (c.rtt_ms||0) > 150);
    const anyBuf = conns.some(c => (c.write_buffer_bytes||0) > 65536);
    let verdict, vClass, hint;
    if (d.protect_mode) { verdict = `⚠ PROTECT — ${esc(d.protect_reason)} (${d.protect_since}s)`; vClass = 'bg-red-100 text-red-700'; }
    else if (lag >= lagHi) { verdict = 'Hub loop saturated'; vClass = 'bg-red-100 text-red-700'; }
    else { verdict = 'Hub loop healthy'; vClass = 'bg-green-100 text-green-700'; }
    if (lag >= lagHi) hint = '🔴 High loop lag with low RTT/buffers → the HUB LOOP is the bottleneck (fix hub-side — likely agent-log/telemetry flood from a provisioning storm).';
    else if (anyHiRtt || anyBuf) hint = '🌐 Loop is healthy but some spokes show high RTT or a growing write buffer → NETWORK / transport path (the hub is in Azure) to those spokes.';
    else hint = '🟢 Loop healthy and transport clean — no backpressure right now. (Catch it live during a stall for the clearest signal.)';
    const rows = conns.map(c => `<tr class="border-b border-slate-100">
        <td class="px-3 py-1.5">${esc(c.spoke)}</td>
        <td class="px-3 py-1.5 font-mono text-xs">${esc(c.remote_ip||'—')}</td>
        <td class="px-3 py-1.5 text-center ${(c.rtt_ms||0)>150?'text-red-600 font-bold':'text-slate-700'}">${c.rtt_ms!=null?c.rtt_ms+' ms':'—'}</td>
        <td class="px-3 py-1.5 text-center ${(c.write_buffer_bytes||0)>65536?'text-red-600 font-bold':'text-slate-700'}">${_fmtBytes(c.write_buffer_bytes)}</td>
        <td class="px-3 py-1.5 text-center text-slate-700">${c.mps}</td>
      </tr>`).join('') || `<tr><td colspan="5" class="px-3 py-3 text-slate-400 italic">No connected spokes.</td></tr>`;
    const talkers = (d.top_talkers||[]).slice(0,6).map(t => `${esc(t.spoke)} (${t.mps}/s)`).join(', ') || '—';
    return `<div class="space-y-4">
      <div class="flex items-center justify-end">
        <span class="text-xs px-2 py-1 rounded-full ${vClass}">${verdict}</span>
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
        <div><div class="text-slate-500 text-xs">Loop lag (now / 60s max)</div><div class="font-bold ${lagColor}">${lag.toFixed(2)}s / ${lagMax.toFixed(2)}s</div></div>
        <div><div class="text-slate-500 text-xs">Hub CPU (%/core)</div><div class="font-bold ${cpuColor}">${d.cpu_pct}%</div></div>
        <div><div class="text-slate-500 text-xs">Memory</div><div class="font-bold ${memColor}">${d.mem_pct}%</div></div>
        <div><div class="text-slate-500 text-xs">Msgs/s · Throughput</div><div class="font-bold text-slate-800">${d.mps} · ${d.throughput_mbps} MB/s</div></div>
        <div><div class="text-slate-500 text-xs">Connected spokes</div><div class="font-bold text-slate-800">${d.connected_spokes}</div></div>
        <div><div class="text-slate-500 text-xs">Req timeouts (recent / total)</div><div class="font-bold ${d.request_timeouts_recent?'text-amber-600':'text-slate-800'}">${d.request_timeouts_recent} / ${d.request_timeouts_total}</div></div>
        <div class="col-span-2"><div class="text-slate-500 text-xs">Top talkers (frames/s)</div><div class="text-slate-700 text-xs">${talkers}</div></div>
      </div>
      <div class="text-xs text-slate-700 bg-slate-50 border border-slate-200 rounded p-2">${hint}</div>
      <div class="overflow-x-auto border border-slate-200 rounded-lg">
        <table class="w-full text-sm"><thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
          <th class="px-3 py-1 text-left">Spoke</th><th class="px-3 py-1 text-left">Remote IP</th>
          <th class="px-3 py-1 text-center">RTT</th><th class="px-3 py-1 text-center">Write buffer</th><th class="px-3 py-1 text-center">msg/s</th>
        </tr></thead><tbody>${rows}</tbody></table>
      </div>
      <div class="text-[11px] text-slate-500">RTT = WS keepalive round-trip (network latency to the spoke). Write buffer = hub→spoke outbound backlog (growing = that spoke/network isn't draining). <b>High loop lag + low RTT/buffers = hub loop; high RTT or growing buffers = network transport.</b></div>
    </div>`;
}

// Spoke Registry Diagnostics — inline card on System → Hub Status. Answers
// "I deleted every spoke I could see and they still step on each other".
// Two facts the Spokes list cannot show: (1) a registration with no tenant_id is
// admin-only in the list (access.py spoke_visible_to_session) yet is still
// claimable as a tenant's Client-Sim broker (hub_spoke_registry.py:446), so a
// tenant-scoped operator cannot even enumerate what is stepping on them; and
// (2) the broker is bound[0] over the CONNECTED candidates, so leftovers from a
// rebuilt box make it flip between cycles. Backed by GET
// /setup/spoke-registry-diag (core/src/routes/setup.py).
async function loadSpokeRegistryDiag() {
    const body = document.getElementById('spoke-registry-diag-body');
    if (!body) return;
    try {
        const d = await apiJson('/setup/spoke-registry-diag');
        body.innerHTML = _spokeRegistryDiagHtml(d);
    } catch (e) {
        body.innerHTML = `<p class="text-red-500 text-xs">Spoke registry diagnostics failed: ${escapeHtml(e.message)}</p>`;
    }
}
window.loadSpokeRegistryDiag = loadSpokeRegistryDiag;

function _srdAge(s) {
    if (s === null || s === undefined) return 'never';
    if (s < 90) return s + 's ago';
    if (s < 5400) return Math.round(s / 60) + 'm ago';
    if (s < 172800) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
}

function _spokeRegistryDiagHtml(d) {
    const rows = (d && d.rows) || [];
    const brokers = (d && d.brokers) || {};
    const findings = (d && d.findings) || [];
    if (!rows.length) return `<p class="text-slate-400 italic text-xs">No spoke registrations.</p>`;

    // Elected brokers first — this is the value that flips, so it leads.
    let html = '';
    const bk = Object.keys(brokers).sort();
    if (bk.length) {
        html += `<div class="mb-4"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-2">Client-Sim broker election</p>
            <div class="space-y-1">` + bk.map(t => {
            const b = brokers[t] || {};
            const warn = b.multiple;
            return `<div class="flex items-start justify-between gap-3 text-xs p-2 rounded ${warn ? 'bg-amber-50 border border-amber-200' : 'bg-slate-50'}">
                <div><span class="font-bold text-slate-600">${escapeHtml(t)}</span>
                    <span class="text-slate-400"> → </span>
                    <span class="font-mono text-slate-700">${escapeHtml(b.elected || 'none')}</span></div>
                <div class="text-right whitespace-nowrap ${warn ? 'text-amber-700' : 'text-slate-400'}">
                    ${(b.candidates || []).length} connected candidate(s)${warn ? ' — pinned to the incumbent' : ''}</div>
            </div>`;
        }).join('') + `</div></div>`;
    }

    // Bulk-delete toolbar. Quick-selects match the two classes that actually
    // accumulate: offline leftovers from a rebuild, and pre-rename '-spoke'
    // twins. Connected spokes are never selectable — a diagnostics page must
    // not be able to tear down a running spoke.
    // Must match the per-row selectable test below, or the button offers to
    // select rows that have no checkbox. A relayed agent with liveness evidence
    // is not a leftover registration — deleting it is a different operation.
    const nOffline = rows.filter(r => !r.connected && !r.is_relayed_agent).length;
    const nTwins = rows.filter(r => r.legacy_twin_of).length;
    html += `<div class="flex flex-wrap items-center gap-2 mb-2 text-xs">
        <button type="button" onclick="srdSelect('offline')" class="px-2 py-1 rounded border border-slate-300 text-slate-600 hover:bg-slate-50" title="Select all offline spoke registrations">Select offline (${nOffline})</button>
        <button type="button" onclick="srdSelect('twins')" class="px-2 py-1 rounded border border-slate-300 text-slate-600 hover:bg-slate-50" title="Select legacy pre-rename spoke twin registrations">Select pre-rename twins (${nTwins})</button>
        <button type="button" onclick="srdSelect('none')" class="px-2 py-1 rounded border border-slate-300 text-slate-600 hover:bg-slate-50" title="Clear all selections">Clear</button>
        <span class="flex-1"></span>
        <button type="button" id="srd-del-btn" onclick="srdDeleteSelected()" disabled
                class="px-3 py-1 rounded border border-red-300 text-red-600 hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed font-bold" title="Delete selected offline spoke registrations from the registry">Delete selected (<span id="srd-del-count">0</span>)</button>
    </div>`;
    html += `<div class="overflow-x-auto"><table class="w-full text-xs">
        <thead><tr class="text-left text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-200">
            <th class="py-1 pr-2 w-6"></th>
            <th class="py-1 pr-2">Spoke</th><th class="py-1 pr-2">Type</th><th class="py-1 pr-2">Tenant</th>
            <th class="py-1 pr-2">State</th><th class="py-1 pr-2">Last seen</th><th class="py-1 pr-2 text-right">Action</th>
        </tr></thead><tbody>`;

    rows.forEach(r => {
        const badges = [];
        if (r.connected) badges.push('<span class="px-1.5 py-0.5 rounded bg-green-100 text-green-700 font-bold">connected</span>');
        else badges.push('<span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-bold">offline</span>');
        // Relayed node agent (pxmx/cs). It has no socket and no session key of
        // its OWN — it dials its parent spoke, which holds both — so "no key"
        // is normal here and must not read as a fault, and it is not a ghost
        // registration to be deleted. Without this the four pxmx agents looked
        // like leftovers an operator should clean up.
        if (r.is_relayed_agent) badges.push('<span class="px-1.5 py-0.5 rounded bg-sky-100 text-sky-700" title="Relayed node agent — reaches the hub through its parent spoke, so it has no socket or session key of its own. Liveness comes from relay traffic. NOT a leftover registration.">relayed agent</span>');
        if (!r.has_key && !r.is_relayed_agent) badges.push('<span class="px-1.5 py-0.5 rounded bg-amber-100 text-amber-700">no key</span>');
        if (r.stuck_never_keyed) badges.push('<span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-bold" title="Approved but never seen and never keyed. Approval only keys a spoke while it is connected, so clicking Approve here never makes it report in. Delete it everywhere, then approve it WHILE it is connected.">stuck — re-approve while connected</span>');
        if (!r.approved && !r.is_relayed_agent) badges.push('<span class="px-1.5 py-0.5 rounded bg-slate-200 text-slate-600">unapproved</span>');
        if (r.admin_only) badges.push('<span class="px-1.5 py-0.5 rounded bg-purple-100 text-purple-700" title="No tenant_id — hidden from a non-admin Spokes list, but still claimable as a tenant broker">hidden</span>');
        if (r.legacy_twin_of) badges.push('<span class="px-1.5 py-0.5 rounded bg-orange-100 text-orange-700" title="Same box as ' + escapeHtml(r.legacy_twin_of) + ' — registered under the pre-2026-07-20 &quot;-spoke&quot; id. Safe to delete once the twin is connected.">twin of ' + escapeHtml(r.legacy_twin_of) + '</span>');
        const del = (r.connected || r.is_relayed_agent)
            ? `<span class="text-slate-300" title="${r.is_relayed_agent ? 'Relayed agent reporting through its parent spoke — not a leftover' : 'Connected — this is a live spoke, not a leftover'}">live</span>`
            : `<button onclick="deleteSpokeRegistration('${escJsAttr(r.spoke_id)}')" class="px-2 py-0.5 rounded border border-red-300 text-red-600 hover:bg-red-50" title="Delete this spoke registration">Delete</button>`;
        const sel = (r.connected || r.is_relayed_agent) ? '' :
            `<input type="checkbox" class="srd-sel" data-twin="${r.legacy_twin_of ? '1' : '0'}" ` +
            `value="${escapeHtml(r.spoke_id)}" onchange="srdSyncCount()" title="Select this spoke registration for deletion">`;
        html += `<tr class="border-b border-slate-100 ${r.connected ? '' : 'bg-slate-50/60'}">
            <td class="py-1.5 pr-2">${sel}</td>
            <td class="py-1.5 pr-2 font-mono text-slate-700">${escapeHtml(r.spoke_id)}
                ${r.hostname ? `<span class="text-slate-400"> (${escapeHtml(r.hostname)})</span>` : ''}</td>
            <td class="py-1.5 pr-2 text-slate-500">${escapeHtml(r.module_type || '—')}</td>
            <td class="py-1.5 pr-2 text-slate-500">${escapeHtml(r.tenant_id || 'unassigned')}</td>
            <td class="py-1.5 pr-2"><div class="flex flex-wrap gap-1">${badges.join('')}</div></td>
            <td class="py-1.5 pr-2 text-slate-400 whitespace-nowrap">${escapeHtml(_srdAge(r.last_seen_age_s))}</td>
            <td class="py-1.5 pr-2 text-right whitespace-nowrap">${del}</td>
        </tr>`;
    });
    html += `</tbody></table></div>`;

    // Orphaned telemetry — cache entries with no matching registration. Kept in
    // its own block because these are NOT spokes: deleting a spoke cannot reach
    // them, so mixing them into the table above would imply the wrong action.
    const orphans = (d && d.orphan_telemetry) || [];
    if (orphans.length) {
        html += `<div class="mt-4 pt-3 border-t border-slate-200">
            <div class="flex items-center justify-between mb-1">
                <p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Orphaned telemetry (no such spoke)</p>
                <button type="button" id="srd-orph-btn" onclick="srdPurgeTelemetry()" disabled
                        class="text-xs px-3 py-1 rounded border border-red-300 text-red-600 hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed font-bold" title="Purge cached telemetry for selected nonexistent spoke IDs">Purge selected (<span id="srd-orph-count">0</span>)</button>
            </div>
            <p class="text-[10px] text-slate-400 mb-2">Cached telemetry keyed to a spoke id that no longer exists — typically an id that changed under a box. It keeps claiming the Proxmox hosts it last reported, so those hosts render under a spoke that no longer runs them. Deleting a spoke cannot remove these; purge them here.</p>
            <div class="space-y-1">` + orphans.map(o =>
            `<label class="flex items-start gap-2 text-xs p-2 rounded bg-amber-50 border border-amber-200 cursor-pointer">
                <input type="checkbox" class="srd-orph mt-0.5" value="${escapeHtml(o.spoke_id)}" onchange="srdSyncOrphCount()" title="Select orphaned telemetry entry to purge">
                <span class="flex-1"><span class="font-mono text-slate-700">${escapeHtml(o.spoke_id)}</span>
                    <span class="text-slate-400"> — tenant ${escapeHtml(o.tenant_id || 'none')}, claims ${o.host_count} host(s)</span>
                    ${(o.hosts || []).length ? `<span class="block text-slate-500 mt-0.5">${(o.hosts || []).map(escapeHtml).join(', ')}</span>` : ''}
                </span>
            </label>`).join('') + `</div></div>`;
    }

    if (findings.length) {
        html += `<div class="mt-3 pt-3 border-t border-slate-100 space-y-1">` + findings.map(f =>
            `<p class="text-[11px] text-slate-500">• ${escapeHtml(f)}</p>`).join('') + `</div>`;
    }
    return html;
}

function srdSyncOrphCount() {
    const n = Array.from(document.querySelectorAll('.srd-orph')).filter(b => b.checked).length;
    const label = document.getElementById('srd-orph-count');
    const btn = document.getElementById('srd-orph-btn');
    if (label) label.textContent = String(n);
    if (btn) btn.disabled = (n === 0);
}
window.srdSyncOrphCount = srdSyncOrphCount;

async function srdPurgeTelemetry() {
    const ids = Array.from(document.querySelectorAll('.srd-orph'))
                     .filter(b => b.checked).map(b => b.value);
    if (!ids.length) return;
    if (!confirm(`Purge cached telemetry for ${ids.length} id(s)?\n\n` + ids.join('\n')
                 + `\n\nThis drops stale cached data only — no running spoke is affected. `
                 + `The hub refuses any id that IS a registered spoke.`)) return;
    try {
        const d = await apiJson('/setup/spoke-registry-diag/purge-telemetry', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: ids }),
        });
        const refused = (d.refused || []).length
            ? ` Refused (still registered): ${(d.refused || []).join(', ')}.` : '';
        showToast(`Purged ${(d.purged || []).length} entr(ies).${refused}`,
                  (d.refused || []).length ? 'error' : 'success');
    } catch (e) {
        showToast(`Purge failed: ${e.message}`, 'error');
    }
    loadSpokeRegistryDiag();
}
window.srdPurgeTelemetry = srdPurgeTelemetry;

// ── Bulk selection / delete for the registry card ───────────────────────────
// Only offline rows carry a checkbox, so nothing here can select a running
// spoke. Deletes are issued one at a time (not Promise.all): each is a state
// mutation on the hub, and a serial loop keeps the failure report per-id
// instead of one opaque rejection.
function srdSyncCount() {
    const boxes = Array.from(document.querySelectorAll('.srd-sel'));
    const n = boxes.filter(b => b.checked).length;
    const label = document.getElementById('srd-del-count');
    const btn = document.getElementById('srd-del-btn');
    if (label) label.textContent = String(n);
    if (btn) btn.disabled = (n === 0);
}
window.srdSyncCount = srdSyncCount;

function srdSelect(which) {
    document.querySelectorAll('.srd-sel').forEach(b => {
        if (which === 'none') b.checked = false;
        else if (which === 'offline') b.checked = true;          // every box IS offline
        else if (which === 'twins') b.checked = b.dataset.twin === '1';
    });
    srdSyncCount();
}
window.srdSelect = srdSelect;

async function srdDeleteSelected() {
    const ids = Array.from(document.querySelectorAll('.srd-sel'))
                     .filter(b => b.checked).map(b => b.value);
    if (!ids.length) return;
    if (!confirm(`Delete ${ids.length} spoke registration(s)?\n\n` + ids.join('\n')
                 + `\n\nOnly do this for boxes that are gone, were rebuilt, or are a `
                 + `pre-rename twin. A box that is still running will re-register on its `
                 + `next connect.`)) return;
    const btn = document.getElementById('srd-del-btn');
    if (btn) btn.disabled = true;
    const failed = [];
    for (const id of ids) {
        try {
            await apiJson(`/setup/spokes/${encodeURIComponent(id)}`, { method: 'DELETE' });
        } catch (e) {
            failed.push(`${id}: ${e.message}`);
        }
    }
    if (failed.length) {
        showToast(`Deleted ${ids.length - failed.length}/${ids.length}. Failed: ${failed.join('; ')}`, 'error');
    } else {
        showToast(`Deleted ${ids.length} registration(s)`, 'success');
    }
    loadSpokeRegistryDiag();
}
window.srdDeleteSelected = srdDeleteSelected;

// Delete a leftover registration. Deliberately offered ONLY for offline rows —
// deleting a connected spoke would tear down a live one, and the whole point of
// this card is to remove ghosts without that risk.
async function deleteSpokeRegistration(spokeId) {
    if (!confirm(`Delete spoke registration "${spokeId}"?\n\nOnly do this if the box is gone or was rebuilt. `
                 + `If it is still running it will re-register on its next connect.`)) return;
    try {
        await apiJson(`/setup/spokes/${encodeURIComponent(spokeId)}`, { method: 'DELETE' });
        showToast(`Deleted registration ${spokeId}`, 'success');
    } catch (e) {
        showToast(`Delete failed: ${e.message}`, 'error');
    }
    loadSpokeRegistryDiag();
}
window.deleteSpokeRegistration = deleteSpokeRegistration;

// ── System → Diagnostics: the consolidated module view ───────────────────────
// Renders /setup/alert-diagnostics in full: alerts GROUPED BY PRODUCER, the
// per-alert forensics (approved? relayed agent? heartbeat? connected?), and the
// endpoint's own verdicts. This is what the footer dot links to.
window._moduleDiagLast = null;

const _MD_SOURCE_LABEL = {
    spoke_out_of_contact: 'Spokes out of contact',
    agent_out_of_contact: 'Agents out of contact',
    fleet_availability:   'Fleet availability',
};
const _MD_SOURCE_NOTE = {
    spoke_out_of_contact: 'A module spoke stopped talking to the hub.',
    agent_out_of_contact: 'A RELAYED node agent (pxmx/cs) went silent. Its parent spoke can still be perfectly healthy — nothing else reports this.',
    fleet_availability:   'Lab capacity: a degraded client fleet. Not a module being down.',
};

async function loadModuleDiagnostics() {
    const el = document.getElementById('module-diag-body');
    if (!el) return;
    let d;
    try { d = await apiJson('/setup/alert-diagnostics'); }
    catch (e) {
        el.innerHTML = `<div class="hpe-card rounded-lg p-5 shadow-sm"><p class="text-sm text-red-500">Diagnostics unavailable: ${escapeHtml(e.message || String(e))}</p></div>`;
        return;
    }
    d._fetched_at = new Date().toLocaleString();
    window._moduleDiagLast = d;

    const alerts = Array.isArray(d.alerts) ? d.alerts : [];
    const rows = Array.isArray(d.rows) ? d.rows : [];
    const findings = Array.isArray(d.findings) ? d.findings : [];
    const rowBy = {};
    rows.forEach(r => { rowBy[r.spoke_id] = r; });

    const pill = (label, n, cls) =>
        `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full ${cls} text-xs font-bold">${label} ${n}</span>`;
    const nErr = alerts.filter(a => a.tier === 'error').length;
    const nWarn = alerts.filter(a => a.tier === 'warning').length;

    // Alerts grouped by PRODUCER — the grouping is the point: "every spoke is
    // green but the dot is red" is only explicable once you can see which
    // producer fired.
    const groups = Object.keys(_MD_SOURCE_LABEL).map(src => {
        const mine = alerts.filter(a => (a.source || 'spoke_out_of_contact') === src);
        if (!mine.length) return '';
        const body = mine.map(a => {
            const r = rowBy[a.spoke_id] || {};
            const tone = a.tier === 'error' ? 'text-red-600' : 'text-amber-600';
            const forensics = [];
            if (r.is_relayed_agent) forensics.push('relayed agent');
            if (r.is_approved === false) forensics.push('NOT approved');
            if (r.is_connected) forensics.push('socket connected — alert may be stale');
            if (r.heartbeat_bare == null && (r.heartbeat_composite || []).length)
                forensics.push('heartbeat is composite-keyed only');
            return `<tr class="border-b border-slate-100 last:border-0">
                <td class="px-4 py-2 font-mono text-xs text-slate-700">${escapeHtml(a.name || a.spoke_id || '—')}</td>
                <td class="px-4 py-2 text-xs font-bold ${tone}">${escapeHtml(a.tier || '')}</td>
                <td class="px-4 py-2 text-xs text-slate-500">${escapeHtml(_durStr(a.duration_s))}</td>
                <td class="px-4 py-2 text-xs text-slate-600">${escapeHtml(a.detail || '')}</td>
                <td class="px-4 py-2 text-[11px] text-amber-700">${escapeHtml(forensics.join(' · '))}</td>
            </tr>`;
        }).join('');
        return `<div class="hpe-card rounded-lg p-5 shadow-sm">
            <p class="text-sm font-bold text-slate-500 uppercase tracking-wider">${escapeHtml(_MD_SOURCE_LABEL[src])} <span class="text-slate-400 normal-case font-normal">(${mine.length})</span></p>
            <p class="text-[11px] text-slate-400 mb-3">${escapeHtml(_MD_SOURCE_NOTE[src] || '')}</p>
            <div class="overflow-x-auto"><table class="w-full text-sm">
              <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>
                <th class="px-4 py-2 text-left font-medium">Module</th>
                <th class="px-4 py-2 text-left font-medium">Tier</th>
                <th class="px-4 py-2 text-left font-medium">For</th>
                <th class="px-4 py-2 text-left font-medium">Detail</th>
                <th class="px-4 py-2 text-left font-medium">Forensics</th>
              </tr></thead><tbody>${body}</tbody></table></div>
          </div>`;
    }).filter(Boolean).join('');

    const findingHtml = findings.length ? `<div class="hpe-card rounded-lg p-5 shadow-sm">
        <p class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Verdicts</p>
        ${findings.map(f => {
            const cls = f.severity === 'error' ? 'border-red-200 bg-red-50 text-red-700'
                      : f.severity === 'warning' ? 'border-amber-200 bg-amber-50 text-amber-700'
                      : 'border-slate-200 bg-slate-50 text-slate-600';
            return `<div class="border rounded-md p-2 mb-1.5 ${cls}">
                <div class="text-xs font-bold">${escapeHtml(f.code || '')}</div>
                <p class="text-[11px] opacity-90">${escapeHtml(f.detail || '')}</p>
                ${(f.ids || []).length ? `<p class="text-[10px] font-mono mt-1 break-all">${escapeHtml((f.ids || []).join(', '))}</p>` : ''}
            </div>`;
        }).join('')}
      </div>` : '';

    el.innerHTML = `
      <div class="hpe-card rounded-lg p-5 shadow-sm flex flex-wrap items-center gap-2">
        ${pill('Errors', nErr, nErr ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500')}
        ${pill('Warnings', nWarn, nWarn ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-500')}
        <span class="text-[11px] text-slate-400 ml-auto">as of ${escapeHtml(d._fetched_at)}</span>
      </div>
      ${alerts.length ? groups : `<div class="hpe-card rounded-lg p-5 shadow-sm"><p class="text-sm text-slate-500">No active alerts from any producer — the MODULE STATUS dot should be green.</p></div>`}
      ${findingHtml}`;
}
window.loadModuleDiagnostics = loadModuleDiagnostics;

function _durStr(s) {
    const n = Number(s || 0);
    if (!isFinite(n) || n <= 0) return '—';
    if (n < 60) return `${Math.round(n)}s`;
    if (n < 3600) return `${Math.floor(n / 60)}m`;
    if (n < 86400) return `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m`;
    return `${Math.floor(n / 86400)}d ${Math.floor((n % 86400) / 3600)}h`;
}

function copyModuleDiagnostics(btn) {
    const d = window._moduleDiagLast;
    if (!d) return;
    const L = [`LM MODULE DIAGNOSTICS — captured ${d._fetched_at}`,
               '(last FETCHED data — press Refresh for live values)', ''];
    const rowBy = {};
    (d.rows || []).forEach(r => { rowBy[r.spoke_id] = r; });
    Object.keys(_MD_SOURCE_LABEL).forEach(src => {
        const mine = (d.alerts || []).filter(a => (a.source || 'spoke_out_of_contact') === src);
        if (!mine.length) return;
        L.push(`${_MD_SOURCE_LABEL[src].toUpperCase()} (${mine.length})`);
        mine.forEach(a => {
            const r = rowBy[a.spoke_id] || {};
            L.push(`  [${a.tier}] ${a.name || a.spoke_id} — ${_durStr(a.duration_s)} — ${a.detail || ''}`);
            const f = [];
            if (r.is_relayed_agent) f.push('relayed agent');
            if (r.is_approved === false) f.push('NOT approved');
            if (r.is_connected) f.push('socket connected (alert may be stale)');
            if (f.length) L.push(`      forensics: ${f.join(' · ')}`);
        });
        L.push('');
    });
    if (!(d.alerts || []).length) L.push('No active alerts from any producer.', '');
    (d.findings || []).forEach(f =>
        L.push(`VERDICT [${f.severity}] ${f.code}: ${f.detail}` +
               ((f.ids || []).length ? `  ids=${(f.ids || []).join(',')}` : '')));
    const txt = L.join('\n');
    if (navigator.clipboard) navigator.clipboard.writeText(txt);
    if (btn) { const o = btn.textContent; btn.textContent = '✓ Copied'; setTimeout(() => { btn.textContent = o; }, 1500); }
}
window.copyModuleDiagnostics = copyModuleDiagnostics;

// Alert Diagnostics — inline card on System → Hub Status. Explains the footer
// MODULE STATUS dot: which producer raised each active alert
// (spoke out-of-contact / agent out-of-contact / fleet availability, merged into
// one list by /status), and which alerts are false positives or stale state.
// Backed by GET /setup/alert-diagnostics (core/src/routes/setup.py).
async function loadAlertDiagnostics() {
    const body = document.getElementById('alert-diag-body');
    if (!body) return;
    try {
        const d = await apiJson('/setup/alert-diagnostics');
        body.innerHTML = _alertDiagHtml(d);
    } catch (e) {
        body.innerHTML = `<p class="text-red-500 text-xs">Alert diagnostics failed: ${escapeHtml(e.message)}</p>`;
    }
}
window.loadAlertDiagnostics = loadAlertDiagnostics;

// Producer labels — the merge at setup.py get_status() is exactly what makes the
// footer tooltip's single "Out-of-contact alerts" heading misleading.
const _ALERT_SOURCE_LABEL = {
    spoke_out_of_contact: 'Spoke out-of-contact',
    fleet_availability:   'Fleet availability',
};

function _alertDiagHtml(d) {
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const cfg = d.config || {}, counts = d.counts || {}, bySrc = counts.by_source || {};
    const alerts = d.alerts || [], rows = d.spoke_alert_rows || [], findings = d.findings || [];
    const dur = s => s == null ? '—' : s >= 3600 ? `${(s/3600).toFixed(1)}h`
        : s >= 60 ? `${Math.floor(s/60)}m` : `${s}s`;
    const ago = ts => ts == null ? '—' : dur(Math.max(0, Math.floor(Date.now()/1000 - ts)));

    // Headline verdict: the dot is red iff any error-tier alert is active, and a
    // false positive means red for a fleet that is actually healthy.
    const anyErr = alerts.some(a => String(a.tier) === 'error');
    const falsePos = findings.filter(f => f.severity === 'error')
                             .reduce((n, f) => n + (f.ids || []).length, 0);
    let verdict, vClass;
    if (!alerts.length) { verdict = 'No active alerts — dot should be green'; vClass = 'bg-green-100 text-green-700'; }
    else if (falsePos)  { verdict = `Dot is RED on ${falsePos} FALSE alert(s)`; vClass = 'bg-red-100 text-red-700'; }
    else if (anyErr)    { verdict = 'Dot is RED — error-tier alert active'; vClass = 'bg-red-100 text-red-700'; }
    else                { verdict = 'Warning-tier alerts only'; vClass = 'bg-amber-100 text-amber-700'; }

    const sevClass = s => s === 'error' ? 'border-red-300 bg-red-50 text-red-700'
                                        : 'border-amber-300 bg-amber-50 text-amber-700';
    const findingHtml = findings.length ? findings.map(f => `
        <div class="border ${sevClass(f.severity)} rounded p-2 text-xs">
            <div class="font-bold uppercase tracking-wide text-[10px] mb-0.5">${esc(f.code.replace(/_/g, ' '))}</div>
            <div class="mb-1">${esc(f.detail)}</div>
            <div class="font-mono text-[11px] opacity-80">${f.ids.map(esc).join(', ')}</div>
        </div>`).join('')
        : `<p class="text-xs text-[#01A982]">No stale or false alert state detected — every active alert reflects a real condition.</p>`;

    const alertRows = alerts.length ? alerts.map(a => `
        <tr class="border-b border-slate-100">
            <td class="px-3 py-1.5 font-medium" title="${esc(a.spoke_id)}">${esc(a.name || a.spoke_id)}</td>
            <td class="px-3 py-1.5 text-xs text-slate-600">${esc(_ALERT_SOURCE_LABEL[a.source] || a.source)}</td>
            <td class="px-3 py-1.5 text-center"><span class="text-xs font-bold ${a.tier === 'error' ? 'text-red-600' : 'text-amber-600'}">${esc(a.tier)}</span></td>
            <td class="px-3 py-1.5 text-center text-xs text-slate-600">${dur(a.duration_s)}</td>
            <td class="px-3 py-1.5 text-xs text-slate-500">${esc(a.detail || '')}</td>
        </tr>`).join('')
        : `<tr><td colspan="5" class="px-3 py-3 text-slate-400 italic">No active alerts.</td></tr>`;

    // Per-spoke forensics: the exact lookups the alert loop performs, so a false
    // positive is visible as "no bare heartbeat, but a fresh composite one".
    const yn = (v, good) => `<span class="${v === good ? 'text-[#01A982]' : 'text-red-600'} font-bold">${v ? 'yes' : 'no'}</span>`;
    const forensicRows = rows.length ? rows.map(r => {
        const comp = (r.heartbeat_composite || []);
        return `<tr class="border-b border-slate-100">
            <td class="px-3 py-1.5 font-mono text-xs">${esc(r.spoke_id)}</td>
            <td class="px-3 py-1.5 text-center text-xs ${r.tier === 'error' ? 'text-red-600 font-bold' : 'text-amber-600'}">${esc(r.tier)}</td>
            <td class="px-3 py-1.5 text-center text-xs">${r.heartbeat_bare != null ? ago(r.heartbeat_bare) + ' ago' : '<span class="text-red-600">none</span>'}</td>
            <td class="px-3 py-1.5 text-center text-xs">${comp.length ? comp.map(c => `<span class="text-[#01A982]" title="${esc(c.key)}">${c.age_s}s ago</span>`).join(', ') : '—'}</td>
            <td class="px-3 py-1.5 text-center text-xs">${yn(r.is_relayed_agent, false)}</td>
            <td class="px-3 py-1.5 text-center text-xs">${yn(r.is_approved, true)}</td>
            <td class="px-3 py-1.5 text-center text-xs text-slate-500">${esc(r.latched_tier || '—')}</td>
        </tr>`;
    }).join('') : `<tr><td colspan="7" class="px-3 py-3 text-slate-400 italic">No spoke out-of-contact alerts.</td></tr>`;

    return `<div class="space-y-4">
      <div class="flex items-center justify-end">
        <span class="text-xs px-2 py-1 rounded-full ${vClass}">${esc(verdict)}</span>
      </div>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
        <div><div class="text-slate-500 text-xs">Spoke out-of-contact</div><div class="font-bold ${bySrc.spoke_out_of_contact ? 'text-red-600' : 'text-slate-800'}">${bySrc.spoke_out_of_contact || 0}</div></div>
        <div><div class="text-slate-500 text-xs">Fleet availability</div><div class="font-bold ${bySrc.fleet_availability ? 'text-red-600' : 'text-slate-800'}">${bySrc.fleet_availability || 0}</div></div>
        <div><div class="text-slate-500 text-xs">Approved · relayed agents</div><div class="font-bold text-slate-800">${counts.approved || 0} · ${counts.relay_ids || 0}</div></div>
      </div>
      <div class="space-y-2">${findingHtml}</div>
      <div class="overflow-x-auto border border-slate-200 rounded-lg">
        <table class="w-full text-sm"><thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
          <th class="px-3 py-1 text-left">Alert</th><th class="px-3 py-1 text-left">Producer</th>
          <th class="px-3 py-1 text-center">Tier</th><th class="px-3 py-1 text-center">Active</th><th class="px-3 py-1 text-left">Detail</th>
        </tr></thead><tbody>${alertRows}</tbody></table>
      </div>
      <div>
        <p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Out-of-contact lookups (per alerted id)</p>
        <div class="overflow-x-auto border border-slate-200 rounded-lg">
          <table class="w-full text-sm"><thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
            <th class="px-3 py-1 text-left">Id</th><th class="px-3 py-1 text-center">Tier</th>
            <th class="px-3 py-1 text-center" title="heartbeat.last_seen[bare_id] — what the alert loop reads">Bare heartbeat</th>
            <th class="px-3 py-1 text-center" title="heartbeat.last_seen['{parent}:{agent_id}'] — where a relayed agent actually reports">Composite heartbeat</th>
            <th class="px-3 py-1 text-center">Relayed agent</th><th class="px-3 py-1 text-center">Approved</th>
            <th class="px-3 py-1 text-center" title="_spoke_alert_tier — a latched warning/error here re-arms the alert instead of clearing it">Latched tier</th>
          </tr></thead><tbody>${forensicRows}</tbody></table>
        </div>
      </div>
      <div class="text-[11px] text-slate-500">Thresholds: warn ${dur(cfg.warn_s)} · error ${dur(cfg.error_s)} · alerting ${cfg.enabled ? 'on' : '<b class="text-amber-600">off</b>'}. <b>No bare heartbeat + a fresh composite one = a relayed node-agent that is online but alerting</b> — the loop looks up the bare id, the Agents table reads the composite key, so the two disagree.</div>
    </div>`;
}

async function showMtlsDebug() {
    const esc = (s) => escapeHtml(String(s == null ? '' : s));
    openModal('mtls-debug-modal', `<div class="p-6"><div class="text-slate-500 italic text-sm">Loading mTLS status…</div></div>`, { card: 'max-w-4xl w-full max-h-[90vh] overflow-y-auto', backdropClose: true });
    let d;
    try {
        const r = await _spokeFetch('/api/mtls/trust-diag');
        if (!r.ok) { document.querySelector('#mtls-debug-modal .p-6')?.replaceChildren(); showToast('mTLS status failed: ' + (r.detail || 'admin required'), 'error'); document.getElementById('mtls-debug-modal')?.remove(); return; }
        d = (r.data && r.data.mtls_enabled !== undefined) ? r.data : (r.data || {});
    } catch (e) { showToast('mTLS status failed: ' + (e.message || e), 'error'); document.getElementById('mtls-debug-modal')?.remove(); return; }
    const cs = d.clients_summary || {};
    const clients = d.clients || [];
    const rows = clients.length ? clients.map(c => `
        <tr class="border-b border-slate-100">
            <td class="px-3 py-1.5 font-medium" title="${esc(c.spoke_id)}">${esc(c.label || c.spoke_id)}</td>
            <td class="px-3 py-1.5">${esc(c.module_type || '—')}</td>
            <td class="px-3 py-1.5 font-bold ${c.local ? 'text-slate-400' : (c.mtls_active ? 'text-[#01A982]' : 'text-amber-600')}" title="${c.local ? 'Co-located spoke — connects over plaintext loopback (ws://127.0.0.1). No TLS leg, so mTLS does not apply. mTLS is remote-only (wss).' : (c.mtls_active ? 'Presenting a verified Hub-CA client cert' : 'Remote spoke connected without presenting a client cert — issue one')}">${c.local ? 'local · N/A' : (c.mtls_active ? 'mTLS ✓' : 'cert-less')}</td>
            <td class="px-3 py-1.5 text-xs">${c.sans && c.sans.length ? esc(c.sans.join(', ')) : '—'}${c.is_ab_pinned ? ' <span class="text-purple-700 font-bold">★ AppBuilder</span>' : ''}</td>
            <td class="px-3 py-1.5 text-xs text-slate-500">${esc(c.not_after || '')}</td>
            <td class="px-3 py-1.5 whitespace-nowrap">
                ${c.local
                  ? `<span class="text-xs text-slate-400 italic" title="mTLS is remote-only (wss). A co-located spoke on loopback has no TLS leg to present a client cert.">loopback — mTLS N/A</span>`
                  : `<button onclick="mtlsProvision('${esc(c.spoke_id)}')" class="text-xs bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-2 py-0.5 rounded font-bold" title="Issue/renew this spoke's Hub-Local-CA mTLS client cert now">issue</button>
                ${c.mtls_active ? `<button onclick="mtlsRevoke('${esc(c.spoke_id)}','${esc(c.label || c.spoke_id)}')" class="text-xs bg-red-600/10 hover:bg-red-600/20 text-red-600 border border-red-600 px-2 py-0.5 rounded font-bold ml-1" title="Revoke this spoke's mTLS client cert (it reconnects cert-less)">revoke</button>` : ''}`}
            </td>
        </tr>`).join('') : `<tr><td colspan="6" class="px-3 py-3 text-slate-400 italic">No connected spokes.</td></tr>`;
    const lmca = (d.lm_mtls_ca_certs || []).map(c => `<div>${esc(c.subject)} <span class="text-slate-400">← ${esc(c.issuer)}</span></div>`).join('') || '<div class="text-slate-400">— none —</div>';
    const pin = (d.pinned_cert_checks || []).map(p => `<div>${esc(p.domain)}: <span class="font-bold ${p.ok ? 'text-[#01A982]' : 'text-red-600'}">${p.ok ? 'accepted' : 'REJECTED'}</span> <span class="text-slate-400">${esc(p.detail || '')}</span></div>`).join('') || '<div class="text-slate-400">no cert tagged AppBuilder</div>';
    const dupes = (d.duplicate_subjects || []);
    openModal('mtls-debug-modal', `
        <div class="p-6 space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-bold text-[#263040]">🔒 mTLS status</h3>
                <span class="text-xs px-2 py-1 rounded-full ${d.mtls_enabled ? 'bg-green-100 text-green-700' : 'bg-slate-200 text-slate-600'}">${d.mtls_enabled ? 'mTLS ENABLED' : 'mTLS off'}</span>
            </div>
            <div class="flex items-center justify-between gap-2 flex-wrap">
              <div class="text-sm text-slate-600">${cs.connected ?? 0} connected · <b class="text-[#01A982]">${cs.mtls_active ?? 0}</b> presenting a verified client cert · <b class="text-slate-500">${cs.cert_less ?? 0}</b> cert-less</div>
              <div class="flex items-center gap-3">
                <label class="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer select-none" title="When ON, the hub auto-mints + delivers a Hub-Local-CA mTLS client cert to every spoke on connect (and renews 7 days before expiry). Turn OFF to manage certs manually.">
                  <input type="checkbox" id="mtls-autoprov-chk" ${d.auto_provision ? 'checked' : ''} onchange="mtlsSetAutoProvision(this.checked)" class="w-4 h-4 rounded">
                  Auto-provision
                </label>
                <button onclick="mtlsProvision('')" class="text-xs bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md font-bold whitespace-nowrap" title="Issue/renew a Hub-Local-CA mTLS client cert for EVERY connected spoke now">⟳ Provision all connected</button>
              </div>
            </div>
            <div class="text-xs text-slate-500">The hub mints each spoke's clientAuth mTLS client cert from its <b>Local CA</b> (public CAs no longer issue clientAuth) — done automatically on connect; use these buttons to (re)issue on demand.</div>
            <div class="overflow-x-auto border border-slate-200 rounded-lg">
                <table class="w-full text-sm"><thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
                    <th class="px-3 py-2 text-left">Spoke</th><th class="px-3 py-2 text-left">Type</th><th class="px-3 py-2 text-left">mTLS</th><th class="px-3 py-2 text-left">Cert SANs</th><th class="px-3 py-2 text-left">Expires</th><th class="px-3 py-2 text-left"></th>
                </tr></thead><tbody>${rows}</tbody></table>
            </div>
            <div class="text-xs text-slate-500">Note: the hub is permissive (CERT_OPTIONAL) — a "cert-less" spoke still works (session-key auth). Only AppBuilder's HUB_REQUEST channel <i>requires</i> a verified, pinned client cert.</div>
            <div class="border-t border-slate-200 pt-3">
                <div class="font-semibold text-slate-700 mb-1">Provisioned mTLS certs (registry)</div>
                <div class="text-xs text-slate-500 mb-2">All Hub-Local-CA mTLS client certs the hub has issued — including ones for spokes that are not connected right now (e.g. a replaced/orphaned box). Remove a stale entry here, or reissue it.</div>
                <div id="mtls-registry-certs" class="overflow-x-auto border border-slate-200 rounded-lg"><div class="p-3 text-slate-400 italic text-sm">Loading provisioned mTLS certs…</div></div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div><div class="font-semibold text-slate-600 mb-1">Hub client-verify CA (LM_MTLS_CA)</div><div class="font-mono text-slate-700 space-y-0.5">${lmca}</div><div class="text-slate-400 mt-1">combined bundle: ${d.combined_ca_count ?? '?'} trusted cert(s)${dupes.length ? ` · <span class="text-amber-600">dup subjects: ${esc(dupes.join(', '))}</span>` : ''}</div></div>
                <div><div class="font-semibold text-slate-600 mb-1">Pinned AppBuilder cert verify</div><div class="font-mono text-slate-700 space-y-0.5">${pin}</div></div>
            </div>
            <div id="mtls-acme-info" class="border-t border-slate-200 pt-3 text-xs text-slate-500">Loading certbot / ACME profile info…</div>
            <div class="flex justify-end"><button onclick="document.getElementById('mtls-debug-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium" title="Close dialog">Close</button></div>
        </div>`, { card: 'max-w-4xl w-full max-h-[90vh] overflow-y-auto', backdropClose: true });
    // certbot / ACME profile info (le spoke) — diagnoses "requested clientAuth but
    // got serverAuth-only": needs certbot >= 4.0 for --preferred-profile, and the
    // clientAuth-capable profile must exist + be named correctly.
    try {
        const ar = await _spokeFetch('/api/le/acme-info');
        const a = (ar.ok && ar.data) ? ar.data : {};
        const el = document.getElementById('mtls-acme-info');
        if (el) {
            if (a.available === false) { el.innerHTML = `<span class="text-amber-600">ACME info unavailable: ${esc(a.reason || a.error || '')}</span>`; }
            else {
                const profs = a.profiles || {};
                const names = Object.keys(profs);
                const profList = names.length
                    ? names.map(n => `<span class="font-mono ${/classic/i.test(n) ? 'text-[#01A982] font-bold' : 'text-slate-700'}">${esc(n)}</span> <span class="text-slate-400">${esc((profs[n] || '').slice(0, 60))}</span>`).join('<br>')
                    : '<span class="text-amber-600">CA advertises no profiles (this ACME server may not support profile selection)</span>';
                const supp = a.supports_profiles;
                el.innerHTML =
                    `<div class="font-semibold text-slate-600 mb-1">certbot / ACME profiles (le spoke)</div>` +
                    `<div>certbot: <span class="font-mono">${esc(a.certbot_version || '?')}</span> · --preferred-profile support: <b class="${supp ? 'text-[#01A982]' : 'text-red-600'}">${supp === null ? 'unknown' : (supp ? 'yes' : 'NO — certbot too old (need ≥4.0)')}</b></div>` +
                    `<div class="mt-1">clientAuth profile requested: <span class="font-mono">${esc(a.clientauth_profile || 'classic')}</span> ${names.length && !names.some(n => n === (a.clientauth_profile || 'classic')) ? '<span class="text-red-600 font-bold">← not in the CA profile list! set LM_LE_CLIENTAUTH_PROFILE to a name below</span>' : ''}</div>` +
                    `<div class="mt-1">CA (${esc(a.acme_directory || '')}) profiles:</div><div class="mt-0.5 pl-2 border-l-2 border-slate-200">${profList}</div>`;
            }
        }
    } catch (e) {
        const el = document.getElementById('mtls-acme-info');
        if (el) el.textContent = 'ACME info error: ' + (e.message || e);
    }
    // Provisioned mTLS cert registry — EVERY Hub-Local-CA client cert the hub has
    // issued, including entries for spokes that are NOT currently connected (a
    // replaced/orphaned box). This is the only place a stale registry entry can be
    // removed from the UI; the connected-spokes table above only lists live spokes.
    try {
        const rr = await _spokeFetch('/api/mtls/client-certs');
        const rel = document.getElementById('mtls-registry-certs');
        if (rel) {
            if (!rr.ok) {
                rel.innerHTML = `<div class="p-3 text-amber-600 italic text-sm">Could not load provisioned certs: ${esc(rr.detail || 'admin required')}</div>`;
            } else {
                const body = rr.data || {};
                const certs = body.certs || (body.data && body.data.certs) || [];
                const now = Date.now();
                const rrows = certs.length ? certs.map(c => {
                    const pk = (c.pk != null ? c.pk : c.spoke_id);
                    // Prefer the friendly spoke/agent name — the registry keys
                    // by spoke id, which for a GUID-keyed spoke is an opaque
                    // UUID. The raw id stays in the row's title attribute.
                    const rawId = c.spoke_id || c.pk || '';
                    const label = (rawId ? spokeDisplayName(rawId) : '') || c.subject || 'unknown';
                    const sanList = Array.isArray(c.san) ? c.san : (Array.isArray(c.sans) ? c.sans : []);
                    const sans = sanList.length ? esc(sanList.join(', ')) : '—';
                    const naStr = c.not_after || '';
                    let expired = false;
                    if (naStr) { const t = Date.parse(naStr); if (!isNaN(t) && t < now) expired = true; }
                    const statusBadge = c.connected
                        ? '<span class="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700 font-bold">connected</span>'
                        : '<span class="text-xs px-2 py-0.5 rounded-full bg-slate-200 text-slate-600 font-bold">offline</span>';
                    const expBadge = expired ? ' <span class="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700 font-bold">EXPIRED</span>' : '';
                    return `
                    <tr class="border-b border-slate-100">
                        <td class="px-3 py-1.5 font-medium" title="pk: ${esc(pk)}${c.module_type ? ' · ' + esc(c.module_type) : ''}">${esc(label)}</td>
                        <td class="px-3 py-1.5 text-xs">${sans}</td>
                        <td class="px-3 py-1.5 text-xs ${expired ? 'text-red-600 font-bold' : 'text-slate-500'}">${esc(naStr || '—')}</td>
                        <td class="px-3 py-1.5 whitespace-nowrap">${statusBadge}${expBadge}</td>
                        <td class="px-3 py-1.5 whitespace-nowrap">
                            <button onclick="mtlsProvision('${esc(pk)}')" class="text-xs bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-2 py-0.5 rounded font-bold" title="Re-issue/renew this Hub-Local-CA mTLS client cert from its registry entry">Reissue</button>
                            <button onclick="mtlsRemoveCert('${esc(pk)}','${esc(label)}')" class="text-xs bg-red-600/10 hover:bg-red-600/20 text-red-600 border border-red-600 px-2 py-0.5 rounded font-bold ml-1" title="Remove this stored mTLS cert from the hub registry — use for a stale/orphaned entry left by a replaced or reset box">Remove</button>
                        </td>
                    </tr>`;
                }).join('') : `<tr><td colspan="5" class="px-3 py-3 text-slate-400 italic">No provisioned mTLS certs.</td></tr>`;
                rel.innerHTML = `<table class="w-full text-sm"><thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
                    <th class="px-3 py-2 text-left">Spoke / ID</th><th class="px-3 py-2 text-left">SANs</th><th class="px-3 py-2 text-left">Expires</th><th class="px-3 py-2 text-left">Status</th><th class="px-3 py-2 text-left">Actions</th>
                </tr></thead><tbody>${rrows}</tbody></table>`;
            }
        }
    } catch (e) {
        const rel = document.getElementById('mtls-registry-certs');
        if (rel) rel.innerHTML = `<div class="p-3 text-amber-600 italic text-sm">Provisioned certs error: ${esc(e.message || e)}</div>`;
    }
}


// Per-cert "Renew now" — FORCES a re-issue (--force-renewal) so it works even when
// the cert isn't near expiry (a plain `certbot renew` no-ops until ~30d out).
async function leRenewCert(domain) {
    showToast(`Renewing ${domain}…`, 'info');
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/renew', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, force: true }),
        });
        if (!ok) { showToast('Renew failed: ' + (detail || ''), 'error'); return; }
        const inner = (data && data.data) ? data.data : (data || {});
        const r = (inner.renewed || [])[0] || {};
        if (r.renewed) showToast(`Renewed ${domain} — re-pushed to targets.`, 'success');
        else showToast(`Renewal did not complete for ${domain}: ${r.error || inner.message || 'unknown error'}`, 'error');
        await loadLEData();
    } catch (e) { showToast('Renew failed: ' + e.message, 'error'); }
}

async function leRenewAll() {
    const cnt = (window._leCerts || []).length;
    if (cnt === 0) { showToast('No managed certificates to renew.', 'success'); return; }
    if (!confirm(`Renew all ${cnt} managed certificate(s) now? This runs "certbot renew" for each on the le spoke and re-pushes new material to their targets.`)) return;
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/renew', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        if (!ok) { showToast('Renew all failed: ' + (detail || ''), 'error'); return; }
        const inner = (data && data.data) ? data.data : (data || {});
        const r = inner.renewed || [];
        const okN = r.filter(x => x.renewed).length;
        const failN = r.length - okN;
        let msg = `Renewed ${okN}/${r.length} certificate(s).`;
        if (failN > 0) msg += `\n${failN} failed:\n` + r.filter(x => !x.renewed).map(x => `  ${x.domain}: ${x.error || 'unknown'}`).join('\n');
        showToast(msg, 'success');
        await loadLEData();
    } catch (e) { showToast('Renew all failed: ' + e.message, 'error'); }
}

async function leRevokeCert(domain) {
    const del = confirm(`Revoke ${domain}?\n\nThis revokes the certificate with Let's Encrypt and removes it from the managed list. The certbot cert material on the le spoke is deleted.\n\nNote: revocation does NOT un-install the cert from existing distribution targets — they keep serving it until it expires. Remove the targets first if you want them to stop serving it immediately.`);
    if (!del) return;
    try {
        const { ok, detail } = await _spokeFetch('/api/le/revoke', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, delete: true }),
        });
        if (!ok) { showToast('Revoke failed: ' + (detail || ''), 'error'); return; }
        showToast(`Revoked ${domain}.`, 'success');
        await loadLEData();
    } catch (e) { showToast('Revoke failed: ' + e.message, 'error'); }
}

function editDnsRecord(name, rtype) {
    const item = (window._dnsRecords || []).find(r => r.name === name && r.type === rtype);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showDnsRecordModal(item);
}

function showDnsRecordModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selectCls = inputCls;
    const typeOpts = ['A', 'AAAA', 'CNAME', 'PTR'].map(t =>
        `<option value="${t}"${editing && editItem.type === t ? ' selected' : ''}>${t}</option>`).join('');
    const modal = openModal('dns-record-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} DNS Record</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Name</label><input id="dns-r-name" title="Fully-qualified domain name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="host.example.com" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Type</label><select id="dns-r-type" title="DNS record type (A, AAAA, CNAME, PTR)" class="${selectCls}" ${editing ? 'disabled' : ''}>${typeOpts}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Value</label><input id="dns-r-value" title="Target IP address or canonical name" value="${val(editItem?.value)}" class="${inputCls}" placeholder="10.0.1.5"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">TTL</label><input id="dns-r-ttl" title="Time to Live in seconds (minimum 60s)" type="number" min="60" value="${val(editItem?.ttl) || 300}" class="${inputCls}"></div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="saveDnsRecord()" title="Save record changes" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Add Record'}</button>
            <button onclick="document.getElementById('dns-record-modal').remove()" title="Cancel and close modal" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    if (editing) { modal.dataset.editName = editItem.name; modal.dataset.editType = editItem.type; }
}

async function saveDnsRecord() {
    const modal = document.getElementById('dns-record-modal');
    const editing = modal && modal.dataset.editName;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        name: editing ? modal.dataset.editName : get('dns-r-name'),
        type: editing ? modal.dataset.editType : get('dns-r-type'),
        value: get('dns-r-value'),
        ttl: parseInt(get('dns-r-ttl')) || 300,
    };
    if (!payload.name || !payload.value) { showToast('Name and Value are required', 'error'); return; }
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/record' + _taTenantQuery(), {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && d.status === 'SUCCESS') { modal.remove(); loadDNSData('Records'); }
        else showToast('Error: ' + (detail || d?.message || 'Operation failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

function editDnsForwarder(zone) {
    const list = window._dnsForwarders || [];
    const item = list.find(f => (f.zone || '.') === zone);
    if (item) {
        showDnsForwarderModal(item);
    }
}

function showDnsForwarderModal(editItem) {
    const isEdit = !!editItem;
    const zoneVal = isEdit ? (editItem.zone || '.') : '.';
    const upstreamsVal = isEdit && editItem.upstreams ? (Array.isArray(editItem.upstreams) ? editItem.upstreams.join(', ') : editItem.upstreams) : '';
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    openModal('dns-forwarder-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${isEdit ? 'Edit DNS Forwarder' : 'Add DNS Forwarder'}</h3>
        <div class="space-y-3">
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Zone</label>
                <input id="dns-fwd-zone" title="Forwarder zone domain (. for root/default)" value="${escapeHtml(zoneVal)}" ${isEdit ? 'readonly class="' + inputCls + ' bg-slate-50 cursor-not-allowed"' : 'class="' + inputCls + '"'} placeholder=". or example.com">
                <p class="text-xs text-slate-400">Use <span class="font-mono">.</span> to forward all non-authoritative queries.</p>
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Upstream servers</label>
                <input id="dns-fwd-upstreams" title="Comma-separated upstream DNS server IP addresses" value="${escapeHtml(upstreamsVal)}" class="${inputCls}" placeholder="1.1.1.1, 1.0.0.1">
                <p class="text-xs text-slate-400">Enter one or more IPv4 or IPv6 addresses separated by commas or spaces.</p>
            </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="saveDnsForwarder()" title="Save forwarder configuration" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">${isEdit ? 'Save Changes' : 'Add Forwarder'}</button>
            <button onclick="document.getElementById('dns-forwarder-modal').remove()" title="Cancel and close modal" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    const modal = document.getElementById('dns-forwarder-modal');
    if (modal && isEdit) {
        modal.dataset.editZone = editItem.zone || '.';
    }
}

async function saveDnsForwarder() {
    const modal = document.getElementById('dns-forwarder-modal');
    const editing = modal && modal.dataset.editZone;
    const zone = document.getElementById('dns-fwd-zone')?.value?.trim() || '.';
    const upstreams = (document.getElementById('dns-fwd-upstreams')?.value || '')
        .split(/[\s,]+/).filter(Boolean);
    if (!upstreams.length) {
        showToast('At least one upstream server is required', 'error');
        return;
    }
    const payload = { zone, upstreams };
    if (editing) {
        payload.old_zone = modal.dataset.editZone;
    }
    try {
        const { ok, data: d, detail } = await _spokeFetch(
            '/api/dns/forwarders' + _tenantQS(), {
                method: editing ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        if (ok && d.status === 'SUCCESS') {
            modal.remove();
            showToast(editing ? `Forwarder ${zone} updated.` : `Forwarder ${zone} added to all DNS servers.`, 'success');
            loadDNSData('Forwarders');
        } else {
            showToast('Error: ' + (detail || d?.message || (editing ? 'Forwarder update failed' : 'Forwarder add failed')), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function deleteDnsForwarder(zone) {
    if (!await showConfirmToast(`Delete forwarder for zone ${zone}?`)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/forwarders' + _tenantQS(), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ zone }),
        });
        if (ok && d.status === 'SUCCESS') {
            showToast(`Forwarder ${zone} deleted.`, 'success');
            loadDNSData('Forwarders');
        } else {
            showToast('Error: ' + (detail || d?.message || 'Delete forwarder failed'), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

// ── DNS override profiles (per-client answers via Unbound views) ─────────────
// An admin defines named profiles (e.g. "PAVO-DEVICE") holding custom answers
// and blocked names; a profile is then assigned to a device IP or subnet and
// every query from that client is answered from the profile first, falling
// back to normal resolution for anything the profile doesn't cover.

// Admin writes go to the picked tenant's DNS spoke; a tenant Admin must name
// an owned tenant explicitly (shared-infra write constraint).
function _dnsOverrideQS() {
    return isTenantAdmin() ? _taTenantQuery() : _tenantQS();
}

// The assignment (if any) that applies to client `ip`: an exact /32 or /128
// wins, else the longest IPv4 prefix containing it. Returns
// {target, profile, label, exact} or null.
function _dnsOverrideFor(ip) {
    const d = window._dnsOverrides;
    const value = String(ip || '').trim();
    if (!d || !value) return null;
    let best = null, bestLen = -1;
    for (const a of (d.assignments || [])) {
        const target = String(a.target || '');
        const [net, bits] = target.split('/');
        const len = parseInt(bits, 10);
        let hit = false;
        if (value.includes(':')) hit = net.toLowerCase() === value.toLowerCase() && len === 128;
        else if (!net.includes(':')) hit = _isIPInCIDR(value, target);
        if (hit && len > bestLen) { best = a; bestLen = len; }
    }
    if (!best) return null;
    return { ...best, exact: bestLen === (value.includes(':') ? 128 : 32) };
}

function _dnsOverrideRecordLines(profile) {
    return (profile.records || []).map(r =>
        `${r.name} ${r.type} ${r.value}${r.ttl && r.ttl !== 300 ? ' ' + r.ttl : ''}`).join('\n');
}

function _dnsOverridesView(d, editIcon, delIcon) {
    const admin = isAdmin();
    const canAssign = admin || isTenantAdmin();
    const profiles = d.profiles || [];
    const assignments = d.assignments || [];
    const members = d.members || [];
    const counts = {};
    assignments.forEach(a => { counts[a.profile] = (counts[a.profile] || 0) + 1; });
    const convColor = { converged: 'bg-green-100 text-green-700', drifted: 'bg-amber-100 text-amber-800',
        unreachable: 'bg-red-100 text-red-700', unknown: 'bg-slate-100 text-slate-600' };
    const memberHtml = members.length ? `<div class="flex flex-wrap gap-2 mb-4 text-xs">${members.map(m =>
        `<span class="px-2 py-1 rounded-md ${convColor[m.convergence] || convColor.unknown}" title="${escapeHtml(m.error || m.convergence)}">${escapeHtml(m.display_name || m.id)}: ${escapeHtml(m.convergence)}</span>`).join('')}</div>` : '';
    const intro = `<p class="text-sm text-slate-500 mb-3">Override profiles give chosen clients different DNS answers. Assign a profile to a device IP or a whole subnet; that client's queries are answered from the profile first and fall back to normal resolution for everything else. Apply a profile from the <b>Records</b> tab with <b>Override…</b> (to that device or its subnet), or use <b>+ Assign</b> to enter any IP or subnet.</p>`;
    const profRows = profiles.map(p => {
        const n = String(p.name).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        return `<tr class="border-b border-slate-100 hover:bg-slate-50">
            <td class="px-4 py-2 font-mono font-medium">${escapeHtml(p.name)}</td>
            <td class="px-4 py-2 text-xs text-slate-600">${escapeHtml(p.description || '')}</td>
            <td class="px-4 py-2 text-xs font-mono whitespace-pre-line">${escapeHtml((p.records || []).slice(0, 4).map(r => `${r.name} ${r.type} ${r.value}`).join('\n'))}${(p.records || []).length > 4 ? `\n… +${p.records.length - 4} more` : ''}</td>
            <td class="px-4 py-2 text-xs font-mono">${escapeHtml((p.block || []).slice(0, 4).join(', '))}${(p.block || []).length > 4 ? ` … +${p.block.length - 4}` : ''}</td>
            <td class="px-4 py-2 text-center text-xs">${counts[p.name] || 0}</td>
            <td class="px-4 py-2 whitespace-nowrap">${admin ? `
                <button onclick="editDnsOverrideProfile('${n}')" class="text-slate-400 hover:text-[#01A982] mr-2" title="Edit profile">${editIcon}</button>
                <button onclick="deleteDnsOverrideProfile('${n}')" class="text-slate-400 hover:text-red-500" title="Delete profile">${delIcon}</button>` : ''}</td>
        </tr>`;
    }).join('');
    const asgRows = assignments.map(a => {
        const t = String(a.target).replace(/'/g, "\\'");
        const removable = canAssign;
        return `<tr class="border-b border-slate-100 hover:bg-slate-50">
            <td class="px-4 py-2 font-mono">${escapeHtml(a.target)}</td>
            <td class="px-4 py-2 text-xs text-slate-600">${escapeHtml(a.label || '')}</td>
            <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800">${escapeHtml(a.profile)}</span></td>
            <td class="px-4 py-2 text-xs text-slate-600">${escapeHtml(a.comment || '')}</td>
            <td class="px-4 py-2 whitespace-nowrap">${removable ? `
                <button onclick="editDnsOverrideAssignment('${t}')" class="text-slate-400 hover:text-[#01A982] mr-2" title="Edit this override (IP/subnet, profile, label, comment)">${editIcon}</button>
                <button onclick="removeDnsOverrideAssignment('${t}')" class="text-slate-400 hover:text-red-500" title="Remove this override (client returns to normal DNS)">${delIcon}</button>` : ''}</td>
        </tr>`;
    }).join('');
    return `<div class="p-4">${intro}${memberHtml}
        <h4 class="text-sm font-bold text-[#263040] mb-2">Profiles</h4>
        ${profiles.length ? `<div class="mb-6">${tableWrap(tableHead(['Name', 'Description', 'Answers', 'Blocked', 'Clients', '']) + `<tbody>${profRows}</tbody>`)}</div>`
            : `<p class="text-sm text-slate-400 mb-6">No override profiles defined${admin ? ' — use <b>+ Add Profile</b>.' : '.'}</p>`}
        <h4 class="text-sm font-bold text-[#263040] mb-2">Assigned clients</h4>
        ${assignments.length ? tableWrap(tableHead(['Client IP / Subnet', 'Label', 'Profile', 'Comment', '']) + `<tbody>${asgRows}</tbody>`)
            : `<p class="text-sm text-slate-400">No clients have an override applied.</p>`}
        <div id="dns-override-live" class="mt-6"></div>
    </div>`;
}

// ── Live check: proof the overrides actually answer ─────────────────────────
// Each resolver reports whether every profile's view is loaded in its RUNNING
// Unbound, and the queries from assigned clients that Unbound answered (or
// blocked) from that view (its log-local-actions lines).
async function loadDnsOverrideLiveCheck(minutes) {
    const box = document.getElementById('dns-override-live');
    if (!box) return;
    const mins = minutes || parseInt(box.dataset.minutes || '60', 10);
    box.dataset.minutes = mins;
    box.innerHTML = `<h4 class="text-sm font-bold text-[#263040] mb-2">Live check</h4><p class="text-sm text-slate-400">Checking every DNS server…</p>`;
    const qs = _tenantQS();
    try {
        const { ok, data: d, detail } = await _spokeFetch(`/api/dns/overrides/verify${qs}${qs ? '&' : '?'}minutes=${mins}`);
        if (!ok || !d || d.status !== 'SUCCESS') {
            box.innerHTML = _dnsOverrideLiveView(null, mins, detail || d?.message || 'Live check unavailable');
            return;
        }
        box.innerHTML = _dnsOverrideLiveView(d, mins);
    } catch (e) {
        box.innerHTML = _dnsOverrideLiveView(null, mins, e.message);
    }
}

function _dnsOverrideLiveView(d, mins, error) {
    const windows = [[60, 'Last hour'], [1440, 'Last 24 hours'], [10080, 'Last 7 days']];
    const header = `<div class="flex items-center gap-2 mb-2">
        <h4 class="text-sm font-bold text-[#263040]">Live check</h4>
        <select onchange="loadDnsOverrideLiveCheck(parseInt(this.value, 10))" class="ml-auto border border-slate-300 rounded-md px-2 py-1 text-xs">
            ${windows.map(([v, t]) => `<option value="${v}" ${v === mins ? 'selected' : ''}>${t}</option>`).join('')}
        </select>
        <button onclick="loadDnsOverrideLiveCheck()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold">Re-check</button>
    </div>`;
    if (!d) return header + `<p class="text-sm text-red-600">${escapeHtml(error || 'Live check unavailable')}</p>`;
    const hits = d.hits || [];
    const fmt = t => escapeHtml(new Date((t || 0) * 1000).toLocaleString());
    const ok = 'bg-green-100 text-green-700', bad = 'bg-red-100 text-red-700', warn = 'bg-amber-100 text-amber-800';

    const memberRows = (d.members || []).map(m => {
        const memberHits = hits.filter(h => h.member === m.display_name).length;
        const views = !m.ok ? `<span class="px-2 py-0.5 rounded-md text-xs ${bad}" title="${escapeHtml(m.error)}">no answer: ${escapeHtml(m.error || 'unreachable')}</span>`
            : (m.views || []).map(v => v.loaded
                ? `<span class="px-2 py-0.5 rounded-md text-xs ${ok}" title="${v.answers} answer line(s) loaded in Unbound">${escapeHtml(v.profile)} ✓ loaded</span>`
                : `<span class="px-2 py-0.5 rounded-md text-xs ${bad}" title="${escapeHtml(v.error)}">${escapeHtml(v.profile)} ✗ not loaded</span>`).join(' ') || '<span class="text-xs text-slate-400">no profiles</span>';
        const logging = !m.ok ? '' : m.log_local_actions === true ? `<span class="px-2 py-0.5 rounded-md text-xs ${ok}">on</span>`
            : m.log_local_actions === false ? `<span class="px-2 py-0.5 rounded-md text-xs ${warn}" title="Turns on automatically with the next override push to this server">off</span>`
            : '<span class="text-xs text-slate-400">unknown</span>';
        return `<tr class="border-b border-slate-100">
            <td class="px-4 py-2 text-sm font-medium">${escapeHtml(m.display_name)}</td>
            <td class="px-4 py-2">${views}</td>
            <td class="px-4 py-2">${logging}</td>
            <td class="px-4 py-2 text-center text-xs">${m.ok ? memberHits : ''}</td>
        </tr>`;
    }).join('');

    const perTarget = {};
    hits.forEach(h => {
        const a = _dnsOverrideFor(h.client);
        if (!a) return;
        const row = perTarget[a.target] || (perTarget[a.target] = { count: 0, last: 0 });
        row.count += 1;
        row.last = Math.max(row.last, h.time || 0);
    });
    const clientRows = (d.assignments || []).map(a => {
        const r = perTarget[a.target];
        return `<tr class="border-b border-slate-100">
            <td class="px-4 py-2 font-mono text-sm">${escapeHtml(a.target)}</td>
            <td class="px-4 py-2 text-xs text-slate-600">${escapeHtml(a.label || '')}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(a.profile)}</td>
            <td class="px-4 py-2">${r ? `<span class="px-2 py-0.5 rounded-md text-xs ${ok}">${r.count} override answer(s)</span>`
                : '<span class="px-2 py-0.5 rounded-md text-xs bg-slate-100 text-slate-600" title="This client has not queried a name in its profile in this window">no overridden queries</span>'}</td>
            <td class="px-4 py-2 text-xs text-slate-500">${r ? fmt(r.last) : ''}</td>
        </tr>`;
    }).join('');

    const hitRows = hits.slice(0, 100).map(h => `<tr class="border-b border-slate-100">
            <td class="px-4 py-2 text-xs whitespace-nowrap">${fmt(h.time)}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(h.member)}</td>
            <td class="px-4 py-2 font-mono text-xs">${escapeHtml(h.client)}</td>
            <td class="px-4 py-2 font-mono text-xs">${escapeHtml(h.name)}</td>
            <td class="px-4 py-2 text-xs">${escapeHtml(h.type)}</td>
            <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-md text-xs ${h.action === 'blocked' ? bad : ok}">${h.action === 'blocked' ? 'Blocked' : 'Override answer'}</span></td>
            <td class="px-4 py-2 text-xs">${escapeHtml(h.profile)}</td>
        </tr>`).join('');

    return header + `<p class="text-xs text-slate-500 mb-2">Asks every DNS server whether each profile is loaded in its running Unbound, and which assigned clients were answered from their override (Unbound logs every local answer with the client IP).</p>
        <div class="mb-4">${tableWrap(tableHead(['DNS server', 'Profiles in Unbound', 'Answer logging', 'Override answers']) + `<tbody>${memberRows}</tbody>`)}</div>
        ${clientRows ? `<div class="mb-4">${tableWrap(tableHead(['Client IP / Subnet', 'Label', 'Profile', 'Status', 'Last override answer']) + `<tbody>${clientRows}</tbody>`)}</div>` : ''}
        ${hits.length ? tableWrap(tableHead(['Time', 'DNS server', 'Client', 'Name', 'Type', 'Result', 'Profile']) + `<tbody>${hitRows}</tbody>`)
            : '<p class="text-sm text-slate-400">No assigned client queried a name in its profile in this window.</p>'}`;
}

function editDnsOverrideProfile(name) {
    const p = ((window._dnsOverrides || {}).profiles || []).find(x => x.name === name);
    if (p) showDnsOverrideProfileModal(p);
}

function showDnsOverrideProfileModal(editItem) {
    const isEdit = !!editItem;
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    openModal('dns-override-profile-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${isEdit ? 'Edit Override Profile' : 'Add Override Profile'}</h3>
        <div class="space-y-3">
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Name</label>
                <input id="dns-ovp-name" class="${inputCls}" value="${escapeHtml(isEdit ? editItem.name : '')}" placeholder="PAVO-DEVICE" title="Letters, digits, '-', '_' or '.' (max 48)">
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Description</label>
                <input id="dns-ovp-desc" class="${inputCls}" value="${escapeHtml(isEdit ? (editItem.description || '') : '')}" placeholder="What clients with this profile see">
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Answers</label>
                <textarea id="dns-ovp-records" rows="6" class="${inputCls} font-mono text-xs" placeholder="api.example.com A 10.1.2.3&#10;*.cdn.example.com A 10.1.2.4 60&#10;portal.example.com CNAME lab.example.net">${escapeHtml(isEdit ? _dnsOverrideRecordLines(editItem) : '')}</textarea>
                <p class="text-xs text-slate-400">One per line: <span class="font-mono">name TYPE value [ttl]</span>. TYPE is A, AAAA or CNAME. <span class="font-mono">*.zone</span> answers every name under that zone.</p>
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Blocked names</label>
                <textarea id="dns-ovp-block" rows="3" class="${inputCls} font-mono text-xs" placeholder="telemetry.example.com&#10;*.ads.example.net">${escapeHtml(isEdit ? (editItem.block || []).join('\n') : '')}</textarea>
                <p class="text-xs text-slate-400">One per line; these return NXDOMAIN (including every name below them).</p>
            </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="saveDnsOverrideProfile()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">${isEdit ? 'Save Changes' : 'Add Profile'}</button>
            <button onclick="document.getElementById('dns-override-profile-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>`, { card: 'w-full max-w-xl p-6 space-y-4 max-h-[90vh] overflow-y-auto' });
    const modal = document.getElementById('dns-override-profile-modal');
    if (modal && isEdit) modal.dataset.editName = editItem.name;
}

// "name TYPE value [ttl]" lines -> record objects; throws on a malformed line.
function _parseDnsOverrideRecords(text) {
    const out = [];
    String(text || '').split('\n').forEach((raw, i) => {
        const line = raw.replace(/#.*/, '').trim();
        if (!line) return;
        const parts = line.split(/\s+/);
        if (parts.length < 3 || parts.length > 4) throw new Error(`Answers line ${i + 1}: expected "name TYPE value [ttl]"`);
        const rec = { name: parts[0], type: parts[1].toUpperCase(), value: parts[2] };
        if (parts[3] !== undefined) rec.ttl = parseInt(parts[3], 10);
        out.push(rec);
    });
    return out;
}

async function saveDnsOverrideProfile() {
    const modal = document.getElementById('dns-override-profile-modal');
    const editing = modal && modal.dataset.editName;
    let records;
    try { records = _parseDnsOverrideRecords(document.getElementById('dns-ovp-records')?.value); }
    catch (e) { showToast(e.message, 'error'); return; }
    const profile = {
        name: (document.getElementById('dns-ovp-name')?.value || '').trim(),
        description: (document.getElementById('dns-ovp-desc')?.value || '').trim(),
        records,
        block: (document.getElementById('dns-ovp-block')?.value || '').split('\n').map(x => x.replace(/#.*/, '').trim()).filter(Boolean),
    };
    if (!profile.name) { showToast('Profile name is required', 'error'); return; }
    const payload = { profile };
    if (editing) payload.old_name = editing;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/overrides/profile' + _tenantQS(), {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
        });
        if (ok && (d.status === 'SUCCESS' || d.status === 'PARTIAL')) {
            modal.remove();
            showToast(d.status === 'PARTIAL' ? `Profile ${profile.name} saved; offline DNS servers will catch up when they reconnect.` : `Profile ${profile.name} saved.`, d.status === 'PARTIAL' ? 'warning' : 'success');
            loadDNSData('Overrides');
        } else {
            showToast('Error: ' + (detail || d?.message || 'Saving profile failed'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteDnsOverrideProfile(name) {
    const inUse = ((window._dnsOverrides || {}).assignments || []).filter(a => a.profile === name).length;
    const msg = inUse ? `Delete profile ${name}? It is applied to ${inUse} client(s); they return to normal DNS.` : `Delete profile ${name}?`;
    if (!await showConfirmToast(msg)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/overrides/profile' + _tenantQS(), {
            method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, force: inUse > 0 }),
        });
        if (ok && (d.status === 'SUCCESS' || d.status === 'PARTIAL')) { showToast(`Profile ${name} deleted.`, 'success'); loadDNSData('Overrides'); }
        else showToast('Error: ' + (detail || d?.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// The default subnet offered for a device IP: its /24 (IPv4) or /64 (IPv6).
function _dnsOverrideDefaultSubnet(ip) {
    const v = String(ip || '').trim();
    if (v.includes(':')) return `${v}/64`;
    const o = v.split('.');
    return o.length === 4 ? `${o[0]}.${o[1]}.${o[2]}.0/24` : v;
}

// The existing assignment whose target is exactly `target` (IP or CIDR), or null.
function _dnsOverrideExact(target) {
    let t = String(target || '').trim().toLowerCase();
    if (t && !t.includes('/')) t += t.includes(':') ? '/128' : '/32';
    return ((window._dnsOverrides || {}).assignments || []).find(a => String(a.target).toLowerCase() === t) || null;
}

// Record-row modal: switch the target between the device IP and a subnet.
function _dnsOverrideScopeChanged() {
    const modal = document.getElementById('dns-override-assign-modal');
    const input = document.getElementById('dns-ova-target');
    if (!modal || !input) return;
    const subnet = document.getElementById('dns-ova-scope')?.value === 'subnet';
    const ip = modal.dataset.deviceIp || '';
    input.value = subnet ? _dnsOverrideDefaultSubnet(ip) : ip;
    input.readOnly = !subnet;
    input.classList.toggle('bg-slate-50', !subnet);
    input.classList.toggle('cursor-not-allowed', !subnet);
    const existing = _dnsOverrideExact(input.value);
    const sel = document.getElementById('dns-ova-profile');
    if (sel) sel.value = existing ? existing.profile : '';
    const label = document.getElementById('dns-ova-label');
    if (label) label.value = existing ? (existing.label || '') : (subnet ? '' : modal.dataset.deviceLabel || '');
    const comment = document.getElementById('dns-ova-comment');
    if (comment) comment.value = existing ? (existing.comment || '') : '';
}

function editDnsOverrideAssignment(target) {
    const a = ((window._dnsOverrides || {}).assignments || []).find(x => x.target === target);
    if (a) showDnsOverrideAssignModal({ target: a.target, label: a.label, comment: a.comment, profile: a.profile, edit: true });
}

// Assign modal. `preset` = {target, label, lock} when launched from a record row;
// there the target starts as the device IP and can be switched to a subnet.
// `preset.edit` (from the Overrides tab) edits an existing assignment in place.
function showDnsOverrideAssignModal(preset) {
    const d = window._dnsOverrides || {};
    const profiles = d.profiles || [];
    if (!profiles.length) { showToast('No override profiles are defined yet' + (isAdmin() ? ' — add one first.' : '. Ask a Global Admin to create one.'), 'error'); return; }
    const p = preset || {};
    const current = p.target ? _dnsOverrideFor(p.target) : null;
    const currentProfile = p.profile || (current && current.exact ? current.profile : '');
    const currentComment = p.edit ? (p.comment || '') : (current && current.exact ? (current.comment || '') : '');
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const opts = (p.lock ? [`<option value="">None (normal DNS)</option>`] : [])
        .concat(profiles.map(x => `<option value="${escapeHtml(x.name)}" ${x.name === currentProfile ? 'selected' : ''}>${escapeHtml(x.name)}${x.description ? ' — ' + escapeHtml(x.description) : ''}</option>`)).join('');
    const scopeHtml = p.lock ? `
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Apply to</label>
                <select id="dns-ova-scope" onchange="_dnsOverrideScopeChanged()" class="${inputCls}">
                    <option value="device">This device only (${escapeHtml(p.target || '')})</option>
                    <option value="subnet">A subnet</option>
                </select>
            </div>` : '';
    openModal('dns-override-assign-modal', `
        <h3 class="text-lg font-bold text-[#263040]">${p.edit ? 'Edit DNS Override' : 'DNS Override'}</h3>
        <div class="space-y-3">${scopeHtml}
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Client IP or subnet</label>
                <input id="dns-ova-target" value="${escapeHtml(p.target || '')}" ${p.lock ? 'readonly' : ''} class="${inputCls}${p.lock ? ' bg-slate-50 cursor-not-allowed' : ''}" placeholder="10.1.2.3 or 10.1.2.0/24" title="A single IP, or a subnet in CIDR form (e.g. 10.1.2.0/24)${isAdmin() ? '' : ' inside your tenant\'s subnets'}">
                ${current && !current.exact ? `<p class="text-xs text-amber-700">Currently inherits <b>${escapeHtml(current.profile)}</b> from ${escapeHtml(current.target)}. A device assignment takes precedence.</p>` : ''}
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Profile</label>
                <select id="dns-ova-profile" class="${inputCls}">${opts}</select>
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Label</label>
                <input id="dns-ova-label" value="${escapeHtml(p.label || '')}" class="${inputCls}" placeholder="Device name (optional)">
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Comment</label>
                <input id="dns-ova-comment" value="${escapeHtml(currentComment)}" maxlength="500" class="${inputCls}" placeholder="Why this override exists (optional)">
            </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
            <button onclick="saveDnsOverrideAssignment()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold">${p.edit ? 'Save Changes' : 'Apply'}</button>
            <button onclick="document.getElementById('dns-override-assign-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>`, { card: 'w-full max-w-md p-6 space-y-4' });
    const modal = document.getElementById('dns-override-assign-modal');
    if (modal) {
        modal.dataset.returnTab = p.lock ? 'Records' : 'Overrides';
        modal.dataset.deviceIp = p.lock ? (p.target || '') : '';
        modal.dataset.deviceLabel = p.lock ? (p.label || '') : '';
        modal.dataset.editTarget = p.edit ? p.target : '';
    }
}

function dnsOverrideForRecord(idx) {
    const r = (window._dnsRecords || [])[idx];
    if (!r) return;
    showDnsOverrideAssignModal({ target: r.value, label: r.name, lock: true });
}

async function saveDnsOverrideAssignment() {
    const modal = document.getElementById('dns-override-assign-modal');
    const target = (document.getElementById('dns-ova-target')?.value || '').trim();
    const profile = document.getElementById('dns-ova-profile')?.value || '';
    const label = (document.getElementById('dns-ova-label')?.value || '').trim();
    const comment = (document.getElementById('dns-ova-comment')?.value || '').trim();
    const oldTarget = (modal && modal.dataset.editTarget) || '';
    const tab = (modal && modal.dataset.returnTab) || 'Overrides';
    if (!target) { showToast('Client IP or subnet is required', 'error'); return; }
    if (!profile && !_dnsOverrideExact(target)) { modal.remove(); return; }
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/override-assignment' + _dnsOverrideQS(), {
            method: profile ? 'POST' : 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(profile ? { target, profile, label, comment, ...(oldTarget ? { old_target: oldTarget } : {}) } : { target }),
        });
        if (ok && (d.status === 'SUCCESS' || d.status === 'PARTIAL')) {
            modal.remove();
            showToast(profile ? `${target} now uses ${profile}.` : `Override removed from ${target}.`, 'success');
            loadDNSData(tab);
        } else {
            showToast('Error: ' + (detail || d?.message || 'Override failed'), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function removeDnsOverrideAssignment(target) {
    if (!await showConfirmToast(`Remove the DNS override from ${target}?`)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/override-assignment' + _dnsOverrideQS(), {
            method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }),
        });
        if (ok && (d.status === 'SUCCESS' || d.status === 'PARTIAL')) { showToast(`Override removed from ${target}.`, 'success'); loadDNSData('Overrides'); }
        else showToast('Error: ' + (detail || d?.message || 'Remove failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteDnsRecord(name, rtype) {
    if (!await showConfirmToast(`Delete DNS record ${name} (${rtype})?`)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/record' + _taTenantQuery(), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, type: rtype }),
        });
        if (ok && d.status === 'SUCCESS') loadDNSData('Records');
        else showToast('Error: ' + (detail || d?.message || 'Delete failed'), 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}
