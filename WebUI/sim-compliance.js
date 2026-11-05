// Simulations → Dashboard compliance views (leadership reporting).
// Compliance = % of graded polls where a check was OK (no-data polls excluded),
// from GET /sim/api/aggregate/compliance. Three candidate layouts, each its own
// Dashboard tab, so the best parts can be kept and the rest removed:
//   Compliance          — scorecard: week / month / quarter / year + 12-month trend
//   Compliance by Check — per check: 24h hourly bar, flaps, 24h/7d/30d/90d/1y
//   Compliance Heatmap  — checks × last 12 months
// Depends on sim-views.js helpers (csFetch, csTenant, csSet, csSetToolbar,
// csEscape, csEmpty), so it must load after sim-views.js.

const CS_COMPLIANCE_WINDOWS = [['d7', 'Week', '7 days'], ['d30', 'Month', '30 days'],
                               ['d90', 'Quarter', '90 days'], ['y1', 'Year', '365 days']];

async function csComplianceLoad() {
    csSetToolbar('');
    const data = await csFetch(`/aggregate/compliance?tenant_id=${csTenant()}`);
    if (!data || !Array.isArray(data.checks)) {
        csSet(csEmpty('Compliance data is unavailable.', 'Try again in a minute.'));
        return null;
    }
    if (!data.checks.length) {
        csSet(csEmpty('No check history yet.', 'Compliance appears once checks have been polled.'));
        return null;
    }
    return data;
}

// Text colour for a compliance % (≥99 green, ≥95 amber, else red).
function csCompColor(v) {
    if (v === null || v === undefined) return 'text-slate-300';
    return v >= 99 ? 'text-emerald-600' : (v >= 95 ? 'text-amber-600' : 'text-red-500');
}

// Background colour for a heatmap / bar cell.
function csCompBg(v) {
    if (v === null || v === undefined) return 'bg-slate-100 text-slate-400';
    return v >= 99 ? 'bg-emerald-500 text-white' : (v >= 95 ? 'bg-amber-400 text-white' : 'bg-red-500 text-white');
}

function csCompPct(v, cls = 'text-xs font-semibold') {
    if (v === null || v === undefined) return '<span class="text-slate-300">—</span>';
    return `<span class="${csCompColor(v)} ${cls}">${v}%</span>`;
}

// "▲ 0.4 pts" vs the previous period; empty when either side is unknown.
function csCompDelta(cur, prev) {
    if (cur === null || cur === undefined || prev === null || prev === undefined) {
        return '<span class="text-slate-400">no previous period yet</span>';
    }
    const d = Math.round((cur - prev) * 10) / 10;
    if (d === 0) return '<span class="text-slate-500">no change vs previous</span>';
    const up = d > 0;
    return `<span class="${up ? 'text-emerald-600' : 'text-red-500'}">${up ? '▲' : '▼'} ${Math.abs(d)} pts vs previous</span>`;
}

function csCompMonthLabel(m) {
    const [y, mo] = m.split('-');
    const names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${names[Number(mo) - 1]} ${y.slice(2)}`;
}

function csCompSinceNote(data) {
    if (!data.since) return '';
    const since = new Date(data.since * 1000).toISOString().slice(0, 10);
    return `<p class="text-xs text-slate-400">History starts ${since}; longer periods fill in as data accumulates.
      Compliance = share of polls where the check was OK (polls with no data are left out). Months and quarters are UTC calendar periods.</p>`;
}

function csCompProductTag(c) {
    return c.product ? `<span class="text-[10px] uppercase tracking-wider text-slate-400 mr-1">${csEscape(c.product)}</span>` : '';
}

// ── Option A: scorecard ─────────────────────────────────────────────────────
async function csRenderCompliance() {
    const data = await csComplianceLoad();
    if (!data) return;
    const cards = CS_COMPLIANCE_WINDOWS.map(([k, label, span]) => {
        const o = data.overall[k] || {};
        const cover = o.days ? `based on ${o.days} day${o.days === 1 ? '' : 's'} of data` : 'no data';
        return `<div class="bg-white border border-slate-200 rounded-lg p-4">
          <div class="text-xs uppercase tracking-wider text-slate-500 font-semibold">${label} <span class="normal-case font-normal">· last ${span}</span></div>
          <div class="mt-1">${csCompPct(o.pct, 'text-3xl font-bold')}</div>
          <div class="text-xs mt-1">${csCompDelta(o.pct, o.prev)}</div>
          <div class="text-[11px] text-slate-400 mt-1">${cover}</div>
        </div>`;
    }).join('');
    // Vertical bar per month; height = compliance %.
    const bars = data.months.map(m => {
        const h = m.pct === null ? 0 : Math.max(2, m.pct);
        return `<div class="flex flex-col items-center flex-1 min-w-0" title="${csCompMonthLabel(m.m)}: ${m.pct === null ? 'no data' : m.pct + '% (' + m.ok + ' of ' + m.graded + ' polls OK)'}">
          <div class="text-[10px] ${csCompColor(m.pct)} font-semibold h-4">${m.pct === null ? '' : m.pct + '%'}</div>
          <div class="w-full h-32 flex items-end"><div class="w-full rounded-t ${csCompBg(m.pct).split(' ')[0]}" style="height:${h}%"></div></div>
          <div class="text-[10px] text-slate-500 mt-1">${csCompMonthLabel(m.m)}</div>
        </div>`;
    }).join('');
    const quarters = data.quarters.map(q => `<div class="bg-white border border-slate-200 rounded-lg p-3 text-center">
        <div class="text-xs text-slate-500 font-semibold">${csEscape(q.q)}</div>
        <div class="mt-1">${csCompPct(q.pct, 'text-xl font-bold')}</div></div>`).join('');
    const worst = data.checks.filter(c => c.d30 !== null && c.d30 < 99).slice(0, 5)
        .map(c => `<li class="flex justify-between py-1 border-b border-slate-100"><span class="font-mono text-xs">${csCompProductTag(c)}${csEscape(c.check)}</span>${csCompPct(c.d30)}</li>`).join('');
    csSet(`<div class="space-y-5">
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">${cards}</div>
      <div class="bg-white border border-slate-200 rounded-lg p-4">
        <div class="text-sm font-semibold text-slate-700 mb-2">Last 12 months</div>
        <div class="flex gap-2 items-end">${bars}</div>
      </div>
      <div><div class="text-sm font-semibold text-slate-700 mb-2">Quarters</div><div class="grid grid-cols-4 gap-3">${quarters}</div></div>
      <div class="bg-white border border-slate-200 rounded-lg p-4">
        <div class="text-sm font-semibold text-slate-700 mb-1">Below 99% this month</div>
        ${worst ? `<ul>${worst}</ul>` : '<div class="text-xs text-slate-400">Every check is at or above 99% over the last 30 days.</div>'}
      </div>
      ${csCompSinceNote(data)}
    </div>`);
}

// ── Option B: by check ──────────────────────────────────────────────────────
// One cell per hour: green all OK, amber mixed (flapping), red mostly failing, grey no data.
function csCompHourBar(hours) {
    if (!hours || !hours.length) return '<span class="text-[11px] text-slate-400">daily data only</span>';
    return `<div class="flex gap-px">${hours.map(c => {
        const bad = c.w + c.e;
        const graded = c.o + bad;
        let cls = 'bg-slate-200';
        if (graded && !bad) cls = 'bg-emerald-500';
        else if (graded && bad * 2 >= graded) cls = 'bg-red-500';
        else if (graded) cls = 'bg-amber-400';
        const t = new Date(c.h * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return `<div class="w-2 h-4 rounded-sm ${cls}" title="${t} — OK ${c.o}, warning ${c.w}, error ${c.e}"></div>`;
    }).join('')}</div>`;
}

function csCompFlaps(n) {
    if (n === null || n === undefined) return '<span class="text-slate-300">—</span>';
    const cls = n >= 3 ? 'text-amber-600 font-bold' : (n ? 'text-slate-700' : 'text-slate-400');
    return `<span class="${cls} text-xs" title="Status changes between consecutive polls in the last 24 hours">${n}</span>`;
}

async function csRenderComplianceByCheck() {
    const data = await csComplianceLoad();
    if (!data) return;
    const cols = ['h24', 'd7', 'd30', 'd90', 'y1'];
    const o = data.overall;
    const overall = `<tr class="bg-slate-50 font-semibold">
      <td class="px-3 py-2 text-sm">Overall</td><td class="px-3 py-2"></td><td class="px-3 py-2"></td>
      <td class="px-3 py-2 text-right"></td>
      ${['d7', 'd30', 'd90', 'y1'].map(k => `<td class="px-3 py-2 text-right">${csCompPct((o[k] || {}).pct)}</td>`).join('')}
    </tr>`;
    const rows = data.checks.map(c => `<tr class="border-t border-slate-100">
      <td class="px-3 py-2 font-mono text-xs">${csCompProductTag(c)}${csEscape(c.check)}
        <div class="text-[10px] text-slate-400">${c.sites} site${c.sites === 1 ? '' : 's'}</div></td>
      <td class="px-3 py-2">${csCompHourBar(c.hours)}</td>
      <td class="px-3 py-2 text-right">${csCompFlaps(c.flaps)}</td>
      ${cols.map(k => `<td class="px-3 py-2 text-right">${csCompPct(c[k])}</td>`).join('')}
    </tr>`).join('');
    const th = h => `<th class="px-3 py-2 text-left font-semibold">${h}</th>`;
    const thr = h => `<th class="px-3 py-2 text-right font-semibold">${h}</th>`;
    csSet(`<div class="space-y-3">
      <div class="overflow-x-auto bg-white border border-slate-200 rounded-lg">
        <table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wider text-slate-500 bg-slate-50">
            <tr>${th('Check')}${th('Last 24 hours')}${thr('Flaps')}${thr('24h')}${thr('7d')}${thr('30d')}${thr('90d')}${thr('1y')}</tr>
          </thead>
          <tbody>${overall}${rows}</tbody>
        </table>
      </div>
      <p class="text-xs text-slate-500"><span class="inline-block w-2 h-3 bg-emerald-500 rounded-sm"></span> all OK
        &nbsp;<span class="inline-block w-2 h-3 bg-amber-400 rounded-sm"></span> mixed (flapping)
        &nbsp;<span class="inline-block w-2 h-3 bg-red-500 rounded-sm"></span> mostly failing
        &nbsp;<span class="inline-block w-2 h-3 bg-slate-200 rounded-sm"></span> no data</p>
      ${csCompSinceNote(data)}
    </div>`);
}

// ── Option C: heatmap ───────────────────────────────────────────────────────
async function csRenderComplianceHeatmap() {
    const data = await csComplianceLoad();
    if (!data) return;
    const cell = v => `<td class="p-0.5"><div class="${csCompBg(v)} rounded text-[11px] font-semibold text-center py-1.5 min-w-[3.25rem]">${v === null || v === undefined ? '—' : v + '%'}</div></td>`;
    const head = data.months.map(m => `<th class="px-1 py-2 text-center font-semibold">${csCompMonthLabel(m.m)}</th>`).join('');
    const overall = `<tr><td class="px-3 py-1 text-sm font-semibold">Overall</td>${data.months.map(m => cell(m.pct)).join('')}${cell((data.overall.y1 || {}).pct)}</tr>`;
    const rows = data.checks.map(c => `<tr><td class="px-3 py-1 font-mono text-xs whitespace-nowrap">${csCompProductTag(c)}${csEscape(c.check)}</td>${c.months.map(cell).join('')}${cell(c.y1)}</tr>`).join('');
    csSet(`<div class="space-y-3">
      <div class="overflow-x-auto bg-white border border-slate-200 rounded-lg p-2">
        <table class="text-sm">
          <thead class="text-xs uppercase tracking-wider text-slate-500"><tr><th class="px-3 py-2 text-left font-semibold">Check</th>${head}<th class="px-1 py-2 text-center font-semibold">Year</th></tr></thead>
          <tbody>${overall}<tr><td colspan="${data.months.length + 2}" class="h-2"></td></tr>${rows}</tbody>
        </table>
      </div>
      <p class="text-xs text-slate-500"><span class="inline-block w-3 h-3 bg-emerald-500 rounded-sm"></span> ≥ 99%
        &nbsp;<span class="inline-block w-3 h-3 bg-amber-400 rounded-sm"></span> 95–99%
        &nbsp;<span class="inline-block w-3 h-3 bg-red-500 rounded-sm"></span> &lt; 95%
        &nbsp;<span class="inline-block w-3 h-3 bg-slate-100 border border-slate-200 rounded-sm"></span> no data</p>
      ${csCompSinceNote(data)}
    </div>`);
}

window.CS_CHILD_RENDERERS['Dashboard::Compliance'] = csRenderCompliance;
window.CS_CHILD_RENDERERS['Dashboard::Compliance by Check'] = csRenderComplianceByCheck;
window.CS_CHILD_RENDERERS['Dashboard::Compliance Heatmap'] = csRenderComplianceHeatmap;
