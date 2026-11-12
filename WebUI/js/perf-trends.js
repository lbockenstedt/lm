// Shared performance trend charts: Storage → Performance (nw.js) and
// Firewalls → Overview (views/firewall-overview.js). Rows are 5-minute
// averages [{ts, metrics}] from a spoke's 7-day history; perfTrendChart draws
// one SVG line chart, perfRangeBar is the History time-range selector (1h…7d
// presets or a custom start/end). A classic script, so the ES-module views
// call these page-level functions too.

// Chart state for the hover read-out, by chart id.
const _perfTrends = {};

// Escape text for markup built in this file.
function _perfEsc(text) {
    return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// SVG line chart of rows between t0 and t1 (epoch seconds), one line per
// {key, label, color}; fmt formats a value. A gap of more than one bucket
// breaks the line. Call perfTrendWire on the container to enable hovering.
function perfTrendChart(id, title, rows, lines, fmt, t0, t1) {
    const W = 720, H = 150, B = 16;
    const legend = lines.map(l => `<span class="inline-flex items-center gap-1 mr-3"><span class="inline-block w-3 h-0.5" style="background:${l.color}"></span>${_perfEsc(l.label)}</span>`).join('');
    const head = `<div class="flex justify-between text-xs text-slate-500 mb-1"><span><span class="font-medium text-slate-700 mr-3">${_perfEsc(title)}</span>${legend}</span><span id="${id}-read" class="font-mono"></span></div>`;
    if (!rows.length) {
        return `<div class="rounded-md border border-slate-200 bg-white p-3">${head}<div class="text-xs text-slate-400 italic py-8 text-center">No data for this range. The spoke records a 5-minute average every 5 minutes.</div></div>`;
    }
    let max = 0;
    rows.forEach(r => lines.forEach(l => { const v = r.metrics[l.key]; if (typeof v === 'number' && v > max) max = v; }));
    max = max || 1;
    const x = ts => (ts - t0) / (t1 - t0) * W;
    const y = v => (H - B) - v / max * (H - B - 14);
    const paths = lines.map(l => {
        let d = '', prev = null;
        rows.forEach(r => {
            const v = r.metrics[l.key];
            if (typeof v !== 'number') { prev = null; return; }
            d += `${prev === null || r.ts - prev > 600 ? 'M' : 'L'}${x(r.ts).toFixed(1)},${y(v).toFixed(1)}`;
            prev = r.ts;
        });
        return `<path d="${d}" fill="none" stroke="${l.color}" stroke-width="1.2" vector-effect="non-scaling-stroke"/>`;
    }).join('');
    // Gridlines spaced to suit the range: days for long ranges, else hours.
    const span = t1 - t0;
    const step = span > 3 * 86400 ? 86400 : span > 86400 ? 21600 : span > 6 * 3600 ? 10800 : span > 2 * 3600 ? 3600 : 900;
    const label = t => step >= 86400
        ? new Date(t * 1000).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })
        : new Date(t * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    let ticks = '';
    const first = new Date(t0 * 1000); first.setMinutes(0, 0, 0);
    if (step >= 86400) first.setHours(0);
    for (let t = first.getTime() / 1000; t < t1; t += step) {
        if (t <= t0) continue;
        const tx = x(t).toFixed(1);
        ticks += `<line x1="${tx}" x2="${tx}" y1="0" y2="${H - B}" stroke="#e2e8f0"/><text x="${tx}" y="${H - 3}" font-size="10" fill="#64748b" text-anchor="middle">${label(t)}</text>`;
    }
    _perfTrends[id] = { rows, lines, fmt, t0, t1, W };
    return `<div class="rounded-md border border-slate-200 bg-white p-3">${head}
        <svg viewBox="0 0 ${W} ${H}" class="w-full" data-perf-chart="${id}">
            <line x1="0" x2="${W}" y1="${H - B}" y2="${H - B}" stroke="#cbd5e1"/>${ticks}
            <text x="2" y="10" font-size="10" fill="#64748b">${_perfEsc(fmt(max))}</text>${paths}
            <line id="${id}-cursor" x1="-1" x2="-1" y1="0" y2="${H - B}" stroke="#94a3b8" stroke-dasharray="3 3"/>
        </svg></div>`;
}

// Show the values of the bucket under the mouse (evt null clears the read-out).
function _perfTrendHover(evt, id) {
    const c = _perfTrends[id];
    const read = document.getElementById(`${id}-read`);
    const cursor = document.getElementById(`${id}-cursor`);
    if (!c || !read || !cursor) return;
    if (!evt) { read.textContent = ''; cursor.setAttribute('x1', -1); cursor.setAttribute('x2', -1); return; }
    const box = evt.currentTarget.getBoundingClientRect();
    const ts = c.t0 + (evt.clientX - box.left) / box.width * (c.t1 - c.t0);
    // Nearest bucket.
    let lo = 0, hi = c.rows.length - 1;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (c.rows[mid].ts < ts) lo = mid + 1; else hi = mid; }
    if (lo > 0 && ts - c.rows[lo - 1].ts < c.rows[lo].ts - ts) lo--;
    const r = c.rows[lo];
    const cx = ((r.ts - c.t0) / (c.t1 - c.t0) * c.W).toFixed(1);
    cursor.setAttribute('x1', cx); cursor.setAttribute('x2', cx);
    const when = new Date(r.ts * 1000).toLocaleString(undefined, { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    read.textContent = `${when} · ` + c.lines.map(l => `${l.label} ${typeof r.metrics[l.key] === 'number' ? c.fmt(r.metrics[l.key]) : '—'}`).join(' · ');
}

// Enable the hover read-out on every chart inside root.
function perfTrendWire(root) {
    root.querySelectorAll('[data-perf-chart]').forEach(svg => {
        svg.addEventListener('mousemove', e => _perfTrendHover(e, svg.dataset.perfChart));
        svg.addEventListener('mouseleave', () => _perfTrendHover(null, svg.dataset.perfChart));
    });
}

// The History range selector. prefix names its inputs (`${prefix}-range-start`);
// range is the current {preset: seconds} or {start, end}.
function perfRangeBar(prefix, range) {
    const button = (value, text) => `<button data-perf-range="${value}">${text}</button>`;
    const local = t => new Date(t * 1000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    const now = Date.now() / 1000;
    return `<div class="flex flex-wrap items-center gap-2 text-xs" data-perf-range-bar="${prefix}">
        <span class="text-slate-500 mr-1">History (5-minute averages):</span>
        ${button(3600, '1h')}${button(21600, '6h')}${button(86400, '24h')}${button(259200, '3d')}${button(604800, '7d')}
        <span class="ml-3 text-slate-500">or</span>
        <input id="${prefix}-range-start" type="datetime-local" class="border border-slate-300 rounded px-1 py-0.5" value="${local(range.start || now - 86400)}">
        <span class="text-slate-500">to</span>
        <input id="${prefix}-range-end" type="datetime-local" class="border border-slate-300 rounded px-1 py-0.5" value="${local(range.end || now)}">
        ${button('custom', 'Show')}
    </div>`;
}

// Wire the selector built by perfRangeBar(prefix): a click calls onPick with
// the new range ({preset} or {start, end}); a custom end before its start is refused.
function perfRangeWire(root, prefix, onPick) {
    const bar = root.querySelector(`[data-perf-range-bar="${prefix}"]`);
    if (!bar) return;
    bar.querySelectorAll('[data-perf-range]').forEach(b => b.addEventListener('click', () => {
        if (b.dataset.perfRange !== 'custom') { onPick({ preset: Number(b.dataset.perfRange) }); return; }
        const st = Date.parse(document.getElementById(`${prefix}-range-start`).value);
        const en = Date.parse(document.getElementById(`${prefix}-range-end`).value);
        if (!isFinite(st) || !isFinite(en) || en <= st) { showToast('Pick a start before the end', 'error'); return; }
        onPick({ start: st / 1000, end: en / 1000 });
    }));
}

// Highlight the selected button and return the window to draw: {t0, t1, qs}.
// qs is '' (no query: the hub's default) when the range is defaultPreset.
function perfRangeWindow(prefix, range, defaultPreset) {
    const now = Date.now() / 1000;
    const t1 = range.preset ? now : range.end;
    const t0 = range.preset ? now - range.preset : range.start;
    document.querySelectorAll(`[data-perf-range-bar="${prefix}"] [data-perf-range]`).forEach(b => {
        const on = String(range.preset || 'custom') === b.dataset.perfRange;
        b.className = `px-2 py-1 rounded ${on ? 'bg-emerald-600 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`;
    });
    const qs = range.preset === defaultPreset ? '' : `?start=${Math.floor(t0)}&end=${Math.ceil(t1)}`;
    return { t0, t1, qs };
}
