// time-window.js — shared "Time window" picker for Overview pages whose
// counters the hub can window (/api/dns/stats, /api/dhcp/stats take
// ?range=hour|day|week|month). Each page keeps its own remembered choice.

const TIME_WINDOWS = { hour: 'last hour', day: 'last day', week: 'last week', month: 'last month' };

// The remembered window for a page ('dns_stats' -> localStorage lm_dns_stats_range).
function timeWindowChoice(page) {
    let v = '';
    try { v = localStorage.getItem(`lm_${page}_range`) || ''; } catch (_) { /* private mode */ }
    return Object.prototype.hasOwnProperty.call(TIME_WINDOWS, v) ? v : 'day';
}

// "&range=…" or "?range=…", depending on whether the URL already has a query.
function timeWindowQS(url, range) {
    return url + (url.includes('?') ? '&' : '?') + 'range=' + encodeURIComponent(range);
}

// Seconds as "N minutes", "N hours" or "N days".
function timeWindowDuration(seconds) {
    const s = Math.max(0, Number(seconds) || 0);
    if (s >= 86400) return `${Math.round(s / 86400 * 10) / 10} days`;
    if (s >= 3600) return `${Math.round(s / 3600 * 10) / 10} hours`;
    return `${Math.max(1, Math.round(s / 60))} minutes`;
}

// The <select> HTML. `id` must be unique on the page; wire it with timeWindowBind.
// `title` is a constant tooltip from the calling page, never user data.
function timeWindowPicker(id, selected, title) {
    const options = Object.entries(TIME_WINDOWS)
        .map(([v, l]) => `<option value="${v}"${v === selected ? ' selected' : ''}>${l.replace('last', 'Last')}</option>`)
        .join('');
    return `<div class="flex items-center justify-end gap-2 mb-3">
            <label for="${id}" class="text-xs text-slate-500">Time window</label>
            <select id="${id}" title="${title || ''}"
                    class="text-xs border border-slate-300 rounded-md px-2 py-1 focus:outline-none focus:ring-1 focus:ring-blue-400">
                ${options}
            </select>
        </div>`;
}

// Remember the new choice and reload the page when the picker changes.
function timeWindowBind(id, page, reload) {
    const select = document.getElementById(id);
    if (!select) return;
    select.addEventListener('change', () => {
        try { localStorage.setItem(`lm_${page}_range`, select.value); } catch (_) { /* private mode */ }
        reload();
    });
}

// A note when the reply's `window` does not cover the whole range: missing
// (server too old to window) or partial (history still filling in). `server`
// names one node ("resolver"), `service` the daemon whose start resets totals.
function timeWindowNote(win, range, server, service) {
    if (!win) {
        return `<div class="text-xs text-amber-600 mb-3">This ${server} does not support time windows yet — counters below are totals since ${service} last started.</div>`;
    }
    if (!win.partial) return '';
    const older = win.unsupported_members
        ? ` (${win.unsupported_members} ${server}(s) on an older version report totals since start)` : '';
    return `<div class="text-xs text-amber-600 mb-3">Counter history covers only the last ${timeWindowDuration(win.covered_seconds)}${older} — the ${TIME_WINDOWS[range]} view fills in as snapshots accumulate.</div>`;
}
