/* Public status page renderer. Dependency-free (the box may be isolated).
 * Fetches /api/status (public) + /api/clients (auth-seam) and renders a
 * cloud-provider-style status page with 90-day uptime bars, plus a Clients tab
 * whose demo dropdown triggers a 2h auto-reverting simulation. */
'use strict';

var TONE = { operational: 'op', degraded: 'deg', down: 'down', nodata: 'nodata' };
var BANNER_TEXT = { op: 'All Systems Operational', deg: 'Partial Degradation', down: 'Major Outage' };
var _clientTick = null;

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function tone(status) { return TONE[String(status || '').toLowerCase()] || 'deg'; }

function showTab(which) {
  document.getElementById('tab-status').classList.toggle('active', which === 'status');
  document.getElementById('tab-clients').classList.toggle('active', which === 'clients');
  document.getElementById('view-status').classList.toggle('hidden', which !== 'status');
  document.getElementById('view-clients').classList.toggle('hidden', which !== 'clients');
  if (which === 'clients') loadClients();
}

/* ── Status view ─────────────────────────────────────────────────────────── */
async function loadStatus() {
  var data;
  try {
    var r = await fetch('/api/status', { cache: 'no-store' });
    data = await r.json();
  } catch (e) { return; }

  document.getElementById('tenant-name').textContent =
    (data.tenant_name ? data.tenant_name + ' — ' : '') + 'Simulation Status';
  if (data.generated_at) {
    var ago = Math.max(0, Math.round(Date.now() / 1000 - data.generated_at));
    document.getElementById('updated').textContent = 'Updated ' + (ago < 60 ? ago + 's' : Math.round(ago / 60) + 'm') + ' ago';
  }

  var t = tone(data.overall);
  var banner = document.getElementById('banner');
  banner.className = 'banner ' + t;
  document.getElementById('banner-text').textContent = BANNER_TEXT[t] || 'Status Unknown';

  var uptime = data.uptime || {};
  var comps = data.components || [];
  var host = document.getElementById('components');
  if (!comps.length) { host.innerHTML = '<div class="row"><span class="detail">No components reported yet.</span></div>'; return; }

  host.innerHTML = comps.map(function (c) {
    var ct = tone(c.status);
    var bars = '';
    var u = uptime[c.name];
    if (u && u.series) {
      bars = '<div class="bars">' + u.series.map(function (s) {
        return '<span class="tick ' + tone(s) + '" title="' + esc(s) + '"></span>';
      }).join('') + '</div>' +
        '<div class="barmeta"><span>90 days ago</span>' +
        '<span>' + (u.uptime_pct != null ? u.uptime_pct + '% uptime' : '') + '</span>' +
        '<span>Today</span></div>';
    }
    return '<div class="row"><div class="head"><span class="name">' + esc(c.name) + '</span>' +
      '<span class="pill ' + ct + '">' + esc(pillLabel(c.status)) + '</span></div>' +
      (c.detail ? '<div class="detail">' + esc(c.detail) + '</div>' : '') + bars + '</div>';
  }).join('');
}

function pillLabel(status) {
  var t = tone(status);
  return t === 'op' ? 'Operational' : t === 'down' ? 'Down' : 'Degraded';
}

/* ── Clients view (auth seam) ────────────────────────────────────────────── */
async function loadClients() {
  var data;
  try {
    var r = await fetch('/api/clients', { cache: 'no-store' });
    if (r.status === 401 || r.status === 403) {
      document.getElementById('clients-body').innerHTML =
        '<tr><td colspan="4" class="detail">Sign-in required to view clients.</td></tr>';
      return;
    }
    data = await r.json();
  } catch (e) { return; }

  var clients = data.clients || [];
  var scenarios = Object.keys(data.scenarios || { normal: 1 });
  if (scenarios.indexOf('normal') === -1) scenarios.unshift('normal');

  var body = document.getElementById('clients-body');
  if (!clients.length) { body.innerHTML = '<tr><td colspan="4" class="detail">No clients.</td></tr>'; return; }

  body.innerHTML = clients.map(function (c) {
    var host = esc(c.name || c.hostname || '');
    var st = tone(c.status === 'up' ? 'operational' : (c.status || 'down'));
    var active = c.demo_active;
    var lastSeen = lastSeenCell(c.last_seen_secs);
    var demoCell;
    if (active && active.scenario && active.scenario !== 'normal') {
      demoCell = '<span class="bolt">⚡</span> ' + esc(active.scenario) +
        ' <span class="countdown" data-exp="' + (active.expires_at || 0) + '">' +
        fmtCountdown(active.expires_in) + '</span>';
    } else {
      var opts = scenarios.map(function (s) { return '<option value="' + esc(s) + '">' + esc(s) + '</option>'; }).join('');
      demoCell = '<select id="sc-' + host + '">' + opts + '</select> ' +
        '<button class="run" onclick="runDemo(\'' + host.replace(/'/g, "\\'") + '\')">Run</button>';
    }
    return '<tr class="' + (active && active.scenario && active.scenario !== 'normal' ? 'demo-active' : '') + '">' +
      '<td>' + host + '</td>' +
      '<td><span class="pill ' + st + '">' + (c.status === 'up' ? 'Up' : 'Down') + '</span></td>' +
      '<td>' + lastSeen + '</td>' +
      '<td>' + demoCell + '</td></tr>';
  }).join('');
}

function lastSeenCell(secs) {
  if (secs == null) return '<span class="last-ok">—</span>';
  var mins = Math.round(secs / 60);
  var cls = mins > 30 ? 'last-stale' : 'last-ok';
  var label = mins < 1 ? 'just now' : mins + ' min ago';
  return '<span class="' + cls + '">' + label + '</span>';
}

function fmtCountdown(secs) {
  if (secs == null || secs < 0) return '';
  var m = Math.floor(secs / 60), s = Math.floor(secs % 60);
  return m + ':' + (s < 10 ? '0' : '') + s;
}

async function runDemo(hostname) {
  var sel = document.getElementById('sc-' + hostname);
  var scenario = sel ? sel.value : 'normal';
  try {
    await fetch('/api/demo', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname: hostname, scenario: scenario })
    });
  } catch (e) { /* ignore — reconcile on next snapshot */ }
  // Optimistic: reload the clients view shortly (hub reflects it on next push).
  setTimeout(loadClients, 1500);
}

/* Tick any live demo countdowns down each second (client-side estimate;
 * reconciled by the next /api/clients fetch). */
function startClientTick() {
  if (_clientTick) return;
  _clientTick = setInterval(function () {
    document.querySelectorAll('.countdown[data-exp]').forEach(function (el) {
      var exp = Number(el.getAttribute('data-exp')) || 0;
      if (!exp) return;
      el.textContent = fmtCountdown(exp - Date.now() / 1000);
    });
  }, 1000);
}

loadStatus();
startClientTick();
setInterval(loadStatus, 15000);
setInterval(function () {
  if (!document.getElementById('view-clients').classList.contains('hidden')) loadClients();
}, 15000);
