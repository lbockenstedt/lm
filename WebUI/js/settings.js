// settings.js — Settings and Setup tiles (incl. OS Updates, backups, LDAP, SSO, notifications, Azure).
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

function _renderSettingsSection(subMenu) {
    const content = document.getElementById('settings-content');
    if (!content) return;
    const card = 'hpe-card rounded-lg shadow-sm overflow-hidden';

    // General / User Access / Tenant Config moved here from Setup — reuse the
    // existing render branches (which target the passed container, so they
    // render into settings-content when invoked from the System view).
    if (subMenu === 'General' || subMenu === 'User Access' || subMenu === 'Tenant Config') {
        _renderSetupSection(subMenu, content);
        return;
    }

    // Sync moved here from Setup — the unified cross-system sync-schedule tile
    // (IPAM↔NAC, VM sync, firewall/NW discovery→IPAM, staleness, source-of-truth).
    // _renderSetupSyncTile renders into the passed container and self-loads its
    // source/config/status data, so it works unchanged from the System view.
    if (subMenu === 'Sync') {
        _renderSetupSyncTile(content);
        return;
    }

    // Self-Backup: scheduled hub-state backup (local rotated archive + optional
    // SSH copy). Global-Admin-only (the /setup/backup/* routes are admin-gated
    // server-side). _renderSetupSelfBackupTile renders into the passed
    // container and self-loads its config/status.
    if (subMenu === 'Self-Backup') {
        _renderSetupSelfBackupTile(content);
        return;
    }

    // System → Icons: reference gallery of the left-nav icon set (image + ID +
    // name), sourced from LM_NAV_ICONS.
    if (subMenu === 'Icons') {
        _renderSettingsIconsTile(content);
        return;
    }

    // Cloud — one primary tab; the second-tier strip (VIEW_CHILDREN.settings.Cloud)
    // is one tab per cloud provider (Azure, OCI), each with its own THIRD tier
    // of integrations (VIEW_GRANDCHILDREN.settings.Cloud) — currentSubChild is
    // the provider, currentSubGrandchild is the specific tile.
    if (subMenu === 'Cloud') {
        const provider = ['Azure', 'OCI'].includes(currentSubChild) ? currentSubChild : 'Azure';
        const gkids = (VIEW_GRANDCHILDREN.settings.Cloud[provider] || []);
        const tile = gkids.includes(currentSubGrandchild) ? currentSubGrandchild : gkids[0];
        if (provider === 'Azure') {
            if (tile === 'NSG') _renderSettingsAzureNsgTile(content);
            else if (tile === 'Cloud NAC') _renderSettingsCloudNacTile(content);
            else if (tile === 'Vault') _renderSettingsKeyVaultTile(content);
            else if (tile === 'NetBox SSO') _renderSettingsNetboxSsoTile(content);
            else _renderSettingsSsoTile(content);
        } else {  // OCI
            if (tile === 'Vault') _renderSettingsOciVaultTile(content);
            else _renderSettingsOciNsgTile(content);
        }
        return;
    }

    // Collab — Teams/Zoom/WebEx traffic-sim management. Hub runs a passive UDP
    // sink (lm-collab-sink); cs clients send raw UDP to it over the wired/USB
    // path. This tile manages which apps are enabled + the default bandwidth and
    // applies the firewall alias/allow rule via the existing firewall endpoints.
    if (subMenu === 'Collab') {
        _renderCollabTile(content);
        return;
    }

    // Notifications — platform-level email alerts (spoke out-of-contact, etc.).
    // Provider dropdown (Azure ACS / Gmail / Yahoo / Office 365 / Generic); ACS
    // defaults to the REST API transport with SMTP fallback, creds auto-pulled
    // from Key Vault. Other providers use SMTP with Fernet-encrypted-at-rest
    // passwords. Admin-only (/setup/notifications is admin-gated server-side).
    if (subMenu === 'Notifications') {
        _renderSettingsNotificationsTile(content);
        return;
    }

    // ── System → Diagnostics ────────────────────────────────────────────────
    // The single place the footer MODULE STATUS dot points at. That dot merges
    // several producers (spoke out-of-contact, agent out-of-contact, fleet
    // availability) and Spokes & Agents rendered only some
    // of them — so clicking through from a red dot could show a page of green
    // spokes and no explanation. Everything the dot can represent is here, with
    // the per-alert forensics that say whether it is real.
    if (subMenu === 'Diagnostics') {
        content.innerHTML = `
            <div class="space-y-4">
                <div class="${card} p-5 flex flex-wrap items-center gap-3">
                    <div>
                        <p class="text-lg font-bold text-[#263040]">Module Diagnostics</p>
                        <p class="text-[11px] text-slate-400">Every producer behind the footer MODULE STATUS dot, with the evidence for each alert.</p>
                    </div>
                    <div class="ml-auto flex items-center gap-2">
                        <button onclick="copyModuleDiagnostics(this)" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-xs font-bold" title="Copy every alert + finding as plain text for a ticket or chat">⧉ Copy all</button>
                        <button onclick="loadModuleDiagnostics()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50">↻ Refresh</button>
                    </div>
                </div>
                <div id="service-cluster-summary"></div>
                <div id="module-diag-body"><p class="text-slate-400 italic text-xs">Loading…</p></div>
            </div>`;
        loadModuleDiagnostics();
        loadServiceClusterSummary();
        return;
    }

    if (subMenu === 'Hub Status') {
        content.innerHTML = `
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">CPU</p><div id="sys-cpu" class="text-2xl font-bold text-slate-700 mt-1">—</div></div>
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Memory</p><div id="sys-mem" class="text-2xl font-bold text-slate-700 mt-1">—</div></div>
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Disk</p><div id="sys-disk" class="text-2xl font-bold text-slate-700 mt-1">—</div></div>
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Throughput</p><div id="sys-throughput" class="text-2xl font-bold text-slate-700 mt-1">—</div></div>
                </div>
                <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Msg/s</p><div id="sys-mps" class="text-xl font-bold text-slate-700 mt-1">—</div></div>
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Queue Depth</p><div id="sys-queue" class="text-xl font-bold text-slate-700 mt-1">—</div></div>
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Backlog</p><div id="sys-backlog" class="text-xl font-bold text-slate-700 mt-1">—</div></div>
                    <div class="${card} p-6"><p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Rate-Limit Drops</p><div id="sys-rate-drops" class="text-xl font-bold text-slate-700 mt-1">—</div></div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center">
                        <div>
                            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hub Service ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                            <p class="text-[10px] text-slate-400 mt-1">Restart <code>lm.service</code> to load freshly-pulled code. Use after an update when a new endpoint returns <b>405 Method Not Allowed</b> — the running process is still the old code until it cycles. Spokes reconnect automatically; this page reloads in a few seconds.</p>
                        </div>
                        <button onclick="restartHubService()" id="restart-hub-btn" class="text-xs px-3 py-1 rounded-md border border-amber-300 text-amber-700 hover:bg-amber-50 transition-all whitespace-nowrap" title="Restart the hub service (lm.service) now">♻️ Restart hub service</button>
                    </div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-3">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hub Health &amp; Connectivity ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <button onclick="loadHubHealthCard()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Event-loop lag + per-spoke transport (RTT / write-buffer) — diagnoses fleet-wide WS backpressure (1011 drops): saturated hub loop vs network path (hub is in Azure)">↻ Refresh</button>
                    </div>
                    <div id="hub-health-body"><p class="text-slate-400 italic text-xs">Loading…</p></div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-1">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Alert Diagnostics ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <button onclick="loadAlertDiagnostics()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Why the footer MODULE STATUS dot is red — which producer raised each alert, and whether any are false positives">↻ Refresh</button>
                    </div>
                    <p class="text-[10px] text-slate-400 mb-3">The footer <b>MODULE STATUS</b> dot turns red on <b>any</b> active error-tier alert, and that badge merges multiple producers — spoke out-of-contact, agent out-of-contact, and fleet availability. Every spoke green while the dot is red is therefore not a contradiction. This card names the producer behind each alert and flags the ones that are stale or false.</p>
                    <div id="alert-diag-body"><p class="text-slate-400 italic text-xs">Loading…</p></div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-1">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spoke Registry Diagnostics ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <button onclick="loadSpokeRegistryDiag()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Every spoke registration the hub holds — including ones a tenant view hides — plus which one is elected as each tenant's Client-Sim broker">↻ Refresh</button>
                    </div>
                    <p class="text-[10px] text-slate-400 mb-3">A rebuilt spoke that was never deregistered leaves its <b>old id</b> behind, still tenant-bound and still electable. The Client-Sim broker is now <b>sticky</b>: it holds until the elected spoke stops being connected/approved/bound, so a spoke that reconnects no longer reassigns it. Before that, election was <code>bound[0]</code> over the connected set, and one flapping spoke moved the broker fleet-wide — the same host logging a different <code>cs_spoke</code>, quota re-pushes never converging. Registrations with <b>no tenant</b> are hidden from a non-admin Spokes list yet can still be claimed as a tenant's broker, which is why deleting everything visible does not always fix it.</p>
                    <div id="spoke-registry-diag-body"><p class="text-slate-400 italic text-xs">Loading…</p></div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-3">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Message Backlog &amp; Rate Limiting ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div class="flex items-center gap-2">
                            <button onclick="resetRateLimitDrops()" id="reset-drops-btn" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Zero the rate-limit drop counters">Reset Drops</button>
                            <button onclick="dropHubBacklog()" id="drop-backlog-btn" class="text-xs px-3 py-1 rounded-md border border-red-300 text-red-600 hover:bg-red-50 transition-all">Drop Backlog</button>
                        </div>
                    </div>
                    <div id="sys-backlog-detail" class="text-xs text-slate-500 space-y-2"><p class="text-slate-400 italic">Loading…</p></div>
                    <div class="mt-4 pt-3 border-t border-slate-100">
                        <p class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-2">Rate Limit (per spoke)</p>
                        <div class="flex flex-wrap items-end gap-3">
                            <label class="text-xs text-slate-500">Burst (capacity)<br>
                                <input type="number" id="rl-capacity" min="1" step="1" class="mt-1 w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                            <label class="text-xs text-slate-500">Refill (msg/s)<br>
                                <input type="number" id="rl-fillrate" min="0.1" step="0.1" class="mt-1 w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        </div>
                        <p class="text-[10px] text-slate-400 mt-2">Applies to each spoke on its next (re)connect. Raise both for relay spokes hosting many agents / at scale.</p>
                    </div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-1">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Backpressure Tuning ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div class="flex justify-end items-center gap-2">
                            <button onclick="resetBackpressureConfig()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Restore recommended defaults (not yet saved)">Reset Defaults</button>
                        </div>
                    </div>
                    <p class="text-[10px] text-slate-400 mb-3">How hard the hub throttles spokes as it heats up. Applies LIVE (each 1s tick). Lower CPU marks + higher max slow-down = more aggressive (keeps CPU out of protect, telemetry gets staler while throttled).</p>
                    <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs text-slate-500">
                        <label>Fleet slow-down at CPU %<br><input type="number" id="bp-fleet-cpu-soft" min="1" max="100" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Max slow-down at CPU %<br><input type="number" id="bp-fleet-cpu-hard" min="1" max="100" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Release below CPU %<br><input type="number" id="bp-fleet-cpu-clear" min="1" max="100" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Slow-down min (s)<br><input type="number" id="bp-coalesce-min" min="0.5" step="0.5" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Slow-down max (s)<br><input type="number" id="bp-coalesce-max" min="1" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Release dwell (s)<br><input type="number" id="bp-release-dwell" min="0" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Offender mark (msg/s)<br><input type="number" id="bp-per-spoke-soft" min="1" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label title="Fleet mode throttles only spokes at or above this rate — quiet spokes (real infra) are never touched">Throttle only above (msg/s)<br><input type="number" id="bp-fleet-min" min="0" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label title="Under protect, shed/disconnect only spokes at or above this rate (surgical + source shed floor)">Protect shed above (msg/s)<br><input type="number" id="bp-protect-shed-min" min="1" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label title="Max spokes disconnected per tick under protect (source-shed)">Protect shed top-K<br><input type="number" id="bp-protect-shed-topk" min="1" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label title="How long a signalled spoke may keep flooding before disconnect+quarantine (needs DDoS disconnect on)">DDoS grace (s)<br><input type="number" id="bp-ddos-grace" min="1" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label class="flex items-end gap-2 pb-1"><input type="checkbox" id="bp-ddos-disconnect" class="w-4 h-4 accent-green-600"> DDoS disconnect<br>flooders</label>
                    </div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-1">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider flex items-center gap-2">Update / Maintenance Window ${helpIcon('lm-hub', null, 'Hub help')}<span id="ug-watchdog-pill" class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-slate-100 text-slate-500 normal-case">watchdog …</span></h3>
                        <div class="flex justify-end items-center gap-2">
                            <button onclick="resetUpdateGateConfig()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Restore defaults (02:00 window)">Reset Defaults</button>
                        </div>
                    </div>
                    <p class="text-[10px] text-slate-400 mb-3">When AUTO-updates <b>apply</b>. The hub pulls new code anytime; the restart into it is held for this window so it never interrupts logged-in users. The footer <b>Update</b> button bypasses this and restarts immediately. <span id="ug-watchdog-status" class="font-mono ml-1"></span></p>
                    <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs text-slate-500">
                        <label>Apply auto-updates<br>
                            <select id="ug-mode" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="window">Only in the daily window (default)</option>
                                <option value="idle_window">When no users online — else the daily window</option>
                                <option value="idle">Only when no users online</option>
                                <option value="immediate">Immediately</option>
                            </select></label>
                        <label>Window start hour (0–23)<br><input type="number" id="ug-window-hour" min="0" max="23" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Window length (hours)<br><input type="number" id="ug-window-duration" min="1" max="24" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label title="IANA zone the window hour is in (e.g. America/Chicago). Blank = the hub's system clock, which is usually UTC.">Window timezone<br><input type="text" id="ug-timezone" placeholder="hub clock (UTC)" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                    </div>
                    <div class="flex justify-end mt-3"><button id="ug-save-btn" onclick="saveUpdateGateConfig()" class="text-xs px-3 py-1 rounded-md bg-green-600 text-white hover:bg-green-700 transition-all">Save</button></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="${card} p-6">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Spokes (<span id="spoke-count">0</span>) ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div id="spoke-list" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                    </div>
                    <div class="${card} p-6">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Agents (<span id="agent-count">0</span>) ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div id="agent-list" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                    </div>
                </div>
                <div class="${card} p-6">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Mutual TLS (Hub ⇄ Spoke ⇄ Agent)</h3>
                    <p class="text-xs text-slate-400 mb-3">Every leg is TLS-encrypted. Mutual authentication (client-cert verification) is <b>off by default</b>.</p>
                    <p class="text-xs text-slate-400 mb-3"><b>Why optional (chicken-and-egg):</b> mTLS needs the LE wildcard + CA on the hub <i>and</i> on every spoke, but spokes receive those materials <i>through</i> their hub connection. The fleet must first come up without mTLS, the hub distributes the wildcard + CA, then mTLS can be switched on — there's no way to start already pinned to mTLS.</p>
                    <p class="text-xs text-amber-600 mb-3"><b>Don't enable too early:</b> a spoke that doesn't yet hold the wildcard + CA can't authenticate and is <b>orphaned</b> — and can't be fixed through the hub (manual on-box recovery). Use <b>Auto-provision</b> (or wait for every per-spoke dot below to turn green) before flipping Enable. Enabling mTLS also doesn't by itself verify the hub's cert — set <b>LM_HUB_TLS_VERIFY=1</b> (or serve a publicly-trusted cert) to close the dial-time hop too.</p>
                    <div id="mtls-readiness" class="flex items-center gap-3 mb-3 text-sm text-slate-500">Checking readiness…</div>
                    <div id="mtls-spokes" class="mb-3 hidden"></div>
                    <div class="flex items-center gap-3 mb-3 pb-3 border-b border-slate-100">
                        <label class="flex items-center gap-2 text-sm text-slate-600">
                            <input type="checkbox" id="mtls-auto-provision" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                            Auto-provision mTLS
                        </label>
                        <button onclick="saveMtlsAutoProvision(this)" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-1.5 rounded-md text-xs font-bold transition-all shadow-sm ml-auto">Save</button>
                        <span id="mtls-auto-provision-hint" class="text-xs text-slate-400"></span>
                    </div>
                    <p class="text-xs text-slate-400 mb-3"><b>Auto-provision</b> = the hub distributes the LE wildcard + CA bundle to the hub and every spoke, then enables mTLS once the whole fleet is ready. No manual file copying.</p>
                    <div class="flex items-center gap-3">
                        <label class="flex items-center gap-2 text-sm text-slate-600">
                            <input type="checkbox" id="mtls-enabled" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                            Enable mutual TLS
                        </label>
                        <button onclick="saveMtlsEnable(this)" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm ml-auto">Save</button>
                    </div>
                </div>
                <div class="${card} p-6">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Idle Session Timeout</h3>
                    <p class="text-xs text-slate-400 mb-3">Automatically log out a user who makes no requests for this long. Applies live to all sessions.</p>
                    <div class="flex items-center gap-3">
                        <select id="session-timeout-minutes" class="bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="0">Never (disabled)</option>
                            <option value="15">15 minutes</option>
                            <option value="30">30 minutes</option>
                            <option value="60">60 minutes</option>
                            <option value="120">2 hours</option>
                            <option value="240">4 hours</option>
                            <option value="480">8 hours</option>
                        </select>
                        <button onclick="saveSessionTimeout(this)" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm ml-auto">Save</button>
                    </div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Active Sessions ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    </div>
                    <div class="overflow-hidden rounded-md border border-slate-200">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                                <tr>
                                    <th class="px-4 py-3">User</th>
                                    <th class="px-4 py-3">Role</th>
                                    <th class="px-4 py-3">Tenants</th>
                                    <th class="px-4 py-3">Expires In</th>
                                    <th class="px-4 py-3"></th>
                                </tr>
                            </thead>
                            <tbody id="sessions-table-body" class="divide-y divide-slate-200">
                                <tr><td colspan="5" class="px-4 py-8 text-center text-slate-400 italic animate-pulse">Loading…</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>`;
        updateStatus();
        loadHubHealthCard();
        loadAlertDiagnostics();
        loadSpokeRegistryDiag();
        loadBackpressureConfig();
        loadUpdateGateConfig();
        loadActiveSessions();
        loadSessionTimeout();
        loadMtlsReadiness();
        // Auto-save on change (no per-card Save buttons). Note: backpressure
        // config applies LIVE each 1s tick, so each committed field change takes
        // effect immediately — `change` fires on commit (blur/Enter), not per
        // keystroke, so a half-typed value is never applied.
        _attachAutoSave(content, _settingsSaveFnFor, 'settingsAutoSave');
    } else if (subMenu === 'API Tokens') {
        content.innerHTML = `
            <div class="${card} p-6 space-y-5">
                <div class="flex justify-between items-center">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">API Tokens ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                </div>
                <p class="text-[11px] text-slate-400 leading-relaxed">Bearer tokens for programmatic API access — they carry <b>your</b> permissions. Send <code>Authorization: Bearer &lt;access&gt;</code>. The access token expires in <b>4 hours</b>; POST the refresh token to <code>/auth/token/refresh</code> to rotate to a fresh pair with no re-login. Tokens are shown <b>once</b> — store them securely.</p>
                <div class="flex items-end gap-2">
                    <label class="text-xs text-slate-500 flex-1">Token name<br>
                        <input type="text" id="apitok-name" placeholder="e.g. ci-pipeline" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                    <button onclick="createApiToken()" id="apitok-create-btn" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-4 py-2 rounded-md text-sm font-bold">Create token</button>
                </div>
                <div id="apitok-new" class="hidden"></div>
                <div class="overflow-hidden rounded-md border border-slate-200">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                            <tr><th class="px-4 py-3">Name</th><th class="px-4 py-3">Created</th><th class="px-4 py-3">Expires</th><th class="px-4 py-3"></th></tr>
                        </thead>
                        <tbody id="apitok-table-body" class="divide-y divide-slate-200">
                            <tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic animate-pulse">Loading…</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>`;
        loadApiTokens();
    } else {
        content.innerHTML = `
            <div class="${card} p-6 space-y-4">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hub Status ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <p class="text-xs text-slate-400 italic">Hub is running. See System → Hub Status for metrics and spoke health.</p>
            </div>`;
    }
}

// Map a Settings (Hub Status) field element → its card's save handler.
function _settingsSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (id.startsWith('rl-'))  return saveRateLimit;
    if (id.startsWith('bp-'))  return saveBackpressureConfig;
    if (id.startsWith('ug-'))  return saveUpdateGateConfig;
    return null;
}

// ── Allowlist mappers for the id-based Setup/Settings tiles ────────────────
// These tiles share a prefix with non-save fields (test inputs, action buttons,
// restore/cert controls, status display), so a prefix match would auto-save on
// the wrong element. Each mapper lists exactly the ids its handler collects.

function _cloudNacSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (['cn-enabled', 'cn-domain', 'cn-idle', 'cn-group-id', 'cn-group-name', 'cn-group-select'].includes(id))
        return saveCloudNac;
    return null;
}

function _keyVaultSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (['kv-enabled', 'kv-url', 'kv-rotate', 'kv-retain',
         'kv-admin-secret', 'kv-fernet-secret', 'kv-prefix'].includes(id))
        return saveKeyVault;
    return null;
}

function _oidcSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (['oidc-enabled', 'oidc-tenant', 'oidc-client', 'oidc-redirect', 'oidc-group',
         'oidc-group-select'].includes(id))
        return saveOidcConfig;
    return null;
}

function _selfBackupSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (['sb-enabled', 'sb-interval', 'sb-keep', 'sb-encrypt', 'sb-include-env',
         'sb-copy-enabled', 'sb-copy-mode', 'sb-copy-interval', 'sb-strict-hostkey',
         'sb-ssh-host', 'sb-ssh-port', 'sb-ssh-user', 'sb-ssh-path', 'sb-ssh-keyfile'].includes(id))
        return saveSelfBackupConfig;
    return null;
}

// Simulations: both cards' fields are dynamic with data-* attributes (no id).
// Quota defaults → data-sqd (+ data-sqd-idpick picker); Sharing → data-simshare
// / data-simna. "+ Add Default" and "Hide N/A" carry none of these → no-op.
function _simSaveFnFor(el) {
    if (!el || !el.dataset) return null;
    if (el.dataset.sqd != null || el.dataset.sqdIdpick != null) return saveSimQuotaDefaults;
    if (el.dataset.simshare != null || el.dataset.simna != null) return saveSimSharing;
    return null;
}

// Shared Tailwind class strings for every Setup tile. Hoisted to module scope
// so each _renderSetup*Tile helper below destructures the same names
// (`card`, `inputCls`, `labelCls`, `btnCls`, `btnSecCls`) that the original
// monolithic _renderSetupSection used — keeping every template byte-identical.
const _SETUP_CLS = {
    card: 'hpe-card rounded-lg p-5 shadow-sm space-y-4',
    inputCls: 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800',
    labelCls: 'text-xs text-slate-500 uppercase font-bold',
    btnCls: 'bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm',
    btnSecCls: 'bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium border border-slate-200',
};


function _renderSetupSpokesTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    // Compact card variant for this tile only — the shared _SETUP_CLS.card uses
    // p-6/space-y-4 which is generous for forms but wastes vertical space here
    // where each row is already a dense mgmt card. Don't change the shared
    // constant (it drives Tenant/User/Firewalls tiles too).
    const saCard = 'hpe-card rounded-lg p-5 shadow-sm space-y-3';
    // Spokes + Agents side-by-side on wide screens (xl:grid-cols-2) so the page
    // height tracks the taller column instead of stacking both fully — halves
    // the scrolling for fleets with many spokes and agents. Stacks on narrower
    // viewports. items-start keeps each card top-aligned and prevents the
    // shorter card from stretching to match the taller one's height (which
    // would re-introduce empty space below its last row).
    content.innerHTML = `
            <div id="spokes-summary" class="flex flex-wrap items-center gap-3 text-xs"></div>
            <div class="flex items-center gap-2 text-xs mb-1">
                <label for="sa-tenant-filter" class="font-bold text-slate-500 uppercase tracking-wider">Tenant</label>
                <select id="sa-tenant-filter" onchange="_onSaTenantFilterChange()" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm text-slate-700 outline-none focus:ring-2 focus:ring-green-500">
                    <option value="default">ADMIN</option>
                    <option value="__unassigned__">Unassigned</option>
                    <option value="__all__" selected>All tenants</option>
                </select>
                <span class="text-[10px] text-slate-400 italic">show spokes &amp; agents for this tenant (Unassigned = not yet bound to one; All tenants = every spoke/agent incl. offline)</span>
            </div>
            <div class="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start">
                <div class="${saCard}">
                    <div class="flex justify-between items-center mb-2">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spokes ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    </div>
                    <div id="spokes-table-wrap"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
                </div>
                <div class="${saCard}">
                    <div class="flex justify-between items-center mb-2">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Agents ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    </div>
                    <div id="agents-table-wrap"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
                </div>
            </div>
            <div class="${saCard}">
                <div class="flex justify-between items-center mb-1">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hub Connection URL</h3>
                </div>
                <p class="text-xs text-slate-500 mb-2">The wss:// address agents and spokes check in to. Changing it repoints every connected remote agent/spoke to the new address (each restarts once to reconnect). Co-located (loopback) and auto-discovering spokes are left alone. Use when the hub's DNS name/IP changes — e.g. after issuing a new cert for a new name. <b>Set this before retiring the old DNS name</b>, while spokes are still connected via it.</p>
                <div class="flex items-center gap-2">
                    <input id="sa-hub-url" type="text" placeholder="wss://hub.example.com:443  or  172.16.1.31" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800" />
                </div>
                <div id="sa-hub-url-note" class="text-[11px] text-slate-400 mt-1"></div>
            </div>
            ${_spokesAgentsLegend()}`;
    _populateSaTenantFilter();
    loadSpokesAndAgents();
    loadSaHubUrl();
    // Auto-save on change — exact-id allowlist so the tenant filter (sa-tenant-
    // filter, which has its own onchange) never fires a hub-URL repoint. The
    // hub URL repoints every connected spoke on commit (blur/Enter), same as
    // the old Save button — type the full URL, then tab away.
    _attachAutoSave(content, _spokesSaveFnFor, 'spokesAutoSave');
}

// Map a Spokes & Agents field element → its save handler (exact-id allowlist —
// the tenant filter shares the sa- prefix but is a view filter, not a save field).
function _spokesSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (id === 'sa-hub-url') return saveSaHubUrl;
    return null;
}

// Hub Connection URL (Setup → Spokes & Agents). The operator sets the address
// agents/spokes check in to; the hub pushes it to every spoke on (re)connect
// and immediately on save, so a hub DNS-name change (e.g. a new cert for a new
// name) propagates without manually editing each agent's .env. See the matching
// POST /api/setup/hub-url backend + SPOKE_SET_HUB_URL handler in core.
async function loadSaHubUrl() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const url = ((data.global_config || {}).hub || {}).url || '';
        const el = document.getElementById('sa-hub-url');
        if (el) el.value = url;
    } catch (e) { console.error('loadSaHubUrl failed', e); }
}

async function saveSaHubUrl() {
    const el = document.getElementById('sa-hub-url');
    const note = document.getElementById('sa-hub-url-note');
    const url = (el ? el.value : '').trim();
    if (note) note.textContent = '';
    try {
        const r = await setupFetch('/api/setup/hub-url', {
            method: 'POST',
            body: JSON.stringify({ url })
        });
        const data = r.ok ? await r.json().catch(() => ({})) : {};
        if (r.ok) {
            const pushed = (data.pushed || []).length;
            const queued = (data.queued || []).length;
            const failed = (data.failed || []).length;
            if (url === '') {
                showToast('Hub URL override cleared.', 'success');
            } else {
                let msg = `Hub URL saved — pushed to ${pushed}`;
                if (queued) msg += `, queued for ${queued} offline`;
                if (failed) msg += `, ${failed} failed`;
                msg += '. Agents will reconnect shortly.';
                showToast(msg, failed ? 'error' : 'success');
            }
            if (note) note.textContent = data.message || '';
        } else {
            showToast('Failed to save hub URL: ' + (data.detail || r.status), 'error');
        }
    } catch (e) {
        showToast('Error saving hub URL: ' + e.message, 'error');
    }
}

// Static legend under the Spokes & Agents tile — explains the row status dot,
// version chip, recovery badge, and the kind/status/tenant badges. Swatch
// classes mirror _diagTelemetryExtras / recoveryBadge / the row renderer so the
// samples match the live UI. Same look as the Simulations → Clients legend.
function _spokesAgentsLegend() {
    const dot = cls => `<span class="inline-block w-2 h-2 rounded-full ${cls}"></span>`;
    const box = cls => `<span class="inline-block w-4 h-3 rounded border ${cls} align-middle"></span>`;
    const lbl = t => `<span class="font-bold uppercase tracking-wider text-slate-400 mr-1">${t}</span>`;
    return `<div class="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500">
      <span class="font-bold uppercase tracking-wider text-slate-400">Legend</span>
      <div class="mt-2 space-y-1.5">
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Status dot')}
          <span class="flex items-center gap-1.5">${dot('bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]')} Online / healthy</span>
          <span class="flex items-center gap-1.5">${dot('bg-amber-400')} Slow heartbeat or pending approval</span>
          <span class="flex items-center gap-1.5">${dot('bg-red-500')} Offline / no heartbeat</span>
          <span class="flex items-center gap-1.5">${dot('bg-slate-300')} No telemetry yet</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Row color')}
          <span class="flex items-center gap-1.5">${box('bg-amber-50 border-amber-300')} Out of date (needs update)</span>
          <span class="flex items-center gap-1.5">${box('bg-red-50 border-red-300')} Last contact &gt; 30 min (stale)</span>
          <span class="flex items-center gap-1.5">${box('bg-white border-slate-200')} Healthy &amp; current</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Flags')}
          <span class="text-slate-400">the line under each name shows</span>
          <span class="font-mono text-slate-400">id</span><span class="text-slate-300">·</span><span>type·module·version·seen&nbsp;Ns&nbsp;ago</span>,
          <span class="text-red-600 font-semibold">out of date</span>
          <span class="text-amber-600 font-semibold">Pending approval</span>
          <span class="text-amber-600 font-semibold">alert: warning</span>/<span class="text-red-600 font-semibold">error</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1">
          ${lbl('Tenant')}
          <span class="flex items-center gap-1.5"><span class="font-mono text-amber-700 font-semibold">shared</span> visible to all tenants</span>
          <span class="flex items-center gap-1.5"><span class="font-mono text-slate-600">&lt;name&gt;</span> private to one tenant</span>
        </div>
      </div>
    </div>`;
}

// Tenant filter for the Spokes & Agents tile. Reads the tenant list from
// /setup/tenants (tenant config — objects carry ``id``/``name``, NOT
// tenant_id/tenant_name) and fills the #sa-tenant-filter dropdown: every tenant
// first, then the two sentinels Unassigned + All tenants. The initial selection
// is the system "default" tenant (guaranteed present — the backend injects it
// when absent, tenants_users.py get_tenants), pre-seeded as a static <option> so
// loadSpokesAndAgents reads the right value with no async race. The DEFAULT
// selection is "All tenants" so an admin sees every spoke/agent — including
// offline ones across all tenants (the user's "I can't see them" gap: stale
// systems bound to a non-default tenant were hidden behind the Default filter).
// A user's choice is preserved across refresh; if it's gone, fall back to
// "All tenants" then "default" then Unassigned. Best-effort: on a failed fetch
// the static options remain usable.
async function _populateSaTenantFilter() {
    const sel = document.getElementById('sa-tenant-filter');
    if (!sel) return;
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const current = sel.value || '__all__';
    try {
        const res = await setupFetch('/setup/tenants');
        if (!res.ok) return;
        const _tdata = await res.json();
        window._sharedTenantId = _tdata.shared_tenant_id || null;  // for the shared badge / gate
        const tenants = _tdata.tenants || [];
        sel.innerHTML =
            tenants.map(t => `<option value="${esc(t.id)}">${esc(t.name || t.id)}</option>`).join('') +
            '<option value="__unassigned__">Unassigned</option>' +
            '<option value="__all__">All tenants</option>';
        const has = v => [...sel.options].some(o => o.value === v);
        sel.value = has(current) ? current
            : (has('__all__') ? '__all__'
               : (has('default') ? 'default' : '__unassigned__'));
    } catch (_e) { /* leave the static options in place */ }
}

// Re-render the Spokes & Agents lists for the newly-selected tenant. The filter
// is read inside loadSpokesAndAgents(), so a plain reload applies it.
function _onSaTenantFilterChange() {
    loadSpokesAndAgents();
}

// ── Setup → Remote Console ───────────────────────────────────────────────────
// Run a diagnostic (allowlist) or — with Debug/shell mode on — arbitrary command
// on the hub or any connected spoke/agent, from the WebUI, so troubleshooting
// doesn't mean dropping into CLI. Global-Admin only (nav + backend gated), OFF by
// default, audit-logged. Endpoints: /api/exec/config (GET/POST knobs),
// /api/exec/targets (GET), /api/exec (POST run).
// ── OS Updates (left-nav view, Global-Admin) ────────────────────────────────
// Fleet OS package updates. The HUB is the module: it collects pending-update
// state from every spoke and agent and, on explicit approval, sends the apply
// commands. Nodes never update themselves.
// Rolling one node at a time, hub last; a manual deploy never reboots (see
// hub_os_updates.py). Deploy everything, or only selected nodes / packages /
// security updates; reboot is a separate per-node action, or Auto-reboot on an
// auto-patch node. Ineligible nodes are listed as unmanaged WITH a reason rather than
// hidden, so "up to date" is never confused with "not covered".
let _osuPoll = null;

function _renderOsUpdatesView(content) {
    // Fleet-wide settings are Global Admin only; a Tenant Admin sees just their nodes.
    const osuFleetCls = isAdmin() ? '' : 'hidden';
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card} space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">OS Updates ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <span id="osu-status" class="text-xs text-slate-400"></span>
            </div>
            <div class="rounded-md bg-amber-50 border border-amber-200 p-3 text-[11px] text-amber-800 leading-snug">
                Operating-system package updates for every spoke and agent — <b>Global-Admin only, every approval is audit-logged</b>.
                Deploys <code>apt dist-upgrade</code> (everything) — or only the nodes/packages you select, or only security updates.
                A manual deploy <b>never reboots</b> — a host needing one is badged with a <b>Reboot…</b> button you use deliberately.
                <b>Auto-patch</b> is approved <b>per node</b> (tick "Auto-patch" on a node) and only runs in the <b>maintenance window</b> below: once per window the fleet is re-checked and approved nodes get what was found, the same way — security updates only or all updates, minus any packages you list under "Never auto-install".
                <b>Auto-reboot</b> (on by default for an auto-patch node — untick it to keep a node up) reboots each node that installed something once the run is done, hub last. No new node is started after the window closes; the auto-check only detects updates.
                A node in a <b>Proxmox cluster</b> is only rebooted if it needs it, in <b>HA maintenance mode</b> (HA guests move to the other nodes first), and the run waits until it is back before taking maintenance off and moving on — one cluster node down at a time.
                Nodes are updated <b>one at a time</b>, and the <b>hub goes last</b> (updating it restarts this page).
                This is separate from LM code updates.
            </div>
            <div class="${osuFleetCls} flex flex-wrap items-end gap-3 border border-slate-200 rounded-md px-3 py-2 bg-slate-50">
                <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="osu-autocheck-enabled" class="w-4 h-4 text-green-600 rounded">Auto-check the fleet</label>
                <div class="space-y-1">
                    <label class="${labelCls}">Every</label>
                    <div class="flex items-center gap-1">
                        <input type="number" id="osu-autocheck-hours" min="1" step="1" value="6" class="${inputCls} w-20">
                        <span class="text-xs text-slate-500">hour(s)</span>
                    </div>
                </div>
                <button onclick="osuSaveAutoCheck()" class="${btnSecCls}">Save</button>
                <span id="osu-autocheck-status" class="text-xs text-slate-400"></span>
            </div>
            <div class="${osuFleetCls} flex flex-wrap items-end gap-3 border border-slate-200 rounded-md px-3 py-2 bg-slate-50">
                <span class="text-sm text-slate-600 self-center">Auto-patch (approved nodes only):</span>
                <div class="space-y-1">
                    <label class="${labelCls}">Install</label>
                    <select id="osu-autopatch-security" class="${inputCls} w-48" onchange="osuSetAutoPatchSecurity(this.value === 'security')">
                        <option value="security">Security updates only</option>
                        <option value="all">All updates</option>
                    </select>
                </div>
                <div class="space-y-1 flex-1 min-w-[16rem]">
                    <label class="${labelCls}" title="Package names or globs, comma-separated. Auto-patch never installs these; manual deploys are unaffected.">Never auto-install</label>
                    <input type="text" id="osu-autopatch-exclude" class="${inputCls}" placeholder="e.g. linux-image-*, docker-ce, proxmox-*">
                </div>
                <button onclick="osuSaveAutoPatchExclude()" class="${btnSecCls}">Save</button>
                <span id="osu-autopatch-count" class="text-xs text-slate-400 self-center"></span>
            </div>
            <div class="${osuFleetCls} flex flex-wrap items-end gap-3 border border-slate-200 rounded-md px-3 py-2 bg-slate-50">
                <span class="text-sm text-slate-600 self-center" title="Auto-patch and auto-reboot only run in this window (once per window). Same start and end = any time.">Maintenance window (off hours):</span>
                <div class="space-y-1">
                    <label class="${labelCls}">From</label>
                    <input type="time" id="osu-window-start" class="${inputCls} w-32" value="01:00">
                </div>
                <div class="space-y-1">
                    <label class="${labelCls}">To</label>
                    <input type="time" id="osu-window-end" class="${inputCls} w-32" value="05:00">
                </div>
                <div class="space-y-1">
                    <label class="${labelCls}">Timezone</label>
                    <input type="text" id="osu-window-tz" class="${inputCls} w-48" placeholder="e.g. America/Chicago">
                </div>
                <button onclick="osuSaveWindow()" class="${btnSecCls}">Save</button>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <button onclick="osuCheck()" class="${btnSecCls}">↻ Check for updates</button>
                <button id="osu-apply-selected" onclick="osuApplySelected()" class="${btnCls}" disabled>Deploy selected (0)</button>
                <button id="osu-apply" onclick="osuApply()" class="${btnSecCls}">Approve &amp; deploy all</button>
                <label class="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer" title="Nodes without picked packages get only their pending security updates"><input type="checkbox" id="osu-security-only" class="w-4 h-4 rounded">Security updates only</label>
                <button id="osu-cancel" onclick="osuCancel()" class="${btnSecCls} hidden">Cancel run</button>
                <span id="osu-run" class="text-xs text-slate-500"></span>
            </div>
            <div class="border border-slate-200 rounded-md px-3 py-2 bg-slate-50 space-y-2">
                <div class="flex flex-wrap items-end gap-3">
                    <div class="space-y-1 flex-1 min-w-[16rem]">
                        <label class="${labelCls}" title="Matches each node's installed packages (reported at the last check) against Debian's security tracker">Who is affected? — CVE id or package</label>
                        <input type="text" id="osu-cve-q" list="osu-cve-list" autocomplete="off" class="${inputCls}" placeholder="e.g. CVE-2026-1234 or php" onkeydown="if (event.key === 'Enter') osuCveSearch()" oninput="osuCvePicked(this.value)">
                        <datalist id="osu-cve-list"></datalist>
                    </div>
                    <button onclick="osuCveSearch()" class="${btnSecCls}">Look up</button>
                </div>
                <div id="osu-cve-body"></div>
            </div>
            <div id="osu-body"><p class="text-xs text-slate-400 italic">Loading…</p></div>
        </div>`;
    osuLoad();
    osuLoadAutoCheck();
    osuLoadAutoPatch();
    osuLoadFleetCves();
}

// Footer "Pending Reboot" alert: during the maintenance window, lists the
// nodes auto-reboot is about to restart (hover for the list). Admins (a
// Tenant Admin sees their own nodes), like the rest of OS Updates; refreshed every minute.
async function osuRefreshRebootTray() {
    const tray = document.getElementById('reboot-tray');
    if (!tray) return;
    let data = { nodes: [] };
    if (typeof isAdmin === 'function' && (isAdmin() || isTenantAdmin())) {
        try { data = await apiJson('/api/os-updates/pending-reboots'); } catch (e) { /* keep hidden */ }
    }
    const nodes = data.in_window ? (data.nodes || []) : [];
    tray.classList.toggle('hidden', !nodes.length);
    tray.classList.toggle('flex', nodes.length > 0);
    if (!nodes.length) return;
    const w = data.window || {};
    document.getElementById('reboot-tray-tooltip').innerHTML =
        `<div class="font-bold mb-1">${nodes.length} system(s) will be rebooted</div>`
        + nodes.map(n => `<div class="flex justify-between gap-4 py-0.5"><span>${escapeHtml(n.label)}</span><span class="opacity-60">${escapeHtml(n.note)}</span></div>`).join('')
        + `<div class="opacity-60 mt-1">Maintenance window ${escapeHtml(w.start || '')}–${escapeHtml(w.end || '')} ${escapeHtml(w.tz || '')}</div>`;
}
setTimeout(osuRefreshRebootTray, 5000);
setInterval(osuRefreshRebootTray, 60000);

// Picking a suggestion looks it up straight away.
window.osuCvePicked = function (value) {
    const opts = document.getElementById('osu-cve-list')?.options || [];
    if (Array.from(opts).some(o => o.value === value)) osuCveSearch();
};

// Suggestions for the who-is-affected box: only the CVEs that affect at least
// one node, shown with their description so the right id is easy to pick.
async function osuLoadFleetCves() {
    try {
        const cves = await apiJson('/api/os-updates/cves/fleet');
        const list = document.getElementById('osu-cve-list');
        if (!list) return;
        list.innerHTML = cves.map(c => `<option value="${escapeHtml(c.cve)}" label="${escapeHtml(
            `${c.urgency ? c.urgency + ' · ' : ''}${c.nodes} node(s) · ${c.description}`)}"></option>`).join('');
        const q = document.getElementById('osu-cve-q');
        if (q) q.title = `${cves.length} CVE(s) affect the fleet — start typing to pick one`;
    } catch (e) { /* best-effort — typing an id still works */ }
}

async function osuLoadAutoPatch() {
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch');
        document.getElementById('osu-autopatch-security').value = cfg.security_only !== false ? 'security' : 'all';
        document.getElementById('osu-autopatch-exclude').value = (cfg.exclude || []).join(', ');
        osuShowWindow(cfg.window);
    } catch (e) { /* best-effort */ }
}

function osuShowWindow(w) {
    if (!w) return;
    document.getElementById('osu-window-start').value = w.start;
    document.getElementById('osu-window-end').value = w.end;
    document.getElementById('osu-window-tz').value = w.tz;
}

window.osuSaveWindow = async function () {
    const window_ = {
        start: document.getElementById('osu-window-start').value,
        end: document.getElementById('osu-window-end').value,
        // Default to this browser's timezone so "01:00" means the operator's 1 AM.
        tz: document.getElementById('osu-window-tz').value.trim()
            || Intl.DateTimeFormat().resolvedOptions().timeZone,
    };
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ window: window_ }) });
        osuShowWindow(cfg.window);
        const w = cfg.window;
        showToast(w.start === w.end
            ? `Auto-patch may run at any time (${w.tz}).`
            : `Auto-patch runs between ${w.start} and ${w.end} (${w.tz}).`, 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
};

window.osuSaveAutoPatchExclude = async function () {
    const exclude = document.getElementById('osu-autopatch-exclude').value
        .split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
    try {
        const cfg = await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ exclude }) });
        document.getElementById('osu-autopatch-exclude').value = (cfg.exclude || []).join(', ');
        showToast(cfg.exclude && cfg.exclude.length
            ? `Auto-patch will never install: ${cfg.exclude.join(', ')}.`
            : 'Auto-patch exclusions cleared.', 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
};

window.osuSetAutoPatchSecurity = async function (on) {
    try {
        await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ security_only: on }) });
        showToast(on ? 'Auto-patch: security updates only.' : 'Auto-patch: all updates.', 'success');
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
};

window.osuToggleAutoPatch = async function (key, on, el) {
    const n = ((window._osuData || {}).nodes || []).find(x => `${x.kind}:${x.id}` === key);
    const label = n ? n.label : key;
    const hubNote = n && n.kind === 'hub' ? '\n\nThis is the HUB — patching it restarts LM services, and Auto-reboot reboots it last.' : '';
    if (on && !confirm(`Approve ${label} for auto-patching?\n\nIn each maintenance window its pending updates are installed automatically, then the node is rebooted (Auto-reboot — untick it to keep the node up).${hubNote}`)) {
        if (el) el.checked = false;
        return;
    }
    try {
        await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ node: key, enabled: on }) });
        showToast(`${label}: auto-patch ${on ? 'approved' : 'off'}.`, 'success');
        osuLoad();
    } catch (e) { if (el) el.checked = !on; showToast('Save failed: ' + (e.message || e), 'error'); }
};

window.osuToggleAutoReboot = async function (key, on, el) {
    const n = ((window._osuData || {}).nodes || []).find(x => `${x.kind}:${x.id}` === key);
    const label = n ? n.label : key;
    try {
        await apiJson('/api/os-updates/auto-patch', { method: 'POST', body: JSON.stringify({ node: key, auto_reboot: on }) });
        showToast(`${label}: auto-reboot ${on ? 'on' : 'off'}.`, 'success');
        osuLoad();
    } catch (e) { if (el) el.checked = !on; showToast('Save failed: ' + (e.message || e), 'error'); }
};

// One-time login for a node blocked by missing privileges. The password goes
// to that node once to install its update helper; LM never stores it.
window.osuFixAccess = function (key) {
    const n = ((window._osuData || {}).nodes || []).find(x => `${x.kind}:${x.id}` === key);
    if (!n) return;
    const inp = 'w-full px-3 py-2 border border-slate-200 rounded-md text-sm';
    openModal('osu-fix-modal', `
      <h3 class="text-lg font-bold text-[#263040]">Fix update access — ${escapeHtml(n.label)}</h3>
      <p class="text-sm text-slate-500">Enter the root password (or a user that can sudo) for this node, one time. It is used once to install LM's update helper and is <b>never stored</b>.</p>
      <input id="osu-fix-user" type="text" value="root" autocomplete="off" placeholder="username" class="${inp}">
      <input id="osu-fix-pw" type="password" autocomplete="off" placeholder="password" class="${inp}">
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="document.getElementById('osu-fix-modal')?.remove()" class="px-4 py-1.5 text-sm rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50">Cancel</button>
        <button id="osu-fix-go" onclick="osuDoFixAccess(${escapeHtml(JSON.stringify(key))})" class="px-4 py-1.5 text-sm rounded-md bg-[#01A982] text-white font-bold hover:bg-[#019972]">Fix access</button>
      </div>`, { backdropClose: true });
    document.getElementById('osu-fix-pw')?.focus();
};

window.osuDoFixAccess = async function (key) {
    const pwEl = document.getElementById('osu-fix-pw');
    const username = (document.getElementById('osu-fix-user')?.value || 'root').trim();
    const password = pwEl?.value || '';
    if (!password) { showToast('Enter the password.', 'info'); return; }
    const btn = document.getElementById('osu-fix-go');
    if (btn) { btn.disabled = true; btn.textContent = 'Fixing…'; }
    try {
        const r = await apiJson('/api/os-updates/fix-access', { method: 'POST', body: JSON.stringify({ node: key, username, password }) });
        document.getElementById('osu-fix-modal')?.remove();
        showToast(r.message || 'Access fixed.', 'success');
        osuLoad();
    } catch (e) {
        if (pwEl) pwEl.value = '';
        if (btn) { btn.disabled = false; btn.textContent = 'Fix access'; }
        showToast('Fix failed: ' + (e.message || e), 'error');
    }
};

async function osuLoadAutoCheck() {
    try {
        const cfg = await apiJson('/api/os-updates/auto-check');
        const chk = document.getElementById('osu-autocheck-enabled');
        const hrs = document.getElementById('osu-autocheck-hours');
        if (chk) chk.checked = cfg.enabled !== false;
        if (hrs) hrs.value = cfg.interval_hours ?? 6;
    } catch (e) { /* best-effort — the manual Check button still works */ }
}

window.osuSaveAutoCheck = async function () {
    const enabled = !!document.getElementById('osu-autocheck-enabled')?.checked;
    const hours = Math.max(1, parseInt(document.getElementById('osu-autocheck-hours')?.value, 10) || 6);
    const st = document.getElementById('osu-autocheck-status');
    try {
        const cfg = await apiJson('/api/os-updates/auto-check', {
            method: 'POST', body: JSON.stringify({ enabled, interval_hours: hours }),
        });
        document.getElementById('osu-autocheck-hours').value = cfg.interval_hours;
        showToast(cfg.enabled ? `Auto-check enabled — every ${cfg.interval_hours}h.` : 'Auto-check disabled.', 'success');
        if (st) { st.textContent = 'saved'; setTimeout(() => { if (st) st.textContent = ''; }, 2000); }
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
};

async function osuLoad() {
    try { _osuRender(await apiJson('/api/os-updates')); }
    catch (e) { const b = document.getElementById('osu-body'); if (b) b.innerHTML = `<p class="text-xs text-red-500">${escapeHtml(String(e.message || e))}</p>`; }
}

window.osuCheck = async function () {
    const st = document.getElementById('osu-status');
    if (st) st.textContent = 'checking every node…';
    try { _osuRender(await apiJson('/api/os-updates/check', { method: 'POST', body: JSON.stringify({ refresh: true }) })); showToast('Update check complete.', 'success'); }
    catch (e) { showToast('Check failed: ' + (e.message || e), 'error'); }
    finally { if (st) st.textContent = ''; }
};

// Selection survives the 5s progress re-render: node keys picked whole, and
// per-node package picks (a node with package picks applies only those). A
// package pick never selects the whole node — clearing the last pick must not
// leave a full dist-upgrade selected.
const _osuSel = { nodes: new Set(), pkgs: {} };
const _osuOpen = new Set();

function _osuSelectedKeys() { return [...new Set([..._osuSel.nodes, ...Object.keys(_osuSel.pkgs)])]; }

function _osuBusy() { const r = (window._osuData || {}).run; return !!(r && r.status === 'running'); }

window.osuToggleNode = function (key, on) {
    _osuSel.nodes[on ? 'add' : 'delete'](key);
    delete _osuSel.pkgs[key];
    _osuRender(window._osuData || {});
};

window.osuTogglePkg = function (key, pkg, on) {
    const set = _osuSel.pkgs[key] || (_osuSel.pkgs[key] = new Set());
    if (on) { set.add(pkg); _osuSel.nodes.delete(key); } else set.delete(pkg);
    if (!set.size) delete _osuSel.pkgs[key];
    _osuRender(window._osuData || {});
};

window.osuToggleOpen = function (key, open) { if (open) _osuOpen.add(key); else _osuOpen.delete(key); };

// CVE lookup: which nodes run a package vulnerable to a CVE (or, for a package
// name, that package's open CVEs). Served from the last check's inventory.
window.osuCveSearch = async function () {
    const q = (document.getElementById('osu-cve-q')?.value || '').trim();
    const out = document.getElementById('osu-cve-body');
    if (!out || !q) return;
    out.innerHTML = '<p class="text-xs text-slate-400 italic">Looking up…</p>';
    try {
        const d = await apiJson('/api/os-updates/cves?q=' + encodeURIComponent(q));
        window._osuCve = d;
        out.innerHTML = _osuCveHtml(d);
    } catch (e) {
        out.innerHTML = `<p class="text-xs text-red-600">${escapeHtml(e.message || String(e))}</p>`;
    }
};

// Pending upgrades on each affected node that belong to the vulnerable packages.
function _osuCveFixes(d) {
    const nodes = {};
    ((window._osuData || {}).nodes || []).forEach(n => { nodes[`${n.kind}:${n.id}`] = n; });
    const picks = [];
    (d.results || []).forEach(r => r.affected.forEach(a => {
        const pending = new Set(((nodes[a.node] || {}).packages || []).map(p => p.package));
        a.binaries.filter(b => pending.has(b)).forEach(b => picks.push([a.node, b]));
    }));
    return picks;
}

window.osuCveSelectFixes = function () {
    const picks = _osuCveFixes(window._osuCve || {});
    picks.forEach(([key, pkg]) => {
        (_osuSel.pkgs[key] || (_osuSel.pkgs[key] = new Set())).add(pkg);
        _osuSel.nodes.delete(key);
    });
    _osuRender(window._osuData || {});
    showToast(`${picks.length} package update(s) selected — review, then "Deploy selected".`, 'success');
};

function _osuCveHtml(d) {
    const note = (cls, text) => `<p class="text-xs ${cls}">${text}</p>`;
    const parts = [];
    if (!Object.keys(d.feeds || {}).length) {
        parts.push(note('text-amber-700', 'No Debian security data yet — run "Check for updates" so nodes report their installed packages and the hub fetches the tracker feed.'));
    } else if (d.kind === 'cve' && !d.known) {
        parts.push(note('text-slate-500', `${escapeHtml(d.query)} is not in Debian's security tracker for the release(s) in this fleet — it may not affect Debian packages, or not be published yet.`));
    } else if (!(d.results || []).length) {
        parts.push(note('text-slate-500', `No open CVEs match "${escapeHtml(d.query)}" on any checked node.`));
    } else {
        const fixes = _osuCveFixes(d).length;
        parts.push(`<div class="flex flex-wrap items-center gap-2 text-xs">
            <b class="${d.affected_nodes ? 'text-red-700' : 'text-emerald-700'}">${d.affected_nodes} of ${d.checked_nodes} checked node(s) affected</b>
            ${fixes ? `<button onclick="osuCveSelectFixes()" class="text-[10px] font-bold text-emerald-800 border border-emerald-300 rounded px-2 py-0.5 hover:bg-emerald-50" title="Pick the pending updates of the vulnerable packages on affected nodes">Select fixes (${fixes})</button>` : ''}
            ${d.truncated ? '<span class="text-slate-400">showing the first 200 CVEs — narrow the search</span>' : ''}</div>`);
        parts.push(...d.results.map(r => {
            const flags = [r.urgency ? `${r.urgency} urgency` : '', r.remote ? 'remote' : ''].filter(Boolean).join(' · ');
            const row = (a, patched) => {
                const status = patched ? _osuBadge('patched', 'emerald')
                    : a.update_pending ? _osuBadge('update pending', 'amber', 'An update for this package is waiting — deploy it from this page')
                    : a.fix_available ? _osuBadge('fixed in Debian — not yet installable here', 'amber', 'Run "Check for updates"; the node may lack the security repo')
                    : _osuBadge('no fix yet', 'red', 'Debian has not released a fix for this release');
                return `<div class="flex flex-wrap items-center justify-between gap-2 py-0.5">
                    <span><b class="text-slate-700">${escapeHtml(a.label)}</b> <span class="text-slate-400">debian ${escapeHtml(a.release)}</span>
                    — ${escapeHtml(a.package)} <span class="text-slate-400">${escapeHtml(a.version)}</span>
                    <span class="text-slate-400">(${escapeHtml(a.binaries.join(', '))})</span></span>${status}</div>`;
            };
            const patched = (r.patched || []).length
                ? `<details class="mt-1"><summary class="cursor-pointer text-[11px] text-slate-400">${r.patched.length} node(s) have the package and are patched</summary>${r.patched.map(a => row(a, true)).join('')}</details>` : '';
            return `<div class="border border-slate-200 rounded-md p-2 bg-white text-[11px]">
                <div class="flex flex-wrap items-center gap-2">
                    <a href="https://security-tracker.debian.org/tracker/${encodeURIComponent(r.cve)}" target="_blank" rel="noopener" class="font-bold text-slate-700 underline">${escapeHtml(r.cve)}</a>
                    <span class="text-slate-400">${escapeHtml(flags)}</span>
                    ${r.affected.length ? _osuBadge(`${r.affected.length} affected`, 'red') : _osuBadge('no node affected', 'emerald')}
                </div>
                <div class="text-slate-500 mt-0.5">${escapeHtml(r.description || '')}</div>
                ${r.affected.map(a => row(a, false)).join('')}${patched}</div>`;
        }));
    }
    if ((d.unknown || []).length) {
        parts.push(`<details><summary class="cursor-pointer text-[11px] text-amber-700">${d.unknown.length} node(s) could not be assessed</summary>
            ${d.unknown.map(u => `<div class="text-[11px] text-slate-500"><b>${escapeHtml(u.label)}</b> — ${escapeHtml(u.reason)}</div>`).join('')}</details>`);
    }
    const feeds = Object.entries(d.feeds || {}).map(([c, f]) =>
        `${escapeHtml(c)}${f.fetched_at ? ' ' + new Date(f.fetched_at * 1000).toLocaleString() : ''}${f.error ? ' (refresh failed: ' + escapeHtml(f.error) + ')' : ''}`).join(', ');
    parts.push(`<p class="text-[10px] text-slate-400">Installed packages as of the last check · Debian security tracker data: ${feeds || 'none available'}</p>`);
    return `<div class="space-y-2">${parts.join('')}</div>`;
}

async function _osuDeploy(body, summary) {
    const secOnly = !!document.getElementById('osu-security-only')?.checked;
    body.security_only = secOnly;
    // Deliberate friction: this changes packages on real hosts.
    if (!confirm(`Approve and deploy OS updates?\n\n${summary}\n\n` +
                 `• ${secOnly ? 'security updates only (unless packages were picked)' : 'apt dist-upgrade, or just the picked packages'}\n` +
                 `• one node at a time, hub last\n` +
                 `• nothing is rebooted automatically — you'll get a badge instead`)) return;
    try {
        const r = await apiJson('/api/os-updates/apply', { method: 'POST', body: JSON.stringify(body) });
        showToast(`Deploying to ${r.queued} node(s) — one at a time.`, 'success');
        _osuSel.nodes.clear(); Object.keys(_osuSel.pkgs).forEach(k => delete _osuSel.pkgs[k]);
        _osuStartPoll();
    } catch (e) { showToast('Apply failed: ' + (e.message || e), 'error'); }
}

window.osuApply = async function () {
    const n = ((window._osuData || {}).totals || {}).with_updates || 0;
    if (!n) { showToast('No nodes have pending updates.', 'info'); return; }
    _osuDeploy({}, `All ${n} node(s) with pending updates.`);
};

window.osuApplySelected = async function () {
    const keys = _osuSelectedKeys();
    if (!keys.length) { showToast('Select at least one node or package.', 'info'); return; }
    const labels = Object.fromEntries(((window._osuData || {}).nodes || []).map(n => [`${n.kind}:${n.id}`, n.label]));
    const packages = {};
    const lines = keys.map(k => {
        const picked = _osuSel.pkgs[k];
        if (picked && picked.size) { packages[k] = [...picked]; return `• ${labels[k] || k}: ${picked.size} package(s)`; }
        return `• ${labels[k] || k}: all pending`;
    });
    const nodes = keys.filter(k => !packages[k]);
    _osuDeploy({ nodes, packages }, lines.join('\n'));
};

window.osuCancel = async function () {
    if (!confirm('Cancel the update run?\n\nThe node currently updating will finish (apt cannot be safely interrupted); queued nodes are skipped.')) return;
    try { const r = await apiJson('/api/os-updates/cancel', { method: 'POST', body: '{}' }); showToast(r.message || 'Cancelling…', 'success'); }
    catch (e) { showToast('Cancel failed: ' + (e.message || e), 'error'); }
};

window.osuReboot = async function (key) {
    const n = ((window._osuData || {}).nodes || []).find(x => `${x.kind}:${x.id}` === key);
    if (!n) return;
    const warn = n.kind === 'hub' ? '\n\nThis is the HUB — the WebUI and every spoke connection drop until it is back.'
        : (n.flavor === 'proxmox' ? '\n\nThis is a Proxmox host — every VM on it goes down with it.' : '');
    if (!confirm(`Reboot ${n.label} in 1 minute?${warn}\n\n(Cancel on the host with: shutdown -c)`)) return;
    try {
        const r = await apiJson('/api/os-updates/reboot', { method: 'POST', body: JSON.stringify({ node: key }) });
        showToast(`${n.label}: ${r.message || 'reboot scheduled'}`, 'success');
        osuLoad();
    } catch (e) { showToast('Reboot failed: ' + (e.message || e), 'error'); }
};

function _osuStartPoll() {
    if (_osuPoll) clearInterval(_osuPoll);
    // A dist-upgrade takes minutes; poll the snapshot so the roll's progress is
    // visible without the operator refreshing.
    _osuPoll = setInterval(async () => {
        try {
            const d = await apiJson('/api/os-updates');
            _osuRender(d);
            if (!d.run || d.run.status !== 'running') { clearInterval(_osuPoll); _osuPoll = null; }
        } catch (e) { clearInterval(_osuPoll); _osuPoll = null; }
    }, 5000);
}

// Literal class strings: Tailwind is precompiled, so built-up names wouldn't exist.
const _OSU_BADGE_CLS = {
    blue: 'text-blue-700 bg-blue-50 border-blue-200',
    red: 'text-red-700 bg-red-50 border-red-200',
    emerald: 'text-emerald-700 bg-emerald-50 border-emerald-200',
    amber: 'text-amber-800 bg-amber-50 border-amber-200',
    slate: 'text-slate-500 bg-slate-100 border-slate-300',
};
const _osuBadge = (text, color, title) => `<span class="text-[10px] font-bold ${_OSU_BADGE_CLS[color]} border rounded-full px-2 py-0.5"${title ? ` title="${escapeHtml(title)}"` : ''}>${escapeHtml(text)}</span>`;

function _osuRender(d) {
    window._osuData = d;
    const body = document.getElementById('osu-body');
    if (!body) return;
    const t = d.totals || {};
    const run = d.run;
    const busy = _osuBusy();
    const runEl = document.getElementById('osu-run');
    if (runEl) {
        const label = { finished: 'complete', cancelled: 'cancelled', interrupted: 'interrupted by a hub restart' };
        runEl.textContent = busy
            ? `deploying ${run.done}/${run.total} — current: ${run.current || '…'}${run.cancel_requested ? ' (cancelling after this node)' : ''}`
            : (run && label[run.status] ? `last run${run.actor === 'auto-patch' ? ' (auto-patch)' : ''}: ${run.done}/${run.total} ${label[run.status]}` : '');
    }
    const nSel = _osuSelectedKeys().length;
    const btn = document.getElementById('osu-apply');
    if (btn) btn.disabled = busy;
    const selBtn = document.getElementById('osu-apply-selected');
    if (selBtn) { selBtn.disabled = busy || !nSel; selBtn.textContent = `Deploy selected (${nSel})`; }
    const cancelBtn = document.getElementById('osu-cancel');
    if (cancelBtn) cancelBtn.classList.toggle('hidden', !busy);
    const chip = (label, val, cls) => `<span class="inline-flex items-baseline gap-1 border rounded-full px-2.5 py-0.5 ${cls || 'bg-white border-slate-200'}"><b class="text-slate-700">${escapeHtml(String(val))}</b><span class="text-slate-500">${escapeHtml(label)}</span></span>`;
    const summary = `<div class="flex flex-wrap items-center gap-1.5 text-xs mb-3">
        ${chip('nodes with updates', t.with_updates || 0, (t.with_updates ? 'bg-amber-50 border-amber-200' : 'bg-white border-slate-200'))}
        ${chip('packages', t.packages || 0)}
        ${chip('security', t.security || 0, (t.security ? 'bg-red-50 border-red-200' : 'bg-white border-slate-200'))}
        ${chip('need reboot', t.reboot_required || 0, (t.reboot_required ? 'bg-amber-50 border-amber-200' : 'bg-white border-slate-200'))}
        ${chip('blocked', t.blocked || 0, (t.blocked ? 'bg-amber-50 border-amber-200' : 'bg-white border-slate-200'))}
        ${chip('unmanaged', t.unmanaged || 0)}
        ${chip('unreachable', t.unreachable || 0, (t.unreachable ? 'bg-red-50 border-red-200' : 'bg-white border-slate-200'))}
        ${chip('not checked yet', t.not_checked || 0, (t.not_checked ? 'bg-slate-100 border-slate-300' : 'bg-white border-slate-200'))}
      </div>`;
    const rows = (d.nodes || []).map(n => {
        const key = `${n.kind}:${n.id}`;
        const jsKey = escapeHtml(JSON.stringify(key));
        const feats = n.features || [];
        const item = run && (run.items || []).find(i => i.key === key);
        let state;
        if (item && item.status === 'applying') state = _osuBadge('applying…', 'blue');
        else if (item && item.status === 'failed') state = _osuBadge('failed', 'red');
        else if (item && item.status === 'interrupted') state = _osuBadge('interrupted', 'red');
        else if (item && item.status === 'queued') state = _osuBadge('queued', 'slate');
        else if (item && item.status === 'done' && busy) state = _osuBadge('updated', 'emerald');
        else if (n.unreachable) state = _osuBadge('unreachable', 'red');
        else if (n.unmanaged) state = _osuBadge('unmanaged', 'slate');
        else if (n.checked === false) state = _osuBadge('not checked yet', 'slate');
        else if (!n.count) state = _osuBadge('up to date', 'emerald');
        else state = _osuBadge(`${n.count} pending`, 'amber');
        const scheduled = n.reboot_scheduled_at && (Date.now() / 1000 - n.reboot_scheduled_at) < 900;
        const reboot = scheduled ? _osuBadge('reboot scheduled', 'blue')
            : (n.reboot_required ? _osuBadge('reboot required', 'amber', 'A kernel/PVE update needs a reboot. Nothing reboots automatically — do it deliberately.') : '');
        const canReboot = n.eligible && n.reboot_required && !scheduled && feats.includes('reboot') && !busy;
        const rebootBtn = canReboot ? `<button onclick="osuReboot(${jsKey})" class="text-[10px] font-bold text-amber-800 border border-amber-300 rounded px-2 py-0.5 hover:bg-amber-100">Reboot…</button>` : '';
        const selectable = n.eligible && n.count && !n.apply_blocker && !busy;
        const nodeBox = selectable
            ? `<input type="checkbox" class="w-4 h-4 rounded" ${_osuSel.nodes.has(key) ? 'checked' : ''} onchange="osuToggleNode(${jsKey}, this.checked)" title="Upgrade everything pending on this node">`
            : '';
        const canPick = selectable && feats.includes('packages');
        const picked = _osuSel.pkgs[key] || new Set();
        const pkgs = (n.packages || []).map(p => {
            const label = `${escapeHtml(p.package)} <span class="text-slate-400">${escapeHtml(p.current)}→${escapeHtml(p.candidate)}</span>`;
            const cls = p.security ? 'text-red-700' : 'text-slate-500';
            if (!canPick) return `<span class="inline-block mr-2 ${cls}">${label}</span>`;
            return `<label class="inline-flex items-center gap-1 mr-3 ${cls} cursor-pointer"><input type="checkbox" class="w-3 h-3" ${picked.has(p.package) ? 'checked' : ''} onchange="osuTogglePkg(${jsKey}, ${escapeHtml(JSON.stringify(p.package))}, this.checked)">${label}</label>`;
        }).join('');
        const pickNote = selectable && !feats.includes('packages')
            ? '<div class="text-[10px] text-slate-400 mt-1">Update LM on this node to pick individual packages — it can only be updated whole.</div>' : '';
        const pickHint = canPick ? `<div class="text-[10px] text-slate-400 mb-1">${picked.size ? `${picked.size} picked — only these will be upgraded on this node.` : 'Pick packages to upgrade only those, or tick the node to upgrade everything.'}</div>` : '';
        const detail = n.reason
            ? `<div class="text-[11px] text-slate-500 mt-1">${escapeHtml(n.reason)}</div>`
            : (n.count ? `<details class="mt-1" ${_osuOpen.has(key) ? 'open' : ''} ontoggle="osuToggleOpen(${jsKey}, this.open)"><summary class="cursor-pointer text-[11px] text-slate-400">${n.count} package(s)${n.security_count ? ` · ${n.security_count} security` : ''}</summary><div class="text-[11px] mt-1 leading-relaxed">${pickHint}${pkgs}</div></details>${pickNote}` : '');
        const fixBtn = n.apply_blocker && feats.includes('fix_access') && !busy
            ? ` <button onclick="osuFixAccess(${jsKey})" class="ml-1 text-[10px] font-bold text-amber-800 border border-amber-300 rounded px-2 py-0.5 hover:bg-amber-100">Fix access…</button>` : '';
        const autoBox = n.eligible
            ? `<label class="flex items-center gap-1 text-[10px] font-bold ${n.auto_patch ? 'text-emerald-700' : 'text-slate-400'} cursor-pointer" title="Install this node's updates automatically in the maintenance window"><input type="checkbox" class="w-3 h-3" ${n.auto_patch ? 'checked' : ''} onchange="osuToggleAutoPatch(${jsKey}, this.checked, this)">Auto-patch</label>` : '';
        const rebootBox = n.eligible && n.auto_patch
            ? `<label class="flex items-center gap-1 text-[10px] font-bold ${n.auto_reboot ? 'text-emerald-700' : 'text-slate-400'} cursor-pointer" title="Reboot this node after auto-patch installs something"><input type="checkbox" class="w-3 h-3" ${n.auto_reboot ? 'checked' : ''} onchange="osuToggleAutoReboot(${jsKey}, this.checked, this)">Auto-reboot</label>` : '';
        const blocker = n.apply_blocker ? `<div class="text-[11px] text-amber-700 mt-1">Can't apply: ${escapeHtml(n.apply_blocker)}${fixBtn}</div>` : '';
        let msg = '';
        if (item && item.message) msg = `<div class="text-[11px] ${item.status === 'done' ? 'text-slate-500' : 'text-red-600'} mt-1">${escapeHtml(item.message)}</div>`;
        else if (item && item.status === 'done' && item.mode === 'packages') msg = `<div class="text-[11px] text-slate-500 mt-1">upgraded ${escapeHtml((item.packages || []).join(', '))}</div>`;
        if (item && item.auto_reboot) msg += `<div class="text-[11px] ${item.auto_reboot === 'scheduled' ? 'text-slate-500' : 'text-red-600'} mt-1">auto-reboot ${escapeHtml(item.auto_reboot)}</div>`;
        return `<div class="border border-slate-200 rounded-md p-3 mb-2">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span class="flex items-center gap-2 text-xs font-bold text-slate-600">${nodeBox}${escapeHtml(n.label)} <span class="font-normal text-slate-400">${escapeHtml(n.kind)}${n.flavor ? ' · ' + escapeHtml(n.flavor) : ''}${n.pve_cluster && n.pve_cluster.name ? ' · PVE cluster ' + escapeHtml(n.pve_cluster.name) : ''}</span></span>
              <span class="flex flex-wrap items-center gap-2 justify-end">${autoBox}${rebootBox}${rebootBtn}${reboot}${state}</span>
            </div>${detail}${blocker}${msg}</div>`;
    }).join('');
    const apCount = document.getElementById('osu-autopatch-count');
    if (apCount) { const k = (d.nodes || []).filter(n => n.auto_patch).length; apCount.textContent = k ? `${k} node(s) approved` : 'no nodes approved — tick "Auto-patch" on a node'; }
    const when = d.checked_at ? new Date(d.checked_at * 1000).toLocaleString() : 'never';
    body.innerHTML = summary + (rows || '<p class="text-xs text-slate-400 italic">No nodes reporting.</p>') +
        `<p class="text-[11px] text-slate-400 mt-2">Last checked: ${escapeHtml(when)}</p>`;
    if (busy && !_osuPoll) _osuStartPoll();
}

function _renderSetupRemoteConsoleTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card} space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Remote Console ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <span id="rc-status" class="text-xs text-slate-400"></span>
            </div>
            <div class="rounded-md bg-amber-50 border border-amber-200 p-3 text-[11px] text-amber-800 leading-snug">
                Runs commands on the hub or a connected spoke/agent for troubleshooting — <b>Global-Admin only, every command is audit-logged</b>. Off by default.
                In diagnostic mode only a curated allowlist runs (systemctl, journalctl, tail, grep, ps, df, ip, git …).
                <b>Debug (shell) mode</b> unlocks arbitrary commands — enable it only while actively troubleshooting; this hub is internet-facing.
            </div>
            <div class="flex flex-wrap gap-6">
                <label class="flex items-center gap-2 text-sm text-slate-700">
                    <input type="checkbox" id="rc-enabled" class="w-4 h-4 text-green-600 rounded" onchange="saveExecConfig()">
                    Enable Remote Console
                </label>
                <label class="flex items-center gap-2 text-sm text-slate-700">
                    <input type="checkbox" id="rc-shell" class="w-4 h-4 text-red-600 rounded" onchange="saveExecConfig()">
                    Debug (shell) mode — allow <b>arbitrary</b> commands
                </label>
            </div>
            <div id="rc-runner" class="space-y-3 pt-3 border-t border-slate-100">
                <div class="flex flex-wrap gap-2 items-end">
                    <div class="space-y-1">
                        <label class="${labelCls}">Target</label>
                        <select id="rc-target" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 min-w-[220px]"><option value="hub">Hub (this box)</option></select>
                    </div>
                    <button onclick="loadExecTargets()" class="${btnSecCls} text-xs">↻ Targets</button>
                </div>
                <div class="space-y-1">
                    <label class="${labelCls}">Command</label>
                    <div class="flex gap-2">
                        <input type="text" id="rc-command" placeholder="systemctl status lm-agent" class="${inputCls} font-mono" onkeydown="if(event.key==='Enter')runExecCommand()">
                        <button onclick="runExecCommand()" class="${btnCls}" id="rc-run">Run</button>
                    </div>
                </div>
                <div id="rc-output-wrap" class="hidden">
                    <div class="flex justify-end mb-1">
                        <button onclick="copyRcOutput()" id="rc-copy" class="text-xs bg-slate-200 hover:bg-slate-300 text-slate-700 px-2 py-1 rounded-md font-semibold">📋 Copy</button>
                    </div>
                    <pre id="rc-output" class="bg-slate-900 text-slate-100 text-xs font-mono rounded-md p-3 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto"></pre>
                </div>
            </div>
        </div>`;
    loadExecConfig();
    loadExecTargets();
}

function _rcReflectEnabled(enabled) {
    const runner = document.getElementById('rc-runner');
    if (runner) { runner.classList.toggle('opacity-40', !enabled); runner.classList.toggle('pointer-events-none', !enabled); }
    const status = document.getElementById('rc-status');
    if (status) { status.textContent = enabled ? 'enabled' : 'disabled'; status.className = 'text-xs ' + (enabled ? 'text-green-600 font-bold' : 'text-slate-400'); }
    const sh = document.getElementById('rc-shell');
    if (sh) sh.disabled = !enabled;
}

async function loadExecConfig() {
    try {
        const r = await setupFetch('/api/exec/config');
        if (!r.ok) return;
        const d = await r.json();
        const en = document.getElementById('rc-enabled');
        const sh = document.getElementById('rc-shell');
        if (en) en.checked = !!d.enabled;
        if (sh) sh.checked = !!d.allow_shell;
        _rcReflectEnabled(!!d.enabled);
    } catch (_e) { /* leave defaults */ }
}

async function saveExecConfig() {
    const enabled = !!document.getElementById('rc-enabled')?.checked;
    let allow_shell = !!document.getElementById('rc-shell')?.checked;
    if (allow_shell && enabled &&
        !confirm('Enable DEBUG (shell) mode?\n\nThis lets a Global-Admin run ARBITRARY commands on the hub and any spoke/agent. This hub is internet-facing — only enable while actively troubleshooting, and turn it off after.')) {
        const sh = document.getElementById('rc-shell'); if (sh) sh.checked = false;
        allow_shell = false;
    }
    try {
        const r = await setupFetch('/api/exec/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled, allow_shell }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { if (typeof showToast === 'function') showToast('Failed: ' + (d.detail || r.status), 'error'); return; }
        const en = document.getElementById('rc-enabled'); if (en) en.checked = !!d.enabled;
        const sh = document.getElementById('rc-shell'); if (sh) sh.checked = !!d.allow_shell;
        _rcReflectEnabled(!!d.enabled);
    } catch (e) { if (typeof showToast === 'function') showToast('Error: ' + e.message, 'error'); }
}

async function loadExecTargets() {
    try {
        const r = await setupFetch('/api/exec/targets');
        if (!r.ok) return;
        const d = await r.json();
        const sel = document.getElementById('rc-target');
        if (!sel) return;
        const cur = sel.value;
        sel.innerHTML = (d.targets || []).map(t =>
            `<option value="${t.id}">${t.label}${t.kind === 'hub' ? '' : ' · ' + t.kind}</option>`).join('');
        if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
    } catch (_e) { /* keep hub-only */ }
}

async function runExecCommand() {
    const target = document.getElementById('rc-target')?.value || 'hub';
    const command = (document.getElementById('rc-command')?.value || '').trim();
    const out = document.getElementById('rc-output');
    const btn = document.getElementById('rc-run');
    if (!command) return;
    const wrap = document.getElementById('rc-output-wrap');
    if (wrap) wrap.classList.remove('hidden');
    if (out) { out.classList.remove('hidden'); out.textContent = 'Running…'; }
    if (btn) btn.disabled = true;
    try {
        const r = await setupFetch('/api/exec', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, command }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { if (out) out.textContent = '⛔ ' + (d.detail || ('HTTP ' + r.status)); return; }
        let text = '';
        if (d.error) text += '⛔ ' + d.error + '\n';
        if (d.stdout) text += d.stdout;
        if (d.stderr) text += (d.stdout ? '\n' : '') + '[stderr]\n' + d.stderr;
        text += `\n\n— exit ${d.rc}${d.mode ? ' · ' + d.mode + ' mode' : ''}${d.truncated ? ' · output truncated' : ''} —`;
        if (out) out.textContent = text.trim();
    } catch (e) {
        if (out) out.textContent = '⛔ ' + e.message;
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function copyRcOutput() {
    const out = document.getElementById('rc-output');
    const btn = document.getElementById('rc-copy');
    if (!out) return;
    const text = out.textContent || '';
    try {
        await navigator.clipboard.writeText(text);
        if (btn) { const t = btn.textContent; btn.textContent = '✓ Copied'; setTimeout(() => { btn.textContent = t; }, 1500); }
    } catch (e) {
        // Fallback (older browser / non-secure context): select the text so the
        // user can Ctrl-C manually.
        const range = document.createRange();
        range.selectNodeContents(out);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        if (btn) { const t = btn.textContent; btn.textContent = 'Select+Ctrl-C'; setTimeout(() => { btn.textContent = t; }, 2000); }
    }
}

// Setup → Tenant Config tile. GET /api/tenants (core/src/api.py get_tenants).
function _renderSetupTenantTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex justify-between items-center">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Tenants ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <div class="flex gap-2">
                        ${isAdmin() ? `<button onclick="syncTenantsFromNetBox()" class="${btnSecCls} text-xs">↓ Sync from NetBox</button>
                        <input type="text" id="new-tenant-id" placeholder="new-tenant-id" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500 w-40">
                        <button onclick="addTenant()" class="${btnCls}">+ Tenant</button>` : `<span class="text-[10px] text-slate-400 italic">edit only — create/sync/re-scope are Global-Admin</span>`}
                    </div>
                </div>
                <div id="tenant-list" class="space-y-2"></div>
                <div id="tenant-empty-state" class="py-8 text-center text-slate-400 italic text-sm">No tenants configured.</div>
                <div id="tenant-editor" class="hidden space-y-4 border-t border-slate-200 pt-4">
                    <p class="text-xs text-slate-500 font-bold uppercase">Editing: <span id="edit-tenant-id" class="font-mono text-[#01A982]"></span></p>
                    <div class="space-y-1"><label class="${labelCls}">Display Name</label><input type="text" id="tenant-name" class="${inputCls}"></div>
                    <div class="flex items-center gap-2"><input type="checkbox" id="tenant-active" class="w-4 h-4 text-green-600 rounded"><label class="text-sm text-slate-600">Set as active tenant</label></div>
                    ${isAdmin() ? `<div class="flex items-center gap-2"><input type="checkbox" id="tenant-shared" class="w-4 h-4 text-green-600 rounded"><label class="text-sm text-slate-600"><b>Shared tenant</b> — its spokes are visible to <b>all</b> tenants (objects still subnet-scoped). Only one tenant can be shared.</label></div>` : ''}
                    <div class="grid grid-cols-3 gap-4">
                        <div class="space-y-1"><label class="${labelCls}">VM Quota</label><input type="number" id="quota-vm" value="0" min="0" class="${inputCls}"></div>
                        <div class="space-y-1"><label class="${labelCls}">CPPM Quota</label><input type="number" id="quota-cppm" value="0" min="0" class="${inputCls}"></div>
                        <div class="space-y-1"><label class="${labelCls}">OPN Quota</label><input type="number" id="quota-opn" value="0" min="0" class="${inputCls}"></div>
                    </div>
                    <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider pt-2">Spoke Scoping</p>
                    <div class="grid grid-cols-3 gap-4">
                        <div class="space-y-1">
                            <label class="${labelCls}">NetBox Tenant Slug</label>
                            <input type="text" id="tenant-netbox-slug" placeholder="acme-corp" class="${inputCls}">
                            <p class="text-[10px] text-slate-400">Filters devices, IPs, and prefixes in NetBox by this tenant slug.</p>
                        </div>
                        <div class="space-y-1">
                            <label class="${labelCls}">Proxmox Tag</label>
                            <input type="text" id="tenant-proxmox-tag" placeholder="tenant-acme" class="${inputCls}">
                            <p class="text-[10px] text-slate-400">Only show VMs tagged with this value in Proxmox.</p>
                        </div>
                        <div class="space-y-1">
                            <label class="${labelCls}">LDAP Base DN</label>
                            <input type="text" id="tenant-ldap-base-dn" placeholder="ou=acme,dc=corp,dc=com" class="${inputCls}">
                            <p class="text-[10px] text-slate-400">Scopes LDAP user/group queries to this OU.</p>
                        </div>
                    </div>
                    <div class="flex justify-end gap-2"><button onclick="saveTenantConfig()" class="${btnCls}">Save</button><button onclick="closeTenantEditor()" class="${btnSecCls}">Cancel</button></div>
                </div>
            </div>`;
    loadTenantConfig();
}

// Setup → User Access tile. GET /api/users (core/src/api.py get_users).
function _renderSetupUserAccessTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex justify-between items-center">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">User Management ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="showAddUserModal()" class="${btnCls}">+ Add User</button>
                </div>
                <div class="overflow-hidden rounded-md border border-slate-200">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr><th class="px-4 py-3">User</th><th class="px-4 py-3">Auth</th><th class="px-4 py-3">Tenants</th><th class="px-4 py-3">Groups</th><th class="px-4 py-3 text-center">Admin</th><th class="px-4 py-3 text-center">View</th><th class="px-4 py-3 text-center">Edit</th><th class="px-4 py-3 text-center">HV</th><th class="px-4 py-3 text-center">FW</th><th class="px-4 py-3 text-center">DNS</th><th class="px-4 py-3 text-center">NAC</th><th class="px-4 py-3 text-center">NW</th><th class="px-4 py-3 text-center">IPAM</th><th class="px-4 py-3 text-center">CS</th><th class="px-4 py-3 text-center">CON</th><th class="px-4 py-3 text-center">CW</th><th class="px-4 py-3"></th></tr></thead>
                        <tbody id="user-permissions-body" class="divide-y divide-slate-200"><tr><td colspan="17" class="px-4 py-8 text-center text-slate-400 italic animate-pulse">Loading users…</td></tr></tbody>
                    </table>
                </div>
                <p class="text-[11px] text-slate-400 mt-2">Check-marks show <em>effective</em> access (permission groups ∪ per-user grants). Manage bundles below.</p>
            </div>
            <div class="${card} mt-4">
                <div class="flex justify-between items-center">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Permission Groups</h3>
                    <button onclick="showGroupModal()" class="${btnCls}">+ New Group</button>
                </div>
                <p class="text-[11px] text-slate-400 mb-2">A group bundles module permissions; assign users to groups instead of setting each flag per user. Optionally map an LDAP group for directory-driven access.</p>
                <div class="overflow-hidden rounded-md border border-slate-200">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr><th class="px-4 py-3">Group</th><th class="px-4 py-3">Permissions</th><th class="px-4 py-3">LDAP Group</th><th class="px-4 py-3 text-center">Members</th><th class="px-4 py-3"></th></tr></thead>
                        <tbody id="permission-groups-body" class="divide-y divide-slate-200"><tr><td colspan="5" class="px-4 py-6 text-center text-slate-400 italic animate-pulse">Loading groups…</td></tr></tbody>
                    </table>
                </div>
            </div>`;
    loadUsers();
    loadGroups();
}



// System → Sync tile. The unified home for cross-system sync schedules:
//   1. IPAM → NAC endpoint sync (moved here from Setup → NAC)
//   2. Hypervisor (Proxmox) → NetBox VM sync (moved here from Setup → IPAM)
// Each card owns its own source dropdown, schedule, Save + Sync-now actions,
// and per-tenant last-sync status. Loaders / actions (defined below):
//   loadEndpointSyncSources/Config/Status + runEndpointSyncNow/saveEndpointSyncConfig
//   loadVmSyncSources/Config/Status       + runVmSyncNow/saveVmSyncConfig
// Backing routes: /setup/endpoint-sync/{sources,status,run} and
// /setup/vm-sync/{sources,status,run}, plus the shared /setup/config
// schedule read/write (core/src/api.py get_endpoint_sync_* / vm_sync_*).
// ── Setup → Self-Backup tile ──────────────────────────────────────────
// Scheduled hub-state backup: local rotated archive + optional SSH copy.
// Global-Admin-only — the /setup/backup/* routes are admin-gated server-side
// (and the /setup/ prefix is admin-gated by the middleware). Config persists
// through the shared POST /setup/config ({config:{self_backup: merged}}).
// IMPORTANT: /setup/config does a top-level gc.update({self_backup: {...}}),
// which REPLACES the whole subtree — so Save sends the full merged dict
// (form fields over the cached config) to preserve the server-managed
// last_backup_at / last_copy_at / last_error fields. Backing routes:
// /setup/backup/{run,test-copy,status} (core/src/routes/self_backup.py).
function _renderSetupSelfBackupTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Scheduled Self-Backup ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="runBackupNow()" id="sb-run-btn" class="${btnCls}">Back up now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Periodically archives the hub state + key stores (Fernet-encrypted at rest already; the archive is an additional rotated copy) to <code>&lt;data_dir&gt;/self-backup/</code>. Archives are optionally Fernet-encrypted (<code>.tgz.enc</code>) and pruned to <em>keep_count</em>. The hub <code>.env</code> (secrets) is excluded unless explicitly included below. <strong>Global Admin only.</strong></p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="sb-enabled" class="w-4 h-4 text-green-600 rounded">Enable scheduled backup</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (hours)</label>
                        <input type="number" id="sb-interval" min="1" value="24" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Keep (count)</label>
                        <input type="number" id="sb-keep" min="1" value="7" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="sb-encrypt" class="w-4 h-4 text-green-600 rounded" checked>Encrypt archive (.tgz.enc)</label>
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="sb-include-env" class="w-4 h-4 text-green-600 rounded">Include .env (secrets)</label>
                </div>
                <div class="mt-4 flex items-center justify-between gap-3">
                    <span class="text-xs text-slate-400">Archives are encrypted with the hub Fernet key — restore requires the same <code>LM_FERNET_KEY</code>.</span>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">SSH Copy to Remote</h3>
                    <button onclick="testBackupCopy()" id="sb-test-btn" class="${btnSecCls}">Test copy</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Optionally <code>scp</code> each backup to a remote host using a private key on the hub. The hub SSH client must already have the key (path only is stored here; key material is never read by the WebUI). <code>after_each_backup</code> pushes right after every backup; <code>own_schedule</code> pushes on its own interval below.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="sb-copy-enabled" class="w-4 h-4 text-green-600 rounded">Enable SSH copy</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Copy mode</label>
                        <select id="sb-copy-mode" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="after_each_backup">After each backup</option>
                            <option value="own_schedule">Own schedule</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Copy interval (hours)</label>
                        <input type="number" id="sb-copy-interval" min="1" value="24" class="w-28 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="sb-strict-hostkey" class="w-4 h-4 text-green-600 rounded">StrictHostKeyChecking</label>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
                    <div class="space-y-1">
                        <label class="${labelCls}">SSH host</label>
                        <input type="text" id="sb-ssh-host" placeholder="backup.example.com" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Port</label>
                        <input type="number" id="sb-ssh-port" min="1" max="65535" value="22" class="w-28 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">User</label>
                        <input type="text" id="sb-ssh-user" placeholder="backup" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Remote path</label>
                        <input type="text" id="sb-ssh-path" placeholder="/backups/lm-hub/" class="${inputCls}">
                    </div>
                    <div class="space-y-1 sm:col-span-2">
                        <label class="${labelCls}">Private key path (on hub)</label>
                        <input type="text" id="sb-ssh-keyfile" placeholder="/root/.ssh/lm_backup_id_ed25519" class="${inputCls}">
                    </div>
                </div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Status &amp; Archives</h3>
                <div id="sb-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                <div class="mt-4">
                    <div class="flex items-center justify-between mb-2">
                        <div class="text-xs font-bold text-slate-500 uppercase tracking-wider">Local archives</div>
                        <div class="flex items-center gap-2">
                            <input type="file" id="sb-upload-file" accept=".tar.gz,.tgz.enc,application/gzip,application/octet-stream" class="hidden" onchange="uploadSelfBackup(this)">
                            <button type="button" onclick="document.getElementById('sb-upload-file').click()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1 rounded-md text-xs font-bold">Upload archive…</button>
                        </div>
                    </div>
                    <p class="text-[11px] text-slate-400 mb-2">Download an archive to keep off-box, or upload one back onto this hub for a system-recovery restore.</p>
                    <div id="sb-archives" class="space-y-1"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
        `;
    loadSelfBackupStatus();
    // Auto-save on change — one handler merges both the Schedule + SSH Copy
    // cards, so an edit in either saves the whole self-backup config. The
    // restore file input + action buttons are excluded by the allowlist mapper.
    _attachAutoSave(content, _selfBackupSaveFnFor, 'selfBackupAutoSave');
}

function _sbFmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KiB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MiB';
    return (n / 1073741824).toFixed(2) + ' GiB';
}

function _sbFmtTs(ts) {
    const v = Number(ts) || 0;
    if (!v) return '<span class="text-slate-400">never</span>';
    try { return new Date(v * 1000).toLocaleString(); }
    catch (e) { return '<span class="text-slate-400">—</span>'; }
}

// Populate the config form + status panel from GET /setup/backup/status.
// Caches the full config subtree so Save can merge form fields over it
// (preserving the server-managed last_backup_at / last_copy_at / last_error).
async function loadSelfBackupStatus() {
    let data;
    try {
        data = await apiJson('/setup/backup/status');
    } catch (e) {
        const st = document.getElementById('sb-status');
        if (st) st.innerHTML = `<p class="text-xs text-red-600">Failed to load status: ${escapeHtml(e.message)}</p>`;
        return;
    }
    window.__lmSelfBackupCfg = data || {};
    const setv = (id, v) => { const el = document.getElementById(id); if (el && document.activeElement !== el) el.value = v; };
    const setc = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
    setc('sb-enabled', data.enabled);
    setv('sb-interval', data.backup_interval_hours ?? 24);
    setv('sb-keep', data.keep_count ?? 7);
    setc('sb-encrypt', data.encrypt_archive !== false);
    setc('sb-include-env', !!data.include_env);
    setc('sb-copy-enabled', !!data.copy_enabled);
    setv('sb-copy-mode', data.copy_mode || 'after_each_backup');
    setv('sb-copy-interval', data.copy_interval_hours ?? 24);
    setc('sb-strict-hostkey', !!data.ssh_strict_hostkey);
    setv('sb-ssh-host', data.ssh_host || '');
    setv('sb-ssh-port', data.ssh_port || 22);
    setv('sb-ssh-user', data.ssh_user || '');
    setv('sb-ssh-path', data.ssh_path || '');
    setv('sb-ssh-keyfile', data.ssh_keyfile || '');

    const errLine = data.last_error
        ? `<div class="text-xs text-red-600">⚠ last error: ${escapeHtml(String(data.last_error))}</div>`
        : '';
    const latest = data.latest
        ? `Latest: <code class="text-slate-700">${escapeHtml(data.latest)}</code>`
        : '<span class="text-slate-400">no archive yet</span>';
    const st = document.getElementById('sb-status');
    if (st) st.innerHTML = `
        <div class="text-xs text-slate-600">Scheduled backup: <strong>${data.enabled ? 'enabled' : 'disabled'}</strong> · interval ${data.backup_interval_hours ?? 24}h · keep ${data.keep_count ?? 7}</div>
        <div class="text-xs text-slate-600">Last backup: ${_sbFmtTs(data.last_backup_at)}</div>
        <div class="text-xs text-slate-600">Last SSH copy: ${_sbFmtTs(data.last_copy_at)} ${data.copy_enabled ? '' : '<span class="text-slate-400">(copy disabled)</span>'}</div>
        <div class="text-xs text-slate-600">${latest} · ${data.backup_count ?? 0} archive(s) · ${_sbFmtBytes(data.total_bytes)}</div>
        ${errLine}
    `;

    const arc = document.getElementById('sb-archives');
    if (arc) {
        const files = Array.isArray(data.backups) ? data.backups : [];
        if (!files.length) {
            arc.innerHTML = '<p class="text-xs text-slate-400 italic">No archives yet — click “Back up now” to take one.</p>';
        } else {
            arc.innerHTML = files.map(f => {
                const when = (() => { try { return new Date((f.mtime || 0) * 1000).toLocaleString(); } catch (e) { return '—'; } })();
                return `<div class="flex items-center justify-between text-xs text-slate-600 py-1 border-b border-slate-100 last:border-0">
                    <code class="break-all">${escapeHtml(f.name)}</code>
                    <span class="ml-3 whitespace-nowrap flex items-center gap-3">
                        <span class="text-slate-400">${_sbFmtBytes(f.size)} · ${when}</span>
                        <button type="button" onclick="downloadSelfBackup('${escapeHtml(f.name).replace(/'/g, "\\'")}')" class="text-[#01A982] hover:underline font-bold">Download</button>
                    </span>
                </div>`;
            }).join('');
        }
    }
}

async function downloadSelfBackup(name) {
    try {
        const r = await setupFetch('/setup/backup/download?name=' + encodeURIComponent(name), { _keepOnNavigate: true });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = name;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    } catch (e) { showToast('Download failed: ' + (e.message || e), 'error'); }
}

async function uploadSelfBackup(input) {
    const file = input && input.files && input.files[0];
    if (!file) return;
    if (!/\.(tar\.gz|tgz\.enc)$/i.test(file.name)) {
        showToast('Pick a .tar.gz or .tgz.enc backup archive.', 'error'); input.value = ''; return;
    }
    try {
        const fd = new FormData();
        fd.append('file', file, file.name);
        const d = await apiJson('/setup/backup/upload', { method: 'POST', body: fd });
        showToast(`Uploaded ${d.name} (${_sbFmtBytes(d.size)}). It now lists as a local archive.`, 'success');
        loadSelfBackupStatus();
    } catch (e) { showToast('Upload failed: ' + (e.message || e), 'error'); }
    finally { input.value = ''; }
}
window.downloadSelfBackup = downloadSelfBackup; window.uploadSelfBackup = uploadSelfBackup;

// Read the form fields, merge over the cached full config, and POST. Sending
// the whole subtree (not just changed fields) because /setup/config replaces
// the self_backup key at the top level — this preserves last_*_at / last_error.
async function saveSelfBackupConfig() {
    const btn = document.getElementById('sb-save-btn') || document.getElementById('sb-copy-save-btn');
    const cur = window.__lmSelfBackupCfg || {};
    const merged = Object.assign({}, cur, {
        enabled: document.getElementById('sb-enabled')?.checked ? true : false,
        backup_interval_hours: Math.max(1, parseInt(document.getElementById('sb-interval')?.value, 10) || 24),
        keep_count: Math.max(1, parseInt(document.getElementById('sb-keep')?.value, 10) || 7),
        include_env: document.getElementById('sb-include-env')?.checked ? true : false,
        encrypt_archive: document.getElementById('sb-encrypt')?.checked ? true : false,
        copy_enabled: document.getElementById('sb-copy-enabled')?.checked ? true : false,
        copy_mode: document.getElementById('sb-copy-mode')?.value || 'after_each_backup',
        copy_interval_hours: Math.max(1, parseInt(document.getElementById('sb-copy-interval')?.value, 10) || 24),
        ssh_host: (document.getElementById('sb-ssh-host')?.value || '').trim(),
        ssh_port: Math.min(65535, Math.max(1, parseInt(document.getElementById('sb-ssh-port')?.value, 10) || 22)),
        ssh_user: (document.getElementById('sb-ssh-user')?.value || '').trim(),
        ssh_path: (document.getElementById('sb-ssh-path')?.value || '').trim(),
        ssh_keyfile: (document.getElementById('sb-ssh-keyfile')?.value || '').trim(),
        ssh_strict_hostkey: document.getElementById('sb-strict-hostkey')?.checked ? true : false,
    });
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const res = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { self_backup: merged } }),
        });
        if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || res.status); }
        window.__lmSelfBackupCfg = merged;
        if (typeof showToast === 'function') showToast('Self-backup config saved (applies live).', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast('Save failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save Schedule'; }
    }
}

async function runBackupNow() {
    const btn = document.getElementById('sb-run-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Backing up…'; }
    try {
        const r = await setupFetch('/setup/backup/run', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok || d.status === 'error') throw new Error(d.error || d.detail || r.status);
        const enc = d.encrypted ? ' (encrypted)' : '';
        const copy = d.copy ? ` · copy: ${d.copy.status || 'ok'}` : '';
        if (typeof showToast === 'function') showToast(`Backup ok: ${d.name} · ${_sbFmtBytes(d.size)}${enc}${copy}`, 'success');
        loadSelfBackupStatus();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Backup failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Back up now'; }
    }
}

async function testBackupCopy() {
    const btn = document.getElementById('sb-test-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
    try {
        const r = await setupFetch('/setup/backup/test-copy', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok || d.status === 'error') throw new Error(d.error || d.detail || r.status);
        if (typeof showToast === 'function') showToast(`Copy ok: ${d.file || ''}`, 'success');
        loadSelfBackupStatus();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Copy test failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Test copy'; }
    }
}

function _renderSetupSyncTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="mb-4 flex items-center justify-between">
            <h2 class="text-base font-bold text-slate-700">Sync settings ${helpIcon('lm-hub', null, 'Hub help')}</h2>
            <span class="text-xs text-slate-400 italic">Auto-saves on change — no Save button.</span>
        </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">GitHub Repo Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="repo-sync-run-btn" onclick="runRepoSyncNow()" class="${btnCls}">Sync now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Scheduled replication of <strong>all repos</strong>: pulls the hub tree + <code>provisioning_repos/*</code> locally and pushes <code>SPOKE_UPDATE</code> to every approved spoke (pxmx / opnsense / cs / cppm / netbox / ldap / nw / le, plus the in-repo dns / dhcp / console / statuspage roles) every <em>interval</em> (default 15 min). The hub self-restarts only when its own code changed (rolled back if it fails to boot); each spoke self-pulls and restarts only on its own version change. Replaces the old 1-hour auto-update loop — this is the single scheduled sync.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="repo-sync-enabled" class="w-4 h-4 text-green-600 rounded" checked>Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="repo-sync-interval" min="1" value="15" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync</div>
                    <div id="repo-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">IPAM ↔ NAC Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="ep-sync-run-btn" onclick="runEndpointSyncNow()" class="${btnCls}">Sync now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Bidirectional. <strong>Forward (IPAM → NAC):</strong> periodically pulls endpoint records (IP / MAC / tenant) from the selected IPAM source and populates ClearPass Device Inventory via the CPPM spoke. The IPAM source is the source of truth — each sync overwrites the tenant's CPPM endpoint set to match. Also fires automatically after any IPAM edit made through the LM module. <strong>Reverse (NAC → IPAM, realtime):</strong> the sub-block below pulls ClearPass Access Tracker / session data (MAC, IP, switch IP/port) every ~1 min and adds to NetBox the devices not already present (only-add-missing — NetBox stays source of truth). NetBox is registered today; the design is modular so another IPAM product can be swapped in by adding one entry to the hub's IPAM_SOURCES registry.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="ep-sync-enabled" class="w-4 h-4 text-green-600 rounded">Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Pull from (IPAM source)</label>
                        <select id="ep-sync-source" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="netbox">NetBox</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Schedule</label>
                        <select id="ep-sync-mode" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="interval">Every (interval)</option>
                            <option value="daily">Daily at time</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="ep-sync-interval" min="1" value="60" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Daily time (HH:MM, 24h)</label>
                        <input type="time" id="ep-sync-time" value="02:00" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync per tenant</div>
                    <div id="endpoint-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
                <div class="mt-5 pt-4 border-t border-slate-200">
                    <div class="flex items-center justify-between mb-3">
                        <div class="text-xs font-bold text-slate-500 uppercase tracking-wider">Realtime NAC → IPAM (reverse)</div>
                        <button id="rt-nac-sync-run-btn" onclick="runRealtimeNacNow()" class="${btnCls}">Sync now</button>
                    </div>
                    <p class="text-xs text-slate-400 mb-3">Pulls ClearPass Access Tracker sessions started in the last <em>lookback</em> minutes every <em>interval</em> minutes and adds to NetBox the MACs not already present — each with a NIC interface (native MAC) + framed IP + a cable to a switch device's port interface. Only-add-missing: existing MACs are skipped (never duplicated, never deleted). Tenant attribution by IP prefix containment.</p>
                    <div class="flex flex-wrap items-end gap-4">
                        <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="rt-nac-sync-enabled" class="w-4 h-4 text-green-600 rounded">Enable realtime reverse sync</label>
                        <div class="space-y-1">
                            <label class="${labelCls}">Interval (minutes)</label>
                            <input type="number" id="rt-nac-sync-interval" min="1" value="1" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        </div>
                        <div class="space-y-1">
                            <label class="${labelCls}">Lookback (minutes)</label>
                            <input type="number" id="rt-nac-sync-lookback" min="1" value="2" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        </div>
                    </div>
                    <div class="mt-4">
                        <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last reverse sync per tenant</div>
                        <div id="rt-nac-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                    </div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">DHCP → DNS (real-time)</h3>
                </div>
                <p class="text-xs text-slate-400 mb-3">Kea registers each lease's hostname in Unbound the moment the lease is committed, and removes it on release/expiry — suffixed with the lease's DHCP scope domain. The hub keeps every DHCP spoke's hook in this state (checked each DNS/DHCP sync cycle). The NetBox → DNS sync remains the durable backstop.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="dns-hook-enabled" class="w-4 h-4 text-green-600 rounded" checked>Enable real-time DHCP → DNS registration</label>
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="dns-hook-register-ptr" class="w-4 h-4 text-green-600 rounded">Also register PTR records</label>
                </div>
                <div id="dns-hook-status" class="text-xs text-slate-400 mt-3"></div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hypervisor → IPAM Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="vm-sync-run-btn" onclick="runVmSyncNow()" class="${btnCls}">Sync now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Periodically pulls each tenant's VMs from the selected hypervisor source (Proxmox via the pxmx spoke, scoped by the tenant's proxmox_tag) and mirrors them into NetBox virtualization records — vCPUs / disk / cluster / primary IP4 / NetBox tenant, matched by a <code>proxmox_unique_id</code> custom field. The hypervisor is the source of truth — each sync overwrites the tenant's NetBox VM set to match (stale records are deleted). Also fires automatically after a VM lifecycle action (start/stop/restart/snapshot). Proxmox is registered today; the design is modular so another hypervisor product can be swapped in by adding one entry to the hub's HYPERVISOR_SOURCES registry.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="vm-sync-enabled" class="w-4 h-4 text-green-600 rounded">Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Pull from (hypervisor source)</label>
                        <select id="vm-sync-source" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="proxmox">Proxmox</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Sync from server</label>
                        <select id="vm-sync-agent" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="">All connected servers</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Schedule</label>
                        <select id="vm-sync-mode" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="interval">Every (interval)</option>
                            <option value="daily">Daily at time</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="vm-sync-interval" min="1" value="60" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Daily time (HH:MM, 24h)</label>
                        <input type="time" id="vm-sync-time" value="03:00" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync per tenant</div>
                    <div id="vm-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Firewall → IPAM Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="fw-sync-run-btn" onclick="runFwDiscoveryNow()" class="${btnCls}">Sync now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Pulls DHCP leases + the ARP table from the selected firewall (OPNsense via the firewall spoke), attributes each discovered device to a tenant by prefix containment (the device IP must sit inside one of the tenant's NetBox prefixes), and mirrors them into NetBox DCIM devices + IP records — tenant-tagged, with the MAC written onto the IP's <code>mac_address</code> custom field (which feeds the IPAM → NAC endpoint sync, so static-IP devices DHCP can't see reach ClearPass). The firewall is the source of truth — each sync overwrites the tenant's discovered-device set to match (stale records are deleted). Devices whose IP matches no tenant prefix are dropped + counted. OPNsense is registered today; the design is modular so another firewall product can be swapped in by adding one entry to the hub's FIREWALL_DISCOVERY_SOURCES registry.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="fw-sync-enabled" class="w-4 h-4 text-green-600 rounded">Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Pull from (firewall source)</label>
                        <select id="fw-sync-source" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="opnsense">OPNsense</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Data to pull</label>
                        <select id="fw-sync-data" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="both">DHCP + ARP</option>
                            <option value="dhcp">DHCP leases only</option>
                            <option value="arp">ARP table only</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Firewall</label>
                        <select id="fw-sync-firewall" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="">All connected firewalls</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Schedule</label>
                        <select id="fw-sync-mode" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="interval">Every (interval)</option>
                            <option value="daily">Daily at time</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="fw-sync-interval" min="1" value="60" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Daily time (HH:MM, 24h)</label>
                        <input type="time" id="fw-sync-time" value="02:00" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox device role (slug)</label>
                        <input id="fw-sync-role" placeholder="discovered" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox device type (slug)</label>
                        <input id="fw-sync-type" placeholder="discovered" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox site (slug, optional)</label>
                        <input id="fw-sync-site" placeholder="" class="${inputCls}">
                    </div>
                </div>
                <div class="mt-4 flex items-center justify-end gap-3">
                    <span class="text-xs text-slate-400">Defaults apply to newly created devices only.</span>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync per tenant</div>
                    <div id="fw-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Network Devices → IPAM Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="nw-sync-run-btn" onclick="runNwDiscoveryNow()" class="${btnCls}">Sync now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Pulls the ARP table from every device on the selected network-device source (switches + gateways via the nw spoke, attributed to the tenant by prefix containment), and mirrors each discovered IP↔MAC into NetBox DCIM devices + IP records — tenant-tagged <code>Network Devices</code>, with the MAC written onto the IP's <code>mac_address</code> custom field (which feeds the IPAM → NAC endpoint sync). The network devices are the source of truth — each sync overwrites the tenant's nw-discovered device set to match (stale nw-owned records are deleted; firewall-discovered records are never touched). Devices whose IP matches no tenant prefix are dropped + counted. Switch/gateway products are registered in the hub's NW_DISCOVERY_SOURCES registry.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="nw-sync-enabled" class="w-4 h-4 text-green-600 rounded">Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Pull from (network source)</label>
                        <select id="nw-sync-source" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="nw">Network Devices</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Schedule</label>
                        <select id="nw-sync-mode" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="interval">Every (interval)</option>
                            <option value="daily">Daily at time</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="nw-sync-interval" min="1" value="60" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Daily time (HH:MM, 24h)</label>
                        <input type="time" id="nw-sync-time" value="02:30" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox device role (slug)</label>
                        <input id="nw-sync-role" placeholder="discovered" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox device type (slug)</label>
                        <input id="nw-sync-type" placeholder="discovered" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox site (slug, optional)</label>
                        <input id="nw-sync-site" placeholder="" class="${inputCls}">
                    </div>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync per tenant</div>
                    <div id="nw-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Console → IPAM Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <span class="text-xs text-slate-400">Event-driven</span>
                </div>
                <p class="text-xs text-slate-400 mb-3">When a Console spoke <b>auto-identifies</b> a device on a serial port (hostname / vendor / model / <b>serial number</b> / MAC / IP scraped from the console session), the hub mirrors it into NetBox DCIM as a tenant-tagged device (<code>discovered_from = Console</code>). There is no schedule — each identify pushes immediately. The sink matches an existing device by <b>serial → IP → MAC → hostname</b> (serial is the strongest key, so a console-found box is reconciled with its firewall/switch-discovered record instead of duplicating). The device is attributed to the port's effective tenant; a tenant with no <code>netbox_tenant_slug</code> is skipped. Hardware is the source of truth: a device seen on the console is real.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="console-sync-enabled" class="w-4 h-4 text-green-600 rounded">Sync identified devices to NetBox</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Source of truth</label>
                        <select id="console-sync-sot" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="external">Console feed (overwrite)</option>
                            <option value="netbox">NetBox (fill gaps only)</option>
                        </select>
                    </div>
                </div>
                <div class="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox device role (slug)</label>
                        <input id="console-sync-role" placeholder="discovered" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox device type (slug)</label>
                        <input id="console-sync-type" placeholder="discovered" class="${inputCls}">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">NetBox site (slug, optional)</label>
                        <input id="console-sync-site" placeholder="" class="${inputCls}">
                    </div>
                </div>
                <div class="mt-4 flex items-center justify-end gap-3">
                    <span class="text-xs text-slate-400">Defaults apply to newly created devices only.</span>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Recent console syncs per tenant</div>
                    <div id="console-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Staleness Sweep ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="staleness-sweep-run-btn" onclick="runStalenessSweepNow()" class="${btnCls}">Sweep now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Cluster-wide NetBox age-out of sync-owned objects. A device / VM / IP the syncs stop seeing ages out: not seen for <em>stale days</em> → status <strong>offline</strong> (a <code>decommissioned_at</code> clock starts); offline + decommissioned for <em>delete days</em> → <strong>deleted</strong> (its IPs free automatically); an unassigned stale IP → freed. Objects with no <code>last_seen</code> custom field (hand-managed inventory the syncs never touched) are <strong>never swept</strong>. Each detection stamps <code>last_seen</code>, so an object the syncs keep seeing is never swept.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="staleness-sweep-enabled" class="w-4 h-4 text-green-600 rounded">Enable scheduled sweep</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="staleness-sweep-interval" min="1" value="60" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Stale after (days)</label>
                        <input type="number" id="staleness-sweep-stale-days" min="1" value="7" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Delete after (days)</label>
                        <input type="number" id="staleness-sweep-delete-days" min="1" value="30" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sweep</div>
                    <div id="staleness-sweep-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Device De-duplication ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <div class="flex gap-2">
                        <button id="netbox-dedupe-scan-btn" onclick="runNetboxDedupe(false)" class="${btnCls}">Scan (dry run)</button>
                        <button id="netbox-dedupe-merge-btn" onclick="runNetboxDedupe(true)" class="${btnCls}">Merge duplicates</button>
                    </div>
                </div>
                <p class="text-xs text-slate-400 mb-3">Finds NetBox devices that are the <strong>same physical box</strong> landed as separate records — grouped by shared <strong>serial</strong> or <strong>MAC</strong> (the pre-existing duplicates the unified sync ladder can't retroactively fix). <strong>Scan</strong> is a dry run that lists the duplicate groups it would merge; <strong>Merge</strong> keeps the most complete record per group (back-filling any identity gaps from the duplicates), re-points their IPs onto it, and deletes the rest. Network hardware is the source of truth.</p>
                <div id="netbox-dedupe-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Click “Scan (dry run)” to preview duplicate device groups.</p></div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spoke Out-of-Contact Alerts ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                </div>
                <p class="text-xs text-slate-400 mb-3">Forgiving liveness alerting, separate from the realtime heartbeat traffic-light. A spoke that blips for a few seconds (restart, WAN jitter) stays quiet; only once an approved spoke has been <strong>out of contact</strong> for <em>warn minutes</em> does a <strong>warning</strong> fire, and after <em>error minutes</em> it escalates to <strong>error</strong> (which also lands in the Error Log / ab feed). Decoupled from the 300s recovery watchdog — that still restarts stranded spokes on its own schedule.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="spoke-alert-enabled" class="w-4 h-4 text-green-600 rounded">Enable out-of-contact alerts</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Warn after (minutes)</label>
                        <input type="number" id="spoke-alert-warn-min" min="1" value="5" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Error after (minutes)</label>
                        <input type="number" id="spoke-alert-error-min" min="1" value="30" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Active alerts</div>
                    <div id="spoke-alerts-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hub-Contact Watchdog ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                </div>
                <p class="text-xs text-slate-400 mb-3">Fleet-wide self-recovery for spokes &amp; agents that lose the hub. When a node can't reach the hub it escalates: <strong>restart the service</strong> after the first threshold, <strong>reboot the host</strong> after the second, then <strong>sleep</strong> and retry; after <em>max runs</em> it gives up and stays offline. The setting is pushed to every node and stored locally, so it still fires when the hub is unreachable. <strong class="text-amber-600">Caution:</strong> the reboot stage restarts the whole machine — on a Proxmox host agent that cycles every VM on it. Off by default.</p>
                <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="hcw-enabled" class="w-4 h-4 text-green-600 rounded">Enable hub-contact watchdog (fleet-wide)</label>
                <div class="flex flex-wrap items-end gap-4">
                    <div class="space-y-1">
                        <label class="${labelCls}">Restart service after (min)</label>
                        <input type="number" id="hcw-service-min" min="1" value="5" class="w-28 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Reboot host after (min)</label>
                        <input type="number" id="hcw-reboot-min" min="2" value="15" class="w-28 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Sleep between runs (min)</label>
                        <input type="number" id="hcw-sleep-min" min="1" value="60" class="w-28 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Max runs (then give up)</label>
                        <input type="number" id="hcw-max-runs" min="1" value="3" class="w-28 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <p id="hcw-msg" class="text-xs text-slate-400 mt-3"></p>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Hub TLS Verification ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                </div>
                <p class="text-xs text-slate-400 mb-3">Whether spokes &amp; agents verify the hub's TLS certificate when they connect — set fleet-wide here instead of re-running installers. Pushed to every node and stored locally (overrides the install-time <code>--tls-verify</code>); a node restarts only if its setting changes. <strong>Always verify</strong> is refused by any node that can't verify the hub cert right now (listed below), so it can't lock a node out. Co-located (loopback) spokes and role sub-spokes are not affected.</p>
                <div class="space-y-1">
                    <label class="${labelCls}">Spoke/agent hub-cert verification</label>
                    <select id="htv-mode" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="install">Per-install (installer setting)</option>
                        <option value="auto">Auto — verify when possible, required once verified</option>
                        <option value="on">Always verify</option>
                        <option value="off">Off (not recommended)</option>
                    </select>
                </div>
                <p id="htv-msg" class="text-xs text-slate-400 mt-3"></p>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Source of Truth ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                </div>
                <p class="text-xs text-slate-400 mb-3">Per-module owner: a module's source of truth is never overwritten by a sync that disagrees. <strong>External</strong> = the feed owns the object (the sync overwrites NetBox to match — e.g. Proxmox owns VMs, the discovery feed owns device MAC/IP). <strong>NetBox</strong> = NetBox owns the object (only-add-missing — existing records are refreshed but never clobbered, protecting hand-managed inventory). Defaults: VMs = Proxmox (external), Devices = NetBox, Access Tracker = NetBox, Endpoint sync = NetBox.</p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="space-y-1">
                        <label class="${labelCls}">VMs (Hypervisor → IPAM)</label>
                        <select id="sot-vm-sync" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="external">Proxmox (external — overwrite)</option>
                            <option value="netbox">NetBox (only-add-missing)</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Devices (Firewall → IPAM)</label>
                        <select id="sot-device-sync" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="external">OPNsense (external — overwrite)</option>
                            <option value="netbox">NetBox (only-add-missing)</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Access Tracker (NAC → IPAM)</label>
                        <select id="sot-access-tracker" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="netbox">NetBox (only-add-missing)</option>
                            <option value="external">External (overwrite)</option>
                        </select>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Endpoint sync (IPAM → NAC)</label>
                        <select id="sot-endpoint-sync" class="bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="netbox">NetBox (only-add-missing)</option>
                            <option value="external">External (overwrite)</option>
                        </select>
                    </div>
                </div>
            </div>`;
    loadEndpointSyncSources();
    loadEndpointSyncConfig();
    loadEndpointSyncStatus();
    loadRealtimeNacSyncConfig();
    loadRealtimeNacSyncStatus();
    loadDnsHookConfig();
    loadVmSyncSources();
    loadVmSyncConfig();
    loadVmSyncStatus();
    loadFwDiscoverySources();
    loadFwDiscoveryConfig();
    loadFwDiscoveryStatus();
    loadNwDiscoverySources();
    loadNwDiscoveryConfig();
    loadNwDiscoveryStatus();
    loadConsoleNetboxSync();
    loadConsoleNetboxStatus();
    loadStalenessSweepConfig();
    loadStalenessSweepStatus();
    loadRepoSyncConfig();
    loadRepoSyncStatus();
    loadSourceOfTruthConfig();
    loadSpokeAlertConfig();
    loadSpokeAlerts();
    loadHubWatchdog();
    loadHubTlsVerify();
    // Auto-save: one delegated `change` listener maps the edited field's id
    // prefix to its card's save handler and fires it — same no-Save-button
    // model as the Proxmox auto-provisioning card. Programmatic value sets
    // by the load* functions above do NOT emit `change`, so rendering does
    // not trigger saves.
    _attachAutoSave(content, _syncSaveFnFor, 'syncAutoSave');
}

// Map a Sync-tile field element → its card's save handler (auto-save on change).
function _syncSaveFnFor(el) {
    const id = (el && el.id) || '';
    if (id.startsWith('repo-sync-'))        return saveRepoSyncConfig;
    if (id.startsWith('rt-nac-sync-'))      return saveRealtimeNacSyncConfig;
    if (id.startsWith('dns-hook-'))         return saveDnsHookConfig;
    if (id.startsWith('ep-sync-'))          return saveEndpointSyncConfig;
    if (id.startsWith('vm-sync-'))          return saveVmSyncConfig;
    if (id.startsWith('fw-sync-'))          return saveFwDiscoveryConfig;
    if (id.startsWith('nw-sync-'))          return saveNwDiscoveryConfig;
    if (id.startsWith('console-sync-'))     return saveConsoleNetboxSync;
    if (id.startsWith('staleness-sweep-'))  return saveStalenessSweepConfig;
    if (id.startsWith('spoke-alert-'))      return saveSpokeAlertConfig;
    if (id.startsWith('hcw-'))              return saveHubWatchdog;
    if (id.startsWith('htv-'))              return saveHubTlsVerify;
    if (id.startsWith('sot-'))              return saveSourceOfTruthConfig;
    return null;
}

// Generic delegated auto-save: one `change` listener on `root` calls the
// per-tile mapper (mapFn(element) → save handler or null) for the edited field.
// `change` covers checkboxes + selects (fire on toggle/select) and
// text/number/time inputs (fire on commit — blur or Enter); programmatic value
// sets by the load* functions do NOT emit `change`, so rendering triggers no
// saves. The `flag` (a dataset key) prevents stacking listeners across
// re-renders — the container node is reused while its innerHTML is replaced,
// and several tiles share that container, so each tile uses its own flag.
function _attachAutoSave(root, mapFn, flag) {
    if (!root || root.dataset[flag] === '1') return;
    root.dataset[flag] = '1';
    root.addEventListener('change', (e) => {
        const fn = mapFn(e.target);
        if (fn) try { fn(); } catch (err) { console.error('[auto-save]', flag, err); }
    });
}



// Setup → Directory (LDAP) — one-form setup (Global Admin only).
// The operator gives only the domain and admin account. The hub
// (core/src/ldap_cluster.py, GET/POST /setup/ldap-directory) finds every agent
// running the ldap-server role, resets their admin password (stored in the
// Credential Vault), wires replication between them, and points the Directory
// spoke at all of them for failover.
function _renderSetupLdapConfigTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Directory (LDAP)</h3>
                    <span id="ldapcfg-spokes-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
                </div>
                <p class="text-xs text-slate-400 mb-3">Enter the domain and admin account. LM finds the LDAP servers (every agent with the <b>LDAP Server</b> role), sets the admin password on all of them, sets up replication between them, and connects the Directory module to them. The password is stored in the Credential Vault. <b>Global Admin only.</b></p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="space-y-1"><label class="${labelCls}">Domain name</label><input id="ldapcfg-domain" type="text" placeholder="orange-tme.com" autocomplete="off" class="${inputCls} font-mono text-xs"></div>
                    <div class="space-y-1"><label class="${labelCls}">Admin username</label><input id="ldapcfg-admin-user" type="text" value="Administrator" autocomplete="off" class="${inputCls} font-mono text-xs"></div>
                    <div class="space-y-1"><label class="${labelCls}">Admin password <span class="text-slate-400 normal-case font-normal">(blank = generate a new one)</span></label><input id="ldapcfg-admin-pw" type="password" autocomplete="new-password" class="${inputCls} font-mono text-xs"></div>
                    <div id="ldapcfg-psk-wrap" class="space-y-1 hidden"><label class="${labelCls}">Vault pass-phrase <span class="text-slate-400 normal-case font-normal">(__admin__ bucket)</span></label><input id="ldapcfg-psk" type="password" autocomplete="off" class="${inputCls} font-mono text-xs"></div>
                </div>
                <p id="ldapcfg-derived" class="mt-2 text-[11px] text-slate-500 font-mono"></p>
                <div class="mt-4">
                    <p class="${labelCls} mb-1">LDAP servers</p>
                    <div id="ldapcfg-servers" class="text-xs text-slate-500">Loading…</div>
                </div>
                <div class="mt-4 flex items-center justify-between gap-3">
                    <span id="ldapcfg-msg" class="text-xs text-slate-400"></span>
                    <button type="button" onclick="saveLdapConfig()" id="ldapcfg-save-btn" class="${btnCls}">Apply</button>
                </div>
            </div>`;
    loadLdapConfig();
}

function _ldapServersTable(servers, results) {
    if (!servers.length) return '<p class="italic">No LDAP servers yet — load the <b>LDAP Server (OpenLDAP)</b> role on an agent. It joins this directory automatically.</p>';
    const res = Object.fromEntries((results || []).map(r => [r.spoke_id, r]));
    return `<table class="w-full text-left"><thead><tr class="text-slate-400"><th class="py-1">Server</th><th>Address</th><th>Replication id</th><th>Status</th></tr></thead><tbody>${servers.map(s => {
        const r = res[s.spoke_id];
        const status = r ? (r.status === 'SUCCESS' ? '<span class="text-green-700">applying (re-deploying)</span>' : `<span class="text-red-700">${escapeHtml(r.message || 'failed')}</span>`)
            : (s.connected ? '<span class="text-green-700">online</span>' : '<span class="text-red-700">offline</span>');
        return `<tr class="border-t border-slate-100"><td class="py-1 font-medium text-slate-700">${escapeHtml(s.name)}</td><td class="font-mono">${escapeHtml(s.address || '—')}</td><td>${escapeHtml(String((r && r.server_id) || s.server_id || '—'))}</td><td>${status}</td></tr>`;
    }).join('')}</tbody></table>`;
}

async function loadLdapConfig() {
    try {
        const d = await apiJson('/setup/ldap-directory');
        const set = (id, v) => { const el = document.getElementById(id); if (el && v) el.value = v; };
        set('ldapcfg-domain', d.domain);
        set('ldapcfg-admin-user', d.admin_user);
        const pw = document.getElementById('ldapcfg-admin-pw');
        if (pw) pw.placeholder = d.admin_pw_set ? 'blank = generate a new one' : 'blank = generate one';
        document.getElementById('ldapcfg-psk-wrap')?.classList.toggle('hidden', !d.vault_psk_required);
        const derived = document.getElementById('ldapcfg-derived');
        if (derived) derived.textContent = d.base_dn ? `Base DN ${d.base_dn} · Admin DN ${d.admin_dn} · Password in vault ${d.vault_secret} · Directory connects to ${d.server_url}` : '';
        const tbl = document.getElementById('ldapcfg-servers');
        if (tbl) tbl.innerHTML = _ldapServersTable(d.servers || []);
        const pill = document.getElementById('ldapcfg-spokes-pill');
        if (pill) {
            const n = d.spokes_connected || 0;
            pill.textContent = n ? `${n} DIRECTORY SPOKE${n === 1 ? '' : 'S'} CONNECTED` : 'NO DIRECTORY SPOKE';
            pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (n ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500');
        }
    } catch (e) { console.error('loadLdapConfig failed', e); }
}

// ── Directory page LDAP-server + EntraID health dots ─────────────────────
// Polls GET /api/ldap/health while the Directory view is open and paints the
// two header dots Green (healthy) / Yellow (degraded) / Red (down). Self-stops
// when the user navigates away from the Directory view.
let _ldapHealthTimer = null;
function _setHealthDot(dotId, labelId, status, detail) {
    const dot = document.getElementById(dotId);
    const lbl = document.getElementById(labelId);
    if (!dot || !lbl) return;
    const map = {
        healthy:  { c: 'bg-green-500', t: 'text-green-700', s: 'Connected' },
        degraded: { c: 'bg-amber-500', t: 'text-amber-700', s: 'Degraded' },
        down:     { c: 'bg-red-500',   t: 'text-red-700',   s: 'Offline' },
    };
    const m = map[status] || { c: 'bg-slate-300', t: 'text-slate-400', s: 'Unknown' };
    dot.className = 'w-2.5 h-2.5 rounded-full ' + m.c;
    lbl.className = m.t;
    lbl.textContent = detail ? `${m.s} — ${detail}` : m.s;  // textContent → no XSS from detail
}
async function pollLdapHealth() {
    // Stop when the user leaves the view OR the session expired (a 401 clears
    // currentUser) — otherwise a tab left open keeps polling a dead session
    // every 10s forever. Logging back in re-renders the view and restarts it.
    if (currentView !== 'ldap' || !currentUser) { stopLdapHealthPoll(); return; }
    try {
        const h = await apiJson('/api/ldap/health', { method: 'GET' });
        _setHealthDot('ldap-health-dot', 'ldap-health-label', h.ldap && h.ldap.status, h.ldap && h.ldap.detail);
        _setHealthDot('entra-health-dot', 'entra-health-label', h.entra && h.entra.status, h.entra && h.entra.detail);
    } catch (e) {
        _setHealthDot('ldap-health-dot', 'ldap-health-label', 'down', 'hub unreachable');
        _setHealthDot('entra-health-dot', 'entra-health-label', 'down', 'hub unreachable');
    }
}
function startLdapHealthPoll() {
    stopLdapHealthPoll();
    pollLdapHealth();
    _ldapHealthTimer = setInterval(pollLdapHealth, 10000);
}
function stopLdapHealthPoll() {
    if (_ldapHealthTimer) { clearInterval(_ldapHealthTimer); _ldapHealthTimer = null; }
}

async function saveLdapConfig() {
    const btn = document.getElementById('ldapcfg-save-btn');
    const msg = document.getElementById('ldapcfg-msg');
    const v = id => (document.getElementById(id)?.value || '').trim();
    const body = { domain: v('ldapcfg-domain'), admin_user: v('ldapcfg-admin-user') || 'Administrator',
                   admin_pw: document.getElementById('ldapcfg-admin-pw')?.value || '', psk: document.getElementById('ldapcfg-psk')?.value || '' };
    if (!body.domain) { showToast('Domain name is required', 'error'); return; }
    if (!confirm(`Apply directory ${body.domain}? This ${body.admin_pw ? 'sets' : 'generates'} a new admin password on every LDAP server and re-deploys them with replication.`)) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Applying…'; }
    try {
        const d = await apiJson('/setup/ldap-directory', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const servers = d.servers || [];
        const failed = servers.filter(s => s.status !== 'SUCCESS').length;
        if (msg) msg.textContent = `Applied to ${servers.length} server${servers.length === 1 ? '' : 's'}${failed ? ` — ${failed} failed` : ''}. Re-deploy takes a few minutes.`;
        showToast(`Directory ${d.base_dn} applied${failed ? ` (${failed} server(s) failed)` : ''}.`, failed ? 'error' : 'success');
        const pw = document.getElementById('ldapcfg-admin-pw'); if (pw) pw.value = '';
        await loadLdapConfig();
        const tbl = document.getElementById('ldapcfg-servers');
        if (tbl && servers.length) tbl.innerHTML = _ldapServersTable(servers.map(s => ({ ...s, connected: true })), servers);
    } catch (e) {
        showToast('Apply failed: ' + (e.message || e), 'error');
        if (msg) msg.textContent = 'Apply failed.';
    } finally { if (btn) { btn.disabled = false; btn.textContent = 'Apply'; } }
}
window.saveLdapConfig = saveLdapConfig;



// Setup → Module Management tile. One unified device-management page for every
// managed module (Firewalls, Network Devices, NAC, IPAM, LDAP, DNS,
// DHCP). A single "+ Add Device" button opens a modal where the admin first
// picks the module type (OPNsense, ClearPass, NetBox, …) and then fills in
// that type's specifics — the device type is determined by the module type and
// the associated spoke it is attached to. All known devices are listed in one
// table with a per-row type badge + Edit/Delete. See DEVICE_TYPES below for the
// declarative per-type schema (endpoint, fields, spoke filter, payload key).
function _renderSetupModuleMgmtTile(content) {
    const { card, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Managed Devices ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="showAddDeviceModal()" class="${btnCls}">+ Add Device</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Every managed module device in one place — firewalls, network devices, NAC, IPAM, directory, DNS, and DHCP instances. Click <strong>Add Device</strong> then choose the module type to attach.</p>
                <div id="all-devices-tabs" class="mb-3"></div>
                <div id="all-devices-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Network Devices — Auto-Poll Default</h3>
                <p class="text-xs text-slate-400 mb-3">Module-level poll cadence applied to every network device that inherits it. A device's own Auto-Poll Interval always overrides this. The nw spoke polls on this cycle to warm the hub cache and sync device inventory into NetBox.</p>
                <div class="flex items-center gap-3">
                    <select id="nw-module-poll-default" class="bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="">Built-in default (6 hours)</option>
                        <option value="0">Off (no auto-poll)</option>
                        <option value="60">Every 1 minute</option>
                        <option value="300">Every 5 minutes</option>
                        <option value="900">Every 15 minutes</option>
                        <option value="1800">Every 30 minutes</option>
                        <option value="3600">Every hour</option>
                        <option value="21600">Every 6 hours</option>
                        <option value="86400">Every day</option>
                    </select>
                    <button onclick="saveNwPollConfig(this)" class="${btnCls} ml-auto">Save</button>
                </div>
                <div class="mt-4 pt-4 border-t border-slate-200">
                    <h4 class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Anti-Stampede (Jitter &amp; Caps)</h4>
                    <p class="text-xs text-slate-400 mb-3">Spreads the fleet's polls so devices never all poll at once. <b>Jitter</b> randomizes each device's cadence so schedules drift apart; the <b>caps</b> bound how many devices poll per 10-second tick and how many run at the same time. Leave on defaults unless a large fleet is causing load spikes.</p>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <label class="text-xs font-medium text-slate-600">Poll Jitter
                            <select id="nw-poll-jitter" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="">Default (±15%)</option>
                                <option value="0">Off (no jitter)</option>
                                <option value="0.05">Low (±5%)</option>
                                <option value="0.15">Medium (±15%)</option>
                                <option value="0.3">High (±30%)</option>
                                <option value="0.5">Very high (±50%)</option>
                            </select>
                        </label>
                        <label class="text-xs font-medium text-slate-600">Max devices / tick
                            <select id="nw-poll-max-per-tick" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="">Default (8)</option>
                                <option value="2">2</option>
                                <option value="4">4</option>
                                <option value="8">8</option>
                                <option value="16">16</option>
                                <option value="32">32</option>
                            </select>
                        </label>
                        <label class="text-xs font-medium text-slate-600">Max concurrent polls
                            <select id="nw-poll-max-concurrency" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="">Default (5)</option>
                                <option value="1">1</option>
                                <option value="3">3</option>
                                <option value="5">5</option>
                                <option value="10">10</option>
                                <option value="20">20</option>
                            </select>
                        </label>
                    </div>
                    <div class="mt-4 pt-4 border-t border-slate-200">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Reachability Sweep (ICMP Ping)</h4>
                        <p class="text-xs text-slate-400 mb-3">A lightweight ICMP ping of every device, on its own cadence (jittered with the same anti-stampede caps above), keeps the fleet <b>up/down</b> badge fresh between the slower data polls. A device the sweep finds offline is <b>not</b> SSH/SNMP/REST-polled. When the spoke itself is offline the badge shows <b>unknown</b> (yellow).</p>
                        <label class="text-xs font-medium text-slate-600">Ping cadence
                            <select id="nw-ping-interval" class="mt-1 w-full sm:w-1/3 bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="">Built-in default (5 minutes)</option>
                                <option value="0">Off (no ping sweep)</option>
                                <option value="60">Every 1 minute</option>
                                <option value="300">Every 5 minutes</option>
                                <option value="600">Every 10 minutes</option>
                                <option value="900">Every 15 minutes</option>
                            </select>
                        </label>
                    </div>
                    <div class="flex justify-end mt-3">
                        <button onclick="saveNwPollConfig(this)" class="${btnCls}">Save</button>
                    </div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-1">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">NetBox → Network Devices Import</h3>
                    <button onclick="runNwNetboxImport(this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium">Import now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">NetBox is the source of truth for the network-device fleet. Devices in NetBox whose <b>role</b> matches the categories below are imported into the nw module automatically; devices you add manually here are written back to NetBox. NetBox-imported devices that are deleted or re-roled in NetBox are removed from nw (manual devices are never touched). Add credentials to an imported device to make it pollable.</p>
                <div class="space-y-3">
                    <label class="flex items-center gap-2 text-sm text-slate-600">
                        <input type="checkbox" id="nw-import-enabled" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                        Enable NetBox → NW import
                    </label>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">NetBox device roles</label>
                            <input type="text" id="nw-import-roles" placeholder="e.g. Switch, Router, Gateway" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <p class="text-[11px] text-slate-400">Comma-separated NetBox role names (matched case-insensitively).</p>
                        </div>
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Default object type</label>
                            <select id="nw-import-default-ot" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="gateway">Gateway</option>
                                <option value="aos_switch">AOS Switch</option>
                                <option value="cx_switch">CX Switch</option>
                                <option value="ex_switch">EX Switch</option>
                            </select>
                            <p class="text-[11px] text-slate-400">Used when a role isn't in the mapping below.</p>
                        </div>
                    </div>
                    <div class="space-y-1">
                        <label class="text-xs text-slate-500 uppercase font-bold">Role → object-type mapping</label>
                        <input type="text" id="nw-import-map" placeholder="Switch=aos_switch, Router=gateway" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500">
                        <p class="text-[11px] text-slate-400">Optional. <code>role=object_type</code> pairs, comma-separated.</p>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Import interval</label>
                            <select id="nw-import-interval" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="300">Every 5 minutes</option>
                                <option value="900" selected>Every 15 minutes</option>
                                <option value="1800">Every 30 minutes</option>
                                <option value="3600">Every hour</option>
                                <option value="21600">Every 6 hours</option>
                                <option value="86400">Every day</option>
                            </select>
                        </div>
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Owning nw spoke</label>
                            <select id="nw-import-spoke" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="">Auto (first nw spoke)</option>
                            </select>
                        </div>
                    </div>
                    <div class="flex justify-end">
                        <button onclick="saveNwNetboxImport(this)" class="${btnCls}">Save</button>
                    </div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-1">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Network Scan — Discovery ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="showAddInstanceModal('nwscan')" class="${btnSecCls} text-xs">+ Add Scan Credential</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Fingerprint the tenant's known IPs (from NetBox / NAC / DHCP / DNS) with the selected scan credentials — the nw spoke port-probes each address and tries SSH / SNMP to identify Aruba/HPE/Juniper switches &amp; gateways. Identified, not-already-known hardware can be auto-added to the fleet (tagged <code>scanned</code>). Optionally crawl LLDP neighbors to expand beyond the inventory. Credentials are vaulted; secrets are never logged.</p>
                <div id="nwscan-instances-list" class="space-y-2 mb-4"><p class="text-xs text-slate-400 italic animate-pulse">Loading credentials…</p></div>
                <div class="space-y-3">
                    <div class="flex flex-wrap gap-4">
                        <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-enabled" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500"> Enable scanning</label>
                        <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-crawl" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500"> Crawl LLDP neighbors</label>
                        <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-autoadd" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500"> Auto-add discovered</label>
                        <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-snmp" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500" checked> Try SNMP</label>
                    </div>
                    <div class="space-y-1">
                        <label class="text-xs text-slate-500 uppercase font-bold">IP sources</label>
                        <div class="flex flex-wrap gap-4">
                            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-src-netbox" class="rounded border-slate-300 text-[#01A982]" checked> NetBox prefixes</label>
                            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-src-nac" class="rounded border-slate-300 text-[#01A982]"> NAC endpoints</label>
                            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-src-dhcp" class="rounded border-slate-300 text-[#01A982]"> DHCP leases</label>
                            <label class="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" id="nwscan-src-dns" class="rounded border-slate-300 text-[#01A982]"> DNS records</label>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Extra subnets (CIDR, comma/space/newline)</label>
                            <textarea id="nwscan-subnets" rows="2" placeholder="10.0.0.0/24, 192.168.1.0/24" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500"></textarea>
                        </div>
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Extra target IPs</label>
                            <textarea id="nwscan-targets" rows="2" placeholder="10.0.0.1, 10.0.0.2" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500"></textarea>
                        </div>
                    </div>
                    <div class="grid grid-cols-3 gap-4">
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">TCP ports</label>
                            <input type="text" id="nwscan-ports" placeholder="22, 443, 80, 23" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        </div>
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Max targets</label>
                            <input type="number" id="nwscan-maxtargets" min="1" max="4096" placeholder="1024" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        </div>
                        <div class="space-y-1">
                            <label class="text-xs text-slate-500 uppercase font-bold">Concurrency</label>
                            <input type="number" id="nwscan-concurrency" min="1" max="128" placeholder="32" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        </div>
                    </div>
                    <div class="flex items-center gap-3">
                        <button onclick="saveNwScanConfig(this)" class="${btnSecCls}">Save config</button>
                        <button onclick="runNwScan(this, true)" class="${btnCls} ml-auto">Scan now (preview)</button>
                        <button onclick="runNwScan(this, false)" class="${btnCls}">Scan &amp; add</button>
                    </div>
                    <div id="nwscan-results" class="text-xs"></div>
                </div>
            </div>
            ${isAdmin() ? `<div class="${card}">
                <div class="flex items-center justify-between mb-1">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">NetBox → Seed Device Catalog</h3>
                    <button onclick="seedNetboxCatalog(this)" class="${btnSecCls} text-xs">Seed catalog</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Loads the bundled Aruba/HPE/Juniper device-type catalog into NetBox — manufacturers, device types, and their interface (24/48-port + SFP+/QSFP28 uplinks), console, and power templates — so you don't hand-build each model. Idempotent: re-running after editing the catalog upserts types and adds any new templates without error (existing templates are never deleted or re-typed). Global-Admin only. After seeding, instantiate a device from a type and its interfaces are auto-created.</p>
            </div>` : ''}
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">TrueNAS Appliances ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="showAddTruenasApplianceModal()" class="${btnCls}" title="Register a new TrueNAS appliance with Lab Manager">+ Add Appliance</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">TrueNAS storage appliances polled over the official WebSocket JSON-RPC client. Each appliance is bound to a tenant + owning storage spoke; the spoke polls on its cycle (pools, datasets, shares, disks, alerts, services, capacity) and warms the hub cache. Use a per-appliance API key (created in TrueNAS → Settings → API Keys); self-signed boxes set Verify SSL off.</p>
                <div id="truenas-appliances-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">TrueNAS — Auto-Poll Default</h3>
                <p class="text-xs text-slate-400 mb-3">Module-level poll cadence applied to every TrueNAS appliance that inherits it. An appliance's own Auto-Poll Interval always overrides this. The storage spoke polls on this cycle to warm the hub cache.</p>
                <div class="flex items-center gap-3">
                    <select id="truenas-module-poll-default" class="bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="Default polling interval applied to all TrueNAS appliances">
                        <option value="">Built-in default (15 minutes)</option>
                        <option value="0">Off (no auto-poll)</option>
                        <option value="60">Every 1 minute</option>
                        <option value="300">Every 5 minutes</option>
                        <option value="900">Every 15 minutes</option>
                        <option value="1800">Every 30 minutes</option>
                        <option value="3600">Every hour</option>
                        <option value="21600">Every 6 hours</option>
                        <option value="86400">Every day</option>
                    </select>
                    <button onclick="saveTruenasPollConfig(this)" class="${btnCls} ml-auto" title="Save TrueNAS default auto-poll cadence">Save</button>
                </div>
            </div>`;
    loadAllDevices();
    loadNwPollConfig();
    loadNwNetboxImport();
    loadInstances('nwscan');
    loadNwScanConfig();
    loadTruenasAppliances();
    loadTruenasPollConfig();
}

// NetBox → NW import config (Setup → Module Management). NetBox = fleet SoT.
async function loadNwNetboxImport() {
    const en = document.getElementById('nw-import-enabled');
    if (!en) return;
    // Populate the nw-spoke picker (reuse the approved-spokes helper).
    try {
        const spokes = await loadApprovedSpokes();
        const sel = document.getElementById('nw-import-spoke');
        if (sel) {
            const nwSpokes = spokes.filter(s => s.module_type === 'nw' || /^(nw|network)/.test(s.spoke_id));
            sel.innerHTML = '<option value="">Auto (first nw spoke)</option>' +
                nwSpokes.map(s => `<option value="${s.spoke_id}" title="${escapeHtml(s.spoke_id)}">${escapeHtml(_spokeName(s))}</option>`).join('');
        }
    } catch (e) { /* keep Auto */ }
    try {
        const r = await setupFetch('/setup/nw-netbox-import');
        if (!r.ok) return;
        const c = (await r.json()).nw_netbox_import || {};
        en.checked = !!c.enabled;
        document.getElementById('nw-import-roles').value = (c.roles || []).join(', ');
        document.getElementById('nw-import-default-ot').value = c.default_object_type || 'gateway';
        document.getElementById('nw-import-map').value =
            Object.entries(c.object_type_map || {}).map(([k, v]) => `${k}=${v}`).join(', ');
        if (c.interval) document.getElementById('nw-import-interval').value = String(c.interval);
        const sp = document.getElementById('nw-import-spoke');
        if (sp && c.spoke_id) sp.value = c.spoke_id;
    } catch (e) { /* defaults */ }
}

function _parseNwImportMap(raw) {
    const map = {};
    (raw || '').split(',').forEach(pair => {
        const [k, v] = pair.split('=').map(s => (s || '').trim());
        if (k && v) map[k] = v;
    });
    return map;
}

async function saveNwNetboxImport(btn) {
    const config = {
        enabled: document.getElementById('nw-import-enabled').checked,
        roles: document.getElementById('nw-import-roles').value.split(',').map(s => s.trim()).filter(Boolean),
        default_object_type: document.getElementById('nw-import-default-ot').value,
        object_type_map: _parseNwImportMap(document.getElementById('nw-import-map').value),
        interval: parseInt(document.getElementById('nw-import-interval').value, 10) || 900,
        spoke_id: document.getElementById('nw-import-spoke').value,
    };
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/nw-netbox-import', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config }),
        });
        if (r.ok) showToast('NetBox → NW import settings saved.', 'success');
        else showToast('Failed to save: ' + (await r.json().catch(() => ({}))).detail, 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save'; } }
}

async function seedNetboxCatalog(btn) {
    if (!await showConfirmToast('Seed NetBox with the bundled Aruba/HPE/Juniper device-type catalog (manufacturers + device types + interface/console/power templates)? Existing types are upserted; missing templates are added; nothing is deleted.')) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Seeding…'; }
    try {
        const r = await apiJson('/api/netbox/seed-catalog', { method: 'POST' });
        const errs = r.errors && r.errors.length;
        const msg = `Seeded: ${r.manufacturers_created} manufacturers, ${r.device_types_created} new device types (${r.device_types_updated} updated), +${r.templates_added} templates` + (errs ? ` · ${r.errors.length} errors` : '');
        showToast(msg, errs ? 'info' : 'success');
    } catch (e) { showToast('Seed failed: ' + e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Seed catalog'; } }
}

// ── Excel rack-layout importer (admin-only) ──────────────────────────────────
// Two-step URL-relay flow: upload .xlsx → hub saves to scratch + spoke detects
// rack sheets + guesses column maps → user edits maps + picks racks → commit
// (spoke re-GETs the file, re-parses, creates racks + devices + mgmt iface/IP).
// Mirrors seedNetboxCatalog/runNwNetboxImport (toast + btn-state) and
// uploadSelfBackup (FormData via apiJson). Tenant = currentTenant stamped on
// every rack + device; 'default' = global.
const RACK_IMPORT_FIELDS = ['name','device_type','serial','asset_tag','position','face','mgmt_ip','mac','role','status','description','ignore'];

async function showRackImportModal() {
    if (!isAdmin()) { showToast('Admin only', 'error'); return; }
    openModal('nb-rack-import-modal', `
        <div class="flex justify-between items-center mb-3">
            <h3 class="text-lg font-bold">Import rack layout from Excel</h3>
            <button onclick="document.getElementById('nb-rack-import-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        <div class="space-y-3">
            <div class="flex items-center gap-3">
                <input id="nb-rack-file" type="file" accept=".xlsx" class="hidden" onchange="uploadRackImportXlsx(this)">
                <button onclick="document.getElementById('nb-rack-file').click()" class="bg-indigo-50 hover:bg-indigo-100 text-indigo-600 border border-indigo-300 px-3 py-1.5 rounded-md text-xs font-bold transition-all shadow-sm">Choose .xlsx…</button>
                <span id="nb-rack-file-name" class="text-xs text-slate-500"></span>
            </div>
            <div id="nb-rack-import-status" class="text-xs text-slate-500"></div>
            <div id="nb-rack-import-results"></div>
        </div>
    `, { card: 'w-full max-w-5xl p-6 space-y-4 max-h-[90vh] overflow-y-auto', backdropClose: true });
    window._rackImport = { upload_id: null, racks: [], form_options: {} };
}
window.showRackImportModal = showRackImportModal;

// ── Rack elevation view (front+rear, like NetBox) ───────────────────────────
// Renders the render-model from NETBOX_GET_RACK_ELEVATION: two side-by-side
// U-grids (top→bottom, highest U first) with consecutive same-device units
// merged via rowspan (multi-U devices), cells tinted with the device role
// color, plus a 0U/side tray underneath. Read-only; non-admins are ownership-
// gated at the route.
function _elevTextOn(hex) {
    const h = (hex || '').replace('#', '');
    if (h.length !== 6) return '#1e293b';
    const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16);
    const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    return lum > 0.6 ? '#1e293b' : '#ffffff';
}

function _elevFaceTable(units, faceLabel) {
    // units: [{unit, device|null}] top→bottom. Merge consecutive same-device-id
    // units into one rowspan cell (multi-U device); empty units stay blank.
    // Row height is driven by the shared `--elev-uh` CSS var set by _fitElevation
    // so the whole rack scales to fit the viewport (see showRackElevationModal).
    const rows = [];
    let i = 0;
    while (i < units.length) {
        const u = units[i];
        const dev = u && u.device;
        let span = 1;
        if (dev && dev.id != null) {
            while (i + span < units.length && units[i + span].device && units[i + span].device.id === dev.id) span++;
        }
        const rowStyle = `style="height:calc(var(--elev-uh,20px) * ${span})"`;
        const label = `<td class="px-1 text-[9px] text-slate-400 font-mono w-7 text-right align-top border-b border-slate-100 leading-none pt-0.5">${u && u.unit != null ? u.unit : ''}</td>`;
        let cell;
        if (dev) {
            const color = dev.role_color || '9e9e9e';
            const fg = _elevTextOn(color);
            cell = `<td rowspan="${span}" class="px-1 text-[10px] align-top border-b border-white/20 overflow-hidden leading-tight" style="background:#${color};color:${fg}">
                <div class="font-semibold truncate leading-tight">${escapeHtml(dev.name || '')}</div>
                <div class="opacity-85 truncate leading-tight">${escapeHtml(dev.model || '')}${dev.role ? ' · ' + escapeHtml(dev.role) : ''}</div>
                ${dev.primary_ip ? `<div class="font-mono opacity-85 truncate leading-tight">${escapeHtml(dev.primary_ip)}</div>` : ''}
            </td>`;
        } else {
            cell = `<td rowspan="${span}" class="border-b border-slate-100 bg-slate-50/40"></td>`;
        }
        rows.push(`<tr ${rowStyle}>${label}${cell}</tr>`);
        i += span;
    }
    if (!rows.length) {
        return `<div class="elev-face flex-1 min-w-0">
            <div class="text-xs font-bold text-slate-400 uppercase mb-1">${faceLabel}</div>
            <p class="text-xs text-slate-400 italic">empty</p></div>`;
    }
    return `<div class="elev-face flex-1 min-w-0">
        <div class="text-xs font-bold text-slate-500 uppercase mb-1">${faceLabel}</div>
        <table class="w-full table-fixed border-collapse">${rows.join('')}</table>
    </div>`;
}

// Scale the rack-elevation U-rows so the full rack fits the visible modal
// height: per-U height = available height / u_height, clamped to a readable
// band. Below the floor it stops shrinking and the grid scrolls instead. Runs
// after render and on window resize while the modal is open.
function _fitElevation() {
    const grid = document.querySelector('#nb-rack-elev-modal .elev-grid');
    if (!grid) return;
    const uHeight = parseInt(grid.dataset.uheight || '0', 10);
    if (!uHeight) return;
    // Space the fixed chrome (modal padding, title, meta row, 0U tray) consumes
    // outside the U-grid — kept as a conservative constant so a short window
    // still leaves the grid a usable slice before it falls back to scrolling.
    const chrome = 190 + (grid.nextElementSibling ? grid.nextElementSibling.offsetHeight : 0);
    const avail = Math.max(0, Math.floor(window.innerHeight * 0.9) - chrome);
    const rowH = Math.max(13, Math.min(24, Math.floor(avail / uHeight) || 24));
    grid.style.setProperty('--elev-uh', rowH + 'px');
}
window.addEventListener('resize', _fitElevation);

async function showRackElevationModal(rackId) {
    // Name comes from the cached racks list (window._nbRacks) — NOT embedded in
    // the onclick attribute, where a JSON.stringify'd double-quoted name would
    // close the HTML attribute early and break the click handler.
    const rk = (window._nbRacks || []).find(r => String(r.id) === String(rackId)) || {};
    const rackName = rk.name || '';
    openModal('nb-rack-elev-modal', `
        <div class="flex justify-between items-center mb-3">
            <h3 class="text-lg font-bold">Rack elevation — ${escapeHtml(rackName || '')}</h3>
            <button onclick="document.getElementById('nb-rack-elev-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        <div id="nb-rack-elev-body" class="text-xs text-slate-500">Loading…</div>
    `, { card: 'w-full max-w-3xl p-6 space-y-4 max-h-[90vh] overflow-y-auto', backdropClose: true });
    try {
        const d = await apiJson(`/api/netbox/racks/${rackId}/elevation`);
        const body = document.getElementById('nb-rack-elev-body');
        if (!d || d.status === 'ERROR') {
            body.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${escapeHtml((d && d.message) || 'NetBox spoke not connected')}</p>`;
            return;
        }
        const r = d.rack || {};
        // Stash the site slug + rack name so the "+ Add device" button can prefill
        // the add form (add_device_to_rack takes a site slug, not the display name).
        window._nbElevMeta = window._nbElevMeta || {};
        window._nbElevMeta[rackId] = { site_slug: r.site_slug || '', rack: r.name || rackName };
        const meta = `<div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-600 mb-3">
            <span><span class="text-slate-400">Site:</span> ${escapeHtml(r.site || '—')}</span>
            <span><span class="text-slate-400">Tenant:</span> ${escapeHtml(r.tenant || '—')}</span>
            <span><span class="text-slate-400">Height:</span> ${r.u_height || 0}U</span>
            <button onclick="_addDeviceFromElev(${rackId})" class="ml-auto bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-bold transition-all">+ Add device</button>
        </div>`;
        const front = (d.faces && d.faces.front) || [];
        const rear  = (d.faces && d.faces.rear)  || [];
        // Rack height drives the per-U scaling; fall back to the tallest unit
        // present if u_height is missing so the grid still fits.
        const maxUnit = Math.max(0, ...front.concat(rear).map(u => (u && u.unit) || 0));
        const uHeight = (r.u_height && r.u_height > 0) ? r.u_height : maxUnit;
        const grid = `<div class="elev-grid flex gap-4 items-start" data-uheight="${uHeight}" style="--elev-uh:20px">${_elevFaceTable(front, 'Front')}${_elevFaceTable(rear, 'Rear')}</div>`;
        const zero = d.zero_u || [];
        const zeroHtml = zero.length ? `<div class="mt-4">
            <div class="text-xs font-bold text-slate-500 uppercase mb-1">0U / side</div>
            <div class="flex flex-wrap gap-2">${zero.map(z => {
                const c = z.role_color || '9e9e9e';
                return `<div class="px-2 py-1 rounded text-[11px]" style="background:#${c};color:${_elevTextOn(c)}">
                    <span class="font-semibold">${escapeHtml(z.name || '')}</span>
                    <span class="opacity-85"> · ${escapeHtml(z.role || '')}</span>
                </div>`;
            }).join('')}</div>
        </div>` : '';
        body.innerHTML = meta + grid + zeroHtml;
        _fitElevation();
    } catch (e) {
        const body = document.getElementById('nb-rack-elev-body');
        if (body) body.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${escapeHtml(e.message || '')}</p>`;
    }
}
window.showRackElevationModal = showRackElevationModal;

// Open the Add-Device form from the rack elevation view, prefilled with this
// rack (+ its site slug). On success submitNetboxAddDevice re-opens the elevation.
function _addDeviceFromElev(rackId) {
    const m = (window._nbElevMeta || {})[rackId] || {};
    showNetboxAddDeviceModal(null, { site: m.site_slug, rack: m.rack, face: 'front',
                                     elevRackId: rackId });
}
window._addDeviceFromElev = _addDeviceFromElev;

async function uploadRackImportXlsx(input) {
    const file = input && input.files && input.files[0];
    if (!file) return;
    if (!/\.xlsx$/i.test(file.name)) { showToast('Pick a .xlsx workbook.', 'error'); input.value = ''; return; }
    document.getElementById('nb-rack-file-name').textContent = file.name;
    const status = document.getElementById('nb-rack-import-status');
    const results = document.getElementById('nb-rack-import-results');
    status.textContent = 'Detecting rack sheets…';
    results.innerHTML = '';
    try {
        const fd = new FormData();
        fd.append('file', file, file.name);
        // apiJson + FormData mirrors uploadSelfBackup — the multipart
        // Content-Type/boundary is set by the browser for a FormData body.
        const d = await apiJson('/api/netbox/racks/import-xlsx', { method: 'POST', body: fd });
        window._rackImport = { upload_id: d.upload_id, racks: d.racks || [], form_options: d.form_options || {} };
        status.textContent = `Detected ${d.racks.length} rack sheet(s). Review the mapping, pick racks, then Import.`;
        renderRackImportResults();
    } catch (e) {
        status.innerHTML = `<span class="text-red-600">Upload/detect failed: ${escapeHtml(e.message || e)}</span>`;
    } finally { input.value = ''; }
}
window.uploadRackImportXlsx = uploadRackImportXlsx;

function renderRackImportResults() {
    const { racks, form_options } = window._rackImport;
    const fo = form_options || {};
    const sites = fo.sites || [];
    const roles = fo.device_roles || [];
    const siteOpts = '<option value="">— pick site —</option>' +
        sites.map(s => `<option value="${escapeHtml(s.slug)}">${escapeHtml(s.name)}</option>`).join('');
    const roleOpts = '<option value="">(no default role)</option>' +
        roles.map(r => `<option value="${escapeHtml(r.slug)}">${escapeHtml(r.name)}</option>`).join('');
    const tenantLabel = (currentTenant && currentTenant !== 'default') ? currentTenant : '(global)';

    let html = `<div class="rounded-lg border border-slate-200 p-3 bg-slate-50">
        <div class="text-xs font-semibold text-slate-600 mb-2">Defaults for all selected racks</div>
        <div class="grid grid-cols-3 gap-2">
            <label class="text-xs">Default Site
                <select id="nb-ri-def-site" class="w-full border rounded px-2 py-1 text-xs mt-0.5">${siteOpts}</select>
            </label>
            <label class="text-xs">Default Role
                <select id="nb-ri-def-role" class="w-full border rounded px-2 py-1 text-xs mt-0.5">${roleOpts}</select>
            </label>
            <label class="text-xs">Tenant (current)
                <input class="w-full border rounded px-2 py-1 text-xs mt-0.5 bg-slate-100" value="${escapeHtml(tenantLabel)}" disabled>
            </label>
        </div>
    </div>`;

    racks.forEach((rk, i) => {
        const isSummary = rk.shape === 'summary';
        const siteOvOpts = '<option value="">(use default)</option>' +
            sites.map(s => `<option value="${escapeHtml(s.slug)}">${escapeHtml(s.name)}</option>`).join('');
        html += `<details class="rounded-lg border border-slate-200"${i === 0 ? ' open' : ''}>
            <summary class="px-3 py-2 text-sm font-medium flex items-center gap-2 cursor-pointer">
                <input type="checkbox" data-ri-include="${i}"${i === 0 ? ' checked' : ''} class="ri-include" onclick="event.stopPropagation()">
                <span>${escapeHtml(rk.rack_name)}</span>
                <span class="text-xs text-slate-400">${escapeHtml(rk.shape)} · ${rk.u_height}U · ${rk.device_count} slots</span>
            </summary>
            <div class="px-3 pb-3 space-y-2">
                <div class="grid grid-cols-3 gap-2">
                    <label class="text-xs">Rack name
                        <input data-ri-name="${i}" class="w-full border rounded px-2 py-1 text-xs mt-0.5" value="${escapeHtml(rk.rack_name)}">
                    </label>
                    <label class="text-xs">Site override
                        <select data-ri-site="${i}" class="w-full border rounded px-2 py-1 text-xs mt-0.5">${siteOvOpts}</select>
                    </label>
                    <label class="text-xs">U-height
                        <input data-ri-u="${i}" type="number" class="w-full border rounded px-2 py-1 text-xs mt-0.5" value="${rk.u_height}">
                    </label>
                </div>
                ${isSummary
                    ? '<p class="text-xs text-slate-400">Summary sheet: Front/Rear text cells become front/rear-face devices (named by their text). No column mapping needed.</p>'
                    : renderColumnMap(rk, i)}
            </div>
        </details>`;
    });

    html += `<div class="flex items-center justify-between pt-3 border-t">
        <label class="text-xs flex items-center gap-1"><input id="nb-ri-dryrun" type="checkbox"> Dry run (validate only, write nothing)</label>
        <div class="flex gap-2">
            <button onclick="document.getElementById('nb-rack-import-modal').remove()" class="px-3 py-1.5 text-xs border border-slate-300 rounded hover:bg-slate-50">Cancel</button>
            <button onclick="commitRackImport(this)" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-1.5 rounded text-xs font-bold transition-all shadow-sm">Import</button>
        </div>
    </div>`;
    document.getElementById('nb-rack-import-results').innerHTML = html;
}
window.renderRackImportResults = renderRackImportResults;

function renderColumnMap(rk, i) {
    const cols = rk.columns || [];
    const cm = rk.column_map || {};
    const rows = cols.map((c, ci) => {
        const sel = cm[c] || 'ignore';
        const opts = RACK_IMPORT_FIELDS.map(f => `<option value="${f}"${f === sel ? ' selected' : ''}>${f}</option>`).join('');
        const sample = (rk.preview_rows && rk.preview_rows[0] && rk.preview_rows[0][ci] != null)
            ? String(rk.preview_rows[0][ci]).slice(0, 40) : '';
        return `<tr>
            <td class="px-2 py-1 text-xs font-mono">${escapeHtml(c)}</td>
            <td class="px-2 py-1 text-xs text-slate-400">${escapeHtml(sample)}</td>
            <td class="px-2 py-1"><select data-ri-map="${i}" data-ri-col="${escapeHtml(c)}" class="border rounded px-1 py-0.5 text-xs">${opts}</select></td>
        </tr>`;
    }).join('');
    return `<div class="text-xs text-slate-600 mt-1">Column mapping (source column → NetBox field):</div>
        <table class="w-full text-xs border rounded"><thead><tr class="bg-slate-100">
            <th class="px-2 py-1 text-left">Column</th>
            <th class="px-2 py-1 text-left">Sample</th>
            <th class="px-2 py-1 text-left">→ Field</th>
        </tr></thead><tbody>${rows}</tbody></table>`;
}
window.renderColumnMap = renderColumnMap;

function collectRackImport() {
    const { racks } = window._rackImport || {};
    if (!racks) return [];
    const defSite = document.getElementById('nb-ri-def-site')?.value || '';
    const defRole = document.getElementById('nb-ri-def-role')?.value || '';
    const tenant = (currentTenant && currentTenant !== 'default') ? currentTenant : '';
    const sheets = [];
    racks.forEach((rk, i) => {
        const inc = document.querySelector(`[data-ri-include="${i}"]`);
        if (!inc || !inc.checked) return;
        const name = document.querySelector(`[data-ri-name="${i}"]`)?.value || rk.rack_name;
        const siteOv = document.querySelector(`[data-ri-site="${i}"]`)?.value || '';
        const u = parseInt(document.querySelector(`[data-ri-u="${i}"]`)?.value, 10) || rk.u_height;
        const column_map = {};
        document.querySelectorAll(`select[data-ri-map="${i}"]`).forEach(sel => {
            const f = sel.value;
            if (f && f !== 'ignore') column_map[sel.dataset.riCol] = f;
        });
        sheets.push({
            sheet: rk.sheet, rack_name: name, shape: rk.shape,
            site_slug: siteOv || defSite, u_height: u, tenant_slug: tenant,
            column_map, default_role_slug: defRole, default_status: 'active',
        });
    });
    return sheets;
}
window.collectRackImport = collectRackImport;

async function commitRackImport(btn) {
    const sheets = collectRackImport();
    if (!sheets.length) { showToast('Select at least one rack to import.', 'error'); return; }
    const upload_id = window._rackImport?.upload_id;
    if (!upload_id) { showToast('No upload — choose a file first.', 'error'); return; }
    const dryRun = !!document.getElementById('nb-ri-dryrun')?.checked;
    if (!await showConfirmToast(`${dryRun ? 'Dry-run' : 'Import'} ${sheets.length} rack sheet(s)?${dryRun ? ' — nothing will be written.' : ''}`)) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }
    try {
        const r = await apiJson('/api/netbox/racks/import-commit', {
            method: 'POST', body: JSON.stringify({ upload_id, sheets, dry_run: dryRun }),
        });
        const errs = (r.errors && r.errors.length) || 0;
        const msg = `${r.dry_run ? 'Dry run: ' : ''}+${r.racks_created} racks (${r.racks_updated} upd), +${r.devices_created} devices (${r.devices_updated} upd), ${r.ips_assigned} IPs`
            + (r.skipped_devices ? ` · ${r.skipped_devices} skipped` : '')
            + (errs ? ` · ${errs} errors` : '');
        showToast(msg, errs ? 'info' : 'success');
        const status = document.getElementById('nb-rack-import-status');
        if (errs && status) {
            status.innerHTML = `<details class="text-xs text-red-600"><summary>${errs} error(s) — unresolved device types? Seed the catalog first.</summary>${r.errors.slice(0, 25).map(e => `<div class="font-mono">${escapeHtml((e.rack || e.sheet || '') + ': ' + (e.name ? e.name + ' — ' : '') + (e.message || ''))}</div>`).join('')}</details>`;
        }
        if (!dryRun && !errs) {
            document.getElementById('nb-rack-import-modal')?.remove();
            loadNetboxData('Racks');
        }
    } catch (e) { showToast('Import failed: ' + (e.message || e), 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Import'; } }
}
window.commitRackImport = commitRackImport;

async function runNwNetboxImport(btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }
    try {
        const r = await setupFetch('/setup/nw-netbox-import/run', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.status === 'SUCCESS') {
            showToast(`Imported: ${d.matched} matched · +${d.added} added · ~${d.updated} updated · -${d.removed} removed.`, 'success');
            loadAllDevices();
        } else if (r.ok && d.status === 'SKIPPED') {
            showToast('Import skipped — enable it and set at least one role first.', 'info');
        } else {
            showToast('Import failed: ' + (d.message || d.detail || r.status), 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Import now'; } }
}

// ── Network Scan (discovery) config + run (Setup → Module Management) ────────
// The active tenant for NW scan calls. 'default' is the admin's unscoped global
// view, not a real tenant — send nothing so the server applies its own default
// rather than trying to resolve a tenant literally named "default".
function _nwActiveTenant() {
    return (typeof currentTenant === 'string' && currentTenant && currentTenant !== 'default')
        ? currentTenant : '';
}

function _nwScanParseList(v) {
    return String(v || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
}

async function loadNwScanConfig() {
    if (!document.getElementById('nwscan-enabled')) return;
    try {
        const r = await setupFetch('/setup/nw-scan-config');
        if (!r.ok) return;
        const cfg = (await r.json()).nw_scan || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
        const val = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        set('nwscan-enabled', cfg.enabled);
        set('nwscan-crawl', cfg.crawl);
        set('nwscan-autoadd', cfg.auto_add);
        set('nwscan-snmp', cfg.try_snmp !== false);
        const srcs = new Set(cfg.ip_sources || ['netbox']);
        set('nwscan-src-netbox', srcs.has('netbox'));
        set('nwscan-src-nac', srcs.has('nac'));
        set('nwscan-src-dhcp', srcs.has('dhcp'));
        set('nwscan-src-dns', srcs.has('dns'));
        val('nwscan-ports', (cfg.tcp_ports || [22, 443, 80, 23]).join(', '));
        val('nwscan-maxtargets', cfg.max_targets || 1024);
        val('nwscan-concurrency', cfg.concurrency || 32);
    } catch (e) { /* leave defaults */ }
}

function _nwScanSources() {
    const s = [];
    if (document.getElementById('nwscan-src-netbox')?.checked) s.push('netbox');
    if (document.getElementById('nwscan-src-nac')?.checked) s.push('nac');
    if (document.getElementById('nwscan-src-dhcp')?.checked) s.push('dhcp');
    if (document.getElementById('nwscan-src-dns')?.checked) s.push('dns');
    return s;
}

function _nwScanConfigBody() {
    return {
        enabled: !!document.getElementById('nwscan-enabled')?.checked,
        crawl: !!document.getElementById('nwscan-crawl')?.checked,
        auto_add: !!document.getElementById('nwscan-autoadd')?.checked,
        try_snmp: !!document.getElementById('nwscan-snmp')?.checked,
        ip_sources: _nwScanSources(),
        tcp_ports: _nwScanParseList(document.getElementById('nwscan-ports')?.value)
            .map(p => parseInt(p, 10)).filter(n => !isNaN(n)),
        max_targets: parseInt(document.getElementById('nwscan-maxtargets')?.value, 10) || 1024,
        concurrency: parseInt(document.getElementById('nwscan-concurrency')?.value, 10) || 32,
    };
}

async function saveNwScanConfig(btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/nw-scan-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: _nwScanConfigBody() }),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) showToast('Scan configuration saved.', 'success');
        else showToast('Failed to save: ' + (d.detail || r.status), 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save config'; }
    }
}

async function runNwScan(btn, dryRun) {
    const out = document.getElementById('nwscan-results');
    const label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = dryRun ? 'Scanning…' : 'Scanning & adding…'; }
    if (out) out.innerHTML = '<p class="text-slate-400 italic animate-pulse">Scanning — this can take a while for large subnets…</p>';
    try {
        const body = {
            dry_run: !!dryRun,
            auto_add: !dryRun,
            crawl: !!document.getElementById('nwscan-crawl')?.checked,
            ip_sources: _nwScanSources(),
            subnets: _nwScanParseList(document.getElementById('nwscan-subnets')?.value),
            targets: _nwScanParseList(document.getElementById('nwscan-targets')?.value),
            max_targets: parseInt(document.getElementById('nwscan-maxtargets')?.value, 10) || 1024,
        };
        // Scope the scan to the tenant the admin is actually viewing. Without
        // this the server fell back to the shared tenant, so the scan ran with
        // another tenant's targets/agent.
        const _t = _nwActiveTenant();
        if (_t) body.tenant = _t;
        const r = await setupFetch('/setup/nw-scan/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { if (out) out.innerHTML = `<p class="text-red-500">Scan failed: ${escapeHtml(d.detail || String(r.status))}</p>`; return; }
        _renderNwScanResults(d);
        if (!dryRun && (d.added || []).length) { showToast(`Added ${d.added.length} discovered device(s).`, 'success'); loadAllDevices(); }
    } catch (e) {
        if (out) out.innerHTML = `<p class="text-red-500">Error: ${escapeHtml(e.message)}</p>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = label; }
    }
}

// Shared scan-result markup for BOTH the Setup card (_renderNwScanResults) and
// the tenant Scan tab (_renderNwScanResults2) so the two never drift.
// Renders three things: the run summary, the identified/added devices, and —
// new — the reachable-but-unidentified hosts, which ARE the whole result of a
// discovery-only (credential-free) scan.
function _nwScanResultsHtml(d) {
    const rows = (d.added && d.added.length) ? d.added : (d.preview || []);
    const reachable = (d.reachable || []).filter(h => h && h.reachable !== false && !(d.identified || []).some(i => i.address === h.address && i.object_type));
    const srcTxt = Object.entries(d.sources || {}).filter(([k]) => k !== 'truncated' && k !== 'failed_batches').map(([k, v]) => `${k}:${v}`).join(' · ') || 'none';
    let html = `<div class="mt-2 p-3 bg-slate-50 border border-slate-200 rounded-md">
        <p class="text-slate-600"><b>${d.targets || 0}</b> target(s) scanned (${escapeHtml(srcTxt)}) · <b>${(d.identified || []).length}</b> identified · <b>${reachable.length}</b> reachable · <b>${d.dry_run ? (d.preview || []).length + ' to add (preview)' : (d.added || []).length + ' added'}</b></p>`;
    if ((d.batches || 0) > 1) {
        html += `<p class="mt-1 text-[11px] text-slate-500">Large scan split into ${d.batches} batches.</p>`;
    }
    if ((d.sources || {}).truncated) {
        html += `<p class="mt-1 text-[11px] text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1">${d.sources.truncated} further address(es) exceeded the scan ceiling and were not scanned. Narrow the sources, or leave very large supernets to the background sweep.</p>`;
    }
    if ((d.sources || {}).failed_batches) {
        html += `<p class="mt-1 text-[11px] text-red-700 bg-red-50 border border-red-200 rounded px-2 py-1">${d.sources.failed_batches} batch(es) failed or timed out; results are partial.</p>`;
    }
    if (d.discovery_only) {
        html += `<p class="mt-1 text-[11px] text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1">Discovery-only scan — no scan credentials were selected, so hosts were probed for reachability and open ports but not logged into. Nothing can be auto-added from this run. Select a credential set to identify and add devices.</p>`;
    }
    if (rows.length) {
        html += '<table class="w-full mt-2 text-left"><thead><tr class="text-slate-400 uppercase text-[10px]"><th class="py-1">Address</th><th>Type</th><th>Name</th><th>OS</th><th>Via</th></tr></thead><tbody>';
        for (const dev of rows) {
            html += `<tr class="border-t border-slate-100"><td class="py-1 font-mono">${escapeHtml(dev.address || '')}</td><td>${escapeHtml(dev.object_type || '')}</td><td>${escapeHtml(dev.name || dev.hostname || '')}</td><td>${escapeHtml(dev.os || '')}</td><td>${escapeHtml(dev.method || '')}</td></tr>`;
        }
        html += '</tbody></table>';
    } else {
        html += '<p class="text-slate-400 italic mt-1">No new manageable devices identified.</p>';
    }
    if (reachable.length) {
        html += `<p class="mt-3 text-[10px] uppercase tracking-wide text-slate-400">Reachable hosts (not identified as a manageable device)</p>`;
        html += '<table class="w-full mt-1 text-left"><thead><tr class="text-slate-400 uppercase text-[10px]"><th class="py-1">Address</th><th>Open ports</th><th>Hostname</th></tr></thead><tbody>';
        for (const h of reachable) {
            html += `<tr class="border-t border-slate-100"><td class="py-1 font-mono">${escapeHtml(h.address || '')}</td><td class="font-mono text-xs">${escapeHtml((h.open_ports || []).join(', '))}</td><td>${escapeHtml(h.hostname || '')}</td></tr>`;
        }
        html += '</tbody></table>';
    }
    return html + '</div>';
}

function _renderNwScanResults(d) {
    const out = document.getElementById('nwscan-results');
    if (!out) return;
    out.innerHTML = _nwScanResultsHtml(d);
}

// Module-level nw auto-poll default + anti-stampede knobs (Setup → Module
// Management). Device-level cadence always wins over the module default.
async function loadNwPollConfig() {
    const sel = document.getElementById('nw-module-poll-default');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/nw-poll-config');
        if (!r.ok) return;
        const d = await r.json();
        sel.value = (d.default_poll_interval === null || d.default_poll_interval === undefined)
            ? '' : String(d.default_poll_interval);
        // Anti-stampede knobs — null/absent → the '' (built-in default) option.
        const setOpt = (id, v) => {
            const el = document.getElementById(id);
            if (el) el.value = (v === null || v === undefined) ? '' : String(v);
        };
        setOpt('nw-poll-jitter', d.poll_jitter_frac);
        setOpt('nw-poll-max-per-tick', d.max_poll_per_tick);
        setOpt('nw-poll-max-concurrency', d.max_poll_concurrency);
        setOpt('nw-ping-interval', d.ping_interval);
    } catch (e) { /* leave built-in defaults selected */ }
}

async function saveNwPollConfig(btn) {
    const sel = document.getElementById('nw-module-poll-default');
    if (!sel) return;
    const raw = sel.value;
    // '' → null (inherit built-in); numeric knobs pass '' through as null too so
    // the spoke falls back to its own defaults. parseFloat keeps the jitter
    // fraction (e.g. 0.15); the caps are ints.
    const numOrNull = (id, parse) => {
        const el = document.getElementById(id);
        if (!el || el.value === '') return null;
        const n = parse(el.value);
        return isNaN(n) ? null : n;
    };
    const body = {
        default_poll_interval: raw === '' ? null : (parseInt(raw, 10) || 0),
        poll_jitter_frac: numOrNull('nw-poll-jitter', parseFloat),
        max_poll_per_tick: numOrNull('nw-poll-max-per-tick', v => parseInt(v, 10)),
        max_poll_concurrency: numOrNull('nw-poll-max-concurrency', v => parseInt(v, 10)),
        ping_interval: numOrNull('nw-ping-interval', v => parseInt(v, 10)),
    };
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/nw-poll-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) showToast(`Module poll default saved${d.pushed ? ` (pushed to ${d.pushed} spoke${d.pushed === 1 ? '' : 's'})` : ''}.`, 'success');
        else showToast('Failed to save: ' + (d.detail || r.status), 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
    }
}

// Setup → Simulations tile. Sim admin overview: global + per-tenant USB
// approvals, cs spoke Kea DHCP status. Served by the Simulations sub-module
// routes under /sim/api/* (core/src/simulations/routes.py), kicked off via
// loadSimAdminOverview() in sim-views.js. (The Tenant Subnet Filtering toggle
// used to live here; it has moved to System → General — see
// _renderSetupGeneralTile, gated by currentView === 'settings'.)
function _renderSetupSimulationsTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="flex items-center gap-6 border-b border-slate-200 mb-4 text-sm font-medium text-slate-600">
                <div id="simtab-btn-usb" onclick="_simSetupTab('usb')" class="sub-nav-item active px-1.5 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">USB</div>
                <div id="simtab-btn-pci" onclick="_simSetupTab('pci')" class="sub-nav-item px-1.5 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">PCI (Tiers)</div>
                <div id="simtab-btn-dhcp" onclick="_simSetupTab('dhcp')" class="sub-nav-item px-1.5 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">DHCP</div>
                <div id="simtab-btn-simq" onclick="_simSetupTab('simq')" class="sub-nav-item px-1.5 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">Quotas</div>
                <div id="simtab-btn-catalog" onclick="_simSetupTab('catalog')" class="sub-nav-item px-1.5 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">Catalog</div>
                <div id="simtab-btn-glv" onclick="_simSetupTab('glv')" class="sub-nav-item px-1.5 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">Learned Values</div>
            </div>
            <div id="simtab-usb" class="space-y-4">
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Discovered USB Devices ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Every USB VID:PID seen across all tenants' spokes (plus tenant-certified/ignored entries not yet in telemetry). Approve or ignore a device type globally — applies to every tenant.</p>
                <div id="global-usb-discovered" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Global USB Approvals ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Platform-wide USB dongle approvals — applies to every tenant (merged with each tenant's own list).</p>
                <div class="space-y-6">
                    <div>
                        <p class="${labelCls} mb-1">Certified globally</p>
                        <div id="global-usb-certified" class="space-y-2 mb-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gusbc-vp" placeholder="1a2b:3c4d" class="w-28 font-mono text-xs ${inputCls} px-2 py-1" title="Vendor ID and Product ID (e.g. 1a2b:3c4d)">
                            <input id="gusbc-label" placeholder="label" class="flex-1 text-xs ${inputCls} px-2 py-1" title="Friendly device description label">
                            <select id="gusbc-type" class="text-xs ${inputCls} px-2 py-1" title="USB device classification type"><option>wireless</option><option>wired</option><option>storage</option><option>other</option></select>
                            <button onclick="addGlobalUsbCert()" class="${btnCls} text-xs px-3 py-1" title="Add device to global certified USB list">+ Add</button>
                        </div>
                    </div>
                    <div>
                        <p class="${labelCls} mb-1">Ignored globally</p>
                        <div id="global-usb-ignored" class="flex flex-wrap gap-1 mb-2 min-h-[2rem]"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gusbi-vp" placeholder="1a2b:3c4d" class="w-28 font-mono text-xs ${inputCls} px-2 py-1" title="Vendor ID and Product ID to ignore">
                            <button onclick="addGlobalUsbIgnore()" class="${btnCls} text-xs px-3 py-1" title="Add device to global ignored USB list">+ Add</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Per-Tenant USB ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Each tenant's own certified/ignored VID:PIDs (merged with the global list when pushed to their spoke). Approve/ignore per tenant below.</p>
                <div id="tenant-usb-list" class="space-y-3"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            </div>
            <div id="simtab-pci" class="space-y-4 hidden">
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Global Tier PCI VID:PIDs ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Platform-wide PCI-passthrough device IDs that classify a VM's tier — applies to every tenant (merged with each tenant's own list). <b>T1</b> = physical / base PCI (e.g. <span class="font-mono">1912:0015</span>); <b>T3</b> = the IoT adapter (e.g. <span class="font-mono">168c:0034</span>). T2 = USB dongle (above). Only T2 is ever auto-deleted under resource pressure; T1/T3 are never torn down.</p>
                <div class="grid grid-cols-2 gap-6">
                    <div>
                        <p class="${labelCls} mb-1">T1 PCI (never torn down)</p>
                        <div id="global-t1-pci" class="flex flex-wrap gap-1 mb-2 min-h-[2rem]"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gt1-vp" placeholder="1912:0015" class="w-28 font-mono text-xs ${inputCls} px-2 py-1" title="PCI vendor:product ID for T1 base hardware">
                            <button onclick="addGlobalTierPci('t1')" class="${btnCls} text-xs px-3 py-1" title="Register T1 physical PCI passthrough device">+ Add</button>
                        </div>
                    </div>
                    <div>
                        <p class="${labelCls} mb-1">T3 PCI (never torn down)</p>
                        <div id="global-t3-pci" class="flex flex-wrap gap-1 mb-2 min-h-[2rem]"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gt3-vp" placeholder="168c:0034" class="w-28 font-mono text-xs ${inputCls} px-2 py-1" title="PCI vendor:product ID for T3 IoT hardware">
                            <button onclick="addGlobalTierPci('t3')" class="${btnCls} text-xs px-3 py-1" title="Register T3 IoT adapter PCI device">+ Add</button>
                        </div>
                    </div>
                </div>
            </div>
            </div>
            <div id="simtab-dhcp" class="space-y-4 hidden">
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">DHCP Server (Kea) ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Isolated sim-client DHCP (Kea <span class="font-mono">kea-dhcp4-sim</span>) on each cs spoke's second NIC (provisioned by install_cs.sh). Shows whether Kea is running and how full the lease pool is. A spoke without Kea shows "Not configured".</p>
                <div id="cs-dhcp-server-status" class="space-y-3"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            </div>
            <div id="simtab-simq" class="space-y-4 hidden">
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Sim Quota Defaults ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Platform-wide default templates a tenant inherits unless it overrides per alert/insight + site in Config → Sim Quotas. Site blank = "all sites". The engine (Chunk 2) merges these with each tenant's overrides. Sims come from the full primitive catalog; a tenant's simulation.conf may offer a subset.</p>
                <div class="flex justify-end flex-wrap gap-2 mb-3">
                    <button onclick="addSimQuotaDefault()" class="${btnCls} text-xs px-3 py-1" title="Define new platform-wide simulation quota default">+ Add Default</button>
                </div>
                <div id="sim-quota-defaults-rows" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Dongle Quarantine — Exclusion Sims</h3>
                  <button onclick="saveQtExcludeSims()" class="${btnCls} text-xs px-3 py-1" title="Save quarantine exclusion simulations">Save</button>
                </div>
                <p class="text-xs text-slate-500 mb-3">Sims whose no-IP / no-SSID outcome is the <b>point</b> of the sim (e.g. <span class="font-mono">dhcp_fail</span>, <span class="font-mono">assoc_fail</span>). A T2 (USB-dongle) client running <b>only</b> these past the 1h grace window is <b>not</b> quarantined. A client running any non-excluded sim (or none) that never connects is shed: its bus is struck + the VM destroyed + re-cloned. Per-tenant override: a tenant's Config → Sim Quotas csc <span class="font-mono">qt_exclude_sims</span> overrides this default.</p>
                <div id="qt-exclude-sims-rows" class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-0"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Simulation Sharing (Stacking)</h3>
                  <div class="flex items-center gap-3">
                    <label class="text-[11px] text-slate-500 flex items-center gap-1"><input type="checkbox" onchange="simSharingToggleHide(this)"> Hide N/A</label>
                  </div>
                </div>
                <p class="text-xs text-slate-500 mb-3">Platform-wide (all tenants): which simulations may be <b>stacked</b> onto a client already running another sim. A <b>non-shareable</b> sim is exclusive — no tenant's Quota Engine will pack it onto a client running other sims (authoritative, overrides a quota's Multi-capable). Mark a sim <b>N/A</b> to hide it via Hide N/A.</p>
                <div id="sim-sharing-rows" class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-0"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Sim Stacking (Weighted)</h3>
                  <button onclick="saveSimStacking()" class="${btnSecCls} text-xs px-3 py-1">Save</button>
                </div>
                <p class="text-xs text-slate-500 mb-3">Platform-wide (all tenants): the ambient pool <b>stacks multiple shareable sims</b> onto each spare client. A sim's <b>weight</b> sets its breadth — weight 3 runs on ~3× the clients of weight 1 (default 1). <b>Max / client</b> caps how many sims one client runs at once; <b>Rotation</b> is how often the assignment re-shuffles so no client keeps the same set forever. Only <b>shareable</b> sims (above) stack, and only sims a tenant lists in <span class="font-mono">randomizable_sims</span> (Config → Pool & SSID) are eligible — empty = stacking off.</p>
                <div class="flex flex-wrap items-center gap-4 mb-3">
                  <label class="text-xs text-slate-600 flex items-center gap-2">Max sims / client
                    <input id="stack-cap" type="number" min="0" max="20" class="${inputCls} text-xs px-2 py-1 w-20"></label>
                  <label class="text-xs text-slate-600 flex items-center gap-2">Rotation (s)
                    <input id="stack-rotation-s" type="number" min="30" step="30" class="${inputCls} text-xs px-2 py-1 w-24"></label>
                  <label class="text-xs text-slate-600 flex items-center gap-2" title="After a client is harvested for an alert sim it rests this long before it can be re-harvested — keeps Central data realistic (no flapping). 0 = off. T1 (PCI radio) clients are EXEMPT: they are the reliable clients the quota sims should run on, so a released T1 is immediately re-harvestable rather than resting while a T2 takes the slot.">Harvest cooldown (h)
                    <input id="harvest-cooldown-h" type="number" min="0" step="0.5" class="${inputCls} text-xs px-2 py-1 w-20"></label>
                </div>
                <div id="sim-stacking-rows" class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-0"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            </div>
            <div id="simtab-catalog" class="space-y-4 hidden">
            <div class="${card}">
                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Observed Catalog ${helpIcon('cs', null, 'Simulations help')}</h3>
                  <div class="flex items-center gap-2">
                    <input id="obs-catalog-search" oninput="_renderObservedCatalog()" placeholder="Search name / category / type…" class="${inputCls} text-xs px-2 py-1 w-56">
                    <button onclick="loadObservedCatalog()" class="${btnSecCls} text-xs px-3 py-1">Refresh</button>
                  </div>
                </div>
                <p class="text-xs text-slate-500 mb-3">Every Central alert/insight the hub has ever observed across <b>all tenants</b> — populated automatically as the hub polls Central and as admins browse Central. This is the same shared library the Sim-Quota "Alert / Insight ID" pickers draw from. Occurrence <b>Count</b> is approximate across hub restarts. Click a column header to sort; use <b>Use in Sim-Quota</b> to stage an entry into a new Sim Quota Defaults row.</p>
                <div id="obs-catalog-table"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            </div>
            <div id="simtab-glv" class="space-y-4 hidden">
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Pending Approval ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">A tenant's learning lab records a stable <b>known-good operating point</b> (the client count + config knobs that reliably fires an alert) and proposes it platform-wide. <b>Approve</b> to publish it for every tenant, or <b>Reject</b> to discard the proposal.</p>
                <div id="glv-pending" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Global Learned Values ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Publish the learned client count needed to fire each alert, platform-wide. A tenant marks a quota row as a <b>Learning lab</b> (Config → Engine); its controller ratchets down to find the min count that fires and records a <b>learned_op</b>. Pick a tenant's stable learned value per alert and Publish it — every other tenant's <b>Consumer</b> rows (Learning off) then seed/lift from it (up-only; never down-ratchet). Highest learned op wins.</p>
                <div id="glv-published" class="space-y-2 mb-4"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Candidates from Learning Labs</h3>
                <p class="text-xs text-slate-500 mb-3">Stable learned values from every tenant's Learning-lab rows, grouped by alert. The highest op per tenant leads. Click <b>Publish</b> to publish that value for the alert (replaces any current published value for it).</p>
                <div id="glv-candidates" class="space-y-3"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            </div>`;
    loadSimAdminOverview();
    loadGlobalTierPci();
    loadSimQuotaDefaults();
    loadObservedCatalog();
    // Auto-save on change. Both cards' fields are rendered dynamically with
    // data-* attributes (no id): quota defaults use data-sqd (+ data-sqd-idpick
    // picker), sharing uses data-simshare / data-simna. The mapper keys off
    // those datasets; "+ Add Default" and "Hide N/A" are unaffected.
    _attachAutoSave(content, _simSaveFnFor, 'simAutoSave');
}

// In-tile sub-tabs for Setup → Simulations: group USB / PCI / DHCP so the tile
// isn't one long stack. Pure show/hide of the three panels + active styling.
function _simSetupTab(name) {
    ['usb', 'pci', 'dhcp', 'simq', 'catalog', 'glv'].forEach(n => {
        const panel = document.getElementById('simtab-' + n);
        const btn = document.getElementById('simtab-btn-' + n);
        if (panel) panel.classList.toggle('hidden', n !== name);
        if (btn) btn.classList.toggle('active', n === name);  // .sub-nav-item.active = HPE-green underline
    });
    // Learned Values loads lazily when its tab is first opened (its panel is
    // hidden on tile render, so we fetch on select rather than up-front).
    if (name === 'glv') loadGlobalLearnedValues();
}


// ── Global Tier PCI VID:PIDs (T1/T3) — superadmin, platform-wide ──────────
// Mirrors the Global USB ignored-list handlers (bare vid:pid strings). Each PUT
// merges global+tenant and pushes to every tenant's spoke (routes.py
// _push_usb_to_tenant), and the agent classifies a VM whose PCI passthrough
// matches → that tier. See /sim/api/superadmin/global-{t1,t3}-pci-vidpids.
function _tierPciEndpoint(tier) { return `/sim/api/superadmin/global-${tier}-pci-vidpids`; }

async function loadGlobalTierPci() {
    for (const tier of ['t1', 't3']) {
        const el = document.getElementById(`global-${tier}-pci`);
        if (!el) continue;
        try {
            const r = await fetch(_tierPciEndpoint(tier), { credentials: 'same-origin' });
            const list = r.ok ? (await r.json()).vidpids || [] : [];
            el.innerHTML = list.length
                ? list.map(vp => `<span class="inline-flex items-center gap-1 text-[11px] font-mono bg-slate-100 text-slate-700 rounded px-2 py-0.5">${vp}<button onclick="removeGlobalTierPci('${tier}','${vp}')" class="text-slate-400 hover:text-red-500" title="Remove">×</button></span>`).join('')
                : '<p class="text-xs text-slate-400 italic">None</p>';
        } catch (e) {
            el.innerHTML = '<p class="text-xs text-red-400 italic">Failed to load</p>';
        }
    }
}

async function addGlobalTierPci(tier) {
    const inp = document.getElementById(`g${tier}-vp`);
    const vp = (inp.value || '').trim().toLowerCase();
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex (e.g. 168c:0034)', 'error'); return; }
    try {
        const r = await fetch(_tierPciEndpoint(tier), { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).vidpids || [] : [];
        if (!cur.includes(vp)) cur.push(vp);
        await apiJson(_tierPciEndpoint(tier), {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vidpids: cur }),
        });
        inp.value = '';
        loadGlobalTierPci();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function removeGlobalTierPci(tier, vp) {
    try {
        const r = await fetch(_tierPciEndpoint(tier), { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).vidpids || [] : [];
        const next = cur.filter(x => x !== vp);
        await fetch(_tierPciEndpoint(tier), {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vidpids: next }),
        });
        loadGlobalTierPci();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

// ── Sim Quota Defaults (Setup → Simulations → Sim Quotas) — superadmin ──────
// Platform-wide default templates a tenant inherits unless it overrides per
// alert/insight + site in Config → Sim Quotas. GET/PUT /sim/api/superadmin/
// sim-quota-defaults (admin-gated). Site is free-text here (blank = "all
// sites"); sims come from the full primitive catalog (a tenant's
// simulation.conf may offer a subset). Mirrors the per-tenant Config → Sim
// Quotas row editor (sim-views.js) but with a free-text site input.
const SIM_QUOTA_DEFAULTS_URL = '/sim/api/superadmin/sim-quota-defaults';
let _simQuotaDefaults = [];
let _simQuotaDefaultsCatalog = { sims: [], sites: [], suggested: {}, meta: {} };

function _simQuotaDefaultFromServer(q) {
    return {
        alert_type: q.alert_type || 'alert',
        alert_id: q.alert_id || '',
        sim_id: q.sim_id || '',
        count: q.count != null ? q.count : 10,
        site: q.site || '',
        multi_capable: !!q.multi_capable,
        rehome: !!q.rehome,
        enabled: !!q.enabled,
        // A sim quota with no alert_id was saved untethered; presence rows (no
        // sim_id) are inherently untethered and ignore this flag.
        tied: !!(q.sim_id && q.alert_id),
    };
}

function _simQuotaDefaultSelect(selected, items, placeholder) {
    return `<option value="">${placeholder}</option>` +
        items.map(it => `<option value="${it}" ${it === selected ? 'selected' : ''}>${it}</option>`).join('');
}

// Simulation dropdown options for a default-quota row: a leading "(Clients
// Associated)" PRESENCE option (value "") — homes N clients to the site, runs
// no sim — then the runnable sim primitives. Selecting presence hides the
// row's Type / Alert ID and forces multi-capable. Mirrors the tenant editor's
// csSimQuotaSimOptions (sim-views.js, both copies).
function _simQuotaDefaultSimOptions(selected, simIds) {
    return '<option value=""' + (selected === '' ? ' selected' : '') +
        '>Clients Associated (no sim)</option>' +
        simIds.map(it => `<option value="${it}" ${it === selected ? 'selected' : ''}>${it}</option>`).join('');
}

// Alert / Insight ID control for a default-quota row: a dropdown sourced from
// the SHARED alert/insight history (catalog.alerts / catalog.insights — every
// alert any tenant has ever seen) that fills the adjacent free-text input, plus
// the free-text input itself so an admin can still type a brand-new alert ID
// before it has ever fired (the chicken/egg the history solves once it has).
function _simQuotaDefaultIdControl(r, ctlCls) {
    const cat = _simQuotaDefaultsCatalog || {};
    const list = (r.alert_type === 'insight' ? cat.insights : cat.alerts) || [];
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    const opts = ['<option value="">— pick from history —</option>'].concat(
        list.map(it => {
            const id = it.id || it.name || '';
            const label = (it.name && it.name !== id) ? `${it.name} — ${id}` : id;
            return `<option value="${esc(id)}">${esc(label)}</option>`;
        })).join('');
    return `<select data-sqd-idpick onchange="_simQuotaDefaultPickId(this)" class="${ctlCls}">${opts}</select>
            <input data-sqd="alert_id" value="${esc(r.alert_id || '')}" placeholder="type or pick — e.g. CLIENT_DHCP_FAILURE" class="${ctlCls}">`;
}
window._simQuotaDefaultPickId = function (sel) {
    const wrap = sel.closest('[data-sqd-row]');
    if (!wrap) return;
    const inp = wrap.querySelector('[data-sqd="alert_id"]');
    if (inp && sel.value) inp.value = sel.value;
};

function _renderSimQuotaDefaultsEditor() {
    const cat = _simQuotaDefaultsCatalog || { sims: [], sites: [], suggested: {}, meta: {} };
    const simIds = (cat.sims || []).map(s => s.sim_id);
    const sites = cat.sites || [];
    const suggested = cat.suggested || {};
    // One shared label + control class so the field labels, dropdowns, and
    // free-form text boxes all render at the same font size / family (text-sm).
    const lblCls = 'text-sm text-slate-600 font-medium';
    const ctlCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500 mt-1';
    const rowsEl = document.getElementById('sim-quota-defaults-rows');
    if (!rowsEl) return;
    const rowHtml = _simQuotaDefaults.map((r, i) => {
        const isPresence = !r.sim_id;
        // A non-presence quota may be UNTETHERED (not tied to an alert/insight):
        // then it needs no alert ID — it just keeps N clients on the sim at the
        // site, much like a presence row. tied defaults on for backward compat.
        const tied = !isPresence && r.tied !== false;
        const simOpts = _simQuotaDefaultSimOptions(r.sim_id, simIds);
        // Site is a dropdown sourced from simulation.conf (platform-wide union).
        // Fall back to a free-text input when no conf has been seen yet so an
        // admin can still type a site before any spoke reports in.
        const siteCtl = sites.length
            ? `<select data-sqd="site" class="${ctlCls}">${_simQuotaDefaultSelect(r.site, sites, '— all sites —')}</select>`
            : `<input data-sqd="site" value="${r.site.replace(/"/g, '&quot;')}" placeholder="all sites" class="${ctlCls}">`;
        // The "Tied to alert/insight" toggle leads the alert section of every
        // sim row so it's obvious it governs the Type / Alert ID fields. Off =
        // untethered (no alert needed). Presence rows have no alert at all.
        const typeCell = isPresence
            ? `<label class="${lblCls}">Presence
                <div class="text-[11px] text-slate-400 italic mt-1 leading-tight">Homes N clients to the site — no sim. They stay free for stackable sims.</div>
              </label>`
            : `<div class="${lblCls}">
                <label class="flex items-center gap-1 cursor-pointer font-semibold text-slate-700"><input data-sqd="tied" type="checkbox" onchange="_simQuotaDefaultOnTiedChange(this)" ${tied ? 'checked' : ''}> Tied to alert/insight</label>
                ${tied
                  ? `<select data-sqd="alert_type" class="${ctlCls}">
                       <option value="alert" ${r.alert_type === 'alert' ? 'selected' : ''}>Alert</option>
                       <option value="insight" ${r.alert_type === 'insight' ? 'selected' : ''}>Insight</option>
                     </select>`
                  : `<div class="text-[11px] text-slate-400 italic mt-1 leading-tight">Presence — no alert/insight (keeps N clients on the sim)</div>`}
              </div>`;
        const idCell = isPresence
            ? `<label class="${lblCls}">Alert / Insight ID
                <div class="text-[11px] text-slate-400 italic mt-1 leading-tight">— none (presence) —</div>
              </label>`
            : (!tied
              ? `<label class="${lblCls}">Alert / Insight ID
                <div class="text-[11px] text-slate-400 italic mt-1 leading-tight">— not required —</div>
              </label>`
              : `<label class="${lblCls}">Alert / Insight ID
                ${_simQuotaDefaultIdControl(r, ctlCls)}
              </label>`);
        return `<div class="grid grid-cols-1 md:grid-cols-7 gap-2 items-end bg-white border border-slate-200 rounded-md p-2" data-sqd-row="${i}">
          ${typeCell}
          ${idCell}
          <label class="${lblCls}">Simulation
            <select data-sqd="sim_id" onchange="_simQuotaDefaultOnSimChange(this)" class="${ctlCls}">${simOpts}</select>
          </label>
          <label class="${lblCls}">Clients
            <input data-sqd="count" type="number" min="1" value="${r.count}" class="${ctlCls}">
          </label>
          <label class="${lblCls}">Site (blank = all)
            ${siteCtl}
          </label>
          <label class="${lblCls} flex flex-col gap-1">
            <span class="flex items-center gap-1"><input data-sqd="multi_capable" type="checkbox" ${isPresence ? 'checked disabled' : (r.multi_capable ? 'checked' : '')}> Multi-capable</span>
            <span class="flex items-center gap-1"><input data-sqd="rehome" type="checkbox" ${r.rehome ? 'checked' : ''}> Re-home</span>
            <span class="flex items-center gap-1"><input data-sqd="enabled" type="checkbox" ${r.enabled ? 'checked' : ''}> Enabled</span>
          </label>
          <button onclick="removeSimQuotaDefault(${i})" class="text-red-600 hover:text-red-800 text-sm font-bold py-2">Remove</button>
        </div>`;
    }).join('');
    const suggestHtml = Object.keys(suggested).length ? `
        <details class="text-xs text-slate-500 mb-2">
          <summary class="cursor-pointer">Suggested alert → sim linkage</summary>
          <ul class="mt-1 list-disc list-inside space-y-0.5">
            ${Object.entries(suggested).map(([a, s]) => `<li><span class="font-mono">${a}</span> → <span class="font-mono">${s}</span> <button onclick="addSimQuotaDefaultSuggested('${a}','${s}')" class="text-[#01A982] hover:underline ml-1">add</button></li>`).join('')}
          </ul>
        </details>` : '';
    rowsEl.innerHTML = suggestHtml + (rowHtml || '<p class="text-xs text-slate-400 italic">No default quotas defined. Add one or pick a suggested linkage above.</p>');
}

function _simQuotaDefaultsSyncFromDom() {
    const rows = [];
    document.querySelectorAll('[data-sqd-row]').forEach(el => {
        const g = (k) => el.querySelector(`[data-sqd="${k}"]`);
        // A presence row (Clients Associated) has no Type / Alert ID controls
        // — nullish-guard so the sync doesn't throw and preserves defaults.
        const sim_id = g('sim_id').value;
        const tied = sim_id ? !!(g('tied') || {}).checked : false;
        rows.push({
            alert_type: (g('alert_type') || {}).value || 'alert',
            // An untethered row (not tied) carries no alert_id regardless of any
            // stale value hidden in the DOM.
            alert_id: tied ? ((g('alert_id') || {}).value || '').trim() : '',
            sim_id,
            count: parseInt(g('count').value || '1', 10) || 1,
            site: g('site').value.trim(),
            multi_capable: !!g('multi_capable').checked,
            rehome: !!g('rehome').checked,
            enabled: !!g('enabled').checked,
            tied,
        });
    });
    _simQuotaDefaults = rows;
    return rows;
}

// Toggling a default row's Simulation between a real sim and "(Clients
// Associated)" (presence) flips the row's Type / Alert ID visibility and
// forces multi-capable for presence. When a real sim with a suggested alert
// linkage is picked, the Alert / Insight ID is AUTO-POPULATED from the
// reverse suggested map (sim → alert) so the admin doesn't have to type the
// canonical alert ID by hand (e.g. picking dhcp_fail fills
// CLIENT_DHCP_FAILURE). The admin can still edit it after. Re-renders the
// editor after syncing current edits from the DOM so nothing is lost.
function _simQuotaDefaultOnSimChange(selectEl) {
    _simQuotaDefaultsSyncFromDom();
    // Reverse the suggested alert→sim map to sim→first alert (the canonical
    // alert for that sim). The catalog ships SUGGESTED_ALERT_SIM as `suggested`.
    const suggested = ((_simQuotaDefaultsCatalog || {}).suggested) || {};
    const bySim = {};
    for (const [alertId, simId] of Object.entries(suggested)) {
        if (!(simId in bySim)) bySim[simId] = alertId;   // first alert wins
    }
    const row = selectEl && selectEl.closest('[data-sqd-row]');
    if (row) {
        const idx = parseInt(row.getAttribute('data-sqd-row'), 10);
        const r = _simQuotaDefaults[idx];
        // Only auto-fill for a real sim with a known suggestion — leave a
        // presence row (sim_id empty) and an unknown sim alone.
        if (r && r.sim_id && bySim[r.sim_id]) {
            r.alert_id = bySim[r.sim_id];
            r.alert_type = 'alert';
        }
    }
    _renderSimQuotaDefaultsEditor();
}

async function loadSimQuotaDefaults() {
    const rowsEl = document.getElementById('sim-quota-defaults-rows');
    if (!rowsEl) return;
    try {
        const data = await apiJson(SIM_QUOTA_DEFAULTS_URL, { credentials: 'same-origin' });
        _simQuotaDefaultsCatalog = data.catalog || { sims: [], sites: [], suggested: {}, meta: {} };
        _simQuotaDefaults = (data.defaults || []).map(_simQuotaDefaultFromServer);
        const cat = _simQuotaDefaultsCatalog;
        _simSharing = (cat.sim_shareable && typeof cat.sim_shareable === 'object') ? { ...cat.sim_shareable } : {};
        _simSharingNA = (cat.sim_na && typeof cat.sim_na === 'object') ? { ...cat.sim_na } : {};
        _qtExcludeSims = Array.isArray(cat.qt_exclude_sims) ? cat.qt_exclude_sims.slice() : [];
        _simWeights = (cat.sim_weights && typeof cat.sim_weights === 'object') ? { ...cat.sim_weights } : {};
        _stackCap = (cat.stack_cap != null) ? cat.stack_cap : 3;
        _stackRotationS = (cat.stack_rotation_s != null) ? cat.stack_rotation_s : 600;
        _harvestCooldownS = (cat.harvest_cooldown_s != null) ? cat.harvest_cooldown_s : 14400;
        _renderSimQuotaDefaultsEditor();
        _renderSimSharing();
        _renderSimStacking();
        _renderQtExcludeSims();
    } catch (e) {
        rowsEl.innerHTML = '<p class="text-xs text-red-400 italic">Failed to load sim quota defaults</p>';
        console.error('loadSimQuotaDefaults failed', e);
    }
}

// ── Simulation Sharing (Stacking) — GLOBAL, Setup → Simulations → Sim Quotas ──
// Platform-wide authoritative per-sim shareable map + a UI-only N/A hide map.
// Saved via the sim-quota-defaults PUT (which also carries the current defaults
// so they aren't wiped). Checkboxes are laid out on a fixed grid so Share / N/A
// line up down every column.
let _simSharing = {};
let _simSharingNA = {};
let _simSharingHideNA = false;

// ── Sim Stacking (Weighted) — GLOBAL, sibling of Simulation Sharing ──────────
// Per-sim breadth weight (weight 3 → ~3× the clients of weight 1), max sims per
// client, and re-shuffle cadence. Saved via the same sim-quota-defaults PUT (which
// also carries defaults + sharing so they aren't wiped). Only shareable sims stack.
let _simWeights = {};
let _stackCap = 3;
let _stackRotationS = 600;
let _harvestCooldownS = 14400;   // 4h; edited in HOURS in the UI

// ── Dongle-quarantine exclusion sims (GLOBAL, Setup → Simulations → Sim Quotas) ─
// The platform-wide set of sim ids whose no-IP/no-SSID outcome is the POINT of
// the sim (dhcp_fail, assoc_fail, …) — a T2 client running ONLY these past the
// 1h grace window is NOT quarantined. Curated in the Sim-Quota Defaults editor;
// saved via the same sim-quota-defaults PUT. The spoke's SimQuotaEngine reads
// the resolved set (this default, overridable per-tenant in csc) from its
// central_sites_config; when neither is set it falls back to the locked default.
let _qtExcludeSims = [];

function _qtExcludeSyncFromDom() {
    _qtExcludeSims = Array.from(document.querySelectorAll('[data-qtexclude]:checked'))
        .map(el => el.getAttribute('data-qtexclude'));
}

function _renderQtExcludeSims() {
    const el = document.getElementById('qt-exclude-sims-rows');
    if (!el) return;
    const cat = _simQuotaDefaultsCatalog || { sims: [] };
    // Every known sim is a candidate (an admin can exclude any sim whose
    // no-connect is by design); sorted for stable display.
    const sims = (cat.sims || []).map(s => s.sim_id)
        .filter(Boolean).sort((a, b) => String(a).toLowerCase().localeCompare(String(b).toLowerCase()));
    const esc = escapeHtml;
    const sel = new Set(_qtExcludeSims);
    el.innerHTML = sims.length
        ? sims.map(f => `<label class="flex items-center gap-2 py-1 border-b border-slate-100 text-xs">
            <input data-qtexclude="${esc(f)}" type="checkbox" ${sel.has(f) ? 'checked' : ''}>
            <span class="font-mono text-slate-600">${esc(f)}</span>
          </label>`).join('')
        : '<p class="text-xs text-slate-400 italic">No simulations found.</p>';
}

function _simSharingSyncFromDom() {
    document.querySelectorAll('[data-simshare]').forEach(el => { _simSharing[el.getAttribute('data-simshare')] = !!el.checked; });
    document.querySelectorAll('[data-simna]').forEach(el => { _simSharingNA[el.getAttribute('data-simna')] = !!el.checked; });
}

function _renderSimSharing() {
    const el = document.getElementById('sim-sharing-rows');
    if (!el) return;
    const cat = _simQuotaDefaultsCatalog || {};
    const meta = cat.meta || {};
    const sims = (cat.sims || []).map(s => s.sim_id).filter(Boolean);
    Object.keys(_simSharing).forEach(k => { if (sims.indexOf(k) < 0) sims.push(k); });
    Object.keys(_simSharingNA).forEach(k => { if (sims.indexOf(k) < 0) sims.push(k); });
    sims.sort((a, b) => String(a).toLowerCase().localeCompare(String(b).toLowerCase()));
    const naVal = f => Object.prototype.hasOwnProperty.call(_simSharingNA, f) ? !!_simSharingNA[f] : false;
    const list = sims.filter(f => !_simSharingHideNA || !naVal(f));
    if (!list.length) { el.innerHTML = '<p class="text-xs text-slate-400 italic">No simulations found.</p>'; return; }
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    el.innerHTML = list.map(f => {
        const na = naVal(f);
        const def = !!(meta[f] && meta[f].multi_capable);
        const cur = Object.prototype.hasOwnProperty.call(_simSharing, f) ? !!_simSharing[f] : def;
        return `<label class="grid grid-cols-[minmax(0,1fr)_5rem_3.5rem] items-center gap-2 py-1 border-b border-slate-100 ${na ? 'opacity-60' : ''}">
          <span class="text-xs font-mono text-slate-600 truncate">${esc(f)}</span>
          <span class="flex items-center gap-1 text-xs"><input data-simshare="${esc(f)}" type="checkbox" ${cur ? 'checked' : ''} ${na ? 'disabled' : ''}> Share</span>
          <span class="flex items-center gap-1 text-xs text-slate-400"><input data-simna="${esc(f)}" type="checkbox" onchange="simSharingOnNA()" ${na ? 'checked' : ''}> N/A</span>
        </label>`;
    }).join('');
}

window.simSharingOnNA = function () {
    _simSharingSyncFromDom(); _renderSimSharing();
    // A sharing change adds/removes a stackable sim → refresh the weight list
    // (sync typed weights first so they survive the re-render).
    _simStackingSyncFromDom(); _renderSimStacking();
};
window.simSharingToggleHide = function (cb) { _simSharingSyncFromDom(); _simSharingHideNA = !!(cb && cb.checked); _renderSimSharing(); };

// ── Sim Stacking (Weighted) render / sync / save ─────────────────────────────
function _simStackingSyncFromDom() {
    document.querySelectorAll('[data-simweight]').forEach(el => {
        const v = parseFloat(el.value);
        _simWeights[el.getAttribute('data-simweight')] = (isFinite(v) && v >= 0) ? v : 1;
    });
    const capEl = document.getElementById('stack-cap');
    const rotEl = document.getElementById('stack-rotation-s');
    const cdEl = document.getElementById('harvest-cooldown-h');
    if (capEl) { const c = parseInt(capEl.value, 10); if (isFinite(c) && c >= 0) _stackCap = c; }
    if (rotEl) { const r = parseInt(rotEl.value, 10); if (isFinite(r) && r >= 30) _stackRotationS = r; }
    if (cdEl) { const h = parseFloat(cdEl.value); if (isFinite(h) && h >= 0) _harvestCooldownS = Math.round(h * 3600); }
}

function _renderSimStacking() {
    const capEl = document.getElementById('stack-cap');
    const rotEl = document.getElementById('stack-rotation-s');
    if (capEl && document.activeElement !== capEl) capEl.value = (_stackCap != null ? _stackCap : 3);
    if (rotEl && document.activeElement !== rotEl) rotEl.value = (_stackRotationS != null ? _stackRotationS : 600);
    const cdEl = document.getElementById('harvest-cooldown-h');
    if (cdEl && document.activeElement !== cdEl) cdEl.value = ((_harvestCooldownS != null ? _harvestCooldownS : 14400) / 3600);
    const el = document.getElementById('sim-stacking-rows');
    if (!el) return;
    const cat = _simQuotaDefaultsCatalog || {};
    const meta = cat.meta || {};
    // Only SHAREABLE sims stack — mirror _renderSimSharing's effective share.
    const isShare = f => Object.prototype.hasOwnProperty.call(_simSharing, f)
        ? !!_simSharing[f] : !!(meta[f] && meta[f].multi_capable);
    let sims = (cat.sims || []).map(s => s.sim_id).filter(Boolean);
    Object.keys(_simWeights).forEach(k => { if (sims.indexOf(k) < 0) sims.push(k); });
    sims = sims.filter(isShare).sort((a, b) =>
        String(a).toLowerCase().localeCompare(String(b).toLowerCase()));
    if (!sims.length) {
        el.innerHTML = '<p class="text-xs text-slate-400 italic">No shareable simulations — mark sims <b>Share</b> above to weight them for stacking.</p>';
        return;
    }
    const esc = escapeHtml;
    el.innerHTML = sims.map(f => {
        const w = Object.prototype.hasOwnProperty.call(_simWeights, f) ? _simWeights[f] : 1;
        return `<label class="grid grid-cols-[minmax(0,1fr)_5rem] items-center gap-2 py-1 border-b border-slate-100">
          <span class="text-xs font-mono text-slate-600 truncate">${esc(f)}</span>
          <input data-simweight="${esc(f)}" type="number" min="0" step="0.5" value="${esc(String(w))}" class="border border-slate-300 rounded px-2 py-0.5 text-xs w-16">
        </label>`;
    }).join('');
}

window.saveSimStacking = async function () {
    _simStackingSyncFromDom();
    try {
        const r = await fetch(SIM_QUOTA_DEFAULTS_URL, {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            // Carry defaults + sharing so the shared PUT doesn't wipe them.
            body: JSON.stringify({ defaults: _simQuotaDefaultsSyncFromDom(),
                                   sim_shareable: _simSharing, sim_na: _simSharingNA,
                                   sim_weights: _simWeights, stack_cap: _stackCap,
                                   stack_rotation_s: _stackRotationS,
                                   harvest_cooldown_s: _harvestCooldownS }),
        });
        if (!r.ok) throw new Error(`${r.status}`);
        if (typeof showToast === 'function') showToast('Sim stacking saved.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast((e && e.message) || 'Save failed', 'error');
        console.error('saveSimStacking failed', e);
    }
};

window.saveQtExcludeSims = async function () {
    _qtExcludeSyncFromDom();
    try {
        const r = await fetch(SIM_QUOTA_DEFAULTS_URL, {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            // Include current defaults + sharing so the shared PUT doesn't wipe them.
            body: JSON.stringify({ defaults: _simQuotaDefaultsSyncFromDom(),
                                   sim_shareable: _simSharing, sim_na: _simSharingNA,
                                   qt_exclude_sims: _qtExcludeSims }),
        });
        if (!r.ok) throw new Error(`${r.status}`);
        if (typeof showToast === 'function') showToast('Quarantine exclusion sims saved.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast((e && e.message) || 'Save failed', 'error');
        console.error('saveQtExcludeSims failed', e);
    }
};

window.saveSimSharing = async function () {
    _simSharingSyncFromDom();
    try {
        const r = await fetch(SIM_QUOTA_DEFAULTS_URL, {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            // Include current defaults so the shared PUT doesn't wipe them.
            body: JSON.stringify({ defaults: _simQuotaDefaultsSyncFromDom(), sim_shareable: _simSharing, sim_na: _simSharingNA, qt_exclude_sims: _qtExcludeSyncFromDom() }),
        });
        if (!r.ok) throw new Error(`${r.status}`);
        if (typeof showToast === 'function') showToast('Simulation sharing saved.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast((e && e.message) || 'Save failed', 'error');
        console.error('saveSimSharing failed', e);
    }
};

function addSimQuotaDefault(preset) {
    _simQuotaDefaultsSyncFromDom();
    const p = preset || {};
    _simQuotaDefaults.push({
        alert_type: p.alert_type || 'alert',
        alert_id: p.alert_id || '',
        sim_id: p.sim_id || '',
        count: p.count != null ? p.count : 10,
        site: p.site || '',
        multi_capable: p.multi_capable != null ? !!p.multi_capable : false,
        rehome: p.rehome != null ? !!p.rehome : false,
        enabled: p.enabled != null ? !!p.enabled : false,
        tied: p.tied != null ? !!p.tied : true,
    });
    _renderSimQuotaDefaultsEditor();
}

// Toggling a row's "Tied to alert/insight" flips whether the Type / Alert ID
// controls show (an untethered quota needs no alert). Sync current edits from
// the DOM first so nothing is lost on the re-render.
window._simQuotaDefaultOnTiedChange = function (cb) {
    _simQuotaDefaultsSyncFromDom();
    const row = cb && cb.closest('[data-sqd-row]');
    if (row) {
        const idx = parseInt(row.getAttribute('data-sqd-row'), 10);
        if (_simQuotaDefaults[idx]) _simQuotaDefaults[idx].tied = !!cb.checked;
    }
    _renderSimQuotaDefaultsEditor();
};

function addSimQuotaDefaultSuggested(alertId, simId) {
    addSimQuotaDefault({ alert_id: alertId, sim_id: simId, count: 10 });
}

function removeSimQuotaDefault(i) {
    _simQuotaDefaultsSyncFromDom();
    _simQuotaDefaults.splice(i, 1);
    _renderSimQuotaDefaultsEditor();
}

async function saveSimQuotaDefaults() {
    const rows = _simQuotaDefaultsSyncFromDom();
    try {
        const data = await apiJson(SIM_QUOTA_DEFAULTS_URL, {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ defaults: rows, qt_exclude_sims: _qtExcludeSyncFromDom() }),
        });
        _simQuotaDefaults = (data.defaults || rows).map(_simQuotaDefaultFromServer);
        _renderSimQuotaDefaultsEditor();
        const errs = data.errors || [];
        if (typeof showToast === 'function') {
            if (errs.length) showToast(`Saved with ${errs.length} issue(s): ${errs.join('; ')}`, 'error');
            else showToast('Sim quota defaults saved.', 'success');
        }
    } catch (e) {
        if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error');
        console.error('saveSimQuotaDefaults failed', e);
    }
}

// ── Observed Catalog (Setup → Simulations → Catalog) — superadmin ───────────
// Read-only view of the hub-wide __alert_insight_history__ catalog: every
// Central alert/insight observed across ALL tenants, with occurrence counts.
// GET /sim/api/superadmin/observed-catalog (admin-gated) → {catalog:[...],count}.
// Searchable + click-to-sort table; the row "Use in Sim-Quota" action stages
// the entry into a new Sim Quota Defaults row (the superadmin/platform-wide
// sibling editor in this same tile) and switches to the Quotas sub-tab.
const OBSERVED_CATALOG_URL = '/sim/api/superadmin/observed-catalog';
let _observedCatalog = [];
let _observedCatalogSort = { key: 'last_seen', dir: 'desc' };

async function loadObservedCatalog() {
    const el = document.getElementById('obs-catalog-table');
    if (!el) return;
    try {
        const data = await apiJson(OBSERVED_CATALOG_URL, { credentials: 'same-origin' });
        _observedCatalog = Array.isArray(data.catalog) ? data.catalog : [];
        _renderObservedCatalog();
    } catch (e) {
        el.innerHTML = '<p class="text-xs text-red-400 italic">Failed to load observed catalog</p>';
        console.error('loadObservedCatalog failed', e);
    }
}

// Click a sortable header: toggle direction if same key, else sort by the new
// key (text asc / numeric desc by default). Re-renders from the cached data.
function _observedCatalogSortBy(key) {
    if (_observedCatalogSort.key === key) {
        _observedCatalogSort.dir = _observedCatalogSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        _observedCatalogSort = { key, dir: (key === 'name' || key === 'type') ? 'asc' : 'desc' };
    }
    _renderObservedCatalog();
}

function _renderObservedCatalog() {
    const el = document.getElementById('obs-catalog-table');
    if (!el) return;
    const esc = escapeHtml;  // shared escaper (escapes &<>"')
    if (!_observedCatalog.length) {
        el.innerHTML = '<p class="text-sm text-slate-400 italic py-4">No alerts/insights observed yet — they populate automatically as the hub polls Central.</p>';
        return;
    }
    const q = ((document.getElementById('obs-catalog-search') || {}).value || '').trim().toLowerCase();
    let rows = _observedCatalog.slice();
    if (q) rows = rows.filter(e => [e.name, e.category, e.type, e.id].some(v => String(v == null ? '' : v).toLowerCase().includes(q)));
    const { key, dir } = _observedCatalogSort;
    const mul = dir === 'asc' ? 1 : -1;
    const numeric = (key === 'count' || key === 'last_seen' || key === 'first_seen');
    rows.sort((a, b) => {
        if (numeric) return (Number(a[key] || 0) - Number(b[key] || 0)) * mul;
        return String(a[key] == null ? '' : a[key]).toLowerCase()
            .localeCompare(String(b[key] == null ? '' : b[key]).toLowerCase()) * mul;
    });
    const arrow = k => _observedCatalogSort.key === k ? (_observedCatalogSort.dir === 'asc' ? ' ▲' : ' ▼') : '';
    // Sortable columns carry an onclick; the rest are plain headers.
    const sortTh = (k, label) => `<th class="px-4 py-2 text-left font-medium cursor-pointer select-none hover:text-slate-700" onclick="_observedCatalogSortBy('${k}')">${label}${arrow(k)}</th>`;
    const plainTh = label => `<th class="px-4 py-2 text-left font-medium">${label}</th>`;
    const head = `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>` +
        sortTh('type', 'Type') + sortTh('name', 'Name') + plainTh('Category') +
        plainTh('Severity') + plainTh('Device Type') + plainTh('Site') +
        plainTh('First Seen') + sortTh('last_seen', 'Last Seen') + sortTh('count', 'Count') +
        plainTh('Action') + `</tr></thead>`;
    const body = rows.map(e => {
        const type = String(e.type || 'alert');
        const badgeCls = type === 'insight' ? 'bg-sky-100 text-sky-700' : 'bg-amber-100 text-amber-700';
        return `<tr class="border-t border-slate-100">
          <td class="px-4 py-2"><span class="inline-block text-[11px] font-medium rounded px-2 py-0.5 ${badgeCls}">${esc(type)}</span></td>
          <td class="px-4 py-2 text-slate-800">${esc(e.name || e.id || '')}</td>
          <td class="px-4 py-2 text-slate-500">${esc(e.category || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${esc(e.severity || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${esc(e.device_type || '—')}</td>
          <td class="px-4 py-2 text-slate-500">${esc(e.site || '—')}</td>
          <td class="px-4 py-2 text-slate-500 whitespace-nowrap">${esc(fmtDate(e.first_seen))}</td>
          <td class="px-4 py-2 text-slate-500 whitespace-nowrap">${esc(fmtDate(e.last_seen))}</td>
          <td class="px-4 py-2 text-slate-700 tabular-nums">${esc(String(e.count == null ? 1 : e.count))}</td>
          <td class="px-4 py-2"><button data-obs-type="${esc(type)}" data-obs-id="${esc(e.id || '')}" data-obs-name="${esc(e.name || e.id || '')}" onclick="_useInSimQuota(this)" class="text-[#01A982] hover:underline text-xs font-medium">Use in Sim-Quota</button></td>
        </tr>`;
    }).join('');
    const empty = '<tr><td colspan="10" class="px-4 py-6 text-center text-slate-400">No entries match your search.</td></tr>';
    el.innerHTML = tableWrap(head + `<tbody>${body || empty}</tbody>`);
}

// Stage an observed entry into a NEW Sim Quota Defaults row (the platform-wide
// superadmin editor in this same tile — the natural target for a cross-tenant
// catalog) with its Alert/Insight type + id pre-filled, then switch to the
// Quotas sub-tab so the admin picks a simulation and saves. Reads type/id/name
// from the button's data-* attributes (escaped, so quotes in a name are safe).
function _useInSimQuota(btn) {
    const type = (btn.getAttribute('data-obs-type') === 'insight') ? 'insight' : 'alert';
    const id = btn.getAttribute('data-obs-id') || '';
    const name = btn.getAttribute('data-obs-name') || id;
    if (!id) return;
    if (typeof addSimQuotaDefault !== 'function') return;
    addSimQuotaDefault({ alert_type: type, alert_id: id, tied: true });
    _simSetupTab('simq');
    const rowsEl = document.getElementById('sim-quota-defaults-rows');
    if (rowsEl && typeof rowsEl.scrollIntoView === 'function') rowsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (typeof showToast === 'function') showToast(`Staged '${name}' into a new Sim-Quota Default row — pick a simulation and Save.`, 'success');
}

// Setup → General (default) tile. Data cache status + update sources + appearance.
// GET /setup/config + /admin/cache/status + /api/appearance (core/src/api.py
// get_setup_config, routes/admin_cache.py admin_cache_status, get_appearance). When invoked from the
// System view (currentView === 'settings'), also renders the Tenant Subnet
// Filtering toggle card — a system-wide enforcement posture setting that lives
// here rather than under Setup → Simulations. The same renderer serves Setup →
// General, where the toggle is intentionally hidden.
function _renderSetupGeneralTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    const subnetFilterCard = currentView === 'settings' ? `
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Tenant Subnet Filtering ${helpIcon('lm-hub', null, 'Hub help')}</h3>
            <p class="text-xs text-slate-500 mb-3">Filter each module's data by the tenant's NetBox prefixes, enforced server-side (a tenant cannot see another tenant's subnet data even via the API). Disable for modules that are scoped by tenant ID instead of subnet (e.g. Simulations).</p>
            <div id="subnet-filter-toggles" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
        </div>` : '';
    const certMonCard = (currentView === 'settings' && isAdmin()) ? `
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Cert Expiry Monitor</h3>
            <p class="text-xs text-slate-400">Daily check of the TLS certificates on the public Aruba Central / HPE GreenLake and Juniper Mist cloud endpoints. When enabled, a <b>Cert Monitor</b> item appears in the left menu (Global Admins only).</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer">
                <input type="checkbox" id="certmon-enabled" onchange="saveCertMonEnabled(this)" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                Enable Cert Expiry Monitor
            </label>
        </div>` : '';
    content.innerHTML = `
        ${subnetFilterCard}
        ${certMonCard}
        <div class="${card}">
            <div class="flex justify-between items-center">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Data Cache ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <div class="flex items-center gap-3">
                    <button onclick="refreshCacheNamespace()" class="${btnSecCls}" title="Refresh every cached module from the spokes now">Refresh now</button>
                    <button onclick="purgeAllCaches()" class="${btnSecCls}" title="Drop all cached data; it is fetched again right away">Purge All</button>
                </div>
            </div>
            <div id="cache-status-rows" class="mt-3 text-sm">
                <p class="py-4 text-center text-slate-400 italic text-xs">Loading…</p>
            </div>
        </div>
        <div class="${card}">
            <div class="flex justify-between items-center">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Update Configuration ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <div class="flex gap-2">
                    <button onclick="triggerUpdate(event)" class="${btnCls}">Update All</button>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Hub Repo URL</label><div class="flex gap-2"><input type="text" id="update-source-hub" class="${inputCls}"><button onclick="scanGitHubRepos()" class="${btnSecCls} whitespace-nowrap">Scan GH</button></div></div>
                <div class="space-y-1"><label class="${labelCls}">Global Branch</label><select id="global-branch" class="${inputCls}"><option value="main">main</option></select></div>
                <div class="space-y-1"><label class="${labelCls}">Proxmox Repo</label><input type="text" id="update-source-pxmx" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">OPNsense Repo</label><input type="text" id="update-source-opn" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Client Sim Repo</label><input type="text" id="update-source-cs" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">CPPM Repo</label><input type="text" id="update-source-cppm" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">NetBox Repo</label><input type="text" id="update-source-netbox" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">LDAP Repo</label><input type="text" id="update-source-ldap" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Network Devices Repo</label><input type="text" id="update-source-nw" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Certificates (LE) Repo</label><input type="text" id="update-source-le" class="${inputCls}"></div>
            </div>
            <div class="flex items-center gap-4 pt-2">
                <span id="last-update-ts" class="text-xs text-slate-400"></span>
            </div>
            <div class="border-t border-slate-200 mt-4 pt-4">
                <p class="text-xs text-slate-400 mb-3">How often the hub checks GitHub and syncs: pulls the hub tree + <code>provisioning_repos/*</code> locally and pushes an update to every approved spoke. Same schedule as System → Sync's "GitHub Repo Sync" card — either one saves/shows it.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="repo-sync-enabled" class="w-4 h-4 text-green-600 rounded" checked>Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Check every (minutes)</label>
                        <input type="number" id="repo-sync-interval" min="1" value="15" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
            </div>
        </div>
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Notifications ${helpIcon('lm-hub', null, 'Hub help')}</h3>
            <p class="text-xs text-slate-400">How long toast messages (success/error confirmations in the bottom/top-right corner) stay on screen before fading out. A visible dismiss (×) always closes one early regardless of this setting.</p>
            <div class="flex items-center gap-3">
                <label class="${labelCls}">Toast Duration (seconds)</label>
                <input type="number" id="toast-duration-input" min="1" max="300" value="10"
                    class="w-20 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                <span id="toast-duration-status" class="text-xs text-slate-400"></span>
            </div>
        </div>
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Agent Relay Timeouts ${helpIcon('lm-hub', null, 'Hub help')}</h3>
            <p class="text-xs text-slate-400">How long a cs spoke waits for its hosted Proxmox agent to acknowledge a relayed command. Long ops (delete / reclone / snapshot / clone / provision) ack immediately and stream their result, but a busy (auto-prov cloning) or WAN-connected agent can be slow — raise the long-op window to avoid false "Agent response timeout" failures. Pushed to cs spokes on connect.</p>
            <div class="flex flex-wrap items-end gap-3">
                <div class="space-y-1"><label class="${labelCls}">Long-op timeout (s)</label>
                    <input type="number" id="relay-timeout-long" min="1" max="600" value="60" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="space-y-1"><label class="${labelCls}">Fast timeout (s)</label>
                    <input type="number" id="relay-timeout-fast" min="1" max="600" value="15" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <span id="relay-timeout-status" class="text-xs text-slate-400"></span>
            </div>
        </div>
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Appearance ${helpIcon('lm-hub', null, 'Hub help')}</h3>
            <p class="text-xs text-slate-400">Configure the header logo shown to the left of the title. Use <code>hpe-svg</code> for the built-in HPE mark, or any image URL/path.</p>
            <div class="space-y-1">
                <label class="${labelCls}">Header logo URL / <code>hpe-svg</code></label>
                <input id="appearance-logo-url" type="text" class="${inputCls}" placeholder="hpe-svg">
            </div>
            <div class="flex items-center gap-2">
                <input id="appearance-show-logo" type="checkbox" class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                <label for="appearance-show-logo" class="text-sm text-slate-600">Show header logo</label>
            </div>
            <div class="flex justify-end items-center gap-3">
                <span id="appearance-status" class="text-xs text-slate-400"></span>
            </div>
        </div>`;
    loadSetupConfig();
    loadCacheStatus();
    loadAppearanceForm();
    loadToastConfigForm();
    loadRelayTimeoutsForm();
    loadRepoSyncConfig();
    if (currentView === 'settings') loadSubnetFilterToggles();
    if (certMonCard) loadCertMonToggle();
    // Auto-save on change (no per-card Save buttons). The Data Cache card is
    // read-only status (no inputs), so it has no save handler.
    _attachAutoSave(content, _generalSaveFnFor, 'generalAutoSave');
}

// Map a General-tile field element → its card's save handler (auto-save on change).
function _generalSaveFnFor(el) {
    if (!el) return null;
    const id = el.id || '';
    if (id.startsWith('update-source-') || id === 'global-branch') return saveUpdateSources;
    if (id.startsWith('repo-sync-'))      return saveRepoSyncConfig;
    if (id.startsWith('toast-'))          return saveToastConfig;
    if (id.startsWith('relay-timeout-'))  return saveRelayTimeouts;
    if (id.startsWith('appearance-'))     return saveAppearance;
    return null;
}

// Dispatch table: each Setup submenu → its tile renderer. The General tile is
// the fallback (run when subMenu matches none of the keys), preserving the
// original monolithic function's trailing default branch.
// ── Settings → SSO (Microsoft Entra ID / OIDC) ──────────────────────────────
// Admin config for Entra ID SSO — enable it, set tenant/client/cert/group/MFA.
// Reads/writes /setup/oidc-config (core/src/routes/oidc.py); env LM_OIDC_* wins
// over stored values. Enabling shows the "Sign in with Microsoft" login button.
// ── Settings → Cloud NAC (JIT Entra provisioning for sim 1X clients) ────────
function _renderSettingsCloudNacTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Cloud NAC — JIT Entra accounts</h3>
                <span id="cn-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">When the engine moves a sim client onto a <b>1X SSID</b>, the hub creates an Entra account for that user, sets a random password, and delivers it to the client as its 802.1X password. Idle accounts (no sign-in for <b>Idle days</b>) are swept + deleted. Reuses the <b>SSO Entra app</b> cert — the app needs Graph <b>User.ReadWrite.All</b> + <b>AuditLog.Read.All</b> (Application) consented, and Entra ID P1 for the sign-in-activity sweep.</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="cn-enabled" class="w-4 h-4 text-green-600 rounded">Enable Cloud NAC provisioning</label>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="space-y-1"><label class="${labelCls}">UPN domain</label><input id="cn-domain" type="text" placeholder="ssplm.onmicrosoft.com" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Idle days (delete after)</label><input id="cn-idle" type="number" placeholder="7" class="${inputCls}"></div>
            </div>
            <div class="mt-3 space-y-1">
                <label class="${labelCls}">Add provisioned users to Entra group <span class="text-slate-400 normal-case font-normal">(optional — target this group with a CA MFA-exclusion / Cloud Auth policy)</span></label>
                <div class="flex gap-2">
                    <input id="cn-group-id" type="text" placeholder="group object ID" class="${inputCls} font-mono text-xs flex-1">
                    <input id="cn-group-name" type="text" placeholder="(name)" readonly class="${inputCls} text-xs flex-1 bg-slate-50">
                    <button type="button" onclick="loadCloudNacGroupPicker()" id="cn-group-btn" class="whitespace-nowrap bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold">Pick from Entra</button>
                </div>
                <select id="cn-group-select" onchange="onCloudNacGroupPick(this)" class="hidden w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></select>
                <p id="cn-group-msg" class="text-[11px] text-amber-600 hidden"></p>
            </div>
            <div class="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3">
                <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">Test provision</div>
                <div class="flex gap-2">
                    <input id="cn-test-user" type="text" placeholder="username (e.g. cschmidt)" class="${inputCls} font-mono text-xs flex-1">
                    <button type="button" onclick="provisionCloudNac()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold whitespace-nowrap">Provision</button>
                </div>
                <p id="cn-test-out" class="text-[11px] font-mono text-slate-600 mt-1 break-all"></p>
            </div>
            <div class="mt-4">
                <div class="flex items-center justify-between mb-1">
                    <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Provisioned accounts <span id="cn-count" class="text-slate-400 font-normal"></span></div>
                    <button type="button" onclick="sweepCloudNac()" class="text-[#01A982] hover:underline text-xs font-bold">Sweep idle now</button>
                </div>
                <div id="cn-accounts" class="border border-slate-200 rounded-md divide-y divide-slate-100 max-h-72 overflow-y-auto text-xs"></div>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="cn-msg" class="text-xs text-slate-400"></span>
            </div>
        </div>`;
    loadCloudNac();
    // Auto-save on change (allowlist mapper — the test-user field and action /
    // display ids are excluded). Picking a group in cn-group-select runs its
    // own onchange (fills cn-group-id/name) then this delegated save fires.
    _attachAutoSave(content, _cloudNacSaveFnFor, 'cloudNacAutoSave');
}

async function loadCloudNac() {
    try {
        const r = await setupFetch('/setup/cloud-nac');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v == null ? '' : v; };
        const el = document.getElementById('cn-enabled'); if (el) el.checked = !!c.enabled;
        set('cn-domain', c.domain); set('cn-idle', c.idle_days || 7);
        set('cn-group-id', c.group_id); set('cn-group-name', c.group_name);
        const pill = document.getElementById('cn-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        const cnt = document.getElementById('cn-count'); if (cnt) cnt.textContent = `(${d.count || 0})`;
        const box = document.getElementById('cn-accounts');
        if (box) {
            const accts = d.accounts || [];
            box.innerHTML = accts.length ? accts.map(a => `
              <div class="flex items-center gap-2 px-2 py-1">
                <span class="font-mono text-slate-700 w-40 shrink-0 truncate" title="${escapeHtml(a.upn || a.username)}">${escapeHtml(a.username)}</span>
                <span class="text-slate-400 flex-1 truncate" title="provisioned ${escapeHtml(a.provisioned_at || '')}">${escapeHtml(a.upn || '')}</span>
                <button type="button" onclick="deprovisionCloudNac('${escapeHtml(a.username)}')" title="Delete Entra account" class="text-red-500 hover:text-red-700 font-bold px-1">✕</button>
              </div>`).join('')
              : '<div class="text-slate-400 italic px-2 py-2">No accounts provisioned yet.</div>';
        }
    } catch (e) { console.error('loadCloudNac failed', e); }
}

function _cloudNacFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    return {
        enabled: !!document.getElementById('cn-enabled')?.checked,
        domain: v('cn-domain'), idle_days: parseInt(v('cn-idle'), 10) || 7,
        group_id: v('cn-group-id'), group_name: v('cn-group-name'),
    };
}

// Reuse the Entra group list (/setup/oidc/groups) to pick the target group by
// name — fills the object ID the provisioning adds users to.
async function loadCloudNacGroupPicker() {
    const btn = document.getElementById('cn-group-btn');
    const sel = document.getElementById('cn-group-select');
    const msg = document.getElementById('cn-group-msg');
    if (!sel) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Loading…'; }
    try {
        const res = await setupFetch('/setup/oidc/groups');
        const d = await res.json().catch(() => ({}));
        const groups = (d && d.groups) || [];
        if (!groups.length) {
            if (msg) { msg.textContent = (d && d.warning) || 'No Entra groups returned (needs Graph Group.Read.All + a generated cert).'; msg.classList.remove('hidden'); }
            sel.classList.add('hidden');
        } else {
            sel.innerHTML = '<option value="">— select an Entra group —</option>' +
                groups.map(g => `<option value="${escapeHtml(g.id)}" data-name="${escapeHtml(g.displayName)}">${escapeHtml(g.displayName)} — ${escapeHtml(g.id)}</option>`).join('');
            sel.classList.remove('hidden');
            if (msg) msg.classList.add('hidden');
        }
    } catch (e) {
        if (msg) { msg.textContent = 'Failed to load Entra groups: ' + (e.message || e); msg.classList.remove('hidden'); }
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Pick from Entra'; }
    }
}
function onCloudNacGroupPick(sel) {
    const id = sel.value;
    if (!id) return;
    const opt = sel.options[sel.selectedIndex];
    const idEl = document.getElementById('cn-group-id'); if (idEl) idEl.value = id;
    const nameEl = document.getElementById('cn-group-name'); if (nameEl) nameEl.value = (opt && opt.getAttribute('data-name')) || '';
}

// Allowed-group picker for SSO (Setup → Azure → SSO). Reuses /setup/oidc/groups
// — the same Entra directory list Cloud NAC's picker uses — so the admin
// picks a group instead of pasting its object ID. On pick, the object ID is
// written into the oidc-group input; the delegated change listener on
// oidc-group-select (in _oidcSaveFnFor) then fires saveOidcConfig.
async function loadOidcGroupPicker() {
    const btn = document.getElementById('oidc-group-btn');
    const sel = document.getElementById('oidc-group-select');
    const msg = document.getElementById('oidc-group-msg');
    if (!sel) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Loading…'; }
    try {
        const res = await setupFetch('/setup/oidc/groups');
        const d = await res.json().catch(() => ({}));
        const groups = (d && d.groups) || [];
        if (!groups.length) {
            if (msg) { msg.textContent = (d && d.warning) || 'No Entra groups returned (needs Graph Group.Read.All + a generated cert).'; msg.classList.remove('hidden'); }
            sel.classList.add('hidden');
        } else {
            sel.innerHTML = '<option value="">— select an Entra group —</option>' +
                groups.map(g => `<option value="${escapeHtml(g.id)}" data-name="${escapeHtml(g.displayName)}">${escapeHtml(g.displayName)} — ${escapeHtml(g.id)}</option>`).join('');
            sel.classList.remove('hidden');
            if (msg) msg.classList.add('hidden');
        }
    } catch (e) {
        if (msg) { msg.textContent = 'Failed to load Entra groups: ' + (e.message || e); msg.classList.remove('hidden'); }
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Pick from Entra'; }
    }
}
function onOidcGroupPick(sel) {
    const id = sel.value;
    if (!id) return;
    const idEl = document.getElementById('oidc-group');
    if (idEl) {
        // APPEND to the allowed-groups list (multiple allowed) rather than
        // replace — de-duped, comma-separated.
        const cur = (idEl.value || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
        if (!cur.includes(id)) cur.push(id);
        idEl.value = cur.join(', ');
    }
    sel.value = '';
    // the delegated change listener on oidc-group-select fires saveOidcConfig
}

async function saveCloudNac() {
    const btn = document.getElementById('cn-save-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/cloud-nac', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _cloudNacFormConfig() }) });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
        showToast('Cloud NAC config saved.', 'success');
        loadCloudNac();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save'; } }
}

async function provisionCloudNac() {
    const user = (document.getElementById('cn-test-user')?.value || '').trim().toLowerCase();
    const out = document.getElementById('cn-test-out');
    if (!user) { showToast('Enter a username', 'info'); return; }
    if (out) out.textContent = 'Provisioning…';
    try {
        const d = await apiJson('/setup/cloud-nac/provision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: user }) });
        const grp = d.group_warning ? `  ⚠ group: ${d.group_warning}` : (d.group_added ? '  ✓ added to group' : '');
        if (out) out.textContent = `${d.created ? 'Created' : 'Reset'} ${d.upn} — password: ${d.password}  (shown once)${grp}`;
        showToast(`${d.created ? 'Created' : 'Reset'} ${d.upn}${d.group_added ? ' (+group)' : ''}`, 'success');
        loadCloudNac();
    } catch (e) { if (out) out.textContent = ''; showToast('Provision failed: ' + (e.message || e), 'error'); }
}

async function deprovisionCloudNac(username) {
    if (!window.confirm(`Delete the Entra account for ${username}?`)) return;
    try {
        const d = await apiJson('/setup/cloud-nac/deprovision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
        showToast(`Deleted ${username}`, 'success');
        loadCloudNac();
    } catch (e) { showToast('Delete failed: ' + (e.message || e), 'error'); }
}

async function sweepCloudNac() {
    const msg = document.getElementById('cn-msg');
    if (msg) msg.textContent = 'Sweeping…';
    try {
        const d = await apiJson('/setup/cloud-nac/sweep', { method: 'POST' });
        showToast(`Sweep: ${d.deleted || 0} idle account(s) deleted.`, 'success');
        if (msg) msg.textContent = `Swept — ${d.deleted || 0} deleted of ${(d.results || []).length}`;
        loadCloudNac();
    } catch (e) { showToast('Sweep failed: ' + (e.message || e), 'error'); if (msg) msg.textContent = ''; }
}

// ── Settings → Azure Key Vault (DR: admin rotation + min bootstrap backup) ──
// ── Collab traffic-sim tile (Setup/Settings → Collab) ─────────────────────────
// Hub runs a passive UDP sink (lm-collab-sink, collab_sink/sink.py) bound to its
// LAN IP on the Teams/Zoom/WebEx media ports. cs simulation clients send raw
// UDP to it over the wired/USB path (cs clients/linux/collab.py) — the media
// never rides the WS control plane. This tile manages which apps are enabled
// + the default bandwidth and applies the OPNsense port-alias + allow rule
// via the EXISTING /api/firewall/{id}/aliases + /rules endpoints (correct
// tenant-scoped authz lives there). The per-app port sets come from the
// backend COLLAB_APP_PORTS registry (single source of truth — cs collab.py
// mirrors them).
function _renderCollabTile(content) {
    const { card, inputCls, labelCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Collab Traffic Sim — Teams / Zoom / WebEx</h3>
                <span id="cb-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Simulates collaboration-app media by sending raw UDP to a passive hub sink over the wired/USB network path (not the WebSocket). Choose which apps are active — their real media ports drive both the client sender and the firewall alias. The sink (<code>lm-collab-sink</code>) listens on the union of active app ports; verify with <code>systemctl status lm-collab-sink</code> on the hub. Client knobs live in the cs repo (<code>configs/simulation.conf</code>: <code>collab</code>/<code>collab_app</code>/<code>collab_bw</code>/<code>collab_server</code>).</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="cb-enabled" class="w-4 h-4 text-green-600 rounded">Enable collab traffic sim</label>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Default app</label>
                    <select id="cb-app" class="${inputCls}">
                        <option value="teams">Microsoft Teams</option>
                        <option value="zoom">Zoom</option>
                        <option value="webex">Cisco WebEx</option>
                    </select>
                </div>
                <div class="space-y-1"><label class="${labelCls}">Default bandwidth</label><input id="cb-bw" type="text" placeholder="1M" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Sink / hub LAN IP (clients target)</label><input id="cb-server" type="text" placeholder="172.16.1.31" class="${inputCls} font-mono text-xs"></div>
            </div>
            <div class="mt-3">
                <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">Active apps <span class="text-slate-400 font-normal">(ports the sink listens on + firewall alias opens)</span></div>
                <div id="cb-app-toggles" class="grid grid-cols-1 sm:grid-cols-3 gap-2"></div>
                <p id="cb-ports" class="text-[11px] font-mono text-slate-500 mt-2"></p>
            </div>
            <div class="mt-4 rounded-md border border-slate-200 bg-slate-50 p-3">
                <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">Replay capture (high-fidelity mode)</div>
                <p class="text-[11px] text-slate-500 mb-2">Upload a real Teams/Zoom/WebEx call capture (<code>.pcap</code>/<code>.pcapng</code>, ≤64&nbsp;MB). Clients replay its <b>client→server</b> frames at the sink and the hub sink replays the capture's <b>server→client</b> frames back — a genuine bidirectional flow DPI/AppRF classifies as the real app. With no capture, clients fall back to synthetic UDP on the same ports.</p>
                <label class="flex items-center gap-2 text-sm text-slate-600 mb-2 cursor-pointer"><input type="checkbox" id="cb-responder" class="w-4 h-4 text-green-600 rounded">Sink responds with the capture's server→client frames <span class="text-[10px] text-slate-400">(applied on <code>lm-collab-sink</code> restart)</span></label>
                <p id="cb-pcap-info" class="text-[11px] font-mono text-slate-500 mb-2">No capture uploaded.</p>
                <div class="flex flex-wrap gap-2 items-center">
                    <input type="file" id="cb-pcap-file" accept=".pcap,.pcapng" class="text-xs">
                    <button type="button" onclick="uploadCollabPcap()" id="cb-pcap-up" class="${btnSecCls} whitespace-nowrap">Upload capture</button>
                    <button type="button" onclick="deleteCollabPcap()" id="cb-pcap-del" class="${btnSecCls} whitespace-nowrap">Remove</button>
                    <a href="#" onclick="downloadCollabPcap(event)" id="cb-pcap-dl" class="text-[11px] text-blue-600 hover:underline">Download</a>
                </div>
                <p id="cb-pcap-msg" class="text-[11px] text-slate-500 mt-2"></p>
            </div>
            <div class="mt-4 rounded-md border border-slate-200 bg-slate-50 p-3">
                <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">Apply to firewall</div>
                <p class="text-[11px] text-slate-500 mb-2">Creates an OPNsense <b>port alias</b> (<code>lm-collab-ports</code>) from the active app ports + a <b>pass</b> rule (UDP, source → hub IP on that alias). Uses the existing firewall endpoints (tenant-scoped). Re-running skips the alias if it already exists; the rule is created each time — delete duplicates in Firewall → Rules.</p>
                <div class="flex flex-wrap gap-2 items-end">
                    <div class="space-y-1 flex-1 min-w-[200px]"><label class="${labelCls}">Firewall</label><select id="cb-fw" class="${inputCls}"><option value="">— select a firewall —</option></select></div>
                    <div class="space-y-1 flex-1 min-w-[180px]"><label class="${labelCls}">Source (any / CIDR / alias)</label><input id="cb-src" type="text" placeholder="any" class="${inputCls} text-xs"></div>
                    <button type="button" onclick="applyCollabFirewall()" id="cb-apply" class="${btnSecCls} whitespace-nowrap">Create alias + allow rule</button>
                </div>
                <p id="cb-apply-msg" class="text-[11px] text-slate-500 mt-2"></p>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="cb-msg" class="text-xs text-slate-400"></span>
            </div>
        </div>`;
    loadCollab();
    loadCollabFirewalls();
    _attachAutoSave(content, _collabSaveFnFor, 'collabAutoSave');
}

async function loadCollab() {
    try {
        const r = await setupFetch('/setup/collab');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const apps = d.apps || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v == null ? '' : v; };
        const en = document.getElementById('cb-enabled'); if (en) en.checked = !!c.enabled;
        set('cb-app', c.default_app || 'teams');
        set('cb-bw', c.default_bw || '1M');
        set('cb-server', c.collab_server || '');
        const resp = document.getElementById('cb-responder'); if (resp) resp.checked = c.responder_enabled !== false;
        _renderCollabPcap(c.pcap);
        const pill = document.getElementById('cb-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        // Per-app toggles + the union port readout.
        const box = document.getElementById('cb-app-toggles');
        const active = c.apps || {};
        if (box) {
            box.innerHTML = Object.entries(apps).map(([k, v]) => `
                <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer border border-slate-200 rounded-md px-3 py-2 bg-white">
                    <input type="checkbox" id="cb-app-${k}" class="w-4 h-4 text-green-600 rounded" ${active[k] !== false ? 'checked' : ''}>
                    <span class="font-medium">${escapeHtml(v.label || k)}</span>
                    <span class="font-mono text-[10px] text-slate-400 ml-auto">${(v.ports || []).join(',')}</span>
                </label>`).join('');
        }
        _updateCollabPorts(apps);
        // Toggling an app re-renders the port readout (and auto-saves).
        box?.querySelectorAll('input[type=checkbox]').forEach(el => el.addEventListener('change', () => { _updateCollabPorts(apps); }));
    } catch (e) { console.error('loadCollab failed', e); }
}

function _updateCollabPorts(apps) {
    const active = [];
    for (const [k, v] of Object.entries(apps || {})) {
        const el = document.getElementById(`cb-app-${k}`);
        if (el && el.checked) active.push(...(v.ports || []));
    }
    const out = document.getElementById('cb-ports');
    if (out) out.textContent = active.length ? `Sink listens on: ${active.join(', ')}` : 'No apps active — sink has no ports.';
}

async function loadCollabFirewalls() {
    try {
        const fws = await loadFirewalls();
        const sel = document.getElementById('cb-fw');
        if (!sel) return;
        const cur = sel.value;
        sel.innerHTML = '<option value="">— select a firewall —</option>' +
            fws.map(f => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.name || f.id)}</option>`).join('');
        if (cur) sel.value = cur;
    } catch (e) { console.error('loadCollabFirewalls failed', e); }
}

function _collabFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    const apps = {};
    document.querySelectorAll('[id^="cb-app-"]').forEach(el => {
        // only the per-app toggles (cb-app-teams/zoom/webex), not cb-app select
        const m = el.id.match(/^cb-app-(teams|zoom|webex)$/);
        if (m) apps[m[1]] = el.checked;
    });
    return {
        enabled: !!document.getElementById('cb-enabled')?.checked,
        default_app: v('cb-app'), default_bw: v('cb-bw'),
        collab_server: v('cb-server'),
        responder_enabled: !!document.getElementById('cb-responder')?.checked,
        apps,
    };
}

// Render the current-capture info line + enable/disable the download/remove
// controls based on whether a capture is stored.
function _renderCollabPcap(pcap) {
    const info = document.getElementById('cb-pcap-info');
    const dl = document.getElementById('cb-pcap-dl');
    const del = document.getElementById('cb-pcap-del');
    const has = !!(pcap && pcap.stats);
    if (dl) dl.style.display = has ? '' : 'none';
    if (del) del.style.display = has ? '' : 'none';
    if (!info) return;
    if (!has) { info.textContent = 'No capture uploaded.'; return; }
    const s = pcap.stats || {};
    const kb = Math.round((pcap.size || 0) / 1024);
    info.textContent = `${pcap.filename || 'replay.pcap'} — ${kb} KB · c2s ${s.c2s_packets || 0} / s2c ${s.s2c_packets || 0} pkts · ${s.duration_s || 0}s · ports ${(s.server_ports || []).join(',') || '—'}`;
}

async function uploadCollabPcap() {
    const fileEl = document.getElementById('cb-pcap-file');
    const msg = document.getElementById('cb-pcap-msg');
    const f = fileEl && fileEl.files && fileEl.files[0];
    if (!f) { if (msg) msg.textContent = 'Choose a .pcap/.pcapng file first.'; return; }
    if (msg) msg.textContent = 'Uploading…';
    try {
        // Send the raw file bytes (the route accepts a raw body with ?name=);
        // avoids multipart so setupFetch's forced JSON content-type is a non-issue.
        const r = await setupFetch('/setup/collab/pcap?name=' + encodeURIComponent(f.name), {
            method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: f });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
        const d = await r.json().catch(() => ({}));
        _renderCollabPcap(d.pcap);
        if (fileEl) fileEl.value = '';
        if (msg) { msg.textContent = 'Capture uploaded.'; setTimeout(() => { if (msg) msg.textContent = ''; }, 2500); }
    } catch (e) { if (msg) msg.textContent = 'Error: ' + e.message; }
}

async function deleteCollabPcap() {
    const msg = document.getElementById('cb-pcap-msg');
    if (!confirm('Remove the uploaded replay capture? Clients will fall back to synthetic UDP.')) return;
    try {
        const r = await setupFetch('/setup/collab/pcap', { method: 'DELETE' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
        _renderCollabPcap(null);
        if (msg) { msg.textContent = 'Capture removed.'; setTimeout(() => { if (msg) msg.textContent = ''; }, 2500); }
    } catch (e) { if (msg) msg.textContent = 'Error: ' + e.message; }
}

async function downloadCollabPcap(ev) {
    if (ev) ev.preventDefault();
    try {
        const r = await setupFetch('/setup/collab/pcap', { _keepOnNavigate: true });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'replay.pcap';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    } catch (e) {
        const msg = document.getElementById('cb-pcap-msg'); if (msg) msg.textContent = 'Error: ' + e.message;
    }
}

async function saveCollab() {
    try {
        const r = await setupFetch('/setup/collab', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _collabFormConfig() }) });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
        const d = await r.json().catch(() => ({}));
        const pill = document.getElementById('cb-state-pill');
        if (pill && d.config) { pill.textContent = d.config.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (d.config.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        const msg = document.getElementById('cb-msg'); if (msg) { msg.textContent = 'Saved.'; setTimeout(() => { if (msg) msg.textContent = ''; }, 2000); }
    } catch (e) {
        const msg = document.getElementById('cb-msg'); if (msg) msg.textContent = 'Error: ' + e.message;
    }
}

// Auto-save on change — only the config fields, not the firewall-apply controls.
function _collabSaveFnFor(el) {
    const id = el.id || '';
    const allow = ['cb-enabled', 'cb-app', 'cb-bw', 'cb-server', 'cb-responder', 'cb-app-teams', 'cb-app-zoom', 'cb-app-webex'];
    return allow.includes(id) ? saveCollab : null;
}

// Create the OPNsense port alias (lm-collab-ports) + a pass rule via the
// existing firewall endpoints. Skips alias creation if it already exists.
async function applyCollabFirewall() {
    const fwId = (document.getElementById('cb-fw')?.value || '').trim();
    const src = (document.getElementById('cb-src')?.value || 'any').trim() || 'any';
    const hubIp = (document.getElementById('cb-server')?.value || '').trim();
    const out = document.getElementById('cb-apply-msg');
    const btn = document.getElementById('cb-apply');
    if (!fwId) { if (out) out.textContent = 'Select a firewall first.'; return; }
    // Collect active ports from the toggles.
    const ports = [];
    ['teams', 'zoom', 'webex'].forEach(k => {
        const el = document.getElementById(`cb-app-${k}`);
        if (el && el.checked) {
            // Read the port list from the toggle label's data — re-derive from
            // the known app ports (single source of truth mirror).
            const known = { teams: [3478, 3481, 3479], zoom: [8801, 8802, 8803], webex: [9000, 5004, 5006] }[k] || [];
            ports.push(...known);
        }
    });
    if (!ports.length) { if (out) out.textContent = 'No apps active — enable at least one.'; return; }
    if (btn) { btn.disabled = true; btn.textContent = 'Applying…'; }
    const tq = _taTenantQuery();
    const log = (m) => { if (out) out.textContent = m; };
    try {
        // 1. Check for an existing lm-collab-ports alias (skip create if present).
        let aliasExists = false;
        try {
            const gr = await fetch(`/api/firewall/${encodeURIComponent(fwId)}/aliases${tq}`);
            if (gr.ok) {
                const gd = await gr.json().catch(() => ({}));
                const items = (gd && (gd.aliases || gd.data || gd)) || [];
                aliasExists = Array.isArray(items) && items.some(a => (a.name || '') === 'lm-collab-ports');
            }
        } catch (_) { /* ignore — fall through to create */ }
        if (!aliasExists) {
            const aliasBody = { name: 'lm-collab-ports', type: 'port', content: ports.join('\n'), description: 'LM collab traffic-sim media ports', category: '' };
            const ar = await fetch(`/api/firewall/${encodeURIComponent(fwId)}/aliases${tq}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(aliasBody) });
            if (!ar.ok) { const e = await ar.json().catch(() => ({})); throw new Error('alias: ' + (e.detail || ar.statusText)); }
            log('Alias lm-collab-ports created. Creating rule…');
        } else {
            log('Alias lm-collab-ports exists. Creating rule…');
        }
        // 2. Pass rule: UDP, source → hub IP on the port alias.
        const ruleBody = { rule: { interface: 'lan', action: 'pass', protocol: 'udp', source_net: src, destination_net: hubIp || 'any', destination_port: 'lm-collab-ports', description: 'LM collab traffic sim (Teams/Zoom/WebEx)', enabled: '1' } };
        const rr = await fetch(`/api/firewall/${encodeURIComponent(fwId)}/rules${tq}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(ruleBody) });
        if (!rr.ok) { const e = await rr.json().catch(() => ({})); throw new Error('rule: ' + (e.detail || rr.statusText)); }
        log('Done — alias ' + (aliasExists ? 'reused' : 'created') + ' + allow rule added. Verify in Firewall → Rules/Aliases.');
    } catch (e) {
        log('Error: ' + e.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Create alias + allow rule'; }
    }
}

// Break-glass admin-password rotation, Fernet-key escrow, and a rolling min
// bootstrap backup stored in Azure Key Vault. Reuses the SSO Entra app cert
// (vault.azure.net token; app needs Key Vault Secrets Officer). Admin-only.
function _renderSettingsKeyVaultTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Key Vault — DR &amp; break-glass</h3>
                <span id="kv-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Stores disaster-recovery material in <b>Azure Key Vault</b> using the <b>SSO Entra app</b> cert — the app needs the <b>Key Vault Secrets Officer</b> role on the vault. On a schedule the hub rotates the local admin password (<b>break-glass</b> — afterwards it lives only in the vault), and pushes a <b>min bootstrap backup</b>: users/logins + the Azure connection + the Fernet key + a pointer to your real backup source. Restore that on a fresh hub → it can call home to Azure and let admins in → then pull the full backup from source.</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="kv-enabled" class="w-4 h-4 text-green-600 rounded">Enable Key Vault DR automation</label>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">Vault URL</label><input id="kv-url" type="text" placeholder="https://my-vault.vault.azure.net" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Rotate admin every (days)</label><input id="kv-rotate" type="number" placeholder="7" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Keep backups (days)</label><input id="kv-retain" type="number" placeholder="7" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Admin-password secret name</label><input id="kv-admin-secret" type="text" placeholder="lm-admin-password" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Fernet-key secret name</label><input id="kv-fernet-secret" type="text" placeholder="lm-fernet-key" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">Backup secret prefix <span class="text-slate-400 normal-case font-normal">(daily: prefix + YYYYMMDD)</span></label><input id="kv-prefix" type="text" placeholder="lm-min-backup-" class="${inputCls} font-mono text-xs"></div>
            </div>
            <div class="mt-3 flex flex-wrap items-center gap-2">
                <button type="button" onclick="testKeyVault()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Test connection</button>
                <button type="button" onclick="testFernetTier1()" title="Tests the DIFFERENT auth path the hub actually uses at boot to source the Fernet key from Key Vault (managed identity via LM_KEYVAULT_URL/LM_FERNET_KEY_KV_SECRET) — separate from 'Test connection' above, which only checks the SSO app-cert path used by the buttons below." class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Test Fernet boot path (Tier 1)</button>
                <button type="button" onclick="saveFernetTier1Config()" title="Writes LM_FERNET_KEY_KV_SECRET and LM_KEYVAULT_URL — using the Vault URL / Fernet-key secret name fields above — into this hub's .env, then restarts the hub to apply them. LM_FERNET_KEY stays in place as a fallback; nothing else in .env is touched." class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Save &amp; restart for Tier 1</button>
                <button type="button" onclick="rotateKeyVaultAdmin()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Rotate admin now</button>
                <button type="button" onclick="pushKeyVaultFernet()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Push Fernet key</button>
                <button type="button" onclick="backupKeyVaultNow()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Backup now</button>
                <span id="kv-action-out" class="text-[11px] font-mono text-slate-600 break-all"></span>
            </div>
            <div class="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3">
                <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">Disaster recovery</div>
                <p class="text-[11px] text-slate-400 mb-2">Download the min bootstrap bundle to keep off-box, or restore one onto this hub (from an uploaded file or a vault secret) to bring logins + Azure back, then pull the full backup from source.</p>
                <div class="flex flex-wrap items-center gap-2">
                    <button type="button" onclick="downloadKeyVaultMin()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Download min backup</button>
                    <input type="file" id="kv-restore-file" accept="application/json,.json" class="hidden" onchange="restoreKeyVaultFromFile(this)">
                    <button type="button" onclick="document.getElementById('kv-restore-file').click()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Restore from file…</button>
                    <input id="kv-restore-secret" type="text" placeholder="or vault secret name" class="${inputCls} font-mono text-xs flex-1 min-w-[10rem]">
                    <button type="button" onclick="restoreKeyVaultFromVault()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Restore from vault</button>
                </div>
                <p id="kv-restore-out" class="text-[11px] font-mono text-slate-600 mt-1 break-all"></p>
            </div>
            <div class="mt-4">
                <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">Backups in vault <span id="kv-bk-count" class="text-slate-400 font-normal"></span></div>
                <div id="kv-backups" class="border border-slate-200 rounded-md divide-y divide-slate-100 max-h-56 overflow-y-auto text-xs"></div>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="kv-msg" class="text-xs text-slate-400"></span>
            </div>
        </div>`;
    loadKeyVault();
    // Auto-save on change (allowlist mapper — restore controls + backup-list
    // display are excluded).
    _attachAutoSave(content, _keyVaultSaveFnFor, 'keyVaultAutoSave');
}

async function loadKeyVault() {
    try {
        const r = await setupFetch('/setup/key-vault');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v == null ? '' : v; };
        const en = document.getElementById('kv-enabled'); if (en) en.checked = !!c.enabled;
        set('kv-url', c.vault_url); set('kv-rotate', c.rotate_days || 7); set('kv-retain', c.retain || 7);
        set('kv-admin-secret', c.admin_secret || 'lm-admin-password');
        set('kv-fernet-secret', c.fernet_secret || 'lm-fernet-key');
        set('kv-prefix', c.backup_prefix || 'lm-min-backup-');
        const pill = document.getElementById('kv-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        const st = d.status || {};
        const cnt = document.getElementById('kv-bk-count'); if (cnt) cnt.textContent = `(${(st.backups || []).length})`;
        const box = document.getElementById('kv-backups');
        if (box) {
            const bks = st.backups || [];
            box.innerHTML = bks.length ? bks.map(n => `<div class="px-2 py-1 font-mono text-slate-700">${escapeHtml(n)}</div>`).join('')
                : `<div class="text-slate-400 italic px-2 py-2">${st.warning ? escapeHtml(st.warning) : 'No backups in the vault yet.'}</div>`;
        }
        const msg = document.getElementById('kv-msg');
        if (msg) msg.textContent = [c.last_rotate ? 'rotated ' + c.last_rotate.slice(0, 10) : '', c.last_backup ? 'backup ' + c.last_backup.slice(0, 10) : ''].filter(Boolean).join(' · ');
    } catch (e) { console.error('loadKeyVault failed', e); }
}

function _keyVaultFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    return {
        enabled: !!document.getElementById('kv-enabled')?.checked,
        vault_url: v('kv-url'),
        rotate_days: parseInt(v('kv-rotate'), 10) || 7,
        retain: parseInt(v('kv-retain'), 10) || 7,
        admin_secret: v('kv-admin-secret') || 'lm-admin-password',
        fernet_secret: v('kv-fernet-secret') || 'lm-fernet-key',
        backup_prefix: v('kv-prefix') || 'lm-min-backup-',
    };
}

async function saveKeyVault() {
    const btn = document.getElementById('kv-save-btn');
    if (btn) btn.disabled = true;
    try {
        await apiJson('/setup/key-vault', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _keyVaultFormConfig() }) });
        showToast('Key Vault settings saved.', 'success');
        loadKeyVault();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) btn.disabled = false; }
}

async function testKeyVault() {
    const out = document.getElementById('kv-action-out');
    if (out) out.textContent = 'Testing…';
    try {
        const r = await setupFetch('/setup/key-vault/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _keyVaultFormConfig() }) });
        const d = await r.json().catch(() => ({}));
        if (d.status === 'ok') { if (out) out.textContent = `OK — ${d.secret_count} secret(s) visible`; showToast('Key Vault connection OK.', 'success'); }
        else { if (out) out.textContent = d.message || 'failed'; showToast('Test failed: ' + (d.message || ''), 'error'); }
    } catch (e) { if (out) out.textContent = ''; showToast('Test failed: ' + (e.message || e), 'error'); }
}

async function testFernetTier1() {
    const out = document.getElementById('kv-action-out');
    if (out) out.textContent = 'Testing Tier-1 boot path…';
    try {
        const r = await setupFetch('/setup/key-vault/test-fernet-tier1', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        const diagBits = [
            `env: LM_FERNET_KEY_KV_SECRET=${d.kv_secret_env_set ? 'set' : 'unset'}`,
            `LM_KEYVAULT_URL=${d.vault_url_env_set ? 'set' : 'unset'}`,
        ];
        if (d.provider) diagBits.push(`provider=${d.provider}`, `ready=${d.ready}`);
        if ('secret_found' in d) diagBits.push(`secret_found=${d.secret_found}`);
        if ('valid_fernet_key' in d) diagBits.push(`valid_fernet_key=${d.valid_fernet_key}`);
        const diagText = diagBits.join(' · ');
        if (d.status === 'ok') {
            if (out) out.textContent = `OK — ${d.message} (${diagText})`;
            showToast('Tier-1 Fernet boot path OK — a restart would source the key from Key Vault.', 'success');
        } else {
            if (out) out.textContent = `${d.message || 'failed'} (${diagText})`;
            showToast('Tier-1 test failed: ' + (d.message || ''), 'error');
        }
    } catch (e) { if (out) out.textContent = ''; showToast('Tier-1 test failed: ' + (e.message || e), 'error'); }
}

// Writes LM_FERNET_KEY_KV_SECRET/LM_KEYVAULT_URL into the hub's own .env
// (reusing whatever's currently in the Vault URL / Fernet-key secret name
// fields above — no separate inputs) and restarts the hub. Confirms first,
// same as restartHubService() — this both touches the hub's secrets file
// AND restarts it.
async function saveFernetTier1Config() {
    const secretName = (document.getElementById('kv-fernet-secret')?.value || '').trim();
    const vaultUrl = (document.getElementById('kv-url')?.value || '').trim();
    if (!secretName || !vaultUrl) {
        showToast('Fill in the Vault URL and Fernet-key secret name fields above first.', 'error');
        return;
    }
    if (!confirm(`Write LM_FERNET_KEY_KV_SECRET=${secretName} and LM_KEYVAULT_URL=${vaultUrl} into `
               + `this hub's .env, then restart lm.service to apply them?\n\n`
               + `LM_FERNET_KEY stays in place as a fallback — nothing else in .env is touched. `
               + `The hub and this page will be briefly unavailable for a few seconds.`)) return;
    const out = document.getElementById('kv-action-out');
    if (out) out.textContent = 'Saving + restarting…';
    try {
        const d = await apiJson('/setup/key-vault/configure-tier1', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret_name: secretName, vault_url: vaultUrl }),
        });
        showToast(`${d.message || 'Saved'} — reloading in ~8s…`, 'success');
        setTimeout(() => location.reload(), 8000);
    } catch (e) {
        if (out) out.textContent = '';
        showToast('Save failed: ' + (e.message || e), 'error');
    }
}

async function _kvAction(path, label, confirmMsg) {
    if (confirmMsg && !confirm(confirmMsg)) return;
    const out = document.getElementById('kv-action-out');
    if (out) out.textContent = label + '…';
    try {
        const d = await apiJson(path, { method: 'POST' });
        if (out) out.textContent = `${label}: ${d.secret || 'ok'}${d.size ? ' (' + d.size + 'b)' : ''}`;
        showToast(`${label} — done.`, 'success');
        loadKeyVault();
    } catch (e) { if (out) out.textContent = ''; showToast(`${label} failed: ` + (e.message || e), 'error'); }
}

function rotateKeyVaultAdmin() { _kvAction('/setup/key-vault/rotate-admin', 'Rotate admin', 'Rotate the local admin password now?\n\nThe new password is stored ONLY in Key Vault (break-glass) and all of that admin’s sessions are logged out. Retrieve it from the vault to log back in.'); }
function pushKeyVaultFernet() { _kvAction('/setup/key-vault/push-fernet', 'Push Fernet'); }
function backupKeyVaultNow() { _kvAction('/setup/key-vault/backup', 'Backup'); }

// ── Notifications (platform email alerts) ─────────────────────────────────
const _NOTIF_PRESETS = {
    azure_acs: { host: 'smtp.azurecomm.net',     port: 587, label: 'Azure ACS (Key Vault-managed)' },
    gmail:     { host: 'smtp.gmail.com',         port: 587, label: 'Gmail' },
    yahoo:     { host: 'smtp.mail.yahoo.com',    port: 587, label: 'Yahoo' },
    office365: { host: 'smtp.office365.com',     port: 587, label: 'Office 365' },
    generic:   { host: '',                       port: 587, label: 'Generic SMTP' },
};

function _renderSettingsNotificationsTile(content) {
    const { card, inputCls, labelCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Notifications — email alerts</h3>
                <span id="notif-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">The hub sends its own alerts (spoke out-of-contact, etc.) over email. Pick a provider; recipient list is always manual. <b>Azure ACS</b> pulls sender creds from <b>Key Vault</b> and defaults to the <b>REST API</b> (grant the SSO app the Communication Services permission) with an SMTP fallback. Other providers use SMTP with the password encrypted at rest.</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="notif-enabled" class="w-4 h-4 text-green-600 rounded">Enable email alerts</label>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Provider</label>
                    <select id="notif-provider" class="${inputCls}" onchange="notifProviderChanged()">
                        <option value="azure_acs">Azure ACS (Key Vault-managed)</option>
                        <option value="gmail">Gmail</option>
                        <option value="yahoo">Yahoo</option>
                        <option value="office365">Office 365</option>
                        <option value="generic">Generic SMTP</option>
                    </select></div>
                <div class="space-y-1" id="notif-transport-wrap"><label class="${labelCls}">ACS transport</label>
                    <select id="notif-transport" class="${inputCls}" onchange="notifTransportChanged()">
                        <option value="api">REST API (default)</option>
                        <option value="smtp">SMTP</option>
                    </select></div>
                <div class="space-y-1" id="notif-acs-source-wrap"><label class="${labelCls}">ACS credential source</label>
                    <select id="notif-acs-source" class="${inputCls}" onchange="notifAcsSourceChanged()">
                        <option value="arm">ARM auto-pull (no vault access)</option>
                        <option value="keyvault">Key Vault secret</option>
                    </select></div>
                <div class="space-y-1 md:col-span-2" id="notif-acs-arm-wrap"><label class="${labelCls}">ACS resource (ARM listKeys)</label>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
                        <div class="flex gap-1">
                            <select id="notif-acs-sub" class="${inputCls} font-mono text-xs flex-1" onchange="onAcsSubChanged()"><option value="">Subscription ID…</option></select>
                            <button type="button" onclick="pullAzureSubs()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-2 py-1 rounded-md text-xs font-bold whitespace-nowrap">Pull</button>
                        </div>
                        <div class="flex gap-1">
                            <select id="notif-acs-rg" class="${inputCls} font-mono text-xs flex-1" onchange="onAcsRgChanged()"><option value="">Resource group…</option></select>
                            <button type="button" onclick="pullAzureRgs()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-2 py-1 rounded-md text-xs font-bold whitespace-nowrap">Pull</button>
                        </div>
                        <div class="flex gap-1">
                            <select id="notif-acs-name" class="${inputCls} font-mono text-xs flex-1" onchange="onAcsResourceChanged()"><option value="">Resource name…</option></select>
                            <button type="button" onclick="pullAcsResources()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-2 py-1 rounded-md text-xs font-bold whitespace-nowrap">Pull</button>
                        </div>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-1">The SSO app calls <span class="font-mono">communicationServices/listKeys</span> via ARM (needs <b>Contributor</b> on the ACS resource/RG). The connection string is cached ~10 min and never touches the vault. <b>Pull</b> lists the subscriptions, resource groups, and ACS resources the app can see — choose top-down.</p></div>
                <div class="space-y-1"><label class="${labelCls}">SMTP host</label><input id="notif-host" type="text" placeholder="smtp.example.com" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">SMTP port</label><input id="notif-port" type="number" placeholder="587" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">SMTP user</label><input id="notif-user" type="text" placeholder="user@example.com" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">SMTP password</label><input id="notif-pass" type="password" placeholder="" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1 md:col-span-2" id="notif-acs-kv-name-wrap"><label class="${labelCls}">ACS Key Vault secret name</label><input id="notif-acs-secret" type="text" placeholder="acs-email-connstr" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1 md:col-span-2" id="notif-acs-vault-wrap"><label class="${labelCls}">Key Vault URL <span class="text-slate-400 normal-case font-normal">(blank = reuse the DR Key Vault URL)</span></label><input id="notif-vault-url" type="text" placeholder="https://my-vault.vault.azure.net" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1 md:col-span-2" id="notif-acs-connstr-wrap"><label class="${labelCls}">ACS connection string <span class="text-slate-400 normal-case font-normal">(one-time push to Key Vault — the SSO app writes it for you)</span></label><textarea id="notif-acs-connstr" rows="2" placeholder="endpoint=https://<resourcename>.communication.azure.com;accesskey=<key>" class="${inputCls} font-mono text-xs"></textarea></div>
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">From email</label><input id="notif-from" type="text" placeholder="DoNotReply@<resourcename>.azurecomm.net" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">To emails <span class="text-slate-400 normal-case font-normal">(comma-separated)</span></label><input id="notif-to" type="text" placeholder="ops@example.com, oncall@example.com" class="${inputCls} font-mono text-xs"></div>
            </div>
            <p id="notif-acs-note" class="text-[11px] text-slate-400 mt-2 hidden">ACS API transport signs each request with the access key (HMAC-SHA256) — no Entra app permission needed. The access key is pulled from ARM (listKeys) or read from the Key Vault secret, depending on the credential source above.</p>
            <div class="mt-3 flex flex-wrap items-center gap-2">
                <button type="button" id="notif-push-btn" onclick="pushAcsSecret()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Push ACS connection string to Key Vault</button>
                <span id="notif-action-out" class="text-[11px] font-mono text-slate-600 break-all"></span>
                <div class="ml-auto flex items-center gap-2">
                    <button type="button" onclick="testNotifications()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Send test email</button>
                    <button type="button" onclick="saveNotifications()" class="bg-[#01A982] hover:bg-[#01A982]/90 text-white px-3 py-1.5 rounded-md text-xs font-bold">Save</button>
                </div>
            </div>
        </div>`;
    loadNotifications();
}

function _notifProvider() { return document.getElementById('notif-provider')?.value || 'azure_acs'; }

function notifProviderChanged() {
    const p = _notifProvider();
    const preset = _NOTIF_PRESETS[p] || _NOTIF_PRESETS.generic;
    const isAcs = p === 'azure_acs';
    const isGeneric = p === 'generic';
    // host/port: editable only for generic; read-only preset for the rest.
    const hostEl = document.getElementById('notif-host');
    const portEl = document.getElementById('notif-port');
    if (hostEl) { if (!isGeneric) hostEl.value = preset.host; hostEl.disabled = !isGeneric; }
    if (portEl) { if (!isGeneric) portEl.value = preset.port; portEl.disabled = !isGeneric; }
    // ACS-only controls
    const showKv = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    showKv('notif-transport-wrap', isAcs);
    showKv('notif-acs-source-wrap', isAcs);
    showKv('notif-acs-arm-wrap', isAcs);        // toggled further by source below
    showKv('notif-acs-kv-name-wrap', isAcs);   // toggled further by source below
    showKv('notif-acs-vault-wrap', isAcs);      // toggled further by source below
    showKv('notif-acs-connstr-wrap', isAcs);    // toggled further by source below
    showKv('notif-push-btn', isAcs);            // toggled further by source below
    // Password field: hidden for ACS (creds via ARM/Key Vault).
    const passEl = document.getElementById('notif-pass');
    if (passEl) { passEl.disabled = isAcs; if (isAcs) passEl.value = ''; passEl.placeholder = isAcs ? 'managed automatically' : ''; }
    if (isAcs) notifAcsSourceChanged(); else notifTransportChanged();
}

function notifAcsSourceChanged() {
    const isAcs = _notifProvider() === 'azure_acs';
    const isKv = isAcs && (document.getElementById('notif-acs-source')?.value || 'arm') === 'keyvault';
    const show = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    // ARM fields only when source=arm; Key Vault secret/push fields only when source=keyvault.
    show('notif-acs-arm-wrap', isAcs && !isKv);
    show('notif-acs-kv-name-wrap', isKv);
    show('notif-acs-vault-wrap', isKv);
    show('notif-acs-connstr-wrap', isKv);
    show('notif-push-btn', isKv);
    notifTransportChanged();
}

function notifTransportChanged() {
    const isAcs = _notifProvider() === 'azure_acs';
    const isApi = isAcs && (document.getElementById('notif-transport')?.value || 'api') === 'api';
    const note = document.getElementById('notif-acs-note');
    if (note) note.classList.toggle('hidden', !isApi);
}

async function loadNotifications() {
    try {
        const r = await setupFetch('/setup/notifications');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v == null ? '' : v; };
        const en = document.getElementById('notif-enabled'); if (en) en.checked = !!c.enabled;
        set('notif-provider', c.provider || 'azure_acs');
        set('notif-transport', c.transport || 'api');
        set('notif-acs-source', c.acs_source || 'arm');
        // Subscription is a select populated by Pull; if a saved id isn't an
        // option yet, seed a placeholder option so it shows (not lost on save).
        const subSel = document.getElementById('notif-acs-sub');
        if (subSel) {
            const savedSub = c.azure_subscription_id || '';
            if (savedSub && !Array.from(subSel.options).some(o => o.value === savedSub)) {
                subSel.innerHTML = `<option value="${savedSub}">${savedSub}</option>`;
            }
            subSel.value = savedSub;
        }
        // RG + resource name are Pull-populated selects; seed a placeholder
        // option for a saved value so it shows (and isn't lost on save) before
        // the user clicks Pull for that level.
        const seedAcsSel = (id, val) => {
            const el = document.getElementById(id);
            if (!el) return;
            const v = val || '';
            if (v && !Array.from(el.options).some(o => o.value === v)) {
                el.innerHTML = `<option value="${v}">${v}</option>`;
            }
            el.value = v;
        };
        seedAcsSel('notif-acs-rg', c.azure_resource_group);
        seedAcsSel('notif-acs-name', c.acs_resource_name);
        set('notif-host', c.smtp_host);
        set('notif-port', c.smtp_port || 587);
        set('notif-user', c.smtp_user);
        set('notif-acs-secret', c.acs_kv_secret_name || 'acs-email-connstr');
        set('notif-vault-url', c.vault_url);
        set('notif-from', c.from_email);
        const to = Array.isArray(c.to_emails) ? c.to_emails.join(', ') : (c.to_emails || '');
        set('notif-to', to);
        const passEl = document.getElementById('notif-pass');
        if (passEl) { passEl.value = ''; passEl.placeholder = c.has_password ? 'set (leave blank to keep)' : ''; }
        const pill = document.getElementById('notif-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        notifProviderChanged();
    } catch (e) { console.error('loadNotifications failed', e); }
}

function _notifFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    const p = _notifProvider();
    const cfg = {
        enabled: !!document.getElementById('notif-enabled')?.checked,
        provider: p,
        smtp_host: v('notif-host'),
        smtp_port: parseInt(v('notif-port'), 10) || 587,
        smtp_user: v('notif-user'),
        from_email: v('notif-from'),
        to_emails: v('notif-to'),
    };
    if (p === 'azure_acs') {
        cfg.transport = document.getElementById('notif-transport')?.value || 'api';
        cfg.acs_source = document.getElementById('notif-acs-source')?.value || 'arm';
        if (cfg.acs_source === 'arm') {
            cfg.azure_subscription_id = v('notif-acs-sub');
            cfg.azure_resource_group = v('notif-acs-rg');
            cfg.acs_resource_name = v('notif-acs-name');
        } else {
            cfg.acs_kv_secret_name = v('notif-acs-secret') || 'acs-email-connstr';
            cfg.vault_url = v('notif-vault-url');
        }
    } else {
        const pw = v('notif-pass');
        if (pw) cfg.smtp_password = pw;   // plaintext → hub Fernet-encrypts at rest
    }
    return cfg;
}

async function saveNotifications() {
    const out = document.getElementById('notif-action-out');
    if (out) out.textContent = 'Saving…';
    try {
        await apiJson('/setup/notifications', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _notifFormConfig() }) });
        showToast('Notifications settings saved.', 'success');
        if (out) out.textContent = 'saved';
        loadNotifications();
    } catch (e) { if (out) out.textContent = ''; showToast('Save failed: ' + (e.message || e), 'error'); }
}

async function testNotifications() {
    const out = document.getElementById('notif-action-out');
    if (out) out.textContent = 'Sending test…';
    try {
        const r = await setupFetch('/setup/notifications/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _notifFormConfig() }) });
        const d = await r.json().catch(() => ({}));
        if (d.status === 'ok') { if (out) out.textContent = `OK — sent via ${d.host} to ${d.recipients} recipient(s)`; showToast('Test email sent.', 'success'); }
        else { if (out) out.textContent = d.message || 'failed'; showToast('Test failed: ' + (d.message || ''), 'error'); }
    } catch (e) { if (out) out.textContent = ''; showToast('Test failed: ' + (e.message || e), 'error'); }
}

async function pushAcsSecret() {
    const out = document.getElementById('notif-action-out');
    const value = (document.getElementById('notif-acs-connstr')?.value || '').trim();
    if (!value) { if (out) out.textContent = 'paste the ACS connection string first'; showToast('Paste the connection string first.', 'error'); return; }
    if (out) out.textContent = 'Pushing to Key Vault…';
    try {
        const r = await setupFetch('/setup/notifications/push-acs-secret', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value }) });
        const d = await r.json().catch(() => ({}));
        if (d.status === 'ok') { if (out) out.textContent = `pushed to secret '${d.secret}'`; showToast('Connection string stored in Key Vault.', 'success'); const ta = document.getElementById('notif-acs-connstr'); if (ta) ta.value = ''; }
        else { if (out) out.textContent = d.message || 'failed'; showToast('Push failed: ' + (d.message || ''), 'error'); }
    } catch (e) { if (out) out.textContent = ''; showToast('Push failed: ' + (e.message || e), 'error'); }
}

async function pullAzureSubs() {
    const out = document.getElementById('notif-action-out');
    const sel = document.getElementById('notif-acs-sub');
    if (!sel) return;
    const cur = (sel.value || '').trim();
    if (out) out.textContent = 'Pulling subscriptions…';
    try {
        const r = await setupFetch('/setup/notifications/azure-subs');
        const d = await r.json().catch(() => ({}));
        if (d.status !== 'ok') { if (out) out.textContent = d.message || 'failed'; showToast('Pull failed: ' + (d.message || ''), 'error'); return; }
        const subs = d.subscriptions || [];
        if (!subs.length) { if (out) out.textContent = 'no subscriptions visible to the SSO app'; showToast('No subscriptions visible to the SSO app.', 'error'); return; }
        sel.innerHTML = subs.map(s => `<option value="${s.id}">${escapeHtml(s.name)} — ${s.id}</option>`).join('');
        if (cur && subs.some(s => s.id === cur)) sel.value = cur;
        if (out) out.textContent = `${subs.length} subscription(s) listed`;
        showToast('Subscriptions pulled.', 'success');
    } catch (e) { if (out) out.textContent = ''; showToast('Pull failed: ' + (e.message || e), 'error'); }
}

async function pullAzureRgs() {
    const out = document.getElementById('notif-action-out');
    const subSel = document.getElementById('notif-acs-sub');
    const rgSel = document.getElementById('notif-acs-rg');
    if (!rgSel) return;
    const sub = (subSel?.value || '').trim();
    if (!sub) { if (out) out.textContent = 'select a subscription first'; showToast('Select a subscription first.', 'error'); return; }
    const cur = (rgSel.value || '').trim();
    if (out) out.textContent = 'Pulling resource groups…';
    try {
        const r = await setupFetch('/setup/notifications/azure-rgs?subscription_id=' + encodeURIComponent(sub));
        const d = await r.json().catch(() => ({}));
        if (d.status !== 'ok') { if (out) out.textContent = d.message || 'failed'; showToast('Pull failed: ' + (d.message || ''), 'error'); return; }
        const rgs = d.resource_groups || [];
        if (!rgs.length) { const _m = 'No resource groups visible — the Entra app likely needs the Reader role on this subscription (Network Contributor scoped to one RG does not allow listing).'; if (out) out.textContent = _m; showToast(_m, 'error'); return; }
        rgSel.innerHTML = rgs.map(g => `<option value="${g.name}">${escapeHtml(g.name)}</option>`).join('');
        if (cur && rgs.some(g => g.name === cur)) rgSel.value = cur;
        if (out) out.textContent = `${rgs.length} resource group(s) listed`;
        showToast('Resource groups pulled.', 'success');
    } catch (e) { if (out) out.textContent = ''; showToast('Pull failed: ' + (e.message || e), 'error'); }
}

async function pullAcsResources() {
    const out = document.getElementById('notif-action-out');
    const subSel = document.getElementById('notif-acs-sub');
    const rgSel = document.getElementById('notif-acs-rg');
    const nameSel = document.getElementById('notif-acs-name');
    if (!nameSel) return;
    const sub = (subSel?.value || '').trim();
    const rg = (rgSel?.value || '').trim();
    if (!sub || !rg) { if (out) out.textContent = 'select a subscription and resource group first'; showToast('Select a subscription and resource group first.', 'error'); return; }
    const cur = (nameSel.value || '').trim();
    if (out) out.textContent = 'Pulling ACS resources…';
    try {
        const r = await setupFetch('/setup/notifications/azure-acs-resources?subscription_id=' + encodeURIComponent(sub) + '&resource_group=' + encodeURIComponent(rg));
        const d = await r.json().catch(() => ({}));
        if (d.status !== 'ok') { if (out) out.textContent = d.message || 'failed'; showToast('Pull failed: ' + (d.message || ''), 'error'); return; }
        const items = d.acs_resources || [];
        if (!items.length) { const _m = 'No Azure Communication Services resource here. Note: an "Email Communication Service" is a DIFFERENT resource type — LM sends via a Communication Services (ACS) resource. Create one and connect your email domain to it, then re-pull. (If it exists, the app needs read + listKeys on it.)'; if (out) out.textContent = _m; showToast('No Communication Services (ACS) resource in this RG — see the note.', 'error'); return; }
        nameSel.innerHTML = items.map(i => `<option value="${i.name}" data-from="${escapeHtml(i.fromEmail || '')}" data-endpoint="${escapeHtml(i.endpoint || '')}" data-state="${escapeHtml(i.provisioningState || '')}">${escapeHtml(i.name)}${i.location ? ' — ' + escapeHtml(i.location) : ''}</option>`).join('');
        if (cur && items.some(i => i.name === cur)) nameSel.value = cur;
        else if (items.length === 1) nameSel.value = items[0].name;  // auto-select the only resource
        if (out) out.textContent = `${items.length} ACS resource(s) listed`;
        // Auto-populate from_email (etc.) for whichever resource is now selected.
        onAcsResourceChanged();
        showToast('ACS resources pulled.', 'success');
    } catch (e) { if (out) out.textContent = ''; showToast('Pull failed: ' + (e.message || e), 'error'); }
}

// Chained auto-pull: changing the subscription clears RG/resource and pulls
// RGs; changing the RG clears the resource and pulls ACS resources.
function onAcsSubChanged() {
    const rgSel = document.getElementById('notif-acs-rg');
    const nameSel = document.getElementById('notif-acs-name');
    if (rgSel) rgSel.innerHTML = '<option value="">Resource group…</option>';
    if (nameSel) nameSel.innerHTML = '<option value="">Resource name…</option>';
    if ((document.getElementById('notif-acs-sub')?.value || '').trim()) pullAzureRgs();
}

function onAcsRgChanged() {
    const nameSel = document.getElementById('notif-acs-name');
    if (nameSel) nameSel.innerHTML = '<option value="">Resource name…</option>';
    if ((document.getElementById('notif-acs-rg')?.value || '').trim()) pullAcsResources();
}

// Selecting an ACS resource auto-populates everything derivable from it:
// from_email (the resource's default AzureManaged MailFrom domain) — only
// when the admin hasn't already typed a custom verified domain — and shows
// the data-plane endpoint + provisioning state as confirmation.
async function onAcsResourceChanged() {
    const nameSel = document.getElementById('notif-acs-name');
    if (!nameSel) return;
    const opt = nameSel.options[nameSel.selectedIndex];
    if (!opt) return;
    const fromEl = document.getElementById('notif-from');
    const from = opt.getAttribute('data-from') || '';
    if (fromEl && from && !(fromEl.value || '').trim()) fromEl.value = from;  // provisional guess
    const out = document.getElementById('notif-action-out');
    const ep = opt.getAttribute('data-endpoint') || '';
    const st = opt.getAttribute('data-state') || '';
    if (out && ep) out.textContent = `${ep}${st ? ' [' + st + ']' : ''}`;

    // Look up the email domains ACTUALLY LINKED to this ACS resource — the only
    // valid senders. Fixes the guessed From (which is usually wrong) and, when
    // NONE are linked, explains the DomainNotLinked send failure directly.
    const sub = (document.getElementById('notif-acs-sub')?.value || '').trim();
    const rg = (document.getElementById('notif-acs-rg')?.value || '').trim();
    const name = (nameSel.value || '').trim();
    if (!sub || !rg || !name) return;
    try {
        const r = await setupFetch(`/setup/notifications/azure-acs-domains?subscription_id=${encodeURIComponent(sub)}&resource_group=${encodeURIComponent(rg)}&acs_name=${encodeURIComponent(name)}`);
        const d = await r.json().catch(() => ({}));
        if (d.status !== 'ok') { if (out) out.textContent = 'Linked-domain lookup: ' + (d.message || 'failed'); return; }
        const doms = d.domains || [];
        if (!doms.length) {
            const m = `⚠ No email domain is LINKED to "${name}" — this is exactly why sending fails with DomainNotLinked. Fix in Azure: Communication Services (${name}) → Email → Domains → Connect domain → pick the domain from your Email Communication Service.`;
            if (out) out.textContent = m;
            showToast('No email domain linked to this ACS resource — see the note.', 'error');
            return;
        }
        const senders = doms.map(x => x.sender);
        if (fromEl && (!(fromEl.value || '').trim() || !senders.includes((fromEl.value || '').trim()))) {
            fromEl.value = senders[0];  // replace the guess with a REAL linked sender
        }
        if (out) out.textContent = `${doms.length} linked domain(s): ${senders.join(', ')}`;
    } catch (e) { /* non-fatal — the manual From field still works */ }
}

async function downloadKeyVaultMin() {
    try {
        const r = await setupFetch('/setup/key-vault/download-min', { _keepOnNavigate: true });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'lm-min-backup.json';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    } catch (e) { showToast('Download failed: ' + (e.message || e), 'error'); }
}

function _kvRestoreReport(d) {
    const out = document.getElementById('kv-restore-out');
    const src = d.backup_source || {};
    const where = src.ssh_host ? `${src.ssh_user ? src.ssh_user + '@' : ''}${src.ssh_host}:${src.ssh_path || ''}` : '(no backup source set)';
    if (out) out.textContent = `Restored ${d.users || 0} users, ${d.permission_groups || 0} groups, ${d.tenants || 0} tenants · certs: ${(d.cert_files || []).length} · Fernet key ${d.fernet_key_present ? 'present' : 'missing'} · backup source: ${where}`;
    showToast('Min backup restored. Now pull the full backup from source, then restart the hub.', 'success');
    loadKeyVault();
}

async function _kvRestore(bodyObj) {
    const out = document.getElementById('kv-restore-out');
    if (out) out.textContent = 'Restoring…';
    try {
        const d = await apiJson('/setup/key-vault/restore', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bodyObj) });
        _kvRestoreReport(d);
    } catch (e) { if (out) out.textContent = ''; showToast('Restore failed: ' + (e.message || e), 'error'); }
}

async function restoreKeyVaultFromFile(input) {
    const file = input && input.files && input.files[0];
    if (!file) return;
    if (!confirm('Restore this min backup onto THIS hub?\n\nIt replaces the local users, permission groups, Azure config and OIDC cert/key. Everyone is logged out.')) { input.value = ''; return; }
    try {
        const bundle = JSON.parse(await file.text());
        await _kvRestore({ bundle });
    } catch (e) { showToast('Bad backup file: ' + (e.message || e), 'error'); }
    finally { input.value = ''; }
}

function restoreKeyVaultFromVault() {
    const secret = (document.getElementById('kv-restore-secret')?.value || '').trim();
    if (!secret) { showToast('Enter the vault secret name to restore from.', 'error'); return; }
    if (!confirm(`Restore min backup from vault secret "${secret}" onto THIS hub?\n\nIt replaces local users, permission groups, Azure config and OIDC cert/key. Everyone is logged out.`)) return;
    _kvRestore({ from_vault: secret });
}

window.testKeyVault = testKeyVault; window.testFernetTier1 = testFernetTier1; window.saveFernetTier1Config = saveFernetTier1Config; window.saveKeyVault = saveKeyVault;
window.rotateKeyVaultAdmin = rotateKeyVaultAdmin; window.pushKeyVaultFernet = pushKeyVaultFernet;
window.backupKeyVaultNow = backupKeyVaultNow; window.downloadKeyVaultMin = downloadKeyVaultMin;
window.restoreKeyVaultFromFile = restoreKeyVaultFromFile; window.restoreKeyVaultFromVault = restoreKeyVaultFromVault;

// ── System → Icons: the left-nav icon set (image + ID + name) ───────────────
// Single source of truth for the left-nav icons. Each entry: {id, name, key,
// svg}. The IDs are stable reference numbers; the SVGs mirror _rebuildMainNav +
// the static nav in index.html so this gallery shows exactly what's on the nav.
const LM_NAV_ICONS = [
    { id: 1,  name: 'Dashboard',    key: 'dashboard', svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z"></path></svg>' },
    { id: 2,  name: 'Hypervisors',  key: 'pxmx',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12H3m18 0h-2M12 5V3m0 18v-2m5.657-14.343l-1.414 1.414M6.757 17.243l-1.414 1.414m12.728 0l-1.414-1.414M6.757 6.757L5.343 5.343M12 8a4 4 0 100 8 4 4 0 000-8z"></path></svg>' },
    { id: 3,  name: 'Firewalls',    key: 'opnsense',   svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>' },
    { id: 4,  name: 'IPAM',         key: 'netbox',     svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 8v2m0 4v-2m8-2v2m0 4v-2M8 12h8"></path></svg>' },
    { id: 5,  name: 'Network',      key: 'nw',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="6" cy="6" r="2.25" stroke-width="2"></circle><circle cx="18" cy="6" r="2.25" stroke-width="2"></circle><circle cx="12" cy="18" r="2.25" stroke-width="2"></circle><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.25 6h7.5M7.2 7.9l3.6 8.2M16.8 7.9l-3.6 8.2"></path></svg>' },
    { id: 6,  name: 'NAC',          key: 'cppm',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>' },
    { id: 7,  name: 'Simulations',  key: 'cs',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path></svg>' },
    { id: 8,  name: 'DNS',          key: 'dns',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.6 9h16.8M3.6 15h16.8M11.5 3a17 17 0 000 18M12.5 3a17 17 0 010 18"></path></svg>' },
    { id: 9,  name: 'DHCP',         key: 'dhcp',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M9 3.75H6.912a2.25 2.25 0 00-2.15 1.588L2.35 13.177a2.25 2.25 0 00-.1.661V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18v-4.162c0-.224-.034-.447-.1-.661L19.24 5.338a2.25 2.25 0 00-2.15-1.588H15M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859M12 3v8.25m0 0l-3-3m3 3l3-3"></path></svg>' },
    { id: 10, name: 'Certificates', key: 'le',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m-6-8h6M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M14.5 19.5l1.5 1.5 2.5-2.5"></path></svg>' },
    { id: 11, name: 'Reports',      key: 'reports',    svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M8 17V11m4 6V7m4 10v-4M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>' },
    { id: 12, name: 'Console',      key: 'console',    svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z"></path></svg>' },
    { id: 13, name: 'Template Repo',key: 'templates',  svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path></svg>' },
    { id: 14, name: 'Bug Report',   key: 'bugs',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M4.5 8.5l2-1.5m13 1.5l-2-1.5M4.5 15.5l2 1.5m13-1.5l-2 1.5M12 4a4 4 0 014 4v4a4 4 0 01-8 0V8a4 4 0 014-4z"></path></svg>' },
    { id: 15, name: 'Feature Request', key: 'features', svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z"></path></svg>' },
    { id: 16, name: 'My Devices',   key: 'mydevices',  svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>' },
    { id: 17, name: 'Setup',        key: 'setup',      svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26"></path></svg>' },
    { id: 18, name: 'System',       key: 'settings',   svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>' },
    { id: 19, name: 'Logs',         key: 'logs',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.25 6.75h12M8.25 12h12M8.25 17.25h12M3.75 6.75h.007v.008H3.75V6.75zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zM3.75 12h.007v.008H3.75V12zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm-.375 5.25h.007v.008H3.75v-.008zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z"></path></svg>' },
    { id: 20, name: 'OS Updates',   key: 'osupdates',  svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path></svg>' },
    { id: 101, name: 'Storage',      key: 'truenas',    svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008V8.25zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008V8.25z"></path></svg>' },
];

// Extra icons available to assign to a module/nav item (not currently in use).
// Same outline style + 24×24 viewBox as LM_NAV_ICONS; IDs continue the series.
const LM_ICON_LIBRARY = [
    { id: 102, name: 'Database',     svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125"></path></svg>' },
    { id: 103, name: 'Cloud',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z"></path></svg>' },
    { id: 104, name: 'Lock',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"></path></svg>' },
    { id: 105, name: 'Key',          svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"></path></svg>' },
    { id: 106, name: 'Chart',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z"></path></svg>' },
    { id: 107, name: 'Users',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"></path></svg>' },
    { id: 108, name: 'Folder',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"></path></svg>' },
    { id: 109, name: 'Clock',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>' },
    { id: 110, name: 'Bell',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0"></path></svg>' },
    { id: 111, name: 'WiFi',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z"></path></svg>' },
    { id: 112, name: 'CPU Chip',     svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25zm.75-12h9v9h-9v-9z"></path></svg>' },
    { id: 113, name: 'Power / Bolt', svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"></path></svg>' },
    { id: 114, name: 'Location',     svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15 10.5a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1115 0z"></path></svg>' },
    { id: 115, name: 'Mail',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"></path></svg>' },
    { id: 116, name: 'Document',     svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"></path></svg>' },
    { id: 117, name: 'Eye',          svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>' },
    { id: 118, name: 'Play',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"></path></svg>' },
    { id: 119, name: 'Sync / Refresh', svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99"></path></svg>' },
    { id: 120, name: 'Globe',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"></path></svg>' },
    { id: 121, name: 'Server',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z"></path></svg>' },
    { id: 122, name: 'Check Circle',   svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>' },
    { id: 123, name: 'X Circle',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>' },
    { id: 124, name: 'Warning',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"></path></svg>' },
    { id: 125, name: 'Info Circle',    svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"></path></svg>' },
    { id: 126, name: 'Minus Circle',   svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15 12H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>' },
    { id: 127, name: 'Star',           svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.562.562 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.562.562 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z"></path></svg>' },
    { id: 128, name: 'Flag',           svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M3 3v1.5M3 21v-6m0 0l2.77-.693a9 9 0 016.208.682l.108.054a9 9 0 006.086.71l3.114-.732a48.524 48.524 0 01-.005-10.499l-3.11.732a9 9 0 01-6.085-.711l-.108-.054a9 9 0 00-6.208-.682L3 4.5M3 15V4.5"></path></svg>' },
    { id: 129, name: 'Bookmark',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0111.186 0z"></path></svg>' },
    { id: 130, name: 'Link',           svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244"></path></svg>' },
    { id: 131, name: 'Fire',           svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.047 8.287 8.287 0 009 9.601a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M12 18a3.75 3.75 0 00.495-7.467 5.99 5.99 0 00-1.925 3.546 5.974 5.974 0 01-2.133-1.001A3.75 3.75 0 0012 18z"></path></svg>' },
    { id: 132, name: 'Signal',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M9.348 14.652a3.75 3.75 0 010-5.304m5.304 0a3.75 3.75 0 010 5.304m-7.425 2.121a6.75 6.75 0 010-9.546m9.546 0a6.75 6.75 0 010 9.546M5.106 18.894c-3.808-3.808-3.808-9.98 0-13.789m13.788 0c3.808 3.808 3.808 9.981 0 13.79M12 12h.008v.008H12V12z"></path></svg>' },
    { id: 133, name: 'Layers',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M6 6.878V6a2.25 2.25 0 012.25-2.25h7.5A2.25 2.25 0 0118 6v.878m-12 0c.235-.083.487-.128.75-.128h10.5c.263 0 .515.045.75.128m-12 0A2.25 2.25 0 004.5 9v.878m13.5-3A2.25 2.25 0 0119.5 9v.878m0 0a2.246 2.246 0 00-.75-.128H5.25c-.263 0-.515.045-.75.128m15 0A2.25 2.25 0 0121 12v6a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 18v-6c0-.98.626-1.813 1.5-2.122"></path></svg>' },
    { id: 134, name: 'Beaker',         svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5"></path></svg>' },
    { id: 135, name: 'Building',       svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"></path></svg>' },
    { id: 136, name: 'Home',           svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"></path></svg>' },
    { id: 137, name: 'Battery',        svg: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M21 10.5h.375c.621 0 1.125.504 1.125 1.125v2.25c0 .621-.504 1.125-1.125 1.125H21M3.75 18h15A2.25 2.25 0 0021 15.75v-6a2.25 2.25 0 00-2.25-2.25h-15A2.25 2.25 0 001.5 9.75v6A2.25 2.25 0 003.75 18zM6 10.5h3.75v3H6v-3z"></path></svg>' },
];

function _renderSettingsIconsTile(content) {
    const { card } = _SETUP_CLS;
    const cell = ic => `
        <div class="flex flex-col items-center justify-center gap-2 p-4 rounded-lg border border-slate-200 hover:border-[#01A982] hover:bg-[#01A982]/5 transition">
            <div class="text-slate-600">${ic.svg}</div>
            <div class="text-sm font-semibold text-slate-700 text-center">${escapeHtml(ic.name)}</div>
            <div class="text-[11px] font-mono text-slate-400">ID ${ic.id}${ic.key ? ' · ' + escapeHtml(ic.key) : ''}</div>
        </div>`;
    const inUse = LM_NAV_ICONS.map(cell).join('');
    const library = LM_ICON_LIBRARY.map(cell).join('');
    content.innerHTML = `
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Left-nav icons — in use <span class="text-slate-400 font-normal">(${LM_NAV_ICONS.length})</span></h3>
            <p class="text-xs text-slate-400 mb-4">The icon set on the left navigation bar. Each has a stable <b>ID</b> and <b>key</b> — reference them when adding a new module or keeping icons consistent. Icons scale to the current text color.</p>
            <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">${inUse}</div>
        </div>
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Available icons <span class="text-slate-400 font-normal">(${LM_ICON_LIBRARY.length})</span></h3>
            <p class="text-xs text-slate-400 mb-4">Extra icons in the same outline style, ready to assign to a new module or nav item — cite the <b>ID</b> and I'll wire it in.</p>
            <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">${library}</div>
        </div>`;
}

// ── Settings → Azure → NetBox SSO (reuse the LM Entra app for NetBox) ───────
// Ports the hub's Azure SSO connection to NetBox: tenant/client_id, the hub's
// client certificate (no secret needed), allowed group, and the Permission
// Groups' Entra group map. Pushes to the netbox-server host's agent, which
// installs the "Sign in with Microsoft" button + restarts NetBox.
function _renderSettingsNetboxSsoTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">NetBox SSO — reuse the LM Entra app</h3>
                <span id="nbsso-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Log into <b>NetBox</b> with the <b>same Entra connection</b> the LM hub uses — tenant, client ID, the hub's <b>client certificate</b>, allowed group and Permission Group mappings are carried over (Global Admin groups become NetBox superusers). Enabling adds a <b>Sign in with Microsoft</b> button to NetBox's login page; local NetBox logins keep working. The one Azure-side step: on that same app registration add the redirect URI <code>https://&lt;netbox-host&gt;/oauth/complete/oidc/</code>.</p>
            <div id="nbsso-auth-mode" class="hidden text-xs rounded-md p-2 mb-3 border"></div>
            <div id="nbsso-oidc-warn" class="hidden text-xs text-amber-600 border border-amber-200 bg-amber-50 rounded-md p-2 mb-3"></div>
            <div id="nbsso-target-warn" class="hidden text-xs text-amber-600 border border-amber-200 bg-amber-50 rounded-md p-2 mb-3"></div>
            <div class="space-y-1 mb-3"><label class="${labelCls}">NetBox host <span class="text-slate-400 normal-case font-normal">(agent that runs NetBox — receives the hub's Entra certificate)</span></label><select id="nbsso-target" class="${inputCls} font-mono text-xs"></select></div>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="nbsso-enabled" class="w-4 h-4 text-green-600 rounded">Enable Entra SSO on NetBox (shows the <b>Sign in with Microsoft</b> button)</label>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Tenant ID <span class="text-slate-400 normal-case font-normal">(from hub SSO)</span></label><input id="nbsso-tenant" type="text" readonly class="${inputCls} font-mono text-xs bg-slate-50"></div>
                <div class="space-y-1"><label class="${labelCls}">Client ID <span class="text-slate-400 normal-case font-normal">(from hub SSO)</span></label><input id="nbsso-client" type="text" readonly class="${inputCls} font-mono text-xs bg-slate-50"></div>
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">Client secret <span class="text-slate-400 normal-case font-normal">(optional — only if the hub has no certificate)</span></label><input id="nbsso-secret" type="password" placeholder="not needed — uses the hub certificate" class="${inputCls} font-mono text-xs" autocomplete="new-password"></div>
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">Redirect URI</label><input id="nbsso-redirect" type="text" placeholder="https://<netbox-host>/oauth/complete/oidc/" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1 md:col-span-2"><label class="${labelCls}">Restrict login to Entra group <span class="text-slate-400 normal-case font-normal">(optional — object ID; blank = same as hub SSO)</span></label><input id="nbsso-allowed" type="text" placeholder="blank = inherit the hub's allowed group" class="${inputCls} font-mono text-xs"></div>
            </div>
            <div class="mt-4">
                <div class="flex items-center justify-between mb-1">
                    <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Entra group → NetBox group map</div>
                    <button type="button" onclick="nbssoSeedGroupMap()" class="text-[#01A982] hover:underline text-xs font-bold">Seed from Permission Groups</button>
                </div>
                <p class="text-[11px] text-slate-400 mb-2">Each login sets the user's NetBox groups to exactly the mapped set. Left = Entra group object ID, right = NetBox group name. Leave empty to use the Permission Groups mapping automatically.</p>
                <div id="nbsso-map-rows" class="space-y-2"></div>
                <button type="button" onclick="nbssoAddMapRow()" class="mt-2 text-xs font-bold text-slate-500 hover:text-slate-700">+ Add mapping</button>
            </div>
            <div id="nbsso-test-out" class="hidden text-xs rounded-md p-2 mt-3 mb-1 border"></div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="nbsso-msg" class="text-xs text-slate-400"></span>
                <div class="flex items-center gap-2">
                    <button type="button" onclick="testNetboxSso()" id="nbsso-test-btn" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 py-1.5 rounded-md text-xs font-bold">Test login</button>
                    <button onclick="saveNetboxSso()" id="nbsso-save-btn" class="${btnCls}">Save &amp; Apply</button>
                </div>
            </div>
        </div>`;
    loadNetboxSso();
}

async function testNetboxSso() {
    const out = document.getElementById('nbsso-test-out');
    const btn = document.getElementById('nbsso-test-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
    if (out) { out.className = 'text-xs rounded-md p-2 mt-3 mb-1 border border-slate-200 bg-slate-50 text-slate-500'; out.classList.remove('hidden'); out.textContent = 'Probing NetBox login → Entra…'; }
    try {
        const d = await apiJson('/setup/netbox-sso/test', { method: 'POST' });
        const good = !!d.ok;
        const f = d.found || {}, m = d.matches || {};
        const tick = b => b ? '✓' : '✗';
        const detail = d.redirects_to_entra
            ? ` — tenant ${tick(m.tenant)}, client ID ${tick(m.client_id)}, redirect URI ${tick(m.redirect_uri)}`
            : '';
        if (out) {
            out.className = 'text-xs rounded-md p-2 mt-3 mb-1 border ' + (good
                ? 'border-green-200 bg-green-50 text-green-700'
                : 'border-amber-200 bg-amber-50 text-amber-700');
            out.textContent = `${good ? '✓ ' : '⚠ '}${d.message || ''}${detail}`;
        }
        showToast(good ? 'NetBox SSO wiring looks good.' : 'NetBox SSO test found an issue.', good ? 'success' : 'error');
    } catch (e) {
        if (out) { out.className = 'text-xs rounded-md p-2 mt-3 mb-1 border border-red-200 bg-red-50 text-red-600'; out.textContent = '✗ ' + (e.message || e); }
        showToast('Test failed: ' + (e.message || e), 'error');
    } finally { if (btn) { btn.disabled = false; btn.textContent = 'Test login'; } }
}
window.testNetboxSso = testNetboxSso;

function _nbssoMapRow(k = '', v = '') {
    const { inputCls } = _SETUP_CLS;
    return `<div class="flex gap-2 nbsso-map-row">
        <input type="text" value="${escapeHtml(k)}" placeholder="Entra group object ID" class="${inputCls} font-mono text-xs flex-1 nbsso-map-k">
        <input type="text" value="${escapeHtml(v)}" placeholder="NetBox group name" class="${inputCls} text-xs flex-1 nbsso-map-v">
        <button type="button" onclick="this.closest('.nbsso-map-row').remove()" class="text-red-500 hover:text-red-700 font-bold px-2">✕</button>
    </div>`;
}
function nbssoAddMapRow() { const box = document.getElementById('nbsso-map-rows'); if (box) box.insertAdjacentHTML('beforeend', _nbssoMapRow()); }
function _nbssoRenderMap(map) {
    const box = document.getElementById('nbsso-map-rows'); if (!box) return;
    const entries = Object.entries(map || {});
    box.innerHTML = entries.length ? entries.map(([k, v]) => _nbssoMapRow(k, v)).join('') : _nbssoMapRow();
}
function _nbssoCollectMap() {
    const map = {};
    document.querySelectorAll('#nbsso-map-rows .nbsso-map-row').forEach(row => {
        const k = (row.querySelector('.nbsso-map-k')?.value || '').trim();
        const v = (row.querySelector('.nbsso-map-v')?.value || '').trim();
        if (k && v) map[k] = v;
    });
    return map;
}

async function loadNetboxSso() {
    try {
        const r = await setupFetch('/setup/netbox-sso');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {}, oidc = d.oidc || {};
        window.__nbssoSuggested = d.suggested_group_map || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v == null ? '' : v; };
        const en = document.getElementById('nbsso-enabled'); if (en) en.checked = !!c.enabled;
        set('nbsso-tenant', oidc.tenant_id); set('nbsso-client', oidc.client_id);
        set('nbsso-redirect', c.redirect_uri); set('nbsso-allowed', c.allowed_group);
        const secEl = document.getElementById('nbsso-secret');
        if (secEl) secEl.placeholder = oidc.cert_available ? 'not needed — uses the hub certificate' : (c.secret_set ? '•••••••• (stored — leave blank to keep)' : 'paste the client secret');
        const alEl = document.getElementById('nbsso-allowed');
        if (alEl) alEl.placeholder = oidc.allowed_group ? `blank = inherit hub (${oidc.allowed_group})` : 'blank = any user in tenant';
        const am = document.getElementById('nbsso-auth-mode');
        if (am) {
            const eff = d.effective || {};
            const nMap = Object.keys(eff.group_map || {}).length, nSu = (eff.superuser_groups || []).length;
            const certMode = d.auth_mode === 'certificate';
            am.className = 'text-xs rounded-md p-2 mb-3 border ' + (d.auth_mode === 'none' ? 'border-amber-200 bg-amber-50 text-amber-700' : 'border-green-200 bg-green-50 text-green-700');
            am.textContent = (certMode ? '✓ Auth: hub Entra certificate (no secret needed)'
                : d.auth_mode === 'secret' ? '✓ Auth: stored client secret (hub has no certificate)'
                : '⚠ No credential — generate the hub certificate in Settings → Azure → SSO, or paste a client secret')
                + ` · ${nMap} group mapping(s) · ${nSu} Global Admin group(s) → NetBox superuser`;
            am.classList.remove('hidden');
        }
        _nbssoRenderMap(c.group_map);
        const pill = document.getElementById('nbsso-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        const ow = document.getElementById('nbsso-oidc-warn');
        if (ow) { if (!oidc.configured) { ow.textContent = 'Hub Entra SSO is not configured yet — set it up in Settings → Cloud → Azure → SSO first (NetBox reuses its tenant + client ID).'; ow.classList.remove('hidden'); } else ow.classList.add('hidden'); }
        const cands = d.netbox_server_agents || [];
        const sel = document.getElementById('nbsso-target');
        if (sel) {
            const opts = [...cands];
            if (c.target_agent && !opts.includes(c.target_agent)) opts.unshift(c.target_agent);
            const pick = c.target_agent || (cands.length === 1 ? cands[0] : '');
            sel.innerHTML = '<option value="">— select —</option>' + opts.map(a =>
                `<option value="${escapeHtml(a)}"${a === pick ? ' selected' : ''}>${escapeHtml(a)}${cands.includes(a) ? '' : ' (offline / no NetBox)'}</option>`).join('');
        }
        const tw = document.getElementById('nbsso-target-warn');
        if (tw) { if (!cands.length) { tw.textContent = 'No connected agent reports a NetBox install. The agent on the NetBox host (the one that deployed the "NetBox Server" role) must be online to enable SSO.'; tw.classList.remove('hidden'); } else tw.classList.add('hidden'); }
    } catch (e) { console.error('loadNetboxSso failed', e); }
}

function nbssoSeedGroupMap() {
    const sug = window.__nbssoSuggested || {};
    if (!Object.keys(sug).length) { showToast('No Permission Groups with an Entra Directory Group set.', 'error'); return; }
    const cur = _nbssoCollectMap();
    _nbssoRenderMap({ ...sug, ...cur });
    showToast('Seeded from Permission Groups — edit the NetBox group names as needed.', 'success');
}

async function saveNetboxSso() {
    const btn = document.getElementById('nbsso-save-btn');
    const v = id => (document.getElementById(id)?.value || '').trim();
    const cfg = {
        enabled: !!document.getElementById('nbsso-enabled')?.checked,
        redirect_uri: v('nbsso-redirect'),
        allowed_group: v('nbsso-allowed'),
        group_map: _nbssoCollectMap(),
        target_agent: v('nbsso-target'),
    };
    const secret = v('nbsso-secret');
    if (secret) cfg.client_secret = secret;  // blank = keep stored
    if (btn) btn.disabled = true;
    try {
        const d = await apiJson('/setup/netbox-sso', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) });
        const msg = document.getElementById('nbsso-msg');
        if (d.no_target) { if (msg) msg.textContent = 'Saved (no NetBox host selected).'; showToast('Saved — no NetBox host selected.', 'success'); }
        else { if (msg) msg.textContent = `Applied to ${(d.pushed || []).length} host(s)${(d.queued || []).length ? ', queued ' + d.queued.length : ''} (auth: ${d.auth_mode || 'secret'}).`; showToast('NetBox SSO pushed to the netbox-server host.', 'success'); }
        loadNetboxSso();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) btn.disabled = false; }
}
window.nbssoAddMapRow = nbssoAddMapRow; window.nbssoSeedGroupMap = nbssoSeedGroupMap; window.saveNetboxSso = saveNetboxSso;

// ── Settings → Azure NSG (alias-style allow-list) ───────────────────────────
// Manage one allow rule in an Azure NSG as an IP allow-list. Reuses the SSO
// Entra app's cert for ARM auth (Network Contributor role required). Admin-only.
function _renderSettingsAzureNsgTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">NSG — IP allow-list</h3>
                <span id="nsg-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Manages one <b>allow rule</b> in an Azure Network Security Group as an IP allow-list (one rule, many IPs — add/remove below). Auth <b>reuses the SSO Entra app's certificate</b>, so set that up first in <b>Settings → SSO</b>. In Azure, grant that app the <b>Network Contributor</b> role on the NSG (or its resource group) — <b>Access control (IAM) → Add role assignment → Network Contributor → assign to the app</b>.</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="nsg-enabled" class="w-4 h-4 text-green-600 rounded">Enable NSG management (Save applies the IP list to Azure)</label>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Subscription ID</label><input id="nsg-sub" type="text" placeholder="xxxxxxxx-xxxx-…" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Resource Group</label><input id="nsg-rg" type="text" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">NSG Name</label><input id="nsg-name" type="text" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Rule Name</label><input id="nsg-rule" type="text" placeholder="lm-allowlist" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Allow priority (100–4096)</label><input id="nsg-prio" type="number" placeholder="300" oninput="_nsgPrioLive()" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Deny priority <span class="text-slate-400 normal-case font-normal">(threat-monitor block rule)</span></label><input id="nsg-deny-prio" type="number" placeholder="400" oninput="_nsgPrioLive()" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Direction</label><select id="nsg-dir" class="${inputCls}"><option>Inbound</option><option>Outbound</option></select></div>
                <div class="space-y-1"><label class="${labelCls}">Protocol</label><select id="nsg-proto" class="${inputCls}"><option value="*">Any</option><option value="Tcp">Tcp</option><option value="Udp">Udp</option></select></div>
                <div class="space-y-1"><label class="${labelCls}">Destination Port(s)</label><input id="nsg-dport" type="text" placeholder="* or 443,22" class="${inputCls}"></div>
            </div>
            <p class="text-[11px] text-slate-500 mt-2 bg-slate-50 rounded px-2 py-1.5 leading-relaxed"><b>Allow must be a lower number than Deny; both below 1000 (Azure's default allow on 443).</b> The <b>Deny priority</b> belongs to the threat monitor (<b>Security</b> view) — editing it here updates <b>both</b> (allow → Azure NSG, deny → threat monitor). <span id="nsg-prio-check"></span></p>
            <div class="mt-3 space-y-1">
                <div class="flex items-center justify-between">
                    <label class="${labelCls}">Allow-list — IP / CIDR + description <span class="text-slate-400 normal-case font-normal">(descriptions are kept in LM only — Azure has no per-IP note)</span></label>
                    <span id="nsg-drift" class="text-[11px] text-slate-400"></span>
                </div>
                <p class="text-[11px] text-slate-400 mb-1">This is a <b>shared trusted list</b>: every IP here is also <b>never auto-blocked</b> by the threat monitor, and the same list is editable under <b>Security → Trusted IPs</b>. IPs open an NSG allow rule only when NSG management is enabled above.</p>
                <div class="flex gap-2 mb-2">
                    <input id="nsg-add-ip" type="text" placeholder="1.2.3.4 or 10.0.0.0/24" class="${inputCls} font-mono text-xs flex-1">
                    <input id="nsg-add-desc" type="text" placeholder="description (optional)" class="${inputCls} text-xs flex-1">
                    <button type="button" onclick="addNsgEntry()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold whitespace-nowrap">+ Add</button>
                </div>
                <div id="nsg-entries" class="border border-slate-200 rounded-md divide-y divide-slate-100 max-h-72 overflow-y-auto"></div>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="nsg-msg" class="text-xs text-slate-400"></span>
                <div class="flex items-center gap-3">
                    <button onclick="testAzureNsg()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-4 py-2 rounded-md text-sm font-bold">Test connection</button>
                    <button onclick="saveAzureNsg()" id="nsg-save-btn" class="${btnCls}">Save &amp; Apply</button>
                </div>
            </div>
        </div>`;
    loadAzureNsg();
}

// Local allow-list DB: [{ip, description}]. IPs go to Azure; descriptions stay
// in LM. renderNsgEntries paints the rows; _syncNsgEntriesFromDom reads inline
// description edits back before add/remove/save.
function renderNsgEntries() {
    const box = document.getElementById('nsg-entries');
    if (!box) return;
    const es = window._nsgEntries || [];
    box.innerHTML = es.length ? es.map((e, i) => `
      <div class="flex items-center gap-2 px-2 py-1">
        <span class="font-mono text-xs text-slate-700 w-44 shrink-0 truncate" title="${escapeHtml(e.ip)}">${escapeHtml(e.ip)}</span>
        <input data-nsg-desc="${i}" value="${escapeHtml(e.description || '')}" placeholder="description" class="flex-1 bg-white border border-slate-200 rounded px-2 py-1 text-xs outline-none focus:ring-1 focus:ring-green-400">
        <button type="button" onclick="removeNsgEntry(${i})" title="Remove" class="text-red-500 hover:text-red-700 text-xs font-bold px-1">✕</button>
      </div>`).join('')
      : '<div class="text-xs text-slate-400 italic px-2 py-2">No IPs yet. Add one above, or hit Test/Save to import what\'s already on the NSG.</div>';
}
function _syncNsgEntriesFromDom() {
    (window._nsgEntries || []).forEach((e, i) => {
        const el = document.querySelector(`[data-nsg-desc="${i}"]`);
        if (el) e.description = el.value;
    });
}
window.addNsgEntry = function () {
    _syncNsgEntriesFromDom();
    const ipEl = document.getElementById('nsg-add-ip'), dEl = document.getElementById('nsg-add-desc');
    const ip = (ipEl?.value || '').trim();
    if (!ip) { if (typeof showToast === 'function') showToast('Enter an IP or CIDR', 'info'); return; }
    window._nsgEntries = window._nsgEntries || [];
    window._nsgEntries.push({ ip, description: (dEl?.value || '').trim() });
    if (ipEl) ipEl.value = ''; if (dEl) dEl.value = '';
    renderNsgEntries();
};
window.removeNsgEntry = function (i) {
    _syncNsgEntriesFromDom();
    (window._nsgEntries || []).splice(i, 1);
    renderNsgEntries();
};

function _azureNsgFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    _syncNsgEntriesFromDom();
    return {
        enabled: !!document.getElementById('nsg-enabled')?.checked,
        subscription_id: v('nsg-sub'), resource_group: v('nsg-rg'),
        nsg_name: v('nsg-name'), rule_name: v('nsg-rule') || 'lm-allowlist',
        priority: parseInt(v('nsg-prio'), 10) || 300,
        direction: v('nsg-dir') || 'Inbound', protocol: v('nsg-proto') || '*',
        dest_port: v('nsg-dport') || '*',
        entries: (window._nsgEntries || []).map(e => ({ ip: e.ip, description: e.description || '' })),
    };
}

async function loadAzureNsg() {
    try {
        const r = await setupFetch('/setup/azure-nsg');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val == null ? '' : val; };
        const chk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };
        chk('nsg-enabled', c.enabled);
        set('nsg-sub', c.subscription_id); set('nsg-rg', c.resource_group); set('nsg-name', c.nsg_name);
        set('nsg-rule', c.rule_name || 'lm-allowlist'); set('nsg-prio', c.priority || 300);
        set('nsg-dir', c.direction || 'Inbound'); set('nsg-proto', c.protocol || '*'); set('nsg-dport', c.dest_port || '*');
        // Deny priority is owned by the threat monitor; the GET returns it under `deny`.
        const denyPrio = (d.deny && d.deny.priority != null) ? d.deny.priority : 400;
        set('nsg-deny-prio', denyPrio);
        window._nsgStoredAllow = c.priority || 300;
        window._nsgStoredDeny = denyPrio;
        window._nsgEntries = (c.entries || []).map(e => ({ ip: e.ip, description: e.description || '' }));
        renderNsgEntries();
        _nsgPrioLive();
        const pill = document.getElementById('nsg-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        const drift = document.getElementById('nsg-drift');
        if (drift) {
            if (d.warning) drift.textContent = 'Live read failed: ' + d.warning;
            else if (Array.isArray(d.live_prefixes)) {
                const localIps = (c.entries || []).map(e => e.ip);
                const same = JSON.stringify(d.live_prefixes.slice().sort()) === JSON.stringify(localIps.slice().sort());
                drift.textContent = `Live in Azure: ${d.live_prefixes.length} IP(s)` + (same ? ' — in sync' : ' — differs from local (Save & Apply to sync)');
            } else drift.textContent = 'Rule not present in Azure yet — Save & Apply to create it.';
        }
    } catch (e) { console.error('loadAzureNsg failed', e); }
}

function _nsgPrioLive() {
    const a = document.getElementById('nsg-prio'), d = document.getElementById('nsg-deny-prio');
    const out = document.getElementById('nsg-prio-check');
    if (a && d && out) out.innerHTML = _prioCheckHtml(a.value, d.value);
}

async function saveAzureNsg() {
    const btn = document.getElementById('nsg-save-btn'); const msg = document.getElementById('nsg-msg');
    const cfg = _azureNsgFormConfig();                 // includes priority (allow)
    const allow = cfg.priority;
    const deny = parseInt((document.getElementById('nsg-deny-prio')?.value || ''), 10);
    // Client-side guard (server enforces the same invariant). Block save when bad.
    const chk = _nsgPriorityCheck(allow, deny);
    if (!chk.ok) { showToast('Cannot save: ' + chk.msg, 'error'); return; }
    if (btn) { btn.disabled = true; btn.textContent = 'Applying…'; }
    try {
        // Save BOTH: allow (full Azure config) → azure_nsg, deny → threat monitor.
        const storedDeny = Number(window._nsgStoredDeny != null ? window._nsgStoredDeny : deny);
        let d = null;
        await _saveOrderedPriorities(allow, storedDeny,
            async () => { d = await apiJson('/setup/azure-nsg', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) }); },
            () => _saveDenyPriority(deny));
        if (d && d.warning) { showToast('Saved, but Azure apply failed: ' + d.warning, 'error'); if (msg) msg.textContent = d.warning; }
        else if (d) {
            const a = d.applied;
            const detail = a ? (a.deleted ? 'rule cleared' : `${(a.prefixes || []).length} IP(s) applied`) : 'saved (not applied)';
            showToast('Azure NSG: ' + detail, 'success'); if (msg) msg.textContent = detail;
        } else { showToast('Priorities saved', 'success'); }
        loadAzureNsg();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save & Apply'; } }
}

async function testAzureNsg() {
    const msg = document.getElementById('nsg-msg');
    if (msg) msg.textContent = 'Testing…';
    try {
        const r = await setupFetch('/setup/azure-nsg/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _azureNsgFormConfig() }) });
        const d = await r.json().catch(() => ({}));
        if (d.status === 'ok') { showToast(`Connected — NSG has ${d.rules} rule(s).`, 'success'); if (msg) msg.textContent = `OK: ${d.location || ''}, ${d.rules} rules`; }
        else { showToast('Test failed: ' + (d.message || 'error'), 'error'); if (msg) msg.textContent = d.message || 'failed'; }
    } catch (e) { showToast('Test failed: ' + (e.message || e), 'error'); if (msg) msg.textContent = String(e.message || e); }
}

// ── Settings → Cloud → OCI → NSG (allow-list) ─────────────────────────────────
// OCI parity for Azure NSG above: manages a SET of allow rules (one per CIDR —
// OCI security rules carry a single source, unlike Azure's prefix-list rule) on
// an OCI Network Security Group. Auth is a plain OCI API signing key (tenancy +
// user OCID + fingerprint + private key), not the Entra app cert. NOTE: OCI NSGs
// support ALLOW rules only — there is no deny/priority to reconcile, so this tile
// has no counterpart to the Azure tile's Allow/Deny priority fields.
function _renderSettingsOciNsgTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">OCI NSG — IP allow-list</h3>
                <span id="oci-nsg-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Manages a set of <b>allow rules</b> (one per IP/CIDR, tagged so a reconcile only touches rules it created) on an Oracle Cloud Infrastructure <b>Network Security Group</b>. Auth is a dedicated <b>OCI API signing key</b> — create one for a user with an IAM policy granting <code>manage security-lists</code> (or <code>use network-security-groups</code>) in the NSG's compartment, then paste its details below. <b>OCI NSGs allow-only</b> — traffic not matched by a rule is denied by default, so there is no deny/priority to configure here (unlike Azure NSG).</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="oci-nsg-enabled" class="w-4 h-4 text-green-600 rounded">Enable NSG management (Save applies the IP list to OCI)</label>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Tenancy OCID</label><input id="oci-nsg-tenancy" type="text" placeholder="ocid1.tenancy.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">User OCID</label><input id="oci-nsg-user" type="text" placeholder="ocid1.user.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Key fingerprint</label><input id="oci-nsg-fp" type="text" placeholder="aa:bb:cc:…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Private key path <span class="text-slate-400 normal-case font-normal">(or kv:&lt;name&gt;)</span></label>
                    <div class="flex gap-2">
                        <input id="oci-nsg-key" type="text" placeholder="/etc/lm/oci/api-key.pem or kv:oci-api-key" class="${inputCls} font-mono text-xs flex-1">
                        <button type="button" onclick="document.getElementById('oci-nsg-key-file').click()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold whitespace-nowrap">Upload…</button>
                        <input type="file" id="oci-nsg-key-file" accept=".pem,.key,text/plain,application/x-pem-file" class="hidden" onchange="uploadOciNsgKey(this)">
                    </div>
                    <p class="text-[11px] text-slate-400">Upload the unencrypted PEM private key generated for this OCI API user (Profile → API Keys → Add API Key). It's written to a 0600 file on this hub and the path above is filled in automatically — the key content itself is never shown or sent back to the browser.</p>
                </div>
                <div class="space-y-1"><label class="${labelCls}">Region</label><select id="oci-nsg-region" class="${inputCls}"><option value="">Loading regions…</option></select></div>
                <div class="space-y-1"><label class="${labelCls}">NSG OCID</label><input id="oci-nsg-id" type="text" placeholder="ocid1.networksecuritygroup.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Destination port</label><input id="oci-nsg-dport" type="text" placeholder="443" class="${inputCls}"></div>
            </div>
            <div class="mt-3 space-y-1">
                <div class="flex items-center justify-between">
                    <label class="${labelCls}">Allow-list — IP / CIDR + description <span class="text-slate-400 normal-case font-normal">(descriptions are kept in LM only — OCI has no per-IP note)</span></label>
                    <span id="oci-nsg-drift" class="text-[11px] text-slate-400"></span>
                </div>
                <div class="flex gap-2 mb-2">
                    <input id="oci-nsg-add-ip" type="text" placeholder="1.2.3.4 or 10.0.0.0/24" class="${inputCls} font-mono text-xs flex-1">
                    <input id="oci-nsg-add-desc" type="text" placeholder="description (optional)" class="${inputCls} text-xs flex-1">
                    <button type="button" onclick="addOciNsgEntry()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold whitespace-nowrap">+ Add</button>
                </div>
                <div id="oci-nsg-entries" class="border border-slate-200 rounded-md divide-y divide-slate-100 max-h-72 overflow-y-auto"></div>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="oci-nsg-msg" class="text-xs text-slate-400"></span>
                <div class="flex items-center gap-3">
                    <button onclick="testOciNsg()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-4 py-2 rounded-md text-sm font-bold">Test connection</button>
                    <button onclick="saveOciNsg()" id="oci-nsg-save-btn" class="${btnCls}">Save &amp; Apply</button>
                </div>
            </div>
        </div>`;
    loadOciNsg();
}

// Local allow-list DB: [{ip, description}]. IPs go to OCI; descriptions stay in
// LM. This is a SEPARATE list from Azure's (Settings → Cloud → Azure → NSG /
// Security → Trusted IPs) — OCI has no deny/threat-monitor tie-in, so unlike
// the Azure list it is not the never-block source.
function renderOciNsgEntries() {
    const box = document.getElementById('oci-nsg-entries');
    if (!box) return;
    const es = window._ociNsgEntries || [];
    box.innerHTML = es.length ? es.map((e, i) => `
      <div class="flex items-center gap-2 px-2 py-1">
        <span class="font-mono text-xs text-slate-700 w-44 shrink-0 truncate" title="${escapeHtml(e.ip)}">${escapeHtml(e.ip)}</span>
        <input data-oci-nsg-desc="${i}" value="${escapeHtml(e.description || '')}" placeholder="description" class="flex-1 bg-white border border-slate-200 rounded px-2 py-1 text-xs outline-none focus:ring-1 focus:ring-green-400">
        <button type="button" onclick="removeOciNsgEntry(${i})" title="Remove" class="text-red-500 hover:text-red-700 text-xs font-bold px-1">✕</button>
      </div>`).join('')
      : '<div class="text-xs text-slate-400 italic px-2 py-2">No IPs yet. Add one above, or hit Test/Save to import what\'s already on the NSG.</div>';
}
function _syncOciNsgEntriesFromDom() {
    (window._ociNsgEntries || []).forEach((e, i) => {
        const el = document.querySelector(`[data-oci-nsg-desc="${i}"]`);
        if (el) e.description = el.value;
    });
}
window.addOciNsgEntry = function () {
    _syncOciNsgEntriesFromDom();
    const ipEl = document.getElementById('oci-nsg-add-ip'), dEl = document.getElementById('oci-nsg-add-desc');
    const ip = (ipEl?.value || '').trim();
    if (!ip) { if (typeof showToast === 'function') showToast('Enter an IP or CIDR', 'info'); return; }
    window._ociNsgEntries = window._ociNsgEntries || [];
    window._ociNsgEntries.push({ ip, description: (dEl?.value || '').trim() });
    if (ipEl) ipEl.value = ''; if (dEl) dEl.value = '';
    renderOciNsgEntries();
};
window.removeOciNsgEntry = function (i) {
    _syncOciNsgEntriesFromDom();
    (window._ociNsgEntries || []).splice(i, 1);
    renderOciNsgEntries();
};

// Populate an OCI Region <select> from the hub's curated catalog. Shared by the
// OCI NSG and OCI Vault tiles. A dropdown (not free text) is deliberate: a
// typo'd region only ever surfaces as a DNS failure at call time.
// `current` is the stored value — kept as an extra option if it isn't in the
// catalog, so a newer//custom region already configured isn't silently lost.
async function _ociPopulateRegions(selectId, current) {
    const el = document.getElementById(selectId);
    if (!el) return;
    let regions = [];
    try {
        const r = await setupFetch('/setup/oci-regions');
        const d = await r.json().catch(() => ({}));
        regions = d.regions || [];
    } catch (e) { console.error('load OCI regions failed', e); }
    const cur = (current || '').trim();
    const opts = ['<option value="">— Select a region —</option>'];
    if (cur && !regions.some(x => x.id === cur)) {
        opts.push(`<option value="${escapeHtml(cur)}">${escapeHtml(cur)} (configured)</option>`);
    }
    regions.forEach(x => opts.push(`<option value="${escapeHtml(x.id)}">${escapeHtml(x.label)}</option>`));
    el.innerHTML = opts.join('');
    el.value = cur;
}

function _ociNsgFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    _syncOciNsgEntriesFromDom();
    return {
        enabled: !!document.getElementById('oci-nsg-enabled')?.checked,
        tenancy_ocid: v('oci-nsg-tenancy'), user_ocid: v('oci-nsg-user'),
        fingerprint: v('oci-nsg-fp'), key_path: v('oci-nsg-key'),
        region: v('oci-nsg-region'), nsg_id: v('oci-nsg-id'),
        dest_port: v('oci-nsg-dport') || '443',
        entries: (window._ociNsgEntries || []).map(e => ({ ip: e.ip, description: e.description || '' })),
    };
}

async function loadOciNsg() {
    try {
        const r = await setupFetch('/setup/oci-nsg');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val == null ? '' : val; };
        const chk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };
        chk('oci-nsg-enabled', c.enabled);
        set('oci-nsg-tenancy', c.tenancy_ocid); set('oci-nsg-user', c.user_ocid);
        set('oci-nsg-fp', c.fingerprint); set('oci-nsg-key', c.key_path);
        set('oci-nsg-region', c.region); set('oci-nsg-id', c.nsg_id);
        await _ociPopulateRegions('oci-nsg-region', c.region);
        set('oci-nsg-dport', c.dest_port || '443');
        window._ociNsgEntries = (c.entries || []).map(e => ({ ip: e.ip, description: e.description || '' }));
        renderOciNsgEntries();
        const pill = document.getElementById('oci-nsg-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
        const drift = document.getElementById('oci-nsg-drift');
        if (drift) {
            if (d.warning) drift.textContent = 'Live read failed: ' + d.warning;
            else if (Array.isArray(d.live_prefixes)) {
                const localIps = (c.entries || []).map(e => e.ip);
                const same = JSON.stringify(d.live_prefixes.slice().sort()) === JSON.stringify(localIps.slice().sort());
                let txt = `Live in OCI: ${d.live_prefixes.length} IP(s) managed by LM` + (same ? ' — in sync' : ' — differs from local (Save & Apply to sync)');
                // Rules the operator created by hand carry no LM marker. They
                // are shown so the screen reflects what is actually on the NSG
                // (it previously reported 0 and looked like a failed read), but
                // LM never edits or adopts them.
                const un = Array.isArray(d.unmanaged_prefixes) ? d.unmanaged_prefixes : [];
                if (un.length) txt += ` · plus ${un.length} pre-existing rule(s) not managed by LM (${un.slice(0, 4).join(', ')}${un.length > 4 ? '…' : ''}) — left untouched`;
                drift.textContent = txt;
            } else drift.textContent = 'NSG not found yet — check the NSG OCID, or Save & Apply once it exists.';
        }
    } catch (e) { console.error('loadOciNsg failed', e); }
}

async function saveOciNsg() {
    const btn = document.getElementById('oci-nsg-save-btn'); const msg = document.getElementById('oci-nsg-msg');
    const cfg = _ociNsgFormConfig();
    if (btn) { btn.disabled = true; btn.textContent = 'Applying…'; }
    try {
        const d = await apiJson('/setup/oci-nsg', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) });
        if (d && d.warning) { showToast('Saved, but OCI apply failed: ' + d.warning, 'error'); if (msg) msg.textContent = d.warning; }
        else if (d) {
            const a = d.applied;
            const detail = a ? `${(a.prefixes || []).length} IP(s) applied (+${a.added || 0}/-${a.removed || 0})` : 'saved (not applied)';
            showToast('OCI NSG: ' + detail, 'success'); if (msg) msg.textContent = detail;
        } else { showToast('Saved', 'success'); }
        loadOciNsg();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save & Apply'; } }
}

async function testOciNsg() {
    const msg = document.getElementById('oci-nsg-msg');
    if (msg) msg.textContent = 'Testing…';
    try {
        const r = await setupFetch('/setup/oci-nsg/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _ociNsgFormConfig() }) });
        const d = await r.json().catch(() => ({}));
        if (d.status === 'ok') { showToast(`Connected — NSG is ${d.lifecycle_state || 'reachable'}.`, 'success'); if (msg) msg.textContent = `OK: ${d.lifecycle_state || ''}`; }
        else { showToast('Test failed: ' + (d.message || 'error'), 'error'); if (msg) msg.textContent = d.message || 'failed'; }
    } catch (e) { showToast('Test failed: ' + (e.message || e), 'error'); if (msg) msg.textContent = String(e.message || e); }
}

// Upload the OCI API signing private key (PEM) instead of hand-typing/scp-ing
// a path onto the hub. The server validates it parses as an unencrypted PEM
// key, writes it to a fixed 0600 path, and persists that path into
// oci_nsg.key_path immediately (independent of the rest of this form / the
// Save & Apply button) -- so a partially-filled form in progress can't lose
// the just-uploaded key.
async function uploadOciNsgKey(input) {
    const file = input && input.files && input.files[0];
    if (!file) return;
    const msg = document.getElementById('oci-nsg-msg');
    try {
        const fd = new FormData();
        fd.append('file', file, file.name);
        const d = await apiJson('/setup/oci-nsg/upload-key', { method: 'POST', body: fd });
        const el = document.getElementById('oci-nsg-key');
        if (el) el.value = d.key_path || '';
        showToast('Private key uploaded and saved.', 'success');
        if (msg) msg.textContent = 'Key uploaded — click Save & Apply to reconcile with the new key.';
    } catch (e) { showToast('Key upload failed: ' + (e.message || e), 'error'); }
    finally { input.value = ''; }
}
window.uploadOciNsgKey = uploadOciNsgKey;

// OCI Vault — connection config for the OCI parity backend of Credential
// Vault (cloud_vault.py dispatches here when oci_vault.enabled). Auth is a
// SEPARATE OCI API signing key from oci_nsg's (a customer may reasonably
// want a narrower-scoped user/key per integration) — see routes/oci_vault.py
// module docstring. Mirrors _renderSettingsOciNsgTile's layout/upload pattern.
function _renderSettingsOciVaultTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">OCI Vault — Key Vault backend</h3>
                <span id="oci-vault-state-pill" class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-500">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Connects the hub's <b>Credential Vault</b> (secret storage abstraction) to an Oracle Cloud Infrastructure <b>Vault</b>. Auth is a dedicated <b>OCI API signing key</b> — create one for a user with an IAM policy granting <code>manage secret-family</code> (create/update secrets) and <code>manage vaults</code> (read-only use is enough for Test connection) in the vault's compartment, then paste its details below. This is a <b>separate</b> OCI user/key from OCI NSG's — a narrower-scoped key per integration is fine.</p>
            <label class="flex items-center gap-2 text-sm text-slate-600 mb-3 cursor-pointer"><input type="checkbox" id="oci-vault-enabled" class="w-4 h-4 text-green-600 rounded">Enable OCI Vault (this hub's Key Vault backend)</label>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Tenancy OCID</label><input id="oci-vault-tenancy" type="text" placeholder="ocid1.tenancy.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">User OCID</label><input id="oci-vault-user" type="text" placeholder="ocid1.user.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Key fingerprint</label><input id="oci-vault-fp" type="text" placeholder="aa:bb:cc:…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Private key path <span class="text-slate-400 normal-case font-normal">(or kv:&lt;name&gt;)</span></label>
                    <div class="flex gap-2">
                        <input id="oci-vault-key" type="text" placeholder="/etc/lm/oci/api-key.pem or kv:oci-vault-key" class="${inputCls} font-mono text-xs flex-1">
                        <button type="button" onclick="document.getElementById('oci-vault-key-file').click()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold whitespace-nowrap">Upload…</button>
                        <input type="file" id="oci-vault-key-file" accept=".pem,.key,text/plain,application/x-pem-file" class="hidden" onchange="uploadOciVaultKey(this)">
                    </div>
                    <p class="text-[11px] text-slate-400">Upload the unencrypted PEM private key generated for this OCI API user (Profile → API Keys → Add API Key). It's written to a 0600 file on this hub and the path above is filled in automatically — the key content itself is never shown or sent back to the browser.</p>
                </div>
                <div class="space-y-1"><label class="${labelCls}">Region</label><select id="oci-vault-region" class="${inputCls}"><option value="">Loading regions…</option></select></div>
                <div class="space-y-1"><label class="${labelCls}">Compartment OCID</label><input id="oci-vault-compartment" type="text" placeholder="ocid1.compartment.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Vault OCID</label><input id="oci-vault-vault" type="text" placeholder="ocid1.vault.oc1..…" class="${inputCls} font-mono text-xs"></div>
                <div class="space-y-1"><label class="${labelCls}">Master encryption key OCID</label><input id="oci-vault-keyid" type="text" placeholder="ocid1.key.oc1..…" class="${inputCls} font-mono text-xs"></div>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="oci-vault-msg" class="text-xs text-slate-400"></span>
                <div class="flex items-center gap-3">
                    <button onclick="testOciVault()" class="bg-slate-100 hover:bg-slate-200 text-slate-600 px-4 py-2 rounded-md text-sm font-bold">Test connection</button>
                    <button onclick="saveOciVault()" id="oci-vault-save-btn" class="${btnCls}">Save</button>
                </div>
            </div>
        </div>`;
    loadOciVault();
}

function _ociVaultFormConfig() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    return {
        enabled: !!document.getElementById('oci-vault-enabled')?.checked,
        tenancy_ocid: v('oci-vault-tenancy'), user_ocid: v('oci-vault-user'),
        fingerprint: v('oci-vault-fp'), key_path: v('oci-vault-key'),
        region: v('oci-vault-region'), compartment_id: v('oci-vault-compartment'),
        vault_id: v('oci-vault-vault'), key_id: v('oci-vault-keyid'),
    };
}

async function loadOciVault() {
    try {
        const r = await setupFetch('/setup/oci-vault');
        const d = await r.json().catch(() => ({}));
        const c = d.config || {};
        const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val == null ? '' : val; };
        const chk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };
        chk('oci-vault-enabled', c.enabled);
        set('oci-vault-tenancy', c.tenancy_ocid); set('oci-vault-user', c.user_ocid);
        set('oci-vault-fp', c.fingerprint); set('oci-vault-key', c.key_path);
        set('oci-vault-region', c.region); set('oci-vault-compartment', c.compartment_id);
        await _ociPopulateRegions('oci-vault-region', c.region);
        set('oci-vault-vault', c.vault_id); set('oci-vault-keyid', c.key_id);
        const pill = document.getElementById('oci-vault-state-pill');
        if (pill) { pill.textContent = c.enabled ? 'ENABLED' : 'DISABLED'; pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' + (c.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'); }
    } catch (e) { console.error('loadOciVault failed', e); }
}

async function saveOciVault() {
    const btn = document.getElementById('oci-vault-save-btn'); const msg = document.getElementById('oci-vault-msg');
    const cfg = _ociVaultFormConfig();
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        await apiJson('/setup/oci-vault', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) });
        showToast('OCI Vault config saved.', 'success'); if (msg) msg.textContent = 'saved';
        loadOciVault();
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save'; } }
}

async function testOciVault() {
    const msg = document.getElementById('oci-vault-msg');
    if (msg) msg.textContent = 'Testing…';
    try {
        const r = await setupFetch('/setup/oci-vault/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: _ociVaultFormConfig() }) });
        const d = await r.json().catch(() => ({}));
        if (d.status === 'ok') { showToast('Connected to OCI Vault.', 'success'); if (msg) msg.textContent = 'OK'; }
        else { showToast('Test failed: ' + (d.message || 'error'), 'error'); if (msg) msg.textContent = d.message || 'failed'; }
    } catch (e) { showToast('Test failed: ' + (e.message || e), 'error'); if (msg) msg.textContent = String(e.message || e); }
}

// Same upload pattern as uploadOciNsgKey, targeting the OCI Vault key path.
async function uploadOciVaultKey(input) {
    const file = input && input.files && input.files[0];
    if (!file) return;
    const msg = document.getElementById('oci-vault-msg');
    try {
        const fd = new FormData();
        fd.append('file', file, file.name);
        const d = await apiJson('/setup/oci-vault/upload-key', { method: 'POST', body: fd });
        const el = document.getElementById('oci-vault-key');
        if (el) el.value = d.key_path || '';
        showToast('Private key uploaded and saved.', 'success');
        if (msg) msg.textContent = 'Key uploaded — click Save to confirm the rest of the config.';
    } catch (e) { showToast('Key upload failed: ' + (e.message || e), 'error'); }
    finally { input.value = ''; }
}
window.testOciVault = testOciVault; window.saveOciVault = saveOciVault; window.uploadOciVaultKey = uploadOciVaultKey;

function _renderSettingsSsoTile(content) {
    const { card, inputCls, labelCls, btnCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card}">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Single Sign-On — Microsoft Entra ID (OIDC)</h3>
                <span id="oidc-state-pill" class="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 font-bold">—</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">Users sign in with Microsoft Entra ID. On callback the hub verifies the id_token against Entra's JWKS, maps Entra <strong>group membership</strong> to LM RBAC + tenant scope, and (when required) <strong>hard-enforces MFA</strong> via the <code>amr</code> claim. Auth uses a <strong>client certificate</strong> (cert + key paths on the hub), not a client secret. Enabling this shows the <em>Sign in with Microsoft</em> button on the login page. <strong>Global Admin only.</strong> Environment overrides (<code>LM_OIDC_*</code>) win over these stored values.</p>
            <div class="flex flex-wrap items-center gap-6 mb-3">
                <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="oidc-enabled" class="w-4 h-4 text-green-600 rounded">Enable Entra ID SSO</label>
                <span class="text-[11px] text-slate-400">MFA is enforced in Entra via Conditional Access — see the SSO setup doc.</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Directory (tenant) ID</label><input id="oidc-tenant" type="text" placeholder="xxxxxxxx-xxxx-xxxx-…" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Application (client) ID</label><input id="oidc-client" type="text" placeholder="xxxxxxxx-xxxx-xxxx-…" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Redirect URI</label><input id="oidc-redirect" type="text" placeholder="https://your-hub/auth/oidc/callback" class="${inputCls}"></div>
                <div class="space-y-1 md:col-span-2">
                    <label class="${labelCls}">Additional redirect URIs <span class="text-slate-400 normal-case font-normal">(optional — one per edge-proxy hostname, comma/newline separated)</span></label>
                    <textarea id="oidc-redirect-uris" rows="2" placeholder="https://proxy-a.example.com/auth/oidc/callback&#10;https://proxy-b.example.com/auth/oidc/callback" class="${inputCls} font-mono text-xs"></textarea>
                    <span class="text-[11px] text-slate-400">Lets SSO return users to the edge proxy they started from. Each URI must ALSO be registered as a redirect URI in the Entra app registration.</span>
                </div>
                <div class="space-y-1">
                    <label class="${labelCls}">Allowed groups <span class="text-slate-400 normal-case font-normal">(object IDs, optional — comma/space separated; membership in ANY grants login)</span></label>
                    <div class="flex gap-2">
                        <input id="oidc-group" type="text" placeholder="Entra group object IDs — blank = any user in the tenant" class="${inputCls} font-mono text-xs flex-1">
                        <button type="button" onclick="loadOidcGroupPicker()" id="oidc-group-btn" class="whitespace-nowrap bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 px-3 rounded-md text-xs font-bold">＋ Pick from Entra</button>
                    </div>
                    <select id="oidc-group-select" onchange="onOidcGroupPick(this)" class="hidden w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></select>
                    <p id="oidc-group-msg" class="text-[11px] text-amber-600 hidden"></p>
                </div>
            </div>
            <div class="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3">
                <div class="flex items-center justify-between gap-2 flex-wrap">
                    <div class="text-xs text-slate-600"><span class="font-bold">Client certificate</span> <span id="oidc-cert-status" class="text-slate-400">checking…</span></div>
                    <button onclick="generateOidcCert()" id="oidc-gen-btn" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1.5 rounded-md text-xs font-bold">Generate certificate</button>
                </div>
                <p class="text-[11px] text-slate-400 mt-1">Auto-creates a self-signed keypair on the hub (in the hub's writable state directory by default — no root/<code>/etc</code> access needed). This is a client credential Entra matches by thumbprint — it is <em>not</em> a TLS/LE cert. Upload the generated certificate below to the Entra app registration → Certificates &amp; secrets → Certificates.</p>
                <div id="oidc-cert-output" class="hidden mt-2">
                    <div class="flex items-center justify-between gap-2 mb-1">
                        <div class="text-[11px] text-slate-500">Thumbprint (x5t): <code id="oidc-cert-thumb" class="text-slate-700"></code></div>
                        <button type="button" onclick="downloadOidcCert()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-[11px] font-bold">Download .cer</button>
                    </div>
                    <label class="text-[11px] text-slate-500"><span class="font-semibold">Download</span> the certificate above and upload the <em>file</em> to Entra → App registration → Certificates &amp; secrets → Certificates (Entra takes a file, not pasted text). This is the <em>public</em> cert — never upload the private key.</label>
                    <textarea id="oidc-cert-pem" readonly rows="6" class="w-full mt-1 bg-white border border-slate-300 rounded-md px-2 py-1 text-[11px] font-mono"></textarea>
                </div>
            </div>
            <div class="mt-4 flex items-center justify-between gap-3">
                <span id="oidc-save-msg" class="text-xs text-slate-400"></span>
            </div>
            <p class="text-[11px] text-slate-400 mt-2">The certificate + key are <em>auto-managed on the hub</em> (Generate above) — the WebUI never sees the key material. In Entra: register the app, add the redirect URI above, upload the generated certificate, and grant Graph <code>Group.Read.All</code> (app) for the group picker + the <code>GroupMember.Read.All</code> &gt;200-group fallback. Advanced: override the location with <code>LM_OIDC_DIR</code> / <code>LM_OIDC_CLIENT_KEY</code>.</p>
        </div>`;
    loadOidcConfig();
    // Auto-save on change (allowlist mapper — cert-management controls are
    // excluded; only the OIDC config fields auto-save).
    _attachAutoSave(content, _oidcSaveFnFor, 'oidcAutoSave');
}

async function loadOidcConfig() {
    try {
        const data = await apiJson('/setup/oidc-config');
        const cfg = data.config || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
        const chk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
        chk('oidc-enabled', cfg.enabled);
        set('oidc-tenant', cfg.tenant_id); set('oidc-client', cfg.client_id);
        set('oidc-redirect', cfg.redirect_uri); set('oidc-group', cfg.allowed_group);
        const extraUris = document.getElementById('oidc-redirect-uris');
        if (extraUris) extraUris.value = (cfg.redirect_uris || []).join('\n');
        const pill = document.getElementById('oidc-state-pill');
        if (pill) {
            pill.textContent = cfg.enabled ? 'ENABLED' : 'DISABLED';
            pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' +
                (cfg.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500');
        }
        // Cert status: whether the key/cert files exist on the hub + thumbprint.
        const st = data.cert_status || {};
        const cs = document.getElementById('oidc-cert-status');
        if (cs) {
            if (st.key_present && st.cert_present) {
                cs.innerHTML = `<span class="text-green-600 font-semibold">ready</span> — ${st.cert_path || ''} · x5t <code>${escapeHtml(st.thumbprint || '')}</code>`;
            } else if (st.key_present && !st.cert_present) {
                cs.innerHTML = `<span class="text-amber-600 font-semibold">key present, cert missing</span> — regenerate to produce both (${escapeHtml(st.cert_path || '')})`;
            } else {
                cs.innerHTML = `<span class="text-red-600 font-semibold">not found</span> at ${escapeHtml(st.key_path || '(hub default)')} — click Generate certificate`;
            }
        }
        const gen = document.getElementById('oidc-gen-btn');
        if (gen) gen.textContent = (st.key_present) ? 'Regenerate certificate' : 'Generate certificate';
    } catch (e) { console.error('loadOidcConfig failed', e); }
}

// Entra's "Upload certificate" takes a FILE (.cer/.pem/.crt), not pasted text —
// download the public cert as a file so it uploads cleanly (and there's no chance
// of grabbing the private key by mistake).
function downloadOidcCert() {
    const pem = (document.getElementById('oidc-cert-pem')?.value || '').trim();
    if (!pem || pem.indexOf('BEGIN CERTIFICATE') < 0) {
        showToast('Generate the certificate first', 'info');
        return;
    }
    const blob = new Blob([pem + '\n'], { type: 'application/x-x509-ca-cert' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'lm-oidc-cert.cer';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function generateOidcCert() {
    const btn = document.getElementById('oidc-gen-btn');
    const regenerating = btn && /regenerate/i.test(btn.textContent || '');
    if (regenerating && !window.confirm('Overwrite the existing OIDC private key? Any cert already uploaded to Entra will stop working until you upload the new one.')) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }
    try {
        const d = await apiJson('/setup/oidc-config/generate-cert', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ force: !!regenerating }),
        });
        // Reveal the cert to upload + thumbprint; refresh paths in the form.
        const out = document.getElementById('oidc-cert-output');
        if (out) out.classList.remove('hidden');
        const thumb = document.getElementById('oidc-cert-thumb');
        if (thumb) thumb.textContent = d.thumbprint || '';
        const pem = document.getElementById('oidc-cert-pem');
        if (pem) pem.value = d.cert_pem || '';
        const setV = (id, v) => { const el = document.getElementById(id); if (el && v) el.value = v; };
        setV('oidc-cert', d.cert_path); setV('oidc-key', d.key_path);
        showToast('Certificate generated — upload it to Entra (Certificates & secrets → Certificates).', 'success');
        loadOidcConfig();
    } catch (e) {
        showToast('Generate certificate failed: ' + (e.message || e), 'error');
    } finally {
        if (btn) { btn.disabled = false; loadOidcConfig(); }
    }
}

async function saveOidcConfig() {
    const btn = document.getElementById('oidc-save-btn');
    const msg = document.getElementById('oidc-save-msg');
    const v = id => (document.getElementById(id)?.value || '').trim();
    const config = {
        enabled: !!document.getElementById('oidc-enabled')?.checked,
        tenant_id: v('oidc-tenant'), client_id: v('oidc-client'),
        redirect_uri: v('oidc-redirect'), allowed_group: v('oidc-group'),
        redirect_uris: v('oidc-redirect-uris'),
        // cert/key paths are auto-managed (hub default dir); not editable here.
    };
    if (config.enabled && (!config.tenant_id || !config.client_id)) {
        if (typeof showToast === 'function') showToast('Tenant ID and Client ID are required to enable SSO', 'error');
        return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const res = await setupFetch('/setup/oidc-config', { method: 'POST', body: JSON.stringify({ config }) });
        const ok = res.ok;
        if (typeof showToast === 'function') showToast(ok ? 'SSO config saved' : 'Save failed', ok ? 'success' : 'error');
        if (msg) msg.textContent = ok ? 'Saved. The login page shows the Microsoft button when enabled.' : 'Save failed.';
        if (ok && typeof refreshOidcButton === 'function') refreshOidcButton();
        if (ok) loadOidcConfig();
    } catch (e) {
        console.error('saveOidcConfig failed', e);
        if (typeof showToast === 'function') showToast('Save failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
    }
}

// ── Setup → Test Data Feed (Global-Admin) ───────────────────────────────────
// Two ends of one feature, so one page sets up both — but a given hub uses only
// one of them. SOURCE (production): publish this hub's fleet as a scrubbed
// snapshot at /api/test-feed/snapshot. RECEIVER (dev/qa/lrb): pull that snapshot
// on an interval and replay it into THIS hub as synthetic spokes, so a branch
// hub gets production's shape with no duplicate lab hardware.
// The scrub runs on the SOURCE, so raw hostnames/addresses never leave it.
// Endpoints: /api/test-feed/{config,snapshot,status,start,stop,test}.
let _tfPoll = null;

function _renderSetupTestFeedTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
        <div class="${card} space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Test Data Feed ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <span id="tf-status" class="text-xs text-slate-400"></span>
            </div>
            <div class="rounded-md bg-amber-50 border border-amber-200 p-3 text-[11px] text-amber-800 leading-snug">
                Gives a test hub a realistic fleet without duplicating lab hardware — <b>Global-Admin only, every change is audit-logged</b>.
                One hub <b>publishes</b> a snapshot of its fleet; another <b>subscribes</b> and replays it as synthetic spokes.
                By default the copy is <b>verbatim</b> — real hostnames, addresses, MACs and serials — so a production issue reproduces against the identifiers you actually see in the field. Passwords, tokens and keys are <b>never</b> included either way.
                <b>Set up only one half on any given hub</b> — publish on production, subscribe on the branch hub.
            </div>

            <div class="border border-slate-200 rounded-md p-4 space-y-3">
                <div class="flex items-center justify-between">
                    <h4 class="text-xs font-bold text-slate-600 uppercase tracking-wider">This hub as a SOURCE</h4>
                    <span id="tf-src-badge" class="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500">off</span>
                </div>
                <p class="text-[11px] text-slate-500 leading-snug">
                    Publishing serves this hub's fleet to any client holding a valid API token.
                    Issue one under <b>Settings → API Tokens</b> and give it to the receiving hub; revoking it stops that feed immediately.
                </p>
                <label class="flex items-center gap-2 text-sm text-slate-700">
                    <input type="checkbox" id="tf-source-enabled" class="w-4 h-4 text-green-600 rounded" onchange="tfSaveSource()" title="Serve this hub's fleet snapshot to any client holding a valid API token. Toggling this saves immediately.">
                    Publish this hub's fleet as a test-data feed
                </label>
                <label class="flex items-center gap-2 text-sm text-slate-700">
                    <input type="checkbox" id="tf-anonymise" class="w-4 h-4 text-green-600 rounded" onchange="tfSaveSource()" title="Replace hostnames, addresses, MACs and serials with stable pseudonyms before publishing. Off = verbatim copy. Passwords/tokens/keys are never included either way.">
                    Anonymise before publishing — replace hostnames, addresses, MACs and serials
                </label>
                <p id="tf-mode-state" class="text-[11px] leading-snug"></p>
                <div id="tf-salt-row" class="flex flex-wrap items-center gap-2 hidden">
                    <button onclick="tfRegenSalt()" class="${btnSecCls} text-xs" title="Mint a new pseudonym salt, so every synthetic identity this hub publishes from now on is different and cannot be correlated with anything already sent">↻ Regenerate pseudonyms</button>
                    <span id="tf-salt-state" class="text-[11px] text-slate-400"></span>
                </div>
            </div>

            <div class="border border-slate-200 rounded-md p-4 space-y-3">
                <div class="flex items-center justify-between">
                    <h4 class="text-xs font-bold text-slate-600 uppercase tracking-wider">This hub as a RECEIVER</h4>
                    <span id="tf-rcv-badge" class="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500">stopped</span>
                </div>
                <p class="text-[11px] text-slate-500 leading-snug">
                    Pulls from the source on an interval and replays it into this hub as synthetic spokes, prefixed so you can bulk-delete them later from <b>Spokes &amp; Agents</b>.
                    The replayed fleet joins this hub's <b>shared tenant</b>, so it is visible to every tenant rather than walled into one.
                    Both tokens come from <b>one pair</b> issued on the SOURCE hub (Settings → API Tokens there). The access token expires after a few hours; with the refresh token the feed rotates it on its own instead of stopping overnight.
                    No onboarding PSK to supply — this hub mints an ephemeral one when the feed starts and revokes it on stop.
                    <br>The sync is <b>additive</b>: agents already installed here are untouched, and the production fleet appears alongside them.
                    <br><b>Name a real tenant</b> if the fleet should show in that tenant's Simulations views — a shared-tenant binding is visible in Spokes &amp; Agents but not there.
                    <span id="tf-tenant-state" class="block mt-1"></span>
                </p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div class="space-y-1">
                        <label class="${labelCls}">Source hub URL</label>
                        <input type="text" id="tf-source-url" placeholder="https://lm-hub.example.com" class="${inputCls}" title="Base URL of the SOURCE hub that is publishing the feed (the hub where you enabled 'Publish this hub's fleet').">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Access token (Bearer) <span id="tf-token-set" class="normal-case font-normal text-slate-400"></span></label>
                        <input type="password" id="tf-token" placeholder="paste to set / change" class="${inputCls}" title="Bearer access token issued on the SOURCE hub (Settings → API Tokens there). Sent to authenticate each snapshot pull. Leave blank to keep the stored value.">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Refresh token <span id="tf-refresh-set" class="normal-case font-normal text-slate-400"></span></label>
                        <input type="password" id="tf-refresh" placeholder="paste to set / change" class="${inputCls}" title="Refresh token from the same pair on the SOURCE hub. Lets the feed rotate the short-lived access token on its own instead of stopping when it expires. Leave blank to keep the stored value.">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Tenant <span class="normal-case font-normal text-slate-400">· blank = shared</span></label>
                        <input type="text" id="tf-tenant" placeholder="leave blank for the shared tenant" class="${inputCls}" title="Name a real tenant to make the replayed fleet show in that tenant's Simulations views. Blank binds it to the shared tenant (visible in Spokes & Agents to every tenant). In 'preserve source tenants' mode this is only the fallback for spokes whose source tenant has no local match.">
                    </div>
                    <div class="space-y-1 md:col-span-2">
                        <label class="flex items-center gap-2 text-xs text-slate-600 cursor-pointer" title="Replay each synthetic spoke into the LOCAL tenant matching its SOURCE tenant, so a multi-tenant production fleet keeps its tenant layout here instead of collapsing into one. A source tenant with no local match (and any unattributed spoke) falls back to the Tenant field above / the shared tenant. Only takes effect when the source is publishing verbatim (an anonymised source omits per-spoke tenant).">
                            <input type="checkbox" id="tf-preserve" class="rounded border-slate-300">
                            <span>Preserve source tenants <span class="text-slate-400 font-normal">— receive all tenants into their matching local tenants</span></span>
                        </label>
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Spoke id prefix</label>
                        <input type="text" id="tf-prefix" value="feed-" class="${inputCls}" title="Prefix added to every synthetic spoke id so you can recognise and bulk-delete the replayed fleet later from Spokes & Agents.">
                    </div>
                    <div class="space-y-1">
                        <label class="${labelCls}">Poll interval (seconds)</label>
                        <input type="number" id="tf-interval" min="15" step="5" value="60" class="${inputCls}" title="How often (seconds, minimum 15) the receiver pulls a fresh snapshot from the source and re-applies it.">
                    </div>
                </div>
                <div class="flex flex-wrap items-center gap-2 pt-1">
                    <button onclick="tfTestSource()" class="${btnSecCls} text-xs" title="Fetch one snapshot from the source and show what it would replay, without starting the feed or connecting any synthetic spoke">Test source</button>
                    <button onclick="tfStart()" id="tf-start" class="${btnCls}" title="Start pulling from the source and replaying it into this hub as synthetic spokes">Start feed</button>
                    <button onclick="tfStop()" id="tf-stop" class="bg-red-100 hover:bg-red-200 text-red-700 px-4 py-2 rounded-md text-sm font-bold border border-red-200" title="Stop the feeder; the synthetic spokes go offline but stay registered until you delete them">Stop feed</button>
                    <button onclick="tfSaveReceiver()" class="${btnSecCls} ml-auto" title="Save the source URL, credentials and polling settings without starting the feed">Save</button>
                </div>
                <div id="tf-output" class="hidden">
                    <pre id="tf-output-body" class="bg-slate-900 text-slate-100 text-[11px] font-mono rounded-md p-3 overflow-x-auto max-h-64"></pre>
                </div>
            </div>
        </div>`;
    tfLoad();
    if (_tfPoll) clearInterval(_tfPoll);
    _tfPoll = setInterval(tfRefreshStatus, 5000);
}

// status → badge class, local to this view (LM has no central status registry).
function _tfBadge(el, text, tone) {
    if (!el) return;
    const tones = {
        on:   'bg-[#01A982]/10 text-[#01A982] border border-[#01A982]',
        off:  'bg-slate-100 text-slate-500',
        warn: 'bg-amber-100 text-amber-700',
        err:  'bg-red-100 text-red-700',
    };
    el.className = `text-[11px] px-2 py-0.5 rounded-full ${tones[tone] || tones.off}`;
    el.textContent = text;
}

async function tfLoad() {
    try {
        const r = await setupFetch('/api/test-feed/config');
        const c = await r.json().catch(() => ({}));
        if (!r.ok) return;
        const set = (id, v) => { const e = document.getElementById(id); if (e && v != null) e.value = v; };
        const chk = document.getElementById('tf-source-enabled');
        if (chk) chk.checked = !!c.source_enabled;
        set('tf-source-url', c.receiver_source_url || '');
        set('tf-tenant', c.receiver_tenant || '');
        set('tf-prefix', c.receiver_prefix || 'feed-');
        set('tf-interval', c.receiver_interval || 60);
        // Secrets come back as booleans, never values — say whether one is stored
        // rather than rendering a fake masked value the operator might trust.
        const tok = document.getElementById('tf-token-set');
        if (tok) tok.textContent = c.receiver_token ? '· stored' : '· not set';
        const rt = document.getElementById('tf-refresh-set');
        if (rt) rt.textContent = c.receiver_refresh_token ? '· stored' : '· not set';
        const anon = document.getElementById('tf-anonymise');
        if (anon) anon.checked = !!c.source_anonymise;
        const pres = document.getElementById('tf-preserve');
        if (pres) pres.checked = !!c.receiver_preserve_tenants;
        const saltRow = document.getElementById('tf-salt-row');
        if (saltRow) saltRow.classList.toggle('hidden', !c.source_anonymise);
        const salt = document.getElementById('tf-salt-state');
        if (salt) salt.textContent = c.source_salt ? 'pseudonyms active' : 'minted on first publish';
        // Say plainly which mode is live. "Verbatim" is the default and the
        // whole point, but it is also the mode where real identifiers leave
        // this hub, so it should never be something you have to infer.
        const mode = document.getElementById('tf-mode-state');
        if (mode) {
            if (c.source_anonymise) {
                mode.className = 'text-[11px] leading-snug text-slate-500';
                mode.textContent = 'Anonymised: identifiers are replaced with stable stand-ins before anything leaves this hub.';
            } else {
                mode.className = 'text-[11px] leading-snug text-amber-700 font-semibold';
                mode.textContent = 'Verbatim: real hostnames, addresses, MACs and serials leave this hub as-is. Secrets are still never included.';
            }
        }
        // The landing tenant is derived, not chosen. Say which one it is — and
        // say plainly when there ISN'T one, because Start will refuse and the
        // reason is not something the operator can guess from this page.
        const ten = document.getElementById('tf-tenant-state');
        if (ten) {
            if (c.receiver_preserve_tenants) {
                const fb = c.receiver_tenant || (c.shared_tenant ? `shared "${c.shared_tenant}"` : null);
                if (fb) {
                    ten.className = 'block mt-1 text-[#01A982]';
                    ten.textContent = `Preserving source tenants: each spoke lands in its matching local tenant; unmatched spokes fall back to ${fb}.`;
                } else {
                    ten.className = 'block mt-1 text-red-600 font-semibold';
                    ten.textContent = 'Preserving source tenants, but there is no fallback — name a tenant above or mark one shared in Setup → Tenants for spokes with no local match.';
                }
            } else if (c.shared_tenant) {
                ten.className = 'block mt-1 text-[#01A982]';
                ten.textContent = c.receiver_tenant
                    ? `Fleet will land in tenant "${c.receiver_tenant}".`
                    : `Fleet will land in shared tenant "${c.shared_tenant}" — visible in Spokes & Agents, but name a real tenant above to see it in Simulations.`;
            } else {
                ten.className = 'block mt-1 text-red-600 font-semibold';
                ten.textContent = c.receiver_tenant
                    ? `Fleet will land in tenant "${c.receiver_tenant}".`
                    : 'No tenant named above and none marked shared — name one, or mark a tenant shared in Setup → Tenants.';
            }
        }
        _tfBadge(document.getElementById('tf-src-badge'),
                 c.source_enabled ? 'publishing' : 'off', c.source_enabled ? 'on' : 'off');
    } catch (e) { console.error('tfLoad failed', e); }
    tfRefreshStatus();
}

async function tfRefreshStatus() {
    if (!document.getElementById('tf-rcv-badge')) {
        if (_tfPoll) { clearInterval(_tfPoll); _tfPoll = null; }
        return;
    }
    try {
        const r = await setupFetch('/api/test-feed/status');
        const d = await r.json().catch(() => ({}));
        if (!r.ok) return;
        const badge = document.getElementById('tf-rcv-badge');
        if (d.running) {
            const mins = Math.floor((d.uptime_s || 0) / 60);
            _tfBadge(badge, `running · ${mins}m`, 'on');
        } else if (d.exit_code) {
            _tfBadge(badge, `stopped · exit ${d.exit_code}`, 'err');
        } else {
            _tfBadge(badge, 'stopped', 'off');
        }
        if (d.last_output) {
            const wrap = document.getElementById('tf-output');
            const body = document.getElementById('tf-output-body');
            if (wrap && body) { wrap.classList.remove('hidden'); body.textContent = d.last_output; }
        }
    } catch (e) { /* transient; the next tick retries */ }
}

async function tfSaveSource() {
    const enabled = !!document.getElementById('tf-source-enabled')?.checked;
    const anonymise = !!document.getElementById('tf-anonymise')?.checked;
    // Confirm on the combination that actually matters: publishing verbatim is
    // what sends real identifiers off this hub.
    if (enabled && !anonymise && !confirm('Publish this hub\'s fleet VERBATIM?\n\nAny client with a valid API token will be able to read every client and VM this hub knows about, with REAL hostnames, addresses, MACs and serials. Passwords, tokens and keys are never included.\n\nTick "Anonymise before publishing" first if you want identifiers replaced.')) {
        const c = document.getElementById('tf-source-enabled'); if (c) c.checked = false;
        return;
    }
    await _tfPost('/api/test-feed/config', { source_enabled: enabled, source_anonymise: anonymise },
                  enabled ? 'Publishing enabled.' : 'Publishing disabled.');
    tfLoad();
}

async function tfRegenSalt() {
    if (!confirm('Regenerate pseudonyms?\n\nEvery synthetic identity published from now on changes. A receiver already running will see its whole roster replaced by new names on the next poll.')) return;
    await _tfPost('/api/test-feed/config', { regenerate_salt: true }, 'Pseudonyms regenerated.');
    tfLoad();
}

async function tfSaveReceiver() {
    const body = {
        receiver_source_url: document.getElementById('tf-source-url')?.value?.trim() || '',
        receiver_tenant: document.getElementById('tf-tenant')?.value?.trim() || '',
        receiver_prefix: document.getElementById('tf-prefix')?.value?.trim() || 'feed-',
        receiver_interval: Number(document.getElementById('tf-interval')?.value) || 60,
        receiver_token: document.getElementById('tf-token')?.value?.trim() || '',
        receiver_refresh_token: document.getElementById('tf-refresh')?.value?.trim() || '',
        receiver_preserve_tenants: !!document.getElementById('tf-preserve')?.checked,
    };
    const ok = await _tfPost('/api/test-feed/config', body, 'Saved.');
    if (ok) {
        // Clear the secret inputs once stored — leaving a token sitting in a
        // form field is how it ends up in a screenshot.
        ['tf-token', 'tf-refresh'].forEach(id => { const e = document.getElementById(id); if (e) e.value = ''; });
        tfLoad();
    }
}

async function tfTestSource() {
    if (typeof showToast === 'function') showToast('Contacting source…', 'info');
    try {
        const r = await setupFetch('/api/test-feed/test', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { showToast('Source test failed: ' + (d.detail || r.status), 'error'); return; }
        showToast(`Source OK — ${d.spoke_count} spoke(s), ${d.client_count} client(s).`, 'success');
        const wrap = document.getElementById('tf-output');
        const bodyEl = document.getElementById('tf-output-body');
        if (wrap && bodyEl) {
            wrap.classList.remove('hidden');
            bodyEl.textContent = JSON.stringify(d.sample_clients || [], null, 2);
        }
    } catch (e) { if (typeof showToast === 'function') showToast('Source test failed: ' + (e.message || e), 'error'); }
}

async function tfStart() {
    if (typeof showToast === 'function') showToast('Starting feed…', 'info');
    if (await _tfPost('/api/test-feed/start', {}, 'Feed started.')) tfRefreshStatus();
}

async function tfStop() {
    if (await _tfPost('/api/test-feed/stop', {}, 'Feed stopped.')) tfRefreshStatus();
}

async function _tfPost(url, body, okMsg) {
    try {
        const r = await setupFetch(url, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body || {}),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
            if (typeof showToast === 'function') showToast('Failed: ' + (d.detail || r.status), 'error');
            return false;
        }
        if (okMsg && typeof showToast === 'function') showToast(okMsg, 'success');
        return true;
    } catch (e) {
        if (typeof showToast === 'function') showToast('Failed: ' + (e.message || e), 'error');
        return false;
    }
}

const SETUP_TILES = {
    'Spokes & Agents':  _renderSetupSpokesTile,
    'Module Management': _renderSetupModuleMgmtTile,
    'Directory (LDAP)': _renderSetupLdapConfigTile,
    'Tenant Config':    _renderSetupTenantTile,
    'User Access':      _renderSetupUserAccessTile,
    'Simulations':      _renderSetupSimulationsTile,
    'Remote Console':   _renderSetupRemoteConsoleTile,
    'Test Data Feed':   _renderSetupTestFeedTile,
};
