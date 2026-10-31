// module-management.js — Network device / TrueNAS modals, multi-instance Setup tabs, module management.
// Split out of main.js (docs/webui-react-lite-plan.md). A classic script:
// it shares globals with main.js and the other js/*.js files and is loaded
// in order by index.html, so code that runs at load time may only use what
// earlier files define. Functions may call anything once the page is up.

// ─── Network Devices: add/edit modal (mirrors the firewall modal) ───────────
// Fields: name, object_type (AOS/CX/EX/Gateway), transport (ssh/rest/snmp/auto),
// address, port, username, password, enable_secret, api_token, snmp_community,
// spoke (filtered to nw spokes). Creds are stored in runtime system.json only.
function showAddNwDeviceModal(prefillDevice) {
    const modal = document.createElement('div');
    modal.id = 'nw-device-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50 sticky top-0">
                <h3 class="text-lg font-bold text-[#263040]" id="nw-modal-title">Add Network Device</h3>
                <button onclick="closeNwDeviceModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Device Name</label><input type="text" id="nw-name" placeholder="e.g. Core Switch" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Object Type</label><select id="nw-object-type" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="aos_switch">AOS Switch</option><option value="cx_switch">CX Switch</option><option value="ex_switch">EX Switch</option><option value="gateway">Gateway</option></select></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Transport</label><select id="nw-transport" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="auto">Auto</option><option value="ssh">SSH/CLI</option><option value="rest">REST API</option><option value="snmp">SNMP</option></select></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label><select id="nw-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading spokes...</option></select></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Port</label><input type="text" id="nw-port" placeholder="22 / 443" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Address / Host IP <span class="text-red-500">*</span></label><input type="text" id="nw-address" placeholder="10.0.0.1" required class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Username</label><input type="text" id="nw-username" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Password</label><input type="password" id="nw-password" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Enable Secret</label><input type="password" id="nw-enable-secret" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Token</label><input type="password" id="nw-api-token" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">SNMP Community</label><input type="text" id="nw-snmp-community" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                ${_vaultCredSelectHtml('nw-vaultcred')}
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Auto-Poll Interval</label>
                    <select id="nw-poll-interval" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="inherit" selected>Inherit module default</option>
                        <option value="0">Off (manual Poll Now only)</option>
                        <option value="60">Every 1 minute</option>
                        <option value="300">Every 5 minutes</option>
                        <option value="900">Every 15 minutes</option>
                        <option value="1800">Every 30 minutes</option>
                        <option value="3600">Every hour</option>
                        <option value="21600">Every 6 hours</option>
                        <option value="86400">Every day</option>
                    </select>
                    <p class="text-[11px] text-slate-400">The nw spoke polls this device on its own cycle (probe + info + ARP/MAC/interfaces), warms the hub cache so sub-views load instantly, and syncs the device + interfaces into NetBox. <b>This device setting overrides the module default</b> (set under Setup → Module Management). Inherit uses the module default (6 hours if unset).</p>
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 sticky bottom-0">
                <button onclick="closeNwDeviceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveNwDevice()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Device</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('nw-spoke');
        if (selector) {
            const nwSpokes = spokes.filter(s =>
                s.module_type === 'nw' || /^(nw|network)/.test(s.spoke_id)
            );
            selector.innerHTML = nwSpokes.length > 0
                ? '<option value="">— select spoke —</option>' + nwSpokes.map(s => `<option value="${s.spoke_id}" title="${escapeHtml(s.spoke_id)}">${escapeHtml(_spokeName(s))}</option>`).join('')
                : '<option value="">No network spokes found</option>';
        }
    });
    _fillVaultCredSelect('nw-vaultcred', prefillDevice && prefillDevice.vault_credential);
}

async function editNwDevice(id) {
    const devices = _nwDevicesCache.length ? _nwDevicesCache : await loadNwDevices();
    const d = devices.find(x => x.id === id);
    if (!d) return;

    showAddNwDeviceModal(d);
    document.getElementById('nw-modal-title').textContent = 'Edit Network Device';
    document.getElementById('nw-name').value = d.name || '';
    document.getElementById('nw-object-type').value = d.object_type || 'aos_switch';
    document.getElementById('nw-transport').value = d.transport || 'auto';
    document.getElementById('nw-address').value = d.address || '';
    document.getElementById('nw-port').value = d.port || '';
    document.getElementById('nw-username').value = d.username || '';
    document.getElementById('nw-password').value = d.password || '';
    document.getElementById('nw-enable-secret').value = d.enable_secret || '';
    document.getElementById('nw-api-token').value = d.api_token || '';
    document.getElementById('nw-snmp-community').value = d.snmp_community || '';
    // Unset → "Inherit" (uses module default); a stored number (incl 0=Off) wins.
    document.getElementById('nw-poll-interval').value =
        (d.poll_interval === undefined || d.poll_interval === null || d.poll_interval === '')
            ? 'inherit' : String(d.poll_interval);

    setTimeout(() => {
        const selector = document.getElementById('nw-spoke');
        if (selector) selector.value = d.spoke_id || '';
    }, 100);

    document.getElementById('nw-device-modal').dataset.deviceId = id;
}

// Strict IPv4 validation for a network device's management address: exactly
// four dot-separated 0-255 octets, no leading-zero octets. Mirrors the backend
// validate_nw_address (ipaddress.IPv4Address) so the client and server agree.
function isValidIPv4(s) {
    const parts = String(s == null ? '' : s).trim().split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d{1,3}$/.test(p) &&
                            !(p.length > 1 && p[0] === '0') &&
                            parseInt(p, 10) <= 255);
}

async function saveNwDevice() {
    const modal = document.getElementById('nw-device-modal');
    const id = modal.dataset.deviceId;
    const config = {
        name: document.getElementById('nw-name').value.trim(),
        object_type: document.getElementById('nw-object-type').value,
        transport: document.getElementById('nw-transport').value,
        spoke_id: document.getElementById('nw-spoke').value,
        address: document.getElementById('nw-address').value.trim(),
        port: parseInt(document.getElementById('nw-port').value, 10) || null,
        username: document.getElementById('nw-username').value,
        password: document.getElementById('nw-password').value,
        enable_secret: document.getElementById('nw-enable-secret').value,
        api_token: document.getElementById('nw-api-token').value,
        snmp_community: document.getElementById('nw-snmp-community').value,
        // 'inherit' → null (use the module default); a number (incl 0=Off) overrides.
        poll_interval: (() => {
            const pv = document.getElementById('nw-poll-interval').value;
            return (pv === 'inherit' || pv === '') ? null : (parseInt(pv, 10) || 0);
        })(),
    };
    const _vc = _collectVaultCred('nw-vaultcred');
    if (_vc !== undefined) config.vault_credential = _vc;
    if (!config.name || !config.object_type) {
        showToast('Device name and object type are required.', 'error');
        return;
    }
    if (!config.address) {
        showToast('Management IP address is required.', 'error');
        return;
    }
    if (!isValidIPv4(config.address)) {
        showToast(`'${config.address}' is not a valid IPv4 address.`, 'error');
        return;
    }

    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `/setup/nw-devices/${id}` : '/setup/nw-devices';
        const payload = id ? { config } : { device: config };
        const response = await setupFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            showToast(`Network device ${id ? 'updated' : 'added'} successfully!`, 'success');
            closeNwDeviceModal();
            loadNwDevicesList();
        } else {
            const err = await response.json().catch(() => ({}));
            showToast('Failed to save network device: ' + (err.detail || response.status), 'error');
        }
    } catch (err) {
        showToast('Error saving network device: ' + err.message, 'error');
    }
}

function closeNwDeviceModal() {
    const modal = document.getElementById('nw-device-modal');
    if (modal) modal.remove();
}

// ─── TrueNAS Appliances: list + add/edit modal + poll config ───────────────
// Backing routes: /setup/truenas-appliances (GET/POST), /setup/truenas-appliances/
// {id} (PUT/DELETE), /setup/truenas-poll-config (GET/POST). Mirrors the Network
// Devices setup pattern. Fields: name, host, api_key (sentinel-merged — leave
// blank to keep the stored key), verify_ssl, auth_mechanism, poll_interval,
// spoke_id (storage spokes), tenant_id. Creds persist in global_config only.
let _truenasAppliancesCache = [];
async function loadTruenasAppliances() {
    try {
        const data = await apiJson('/setup/truenas-appliances');
        _truenasAppliancesCache = Array.isArray(data.truenas_appliances) ? data.truenas_appliances : [];
        return _truenasAppliancesCache;
    } catch (e) {
        _truenasAppliancesCache = [];
        return [];
    }
}
async function loadTruenasAppliancesList() {
    const listEl = document.getElementById('truenas-appliances-list');
    if (!listEl) return;
    try {
        const apps = await loadTruenasAppliances();
        if (!apps.length) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No TrueNAS appliances configured.</p>';
            return;
        }
        listEl.innerHTML = apps.map(a => {
            const sub = [
                a.host || '',
                a.api_key_set ? 'key set' : 'no key',
                a.verify_ssl === false ? 'verify SSL off' : 'verify SSL on',
            ].filter(Boolean).join(' · ');
            return `<div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${escapeHtml(a.name || a.id)}</span><span class="ml-2 text-xs text-slate-400">${escapeHtml(sub)}</span></div>
                <div class="flex gap-2">
                    <button onclick="editTruenasAppliance('${escapeHtml(a.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium" title="Edit appliance settings">Edit</button>
                    <button onclick="deleteTruenasAppliance('${escapeHtml(a.id)}')" class="text-xs text-red-400 hover:text-red-600 font-medium" title="Remove appliance from Lab Manager">Delete</button>
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading appliances: ${e.message}</p>`;
    }
}
async function deleteTruenasAppliance(id) {
    if (!await showConfirmToast(`Delete TrueNAS appliance ${id}?`)) return;
    try {
        await apiJson(`/setup/truenas-appliances/${id}`, { method: 'DELETE' });
        loadTruenasAppliancesList();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}
function showAddTruenasApplianceModal() {
    const modal = document.createElement('div');
    modal.id = 'truenas-appliance-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50 sticky top-0">
                <h3 class="text-lg font-bold text-[#263040]" id="truenas-modal-title">Add TrueNAS Appliance</h3>
                <button onclick="closeTruenasApplianceModal()" class="text-slate-400 hover:text-slate-600 transition-colors" title="Close modal"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Name</label><input type="text" id="truenas-name" placeholder="e.g. nas-01" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="TrueNAS appliance display name"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Host / IP</label><input type="text" id="truenas-host" placeholder="10.0.0.50" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="TrueNAS host IP address or FQDN"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Key</label><input type="password" id="truenas-api-key" placeholder="Create in TrueNAS → Settings → API Keys" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="TrueNAS API key token for WebSocket JSON-RPC auth"><p class="text-[11px] text-slate-400">Leave blank on edit to keep the stored key (sentinel-merge). The spoke forces <code>wss://</code>; keys auto-revoke over plain <code>ws://</code>.</p></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Verify SSL</label><select id="truenas-verify-ssl" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="TLS certificate verification mode"><option value="true">On (trusted CA)</option><option value="false" selected>Off (self-signed)</option></select></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Auth Mechanism</label><select id="truenas-auth-mech" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="Authentication handshake protocol"><option value="auto" selected>Auto (SCRAM→PLAIN)</option><option value="PLAIN">PLAIN (Core / 24.x)</option><option value="SCRAM">SCRAM-SHA-512 (26+)</option></select></div>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Storage Spoke</label><select id="truenas-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="Target storage spoke managing this appliance"><option value="">Loading spokes...</option></select></div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Auto-Poll Interval</label>
                    <select id="truenas-poll-interval" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" title="Per-appliance polling cadence">
                        <option value="inherit" selected>Inherit module default</option>
                        <option value="0">Off (manual Poll Now only)</option>
                        <option value="60">Every 1 minute</option>
                        <option value="300">Every 5 minutes</option>
                        <option value="900">Every 15 minutes</option>
                        <option value="1800">Every 30 minutes</option>
                        <option value="3600">Every hour</option>
                        <option value="21600">Every 6 hours</option>
                        <option value="86400">Every day</option>
                    </select>
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 sticky bottom-0">
                <button onclick="closeTruenasApplianceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors" title="Cancel and close dialog">Cancel</button>
                <button onclick="saveTruenasAppliance()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm" title="Save appliance credentials and settings">Save Appliance</button>
            </div>
        </div>`;
    document.body.appendChild(modal);

    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('truenas-spoke');
        if (selector) {
            const tnSpokes = spokes.filter(s =>
                s.module_type === 'storage' || /^truenas/.test(s.spoke_id));
            selector.innerHTML = tnSpokes.length > 0
                ? '<option value="">— select spoke —</option>' + tnSpokes.map(s => `<option value="${s.spoke_id}" title="${escapeHtml(s.spoke_id)}">${escapeHtml(_spokeName(s))}</option>`).join('')
                : '<option value="">No storage spokes found</option>';
        }
    });
}
async function editTruenasAppliance(id) {
    const apps = _truenasAppliancesCache.length ? _truenasAppliancesCache : await loadTruenasAppliances();
    const a = apps.find(x => x.id === id);
    if (!a) return;
    showAddTruenasApplianceModal();
    document.getElementById('truenas-modal-title').textContent = 'Edit TrueNAS Appliance';
    document.getElementById('truenas-name').value = a.name || '';
    document.getElementById('truenas-host').value = a.host || '';
    // api_key left blank → route sentinel-merges the stored key.
    document.getElementById('truenas-api-key').value = '';
    document.getElementById('truenas-verify-ssl').value = (a.verify_ssl === false) ? 'false' : 'true';
    document.getElementById('truenas-auth-mech').value = a.auth_mechanism || 'auto';
    document.getElementById('truenas-poll-interval').value =
        (a.poll_interval === undefined || a.poll_interval === null || a.poll_interval === '')
            ? 'inherit' : String(a.poll_interval);
    setTimeout(() => {
        const selector = document.getElementById('truenas-spoke');
        if (selector) selector.value = a.spoke_id || '';
    }, 100);
    document.getElementById('truenas-appliance-modal').dataset.applianceId = id;
}
async function saveTruenasAppliance() {
    const modal = document.getElementById('truenas-appliance-modal');
    const id = modal.dataset.applianceId;
    const verifyRaw = document.getElementById('truenas-verify-ssl').value;
    const config = {
        name: document.getElementById('truenas-name').value.trim(),
        host: document.getElementById('truenas-host').value.trim(),
        verify_ssl: verifyRaw === 'true',
        auth_mechanism: document.getElementById('truenas-auth-mech').value,
        spoke_id: document.getElementById('truenas-spoke').value,
        poll_interval: (() => {
            const pv = document.getElementById('truenas-poll-interval').value;
            return (pv === 'inherit' || pv === '') ? null : (parseInt(pv, 10) || 0);
        })(),
    };
    const key = document.getElementById('truenas-api-key').value;
    if (key) config.api_key = key;   // absent → route keeps the stored key
    if (!config.name || !config.host) {
        showToast('Name and host are required.', 'error');
        return;
    }
    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `/setup/truenas-appliances/${id}` : '/setup/truenas-appliances';
        const payload = id ? { config } : { appliance: config };
        const response = await setupFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (response.ok) {
            showToast(`TrueNAS appliance ${id ? 'updated' : 'added'} successfully!`, 'success');
            closeTruenasApplianceModal();
            loadTruenasAppliancesList();
        } else {
            const err = await response.json().catch(() => ({}));
            showToast('Failed to save appliance: ' + (err.detail || response.status), 'error');
        }
    } catch (err) {
        showToast('Error saving appliance: ' + err.message, 'error');
    }
}
function closeTruenasApplianceModal() {
    const modal = document.getElementById('truenas-appliance-modal');
    if (modal) modal.remove();
}
async function loadTruenasPollConfig() {
    const sel = document.getElementById('truenas-module-poll-default');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/truenas-poll-config');
        if (!r.ok) return;
        const d = await r.json();
        sel.value = (d.default_poll_interval === null || d.default_poll_interval === undefined)
            ? '' : String(d.default_poll_interval);
    } catch (e) { /* leave built-in default selected */ }
}
async function saveTruenasPollConfig(btn) {
    const sel = document.getElementById('truenas-module-poll-default');
    if (!sel) return;
    const raw = sel.value;
    const body = { default_poll_interval: raw === '' ? null : (parseInt(raw, 10) || 0) };
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const r = await setupFetch('/setup/truenas-poll-config', {
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

// ─── Multi-instance Setup tabs (NAC / IPAM / LDAP / DNS / DHCP) ───────────────
// Mirrors the Firewalls Setup pattern: each product renders a list of bound
// connection instances with per-row Edit/Delete and an "+ Add Instance" modal.
// One shared, config-driven implementation backs all five products.

const INSTANCE_PRODUCTS = {
    nac: {
        title: 'NAC / ClearPass Instance',
        endpoint: '/setup/nac-instances',
        listId: 'nac-instances-list',
        moduleType: 'nac',
        // A bare, not-yet-role-loaded base agent (module_type 'agent') is also
        // selectable — binding an instance to one auto-loads the matching
        // coordinator role as part of the save, instead of requiring a
        // separate manual "Load Role" step first (see routes/role_pool.py).
        alsoBareAgent: true,
        // LOAD_ROLE/UNLOAD_ROLE role name (routes/role_pool.py's PRODUCT_ROLE) —
        // used to derive a sub-spoke's base agent id for the failover pool
        // checkboxes (spokeX-cppm -> spokeX).
        roleName: 'cppm',
        vaultPicker: true,
        rowSummary: inst => `${inst.host || '—'}`,
        fields: [
            { id: 'host', label: 'CPPM Host', placeholder: 'https://clearpass.example.com' },
            { id: 'client_id', label: 'OAuth2 Client ID', placeholder: 'API client ID' },
            { id: 'client_secret', label: 'OAuth2 Client Secret', type: 'password', placeholder: 'Client secret' },
            { id: 'user', label: 'Fallback Username', placeholder: 'admin' },
            { id: 'password', label: 'Fallback Password', type: 'password', placeholder: 'Password' },
            { id: 'verify_ssl', label: 'TLS Certificate', type: 'select', options: [['true', 'Verify cert (secure)'], ['false', 'Allow untrusted / self-signed cert']] },
        ],
    },
    ipam: {
        title: 'IPAM / NetBox Instance',
        endpoint: '/setup/ipam-instances',
        listId: 'ipam-instances-list',
        moduleType: 'ipam',
        alsoBareAgent: true,
        roleName: 'netbox',
        vaultPicker: true,
        rowSummary: inst => `${inst.url || '—'}`,
        fields: [
            { id: 'url', label: 'NetBox URL', placeholder: 'http://netbox.example.com' },
            { id: 'api_token', label: 'API Token', type: 'password', placeholder: 'API token' },
            { id: 'verify_ssl', label: 'TLS Certificate', type: 'select', options: [['1', 'Verify cert (secure)'], ['0', 'Ignore cert (self-signed / internal CA)']] },
        ],
    },
    ldap: {
        title: 'Directory / LDAP Instance',
        endpoint: '/setup/ldap-instances',
        listId: 'ldap-instances-list',
        moduleType: 'directory',
        alsoBareAgent: true,
        roleName: 'ldap',
        rowSummary: inst => `${inst.server_url || '—'}`,
        fields: [
            { id: 'server_url', label: 'Server URL', placeholder: 'ldap://localhost:389' },
            { id: 'base_dn', label: 'Base DN', placeholder: 'dc=example,dc=org' },
            { id: 'admin_dn', label: 'Admin DN', placeholder: 'cn=admin,dc=example,dc=org' },
            { id: 'admin_pw', label: 'Admin Password', type: 'password', placeholder: 'Password' },
        ],
    },
    dns: {
        title: 'DNS Server Worker (external/manual)',
        endpoint: '/setup/dns-instances',
        listId: 'dns-instances-list',
        moduleType: 'dns',
        rowSummary: inst => `${inst.host || '—'}`,
        fields: [
            { id: 'member_id', label: 'Worker ID (advanced)', placeholder: 'dns-a' },
            { id: 'host', label: 'DNS Server Host / IP', placeholder: '10.0.0.1' },
            { id: 'worker_secret', label: 'Worker Secret (external workers only)', type: 'password', placeholder: 'Not needed for DNS Server roles installed by LM' },
        ],
    },
    dhcp: {
        title: 'DHCP / Kea Instance',
        endpoint: '/setup/dhcp-instances',
        listId: 'dhcp-instances-list',
        moduleType: 'dhcp',
        rowSummary: inst => `${inst.host || '—'}`,
        fields: [
            { id: 'host', label: 'DHCP Server Host / IP', placeholder: '10.0.0.1' },
        ],
    },
    nwscan: {
        title: 'Network Scan Credential',
        endpoint: '/setup/nw-scan-credentials',
        listId: 'nwscan-instances-list',
        moduleType: 'nw',
        vaultPicker: true,
        rowSummary: inst => `${inst.name || '—'}${inst.username ? ' · ' + inst.username : ''}`,
        fields: [
            { id: 'username', label: 'SSH Username', placeholder: 'admin' },
            { id: 'password', label: 'SSH Password', type: 'password', placeholder: 'Password' },
            { id: 'enable_secret', label: 'Enable Secret', type: 'password', placeholder: 'Optional (AOS-S enable)' },
            { id: 'snmp_community', label: 'SNMP Community', placeholder: 'public' },
        ],
    },
};

// DEVICE_TYPES — the unified registry backing Setup → Module Management. It
// extends INSTANCE_PRODUCTS with the two bespoke device families (firewalls
// and network devices) so every managed module shares one declarative shape:
//   endpoint     — REST collection (GET lists, POST creates, DELETE/{id}).
//   responseKey   — the list key in the GET response (firewalls / nw_devices /
//                   instances).
//   moduleType   — the spoke module_type the device attaches to (used to
//                   filter the Associated Spoke dropdown).
//   spokeFilter   — fallback predicate for spokes whose module_type is absent.
//   payloadKey   — the POST body key ({payloadKey: config}); PUT is uniformly
//                   {config} for every family.
//   badgeLabel   — short label shown in the unified device table.
//   rowSummary   — one-line host/endpoint summary for the table row.
//   fields        — ordered form fields; type 'text'|'password'|'select'
//                   (selects carry options as [value,label] pairs). 'port' is
//                   coerced to an int on save (per-family default via `default`).
// The five instance families reuse INSTANCE_PRODUCTS verbatim (same fields /
// endpoints) so the per-module Add Instance modal and the unified page stay in
// sync; only the device-type-specific keys are added here.
const DEVICE_TYPES = {
    firewall: {
        title: 'Firewall',
        endpoint: '/setup/firewalls',
        responseKey: 'firewalls',
        moduleType: 'firewall',
        spokeFilter: s => s.module_type === 'firewall' || /^(opn|fw|firewall|pfsense|fortigate|juniper)/.test(s.spoke_id),
        payloadKey: 'firewall',
        badgeLabel: 'Firewall',
        vaultPicker: true,
        rowSummary: d => `${d.host || '—'}${d.port ? ':' + d.port : ''}`,
        fields: [
            { id: 'model', label: 'Model', type: 'select', options: [['opnsense','OPNsense'],['juniper','Juniper'],['fortigate','Fortigate'],['pfsense','pfSense']] },
            { id: 'host', label: 'Host / IP', placeholder: '172.16.1.1' },
            { id: 'port', label: 'Port', placeholder: '8443', coerce: 'int', default: 8443 },
            { id: 'api_key', label: 'API Key' },
            { id: 'api_secret', label: 'API Secret', type: 'password' },
        ],
    },
    nw: {
        title: 'Network Device',
        endpoint: '/setup/nw-devices',
        responseKey: 'nw_devices',
        moduleType: 'nw',
        spokeFilter: s => s.module_type === 'nw' || /^(nw|network)/.test(s.spoke_id),
        payloadKey: 'device',
        badgeLabel: 'Network',
        vaultPicker: true,
        rowSummary: d => `${d.address || '—'}${d.port ? ':' + d.port : ''}`,
        fields: [
            { id: 'object_type', label: 'Object Type', type: 'select', options: [['aos_switch','AOS Switch'],['cx_switch','CX Switch'],['ex_switch','EX Switch'],['gateway','Gateway']] },
            { id: 'transport', label: 'Transport', type: 'select', options: [['auto','Auto'],['ssh','SSH/CLI'],['rest','REST API'],['snmp','SNMP']] },
            { id: 'address', label: 'Address / Host IP', placeholder: '10.0.0.1' },
            { id: 'port', label: 'Port', placeholder: '22 / 443', coerce: 'int' },
            { id: 'username', label: 'Username' },
            { id: 'password', label: 'Password', type: 'password' },
            { id: 'enable_secret', label: 'Enable Secret', type: 'password' },
            { id: 'api_token', label: 'API Token', type: 'password' },
            { id: 'snmp_community', label: 'SNMP Community' },
            { id: 'poll_interval', label: 'Auto-Poll Interval', type: 'select', coerce: 'nullableInt',
              options: [['','Inherit module default'],['0','Off (manual Poll Now only)'],['60','Every 1 minute'],['300','Every 5 minutes'],['900','Every 15 minutes'],['1800','Every 30 minutes'],['3600','Every hour'],['21600','Every 6 hours'],['86400','Every day']] },
        ],
    },
    // nac/ipam/ldap inherit `alsoBareAgent: true` from INSTANCE_PRODUCTS above
    // — a not-yet-role-loaded base agent is selectable, and binding an
    // instance to one auto-loads the matching coordinator role on save.
    nac:   Object.assign({}, INSTANCE_PRODUCTS.nac,   { badgeLabel: 'NAC',  payloadKey: 'instance', responseKey: 'instances' }),
    ipam:  Object.assign({}, INSTANCE_PRODUCTS.ipam,  { badgeLabel: 'IPAM', payloadKey: 'instance', responseKey: 'instances' }),
    ldap:  Object.assign({}, INSTANCE_PRODUCTS.ldap,  { badgeLabel: 'LDAP', payloadKey: 'instance', responseKey: 'instances' }),
    dns:   Object.assign({}, INSTANCE_PRODUCTS.dns,   { badgeLabel: 'DNS',  payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'dns' }),
    dhcp:  Object.assign({}, INSTANCE_PRODUCTS.dhcp,  { badgeLabel: 'DHCP', payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'dhcp' }),
};

// Owning-tenant badge for the Setup instance lists. These lists are the ADMIN's
// global view, so they mix every tenant's entries — without this the only clue
// to ownership is whatever someone typed into the name, which is exactly how a
// pair of LRB-owned scan credentials called "Admin - …" got mistaken for the
// Admin tenant's own. Unassigned (no tenant_id) is admin-only, not global.
function _instanceTenantBadge(inst) {
    const tid = (inst && inst.tenant_id) ? String(inst.tenant_id) : '';
    if (!tid) return `<span class="ml-2 text-xs text-slate-400" title="Not bound to a tenant — visible to admins only, and not usable by a tenant-scoped scan">unassigned</span>`;
    return `<span class="ml-2 text-xs text-indigo-600" title="Owning tenant: ${escapeHtml(tid)}">tenant: ${escapeHtml(tid)}</span>`;
}

async function loadInstances(productKey) {
    const p = INSTANCE_PRODUCTS[productKey];
    if (!p) return;
    const listEl = document.getElementById(p.listId);
    if (!listEl) return;
    try {
        const instances = (await apiJson(p.endpoint)).instances || [];
        window._instances = window._instances || {};
        window._instances[productKey] = instances;
        if (instances.length === 0) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No instances configured.</p>';
            return;
        }
        listEl.innerHTML = instances.map(inst => `
            <div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${inst.name || inst.id}</span><span class="ml-2 text-xs text-slate-400">${p.rowSummary(inst)}${inst.spoke_id ? ' · ' + inst.spoke_id : ''}</span>${_instanceTenantBadge(inst)}${(inst.vault_credential && inst.vault_credential.name) ? `<span class="ml-2 text-xs text-emerald-600" title="Secret supplied from Credential Vault: ${escapeHtml(inst.vault_credential.bucket)} › ${escapeHtml(inst.vault_credential.name)}">🔐 vault</span>` : ''}</div>
                <div class="flex gap-2">
                    <button onclick="editInstance('${productKey}','${inst.id}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                    <button onclick="deleteInstance('${productKey}','${inst.id}')" class="text-xs text-red-400 hover:text-red-600 font-medium">Delete</button>
                </div>
            </div>`).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading instances: ${e.message}</p>`;
    }
}

// Derive the failover-pool checkbox candidates from the same `matched` spoke
// rows the Associated Spoke dropdown uses — deduped to one entry per PHYSICAL
// box (a bare base agent and its own already-loaded role sub-spoke, e.g.
// 'spokeA' and 'spokeA-cppm', are the same candidate; store/display by the
// base agent id, matching what instance_relocate.py expects in spoke_pool).
function _instancePoolCandidates(p, matched) {
    const byBase = new Map();
    matched.forEach(s => {
        const suffix = '-' + p.roleName;
        const baseId = s.module_type === 'agent' ? s.spoke_id
            : (s.spoke_id.endsWith(suffix) ? s.spoke_id.slice(0, -suffix.length) : s.spoke_id);
        // Prefer a bare agent row's label (it's the base identity); an
        // already-loaded sub-spoke row only fills in if the base agent
        // itself isn't separately listed.
        if (!byBase.has(baseId) || s.module_type === 'agent') {
            byBase.set(baseId, _spokeName(s));
        }
    });
    return Array.from(byBase, ([baseId, label]) => ({ baseId, label }))
        .sort((a, b) => a.label.localeCompare(b.label));
}

function showAddInstanceModal(productKey, editItem) {
    const p = INSTANCE_PRODUCTS[productKey];
    if (!p) return;
    const modal = document.createElement('div');
    modal.id = 'instance-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    const fieldHtml = p.fields.map(f => {
        const type = f.type || 'text';
        const cls = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
        const inner = type === 'select'
            ? `<select id="inst-${f.id}" class="${cls}">${(f.options || []).map(([v, lbl]) => `<option value="${v}">${lbl}</option>`).join('')}</select>`
            : `<input type="${type}" id="inst-${f.id}" placeholder="${f.placeholder || ''}" class="${cls}">`;
        return `                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">${f.label}</label>${inner}</div>`;
    }).join('\n');
    // IPAM-only: an "Apply schema changes" button that provisions the Lab
    // Manager custom fields (Proxmox / OPNsense / ClearPass sync) on the
    // connected NetBox via POST /setup/ipam/apply-schema. Idempotent + safe to
    // re-run — the engine get-or-creates + verifies every attachment, so it
    // never errors when the fields already exist (existing installs pick up
    // newly-added fields without a reinstall). Hidden for non-IPAM products.
    const schemaBtnHtml = productKey === 'ipam'
        ? `<div class="pt-3 mt-2 border-t border-slate-100 space-y-1">
                <button onclick="applyIpamSchema()" class="w-full px-4 py-2 rounded-md text-sm font-semibold text-[#01A982] border border-[#01A982] hover:bg-[#01A982] hover:text-white transition-all">Apply schema changes</button>
                <p class="text-[11px] text-slate-400 leading-snug">Provisions the Lab Manager custom fields used by the Proxmox, OPNsense, and ClearPass syncs on the connected NetBox. Idempotent — safe to run as many times as needed; existing fields are left in place.</p>
            </div>`
        : '';
    // Optional Credential Vault picker (products that carry a connection secret,
    // e.g. NAC/ClearPass). Backs the secret field(s) with a Vault entry so the
    // plaintext never persists on the hub — see instance_vault.py.
    const vaultHtml = p.vaultPicker ? _vaultCredSelectHtml('inst-vaultcred') : '';
    // Failover pool (PR2, coordinator roles only): an unordered, checkbox-
    // selected set of candidate spokes. When the currently active spoke goes
    // out of contact, the hub cold-switches to another checked candidate —
    // no ordering/priority, and deliberately no auto-failback (see
    // instance_relocate.py). Empty/unchecked = plain single-spoke behavior.
    const failoverPoolHtml = p.roleName ? `
                <div class="space-y-2 pt-2 border-t border-slate-100">
                    <label class="text-xs text-slate-500 uppercase font-bold">Failover Pool (optional)</label>
                    <p class="text-[11px] text-slate-400 leading-snug">Spokes that can take over this instance if the active one goes out of contact, or if load gets unbalanced across the pool. No priority order — the hub picks any available checked spoke. Once relocated, it stays there (no automatic fail-back).</p>
                    <div id="inst-spoke-pool" class="max-h-32 overflow-y-auto space-y-1 border border-slate-200 rounded-md p-2">
                        <p class="text-xs text-slate-400 italic">Loading spokes…</p>
                    </div>
                    <p id="inst-active-spoke" class="text-[11px] text-slate-500"></p>
                </div>` : '';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">${editItem ? 'Edit' : 'Add'} ${p.title}</h3>
                <button onclick="closeInstanceModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Instance Name</label><input type="text" id="inst-name" placeholder="e.g. Primary ${p.title.replace(' Instance', '')}" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label><select id="inst-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading spokes...</option></select></div>
${fieldHtml}
${vaultHtml}
${failoverPoolHtml}
${schemaBtnHtml}
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeInstanceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveInstance('${productKey}')" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    modal.dataset.product = productKey;
    if (editItem) modal.dataset.instanceId = editItem.id;
    if (p.vaultPicker) _fillVaultCredSelect('inst-vaultcred', editItem && editItem.vault_credential);

    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('inst-spoke');
        if (!selector) return;
        const matched = spokes.filter(s => (s.module_type === p.moduleType
                                            || (p.alsoBareAgent && s.module_type === 'agent'))
                                           && _spokeBindable(s));
        selector.innerHTML = matched.length > 0
            ? '<option value="">— select spoke —</option>' + matched.map(s => `<option value="${s.spoke_id}" title="${escapeHtml(s.spoke_id)}">${escapeHtml(_spokeName(s))}</option>`).join('')
            : `<option value="">No ${p.moduleType} spokes found</option>`;
        if (editItem) selector.value = editItem.spoke_id || '';

        if (p.roleName) {
            const poolEl = document.getElementById('inst-spoke-pool');
            const activeEl = document.getElementById('inst-active-spoke');
            if (poolEl) {
                const candidates = _instancePoolCandidates(p, matched);
                const checked = new Set((editItem && editItem.spoke_pool) || []);
                poolEl.innerHTML = candidates.length > 0
                    ? candidates.map(c => `<label class="flex items-center gap-2 text-sm text-slate-600">
                            <input type="checkbox" class="inst-pool-cb" value="${escapeHtml(c.baseId)}"${checked.has(c.baseId) ? ' checked' : ''}>
                            ${escapeHtml(c.label)}
                        </label>`).join('')
                    : '<p class="text-xs text-slate-400 italic">No eligible spokes found.</p>';
            }
            if (activeEl) {
                const activeSpoke = editItem && editItem.spoke_id
                    ? spokes.find(s => s.spoke_id === editItem.spoke_id) : null;
                activeEl.textContent = activeSpoke
                    ? `Currently active on: ${_spokeName(activeSpoke)}`
                    : (editItem && editItem.spoke_id ? `Currently active on: ${editItem.spoke_id}` : '');
            }
        }
    });

    if (editItem) {
        document.getElementById('inst-name').value = editItem.name || '';
        p.fields.forEach(f => {
            const el = document.getElementById('inst-' + f.id);
            if (!el) return;
            // For a <select>, only override the default (first option) when the
            // instance has a stored value — an old instance with no verify_ssl
            // then keeps the secure "Verify" default instead of going blank.
            // Checked against undefined/null/'' rather than plain truthiness so
            // a real boolean `false` (e.g. verify_ssl disabled) still counts as
            // "has a stored value" instead of falling back to the default.
            const has = editItem[f.id] !== undefined && editItem[f.id] !== null && editItem[f.id] !== '';
            if (el.tagName === 'SELECT') { if (has) el.value = String(editItem[f.id]); }
            else el.value = has ? editItem[f.id] : '';
        });
    }
}

async function editInstance(productKey, id) {
    const instances = (window._instances || {})[productKey] || [];
    const inst = instances.find(x => x.id === id);
    if (!inst) return;
    showAddInstanceModal(productKey, inst);
}

async function saveInstance(productKey) {
    const p = INSTANCE_PRODUCTS[productKey];
    if (!p) return;
    const modal = document.getElementById('instance-modal');
    if (!modal) return;
    const id = modal.dataset.instanceId;
    const config = {
        name: document.getElementById('inst-name').value,
        spoke_id: document.getElementById('inst-spoke').value,
    };
    if (p.roleName) {
        config.spoke_pool = Array.from(document.querySelectorAll('#inst-spoke-pool .inst-pool-cb:checked'))
            .map(cb => cb.value);
    }
    p.fields.forEach(f => {
        let v = document.getElementById('inst-' + f.id).value;
        // A select whose options are literally true/false (e.g. verify_ssl)
        // saves as a real boolean, not the string 'false' — which Python
        // treats as truthy and would silently invert the setting.
        if (f.type === 'select' && (v === 'true' || v === 'false')) v = (v === 'true');
        config[f.id] = v;
    });
    if (p.vaultPicker) {
        const vc = _collectVaultCred('inst-vaultcred');
        if (vc !== undefined) config.vault_credential = vc;
    }
    // nac/ipam/ldap: binding to a spoke that hasn't loaded the matching
    // coordinator role yet now auto-loads it as part of this save (see
    // routes/role_pool.py) — that can take up to ~2 minutes the first time
    // (a sibling-repo git clone + pip install), so set expectations instead
    // of leaving the operator staring at a stuck Save button.
    if (p.alsoBareAgent) showToast('Saving — if this spoke hasn\'t run this role before, '
        + 'loading it can take up to a couple of minutes…', 'info');
    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `${p.endpoint}/${id}` : p.endpoint;
        const payload = id ? { config: config } : { instance: config };
        const r = await setupFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (r.ok) {
            showToast(`Instance ${id ? 'updated' : 'added'} successfully!`, 'success');
            closeInstanceModal();
            loadInstances(productKey);
        } else {
            const err = await r.json().catch(() => ({}));
            showToast('Failed to save instance: ' + (err.detail || r.status), 'error');
        }
    } catch (e) {
        showToast('Error saving instance: ' + e.message, 'error');
    }
}

async function deleteInstance(productKey, id) {
    const p = INSTANCE_PRODUCTS[productKey];
    if (!p) return;
    if (!await showConfirmToast(`Delete this ${p.title.toLowerCase()}?`)) return;
    try {
        await apiJson(`${p.endpoint}/${id}`, { method: 'DELETE' });
        loadInstances(productKey);
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

// "Apply schema changes" button on the IPAM/NetBox instance modal →
// POST /setup/ipam/apply-schema → the connected NetBox spoke runs its
// idempotent _ensure_custom_fields(force=True) over the shared
// CUSTOM_FIELDS_SPEC (the same spec install.sh provisions on a fresh
// install). Fire-and-forget: no confirm() dialog — a "started" toast fires on
// click, and a "completed"/"failed" toast fires when the spoke finishes (the
// hub holds the request open up to 120s for the heavy provisioning run).
// Never errors if the schema is already up to date.
async function applyIpamSchema() {
    showToast('Applying Lab Manager schema to NetBox…', 'info');
    try {
        const r = await setupFetch('/setup/ipam/apply-schema', { method: 'POST' });
        const body = await r.json().catch(() => ({}));
        if (!r.ok) {
            showToast('Apply schema failed: ' + (body.detail || r.status), 'error');
            return;
        }
        const total = body.total ?? '?';
        const created = body.created ?? 0;
        const attached = body.attached ?? 0;
        const already = body.already_attached ?? 0;
        const warns = Array.isArray(body.warnings) ? body.warnings : [];
        const ok = body.status === 'SUCCESS';
        showToast(`Schema apply ${ok ? 'complete' : 'partial'}: ${total} fields · ${created} created · ${attached} attached · ${already} already${warns.length ? ' · ' + warns.length + ' warning(s)' : ''}`,
                  ok ? 'success' : 'info');
        if (warns.length) {
            // Surface the first warning so a partial result isn't silent.
            showToast('Warning: ' + warns[0], 'info');
        }
    } catch (e) {
        showToast('Error applying schema: ' + e.message, 'error');
    }
}

function closeInstanceModal() {
    const modal = document.getElementById('instance-modal');
    if (modal) modal.remove();
}

// ─── Module Management: unified device list + Add/Edit/Delete ──────────────
// One page (Setup → Module Management) lists every managed module device and
// lets an admin add any of them through a single modal: pick the module type
// first, then fill in that type's specifics. DEVICE_TYPES drives the schema.

// Device-CRUD base path per role. A Global Admin uses the admin /setup/* CRUD;
// a tenant-admin uses the session-scoped /tenant/devices/* mirror (same route
// shapes, so only the base swaps). Every DEVICE_TYPES.endpoint starts '/setup'.
// The unified device driver (loadAllDevices/saveDevice/deleteDevice) routes
// through here so one code path serves the admin Setup tile and the tenant-admin
// "My Devices" view.
function _devEndpoint(t) {
    if (isAdmin()) return t.endpoint;
    return '/tenant/devices' + t.endpoint.slice('/setup'.length);
}

async function loadAllDevices() {
    const listEl = document.getElementById('all-devices-list');
    if (!listEl) return;
    listEl.innerHTML = '<p class="text-xs text-slate-400 italic animate-pulse">Loading…</p>';
    const entries = Object.entries(DEVICE_TYPES);
    const results = await Promise.all(entries.map(async ([typeKey, t]) => {
        try {
            const r = await setupFetch(_devEndpoint(t));
            if (!r.ok) return [];
            const data = await r.json();
            const items = data[t.responseKey] || [];
            return (Array.isArray(items) ? items : []).map(d => ({ _typeKey: typeKey, _id: d.id, ...d }));
        } catch (e) {
            console.error(`loadAllDevices: ${typeKey} fetch failed:`, e);
            return [];
        }
    }));
    const all = results.flat();
    window._allDevices = all;
    if (all.length === 0) {
        const tabsEl = document.getElementById('all-devices-tabs');
        if (tabsEl) tabsEl.innerHTML = '';
        listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No managed devices yet. Click <strong>Add Device</strong> to attach one.</p>';
        return;
    }
    // Map spoke_id -> friendly name AND -> tenant so each row shows the spoke
    // NAME (not the GUID) and so devices can be grouped/filtered by tenant.
    // loadApprovedSpokes() is tenant-safe; ensureTenants() gives tenant display
    // names (admin only — tenant-admins see just their own devices).
    const _spokeNameById = {};
    const _spokeTenantById = {};
    try {
        (await loadApprovedSpokes()).forEach(s => {
            _spokeNameById[s.spoke_id] = _spokeName(s);
            _spokeTenantById[s.spoke_id] = _tenantOf(s) || '';
        });
    } catch (e) { /* best-effort — fall back to the id below */ }
    if (isAdmin()) { try { await ensureTenants(); } catch (_e) { /* names optional */ } }
    const _tenantNames = window._allTenantsName || {};
    // Decorate each device with its resolved spoke name + tenant so both the
    // tab bar and the row renderer can read them without re-deriving.
    all.forEach(d => {
        d._spokeName = d.spoke_id ? (_spokeNameById[d.spoke_id] || d.spoke_id) : '';
        d._tenant = d.spoke_id ? (_spokeTenantById[d.spoke_id] || '') : '';
        d._tenantLabel = d._tenant ? (_tenantNames[d._tenant] || d._tenant) : '';
    });
    if (!window._mdFilter) window._mdFilter = { type: 'all', tenant: 'all' };
    // Self-heal a stale filter after a delete/add: if the selected type or
    // tenant no longer owns any device, fall back to 'all' so the user isn't
    // stranded on an empty tab.
    const f = window._mdFilter;
    if (f.type !== 'all' && !all.some(d => d._typeKey === f.type)) f.type = 'all';
    if (f.tenant !== 'all' && !all.some(d => (d._tenant || '') === f.tenant)) f.tenant = 'all';
    _renderManagedDeviceTabs();
    _renderManagedDeviceList();
}

// Filter state for the Managed Devices list. Two independent, AND-combined
// dimensions: module TYPE (_typeKey) and TENANT (tenant id). 'all' = no filter.
// Kept on window so the tab click handlers survive re-renders.
function _mdFilteredDevices() {
    const f = window._mdFilter || { type: 'all', tenant: 'all' };
    return (window._allDevices || []).filter(d =>
        (f.type === 'all' || d._typeKey === f.type) &&
        (f.tenant === 'all' || (d._tenant || '') === f.tenant));
}

// Build the two-row sub-nav for Managed Devices: a device-TYPE row (always) and
// a TENANT row (admin only, when >1 tenant owns devices). Counts are contextual
// — a type tab shows how many match under the current tenant filter, and vice
// versa — so the numbers always reflect what a click would reveal. Mirrors the
// Setup → Simulations sub-tab idiom (.sub-nav-item.active = HPE-green underline).
function _renderManagedDeviceTabs() {
    const wrap = document.getElementById('all-devices-tabs');
    if (!wrap) return;
    const all = window._allDevices || [];
    const f = window._mdFilter || (window._mdFilter = { type: 'all', tenant: 'all' });

    // Type tabs: only types that actually have a device, ordered by DEVICE_TYPES.
    const underTenant = all.filter(d => f.tenant === 'all' || (d._tenant || '') === f.tenant);
    const typeCounts = {};
    underTenant.forEach(d => { typeCounts[d._typeKey] = (typeCounts[d._typeKey] || 0) + 1; });
    const typeKeys = Object.keys(DEVICE_TYPES).filter(k =>
        all.some(d => d._typeKey === k));
    const chip = (active, onclick, label, count) =>
        `<div onclick="${onclick}" class="sub-nav-item ${active ? 'active ' : ''}px-2 py-1 text-xs uppercase tracking-normal cursor-pointer select-none">${escapeHtml(label)}<span class="ml-1 text-[10px] text-slate-400 normal-case">${count}</span></div>`;
    // A single device type makes the type row redundant (All == that one type).
    let typeRow = '';
    if (typeKeys.length > 1) {
        let chips = chip(f.type === 'all', "_mdSelectType('all')", 'All', underTenant.length);
        chips += typeKeys.map(k => chip(f.type === k, `_mdSelectType('${k}')`,
            DEVICE_TYPES[k].badgeLabel || DEVICE_TYPES[k].title, typeCounts[k] || 0)).join('');
        typeRow = `<div class="flex flex-wrap items-center gap-x-1 gap-y-1">
            <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider mr-1">Type</span>${chips}</div>`;
    } else if (f.type !== 'all') {
        // Only one type exists but a stale filter still points at a removed one.
        f.type = 'all';
    }

    // Tenant tabs (admin only): tenants that own ≥1 device, under the current
    // type filter. A single tenant (or none) makes the row pointless → hide it.
    let tenantRow = '';
    if (isAdmin()) {
        const underType = all.filter(d => f.type === 'all' || d._typeKey === f.type);
        const tenantCounts = {};
        underType.forEach(d => {
            const t = d._tenant || '';
            if (t) tenantCounts[t] = (tenantCounts[t] || 0) + 1;
        });
        const tenantIds = Object.keys(tenantCounts).sort((a, b) =>
            (a).localeCompare(b));
        if (tenantIds.length > 1) {
            const names = window._allTenantsName || {};
            let row = chip(f.tenant === 'all', "_mdSelectTenant('all')", 'All Tenants', underType.length);
            row += tenantIds.map(tid => chip(f.tenant === tid,
                `_mdSelectTenant('${escJsAttr(tid)}')`, names[tid] || tid, tenantCounts[tid])).join('');
            tenantRow = `<div class="flex flex-wrap items-center gap-x-1 gap-y-1 border-b border-slate-100 pb-1 mb-1">
                <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider mr-1">Tenant</span>${row}</div>`;
        }
    }

    wrap.innerHTML = tenantRow + typeRow;
}

function _mdSelectType(key) {
    (window._mdFilter || (window._mdFilter = { type: 'all', tenant: 'all' })).type = key;
    _renderManagedDeviceTabs();
    _renderManagedDeviceList();
}

function _mdSelectTenant(tid) {
    (window._mdFilter || (window._mdFilter = { type: 'all', tenant: 'all' })).tenant = tid;
    _renderManagedDeviceTabs();
    _renderManagedDeviceList();
}

// Render the (filtered) device rows into #all-devices-list. Reads the decorated
// window._allDevices; the spoke name + tenant were resolved in loadAllDevices.
function _renderManagedDeviceList() {
    const listEl = document.getElementById('all-devices-list');
    if (!listEl) return;
    const rows = _mdFilteredDevices();
    if (rows.length === 0) {
        listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No devices match this filter.</p>';
        return;
    }
    listEl.innerHTML = rows.map(d => {
        const t = DEVICE_TYPES[d._typeKey];
        const name = d.name || d.id;
        const summary = t.rowSummary(d);
        const spoke = d.spoke_id
            ? ` · <span title="${escapeHtml(d.spoke_id)}">${escapeHtml(d._spokeName || d.spoke_id)}</span>`
            : '';
        const tenant = (isAdmin() && d._tenantLabel)
            ? `<span class="ml-2 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700" title="Tenant: ${escapeHtml(d._tenant)}">${escapeHtml(d._tenantLabel)}</span>`
            : '';
        const eId = String(d._id).replace(/'/g, "\\'");
        return `<div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
            <div><span class="text-sm font-medium text-slate-700">${escapeHtml(name)}</span><span class="ml-2 px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-700">${t.badgeLabel}</span>${tenant}<span class="ml-2 text-xs text-slate-400">${escapeHtml(summary)}${spoke}</span>${(d.vault_credential && d.vault_credential.name) ? `<span class="ml-2 text-xs text-emerald-600" title="Secret supplied from Credential Vault: ${escapeHtml(d.vault_credential.bucket)} › ${escapeHtml(d.vault_credential.name)}">🔐 vault</span>` : ''}</div>
            <div class="flex gap-2">
                <button onclick="editDevice('${d._typeKey}','${eId}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                <button onclick="deleteDevice('${d._typeKey}','${eId}')" class="text-xs text-red-400 hover:text-red-600 font-medium">Delete</button>
            </div>
        </div>`;
    }).join('');
}

// Render the type-specific field section for the unified Add/Edit Device modal.
// Selects render their options; everything else is a text/password input.
function _deviceFieldHtml(t, field, values) {
    const id = `dev-${field.id}`;
    const val = values ? (values[field.id] ?? '') : '';
    const cls = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    if (field.type === 'select') {
        const opts = (field.options || []).map(([v, lbl]) => `<option value="${v}"${String(v) === String(val) ? ' selected' : ''}>${lbl}</option>`).join('');
        return `                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">${field.label}</label><select id="${id}" class="${cls}">${opts}</select></div>`;
    }
    const type = field.type || 'text';
    const ph = field.placeholder ? ` placeholder="${field.placeholder}"` : '';
    return `                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">${field.label}</label><input type="${type}" id="${id}" value="${escapeHtml(String(val))}"${ph} class="${cls}"></div>`;
}

function showAddDeviceModal(editTypeKey, editItem) {
    const typeKeys = Object.keys(DEVICE_TYPES);
    const modal = document.createElement('div');
    modal.id = 'device-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50 sticky top-0">
                <h3 class="text-lg font-bold text-[#263040]">${editItem ? 'Edit' : 'Add'} Managed Device</h3>
                <button onclick="closeDeviceModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Device Name</label><input type="text" id="dev-name" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Module Type</label><select id="dev-type" ${editItem ? 'disabled' : ''} onchange="_onDeviceTypeChange()" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${typeKeys.map(k => `<option value="${k}"${k === editTypeKey ? ' selected' : ''}>${DEVICE_TYPES[k].title}</option>`).join('')}</select></div>
                <div class="space-y-2 md:col-span-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label><select id="dev-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading spokes...</option></select></div>
                <div id="dev-fields" class="md:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 sticky bottom-0">
                <button onclick="closeDeviceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveDevice()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    if (editItem) {
        modal.dataset.editType = editTypeKey;
        modal.dataset.editId = editItem.id;
    }
    _renderDeviceModalFields(editTypeKey || typeKeys[0], editItem);
}

// Re-render the type-specific fields + repopulate the Associated Spoke dropdown
// when the Module Type selection changes. The device type is determined by the
// module type (and the spoke it attaches to), so the spoke list is filtered to
// that module's spokes.
function _renderDeviceModalFields(typeKey, values) {
    const t = DEVICE_TYPES[typeKey];
    if (!t) return;
    const wrap = document.getElementById('dev-fields');
    if (wrap) wrap.innerHTML = t.fields.map(f => _deviceFieldHtml(t, f, values)).join('\n');
    // Optional Credential Vault picker for products with a connection secret
    // (NAC / network device) — spans both grid columns; filled + preselected
    // async from the record's existing {bucket,name} reference.
    if (wrap && t.vaultPicker) {
        wrap.innerHTML += `<div class="md:col-span-2">${_vaultCredSelectHtml('dev-vaultcred')}</div>`;
        _fillVaultCredSelect('dev-vaultcred', values && values.vault_credential);
    }
    // Name is only auto-filled from the edit item (top-level field), not fields.
    if (values && values.name) {
        const nameEl = document.getElementById('dev-name');
        if (nameEl) nameEl.value = values.name;
    }
    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('dev-spoke');
        if (!selector) return;
        const matched = spokes.filter(s => t.moduleType
                                  ? (s.module_type === t.moduleType || (t.alsoBareAgent && s.module_type === 'agent'))
                                  : true)
                              .filter(s => t.spokeFilter ? t.spokeFilter(s) : true)
                              .filter(_spokeBindable);
        const current = values ? values.spoke_id : '';
        selector.innerHTML = matched.length > 0
            ? '<option value="">— select spoke —</option>' + matched.map(s => `<option value="${s.spoke_id}"${s.spoke_id === current ? ' selected' : ''} title="${escapeHtml(s.spoke_id)}">${escapeHtml(_spokeName(s))}</option>`).join('')
            : `<option value="">No ${t.moduleType || ''} spokes found</option>`;
    });
}

function _onDeviceTypeChange() {
    const typeKey = document.getElementById('dev-type').value;
    _renderDeviceModalFields(typeKey, null);
}

async function editDevice(typeKey, id) {
    const all = window._allDevices || [];
    const d = all.find(x => x._typeKey === typeKey && x._id === id);
    if (!d) return;
    showAddDeviceModal(typeKey, d);
}

async function saveDevice() {
    const modal = document.getElementById('device-modal');
    if (!modal) return;
    const typeKey = document.getElementById('dev-type').value;
    const t = DEVICE_TYPES[typeKey];
    if (!t) return;
    const id = modal.dataset.editId;
    const config = {
        name: (document.getElementById('dev-name').value || '').trim(),
        spoke_id: document.getElementById('dev-spoke').value,
    };
    if (!config.name) { showToast('Device name is required.', 'error'); return; }
    t.fields.forEach(f => {
        const el = document.getElementById('dev-' + f.id);
        let v = el ? el.value : '';
        if (f.coerce === 'int') v = parseInt(v, 10) || (f.default != null ? f.default : null);
        // Nullable-int (e.g. nw Auto-Poll Interval): blank = inherit (null);
        // an explicit 0 (Off) must survive, so don't collapse it to null.
        else if (f.coerce === 'nullableInt') v = (v === '' ? null : (parseInt(v, 10) || 0));
        config[f.id] = v;
    });
    if (t.vaultPicker) {
        const vc = _collectVaultCred('dev-vaultcred');
        if (vc !== undefined) config.vault_credential = vc;
    }
    // IPAM Apply-schema is product-specific; keep it on the IPAM instance modal.
    // The unified modal handles the common add/edit path only.
    try {
        const method = id ? 'PUT' : 'POST';
        const ep = _devEndpoint(t);
        const url = id ? `${ep}/${encodeURIComponent(id)}` : ep;
        const payload = id ? { config } : { [t.payloadKey]: config };
        const r = await setupFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (r.ok) {
            showToast(`Device ${id ? 'updated' : 'added'} successfully`, 'success');
            closeDeviceModal();
            loadAllDevices();
        } else {
            const err = await r.json().catch(() => ({}));
            showToast('Failed to save device: ' + (err.detail || r.status), 'error');
        }
    } catch (e) {
        showToast('Error saving device: ' + e.message, 'error');
    }
}

async function deleteDevice(typeKey, id) {
    const t = DEVICE_TYPES[typeKey];
    if (!t) return;
    if (!await showConfirmToast(`Delete this ${t.title.toLowerCase()} (${id})?`)) return;
    try {
        await apiJson(`${_devEndpoint(t)}/${encodeURIComponent(id)}`, { method: 'DELETE' });
        loadAllDevices();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function closeDeviceModal() {
    const modal = document.getElementById('device-modal');
    if (modal) modal.remove();
}

// Toast duration (Setup → General → Notifications). window.TOAST_DURATION_MS
// is read by showToast(); loaded once at startup (loadToastConfig, below,
// public GET so it works pre-auth on the login screen too) and again whenever
// the General settings tile renders its form. Falls back to 10s if the fetch
// fails or hasn't completed yet — matches the server-side default.
window.TOAST_DURATION_MS = 10000;

async function loadToastConfig() {
    try {
        const r = await fetch('/setup/toast-config', { credentials: 'same-origin' });
        if (!r.ok) return;
        const d = await r.json();
        if (d.toast_duration_s) window.TOAST_DURATION_MS = Number(d.toast_duration_s) * 1000;
    } catch (e) { console.error('loadToastConfig', e); }
}

async function loadToastConfigForm() {
    await loadToastConfig();
    const el = document.getElementById('toast-duration-input');
    if (el) el.value = window.TOAST_DURATION_MS / 1000;
}

// Agent relay timeouts (Setup → General) — global_config.agent_relay_timeout_*_s,
// pushed to cs spokes via CS_CONFIG_UPDATE and read by their SPOKE_RELAY forward.
async function loadRelayTimeoutsForm() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const gc = ((await r.json()) || {}).global_config || {};
        const lo = document.getElementById('relay-timeout-long');
        const fa = document.getElementById('relay-timeout-fast');
        if (lo && gc.agent_relay_timeout_long_s != null) lo.value = gc.agent_relay_timeout_long_s;
        if (fa && gc.agent_relay_timeout_fast_s != null) fa.value = gc.agent_relay_timeout_fast_s;
    } catch (e) { console.error('loadRelayTimeoutsForm', e); }
}

async function saveRelayTimeouts() {
    const lo = Number(document.getElementById('relay-timeout-long')?.value);
    const fa = Number(document.getElementById('relay-timeout-fast')?.value);
    const status = document.getElementById('relay-timeout-status');
    if (!(lo >= 1) || !(fa >= 1)) {
        if (status) status.textContent = 'Enter values ≥ 1s.';
        return;
    }
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { agent_relay_timeout_long_s: lo, agent_relay_timeout_fast_s: fa } }),
        });
        if (r.ok) {
            if (status) status.textContent = 'Saved.';
            if (typeof showToast === 'function') showToast(`Relay timeouts saved (long ${lo}s, fast ${fa}s). Applies as cs spokes reconnect.`, 'success');
        } else if (status) { status.textContent = 'Failed to save.'; }
    } catch (e) { if (status) status.textContent = 'Failed to save.'; console.error('saveRelayTimeouts', e); }
}

async function saveToastConfig() {
    const el = document.getElementById('toast-duration-input');
    const status = document.getElementById('toast-duration-status');
    const seconds = Math.max(1, Math.min(300, Number(el?.value) || 10));
    try {
        const r = await setupFetch('/setup/toast-config', {
            method: 'POST', body: JSON.stringify({ toast_duration_s: seconds }),
        });
        if (r.ok) {
            window.TOAST_DURATION_MS = seconds * 1000;
            if (status) status.textContent = 'Saved.';
            showToast(`Toasts now stay on screen for ${seconds}s`, 'success');
        } else if (status) {
            status.textContent = 'Failed to save.';
        }
    } catch (e) {
        if (status) status.textContent = 'Failed to save.';
        console.error('saveToastConfig', e);
    }
}

async function loadAppearance() {
    try {
        const response = await setupFetch('/setup/appearance');
        if (!response.ok) return;
        const data = await response.json();
        const config = data.config;
        applyAppearance(config);
    } catch (err) {
        console.error('Failed to load appearance', err);
    }
}

function applyAppearance(config) {
    if (!config) return;
    const primary = config.primary_color || '#01A982';
    const navy = config.navy_color || '#263040';
    try {
        document.documentElement.style.setProperty('--hpe-green', primary);
        document.documentElement.style.setProperty('--hpe-navy', navy);
    } catch (e) {
        console.error('Failed to set CSS variables:', e);
    }
    // The header logo is ALWAYS the built-in HPE mark, byte-identical to the
    // login-screen logo (green #01A982 bar + white wordmark on the dark top
    // bar). We deliberately ignore appearance.logo_url and show_logo_left here:
    // a saved custom logo_url was rendering a foreign <img> (e.g. a black-on-white
    // HPE logo) in the header, which didn't match the login page's static
    // green+white SVG. Matching the login page means always showing the brand mark.
    const target = document.getElementById('logo-left');
    if (target) {
        target.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 180 504 144" width="74" height="21" role="img" aria-label="HPE" style="height:21px;width:auto;color:#fff;display:block;"><path fill="#01A982" d="M391.2 261.27v35.46H504V324H362.4v-90H504v27.27H391.2Z"/><path fill="currentColor" d="M276.67 180h-89.25v144h28.8v-36.6h60c37.92 0 59.7-21.6 59.7-53.4 0-32.01-21.78-54-59.25-54Zm-1.88 79.8h-58.57v-52.54h58.57c22.68 0 31.28 10.48 31.28 26.73 0 16.08-8.6 25.8-31.28 25.8Zm116.41-39.18h-28.8V180H504v27.27H391.2v13.36ZM151.2 180v144h-28.8v-59.02H28.8V324H0V180h28.8v57.38h93.6V180h28.8Z"/></svg>`;
    }
}

// Populate the Appearance settings form from the saved config.
async function loadAppearanceForm() {
    try {
        const r = await setupFetch('/setup/appearance');
        if (!r.ok) return;
        const data = await r.json();
        const c = data.config || {};
        const urlEl = document.getElementById('appearance-logo-url');
        const showEl = document.getElementById('appearance-show-logo');
        if (urlEl) urlEl.value = c.logo_url ?? 'hpe-svg';
        if (showEl) showEl.checked = c.show_logo_left !== false;
    } catch (e) {
        console.error('loadAppearanceForm', e);
    }
}

// Persist the Appearance settings and re-apply the header logo immediately.
async function saveAppearance() {
    const urlEl = document.getElementById('appearance-logo-url');
    const showEl = document.getElementById('appearance-show-logo');
    const status = document.getElementById('appearance-status');
    const config = {
        logo_url: (urlEl?.value || '').trim() || 'hpe-svg',
        show_logo_left: showEl ? showEl.checked : true,
    };
    try {
        const r = await setupFetch('/setup/appearance', { method: 'POST', body: JSON.stringify({ config }) });
        if (r.ok) {
            if (status) status.textContent = 'Saved.';
            await loadAppearance();   // re-apply to the header right away
        } else if (status) {
            status.textContent = 'Failed to save.';
        }
    } catch (e) {
        if (status) status.textContent = 'Failed to save.';
        console.error('saveAppearance', e);
    }
}

// Periodic session re-validation. A 200 means still authenticated; a 401 is
// caught by the global fetch override (handleSessionExpired) and this throws,
// which we swallow here. Only fires while logged in.
async function _pingSession() {
    if (!currentUser) return;
    try {
        const r = await fetch('/auth/me', { credentials: 'same-origin' });
        if (r && r.ok) {
            // Re-read the live user record so a promotion/demotion (or an
            // admin-flag reconciliation) made AFTER login takes effect without a
            // manual page refresh. Without this, currentUser.permissions is
            // frozen at login and the admin navs (Setup/Logs/System) never
            // appear/disappear until the user reloads. /auth/me re-reads the
            // live record server-side (api.py:auth_me); a 401 is caught by the
            // global fetch override (handleSessionExpired) and throws, skipping
            // this branch entirely.
            const fresh = await r.json();
            if (fresh && typeof fresh === 'object') {
                const wasAdmin = isAdmin();
                currentUser = {
                    ...currentUser,
                    permissions: fresh.permissions ?? currentUser.permissions,
                    tenants:      fresh.tenants      ?? currentUser.tenants,
                    tenant_id:    fresh.tenant_id    ?? currentUser.tenant_id,
                    protected:    fresh.protected    ?? currentUser.protected,
                    default_tenant: fresh.default_tenant,
                };
                if (wasAdmin !== isAdmin()) {
                    // Admin status changed mid-session — re-render the sidebar so
                    // the admin-only nav items appear/disappear without a reload.
                    updateStatus();
                }
            }
        }
    } catch (e) { /* 401 already routed to login by the fetch override */ }
}

async function _initApp() {
    // Admin-only eye + copy on every API-credential field. Idempotent + covers
    // all login paths (session restore + fresh login); observes dynamic forms.
    try { startApiFieldObserver(); } catch (e) { /* noop */ }
    try {
        // Pick the active tenant: user's first assigned tenant > localStorage > default.
        // Non-admin users with assigned tenants cannot switch outside their list.
        // Protected admins (no tenant assignments) always start on 'default' so a
        // stale localStorage value from a previous session doesn't scope their view.
        const allowed = userAllowedTenants();
        let resolved;
        // The user's chosen default tenant wins (the hub only returns it while
        // the tenant exists and the user may still view it).
        const preferred = currentUser?.default_tenant;
        if (preferred && canAccessTenant(preferred)) {
            resolved = preferred;
        } else if (currentUser?.protected && !allowed.length) {
            resolved = 'default';
            localStorage.removeItem('lm_tenant');
        } else {
            const saved = localStorage.getItem('lm_tenant') || 'default';
            resolved = currentUser?.tenant_id || saved;
            if (!canAccessTenant(resolved) && allowed.length > 0) resolved = allowed[0];
        }
        currentTenant = resolved;
        setTenant(currentTenant);

        // Reveal the admin-only nav items (Setup/Logs/System) immediately now
        // that the session is confirmed, instead of waiting for the first
        // updateStatus() poll to rebuild the sidebar. That poll awaits /status
        // plus the admin-only /setup/pending_spokes + /setup/diagnostics; if it
        // is slow or fails the items stay hidden until a manual refresh — the
        // "sometimes I have to refresh to get the admin menus" race.
        // _rebuildMainNav re-affirms visibility on every poll; this just makes
        // the first paint correct. Non-admins keep the static `hidden`.
        if (isAdmin()) {
            ['nav-setup', 'nav-logs', 'nav-settings'].forEach(id => {
                document.getElementById(id)?.classList.remove('hidden');
            });
        }

        // Admins (protected, no tenant assignments) get a picker listing EVERY
        // tenant so they can view any tenant's systems in Simulations (and
        // elsewhere). Non-admins are limited to their assigned tenants (allowed).
        // Both fetch /setup/tenants so entries carry their display name and the
        // is_group flag — a NetBox tenant GROUP is selectable like a tenant and
        // shows the union of its member tenants, so it must not render as the
        // raw "group:<slug>" id.
        let pickerTenants = allowed.map(id => ({ id, name: id, isGroup: false, members: [] }));
        try {
            const r = await fetch('/setup/tenants', { credentials: 'same-origin' });
            if (r.ok) {
                const td = await r.json();
                let rows = (td.tenants || []).map(t => ({
                    id: t.id,
                    name: t.name || t.id,
                    isGroup: !!t.is_group,
                    members: t.members || [],
                }));
                if (!isAdmin()) rows = rows.filter(t => allowed.includes(t.id));
                if (rows.length) pickerTenants = rows;
            }
        } catch (e) { console.error('_initApp: tenant picker fetch failed — falling back to allowed tenants', e); }
        // Groups first, then tenants, each alphabetically — a group is a wider
        // scope, so it reads as the parent of the tenants listed under it.
        pickerTenants.sort((a, b) =>
            (b.isGroup - a.isGroup) || a.name.localeCompare(b.name));
        const tenantNameMap = {};
        pickerTenants.forEach(t => { tenantNameMap[t.id] = t.name; });
        window._lmTenantPicker = pickerTenants;

        // Build the user chip in the header
        const chip = document.getElementById('user-chip');
        const nameEl = document.getElementById('user-chip-name');
        const wrap = document.getElementById('user-chip-tenant-wrap');
        if (chip && currentUser) {
            // For Entra users user_id is the oid GUID — show the friendly name/
            // email instead. Local users have no name, so this falls back to the
            // user_id (which is their username).
            if (nameEl) nameEl.textContent = currentUser.display_name || currentUser.name || currentUser.email || currentUser.user_id;
            if (wrap) {
                const chipLabel = tenantNameMap[currentTenant] || currentTenant;
                if (pickerTenants.length > 1) {
                    // Multi-tenant picker: admins see every tenant; non-admins see
                    // only their assigned tenants. Click-toggled (not hover) so the
                    // menu stays open while the user moves to / clicks an item.
                    wrap.innerHTML = `
                        <div class="relative" id="tenant-picker-wrap">
                            <button onclick="toggleTenantPicker(event)" class="px-2 py-0.5 rounded-full bg-[#01A982] text-white text-[10px] font-bold uppercase tracking-wider flex items-center gap-1">
                                <span id="user-chip-tenant">${escapeHtml(chipLabel)}</span>
                                <svg class="w-2.5 h-2.5 opacity-70" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"/></svg>
                            </button>
                            <div id="tenant-picker-menu" class="hidden absolute top-full left-1/2 -translate-x-1/2 mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl z-50 min-w-[140px] max-h-[60vh] overflow-y-auto py-1">
                                ${pickerTenants.map(t => `
                                    <div class="flex items-center hover:bg-[#01A982] group">
                                    <button data-tid="${escapeHtml(t.id)}" onclick="viewAsTenant('${escapeHtml(t.id)}')" title="${t.isGroup ? escapeHtml('Tenant group — shows: ' + (t.members.join(', ') || 'no members')) : ''}" class="flex-1 text-left pl-3 pr-1 py-1.5 text-[11px] text-slate-200 group-hover:text-white transition-colors flex items-center justify-between gap-2 ${t.id===currentTenant?'font-bold text-[#01A982]':''}">
                                        <span>${escapeHtml(t.name)}</span>
                                        ${t.isGroup ? `<span class="px-1 rounded bg-slate-600 text-slate-200 text-[9px] font-bold uppercase tracking-wider shrink-0">Group</span>` : ''}
                                    </button>
                                    ${_tenantDefaultStar(t.id)}
                                    </div>
                                `).join('')}
                            </div>
                        </div>`;
                    _bindTenantPickerListeners();
                } else if (currentTenant && currentTenant !== 'default') {
                    wrap.innerHTML = `<span id="user-chip-tenant" class="px-2 py-0.5 rounded-full bg-[#01A982] text-white text-[10px] font-bold uppercase tracking-wider">${escapeHtml(chipLabel)}</span>`;
                } else {
                    wrap.innerHTML = '';
                }
            }
            chip.classList.remove('hidden');
            chip.classList.add('flex');
        }

        const savedTheme = localStorage.getItem('lm_theme') || 'default';
        setTheme(savedTheme);

        loadAppearance();
        loadToastConfig();
        loadTenantPrefixes();  // background — prefixes used for filtering, not dashboard render
        installClickFeedback();  // immediate "Loading …" ack on every button click
        setView('dashboard');
        _startCacheStatusPolling();
        pollManager.register(updateStatus, 10000);
        // Re-validate the session periodically. /status (above) is public and
        // stays 200 even after auth expires, so it can't signal expiry on its
        // own. A 401 here is caught by the global fetch override, which sends
        // the user back to login instead of leaving a cached view rendering.
        pollManager.register(_pingSession, 60000);
        console.log("Lab Manager UI: Initialization complete.");
    } catch (err) {
        console.error("Lab Manager UI: Critical initialization error:", err);
        showToast("UI Initialization failed: " + err.message, 'error');
    }
}

// Entra ID (OIDC) SSO button — shown only when the hub reports OIDC enabled.
// The button is a plain navigation to /auth/oidc/login, which mints PKCE+state
// and 302s to Entra; on callback the hub sets the lm_session cookie and
// redirects back to the app root, so DOMContentLoaded re-checks /auth/me and
// continues into _initApp. No fetch/JSON here — it's a top-level browser
// redirect, so the SSO cookie + cross-origin hop work as the OIDC backend expects.
async function refreshOidcButton() {
    const wrap = document.getElementById('login-oidc-wrap');
    if (!wrap) return;
    try {
        const r = await fetch('/auth/oidc/enabled', { credentials: 'same-origin' });
        if (!r.ok) { wrap.classList.add('hidden'); return; }
        const body = await r.json().catch(() => ({}));
        wrap.classList.toggle('hidden', !body.enabled);
    } catch (_e) {
        // Hub unreachable / older build without the endpoint → hide the button.
        wrap.classList.add('hidden');
    }
}

function doOidcLogin() {
    window.location.href = '/auth/oidc/login';
}

async function doLogin() {
    const username = (document.getElementById('login-username')?.value || '').trim();
    const password = document.getElementById('login-password')?.value || '';
    const errEl = document.getElementById('login-error');
    if (errEl) errEl.classList.add('hidden');

    if (!username || !password) {
        if (errEl) { errEl.textContent = 'Username and password are required.'; errEl.classList.remove('hidden'); }
        return;
    }

    try {
        const r = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'same-origin',
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            if (errEl) { errEl.textContent = err.detail || 'Invalid credentials.'; errEl.classList.remove('hidden'); }
            return;
        }
        currentUser = await r.json();
        document.getElementById('login-overlay')?.classList.add('hidden');
        _initApp();
    } catch (e) {
        if (errEl) { errEl.textContent = 'Connection error — is the hub running?'; errEl.classList.remove('hidden'); }
    }
}

async function doLogout() {
    await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    currentUser = null;
    // Always return to login panel (not setup) on logout
    document.getElementById('setup-panel')?.classList.add('hidden');
    document.getElementById('login-panel')?.classList.remove('hidden');
    document.getElementById('login-overlay')?.classList.remove('hidden');
    document.getElementById('user-chip')?.classList.add('hidden');
    document.getElementById('user-chip')?.classList.remove('flex');
    document.getElementById('login-username')?.focus();
    refreshOidcButton();
}

async function doSetup() {
    const username = (document.getElementById('setup-username')?.value || '').trim();
    const password = document.getElementById('setup-password')?.value || '';
    const password2 = document.getElementById('setup-password2')?.value || '';
    const setupToken = document.getElementById('setup-token')?.value || '';
    const errEl = document.getElementById('setup-error');
    if (errEl) errEl.classList.add('hidden');

    if (!username || !password) {
        if (errEl) { errEl.textContent = 'Username and password are required.'; errEl.classList.remove('hidden'); }
        return;
    }
    if (password.length < 8) {
        if (errEl) { errEl.textContent = 'Password must be at least 8 characters.'; errEl.classList.remove('hidden'); }
        return;
    }
    if (password !== password2) {
        if (errEl) { errEl.textContent = 'Passwords do not match.'; errEl.classList.remove('hidden'); }
        return;
    }

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (setupToken) headers['X-Setup-Token'] = setupToken;
        const r = await fetch('/auth/setup', {
            method: 'POST',
            headers,
            body: JSON.stringify({ username, password }),
            credentials: 'same-origin',
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            if (errEl) { errEl.textContent = err.detail || 'Setup failed.'; errEl.classList.remove('hidden'); }
            return;
        }
        currentUser = await r.json();
        document.getElementById('login-overlay')?.classList.add('hidden');
        _initApp();
    } catch (e) {
        if (errEl) { errEl.textContent = 'Connection error — is the hub running?'; errEl.classList.remove('hidden'); }
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log("Lab Manager UI: Checking session...");
    try {
        const r = await fetch('/auth/me', { credentials: 'same-origin' });
        if (r.ok) {
            currentUser = await r.json();
            document.getElementById('login-overlay')?.classList.add('hidden');
            _initApp();
        } else {
            const body = await r.json().catch(() => ({}));
            if (body.first_run) {
                document.getElementById('login-panel')?.classList.add('hidden');
                document.getElementById('setup-panel')?.classList.remove('hidden');
                document.getElementById('setup-username')?.focus();
            } else {
                document.getElementById('login-username')?.focus();
            }
            // Reveal the "Sign in with Microsoft" button when OIDC is configured.
            refreshOidcButton();
        }
    } catch (e) {
        console.warn("Session check failed:", e);
        document.getElementById('login-username')?.focus();
        refreshOidcButton();
    }
});
