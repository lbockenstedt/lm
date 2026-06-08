async function updateStatus() {
    const statusEl = document.getElementById('connection-status');
    const spokeList = document.getElementById('spoke-list');
    const versionEl = document.getElementById('sys-version');

    try {
        const response = await fetch('/status');
        if (!response.ok) throw new Error('API Error');
        const data = await response.json();

        // Update Connection Status
        statusEl.innerHTML = `
            <div class="w-2 h-2 rounded-full bg-green-500"></div>
            <span class="text-green-400">Hub Online</span>
        `;

        // Update Version
        versionEl.textContent = "0.06"; // Matches current build

        // Update Spokes
        const connections = data.active_connections || [];
        if (connections.length === 0) {
            spokeList.innerHTML = `<p class="text-xs text-slate-500 italic">No spokes connected.</p>`;
        } else {
            spokeList.innerHTML = connections.map(id => `
                <div class="flex items-center justify-between p-3 rounded-xl bg-slate-800/40 border border-slate-700/50 hover:border-blue-500/50 transition-all group">
                    <div class="flex items-center gap-3">
                        <div class="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]"></div>
                        <span class="text-sm font-medium text-slate-300 group-hover:text-white transition-colors">${id}</span>
                    </div>
                    <span class="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Online</span>
                </div>
            `).join('');
        }

    } catch (err) {
        statusEl.innerHTML = `
            <div class="w-2 h-2 rounded-full bg-red-500"></div>
            <span class="text-red-400">Hub Offline</span>
        `;
        spokeList.innerHTML = `<p class="text-xs text-red-500 italic">Error connecting to Hub API.</p>`;
    }
}

async function lookupFirewall() {
    const vmId = document.getElementById('vm-id-input').value.trim();
    if (!vmId) return;

    const details = document.getElementById('vm-details');
    const emptyState = document.getElementById('vm-empty-state');
    const tableBody = document.getElementById('firewall-table-body');
    const ipEl = document.getElementById('res-ip');
    const idEl = document.getElementById('res-vm-id');

    emptyState.classList.add('hidden');
    details.classList.remove('hidden');
    tableBody.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-slate-500 animate-pulse">Querying OPNsense spoke...</td></tr>`;

    try {
        const response = await fetch(`/vm/${vmId}/firewall`);
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to fetch firewall rules');
        }
        const data = await response.json();

        // Update VM Info
        idEl.textContent = vmId;
        ipEl.textContent = data.ip || 'Unknown';

        // Update Table
        const rules = data.rules || [];
        if (rules.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="4" class="px-4 py-4 text-center text-slate-500 italic">No rules found for this IP.</td></tr>`;
        } else {
            tableBody.innerHTML = rules.map(rule => `
                <tr class="hover:bg-slate-800/30 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs text-slate-400">${rule.id || 'N/A'}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${rule.action === 'pass' ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}">
                            ${rule.action}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-slate-300">${rule.protocol || 'TCP'}</td>
                    <td class="px-4 py-3 text-slate-300">${rule.destination || '-'}</td>
                </tr>
            `).join('');
        }

    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-red-400 font-medium">${err.message}</td></tr>`;
    }
}

// Initial load and polling
updateStatus();
setInterval(updateStatus, 10000);
