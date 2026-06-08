const VIEWS = {
    dashboard: {
        name: 'Overview',
        subMenus: ['Status', 'Performance', 'Events'],
        render: () => `
            <div class="space-y-6">
                <h2 class="text-2xl font-bold mb-6">Infrastructure Overview</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="hpe-card rounded-2xl p-6">
                        <label class="text-xs text-slate-500 uppercase font-bold">Active Spokes</label>
                        <div id="spoke-count" class="text-4xl font-bold mt-2 text-blue-400">0</div>
                    </div>
                    <div class="hpe-card rounded-2xl p-6">
                        <label class="text-xs text-slate-500 uppercase font-bold">System Health</label>
                        <div id="health-status" class="text-4xl font-bold mt-2 text-green-400">Optimal</div>
                    </div>
                    <div class="hpe-card rounded-2xl p-6">
                        <label class="text-xs text-slate-500 uppercase font-bold">Network Latency</label>
                        <div class="text-4xl font-bold mt-2 text-slate-200">~1.2ms</div>
                    </div>
                </div>

                <div class="hpe-card rounded-2xl p-6">
                    <h3 class="text-lg font-semibold mb-4">Connected Spokes</h3>
                    <div id="spoke-list" class="space-y-3">
                        <div class="animate-pulse flex space-x-4 p-2">
                            <div class="rounded-full bg-slate-700 h-10 w-10"></div>
                            <div class="flex-1 space-y-6 py-1">
                                <div class="h-2 bg-slate-700 rounded"></div>
                                <div class="h-2 bg-slate-700 rounded w-5/6"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `
    },
    resources: {
        name: 'Resources',
        subMenus: ['VM Lookup', 'Firewall Rules', 'Interface Map'],
        render: () => `
            <div class="space-y-6">
                <h2 class="text-2xl font-bold mb-6">Resource Management</h2>
                <div class="hpe-card rounded-2xl p-6">
                    <div class="flex gap-4 mb-8">
                        <input id="vm-id-input" type="text" placeholder="Enter VM ID (e.g. vm-101)"
                               class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:ring-2 focus:ring-blue-500 outline-none transition-all text-white">
                        <button onclick="lookupFirewall()"
                                class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg text-sm font-medium transition-all">
                            Lookup Firewall
                        </button>
                    </div>

                    <div id="vm-details" class="hidden space-y-6">
                        <div class="grid grid-cols-2 gap-4">
                            <div class="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
                                <label class="text-xs text-slate-500 uppercase font-bold">VM ID</label>
                                <div id="res-vm-id" class="text-lg font-medium text-slate-200">-</div>
                            </div>
                            <div class="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
                                <label class="text-xs text-slate-500 uppercase font-bold">IP Address</label>
                                <div id="res-ip" class="text-lg font-medium text-blue-400">-</div>
                            </div>
                        </div>

                        <div>
                            <h3 class="text-sm font-semibold text-slate-400 mb-3 uppercase tracking-wider">OPNsense Firewall Rules</h3>
                            <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/50">
                                <table class="w-full text-left text-sm">
                                    <thead class="bg-slate-800 text-slate-400 uppercase text-xs">
                                        <tr>
                                            <th class="px-4 py-3">Rule ID</th>
                                            <th class="px-4 py-3">Action</th>
                                            <th class="px-4 py-3">Protocol</th>
                                            <th class="px-4 py-3">Destination</th>
                                        </tr>
                                    </thead>
                                    <tbody id="firewall-table-body" class="divide-y divide-slate-800">
                                        <!-- Rows injected here -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <div id="vm-empty-state" class="py-12 text-center text-slate-500">
                        <svg class="w-12 h-12 mx-auto mb-3 opacity-20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                        <p>Enter a VM ID to inspect its connectivity and firewall rules.</p>
                    </div>
                </div>
            </div>
        `
    },
    settings: {
        name: 'System',
        subMenus: ['General', 'Network', 'Auth', 'Logs'],
        render: () => `
            <div class="space-y-6">
                <h2 class="text-2xl font-bold mb-6">System Configuration</h2>
                <div class="hpe-card rounded-2xl p-6 space-y-4">
                    <div class="flex justify-between p-4 rounded-lg bg-slate-900/50 border border-slate-800">
                        <span class="text-slate-400">Hub Version</span>
                        <span class="text-blue-400 font-mono font-bold">0.07</span>
                    </div>
                    <div class="flex justify-between p-4 rounded-lg bg-slate-900/50 border border-slate-800">
                        <span class="text-slate-400">API Status</span>
                        <span class="text-green-400 font-bold">Active</span>
                    </div>
                    <div class="flex justify-between p-4 rounded-lg bg-slate-900/50 border border-slate-800">
                        <span class="text-slate-400">Deployment Mode</span>
                        <span class="text-slate-200">LXC Native</span>
                    </div>
                </div>
            </div>
        `
    }
};

let currentView = 'dashboard';

function setView(viewId) {
    currentView = viewId;

    // Update Nav Active State
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.getElementById(`nav-${viewId}`).classList.add('active');

    // Update Top Nav
    const topNav = document.getElementById('top-nav');
    const view = VIEWS[viewId];
    topNav.innerHTML = view.subMenus.map((menu, i) => `
        <div class="sub-nav-item ${i === 0 ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest">
            ${menu}
        </div>
    `).join('');

    // Update Content
    document.getElementById('viewport').innerHTML = view.render();

    // Re-bind view-specific logic
    if (viewId === 'dashboard') updateStatus();
}

async function updateStatus() {
    const statusEl = document.getElementById('connection-status');
    const spokeList = document.getElementById('spoke-list');
    const spokeCount = document.getElementById('spoke-count');

    if (!statusEl || !spokeList) return;

    try {
        const response = await fetch('/status');
        if (!response.ok) throw new Error('API Error');
        const data = await response.json();

        statusEl.innerHTML = `
            <div class="w-1.5 h-1.5 rounded-full bg-green-500"></div>
            <span class="text-green-400">Hub Online</span>
        `;

        const connections = data.active_connections || [];
        if (spokeCount) spokeCount.textContent = connections.length;

        // --- Dynamic Menu Visibility ---
        // Resources menu requires either a pxmx or opn spoke
        const hasResourcesSpoke = connections.some(id => id.includes('pxmx') || id.includes('opn'));
        const resNav = document.getElementById('nav-resources');
        if (resNav) {
            resNav.style.display = hasResourcesSpoke ? 'flex' : 'none';
        }

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
            <div class="w-1.5 h-1.5 rounded-full bg-red-500"></div>
            <span class="text-red-400">Hub Offline</span>
        `;
        if (spokeList) spokeList.innerHTML = `<p class="text-xs text-red-500 italic">Error connecting to Hub API.</p>`;
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

        idEl.textContent = vmId;
        ipEl.textContent = data.ip || 'Unknown';

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

// Initial Launch
document.addEventListener('DOMContentLoaded', () => {
    setView('dashboard');
    setInterval(updateStatus, 10000);
});
